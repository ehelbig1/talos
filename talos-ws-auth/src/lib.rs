// async-graphql 7.x type-walks the talos-api MutationRoot under cargo
// build in a way that exceeds the default 128-deep query layout limit.
// Same fix as controller::lib (commit 47258c0).
#![recursion_limit = "256"]

use axum::extract::ws::{Message, WebSocket};
use axum::http::HeaderValue;
use futures::{stream::StreamExt, SinkExt};
use std::sync::Arc;
use uuid::Uuid;

use talos_auth::AuthService;
use talos_config as config;
use talos_metrics::{WsActiveSession, WsHandshakeOutcome, WsOperationOutcome, WsSessionEnd};

/// Why a handshake did not (or did) produce a session, decided from the
/// Origin header alone — pure, so every arm is a unit test. `production`
/// decides whether an ABSENT Origin is refused (browsers always send one on a
/// WS upgrade; non-browser dev clients may not). `allowed` is the deployment's
/// allow-list (`talos_config::is_allowed_origin` in production code).
pub fn classify_origin(
    origin: Option<&HeaderValue>,
    production: bool,
    allowed: impl Fn(&str) -> bool,
) -> Result<(), WsHandshakeOutcome> {
    match origin {
        Some(value) => match value.to_str() {
            Ok(text) if allowed(text) => Ok(()),
            Ok(_) => Err(WsHandshakeOutcome::OriginNotAllowed),
            Err(_) => Err(WsHandshakeOutcome::OriginMalformed),
        },
        None if production => Err(WsHandshakeOutcome::OriginMissing),
        None => Ok(()),
    }
}

/// An authenticated socket's identity, plus how long the access token has
/// left — the session's hard deadline (a stolen-and-later-revoked cookie is
/// bounded by it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsAuth {
    pub user_id: Uuid,
    pub is_2fa_verified: bool,
    pub secs_until_expiry: u64,
}

/// Classify the cookie: absent, unverifiable, or carrying a `sub` that is not
/// a UUID — each its own outcome for the operator, ONE `connection_error` for
/// the caller. `verify` is `AuthService::verify_token` reduced to
/// `(sub, is_2fa_verified, exp)` so this stays pure and testable; `now_secs`
/// is the caller's clock (a token whose `exp` is already past yields a
/// zero-second session, which the deadline then closes at once).
pub fn classify_auth(
    access_token: Option<&str>,
    verify: impl FnOnce(&str) -> Result<(String, bool, i64), String>,
    now_secs: u64,
) -> Result<WsAuth, (WsHandshakeOutcome, Option<String>)> {
    let Some(token) = access_token else {
        return Err((WsHandshakeOutcome::NoToken, None));
    };
    let (sub, is_2fa_verified, exp) =
        verify(token).map_err(|e| (WsHandshakeOutcome::InvalidToken, Some(e)))?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| (WsHandshakeOutcome::InvalidUserId, None))?;
    let secs_until_expiry = u64::try_from(exp).unwrap_or(0).saturating_sub(now_secs);
    Ok(WsAuth {
        user_id,
        is_2fa_verified,
        secs_until_expiry,
    })
}

/// The ONE place a handshake's outcome is counted and logged (package DU,
/// 2026-09-22 — before it, nine refusal arms each carried their own WARN and
/// none reached a series). Security refusals go to `talos_audit` at WARN;
/// a cookieless socket is DEBUG (nothing to guess with; the counter has it);
/// the two protocol outcomes keep the `event_kind`s operators already filter
/// on. `Authenticated` is counted here and described at the auth site, which
/// holds the user id. `detail` is bounded to 256 bytes before it is logged —
/// it is caller-influenced (an Origin string, a verifier error) and never a
/// token.
fn report_handshake(outcome: WsHandshakeOutcome, detail: Option<&str>) {
    talos_metrics::record_ws_handshake(outcome);
    let detail = detail.map(|d| {
        let mut end = d.len().min(256);
        while !d.is_char_boundary(end) {
            end -= 1;
        }
        &d[..end]
    });
    match outcome {
        WsHandshakeOutcome::Authenticated => {}
        WsHandshakeOutcome::NoToken => tracing::debug!(
            target: "talos_ws_auth",
            event_kind = "ws_handshake_refused",
            outcome = outcome.as_str(),
            "WebSocket connection_init without an access-token cookie"
        ),
        WsHandshakeOutcome::ProtocolViolation => tracing::warn!(
            target: "talos_ws_auth",
            event_kind = "ws_protocol_violation",
            outcome = outcome.as_str(),
            "WebSocket first message was not connection_init — closing"
        ),
        WsHandshakeOutcome::InitNotReceived => tracing::warn!(
            target: "talos_ws_auth",
            event_kind = "ws_init_not_received",
            outcome = outcome.as_str(),
            pending_refusal = detail,
            "WebSocket closed without observing connection_init within deadline"
        ),
        refusal => tracing::warn!(
            target: "talos_audit",
            event_kind = "ws_handshake_refused",
            outcome = refusal.as_str(),
            detail,
            "WebSocket handshake refused"
        ),
    }
}

/// Custom WebSocket handler that validates JWT tokens on connection
/// Token is extracted from httpOnly cookie in the upgrade request (secure!)
pub async fn handle_websocket_auth(
    mut socket: WebSocket,
    schema: talos_api::TalosSchema,
    auth_service: Arc<AuthService>,
    access_token: Option<String>,
    origin: Option<HeaderValue>,
) {
    // Validate Origin header to prevent Cross-Site WebSocket Hijacking (CSWH).
    if let Err(outcome) = classify_origin(
        origin.as_ref(),
        config::is_production(),
        config::is_allowed_origin,
    ) {
        // The Origin string is what an operator triaging CSWH needs; it is
        // caller-supplied and bounded by the report site.
        let shown = origin.as_ref().and_then(|v| v.to_str().ok());
        report_handshake(outcome, shown);
        let _ = socket.close().await;
        return;
    }

    // Authenticate using token from cookie (extracted from HTTP headers).
    // We also capture the token's expiry so we can hard-terminate the connection
    // when the token expires — this covers the session-revocation case where an
    // attacker holds a stolen token that is later revoked server-side.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // The verdict is held, not reported: the handshake's outcome is what the
    // socket ENDS as, and a cookieless client that never sends
    // connection_init ends as `init_not_received`, not `no_token`.
    let auth_result: Result<
        (Uuid, bool, tokio::time::Instant),
        (WsHandshakeOutcome, Option<String>),
    > = classify_auth(
        access_token.as_deref(),
        |token| {
            auth_service
                .verify_token(token)
                .map(|claims| (claims.sub, claims.is_2fa_verified, claims.exp as i64))
                .map_err(|e| format!("{e:?}"))
        },
        now_secs,
    )
    .map(|auth| {
        let deadline =
            tokio::time::Instant::now() + tokio::time::Duration::from_secs(auth.secs_until_expiry);
        tracing::info!(
            user_id = %auth.user_id,
            is_2fa_verified = auth.is_2fa_verified,
            expires_in_secs = auth.secs_until_expiry,
            "WebSocket authenticated (via cookie)"
        );
        (auth.user_id, auth.is_2fa_verified, deadline)
    });

    // Wait for connection_init message with a 30-second timeout.
    // This prevents malicious clients from holding WebSocket connections open
    // indefinitely without completing the init handshake.
    let init_deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(30);
    // MCP-633 (2026-05-12): track whether connection_init was received
    // before falling through to handle_graphql_ws. Pre-fix, a client
    // that opened the WS and sent NO application-level messages for 30s
    // would exit the loop via init_deadline timeout (or via socket
    // close), and if `auth_result` was Some (token in query string
    // was valid) the code would proceed to `handle_graphql_ws` WITHOUT
    // ever having seen a connection_init frame. graphql-ws protocol
    // requires connection_init as the first frame; without it the
    // session is in an undefined state. Sibling pattern to L-21 (which
    // closed the "non-init Text early" case but not the "no message
    // at all" case). Track explicitly and refuse to continue if init
    // was never observed.
    let mut init_received = false;
    while let Ok(Some(msg)) = tokio::time::timeout_at(init_deadline, socket.recv()).await {
        if let Ok(msg) = msg {
            match msg {
                Message::Text(text) => {
                    // L-21: graphql-ws protocol REQUIRES `connection_init`
                    // as the first message. Pre-fix, malformed JSON or
                    // any other Text message was silently ignored — the
                    // socket sat idle until the 30s init_deadline,
                    // wasting a server connection slot per malformed
                    // hello. Now reject the first non-init Text message
                    // with a connection_error and close.
                    let parsed: Option<serde_json::Value> = serde_json::from_str(&text).ok();
                    let is_init = parsed
                        .as_ref()
                        .and_then(|j| j.get("type").and_then(|t| t.as_str()))
                        == Some("connection_init");

                    if !is_init {
                        report_handshake(WsHandshakeOutcome::ProtocolViolation, None);
                        let error = serde_json::json!({
                            "type": "connection_error",
                            "payload": {
                                "message": "Protocol violation: expected connection_init"
                            }
                        });
                        if let Ok(error_text) = serde_json::to_string(&error) {
                            let _ = socket.send(Message::Text(error_text.into())).await;
                        }
                        let _ = socket.close().await;
                        return;
                    }

                    // Check if authenticated
                    match &auth_result {
                        Ok(_) => {
                            // Send connection_ack
                            let ack = serde_json::json!({
                                "type": "connection_ack"
                            });
                            if let Ok(ack_text) = serde_json::to_string(&ack) {
                                let _ = socket.send(Message::Text(ack_text.into())).await;
                            }
                            report_handshake(WsHandshakeOutcome::Authenticated, None);
                            // MCP-633: mark init complete before exiting the loop.
                            init_received = true;
                            break;
                        }
                        Err((refusal, detail)) => {
                            // Authentication failed: ONE caller-facing sentence for
                            // all three token outcomes; the split is the operator's.
                            report_handshake(*refusal, detail.as_deref());
                            let error = serde_json::json!({
                                "type": "connection_error",
                                "payload": {
                                    "message": "Authentication required"
                                }
                            });
                            if let Ok(error_text) = serde_json::to_string(&error) {
                                let _ = socket.send(Message::Text(error_text.into())).await;
                            }
                            let _ = socket.close().await;
                            return;
                        }
                    }
                }
                Message::Close(_) => {
                    // Left before connection_init: the same ending as the
                    // deadline, reported below.
                    break;
                }
                _ => {}
            }
        }
    }

    // MCP-633: refuse to enter the GraphQL session if connection_init
    // was never observed. The loop above breaks ONLY after a successful
    // init+auth handshake; if we exit via init_deadline timeout, socket
    // close, or any non-Text message starvation, `init_received` stays
    // false and we close instead of falling through. Without this gate,
    // a client that authenticated via the access token but never sent
    // connection_init would enter `handle_graphql_ws` in an undefined
    // protocol state. async-graphql's downstream handler would soft-fail,
    // but the right behavior is to refuse explicitly.
    if !init_received {
        let pending = auth_result
            .as_ref()
            .err()
            .map(|(refusal, _)| refusal.as_str());
        report_handshake(WsHandshakeOutcome::InitNotReceived, pending);
        let _ = socket.close().await;
        return;
    }

    // If authenticated, inject user_id into schema data and continue with GraphQL protocol.
    // Wrap the session in a hard deadline matching the token expiry: the connection is closed
    // when the access token expires, bounding exposure from stolen or later-revoked tokens.
    if let Ok((user_id, is_2fa_verified, deadline)) = auth_result {
        // Holding the guard IS the session's presence in
        // `talos_ws_active_sessions`; it is released however the session ends.
        let _active = WsActiveSession::open();
        let ended = match tokio::time::timeout_at(
            deadline,
            handle_graphql_ws(socket, schema, user_id, is_2fa_verified),
        )
        .await
        {
            Ok(end) => end,
            Err(_) => {
                tracing::info!(user_id = %user_id, "WebSocket connection closed: access token expired");
                WsSessionEnd::TokenExpired
            }
        };
        talos_metrics::record_ws_session_end(ended);
    }
}

/// Handle GraphQL WebSocket protocol after authentication. Returns how the
/// session ended; the caller records it.
async fn handle_graphql_ws(
    socket: WebSocket,
    schema: talos_api::TalosSchema,
    user_id: Uuid,
    is_2fa_verified: bool,
) -> WsSessionEnd {
    let (mut sink, mut stream) = socket.split();

    // Process incoming messages
    while let Some(msg) = stream.next().await {
        if let Ok(msg) = msg {
            match msg {
                Message::Text(text) => {
                    // MCP-1118 (2026-05-16): log byte-length only.
                    // Pre-fix `WebSocket received message: {}` printed
                    // the full message body at debug level. The body
                    // is operator-supplied GraphQL — including
                    // subscription `payload.query`, `payload.variables`,
                    // and any operationName. Variables routinely carry
                    // sensitive content: auth-related mutation inputs
                    // (currentPassword for changePassword), secret-
                    // setter payloads (`createSecret(input: {value:
                    // "sk-..."})`), session tokens passed as variables
                    // on the WS path. An operator running with
                    // `RUST_LOG=debug` (common during incident triage)
                    // would have written every authenticated user's
                    // sensitive variables into the log aggregator
                    // verbatim. Per CLAUDE.md "NEVER log sensitive
                    // values (tokens, cookies, API keys, secrets)";
                    // log presence + size only. Same shape as MCP-531
                    // (REST auth Cookie header presence-only).
                    tracing::debug!(byte_len = text.len(), "WebSocket received message");
                    // Parse as GraphQL WS message
                    if let Ok(ws_msg) = serde_json::from_str::<serde_json::Value>(&text) {
                        let msg_type = ws_msg.get("type").and_then(|t| t.as_str());
                        tracing::debug!("WebSocket message type: {:?}", msg_type);

                        match msg_type {
                            Some("start") | Some("subscribe") => {
                                tracing::info!("WebSocket subscription start received");
                                // Handle subscription
                                if let Some(id) = ws_msg.get("id").and_then(|i| i.as_str()) {
                                    if let Some(payload) = ws_msg.get("payload") {
                                        if let Ok(request) =
                                            serde_json::from_value::<async_graphql::Request>(
                                                payload.clone(),
                                            )
                                        {
                                            // 2026-09-10: the WebSocket lane
                                            // executes SUBSCRIPTIONS only.
                                            // `execute_stream` will happily run
                                            // a query or a mutation as a
                                            // one-item stream, which made `/ws`
                                            // a second mutation transport
                                            // without the HTTP lane's CSRF
                                            // discipline. An operation that
                                            // does not parse or cannot be
                                            // classified is refused too.
                                            match talos_api::schema::operation_is_subscription(
                                                &request.query,
                                                request.operation_name.as_deref(),
                                            ) {
                                                Ok(true) => {}
                                                Ok(false) | Err(_) => {
                                                    talos_metrics::record_ws_operation(
                                                        WsOperationOutcome::RefusedNonSubscription,
                                                    );
                                                    tracing::warn!(
                                                        target: "talos_audit",
                                                        event_kind = "ws_non_subscription_refused",
                                                        %user_id,
                                                        "WebSocket lane refused a non-subscription operation"
                                                    );
                                                    let err_msg = serde_json::json!({
                                                        "type": "error",
                                                        "id": id,
                                                        "payload": [{
                                                            "message": "Only subscription \
                                                                operations may be executed \
                                                                over the WebSocket transport. \
                                                                Send queries and mutations to \
                                                                POST /graphql."
                                                        }]
                                                    });
                                                    if let Ok(err_text) =
                                                        serde_json::to_string(&err_msg)
                                                    {
                                                        let _ = sink
                                                            .send(Message::Text(err_text.into()))
                                                            .await;
                                                    }
                                                    continue;
                                                }
                                            }

                                            // Security review 2026-07-19 (P3):
                                            // a pre-2FA (password-only) session
                                            // may not open subscriptions — none
                                            // are auth-bootstrap operations, so
                                            // the allowlist rejects them all.
                                            // Mirrors the HTTP graphql_handler
                                            // gate and the REST pre-2FA 403.
                                            if !is_2fa_verified
                                                && !talos_api::schema::pre_2fa_operation_allowed(
                                                    &request.query,
                                                    request.operation_name.as_deref(),
                                                )
                                            {
                                                talos_metrics::record_ws_operation(
                                                    WsOperationOutcome::RefusedPreSecondFactor,
                                                );
                                                let err_msg = serde_json::json!({
                                                    "type": "error",
                                                    "id": id,
                                                    "payload": [{
                                                        "message": "Two-Factor Authentication \
                                                            required. Complete 2FA verification \
                                                            to subscribe."
                                                    }]
                                                });
                                                if let Ok(err_text) =
                                                    serde_json::to_string(&err_msg)
                                                {
                                                    let _ = sink
                                                        .send(Message::Text(err_text.into()))
                                                        .await;
                                                }
                                                continue;
                                            }

                                            // Add user_id and 2FA status to request data
                                            let req = request.data(user_id).data(
                                                talos_api::schema::IsTwoFactorVerified(
                                                    is_2fa_verified,
                                                ),
                                            );

                                            // Execute subscription
                                            talos_metrics::record_ws_operation(
                                                WsOperationOutcome::Started,
                                            );
                                            let mut response_stream = schema.execute_stream(req);

                                            // Send data messages
                                            while let Some(mut response) =
                                                response_stream.next().await
                                            {
                                                // 2026-09-10: same production
                                                // error scrubber as the HTTP
                                                // `graphql_handler` — one home.
                                                talos_api::schema::scrub_response_errors(
                                                    &mut response,
                                                );
                                                let data_msg = serde_json::json!({
                                                    "type": "data",
                                                    "id": id,
                                                    "payload": response
                                                });

                                                if let Ok(data_text) =
                                                    serde_json::to_string(&data_msg)
                                                {
                                                    if sink
                                                        .send(Message::Text(data_text.into()))
                                                        .await
                                                        .is_err()
                                                    {
                                                        break;
                                                    }
                                                }
                                            }

                                            // Send complete message
                                            let complete_msg = serde_json::json!({
                                                "type": "complete",
                                                "id": id
                                            });
                                            if let Ok(complete_text) =
                                                serde_json::to_string(&complete_msg)
                                            {
                                                let _ = sink
                                                    .send(Message::Text(complete_text.into()))
                                                    .await;
                                            }
                                        }
                                    }
                                }
                            }
                            Some("stop") => {
                                // Handle stop message
                                if let Some(id) = ws_msg.get("id").and_then(|i| i.as_str()) {
                                    let complete_msg = serde_json::json!({
                                        "type": "complete",
                                        "id": id
                                    });
                                    if let Ok(complete_text) = serde_json::to_string(&complete_msg)
                                    {
                                        let _ =
                                            sink.send(Message::Text(complete_text.into())).await;
                                    }
                                }
                            }
                            Some("connection_terminate") => {
                                return WsSessionEnd::ClientTerminated;
                            }
                            _ => {}
                        }
                    }
                }
                Message::Close(_) => {
                    return WsSessionEnd::ClientTerminated;
                }
                _ => {}
            }
        }
    }
    WsSessionEnd::StreamEnded
}

#[cfg(test)]
mod handshake_classification_tests {
    use super::{classify_auth, classify_origin, WsAuth};
    use axum::http::HeaderValue;
    use talos_metrics::WsHandshakeOutcome as O;
    use uuid::Uuid;

    fn allowed(o: &str) -> bool {
        o == "https://app.example"
    }

    #[test]
    fn origin_absent_is_refused_in_production_only() {
        assert_eq!(classify_origin(None, true, allowed), Err(O::OriginMissing));
        assert_eq!(classify_origin(None, false, allowed), Ok(()));
    }

    #[test]
    fn origin_not_on_the_allow_list_is_refused_whatever_the_environment() {
        let h = HeaderValue::from_static("https://evil.example");
        assert_eq!(
            classify_origin(Some(&h), true, allowed),
            Err(O::OriginNotAllowed)
        );
        assert_eq!(
            classify_origin(Some(&h), false, allowed),
            Err(O::OriginNotAllowed)
        );
        let ok = HeaderValue::from_static("https://app.example");
        assert_eq!(classify_origin(Some(&ok), true, allowed), Ok(()));
    }

    #[test]
    fn a_non_utf8_origin_is_malformed_not_merely_disallowed() {
        let h = HeaderValue::from_bytes(b"https://\xff.example").unwrap();
        assert_eq!(
            classify_origin(Some(&h), true, allowed),
            Err(O::OriginMalformed)
        );
    }

    #[test]
    fn the_three_token_refusals_are_told_apart_for_the_operator() {
        let uid = Uuid::new_v4();
        let good = |_: &str| Ok((uid.to_string(), true, 1_000_100_i64));
        assert_eq!(
            classify_auth(None, good, 1_000_000),
            Err((O::NoToken, None))
        );
        assert_eq!(
            classify_auth(
                Some("t"),
                |_| Err("ExpiredSignature".to_string()),
                1_000_000
            ),
            Err((O::InvalidToken, Some("ExpiredSignature".to_string())))
        );
        assert_eq!(
            classify_auth(
                Some("t"),
                |_| Ok(("not-a-uuid".to_string(), true, 1_000_100)),
                1_000_000
            ),
            Err((O::InvalidUserId, None))
        );
        assert_eq!(
            classify_auth(Some("t"), good, 1_000_000),
            Ok(WsAuth {
                user_id: uid,
                is_2fa_verified: true,
                secs_until_expiry: 100,
            })
        );
    }

    #[test]
    fn an_already_expired_token_yields_a_zero_second_session_not_a_wraparound() {
        let uid = Uuid::new_v4();
        let past = |_: &str| Ok((uid.to_string(), false, 5_i64));
        let auth = classify_auth(Some("t"), past, 1_000_000).unwrap();
        assert_eq!(auth.secs_until_expiry, 0);
        let negative = |_: &str| Ok((uid.to_string(), false, -1_i64));
        assert_eq!(
            classify_auth(Some("t"), negative, 10)
                .unwrap()
                .secs_until_expiry,
            0
        );
    }

    /// TEXTUAL pin, stated as such: the handshake reports through ONE site
    /// and every outcome is reachable from production code; the session end
    /// and the operation outcomes are recorded at their arms. The production
    /// half is everything ABOVE this module.
    #[test]
    fn every_outcome_is_recorded_from_production_code() {
        let src = include_str!("lib.rs");
        let production = &src[..src.find("mod handshake_classification_tests").unwrap()];
        assert_eq!(
            production.matches("report_handshake(").count(),
            6,
            "5 call sites + the fn"
        );
        for variant in [
            "OriginMissing",
            "OriginMalformed",
            "OriginNotAllowed",
            "NoToken",
            "InvalidToken",
            "InvalidUserId",
            "ProtocolViolation",
            "InitNotReceived",
            "Authenticated",
        ] {
            assert!(
                production.contains(&format!("WsHandshakeOutcome::{variant}")),
                "{variant} is never produced by production code"
            );
        }
        assert_eq!(
            production
                .matches("talos_metrics::record_ws_session_end(")
                .count(),
            1
        );
        assert_eq!(production.matches("WsSessionEnd::TokenExpired").count(), 1);
        assert_eq!(
            production.matches("WsSessionEnd::ClientTerminated").count(),
            2
        );
        assert_eq!(production.matches("WsSessionEnd::StreamEnded").count(), 1);
        assert_eq!(
            production
                .matches("talos_metrics::record_ws_operation(")
                .count(),
            3
        );
        assert_eq!(production.matches("WsActiveSession::open()").count(), 1);
    }
}
