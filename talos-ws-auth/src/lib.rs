// async-graphql 7.x type-walks the talos-api MutationRoot under cargo
// build in a way that exceeds the default 128-deep query layout limit.
// Same fix as controller::lib (commit 47258c0).
#![recursion_limit = "256"]

use axum::extract::ws::{Message, WebSocket};
use axum::http::HeaderValue;
use futures::{stream::StreamExt, Sink, SinkExt, Stream};
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

/// Per-socket cap on concurrently open subscriptions (package DV). The
/// dashboard's busiest page holds four; a client asking for more is a bug or
/// a probe, and every open subscription is a spawned task and a live
/// `execute_stream`, so the cap bounds what one authenticated socket can
/// cost the controller. A `start` past the cap is refused with an `error`
/// frame and counted; existing subscriptions are untouched.
pub const MAX_SUBSCRIPTIONS_PER_SOCKET: usize = 16;

/// Frames waiting for the socket writer. Subscription tasks `await` on a
/// full buffer (backpressure to the stream, not memory growth); the buffer
/// only has to absorb a burst across the `MAX_SUBSCRIPTIONS_PER_SOCKET`
/// tasks that share it.
const OUTBOUND_FRAME_BUFFER: usize = 256;

/// Everything the session spawned, aborted on drop. The session future is
/// what the handshake wraps in the token-expiry deadline, and a timed-out
/// future is DROPPED — so this guard, not a code path, is what guarantees
/// that no subscription task or writer outlives its socket.
struct SessionTasks {
    writer: tokio::task::JoinHandle<()>,
    subscriptions: std::collections::HashMap<String, tokio::task::JoinHandle<()>>,
}

impl Drop for SessionTasks {
    fn drop(&mut self) {
        for (_, handle) in self.subscriptions.drain() {
            handle.abort();
        }
        self.writer.abort();
    }
}

impl SessionTasks {
    /// Drop handles whose task already finished (the stream completed), so a
    /// long session cannot fill the map with dead entries and a completed
    /// id may be reused.
    fn reap(&mut self) {
        self.subscriptions.retain(|_, h| !h.is_finished());
    }
}

fn text_frame(value: &serde_json::Value) -> Option<Message> {
    serde_json::to_string(value)
        .ok()
        .map(|t| Message::Text(t.into()))
}

fn error_frame(id: &str, message: &str) -> Option<Message> {
    text_frame(&serde_json::json!({
        "type": "error",
        "id": id,
        "payload": [{ "message": message }]
    }))
}

/// Handle the graphql-ws protocol after authentication and return how the
/// session ended; the caller records it.
///
/// Since package DV (2026-09-22) one socket carries MANY subscriptions: each
/// `start` spawns its own task streaming `data` frames through ONE bounded
/// channel to ONE writer task, `stop` aborts the named task, and every task
/// is aborted when the session ends however it ends (`SessionTasks`' Drop).
/// Before this the `start` arm awaited the whole response stream INSIDE the
/// read loop, so a second `start` on the same socket was not read until the
/// first subscription completed, and `stop` echoed `complete` without
/// ending anything — the lane worked only because the frontend opened one
/// socket per subscription (three per dashboard load).
///
/// Generic over the transport and the schema so a test can drive it with a
/// channel-backed duplex and a two-field schema; production passes the axum
/// socket and `TalosSchema`.
async fn handle_graphql_ws<T, Q, M, S>(
    socket: T,
    schema: async_graphql::Schema<Q, M, S>,
    user_id: Uuid,
    is_2fa_verified: bool,
) -> WsSessionEnd
where
    T: Stream<Item = Result<Message, axum::Error>> + Sink<Message> + Unpin + Send + 'static,
    <T as Sink<Message>>::Error: std::fmt::Debug,
    Q: async_graphql::ObjectType + 'static,
    M: async_graphql::ObjectType + 'static,
    S: async_graphql::SubscriptionType + 'static,
{
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(OUTBOUND_FRAME_BUFFER);
    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if sink.send(frame).await.is_err() {
                break;
            }
        }
    });
    let mut tasks = SessionTasks {
        writer,
        subscriptions: std::collections::HashMap::new(),
    };

    while let Some(msg) = stream.next().await {
        let Ok(msg) = msg else { continue };
        match msg {
            Message::Text(text) => {
                // MCP-1118 (2026-05-16): log byte-length only. The body is
                // operator-supplied GraphQL — subscription `payload.query`,
                // `payload.variables`, operationName — and variables can
                // carry sensitive content; per CLAUDE.md "NEVER log
                // sensitive values", log presence + size only (same shape as
                // MCP-531, REST auth Cookie header presence-only).
                tracing::debug!(byte_len = text.len(), "WebSocket received message");
                let Ok(ws_msg) = serde_json::from_str::<serde_json::Value>(&text) else {
                    continue;
                };
                let msg_type = ws_msg.get("type").and_then(|t| t.as_str());
                tracing::debug!("WebSocket message type: {:?}", msg_type);

                match msg_type {
                    Some("start") | Some("subscribe") => {
                        tracing::info!("WebSocket subscription start received");
                        let Some(id) = ws_msg.get("id").and_then(|i| i.as_str()) else {
                            continue;
                        };
                        let Some(payload) = ws_msg.get("payload") else {
                            continue;
                        };
                        let Ok(request) =
                            serde_json::from_value::<async_graphql::Request>(payload.clone())
                        else {
                            continue;
                        };

                        // 2026-09-10: the WebSocket lane executes SUBSCRIPTIONS
                        // only. `execute_stream` will happily run a query or a
                        // mutation as a one-item stream, which made `/ws` a
                        // second mutation transport without the HTTP lane's
                        // CSRF discipline. An operation that does not parse or
                        // cannot be classified is refused too.
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
                                if let Some(frame) = error_frame(
                                    id,
                                    "Only subscription operations may be executed over the \
                                     WebSocket transport. Send queries and mutations to \
                                     POST /graphql.",
                                ) {
                                    let _ = tx.send(frame).await;
                                }
                                continue;
                            }
                        }

                        // Security review 2026-07-19 (P3): a pre-2FA
                        // (password-only) session may not open subscriptions —
                        // none are auth-bootstrap operations, so the allowlist
                        // rejects them all. Mirrors the HTTP graphql_handler
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
                            if let Some(frame) = error_frame(
                                id,
                                "Two-Factor Authentication required. Complete 2FA \
                                 verification to subscribe.",
                            ) {
                                let _ = tx.send(frame).await;
                            }
                            continue;
                        }

                        tasks.reap();
                        if tasks.subscriptions.contains_key(id) {
                            talos_metrics::record_ws_operation(
                                WsOperationOutcome::RefusedDuplicateId,
                            );
                            tracing::warn!(
                                target: "talos_ws_auth",
                                event_kind = "ws_duplicate_subscription_id",
                                %user_id,
                                "WebSocket start reused a live subscription id"
                            );
                            if let Some(frame) =
                                error_frame(id, "A subscription with this id is already open.")
                            {
                                let _ = tx.send(frame).await;
                            }
                            continue;
                        }
                        if tasks.subscriptions.len() >= MAX_SUBSCRIPTIONS_PER_SOCKET {
                            talos_metrics::record_ws_operation(
                                WsOperationOutcome::RefusedTooManySubscriptions,
                            );
                            tracing::warn!(
                                target: "talos_audit",
                                event_kind = "ws_subscription_cap_refused",
                                %user_id,
                                open = tasks.subscriptions.len(),
                                cap = MAX_SUBSCRIPTIONS_PER_SOCKET,
                                "WebSocket start refused: per-socket subscription cap"
                            );
                            if let Some(frame) =
                                error_frame(id, "Too many open subscriptions on this connection.")
                            {
                                let _ = tx.send(frame).await;
                            }
                            continue;
                        }

                        // Add user_id and 2FA status to request data
                        let req = request
                            .data(user_id)
                            .data(talos_api::schema::IsTwoFactorVerified(is_2fa_verified));

                        talos_metrics::record_ws_operation(WsOperationOutcome::Started);
                        let mut response_stream = schema.execute_stream(req);
                        let sub_tx = tx.clone();
                        let sub_id = id.to_string();
                        let handle = tokio::spawn(async move {
                            while let Some(mut response) = response_stream.next().await {
                                // 2026-09-10: same production error scrubber as
                                // the HTTP `graphql_handler` — one home.
                                talos_api::schema::scrub_response_errors(&mut response);
                                let Some(frame) = text_frame(&serde_json::json!({
                                    "type": "data",
                                    "id": sub_id,
                                    "payload": response
                                })) else {
                                    continue;
                                };
                                if sub_tx.send(frame).await.is_err() {
                                    return;
                                }
                            }
                            if let Some(frame) = text_frame(&serde_json::json!({
                                "type": "complete",
                                "id": sub_id
                            })) {
                                let _ = sub_tx.send(frame).await;
                            }
                        });
                        tasks.subscriptions.insert(id.to_string(), handle);
                    }
                    Some("stop") => {
                        if let Some(id) = ws_msg.get("id").and_then(|i| i.as_str()) {
                            // Abort the stream — before DV this only echoed
                            // `complete` and the server-side stream ran on
                            // until the socket closed.
                            if let Some(handle) = tasks.subscriptions.remove(id) {
                                handle.abort();
                            }
                            if let Some(frame) = text_frame(&serde_json::json!({
                                "type": "complete",
                                "id": id
                            })) {
                                let _ = tx.send(frame).await;
                            }
                        }
                    }
                    Some("connection_terminate") => {
                        return WsSessionEnd::ClientTerminated;
                    }
                    _ => {}
                }
            }
            Message::Close(_) => {
                return WsSessionEnd::ClientTerminated;
            }
            _ => {}
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
            5
        );
        assert_eq!(production.matches("WsActiveSession::open()").count(), 1);
    }
}

/// Package DV: the session loop driven end to end over a channel-backed
/// transport and a two-field schema. Every case here is impossible on the
/// pre-DV loop by construction — it awaited one subscription's whole stream
/// inside the read loop, so a second `start` was never read.
#[cfg(test)]
mod multiplex_tests {
    use super::{handle_graphql_ws, MAX_SUBSCRIPTIONS_PER_SOCKET};
    use axum::extract::ws::Message;
    use futures::channel::mpsc;
    use futures::{Sink, Stream, StreamExt};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Context as TaskContext, Poll};
    use std::time::Duration;
    use talos_metrics::WsSessionEnd;
    use uuid::Uuid;

    /// A socket stand-in: the test writes inbound frames, reads outbound ones.
    struct Duplex {
        inbound: mpsc::UnboundedReceiver<Result<Message, axum::Error>>,
        outbound: mpsc::UnboundedSender<Message>,
    }

    impl Stream for Duplex {
        type Item = Result<Message, axum::Error>;
        fn poll_next(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
        ) -> Poll<Option<Self::Item>> {
            Pin::new(&mut self.inbound).poll_next(cx)
        }
    }

    impl Sink<Message> for Duplex {
        type Error = ();
        fn poll_ready(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<Result<(), ()>> {
            Poll::Ready(Ok(()))
        }
        fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), ()> {
            self.outbound.unbounded_send(item).map_err(|_| ())
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<Result<(), ()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<Result<(), ()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A subscription stream that never yields and never ends; its guard
    /// counts how many are alive, which is how "the task was aborted" is
    /// observed from outside.
    struct Forever(Arc<AtomicUsize>);
    impl Forever {
        fn new(live: Arc<AtomicUsize>) -> Self {
            live.fetch_add(1, Ordering::SeqCst);
            Self(live)
        }
    }
    impl Drop for Forever {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    impl Stream for Forever {
        type Item = i32;
        fn poll_next(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<Option<i32>> {
            Poll::Pending
        }
    }

    struct TestQuery;
    #[async_graphql::Object]
    impl TestQuery {
        async fn ok(&self) -> bool {
            true
        }
    }

    struct TestSubscription;
    #[async_graphql::Subscription]
    impl TestSubscription {
        async fn ticks(&self, n: i32) -> impl Stream<Item = i32> {
            futures::stream::iter(0..n)
        }
        async fn forever(&self, ctx: &async_graphql::Context<'_>) -> impl Stream<Item = i32> {
            Forever::new(ctx.data_unchecked::<Arc<AtomicUsize>>().clone())
        }
    }

    type TestSchema =
        async_graphql::Schema<TestQuery, async_graphql::EmptyMutation, TestSubscription>;

    struct Harness {
        to_server: mpsc::UnboundedSender<Result<Message, axum::Error>>,
        from_server: mpsc::UnboundedReceiver<Message>,
        live: Arc<AtomicUsize>,
        session: tokio::task::JoinHandle<WsSessionEnd>,
    }

    /// The process-global registry is shared by every test in this binary, so
    /// the tests that record or read `talos_ws_operations_total` serialise.
    static SERIES_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn registry() -> &'static Arc<talos_metrics::TalosMetrics> {
        if talos_metrics::global().is_none() {
            talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("registry"));
        }
        talos_metrics::global().expect("installed above")
    }

    fn spawn_session() -> Harness {
        let live = Arc::new(AtomicUsize::new(0));
        let schema: TestSchema =
            async_graphql::Schema::build(TestQuery, async_graphql::EmptyMutation, TestSubscription)
                .data(live.clone())
                .finish();
        let (to_server, inbound) = mpsc::unbounded();
        let (outbound, from_server) = mpsc::unbounded();
        let duplex = Duplex { inbound, outbound };
        let session = tokio::spawn(handle_graphql_ws(duplex, schema, Uuid::new_v4(), true));
        Harness {
            to_server,
            from_server,
            live,
            session,
        }
    }

    fn frame(v: serde_json::Value) -> Result<Message, axum::Error> {
        Ok(Message::Text(v.to_string().into()))
    }

    fn start(id: &str, query: &str) -> Result<Message, axum::Error> {
        frame(serde_json::json!({
            "id": id,
            "type": "start",
            "payload": { "query": query }
        }))
    }

    fn stop(id: &str) -> Result<Message, axum::Error> {
        frame(serde_json::json!({ "id": id, "type": "stop" }))
    }

    async fn next_frame(h: &mut Harness) -> serde_json::Value {
        let m = tokio::time::timeout(Duration::from_secs(2), h.from_server.next())
            .await
            .expect("a frame within 2 s")
            .expect("the server did not close");
        match m {
            Message::Text(t) => serde_json::from_str(&t).expect("json frame"),
            other => panic!("unexpected frame {other:?}"),
        }
    }

    async fn wait_live(h: &Harness, want: usize) {
        wait_live_on(&h.live, want).await;
    }

    async fn wait_live_on(live: &Arc<AtomicUsize>, want: usize) {
        for _ in 0..200 {
            if live.load(Ordering::SeqCst) == want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "live subscriptions stuck at {} (wanted {want})",
            live.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn a_second_subscription_is_served_while_the_first_is_still_streaming() {
        let _g = SERIES_LOCK.lock().await;
        let mut h = spawn_session();
        h.to_server
            .unbounded_send(start("a", "subscription { forever }"))
            .unwrap();
        wait_live(&h, 1).await;
        h.to_server
            .unbounded_send(start("b", "subscription { ticks(n: 2) }"))
            .unwrap();
        // Pre-DV the read loop was inside `a`'s stream and `b` was never read.
        let mut b_data = 0;
        loop {
            let f = next_frame(&mut h).await;
            assert_eq!(f["id"], "b", "only b produces frames: {f}");
            match f["type"].as_str() {
                Some("data") => {
                    b_data += 1;
                    assert_eq!(f["payload"]["data"]["ticks"], b_data - 1);
                }
                Some("complete") => break,
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(b_data, 2);
        assert_eq!(h.live.load(Ordering::SeqCst), 1, "a is still open");
        h.to_server.unbounded_send(stop("a")).unwrap();
        let f = next_frame(&mut h).await;
        assert_eq!(
            (f["type"].as_str(), f["id"].as_str()),
            (Some("complete"), Some("a"))
        );
        // `stop` ABORTS the stream server-side — pre-DV it ran on.
        wait_live(&h, 0).await;
        h.to_server
            .unbounded_send(frame(serde_json::json!({ "type": "connection_terminate" })))
            .unwrap();
        assert_eq!(h.session.await.unwrap(), WsSessionEnd::ClientTerminated);
    }

    #[tokio::test]
    async fn the_per_socket_cap_refuses_the_next_start_and_leaves_the_others_alone() {
        let _g = SERIES_LOCK.lock().await;
        let mut h = spawn_session();
        for i in 0..MAX_SUBSCRIPTIONS_PER_SOCKET {
            h.to_server
                .unbounded_send(start(&format!("s{i}"), "subscription { forever }"))
                .unwrap();
        }
        wait_live(&h, MAX_SUBSCRIPTIONS_PER_SOCKET).await;
        h.to_server
            .unbounded_send(start("overflow", "subscription { forever }"))
            .unwrap();
        let f = next_frame(&mut h).await;
        assert_eq!(
            (f["type"].as_str(), f["id"].as_str()),
            (Some("error"), Some("overflow"))
        );
        assert!(f["payload"][0]["message"]
            .as_str()
            .unwrap()
            .contains("Too many open subscriptions"));
        assert_eq!(h.live.load(Ordering::SeqCst), MAX_SUBSCRIPTIONS_PER_SOCKET);
        h.to_server
            .unbounded_send(frame(serde_json::json!({ "type": "connection_terminate" })))
            .unwrap();
        let live = h.live.clone();
        assert_eq!(h.session.await.unwrap(), WsSessionEnd::ClientTerminated);
        // Session end aborts every task.
        wait_live_on(&live, 0).await;
    }

    #[tokio::test]
    async fn a_live_id_cannot_be_reused_but_a_completed_one_can() {
        let _g = SERIES_LOCK.lock().await;
        let mut h = spawn_session();
        h.to_server
            .unbounded_send(start("x", "subscription { forever }"))
            .unwrap();
        wait_live(&h, 1).await;
        h.to_server
            .unbounded_send(start("x", "subscription { ticks(n: 1) }"))
            .unwrap();
        let f = next_frame(&mut h).await;
        assert_eq!(
            (f["type"].as_str(), f["id"].as_str()),
            (Some("error"), Some("x"))
        );
        assert!(f["payload"][0]["message"]
            .as_str()
            .unwrap()
            .contains("already open"));
        assert_eq!(
            h.live.load(Ordering::SeqCst),
            1,
            "the live one is untouched"
        );
        h.to_server.unbounded_send(stop("x")).unwrap();
        assert_eq!(next_frame(&mut h).await["type"], "complete");
        wait_live(&h, 0).await;
        // The id is free again once its task is gone.
        h.to_server
            .unbounded_send(start("x", "subscription { ticks(n: 1) }"))
            .unwrap();
        let d = next_frame(&mut h).await;
        assert_eq!(
            (d["type"].as_str(), d["id"].as_str()),
            (Some("data"), Some("x"))
        );
        assert_eq!(next_frame(&mut h).await["type"], "complete");
        // And an id freed by NATURAL completion (no `stop`) is reusable too —
        // that is `reap`'s job, and without it this third start is refused as
        // "already open" (mutation-proved). The task sends `complete` and
        // THEN returns, so `is_finished()` can lag the frame by microseconds;
        // a refusal is re-tried a bounded number of times rather than read as
        // the verdict. A deleted reap never frees the id and exhausts the
        // bound.
        let mut served = false;
        for _ in 0..50 {
            h.to_server
                .unbounded_send(start("x", "subscription { ticks(n: 1) }"))
                .unwrap();
            let f = next_frame(&mut h).await;
            if f["type"] == "error" {
                tokio::time::sleep(Duration::from_millis(5)).await;
                continue;
            }
            assert_eq!(
                (f["type"].as_str(), f["id"].as_str()),
                (Some("data"), Some("x"))
            );
            assert_eq!(next_frame(&mut h).await["type"], "complete");
            served = true;
            break;
        }
        assert!(served, "a naturally completed id was never freed");
        h.to_server
            .unbounded_send(frame(serde_json::json!({ "type": "connection_terminate" })))
            .unwrap();
        assert_eq!(h.session.await.unwrap(), WsSessionEnd::ClientTerminated);
    }

    /// The `started` series counts ACCEPTED starts only: a refused start
    /// moves its own refusal series and nothing else. Reads the real
    /// registry, so this test and its siblings serialise on `SERIES_LOCK`.
    #[tokio::test]
    async fn a_refused_start_moves_its_refusal_series_and_not_started() {
        let _g = SERIES_LOCK.lock().await;
        let m = registry();
        let read = |label: &str| m.ws_operations_total.with_label_values(&[label]).get();
        let (started0, dup0, cap0) = (
            read("started"),
            read("refused_duplicate_id"),
            read("refused_too_many"),
        );
        let mut h = spawn_session();
        h.to_server
            .unbounded_send(start("a", "subscription { forever }"))
            .unwrap();
        wait_live(&h, 1).await;
        assert_eq!(read("started") - started0, 1.0, "one accepted start");
        h.to_server
            .unbounded_send(start("a", "subscription { forever }"))
            .unwrap();
        assert_eq!(next_frame(&mut h).await["type"], "error");
        assert_eq!(read("refused_duplicate_id") - dup0, 1.0);
        assert_eq!(
            read("started") - started0,
            1.0,
            "the refused start did not count as started"
        );
        for i in 1..MAX_SUBSCRIPTIONS_PER_SOCKET {
            h.to_server
                .unbounded_send(start(&format!("s{i}"), "subscription { forever }"))
                .unwrap();
        }
        wait_live(&h, MAX_SUBSCRIPTIONS_PER_SOCKET).await;
        h.to_server
            .unbounded_send(start("over", "subscription { forever }"))
            .unwrap();
        assert_eq!(next_frame(&mut h).await["type"], "error");
        assert_eq!(read("refused_too_many") - cap0, 1.0);
        assert_eq!(
            read("started") - started0,
            MAX_SUBSCRIPTIONS_PER_SOCKET as f64,
            "exactly the accepted starts"
        );
        h.to_server
            .unbounded_send(frame(serde_json::json!({ "type": "connection_terminate" })))
            .unwrap();
        assert_eq!(h.session.await.unwrap(), WsSessionEnd::ClientTerminated);
    }

    /// The handshake wraps the session in the token-expiry deadline, and a
    /// timed-out future is DROPPED — this is that drop, and the guard is what
    /// makes it abort the spawned streams instead of orphaning them.
    #[tokio::test]
    async fn dropping_the_session_future_aborts_every_subscription_task() {
        let _g = SERIES_LOCK.lock().await;
        let h = spawn_session();
        h.to_server
            .unbounded_send(start("a", "subscription { forever }"))
            .unwrap();
        h.to_server
            .unbounded_send(start("b", "subscription { forever }"))
            .unwrap();
        wait_live(&h, 2).await;
        h.session.abort();
        wait_live(&h, 0).await;
    }

    #[tokio::test]
    async fn a_query_over_the_socket_is_refused_and_the_session_survives() {
        let _g = SERIES_LOCK.lock().await;
        let mut h = spawn_session();
        h.to_server
            .unbounded_send(start("q", "query { ok }"))
            .unwrap();
        let f = next_frame(&mut h).await;
        assert_eq!(
            (f["type"].as_str(), f["id"].as_str()),
            (Some("error"), Some("q"))
        );
        assert!(f["payload"][0]["message"]
            .as_str()
            .unwrap()
            .contains("Only subscription operations"));
        h.to_server
            .unbounded_send(start("s", "subscription { ticks(n: 1) }"))
            .unwrap();
        assert_eq!(next_frame(&mut h).await["type"], "data");
        assert_eq!(next_frame(&mut h).await["type"], "complete");
        // The transport ending without a terminate frame is `stream_ended`.
        drop(h.to_server);
        assert_eq!(h.session.await.unwrap(), WsSessionEnd::StreamEnded);
    }
}
