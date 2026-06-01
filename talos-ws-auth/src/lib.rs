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

/// Custom WebSocket handler that validates JWT tokens on connection
/// Token is extracted from httpOnly cookie in the upgrade request (secure!)
pub async fn handle_websocket_auth(
    mut socket: WebSocket,
    schema: talos_api::TalosSchema,
    auth_service: Arc<AuthService>,
    access_token: Option<String>,
    origin: Option<HeaderValue>,
) {
    // Validate Origin header to prevent Cross-Site WebSocket Hijacking (CSWH)
    if let Some(origin_val) = origin {
        if let Ok(origin_str) = origin_val.to_str() {
            if !config::is_allowed_origin(origin_str) {
                tracing::warn!(
                    "WebSocket connection rejected: unauthorized origin {:?}",
                    origin_val
                );
                let _ = socket.close().await;
                return;
            }
        } else {
            tracing::warn!("WebSocket connection rejected: invalid Origin header format");
            let _ = socket.close().await;
            return;
        }
    } else if config::is_production() {
        // In production, require an Origin header for security
        tracing::warn!("WebSocket connection rejected: missing Origin header in production");
        let _ = socket.close().await;
        return;
    }

    // Authenticate using token from cookie (extracted from HTTP headers).
    // We also capture the token's expiry so we can hard-terminate the connection
    // when the token expires — this covers the session-revocation case where an
    // attacker holds a stolen token that is later revoked server-side.
    let auth_result: Option<(Uuid, bool, tokio::time::Instant)> = if let Some(token) = access_token
    {
        match auth_service.verify_token(&token) {
            Ok(claims) => match Uuid::parse_str(&claims.sub) {
                Ok(user_id) => {
                    // Convert JWT exp (Unix seconds) → Instant for use with tokio timeout.
                    let now_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let secs_until_expiry = (claims.exp as u64).saturating_sub(now_secs);
                    let deadline = tokio::time::Instant::now()
                        + tokio::time::Duration::from_secs(secs_until_expiry);
                    tracing::info!(
                        user_id = %user_id,
                        is_2fa_verified = claims.is_2fa_verified,
                        expires_in_secs = secs_until_expiry,
                        "WebSocket authenticated (via cookie)"
                    );
                    Some((user_id, claims.is_2fa_verified, deadline))
                }
                Err(_) => {
                    tracing::warn!("WebSocket authentication failed: invalid user ID");
                    None
                }
            },
            Err(e) => {
                tracing::warn!("WebSocket authentication failed: {:?}", e);
                None
            }
        }
    } else {
        tracing::warn!("WebSocket authentication failed: no access token in cookie");
        None
    };

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
                        tracing::warn!(
                            target: "talos_ws_auth",
                            event_kind = "ws_protocol_violation",
                            "WebSocket first message was not connection_init — closing"
                        );
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
                    if auth_result.is_some() {
                        // Send connection_ack
                        let ack = serde_json::json!({
                            "type": "connection_ack"
                        });
                        if let Ok(ack_text) = serde_json::to_string(&ack) {
                            let _ = socket.send(Message::Text(ack_text.into())).await;
                        }
                        // MCP-633: mark init complete before exiting the loop.
                        init_received = true;
                        break;
                    } else {
                        // Authentication failed
                        tracing::warn!("WebSocket connection_init received but not authenticated");
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
                Message::Close(_) => {
                    return;
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
        tracing::warn!(
            target: "talos_ws_auth",
            event_kind = "ws_init_not_received",
            "WebSocket closed without observing connection_init within deadline"
        );
        let _ = socket.close().await;
        return;
    }

    // If authenticated, inject user_id into schema data and continue with GraphQL protocol.
    // Wrap the session in a hard deadline matching the token expiry: the connection is closed
    // when the access token expires, bounding exposure from stolen or later-revoked tokens.
    if let Some((user_id, is_2fa_verified, deadline)) = auth_result {
        if tokio::time::timeout_at(
            deadline,
            handle_graphql_ws(socket, schema, user_id, is_2fa_verified),
        )
        .await
        .is_err()
        {
            tracing::info!(user_id = %user_id, "WebSocket connection closed: access token expired");
        }
    }
}

/// Handle GraphQL WebSocket protocol after authentication
async fn handle_graphql_ws(
    socket: WebSocket,
    schema: talos_api::TalosSchema,
    user_id: Uuid,
    is_2fa_verified: bool,
) {
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
                                            // Add user_id and 2FA status to request data
                                            let req = request.data(user_id).data(
                                                talos_api::schema::IsTwoFactorVerified(
                                                    is_2fa_verified,
                                                ),
                                            );

                                            // Execute subscription
                                            let mut response_stream = schema.execute_stream(req);

                                            // Send data messages
                                            while let Some(response) = response_stream.next().await
                                            {
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
                                break;
                            }
                            _ => {}
                        }
                    }
                }
                Message::Close(_) => {
                    break;
                }
                _ => {}
            }
        }
    }
}
