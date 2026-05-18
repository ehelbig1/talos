use axum::extract::ws::{Message, WebSocket};
use futures_util::{stream::StreamExt, SinkExt};
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::AuthService;

/// Custom WebSocket handler that validates JWT tokens on connection
/// Token is extracted from httpOnly cookie in the upgrade request (secure!)
pub async fn handle_websocket_auth(
    mut socket: WebSocket,
    schema: crate::TalosSchema,
    auth_service: Arc<AuthService>,
    access_token: Option<String>,
) {
    // Authenticate using token from cookie (extracted from HTTP headers)
    let authenticated_user_id: Option<Uuid> = if let Some(token) = access_token {
        match auth_service.verify_token(&token) {
            Ok(claims) => match Uuid::parse_str(&claims.sub) {
                Ok(user_id) => {
                    tracing::info!("WebSocket authenticated for user: {} (via cookie)", user_id);
                    Some(user_id)
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

    // Wait for connection_init message (no auth required - already done via cookie)
    while let Some(msg) = socket.recv().await {
        if let Ok(msg) = msg {
            match msg {
                Message::Text(text) => {
                    // Try to parse as JSON
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                        if json.get("type").and_then(|t| t.as_str()) == Some("connection_init") {
                            // Check if authenticated
                            if authenticated_user_id.is_some() {
                                // Send connection_ack
                                let ack = serde_json::json!({
                                    "type": "connection_ack"
                                });
                                if let Ok(ack_text) = serde_json::to_string(&ack) {
                                    let _ = socket.send(Message::Text(ack_text.into())).await;
                                }
                                break;
                            } else {
                                // Authentication failed
                                tracing::warn!(
                                    "WebSocket connection_init received but not authenticated"
                                );
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
                }
                Message::Close(_) => {
                    return;
                }
                _ => {}
            }
        }
    }

    // If authenticated, inject user_id into schema data and continue with GraphQL protocol
    if let Some(user_id) = authenticated_user_id {
        // Handle GraphQL WebSocket protocol
        handle_graphql_ws(socket, schema, user_id).await;
    }
}

/// Handle GraphQL WebSocket protocol after authentication
async fn handle_graphql_ws(socket: WebSocket, schema: crate::TalosSchema, user_id: Uuid) {
    let (mut sink, mut stream) = socket.split();

    // Process incoming messages
    while let Some(msg) = stream.next().await {
        if let Ok(msg) = msg {
            match msg {
                Message::Text(text) => {
                    tracing::debug!("WebSocket received message: {}", text);
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
                                            // Add user_id to request data
                                            let req = request.data(user_id);

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
