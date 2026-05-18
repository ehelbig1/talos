use talos_sdk_macros::talos_module;

#[talos_module(world = "messaging-node")]
fn run(input: String) -> Result<String, String> {
    use talos::core::logging::{self, Level};
    use talos::core::messaging;
    use talos::core::{env, datetime, crypto};

        // Parse input
        let input_json: serde_json::Value = serde_json::from_str(&input)
            .map_err(|e| format!("Invalid JSON input: {}", e))?;

        // Get config
        let config = input_json.get("config")
            .ok_or("Missing config")?;

        let topic = config.get("topic")
            .and_then(|v| v.as_str())
            .ok_or("Missing topic")?;

        let message = config.get("message")
            .and_then(|v| v.as_str())
            .ok_or("Missing message")?;

        let add_metadata = config.get("add_metadata")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        // Build message payload
        let payload = if add_metadata {
            // Parse original message as JSON
            let msg_json: serde_json::Value = serde_json::from_str(message)
                .unwrap_or(serde_json::json!({"text": message}));

            // Add metadata
            let workflow_id = env::get_workflow_id();
            let execution_id = env::get_execution_id();
            let timestamp = datetime::now_iso();
            let message_id = crypto::uuid();

            let enhanced = serde_json::json!({
                "message_id": message_id,
                "timestamp": timestamp,
                "workflow_id": workflow_id,
                "execution_id": execution_id,
                "payload": msg_json
            });

            serde_json::to_string(&enhanced)
                .map_err(|e| format!("Failed to serialize message: {}", e))?
        } else {
            message.to_string()
        };

        // Enforce message size limit to prevent memory exhaustion in the message queue.
        const MAX_PAYLOAD_BYTES: usize = 1_000_000; // 1 MB
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(format!(
                "Message payload too large ({} bytes); limit is {} bytes",
                payload.len(),
                MAX_PAYLOAD_BYTES
            ));
        }

        logging::log(Level::Info, &format!("Publishing message to topic: {}", topic));
        logging::log(Level::Debug, &format!("Message payload: {} bytes", payload.len()));

        // Publish message
        messaging::publish(topic, payload.as_bytes())
            .map_err(|_| "Failed to publish message — check topic name and messaging configuration".to_string())?;

        logging::log(Level::Info, "Message published successfully");

        // Return result
        let result = serde_json::json!({
            "success": true,
            "topic": topic,
            "bytes_sent": payload.len()
        });

        serde_json::to_string(&result)
            .map_err(|e| format!("Failed to serialize result: {}", e))
    }
