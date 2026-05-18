use talos_sdk_macros::talos_module;

#[talos_module(world = "cache-node")]
fn run(input: String) -> Result<String, String> {
    use talos::core::logging::{self, Level};
    use talos::core::cache;

        // Parse input
        let input_json: serde_json::Value = serde_json::from_str(&input)
            .map_err(|e| format!("Invalid JSON input: {}", e))?;

        // Get config
        let config = input_json.get("config")
            .ok_or("Missing config")?;

        let operation = config.get("operation")
            .and_then(|v| v.as_str())
            .unwrap_or("get");

        let key = config.get("key")
            .and_then(|v| v.as_str())
            .ok_or("Missing cache key")?;

        // Perform cache operation
        let result = match operation {
            "get" => {
                match cache::get(key) {
                    Ok(value) => {
                        logging::log(Level::Info, &format!("Cache HIT: {}", key));
                        serde_json::json!({
                            "success": true,
                            "operation": "get",
                            "key": key,
                            "value": value,
                            "cache_hit": true
                        })
                    }
                    Err(_) => {
                        logging::log(Level::Info, &format!("Cache MISS: {}", key));
                        serde_json::json!({
                            "success": true,
                            "operation": "get",
                            "key": key,
                            "cache_hit": false
                        })
                    }
                }
            }
            "set" => {
                let value = config.get("value")
                    .and_then(|v| v.as_str())
                    .ok_or("Missing value for set operation")?;

                let ttl = config.get("ttl")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);

                cache::set(key, value, ttl)
                    .map_err(|e| format!("Cache set failed: {:?}", e))?;

                logging::log(Level::Info, &format!("Cache SET: {} (TTL: {:?}s)", key, ttl));

                serde_json::json!({
                    "success": true,
                    "operation": "set",
                    "key": key,
                    "ttl": ttl
                })
            }
            "delete" => {
                cache::delete(key)
                    .map_err(|e| format!("Cache delete failed: {:?}", e))?;

                logging::log(Level::Info, &format!("Cache DELETE: {}", key));

                serde_json::json!({
                    "success": true,
                    "operation": "delete",
                    "key": key
                })
            }
            "increment" => {
                let amount = config.get("amount")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(1);

                let new_value = cache::increment(key, amount)
                    .map_err(|e| format!("Cache increment failed: {:?}", e))?;

                logging::log(Level::Info, &format!("Cache INCREMENT: {} by {} = {}", key, amount, new_value));

                serde_json::json!({
                    "success": true,
                    "operation": "increment",
                    "key": key,
                    "value": new_value
                })
            }
            _ => return Err(format!("Unknown operation: {}", operation))
        };

        serde_json::to_string(&result)
            .map_err(|e| format!("Failed to serialize result: {}", e))
    }
