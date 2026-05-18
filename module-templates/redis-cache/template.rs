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
                // Find value from multiple sources (in priority order):
                // 1. Direct input.value (single upstream node output)
                // 2. Any top-level object with a "value" key (named upstream node output)
                // 3. __trigger_input__.value
                // 4. config.value (static)
                // 5. If all else fails, stringify the entire upstream input as the value
                let value: String = if let Some(v) = input_json.get("value").and_then(|v| v.as_str()) {
                    v.to_string()
                } else if let Some(v) = input_json.get("input").and_then(|i| i.get("value")).and_then(|v| v.as_str()) {
                    v.to_string()
                } else if let Some(v) = input_json.as_object().and_then(|obj| {
                    // Search all top-level objects for a "value" key (upstream node outputs are keyed by node name)
                    obj.iter()
                        .filter(|(k, _)| !k.starts_with("__") && *k != "config" && *k != "input")
                        .find_map(|(_, v)| {
                            v.get("value").and_then(|val| val.as_str().map(String::from))
                                .or_else(|| Some(v.to_string())) // Fallback: stringify the entire upstream output
                        })
                }) {
                    v
                } else if let Some(v) = input_json.get("__trigger_input__").and_then(|t| t.get("value")).and_then(|v| v.as_str()) {
                    v.to_string()
                } else if let Some(v) = config.get("value").and_then(|v| v.as_str()) {
                    v.to_string()
                } else {
                    return Err("Missing value for set operation. Pass value via upstream node output, trigger input, or config.value".to_string());
                };
                let value = &value;

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
