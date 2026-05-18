use talos_sdk_macros::talos_module;

#[talos_module(world = "minimal-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value = serde_json::from_str(&input)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    let config = input_json
        .get("config")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let selector = config
        .get("SELECTOR")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let transform_type = config
        .get("TRANSFORM")
        .and_then(|v| v.as_str())
        .unwrap_or("none");

    // Upstream node output arrives as the "input" key in the wrapped payload.
    // Fall back to the whole payload if a direct "input" key is absent.
    let data = input_json
        .get("input")
        .cloned()
        .unwrap_or_else(|| input_json.clone());

    // If SELECTOR is set, navigate the dot-notation path into data.
    // Supports "a.b.c" paths. Returns an error if any segment is missing.
    let mut selected = data;
    if !selector.is_empty() {
        for segment in selector.split('.') {
            selected = match selected.get(segment).cloned() {
                Some(v) => v,
                None => {
                    return Err(format!(
                        "Selector '{}' failed: key '{}' not found",
                        selector, segment
                    ))
                }
            };
        }
    }

    // Apply optional transform
    let result = match transform_type {
        "keys_to_lowercase" => {
            if let Some(obj) = selected.as_object() {
                let lowered: serde_json::Map<String, serde_json::Value> = obj
                    .iter()
                    .map(|(k, v)| (k.to_lowercase(), v.clone()))
                    .collect();
                serde_json::Value::Object(lowered)
            } else {
                selected
            }
        }
        "keys_to_uppercase" => {
            if let Some(obj) = selected.as_object() {
                let uppered: serde_json::Map<String, serde_json::Value> = obj
                    .iter()
                    .map(|(k, v)| (k.to_uppercase(), v.clone()))
                    .collect();
                serde_json::Value::Object(uppered)
            } else {
                selected
            }
        }
        "wrap" => serde_json::json!({ "value": selected }),
        _ => selected, // "none" or unrecognised: pass through as-is
    };

    Ok(serde_json::to_string(&result).unwrap_or_default())
}
