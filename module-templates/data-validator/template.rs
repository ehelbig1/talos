use talos_sdk_macros::talos_module;

#[talos_module(world = "minimal-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value = serde_json::from_str(&input)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    let config = input_json
        .get("config")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let validation_type = config
        .get("VALIDATION_TYPE")
        .and_then(|v| v.as_str())
        .unwrap_or("numeric");

    // Upstream node output arrives as the "input" key in the wrapped payload.
    let data = input_json
        .get("input")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    // FIELD selects which key within `data` to validate.
    // When FIELD is empty the data value itself is validated directly.
    // When the field is not found in `data`, fall back to the top-level
    // input_json (handles cases where trigger input fields are spread
    // at the root level of the wrapped payload).
    let field_name = config
        .get("FIELD")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let value = if field_name.is_empty() {
        data.clone()
    } else {
        data.get(field_name)
            .cloned()
            .or_else(|| input_json.get(field_name).cloned())
            .unwrap_or(serde_json::Value::Null)
    };

    if validation_type == "numeric" {
        let num = match value.as_f64() {
            Some(n) => n,
            None => {
                let result = serde_json::json!({
                    "success": false,
                    "error": format!(
                        "Validation failed: field '{}' is not a numeric value (got: {})",
                        field_name, value
                    ),
                    "field": field_name,
                    "input": data,
                });
                return Ok(serde_json::to_string(&result).unwrap_or_default());
            }
        };

        if let Some(min_val) = config.get("MIN_VALUE").and_then(|v| v.as_f64()) {
            if num < min_val {
                let result = serde_json::json!({
                    "success": false,
                    "error": format!(
                        "Validation failed: {} ({}) is less than minimum {}",
                        field_name, num, min_val
                    ),
                    "field": field_name,
                    "value": num,
                    "min": min_val,
                });
                return Ok(serde_json::to_string(&result).unwrap_or_default());
            }
        }

        if let Some(max_val) = config.get("MAX_VALUE").and_then(|v| v.as_f64()) {
            if num > max_val {
                let result = serde_json::json!({
                    "success": false,
                    "error": format!(
                        "Validation failed: {} ({}) is greater than maximum {}",
                        field_name, num, max_val
                    ),
                    "field": field_name,
                    "value": num,
                    "max": max_val,
                });
                return Ok(serde_json::to_string(&result).unwrap_or_default());
            }
        }

        let result = serde_json::json!({
            "success": true,
            "field": field_name,
            "value": num,
        });
        return Ok(serde_json::to_string(&result).unwrap_or_default());
    }

    // Field presence validation: check that the named field exists in data
    if !field_name.is_empty() {
        let has_field = data
            .as_object()
            .map(|obj| obj.contains_key(field_name))
            .unwrap_or(false);

        if !has_field {
            let result = serde_json::json!({
                "success": false,
                "error": format!("Validation failed: required field '{}' is missing", field_name),
                "field": field_name,
            });
            return Ok(serde_json::to_string(&result).unwrap_or_default());
        }
    }

    let result = serde_json::json!({
        "success": true,
        "field": field_name,
        "input": data,
    });
    Ok(serde_json::to_string(&result).unwrap_or_default())
}
