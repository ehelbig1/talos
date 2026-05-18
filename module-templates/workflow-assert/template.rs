use talos_sdk_macros::talos_module;

#[talos_module(world = "minimal-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value = serde_json::from_str(&input).unwrap_or(serde_json::json!({}));
    let config = input_json.get("config").cloned().unwrap_or(serde_json::json!({}));

    let assertions_str = config.get("ASSERTIONS").and_then(|v| v.as_str())
        .ok_or("Missing required config: ASSERTIONS")?;
    let fail_fast = config.get("FAIL_FAST").and_then(|v| v.as_bool()).unwrap_or(true);

    let assertions: Vec<serde_json::Value> = serde_json::from_str(assertions_str)
        .map_err(|e| format!("ASSERTIONS must be a valid JSON array: {}", e))?;

    // Resolve a dot-notation path against the input JSON
    let resolve_path = |path: &str, data: &serde_json::Value| -> Option<serde_json::Value> {
        let mut current = data;
        let parts: Vec<&str> = path.split('.').collect();
        let parts_owned: Vec<String> = parts.iter().map(|s| s.to_string()).collect();
        let mut result = None;
        let mut temp;
        let mut ptr = current;
        for part in &parts_owned {
            if let Some(v) = ptr.get(part.as_str()) {
                temp = v.clone();
                // We need to return at the end
                result = Some(temp.clone());
                // Can't reborrow in this pattern easily; use a workaround
                current = &serde_json::Value::Null; // placeholder
                let _ = current;
                ptr = v;
            } else {
                return None;
            }
        }
        result
    };

    let mut failed: Vec<serde_json::Value> = Vec::new();

    for assertion in &assertions {
        let path = match assertion.get("path").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => {
                failed.push(serde_json::json!({ "error": "assertion missing 'path'" }));
                if fail_fast { break; }
                continue;
            }
        };
        let op = match assertion.get("op").and_then(|v| v.as_str()) {
            Some(o) => o,
            None => {
                failed.push(serde_json::json!({ "path": path, "error": "assertion missing 'op'" }));
                if fail_fast { break; }
                continue;
            }
        };
        let expected = assertion.get("value");

        // Resolve path manually (avoiding closure borrow issues)
        let actual = {
            let mut ptr: &serde_json::Value = &input_json;
            let mut found = true;
            for part in path.split('.') {
                if let Some(v) = ptr.get(part) {
                    ptr = v;
                } else {
                    found = false;
                    break;
                }
            }
            if found { Some(ptr.clone()) } else { None }
        };

        let pass = match op {
            "exists"     => actual.is_some(),
            "not_exists" => actual.is_none(),
            "eq" => {
                if let (Some(a), Some(e)) = (&actual, expected) {
                    a == e
                } else {
                    false
                }
            }
            "ne" => {
                if let (Some(a), Some(e)) = (&actual, expected) {
                    a != e
                } else {
                    actual.is_none() && expected.is_none()
                }
            }
            "gt" => {
                if let (Some(a), Some(e)) = (actual.as_ref().and_then(|v| v.as_f64()),
                                              expected.and_then(|v| v.as_f64())) {
                    a > e
                } else { false }
            }
            "lt" => {
                if let (Some(a), Some(e)) = (actual.as_ref().and_then(|v| v.as_f64()),
                                              expected.and_then(|v| v.as_f64())) {
                    a < e
                } else { false }
            }
            "contains" => {
                let haystack = actual.as_ref().and_then(|v| v.as_str()).unwrap_or("");
                let needle = expected.and_then(|v| v.as_str()).unwrap_or("");
                haystack.contains(needle)
            }
            _ => {
                failed.push(serde_json::json!({
                    "path": path, "op": op, "error": "unknown op"
                }));
                if fail_fast { break; }
                continue;
            }
        };

        if !pass {
            failed.push(serde_json::json!({
                "path": path,
                "op": op,
                "expected": expected,
                "actual": actual,
            }));
            if fail_fast { break; }
        }
    }

    if !failed.is_empty() {
        return Err(format!(
            "Assertion failures: {}",
            serde_json::to_string(&failed).unwrap_or_else(|_| failed.len().to_string())
        ));
    }

    let result = serde_json::json!({
        "passed": true,
        "assertions_checked": assertions.len(),
    });
    Ok(result.to_string())
}
