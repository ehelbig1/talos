use talos_sdk_macros::talos_module;

#[talos_module(world = "minimal-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value = serde_json::from_str(&input).unwrap_or(serde_json::json!({}));
    let config = input_json.get("config").cloned().unwrap_or(serde_json::json!({}));

    let csv_field = config.get("CSV_FIELD").and_then(|v| v.as_str()).unwrap_or("csv");
    let delimiter_str = config.get("DELIMITER").and_then(|v| v.as_str()).unwrap_or(",");
    let has_header = config.get("HAS_HEADER").and_then(|v| v.as_bool()).unwrap_or(true);
    let max_rows = config.get("MAX_ROWS").and_then(|v| v.as_u64()).unwrap_or(10000) as usize;

    let delimiter = delimiter_str.chars().next().unwrap_or(',');

    let csv_str = input_json.get(csv_field)
        .and_then(|v| v.as_str())
        .or_else(|| input_json.get("input").and_then(|v| v.as_str()))
        .unwrap_or("");

    if csv_str.is_empty() {
        return Ok(serde_json::json!({ "rows": [], "count": 0 }).to_string());
    }

    let lines: Vec<&str> = csv_str.lines().collect();
    if lines.is_empty() {
        return Ok(serde_json::json!({ "rows": [], "count": 0 }).to_string());
    }

    let parse_row = |line: &str| -> Vec<String> {
        let mut fields = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '"' {
                if in_quotes && chars.peek() == Some(&'"') {
                    chars.next();
                    current.push('"');
                } else {
                    in_quotes = !in_quotes;
                }
            } else if c == delimiter && !in_quotes {
                fields.push(current.trim().to_string());
                current = String::new();
            } else {
                current.push(c);
            }
        }
        fields.push(current.trim().to_string());
        fields
    };

    let (headers, data_start) = if has_header && !lines.is_empty() {
        (parse_row(lines[0]), 1)
    } else {
        (vec![], 0)
    };

    let mut rows: Vec<serde_json::Value> = Vec::new();
    for line in lines.iter().skip(data_start).take(max_rows) {
        if line.trim().is_empty() { continue; }
        let fields = parse_row(line);
        if has_header {
            let mut obj = serde_json::Map::new();
            for (i, header) in headers.iter().enumerate() {
                let val = fields.get(i).cloned().unwrap_or_default();
                obj.insert(header.clone(), serde_json::Value::String(val));
            }
            rows.push(serde_json::Value::Object(obj));
        } else {
            rows.push(serde_json::Value::Array(
                fields.into_iter().map(serde_json::Value::String).collect(),
            ));
        }
    }

    let count = rows.len();
    let result = serde_json::json!({
        "rows": rows,
        "count": count,
        "headers": if has_header { serde_json::json!(headers) } else { serde_json::json!(null) },
    });
    Ok(result.to_string())
}
