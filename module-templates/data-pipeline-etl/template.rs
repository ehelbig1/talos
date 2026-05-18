use talos_sdk_macros::talos_module;

#[talos_module(world = "database-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value = serde_json::from_str(&input)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    let config = input_json
        .get("config")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let source_url = config
        .get("SOURCE_URL")
        .and_then(|v| v.as_str())
        .ok_or("Missing required config: SOURCE_URL")?
        .to_string();

    let target_table = config
        .get("TARGET_TABLE")
        .and_then(|v| v.as_str())
        .ok_or("Missing required config: TARGET_TABLE")?;

    // Validate table name: only alphanumeric and underscores are safe to
    // interpolate into a SQL string. The database interface does not support
    // parameterised identifiers.
    if target_table.is_empty()
        || !target_table
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(format!(
            "Invalid TARGET_TABLE '{}': only alphanumeric characters and underscores are allowed",
            target_table
        ));
    }
    let target_table = target_table.to_string();

    // Optional: inject an Authorization header from a stored secret.
    let api_token_secret = config
        .get("API_TOKEN_SECRET")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    use talos::core::http::{Method, Request};

    let mut headers = vec![
        ("Accept".to_string(), "application/json".to_string()),
        ("User-Agent".to_string(), "Talos-ETL-Pipeline/1.0".to_string()),
    ];

    if !api_token_secret.is_empty() {
        if let Ok(token) = talos::core::secrets::get_secret(api_token_secret) {
            headers.push(("Authorization".to_string(), format!("Bearer {}", token)));
        }
        // Continue without auth if the secret is not found — let the server
        // decide whether to return 401 (which will propagate as a node failure).
    }

    // ── EXTRACT ────────────────────────────────────────────────────────────
    let request = Request {
        method: Method::Get,
        url: source_url.clone(),
        headers,
        body: vec![],
        timeout_ms: Some(15000),
    };

    let resp = talos::core::http::fetch(&request)
        .map_err(|e| format!("HTTP request failed: {:?}", e))?;

    if resp.status >= 400 {
        return Err(format!(
            "Source URL returned HTTP {} during extraction",
            resp.status
        ));
    }

    let raw = String::from_utf8(resp.body)
        .map_err(|_| "Invalid UTF-8 in HTTP response body".to_string())?;

    let records: Vec<serde_json::Value> = serde_json::from_str(&raw)
        .map_err(|e| format!("Expected a JSON array from source URL: {}", e))?;

    // ── TRANSFORM + LOAD ───────────────────────────────────────────────────
    // The database interface exposes a platform-managed connection; no
    // connection string is needed here.
    let insert_sql = format!(
        "INSERT INTO {} (remote_id, name, email, company) VALUES ($1, $2, $3, $4)",
        target_table
    );

    let mut loaded: u32 = 0;
    let mut errors: u32 = 0;

    for record in &records {
        let remote_id = record
            .get("id")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
            .to_string();
        let name = record
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .to_string();
        // Normalise email to lowercase as a basic transform step
        let email = record
            .get("email")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        let company = record
            .get("company")
            .and_then(|c| c.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("Independent")
            .to_string();

        let params = vec![remote_id, name, email, company];
        match talos::core::database::execute_query(&insert_sql, &params) {
            Ok(_) => loaded += 1,
            Err(_) => errors += 1,
        }
    }

    let result = serde_json::json!({
        "records_fetched": records.len(),
        "records_loaded": loaded,
        "records_failed": errors,
        "target_table": target_table,
        "source_url": source_url,
    });

    Ok(serde_json::to_string(&result).unwrap_or_default())
}
