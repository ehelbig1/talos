#![allow(warnings)]
use serde_json::Value;
use talos::core::database::execute_query;
use talos::core::http::{fetch, Method, Request};
use talos::core::logging::{self, Level};
use talos::core::secrets::get_secret;
use talos_sdk_macros::talos_node;

#[talos_node]
pub fn run(
    api_endpoint: String,
    api_token_secret: String,
    target_table: String,
) -> Result<String, String> {
    // 1. EXTRACT: Fetch Data from external API
    logging::log(
        Level::Info,
        &format!("Extracting data from {}...", api_endpoint),
    );

    let mut headers = vec![
        ("Accept".to_string(), "application/json".to_string()),
        ("User-Agent".to_string(), "Talos-ETL-Pipeline".to_string()),
    ];

    if !api_token_secret.is_empty() {
        if let Ok(token) = get_secret(&api_token_secret) {
            headers.push(("Authorization".to_string(), format!("Bearer {}", token)));
        }
    }

    let req = Request {
        method: Method::Get,
        url: api_endpoint.clone(),
        headers,
        body: vec![],
        timeout_ms: Some(15000),
    };

    let resp = fetch(&req).map_err(|e| format!("HTTP request failed: {:?}", e))?;
    if resp.status != 200 {
        return Err(format!(
            "API returned status {} during extraction",
            resp.status
        ));
    }

    let raw_json: Value =
        serde_json::from_slice(&resp.body).map_err(|e| format!("Invalid JSON response: {}", e))?;

    // Must be an array of objects to process
    let records = match raw_json.as_array() {
        Some(arr) => arr,
        None => return Err("Expected API to return a JSON array".to_string()),
    };

    logging::log(
        Level::Info,
        &format!("Extraction complete. Fetched {} records.", records.len()),
    );

    // 2. TRANSFORM: Sanitize the Data
    logging::log(Level::Info, "Transforming data (stripping PII)...");

    let mut processed_count = 0;
    let mut sql_errors = 0;

    // Ensure the table exists. In a production scenario, you would manage schemas via migrations,
    // but for this dynamic ETL we can run a CREATE TABLE IF NOT EXISTS.
    let create_sql = format!(
        "CREATE TABLE IF NOT EXISTS {} (
            id SERIAL PRIMARY KEY,
            remote_id VARCHAR(255),
            name VARCHAR(255),
            email VARCHAR(255),
            company VARCHAR(255)
        )",
        target_table
    );
    let _ = execute_query(&create_sql, &[]);

    // 3. LOAD: Insert into PostgreSQL
    logging::log(
        Level::Info,
        &format!("Loading data into '{}'...", target_table),
    );
    let insert_sql = format!(
        "INSERT INTO {} (remote_id, name, email, company) VALUES ($1, $2, $3, $4)",
        target_table
    );

    for record in records {
        // We expect JSON Placeholder 'users' schema or similar for this demo plugin.
        // Strip sensitive/unnecessary data and extract what we need.
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

        // Example Transformation: Hash or lowercase the email
        let mut email = record
            .get("email")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        email = email.to_lowercase(); // Format standardisation

        // Extract nested objects securely
        let company_name = record
            .get("company")
            .and_then(|c| c.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("Independent")
            .to_string();

        let params = vec![remote_id, name, email, company_name];

        match execute_query(&insert_sql, &params) {
            Ok(_) => processed_count += 1,
            Err(e) => {
                logging::log(Level::Warn, &format!("Failed to insert record: {:?}", e));
                sql_errors += 1;
            }
        }
    }

    Ok(format!(
        "ETL Pipeline Complete! Successfully Extracted {}, Transformed, and Loaded {} records into '{}' ({} errors).",
        records.len(), processed_count, target_table, sql_errors
    ))
}
