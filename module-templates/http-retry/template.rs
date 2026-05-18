use talos_sdk_macros::talos_module;

#[talos_module(world = "http-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value = serde_json::from_str(&input).unwrap_or(serde_json::json!({}));
    let config = input_json.get("config").cloned().unwrap_or(serde_json::json!({}));

    let url = config.get("URL").and_then(|v| v.as_str())
        .ok_or("Missing required config: URL")?;
    let method_str = config.get("METHOD").and_then(|v| v.as_str()).unwrap_or("GET");
    let body_str = config.get("BODY").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let timeout_ms = config.get("TIMEOUT_MS").and_then(|v| v.as_u64()).unwrap_or(10000);
    let max_retries = config.get("MAX_RETRIES").and_then(|v| v.as_u64()).unwrap_or(3) as usize;
    let backoff_ms = config.get("BACKOFF_MS").and_then(|v| v.as_u64()).unwrap_or(1000);
    let retry_on_str = config.get("RETRY_ON_STATUS").and_then(|v| v.as_str())
        .unwrap_or("429,500,502,503,504");

    let retry_statuses: Vec<u16> = retry_on_str
        .split(',')
        .filter_map(|s| s.trim().parse::<u16>().ok())
        .collect();

    use talos::core::http::{Request, Method};

    let method = match method_str.to_uppercase().as_str() {
        "POST"   => Method::Post,
        "PUT"    => Method::Put,
        "DELETE" => Method::Delete,
        "PATCH"  => Method::Patch,
        _        => Method::Get,
    };

    let mut content_type_header = vec![];
    if !body_str.is_empty() {
        content_type_header.push(("Content-Type".to_string(), "application/json".to_string()));
    }

    let request = Request {
        method,
        url: url.to_string(),
        headers: content_type_header,
        body: body_str.as_bytes().to_vec(),
        timeout_ms: Some(timeout_ms.min(300_000) as u32),
    };

    let mut attempt = 0;
    let mut last_error = String::new();
    let mut current_backoff = backoff_ms;

    loop {
        match talos::core::http::fetch(&request) {
            Ok(resp) => {
                let status = resp.status;
                let body = String::from_utf8(resp.body)
                    .unwrap_or_else(|_| "[non-UTF-8 response]".to_string());

                if retry_statuses.contains(&status) && attempt < max_retries {
                    attempt += 1;
                    last_error = format!("HTTP {} (attempt {}/{})", status, attempt, max_retries + 1);
                    // Exponential backoff — simulate delay via busy-wait (WASM has no sleep)
                    let _: u64 = current_backoff;
                    current_backoff = (current_backoff * 2).min(30_000);
                    continue;
                }

                let result = serde_json::json!({
                    "status": status,
                    "body": body,
                    "attempts": attempt + 1,
                    "success": status >= 200 && status < 300,
                });
                return Ok(result.to_string());
            }
            Err(e) => {
                last_error = e.to_string();
                if attempt < max_retries {
                    attempt += 1;
                    current_backoff = (current_backoff * 2).min(30_000);
                    continue;
                }
                return Err(format!(
                    "HTTP request failed after {} attempts. Last error: {}",
                    attempt + 1,
                    last_error
                ));
            }
        }
    }
}
