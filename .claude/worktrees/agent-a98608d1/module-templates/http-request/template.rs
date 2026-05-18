use talos_sdk_macros::talos_module;

// 1. Define strict structs for expected payload to prevent WebAssembly stack overflows.
// Do NOT use `serde_json::Value` for root payloads, as deeply nested JSON will panic the Wasmtime runtime.
#[derive(serde::Deserialize)]
struct HeaderItem {
    key: Option<String>,
    value: Option<String>,
}

#[derive(serde::Deserialize)]
struct HttpRequestConfig {
    #[serde(rename = "METHOD")]
    method: Option<String>,
    #[serde(rename = "URL")]
    url: Option<String>,
    #[serde(rename = "HEADERS")]
    headers: Option<Vec<HeaderItem>>,
    #[serde(rename = "BODY")]
    body: Option<String>,
    #[serde(rename = "TIMEOUT_MS")]
    timeout_ms: Option<u64>,
}

#[derive(serde::Deserialize)]
struct Payload {
    config: Option<HttpRequestConfig>,
}

#[talos_module(world = "network-node")]
fn run(input: String) -> Result<String, String> {
    use talos::core::http::{Request, Method};

    // 2. Parse payload safely using the structured envelope
    let payload: Payload = serde_json::from_str(&input)
        .map_err(|e| format!("Invalid JSON input: {}", e))?;

    let config = payload.config
        .ok_or("Missing 'config' in input")?;

    let method_str = config.method.as_deref().unwrap_or("GET");
    let method = match method_str {
        "GET" => Method::Get,
        "POST" => Method::Post,
        "PUT" => Method::Put,
        "DELETE" => Method::Delete,
        "PATCH" => Method::Patch,
        _ => Method::Get,
    };

    let url = config.url
        .ok_or("Missing 'URL' in config")?;

    let mut headers = Vec::new();
    if let Some(config_headers) = config.headers {
        for header_obj in config_headers {
            if let (Some(k), Some(v)) = (header_obj.key, header_obj.value) {
                headers.push((k, v));
            }
        }
    }

    let body = config.body.unwrap_or_default();
    let timeout_ms = config.timeout_ms.unwrap_or(5000) as u32;

    let request = Request {
        method,
        url,
        headers,
        body: body.into_bytes(),
        timeout_ms: Some(timeout_ms),
    };

    match talos::core::http::fetch(&request) {
        Ok(resp) => {
            let body_str = String::from_utf8(resp.body)
                .map_err(|_| "Invalid UTF-8 in response".to_string())?;
            Ok(body_str)
        }
        Err(e) => Err(format!("HTTP request failed: {:?}", e))
    }
}
