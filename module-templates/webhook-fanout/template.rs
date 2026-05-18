use talos_sdk_macros::talos_module;

// Strict typed structs over the input envelope — Value-parsing here would
// dominate the fuel budget on large fan-outs, exactly the anti-pattern the
// hygiene linter flags. The "items" array stays as serde_json::Value
// elements only so the body forwarding can pass arbitrary upstream shapes
// through verbatim; that's the one Value site we accept, and only at the
// element granularity (not the envelope).

#[derive(serde::Deserialize)]
struct HeaderItem {
    key: Option<String>,
    value: Option<String>,
}

#[derive(serde::Deserialize)]
struct WebhookConfig {
    #[serde(rename = "URL")]
    url: Option<String>,
    #[serde(rename = "INPUT_FIELD")]
    input_field: Option<String>,
    #[serde(rename = "AUTH_HEADER_NAME")]
    auth_header_name: Option<String>,
    #[serde(rename = "AUTH_HEADER_VALUE")]
    auth_header_value: Option<String>,
    #[serde(rename = "EXTRA_HEADERS")]
    extra_headers: Option<Vec<HeaderItem>>,
    #[serde(rename = "TIMEOUT_MS")]
    timeout_ms: Option<u32>,
    #[serde(rename = "STOP_ON_ERROR")]
    stop_on_error: Option<bool>,
    #[serde(rename = "MAX_ITEMS")]
    max_items: Option<u32>,
}

#[derive(serde::Deserialize)]
struct Payload {
    config: Option<WebhookConfig>,
    // upstream output. Untyped because each integration has its own shape;
    // we only need to find the array field by name (or accept the whole
    // payload as an array).
    #[serde(default)]
    input: serde_json::Value,
}

const DEFAULT_INPUT_FIELD: &str = "items";
const DEFAULT_AUTH_HEADER: &str = "x-auth-token";
const DEFAULT_TIMEOUT_MS: u32 = 5_000;
const DEFAULT_MAX_ITEMS: u32 = 100;
const HARD_MAX_ITEMS: u32 = 1_000;

#[talos_module(world = "http-node")]
fn run(input: String) -> Result<String, String> {
    use talos::core::http::{self, Method, Request};

    let payload: Payload = serde_json::from_str(&input)
        .map_err(|e| format!("webhook-fanout: invalid input JSON: {e}"))?;
    let cfg = payload.config.ok_or("webhook-fanout: missing config")?;

    let url = cfg
        .url
        .filter(|s| !s.is_empty())
        .ok_or("webhook-fanout: URL is required")?;
    let auth_value = cfg
        .auth_header_value
        .filter(|s| !s.is_empty())
        .ok_or("webhook-fanout: AUTH_HEADER_VALUE is required (use vault://path/to/secret)")?;
    // Defensive: if the configured value lacks the vault:// prefix we'd
    // send the literal string as a token (silent auth bypass). Fail closed.
    if !auth_value.starts_with("vault://") {
        return Err(
            "webhook-fanout: AUTH_HEADER_VALUE must start with 'vault://'. \
             Worker resolves the header value at fetch time so the secret \
             never crosses the WASM boundary; literal tokens in node \
             config would defeat that guarantee."
                .to_string(),
        );
    }

    let auth_header_name = cfg
        .auth_header_name
        .unwrap_or_else(|| DEFAULT_AUTH_HEADER.to_string());
    let input_field = cfg
        .input_field
        .unwrap_or_else(|| DEFAULT_INPUT_FIELD.to_string());
    let timeout_ms = cfg.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS).max(100);
    let stop_on_error = cfg.stop_on_error.unwrap_or(false);
    let max_items = cfg
        .max_items
        .unwrap_or(DEFAULT_MAX_ITEMS)
        .clamp(1, HARD_MAX_ITEMS);

    // Resolve the array. Try (1) input[INPUT_FIELD], (2) input itself if
    // it's already an array. Anything else is "no items to dispatch" —
    // return cleanly so empty upstreams don't fail the workflow.
    let items_ref: Option<&Vec<serde_json::Value>> = match &payload.input {
        serde_json::Value::Object(map) => map.get(&input_field).and_then(|v| v.as_array()),
        serde_json::Value::Array(arr) => Some(arr),
        _ => None,
    };
    let items = match items_ref {
        Some(arr) if !arr.is_empty() => arr,
        _ => {
            let out = serde_json::json!({
                "url": url,
                "candidate_count": 0,
                "dispatched": 0,
                "errors": 0,
                "skipped_reason": "no items in upstream",
            });
            return serde_json::to_string(&out).map_err(|e| e.to_string());
        }
    };

    // Extra headers + content-type default. content-type can be overridden
    // via EXTRA_HEADERS by setting key="content-type".
    let mut headers: Vec<(String, String)> = Vec::with_capacity(2 + cfg.extra_headers.as_ref().map_or(0, |h| h.len()));
    let mut has_content_type = false;
    if let Some(extras) = cfg.extra_headers {
        for HeaderItem { key, value } in extras {
            if let (Some(k), Some(v)) = (key, value) {
                if !k.is_empty() {
                    if k.eq_ignore_ascii_case("content-type") {
                        has_content_type = true;
                    }
                    headers.push((k, v));
                }
            }
        }
    }
    if !has_content_type {
        headers.insert(0, ("content-type".to_string(), "application/json".to_string()));
    }
    headers.push((auth_header_name, auth_value));

    let mut dispatched = 0u32;
    let mut errors = 0u32;
    let mut error_samples: Vec<serde_json::Value> = Vec::new();

    for (idx, item) in items.iter().take(max_items as usize).enumerate() {
        let body_bytes = match serde_json::to_vec(item) {
            Ok(b) => b,
            Err(e) => {
                errors += 1;
                if error_samples.len() < 3 {
                    error_samples.push(serde_json::json!({
                        "index": idx,
                        "phase": "serialize",
                        "err": e.to_string(),
                    }));
                }
                if stop_on_error {
                    break;
                }
                continue;
            }
        };

        let req = Request {
            method: Method::Post,
            url: url.clone(),
            headers: headers.clone(),
            body: body_bytes,
            timeout_ms: Some(timeout_ms),
        };

        match http::fetch(&req) {
            Ok(resp) if resp.status >= 200 && resp.status < 300 => {
                dispatched += 1;
            }
            Ok(resp) => {
                errors += 1;
                if error_samples.len() < 3 {
                    let body_text = String::from_utf8_lossy(&resp.body)
                        .chars()
                        .take(200)
                        .collect::<String>();
                    error_samples.push(serde_json::json!({
                        "index": idx,
                        "phase": "http",
                        "status": resp.status,
                        "body": body_text,
                    }));
                }
                if stop_on_error {
                    break;
                }
            }
            Err(e) => {
                errors += 1;
                if error_samples.len() < 3 {
                    error_samples.push(serde_json::json!({
                        "index": idx,
                        "phase": "transport",
                        "err": format!("{e:?}"),
                    }));
                }
                if stop_on_error {
                    break;
                }
            }
        }
    }

    let truncated = items.len() as u32 > max_items;
    let out = serde_json::json!({
        "url": url,
        "candidate_count": items.len(),
        "dispatched": dispatched,
        "errors": errors,
        "error_samples": error_samples,
        "truncated_to_max_items": truncated,
        "stopped_on_error": stop_on_error && errors > 0,
    });
    serde_json::to_string(&out).map_err(|e| e.to_string())
}
