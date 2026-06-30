use talos_sdk_macros::talos_module;

// 1. Define strict structs for expected payload to prevent WebAssembly stack overflows.
// Do NOT use `serde_json::Value` for root payloads, as deeply nested JSON will panic the Wasmtime runtime.
#[derive(serde::Deserialize)]
struct HeaderItem {
    key: Option<String>,
    value: Option<String>,
}

// Each field accepts both the canonical SCREAMING_SNAKE_CASE form and the
// lowercase form via `#[serde(alias = ...)]`. The platform docs show
// SCREAMING_SNAKE for legacy reasons; in practice callers (including the
// MCP-driven workflow builders) frequently reach for lowercase by analogy
// with HTTP/REST conventions, and getting bounced for it costs an extra
// validation cycle. Accepting both is two characters per field and one
// less papercut. Same treatment applied to the METHOD enum below.
#[derive(serde::Deserialize)]
struct HttpRequestConfig {
    #[serde(rename = "METHOD", alias = "method")]
    method: Option<String>,
    #[serde(rename = "URL", alias = "url")]
    url: Option<String>,
    #[serde(rename = "HEADERS", alias = "headers")]
    headers: Option<Vec<HeaderItem>>,
    #[serde(rename = "BODY", alias = "body")]
    body: Option<String>,
    #[serde(rename = "TIMEOUT_MS", alias = "timeout_ms")]
    timeout_ms: Option<u64>,
    /// Set to true to sanitize the response for safe LLM consumption:
    /// strips HTML tags, enforces MAX_CONTENT_LENGTH, and wraps in
    /// [EXTERNAL_CONTENT_BEGIN]...[EXTERNAL_CONTENT_END] delimiters.
    #[serde(rename = "SANITIZE_FOR_LLM", alias = "sanitize_for_llm")]
    sanitize_for_llm: Option<bool>,
    /// Maximum byte length of the response body when SANITIZE_FOR_LLM is true.
    /// Defaults to 8192. Content is truncated before the LLM delimiter is added.
    #[serde(rename = "MAX_CONTENT_LENGTH", alias = "max_content_length")]
    max_content_length: Option<u64>,
    /// Maximum bytes of raw response body to return, applied REGARDLESS of
    /// SANITIZE_FOR_LLM. Use when chaining into a downstream extractor (e.g.
    /// html-to-text) that's smarter than this module's naive tag stripper —
    /// you still need to keep the raw bytes under the platform's WASM input
    /// limit (~1MB) so the next node can receive them. UTF-8 boundary safe:
    /// the cap is walked back to the nearest char boundary so multi-byte
    /// chars never split. Unset = no truncation (back-compat default).
    #[serde(rename = "MAX_RESPONSE_BYTES", alias = "max_response_bytes")]
    max_response_bytes: Option<u64>,
}

#[derive(serde::Deserialize)]
struct Payload {
    config: Option<HttpRequestConfig>,
}

// Least privilege: this module only uses `talos::core::http`, which `http-node`
// provides. `network-node` is a superset (adds graphql/email/state/http-stream/…)
// none of which are used here. Keep this in sync with talos.json `capability_world`
// — lint-structural.sh check 48 enforces the match.
#[talos_module(world = "http-node")]
fn run(input: String) -> Result<String, String> {
    use talos::core::http::{Request, Method};

    // 2. Parse payload safely using the structured envelope
    let payload: Payload = serde_json::from_str(&input)
        .map_err(|e| format!("Invalid JSON input: {}", e))?;

    let config = payload.config
        .ok_or("Missing 'config' in input")?;

    // Accept any case ("GET", "get", "Get") — uppercase first, then match.
    // Pre-r247 only the SCREAMING form matched and "get" silently fell
    // through to the catch-all → silent GET, even on a "POST" intent.
    let method_str = config
        .method
        .as_deref()
        .unwrap_or("GET")
        .to_ascii_uppercase();
    let method = match method_str.as_str() {
        "GET" => Method::Get,
        "POST" => Method::Post,
        "PUT" => Method::Put,
        "DELETE" => Method::Delete,
        "PATCH" => Method::Patch,
        other => {
            return Err(format!(
                "METHOD '{}' is not supported. Use one of: GET, POST, PUT, DELETE, PATCH (any case).",
                other
            ));
        }
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
    let sanitize = config.sanitize_for_llm.unwrap_or(false);
    let max_content_length = config.max_content_length.unwrap_or(8192) as usize;

    let request = Request {
        method,
        url,
        headers,
        body: body.into_bytes(),
        timeout_ms: Some(timeout_ms),
    };

    let max_response_bytes = config.max_response_bytes.map(|n| n as usize);

    match talos::core::http::fetch(&request) {
        Ok(resp) => {
            let status = resp.status;
            let body_str = String::from_utf8(resp.body)
                .map_err(|_| "Invalid UTF-8 in response".to_string())?;

            // Apply MAX_RESPONSE_BYTES BEFORE the 4xx/5xx error message
            // (so an error body the size of a page doesn't exceed the
            // upstream WASM input limit when the error is propagated)
            // AND before the sanitize/return paths (so both modes get
            // the same truncation discipline). UTF-8 boundary safe.
            //
            // Truncation marker also reports the *JSON-encoded* size of the
            // truncated body — the engine wraps node outputs in JSON before
            // handing them to the next node, and HTML inflates ~2× from
            // quote/newline escaping. Surfacing the encoded size here lets
            // operators pick a sane MAX_RESPONSE_BYTES on the first try
            // instead of trial-and-erroring against the platform's 1MB
            // next-node input cap. Real symptom 2026-04-30: watch-ghas
            // with MAX_RESPONSE_BYTES=800000 still tripped the cap because
            // 530KB HTML JSON-encoded to 1.1MB.
            let body_str = match max_response_bytes {
                Some(cap) if body_str.len() > cap => {
                    let original_len = body_str.len();
                    let mut safe = cap;
                    while safe > 0 && !body_str.is_char_boundary(safe) {
                        safe -= 1;
                    }
                    let truncated = &body_str[..safe];
                    // JSON encoding wraps the string in quotes (+2) and escapes
                    // `"`, `\`, control chars, `\n`, etc. `serde_json::to_string`
                    // is the source of truth — counting escape-causing chars by
                    // hand drifts. Cost is one O(N) pass on the truncation path
                    // only (never the steady-state path).
                    let json_encoded_len = serde_json::to_string(truncated)
                        .map(|s| s.len().saturating_sub(2))
                        .unwrap_or(safe);
                    format!(
                        "{}...(truncated by MAX_RESPONSE_BYTES from {} to {} bytes; ~{} bytes after JSON encoding for next node)",
                        truncated,
                        original_len,
                        safe,
                        json_encoded_len
                    )
                }
                _ => body_str,
            };

            // Treat 4xx and 5xx as node failures so error edges are followed
            // and retry policies are applied. Callers that want to handle
            // non-2xx responses themselves can read the status from the error.
            if status >= 400 {
                return Err(format!("HTTP {} error: {}", status, body_str));
            }

            if sanitize {
                // ── Phase 3.2: HTTP content sanitization for LLM safety ───────
                // Strip HTML tags via a simple state machine (no regex dependency).
                let stripped = {
                    let mut out = String::with_capacity(body_str.len());
                    let mut in_tag = false;
                    for ch in body_str.chars() {
                        match ch {
                            '<' => { in_tag = true; }
                            '>' => { in_tag = false; }
                            _ if !in_tag => { out.push(ch); }
                            _ => {}
                        }
                    }
                    out
                };

                // Enforce MAX_CONTENT_LENGTH before handing to LLM.
                // UTF-8 boundary safe — walk back from byte cap to the
                // nearest char boundary so multi-byte chars never split.
                let truncated = if stripped.len() > max_content_length {
                    let mut safe = max_content_length;
                    while safe > 0 && !stripped.is_char_boundary(safe) {
                        safe -= 1;
                    }
                    format!(
                        "{} [TRUNCATED at {} bytes]",
                        &stripped[..safe],
                        max_content_length
                    )
                } else {
                    stripped
                };

                // Wrap in explicit delimiters so the LLM can distinguish
                // external content from instructions and user input.
                Ok(format!(
                    "[EXTERNAL_CONTENT_BEGIN]\n{}\n[EXTERNAL_CONTENT_END]",
                    truncated
                ))
            } else {
                Ok(body_str)
            }
        }
        Err(e) => Err(format!("HTTP request failed: {:?}", e))
    }
}
