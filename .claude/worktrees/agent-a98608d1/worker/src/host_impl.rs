//! Host function implementations for all WIT interfaces.
//!
//! Each `impl <interface>::Host for TalosContext` block provides the host side
//! of one WIT interface imported by the `automation-node` world.

use crate::context::TalosContext;

// Bring the generated WIT bindings into scope.
use crate::bindings::talos::core::{
    cache as wit_cache, crypto as wit_crypto, data_transform as wit_data_transform,
    database as wit_database, datetime as wit_datetime, email as wit_email, env as wit_env,
    files as wit_files, graphql as wit_graphql, http as wit_http, json as wit_json,
    logging as wit_logging, messaging as wit_messaging, secrets as wit_secrets, state as wit_state,
    templates as wit_templates, webhook as wit_webhook,
};
use sha2::{Digest, Sha256};

// ============================================================================
// HTTP
// ============================================================================

impl wit_http::Host for TalosContext {
    async fn fetch(
        &mut self,
        req: wit_http::Request,
    ) -> Result<wit_http::Response, wit_http::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if matches!(
            self.capability_world,
            CapabilityWorld::Minimal | CapabilityWorld::Unknown
        ) {
            tracing::warn!("WASM module attempted HTTP request but lacks Http capability");
            return Err(wit_http::Error::Forbiddenhost);
        }
        // Validate and parse the URL first.
        let url: url::Url = req.url.parse().map_err(|_| wit_http::Error::Invalidurl)?;

        // Enforce the host allowlist.  An empty list means DENY ALL — the module
        // must be configured with an explicit allowlist, or use "*" to allow any host.
        let host = url.host_str().unwrap_or("");
        if self.allowed_hosts.is_empty() {
            tracing::warn!(
                host,
                "WASM module attempted HTTP request but no host allowlist is configured — \
                 denying. Set WASM_ALLOWED_HOSTS=\"*\" to allow all hosts."
            );
            return Err(wit_http::Error::Forbiddenhost);
        }

        // DNS rebinding / SSRF protection: if the host parses as an IP address literal,
        // reject private, loopback, link-local, and multicast ranges immediately.
        // This prevents a WASM module from using an IP literal to reach internal services
        // even when the allowlist contains a wildcard ("*").
        match url.host() {
            Some(url::Host::Ipv4(addr)) => {
                if addr.is_loopback()
                    || addr.is_private()
                    || addr.is_link_local()
                    || addr.is_multicast()
                    || addr.is_broadcast()
                {
                    tracing::warn!(
                        ip = %addr,
                        "WASM module attempted to reach a private/loopback IPv4 address — blocking"
                    );
                    return Err(wit_http::Error::Forbiddenhost);
                }
            }
            Some(url::Host::Ipv6(addr)) => {
                if addr.is_loopback() || addr.is_multicast() {
                    tracing::warn!(
                        ip = %addr,
                        "WASM module attempted to reach a loopback/multicast IPv6 address — blocking"
                    );
                    return Err(wit_http::Error::Forbiddenhost);
                }
                // Block IPv6 link-local (fe80::/10) and unique-local (fc00::/7) addresses.
                let segments = addr.segments();
                let first = segments[0];
                if (first & 0xffc0) == 0xfe80 || (first & 0xfe00) == 0xfc00 {
                    tracing::warn!(
                        ip = %addr,
                        "WASM module attempted to reach a private IPv6 address — blocking"
                    );
                    return Err(wit_http::Error::Forbiddenhost);
                }
            }
            _ => {} // hostname — rely on allowlist; full DNS resolution would add latency
        }

        let allowed = self
            .allowed_hosts
            .iter()
            .any(|allowed| allowed == "*" || allowed == host);
        if !allowed {
            tracing::warn!(
                host,
                allowed = ?self.allowed_hosts,
                "WASM module attempted to reach a forbidden host"
            );
            return Err(wit_http::Error::Forbiddenhost);
        }

        // Enforce method allowlist (empty = allow all methods).
        let method_str = match req.method {
            wit_http::Method::Get => "GET",
            wit_http::Method::Post => "POST",
            wit_http::Method::Put => "PUT",
            wit_http::Method::Delete => "DELETE",
            wit_http::Method::Patch => "PATCH",
        };
        if !self.allowed_methods.is_empty()
            && !self
                .allowed_methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(method_str))
        {
            tracing::warn!(
                host,
                method = method_str,
                allowed_methods = ?self.allowed_methods,
                "WASM module attempted a disallowed HTTP method"
            );
            return Err(wit_http::Error::Forbiddenhost);
        }

        // Build the async reqwest request
        let method = req.method;
        let headers = req.headers.clone();
        let body = req.body.clone();
        let timeout_ms = req.timeout_ms.unwrap_or(30_000) as u64;
        let url_str = req.url.clone();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .user_agent("Talos-Worker/1.0")
            .redirect(reqwest::redirect::Policy::none()) // Prevent SSRF via open redirect
            .build()
            .map_err(|_| wit_http::Error::Networkerror)?;

        let reqwest_method = match method {
            wit_http::Method::Get => reqwest::Method::GET,
            wit_http::Method::Post => reqwest::Method::POST,
            wit_http::Method::Put => reqwest::Method::PUT,
            wit_http::Method::Delete => reqwest::Method::DELETE,
            wit_http::Method::Patch => reqwest::Method::PATCH,
        };

        let mut builder = client.request(reqwest_method, &url_str);
        for (name, value) in &headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        if !body.is_empty() {
            builder = builder.body(body.clone());
        }

        let response = builder.send().await.map_err(|e| {
            if e.is_timeout() {
                wit_http::Error::Timeout
            } else {
                wit_http::Error::Networkerror
            }
        })?;

        let status = response.status().as_u16();
        let resp_headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();
        // Enforce configurable response size limit to prevent OOM.
        const DEFAULT_MAX_RESPONSE: usize = 10 * 1024 * 1024; // 10 MiB
        let max_resp = std::env::var("WASM_HTTP_MAX_RESPONSE_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_RESPONSE);

        // Prevent OOM by reading chunks up to max_resp.
        let content_length = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        let capacity = std::cmp::min(content_length, max_resp);
        let mut resp_body_bytes = Vec::with_capacity(capacity);
        let mut stream = response.bytes_stream();
        use futures_util::StreamExt;
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.map_err(|_| wit_http::Error::Networkerror)?;
            if resp_body_bytes.len() + chunk.len() > max_resp {
                tracing::warn!(
                    limit = max_resp,
                    "HTTP response exceeds size limit during streaming"
                );
                return Err(wit_http::Error::Networkerror);
            }
            resp_body_bytes.extend_from_slice(&chunk);
        }
        let resp_body = resp_body_bytes;

        Ok(wit_http::Response {
            status,
            headers: resp_headers,
            body: resp_body,
        })
    }
}

// ============================================================================
// Logging
// ============================================================================

impl wit_logging::Host for TalosContext {
    async fn log(&mut self, lvl: wit_logging::Level, mut msg: String) {
        let execution_id = self.execution_id.clone().unwrap_or_default();
        let request_id = self.request_id.clone().unwrap_or_default();

        // Enforce 10K character limit to prevent log injection/flooding OOMs
        if msg.len() > 10000 {
            msg = msg.chars().take(10000).collect::<String>();
            msg.push_str("...[TRUNCATED]");
        }

        // Emit to the host tracing system.
        // Redact any secret values present in the log message.
        fn redact(msg: &str, secrets: &std::collections::HashMap<String, String>) -> String {
            if secrets.is_empty() || msg.is_empty() {
                return msg.to_string();
            }
            let patterns: Vec<&str> = secrets
                .values()
                .filter(|v| !v.is_empty())
                .map(|s| s.as_str())
                .collect();
            if patterns.is_empty() {
                return msg.to_string();
            }
            if let Ok(ac) = aho_corasick::AhoCorasick::new(&patterns) {
                let replacements: Vec<&str> = vec!["***"; patterns.len()];
                ac.replace_all(msg, &replacements)
            } else {
                let mut out = msg.to_string();
                for val in patterns {
                    out = out.replace(val, "***");
                }
                out
            }
        }
        let safe_msg = redact(&msg, &self.secrets);
        match lvl {
            wit_logging::Level::Debug => tracing::debug!(execution_id, "[WASM] {}", safe_msg),
            wit_logging::Level::Info => tracing::info!(execution_id, "[WASM] {}", safe_msg),
            wit_logging::Level::Warn => tracing::warn!(execution_id, "[WASM] {}", safe_msg),
            wit_logging::Level::Error => tracing::error!(execution_id, "[WASM] {}", safe_msg),
        }

        // Publish structured log to NATS so the controller can persist it.
        if let Some(nats) = &self.nats_client {
            if !execution_id.is_empty() {
                let level_str = match lvl {
                    wit_logging::Level::Debug => "DEBUG",
                    wit_logging::Level::Info => "INFO",
                    wit_logging::Level::Warn => "WARN",
                    wit_logging::Level::Error => "ERROR",
                };

                use opentelemetry::trace::TraceContextExt;
                use tracing_opentelemetry::OpenTelemetrySpanExt;
                let span = tracing::Span::current();
                let ctx = span.context();
                let span_ref = ctx.span();
                let span_context = span_ref.span_context();
                let trace_id = if span_context.is_valid() {
                    Some(span_context.trace_id().to_string())
                } else {
                    None
                };
                let span_id = if span_context.is_valid() {
                    Some(span_context.span_id().to_string())
                } else {
                    None
                };

                let log_entry = serde_json::json!({
                    "execution_id": execution_id,
                    "request_id": request_id,
                    "level": level_str,
                    "message": safe_msg,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "source": "wasm",
                    "trace_id": trace_id,
                    "span_id": span_id
                });

                if let Ok(payload) = serde_json::to_vec(&log_entry) {
                    let nats = nats.clone();
                    let topic = format!("wasm.log.{}", execution_id);
                    // Fire-and-forget: logging must not fail the job.

                    let _ = nats.publish(topic, payload.into()).await;
                }
            }
        }
    }
}

// ============================================================================
// Secrets
// ============================================================================

impl wit_secrets::Host for TalosContext {
    async fn get_secret(&mut self, key_path: String) -> Result<String, wit_secrets::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Secrets | CapabilityWorld::Database | CapabilityWorld::Trusted
        ) {
            tracing::warn!("WASM module attempted secrets access but lacks Secrets capability");
            return Err(wit_secrets::Error::Notfound);
        }

        if let Some(ledger_mutex) = &self.audit_ledger {
            let key_hash = format!("{:x}", Sha256::digest(key_path.as_bytes()));
            let mut ledger = ledger_mutex.lock().await;
            let event = ledger.append(
                "agent:wasm",
                "wasi:secrets_get",
                &serde_json::json!({
                    "key_hash": key_hash,
                })
                .to_string(),
            );
            drop(ledger);

            if let Some(n) = &self.nats_client {
                let event_clone = event.clone();
                let nats = n.clone();
                tokio::spawn(async move {
                    let payload = serde_json::json!({
                        "event": event_clone.clone(),
                        "hash": event_clone.calculate_hash()
                    });
                    match serde_json::to_vec(&payload) {
                        Ok(bytes) => {
                            let _ = nats
                                .publish("talos.audit.ledger".to_string(), bytes.into())
                                .await;
                        }
                        Err(e) => tracing::error!(
                            "Failed to serialize audit event for secrets_get: {}",
                            e
                        ),
                    }
                });
            }
        }

        match self.secrets.get(&key_path) {
            Some(value) => Ok(value.clone()),
            None => {
                tracing::warn!(
                    key_path,
                    module_id = ?self.module_id,
                    "WASM module requested a secret that is not available"
                );
                Err(wit_secrets::Error::Notfound)
            }
        }
    }
}

// ============================================================================
// State (workflow-scoped in-memory key-value store)
// ============================================================================

impl wit_state::Host for TalosContext {
    async fn get(&mut self, key: String) -> Result<String, wit_state::Error> {
        let store = self
            .state_store
            .lock()
            .map_err(|_| wit_state::Error::Storagefailed)?;
        store.get(&key).cloned().ok_or(wit_state::Error::Notfound)
    }

    async fn set(&mut self, key: String, value: String) -> Result<(), wit_state::Error> {
        if key.is_empty() || key.len() > 1024 {
            return Err(wit_state::Error::Invalidkey);
        }
        if value.len() > 1024 * 1024 {
            // 1MB limit
            tracing::warn!("State value exceeds 1MB limit");
            return Err(wit_state::Error::Storagefailed);
        }
        let mut store = self
            .state_store
            .lock()
            .map_err(|_| wit_state::Error::Storagefailed)?;

        // Enforce 1000 key limit to prevent host OOM
        if store.len() >= 1000 && !store.contains_key(&key) {
            tracing::warn!("State store exceeds 1000 key limit");
            return Err(wit_state::Error::Storagefailed);
        }
        store.insert(key, value);
        Ok(())
    }

    async fn delete(&mut self, key: String) -> Result<(), wit_state::Error> {
        let mut store = self
            .state_store
            .lock()
            .map_err(|_| wit_state::Error::Storagefailed)?;
        store.remove(&key);
        Ok(())
    }

    async fn exists(&mut self, key: String) -> bool {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Cache | CapabilityWorld::Trusted
        ) {
            return false;
        }
        self.state_store
            .lock()
            .map(|s| s.contains_key(&key))
            .unwrap_or(false)
    }

    async fn list_keys(&mut self) -> Vec<String> {
        self.state_store
            .lock()
            .map(|s| s.keys().cloned().collect())
            .unwrap_or_default()
    }
}

// ============================================================================
// Environment / workflow metadata
// ============================================================================

impl wit_env::Host for TalosContext {
    async fn get_var(&mut self, key: String) -> Option<String> {
        self.env_vars.get(&key).cloned()
    }

    async fn get_all_vars(&mut self) -> String {
        serde_json::to_string(&self.env_vars).unwrap_or_else(|_| "{}".to_string())
    }

    async fn get_workflow_id(&mut self) -> String {
        self.workflow_id.clone().unwrap_or_default()
    }

    async fn get_execution_id(&mut self) -> String {
        self.execution_id.clone().unwrap_or_default()
    }

    async fn get_module_id(&mut self) -> String {
        self.module_id.clone().unwrap_or_default()
    }
}

// ============================================================================
// JSON utilities
// ============================================================================

impl wit_json::Host for TalosContext {
    async fn parse(&mut self, json_str: String) -> Result<(), wit_json::Error> {
        // Guard against overly large payloads (default 1 MiB).
        const DEFAULT_MAX_JSON: usize = 1024 * 1024;
        let max_json = std::env::var("WASM_MAX_JSON_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_JSON);
        if json_str.len() > max_json {
            tracing::warn!(
                size = json_str.len(),
                limit = max_json,
                "JSON payload exceeds size limit"
            );
            return Err(wit_json::Error::Parseerror);
        }
        serde_json::from_str::<serde_json::Value>(&json_str)
            .map(|_| ())
            .map_err(|_| wit_json::Error::Parseerror)
    }

    async fn query(&mut self, json_str: String, path: String) -> Result<String, wit_json::Error> {
        // Enforce JSON size limit.
        const DEFAULT_MAX_JSON: usize = 1024 * 1024;
        let max_json = std::env::var("WASM_MAX_JSON_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_JSON);
        if json_str.len() > max_json {
            tracing::warn!(
                size = json_str.len(),
                limit = max_json,
                "JSON payload exceeds size limit"
            );
            return Err(wit_json::Error::Parseerror);
        }
        let value: serde_json::Value =
            serde_json::from_str(&json_str).map_err(|_| wit_json::Error::Parseerror)?;

        // Support simple dot-notation paths: "user.email", "$.items[0]", etc.
        let result = json_path_query(&value, &path)?;
        serde_json::to_string(&result).map_err(|_| wit_json::Error::Parseerror)
    }

    async fn merge(&mut self, json1: String, json2: String) -> Result<String, wit_json::Error> {
        // Enforce size limits for both inputs.
        const DEFAULT_MAX_JSON: usize = 1024 * 1024;
        let max_json = std::env::var("WASM_MAX_JSON_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_JSON);
        if json1.len() > max_json || json2.len() > max_json {
            tracing::warn!(
                size1 = json1.len(),
                size2 = json2.len(),
                limit = max_json,
                "JSON payload exceeds size limit"
            );
            return Err(wit_json::Error::Parseerror);
        }
        let mut v1: serde_json::Value =
            serde_json::from_str(&json1).map_err(|_| wit_json::Error::Parseerror)?;
        let v2: serde_json::Value =
            serde_json::from_str(&json2).map_err(|_| wit_json::Error::Parseerror)?;
        json_merge(&mut v1, v2);
        serde_json::to_string(&v1).map_err(|_| wit_json::Error::Parseerror)
    }

    async fn prettify(&mut self, json_str: String) -> Result<String, wit_json::Error> {
        // Enforce JSON size limit.
        const DEFAULT_MAX_JSON: usize = 1024 * 1024;
        let max_json = std::env::var("WASM_MAX_JSON_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_JSON);
        if json_str.len() > max_json {
            tracing::warn!(
                size = json_str.len(),
                limit = max_json,
                "JSON payload exceeds size limit"
            );
            return Err(wit_json::Error::Parseerror);
        }
        let value: serde_json::Value =
            serde_json::from_str(&json_str).map_err(|_| wit_json::Error::Parseerror)?;
        serde_json::to_string_pretty(&value).map_err(|_| wit_json::Error::Parseerror)
    }

    async fn minify(&mut self, json_str: String) -> Result<String, wit_json::Error> {
        // Enforce JSON size limit.
        const DEFAULT_MAX_JSON: usize = 1024 * 1024;
        let max_json = std::env::var("WASM_MAX_JSON_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_JSON);
        if json_str.len() > max_json {
            tracing::warn!(
                size = json_str.len(),
                limit = max_json,
                "JSON payload exceeds size limit"
            );
            return Err(wit_json::Error::Parseerror);
        }
        let value: serde_json::Value =
            serde_json::from_str(&json_str).map_err(|_| wit_json::Error::Parseerror)?;
        serde_json::to_string(&value).map_err(|_| wit_json::Error::Parseerror)
    }
}

/// Recursive deep-merge: `target` is mutated by merging `source` into it.
/// Object keys in `source` override `target`; arrays are replaced.
fn json_merge(target: &mut serde_json::Value, source: serde_json::Value) {
    match (target, source) {
        (serde_json::Value::Object(t), serde_json::Value::Object(s)) => {
            for (k, v) in s {
                let entry = t.entry(k).or_insert(serde_json::Value::Null);
                json_merge(entry, v);
            }
        }
        (target, source) => *target = source,
    }
}

/// Simple dot-notation and `$`-prefix JSON path query.
fn json_path_query<'a>(
    value: &'a serde_json::Value,
    path: &str,
) -> Result<&'a serde_json::Value, wit_json::Error> {
    /// Maximum path segments to prevent O(n) stack usage and ReDoS-style abuse.
    const MAX_PATH_DEPTH: usize = 128;

    let path = path.trim_start_matches("$.").trim_start_matches('$');
    let mut current = value;
    let mut depth = 0usize;
    for segment in path.split('.') {
        depth += 1;
        if depth > MAX_PATH_DEPTH {
            return Err(wit_json::Error::Invalidpath);
        }
        if segment.is_empty() {
            continue;
        }
        // Handle array index: e.g. `items[0]`
        if let Some(bracket_pos) = segment.find('[') {
            let key = &segment[..bracket_pos];
            let idx_str = segment[bracket_pos + 1..].trim_end_matches(']');
            let idx: usize = idx_str.parse().map_err(|_| wit_json::Error::Invalidpath)?;
            if !key.is_empty() {
                current = current.get(key).ok_or(wit_json::Error::Invalidpath)?;
            }
            current = current.get(idx).ok_or(wit_json::Error::Invalidpath)?;
        } else {
            current = current.get(segment).ok_or(wit_json::Error::Invalidpath)?;
        }
    }
    Ok(current)
}

// ============================================================================
// Date / time
// ============================================================================

impl wit_datetime::Host for TalosContext {
    async fn now_unix(&mut self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    async fn now_iso(&mut self) -> String {
        chrono::Utc::now().to_rfc3339()
    }

    async fn parse(
        &mut self,
        date_str: String,
        _format: Option<String>,
    ) -> Result<u64, wit_datetime::Error> {
        // Try RFC 3339 first, then RFC 2822.
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&date_str) {
            return Ok(dt.timestamp() as u64);
        }
        if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(&date_str) {
            return Ok(dt.timestamp() as u64);
        }
        Err(wit_datetime::Error::Parseerror)
    }

    async fn format(
        &mut self,
        timestamp: u64,
        format: String,
    ) -> Result<String, wit_datetime::Error> {
        let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp as i64, 0)
            .ok_or(wit_datetime::Error::Invalidformat)?;
        Ok(dt.format(&format).to_string())
    }

    async fn add_seconds(&mut self, timestamp: u64, seconds: i64) -> u64 {
        (timestamp as i64).saturating_add(seconds) as u64
    }

    async fn diff_seconds(&mut self, timestamp1: u64, timestamp2: u64) -> i64 {
        (timestamp1 as i64).saturating_sub(timestamp2 as i64)
    }
}

// ============================================================================
// Crypto
// ============================================================================

/// Maximum input size for hash/HMAC operations (100 MiB).
/// Prevents a WASM guest from triggering multi-second CPU stalls on the host.
const MAX_HASH_INPUT_BYTES: usize = 100 * 1024 * 1024;

/// Maximum HMAC key size (1 MiB).
/// HMAC keys beyond one block are hashed by the algorithm anyway; this cap
/// prevents host memory pressure from oversized keys.
const MAX_HMAC_KEY_BYTES: usize = 1024 * 1024;

impl wit_crypto::Host for TalosContext {
    async fn hash(&mut self, algorithm: wit_crypto::HashAlgorithm, data: Vec<u8>) -> Vec<u8> {
        // Guard against DoS via oversized input.
        if data.len() > MAX_HASH_INPUT_BYTES {
            tracing::warn!(
                data_len = data.len(),
                limit = MAX_HASH_INPUT_BYTES,
                "hash() input exceeds size limit — returning empty vec"
            );
            return vec![];
        }
        use sha2::Digest;
        match algorithm {
            wit_crypto::HashAlgorithm::Sha256 => sha2::Sha256::digest(&data).to_vec(),
            wit_crypto::HashAlgorithm::Sha512 => sha2::Sha512::digest(&data).to_vec(),
            wit_crypto::HashAlgorithm::Md5 => md5::compute(&data).to_vec(),
        }
    }

    async fn hmac(
        &mut self,
        algorithm: wit_crypto::HashAlgorithm,
        key: Vec<u8>,
        data: Vec<u8>,
    ) -> Vec<u8> {
        // Guard against DoS via oversized key or data.
        if key.len() > MAX_HMAC_KEY_BYTES || data.len() > MAX_HASH_INPUT_BYTES {
            tracing::warn!(
                key_len = key.len(),
                data_len = data.len(),
                "hmac() key or data exceeds size limit — returning empty vec"
            );
            return vec![];
        }
        use hmac::{Hmac, Mac};
        // new_from_slice() accepts any key length for HMAC (unlike block ciphers), so
        // the error branch is unreachable in practice, but we handle it to avoid panics.
        match algorithm {
            wit_crypto::HashAlgorithm::Sha256 => match Hmac::<sha2::Sha256>::new_from_slice(&key) {
                Ok(mut mac) => {
                    mac.update(&data);
                    mac.finalize().into_bytes().to_vec()
                }
                Err(_) => {
                    tracing::warn!("hmac() failed to build HMAC instance");
                    vec![]
                }
            },
            wit_crypto::HashAlgorithm::Sha512 => match Hmac::<sha2::Sha512>::new_from_slice(&key) {
                Ok(mut mac) => {
                    mac.update(&data);
                    mac.finalize().into_bytes().to_vec()
                }
                Err(_) => {
                    tracing::warn!("hmac() failed to build HMAC instance");
                    vec![]
                }
            },
            wit_crypto::HashAlgorithm::Md5 => {
                // HMAC-MD5 is cryptographically weak; fall back to HMAC-SHA256.
                // The md5 0.7 crate is not digest 0.10 compatible, so we cannot
                // construct Hmac::<md5::Md5> directly.  Returning HMAC-SHA256 keeps
                // the interface functional while steering callers away from MD5.
                match Hmac::<sha2::Sha256>::new_from_slice(&key) {
                    Ok(mut mac) => {
                        mac.update(&data);
                        mac.finalize().into_bytes().to_vec()
                    }
                    Err(_) => {
                        tracing::warn!("hmac() fallback HMAC-SHA256 failed");
                        vec![]
                    }
                }
            }
        }
    }

    async fn encode(&mut self, encoding: wit_crypto::Encoding, data: Vec<u8>) -> String {
        match encoding {
            wit_crypto::Encoding::Hex => hex::encode(&data),
            wit_crypto::Encoding::Base64 => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(&data)
            }
            wit_crypto::Encoding::Base64url => {
                use base64::Engine;
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&data)
            }
        }
    }

    async fn decode(
        &mut self,
        encoding: wit_crypto::Encoding,
        data: String,
    ) -> Result<Vec<u8>, wit_crypto::Error> {
        match encoding {
            wit_crypto::Encoding::Hex => {
                hex::decode(&data).map_err(|_| wit_crypto::Error::Invalidinput)
            }
            wit_crypto::Encoding::Base64 => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(&data)
                    .map_err(|_| wit_crypto::Error::Invalidinput)
            }
            wit_crypto::Encoding::Base64url => {
                use base64::Engine;
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(&data)
                    .map_err(|_| wit_crypto::Error::Invalidinput)
            }
        }
    }

    async fn random_bytes(&mut self, length: u32) -> Vec<u8> {
        use rand::RngCore;
        const MAX_RANDOM_BYTES: u32 = 1_000_000; // 1 MB — prevents host memory exhaustion
        if length > MAX_RANDOM_BYTES {
            tracing::warn!(
                "random_bytes() requested {} bytes, exceeds limit of {}; returning empty",
                length,
                MAX_RANDOM_BYTES
            );
            return vec![];
        }
        let mut bytes = vec![0u8; length as usize];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    }

    async fn uuid(&mut self) -> String {
        uuid::Uuid::new_v4().to_string()
    }
}

// ============================================================================
// Cache (Redis)
// ============================================================================

impl wit_cache::Host for TalosContext {
    async fn get(&mut self, key: String) -> Result<String, wit_cache::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Cache | CapabilityWorld::Trusted
        ) {
            tracing::warn!("WASM module attempted cache access but lacks Cache capability");
            return Err(wit_cache::Error::Connectionfailed);
        }

        let redis = self
            .redis_client
            .as_ref()
            .ok_or(wit_cache::Error::Connectionfailed)?;

        use redis::AsyncCommands;
        let mut conn = redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| wit_cache::Error::Connectionfailed)?;
        conn.get::<_, String>(&key)
            .await
            .map_err(|_| wit_cache::Error::Notfound)
    }

    async fn set(
        &mut self,
        key: String,
        value: String,
        ttl: Option<u32>,
    ) -> Result<(), wit_cache::Error> {
        if key.is_empty() || key.len() > 1024 {
            return Err(wit_cache::Error::Operationfailed);
        }
        if value.len() > 10 * 1024 * 1024 {
            // 10MB limit
            tracing::warn!("Cache value exceeds 10MB limit");
            return Err(wit_cache::Error::Operationfailed);
        }

        let redis = self
            .redis_client
            .as_ref()
            .ok_or(wit_cache::Error::Connectionfailed)?;

        use redis::AsyncCommands;
        let mut conn = redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| wit_cache::Error::Connectionfailed)?;
        match ttl {
            Some(secs) => conn
                .set_ex::<_, _, ()>(&key, &value, secs as u64)
                .await
                .map_err(|_| wit_cache::Error::Operationfailed),
            None => conn
                .set::<_, _, ()>(&key, &value)
                .await
                .map_err(|_| wit_cache::Error::Operationfailed),
        }
    }

    async fn delete(&mut self, key: String) -> Result<(), wit_cache::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Cache | CapabilityWorld::Trusted
        ) {
            tracing::warn!("WASM module attempted cache access but lacks Cache capability");
            return Err(wit_cache::Error::Connectionfailed);
        }

        let redis = self
            .redis_client
            .as_ref()
            .ok_or(wit_cache::Error::Connectionfailed)?;

        use redis::AsyncCommands;
        let mut conn = redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| wit_cache::Error::Connectionfailed)?;
        conn.del::<_, ()>(&key)
            .await
            .map_err(|_| wit_cache::Error::Operationfailed)
    }

    async fn exists(&mut self, key: String) -> bool {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Cache | CapabilityWorld::Trusted
        ) {
            return false;
        }
        let Some(redis) = &self.redis_client else {
            return false;
        };

        use redis::AsyncCommands;
        let Ok(mut conn) = redis.get_multiplexed_async_connection().await else {
            return false;
        };
        conn.exists::<_, bool>(&key).await.unwrap_or(false)
    }

    async fn increment(&mut self, key: String, amount: i64) -> Result<i64, wit_cache::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Cache | CapabilityWorld::Trusted
        ) {
            tracing::warn!("WASM module attempted cache access but lacks Cache capability");
            return Err(wit_cache::Error::Connectionfailed);
        }

        let redis = self
            .redis_client
            .as_ref()
            .ok_or(wit_cache::Error::Connectionfailed)?;

        use redis::AsyncCommands;
        let mut conn = redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| wit_cache::Error::Connectionfailed)?;
        conn.incr::<_, _, i64>(&key, amount)
            .await
            .map_err(|_| wit_cache::Error::Operationfailed)
    }

    async fn decrement(&mut self, key: String, amount: i64) -> Result<i64, wit_cache::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Cache | CapabilityWorld::Trusted
        ) {
            tracing::warn!("WASM module attempted cache access but lacks Cache capability");
            return Err(wit_cache::Error::Connectionfailed);
        }

        self.increment(key, -amount).await
    }

    async fn mget(&mut self, keys: Vec<String>) -> Result<Vec<Option<String>>, wit_cache::Error> {
        let redis = self
            .redis_client
            .as_ref()
            .ok_or(wit_cache::Error::Connectionfailed)?;

        use redis::AsyncCommands;
        let mut conn = redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| wit_cache::Error::Connectionfailed)?;
        conn.mget::<_, Vec<Option<String>>>(keys)
            .await
            .map_err(|_| wit_cache::Error::Operationfailed)
    }

    async fn mset(&mut self, pairs: Vec<(String, String)>) -> Result<(), wit_cache::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Cache | CapabilityWorld::Trusted
        ) {
            tracing::warn!("WASM module attempted cache access but lacks Cache capability");
            return Err(wit_cache::Error::Connectionfailed);
        }

        let redis = self
            .redis_client
            .as_ref()
            .ok_or(wit_cache::Error::Connectionfailed)?;

        use redis::AsyncCommands;
        let mut conn = redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| wit_cache::Error::Connectionfailed)?;
        conn.mset::<_, _, ()>(&pairs)
            .await
            .map_err(|_| wit_cache::Error::Operationfailed)
    }

    async fn expire(&mut self, key: String, ttl: u32) -> Result<(), wit_cache::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Cache | CapabilityWorld::Trusted
        ) {
            tracing::warn!("WASM module attempted cache access but lacks Cache capability");
            return Err(wit_cache::Error::Connectionfailed);
        }

        let redis = self
            .redis_client
            .as_ref()
            .ok_or(wit_cache::Error::Connectionfailed)?;

        use redis::AsyncCommands;
        let mut conn = redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| wit_cache::Error::Connectionfailed)?;
        conn.expire::<_, ()>(&key, ttl as i64)
            .await
            .map_err(|_| wit_cache::Error::Operationfailed)
    }
}

// ============================================================================
// Messaging (NATS)
// ============================================================================

impl wit_messaging::Host for TalosContext {
    async fn publish(
        &mut self,
        topic: String,
        payload: Vec<u8>,
    ) -> Result<(), wit_messaging::Error> {
        if payload.len() > 10 * 1024 * 1024 {
            // 10MB limit
            tracing::warn!("Message payload exceeds 10MB limit");
            return Err(wit_messaging::Error::Publishfailed);
        }
        let nats = self
            .nats_client
            .as_ref()
            .ok_or(wit_messaging::Error::Connectionfailed)?;
        let nats = nats.clone();

        nats.publish(topic, payload.into())
            .await
            .map_err(|_| wit_messaging::Error::Publishfailed)
    }

    async fn publish_with_headers(
        &mut self,
        msg: wit_messaging::Message,
    ) -> Result<(), wit_messaging::Error> {
        if msg.payload.len() > 10 * 1024 * 1024 {
            // 10MB limit
            tracing::warn!("Message payload exceeds 10MB limit");
            return Err(wit_messaging::Error::Publishfailed);
        }
        let nats = self
            .nats_client
            .as_ref()
            .ok_or(wit_messaging::Error::Connectionfailed)?;
        let nats = nats.clone();

        let mut headers = async_nats::HeaderMap::new();
        if let Some(hdr_list) = msg.headers {
            for (k, v) in hdr_list {
                headers.insert(k.as_str(), v.as_str());
            }
        }
        nats.publish_with_headers(msg.topic, headers, msg.payload.into())
            .await
            .map_err(|_| wit_messaging::Error::Publishfailed)
    }

    async fn request(
        &mut self,
        topic: String,
        payload: Vec<u8>,
        timeout_ms: u32,
    ) -> Result<Vec<u8>, wit_messaging::Error> {
        let nats = self
            .nats_client
            .as_ref()
            .ok_or(wit_messaging::Error::Connectionfailed)?;
        let nats = nats.clone();

        let reply = tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms as u64),
            nats.request(topic, payload.into()),
        )
        .await
        .map_err(|_| wit_messaging::Error::Publishfailed)?
        .map_err(|_| wit_messaging::Error::Publishfailed)?;
        Ok(reply.payload.to_vec())
    }
}

// ============================================================================
// GraphQL client
// ============================================================================

impl wit_graphql::Host for TalosContext {
    async fn execute(
        &mut self,
        req: wit_graphql::Request,
    ) -> Result<wit_graphql::Response, wit_graphql::Error> {
        self.execute_graphql_inner(req, 0).await
    }

    async fn execute_with_retry(
        &mut self,
        req: wit_graphql::Request,
        max_retries: u32,
    ) -> Result<wit_graphql::Response, wit_graphql::Error> {
        self.execute_graphql_inner(req, max_retries).await
    }
}

impl TalosContext {
    async fn execute_graphql_inner(
        &mut self,
        req: wit_graphql::Request,
        max_retries: u32,
    ) -> Result<wit_graphql::Response, wit_graphql::Error> {
        let url = req.url.clone();
        let query = req.query.clone();
        let variables = req.variables.clone();
        let headers = req.headers.clone().unwrap_or_default();
        let timeout_ms = req.timeout_ms.unwrap_or(30_000) as u64;

        // Reject oversized queries and variable payloads to prevent sending
        // multi-GB requests to the remote server (OOM + bandwidth abuse).
        const MAX_GRAPHQL_QUERY_BYTES: usize = 1_000_000; // 1 MB
        if query.len() > MAX_GRAPHQL_QUERY_BYTES {
            return Err(wit_graphql::Error::Networkerror);
        }
        if let Some(ref vars) = variables {
            if vars.len() > MAX_GRAPHQL_QUERY_BYTES {
                return Err(wit_graphql::Error::Invalidvariables);
            }
        }

        let allowed_hosts = self.allowed_hosts.clone();

        // Enforce host allowlist for GraphQL endpoints too.
        // Empty allowlist = DENY ALL (same policy as the HTTP host function).
        {
            let parsed: url::Url = url.parse().map_err(|_| wit_graphql::Error::Networkerror)?;
            let host = parsed.host_str().unwrap_or("");
            if allowed_hosts.is_empty() {
                tracing::warn!(
                    host,
                    "WASM module attempted GraphQL request but no host allowlist is \
                             configured — denying."
                );
                return Err(wit_graphql::Error::Networkerror);
            }
            if !allowed_hosts.iter().any(|a| a == "*" || a == host) {
                return Err(wit_graphql::Error::Networkerror);
            }
        }

        // GraphQL requests are always POST. Reject if POST is not in the allowlist.
        let allowed_methods = self.allowed_methods.clone();
        if !allowed_methods.is_empty()
            && !allowed_methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case("POST"))
        {
            tracing::warn!(
                "WASM module attempted GraphQL (POST) but POST is not in allowed_methods"
            );
            return Err(wit_graphql::Error::Networkerror);
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| wit_graphql::Error::Networkerror)?;

        let mut body = serde_json::json!({ "query": query });
        if let Some(vars) = variables {
            let vars_val: serde_json::Value =
                serde_json::from_str(&vars).map_err(|_| wit_graphql::Error::Invalidvariables)?;
            body["variables"] = vars_val;
        }

        let mut attempts = 0;
        loop {
            let mut req_builder = client.post(&url).json(&body);
            for (k, v) in &headers {
                req_builder = req_builder.header(k.as_str(), v.as_str());
            }

            let result = req_builder.send().await;
            attempts += 1;

            match result {
                Ok(resp) => {
                    // Cap GraphQL response at 10 MB to prevent WASM OOM from
                    // malicious or oversized remote server responses (H6).
                    const MAX_GRAPHQL_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
                    let mut bytes = Vec::new();
                    let mut stream = resp.bytes_stream();
                    use futures_util::StreamExt;
                    while let Some(chunk_result) = stream.next().await {
                        let chunk = chunk_result.map_err(|_| wit_graphql::Error::Parseerror)?;
                        if bytes.len() + chunk.len() > MAX_GRAPHQL_RESPONSE_BYTES {
                            tracing::warn!(
                                "GraphQL response exceeds 10 MB size limit during streaming"
                            );
                            return Err(wit_graphql::Error::Parseerror);
                        }
                        bytes.extend_from_slice(&chunk);
                    }
                    let resp_json: serde_json::Value = serde_json::from_slice(&bytes)
                        .map_err(|_| wit_graphql::Error::Parseerror)?;

                    let data = resp_json.get("data").map(|d| d.to_string());
                    let errors = resp_json
                        .get("errors")
                        .and_then(|e| e.as_array())
                        .map(|arr| arr.iter().map(|e| e.to_string()).collect::<Vec<_>>());

                    return Ok(wit_graphql::Response { data, errors });
                }
                Err(_) if attempts <= max_retries => {
                    // Cap backoff at 30 s to prevent indefinitely blocked workers.
                    let backoff_ms = (100u64 * 2u64.saturating_pow(attempts - 1)).min(30_000);
                    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                }
                Err(_) => return Err(wit_graphql::Error::Networkerror),
            }
        }
    }
}

// ============================================================================
// Webhook sender
// ============================================================================

impl wit_webhook::Host for TalosContext {
    async fn send(
        &mut self,
        req: wit_webhook::WebhookRequest,
    ) -> Result<wit_webhook::WebhookResponse, wit_webhook::Error> {
        let url = req.url.clone();
        let headers = req.headers.clone();
        let body = req.body.clone();
        let max_retries = req.max_retries.unwrap_or(3);
        let retry_delay_ms = req.retry_delay_ms.unwrap_or(1_000) as u64;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| wit_webhook::Error::Sendfailed)?;

        let mut retries = 0u32;
        loop {
            let mut req_builder = client.post(&url).body(body.clone());
            for (k, v) in &headers {
                req_builder = req_builder.header(k.as_str(), v.as_str());
            }

            match req_builder.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    const MAX_WEBHOOK_RESP_BYTES: usize = 1_000_000;
                    let mut bytes = Vec::new();
                    let mut stream = resp.bytes_stream();
                    use futures_util::StreamExt;
                    while let Some(chunk_result) = stream.next().await {
                        if let Ok(chunk) = chunk_result {
                            let remaining = MAX_WEBHOOK_RESP_BYTES.saturating_sub(bytes.len());
                            if remaining > 0 {
                                let take = chunk.len().min(remaining);
                                bytes.extend_from_slice(&chunk[..take]);
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    let body = String::from_utf8_lossy(&bytes).into_owned();
                    return Ok(wit_webhook::WebhookResponse {
                        status,
                        body,
                        retries,
                    });
                }
                Err(e) if retries < max_retries => {
                    retries += 1;
                    if e.is_timeout() {
                        return Err(wit_webhook::Error::Timeout);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(retry_delay_ms)).await;
                }
                Err(e) => {
                    return Err(if e.is_timeout() {
                        wit_webhook::Error::Timeout
                    } else {
                        wit_webhook::Error::Sendfailed
                    });
                }
            }
        }
    }
}

// ============================================================================
// Email (SMTP via lettre — stubbed; provide SMTP_* env vars to enable)
// ============================================================================

impl wit_email::Host for TalosContext {
    async fn send(&mut self, msg: wit_email::Message) -> Result<(), wit_email::Error> {
        // Validate recipient addresses.
        for addr in &msg.to {
            if !addr.contains('@') {
                return Err(wit_email::Error::Invalidaddress);
            }
        }

        // Log the email as a structured event for now; wire up a real SMTP
        // client (e.g. lettre) when SMTP_HOST is configured.
        tracing::info!(
            to = ?msg.to,
            subject = msg.subject,
            "[WASM email] Email send requested (SMTP not yet configured)"
        );

        // Return Ok rather than failing — callers should not break if email
        // is not configured in development.
        Ok(())
    }
}

// ============================================================================
// Database (placeholder — enforce row-level scoping in production)
// ============================================================================

impl wit_database::Host for TalosContext {
    async fn execute_query(
        &mut self,
        sql: String,
        params: Vec<String>,
    ) -> Result<wit_database::QueryResult, wit_database::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Database | CapabilityWorld::Trusted
        ) {
            tracing::warn!("WASM module attempted database access but lacks Database capability");
            return Err(wit_database::Error::Connectionfailed);
        }
        if let Some(ledger_mutex) = &self.audit_ledger {
            let mut ledger = ledger_mutex.lock().await;
            let event = ledger.append(
                "agent:wasm",
                "wasi:database_execute_query",
                &serde_json::json!({
                    "sql": sql,
                    "params": params,
                })
                .to_string(),
            );
            if let Some(n) = &self.nats_client {
                let payload = serde_json::json!({
                    "event": event.clone(),
                    "hash": event.calculate_hash()
                });
                let _ = n
                    .publish(
                        "talos.audit.ledger".to_string(),
                        serde_json::to_vec(&payload).unwrap_or_default().into(),
                    )
                    .await;
            }
        }
        let pool = match &self.db_pool {
            Some(pool) => pool.clone(),
            None => {
                tracing::warn!("[WASM] database connection pool is not configured");
                return Err(wit_database::Error::Connectionfailed);
            }
        };

        // Check if it's a SELECT or RETURNING query to determine whether to fetch rows.
        let is_fetch = sql.trim_start().to_uppercase().starts_with("SELECT")
            || sql.to_uppercase().contains("RETURNING");

        if is_fetch {
            // Wrap the query to make Postgres do the JSON serialization for us!
            // This handles arbitrary generic columns (dates, UUIDs, custom types) automatically.
            let wrapped_sql = format!(
                "SELECT COALESCE(json_agg(t), '[]'::json) AS json_res FROM ({}) t",
                sql
            );

            let mut query = sqlx::query(&wrapped_sql);
            for p in &params {
                query = query.bind(p);
            }

            use sqlx::Row;
            let row = query.fetch_one(&pool).await.map_err(|e| {
                tracing::error!("Database query error: {}", e);
                wit_database::Error::Queryerror
            })?;

            // The result is a single JSON value.
            let json_val: serde_json::Value = row.try_get("json_res").map_err(|e| {
                tracing::error!("Database parsing error: {}", e);
                wit_database::Error::Queryerror
            })?;

            let rows_str = json_val.to_string();
            if rows_str.len() > 10 * 1024 * 1024 {
                tracing::warn!("Database query result exceeds 10MB limit");
                return Err(wit_database::Error::Queryerror);
            }

            Ok(wit_database::QueryResult {
                rows: rows_str,
                rows_affected: 0,
            })
        } else {
            let mut query = sqlx::query(&sql);
            for p in &params {
                query = query.bind(p);
            }

            let result = query.execute(&pool).await.map_err(|e| {
                tracing::error!("Database execute error: {}", e);
                wit_database::Error::Queryerror
            })?;

            Ok(wit_database::QueryResult {
                rows: "[]".to_string(),
                rows_affected: result.rows_affected() as u64,
            })
        }
    }
}

// ============================================================================
// Files (capability-based sandbox)
// ============================================================================

impl wit_files::Host for TalosContext {
    async fn read(&mut self, path: String) -> Result<Vec<u8>, wit_files::Error> {
        let safe_path = sanitize_path(&path)?;
        tokio::task::block_in_place(|| self.fs_dir.read(&safe_path)).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => wit_files::Error::Notfound,
            std::io::ErrorKind::PermissionDenied => wit_files::Error::Permissiondenied,
            _ => wit_files::Error::Ioerror,
        })
    }

    async fn write(&mut self, path: String, contents: Vec<u8>) -> Result<(), wit_files::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Filesystem | CapabilityWorld::Trusted
        ) {
            tracing::warn!("WASM module attempted file access but lacks Filesystem capability");
            return Err(wit_files::Error::Permissiondenied);
        }

        let safe_path = sanitize_path(&path)?;
        tokio::task::block_in_place(|| {
            // Create parent directories within the sandbox if needed.
            if let Some(parent) = safe_path.parent() {
                if parent != std::path::Path::new("") {
                    self.fs_dir
                        .create_dir_all(parent)
                        .map_err(|_| wit_files::Error::Ioerror)?;
                }
            }
            self.fs_dir
                .write(&safe_path, &contents)
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::PermissionDenied => wit_files::Error::Permissiondenied,
                    _ => wit_files::Error::Ioerror,
                })
        })
    }

    async fn exists(&mut self, path: String) -> bool {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Filesystem | CapabilityWorld::Trusted
        ) {
            return false;
        }
        sanitize_path(&path)
            .map(|p| tokio::task::block_in_place(|| self.fs_dir.metadata(&p).is_ok()))
            .unwrap_or(false)
    }

    async fn metadata(
        &mut self,
        path: String,
    ) -> Result<wit_files::FileMetadata, wit_files::Error> {
        let safe_path = sanitize_path(&path)?;
        let meta = tokio::task::block_in_place(|| {
            self.fs_dir
                .metadata(&safe_path)
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::NotFound => wit_files::Error::Notfound,
                    _ => wit_files::Error::Ioerror,
                })
        })?;
        let modified_unix = meta
            .modified()
            .ok()
            .and_then(|t| t.into_std().duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Ok(wit_files::FileMetadata {
            size: meta.len(),
            modified_unix,
            is_directory: meta.is_dir(),
        })
    }

    async fn list_dir(&mut self, path: String) -> Result<Vec<String>, wit_files::Error> {
        let safe_path = sanitize_path(&path)?;
        tokio::task::block_in_place(|| {
            let entries = self
                .fs_dir
                .read_dir(&safe_path)
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::NotFound => wit_files::Error::Notfound,
                    _ => wit_files::Error::Ioerror,
                })?;
            // Limit the number of entries to prevent OOM on directories with millions of files.
            const MAX_DIR_ENTRIES: usize = 10_000;
            let names: Vec<String> = entries
                .flatten()
                .take(MAX_DIR_ENTRIES)
                .filter_map(|e| e.file_name().into_string().ok())
                .collect();
            Ok(names)
        })
    }

    async fn delete(&mut self, path: String) -> Result<(), wit_files::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Filesystem | CapabilityWorld::Trusted
        ) {
            tracing::warn!("WASM module attempted file access but lacks Filesystem capability");
            return Err(wit_files::Error::Permissiondenied);
        }

        let safe_path = sanitize_path(&path)?;
        tokio::task::block_in_place(|| {
            let is_dir = self
                .fs_dir
                .metadata(&safe_path)
                .map(|m| m.is_dir())
                .unwrap_or(false);
            if is_dir {
                self.fs_dir.remove_dir_all(&safe_path)
            } else {
                self.fs_dir.remove_file(&safe_path)
            }
            .map_err(|_| wit_files::Error::Ioerror)
        })
    }
}

/// Strip `..` components and leading `/` to prevent path traversal attacks.
fn sanitize_path(path: &str) -> Result<std::path::PathBuf, wit_files::Error> {
    use std::path::{Component, PathBuf};
    let mut safe = PathBuf::new();
    for component in std::path::Path::new(path).components() {
        match component {
            Component::Normal(c) => safe.push(c),
            Component::CurDir => {}
            // Reject any attempt to escape the sandbox.
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(wit_files::Error::Invalidpath);
            }
        }
    }
    Ok(safe)
}

// ============================================================================
// Templates (Jinja2-compatible via minijinja)
// ============================================================================

impl wit_templates::Host for TalosContext {
    async fn render(
        &mut self,
        template: String,
        variables: String,
        _syntax: wit_templates::Syntax,
    ) -> Result<String, wit_templates::Error> {
        /// 1 MB template source limit — prevents parser memory exhaustion.
        const MAX_TEMPLATE_BYTES: usize = 1_000_000;
        /// 10 MB rendered output limit — prevents loop-amplification attacks.
        const MAX_RENDERED_BYTES: usize = 10_000_000;

        if template.len() > MAX_TEMPLATE_BYTES {
            tracing::warn!(
                "Template source too large ({} bytes, limit {})",
                template.len(),
                MAX_TEMPLATE_BYTES
            );
            return Err(wit_templates::Error::Parseerror);
        }

        /// 10 MB variables limit — prevents memory exhaustion from a very large JSON blob.
        const MAX_VARIABLES_BYTES: usize = 10_000_000;
        if variables.len() > MAX_VARIABLES_BYTES {
            tracing::warn!(
                "Template variables too large ({} bytes, limit {})",
                variables.len(),
                MAX_VARIABLES_BYTES
            );
            return Err(wit_templates::Error::Parseerror);
        }

        let vars: serde_json::Value =
            serde_json::from_str(&variables).map_err(|_| wit_templates::Error::Parseerror)?;

        let mut env = minijinja::Environment::new();
        // Auto-escape HTML by default for security (prevents XSS).
        env.set_auto_escape_callback(|_| minijinja::AutoEscape::Html);
        env.add_template("__inline__", &template)
            .map_err(|_| wit_templates::Error::Parseerror)?;
        let tmpl = env
            .get_template("__inline__")
            .map_err(|_| wit_templates::Error::Parseerror)?;
        let rendered = tmpl
            .render(minijinja::Value::from_serialize(&vars))
            .map_err(|_| wit_templates::Error::Rendererror)?;

        if rendered.len() > MAX_RENDERED_BYTES {
            tracing::warn!(
                "Rendered template output too large ({} bytes, limit {})",
                rendered.len(),
                MAX_RENDERED_BYTES
            );
            return Err(wit_templates::Error::Rendererror);
        }

        Ok(rendered)
    }

    async fn render_file(
        &mut self,
        path: String,
        variables: String,
        syntax: wit_templates::Syntax,
    ) -> Result<String, wit_templates::Error> {
        let contents = <TalosContext as wit_files::Host>::read(self, path)
            .await
            .map_err(|_| wit_templates::Error::Parseerror)?;
        let template = String::from_utf8(contents).map_err(|_| wit_templates::Error::Parseerror)?;
        self.render(template, variables, syntax).await
    }
}

// ============================================================================
// Data transform (CSV / XML)
// ============================================================================

/// Maximum number of CSV rows accepted by `csv_to_json`.
/// Prevents host memory exhaustion from a single oversized payload.
const MAX_CSV_ROWS: usize = 100_000;
/// Maximum CSV input size (10 MB). A row-only limit can be bypassed by wide records.
const MAX_CSV_BYTES: usize = 10_000_000;
/// Maximum number of columns in a CSV file to prevent memory exhaustion.
const MAX_CSV_COLUMNS: usize = 1_000;

impl wit_data_transform::Host for TalosContext {
    async fn csv_to_json(
        &mut self,
        csv_input: String,
        options: Option<wit_data_transform::CsvOptions>,
    ) -> Result<String, wit_data_transform::Error> {
        if csv_input.len() > MAX_CSV_BYTES {
            tracing::warn!(
                "csv_to_json input too large ({} bytes, limit {})",
                csv_input.len(),
                MAX_CSV_BYTES
            );
            return Err(wit_data_transform::Error::Parseerror);
        }

        let delimiter = options
            .as_ref()
            .and_then(|o| o.delimiter.as_deref())
            .and_then(|d| d.chars().next())
            .unwrap_or(',') as u8;
        let has_headers = options.as_ref().map(|o| o.has_headers).unwrap_or(true);

        let mut rdr = csv::ReaderBuilder::new()
            .delimiter(delimiter)
            .has_headers(has_headers)
            .from_reader(csv_input.as_bytes());

        if has_headers {
            let headers: Vec<String> = rdr
                .headers()
                .map_err(|_| wit_data_transform::Error::Parseerror)?
                .iter()
                .map(|s| s.to_string())
                .collect();

            if headers.len() > MAX_CSV_COLUMNS {
                tracing::warn!(
                    "csv_to_json too many columns ({}, limit {})",
                    headers.len(),
                    MAX_CSV_COLUMNS
                );
                return Err(wit_data_transform::Error::Invalidformat);
            }

            let mut rows = Vec::new();
            for result in rdr.records() {
                if rows.len() >= MAX_CSV_ROWS {
                    return Err(wit_data_transform::Error::Invalidformat);
                }
                let record = result.map_err(|_| wit_data_transform::Error::Parseerror)?;
                let mut map = serde_json::Map::new();
                for (i, field) in record.iter().enumerate() {
                    let key = headers.get(i).map(|s| s.as_str()).unwrap_or("unknown");
                    map.insert(
                        key.to_string(),
                        serde_json::Value::String(field.to_string()),
                    );
                }
                rows.push(serde_json::Value::Object(map));
            }
            serde_json::to_string(&rows).map_err(|_| wit_data_transform::Error::Parseerror)
        } else {
            let mut rows = Vec::new();
            for result in rdr.records() {
                if rows.len() >= MAX_CSV_ROWS {
                    return Err(wit_data_transform::Error::Invalidformat);
                }
                let record = result.map_err(|_| wit_data_transform::Error::Parseerror)?;
                let arr: Vec<serde_json::Value> = record
                    .iter()
                    .map(|f| serde_json::Value::String(f.to_string()))
                    .collect();
                rows.push(serde_json::Value::Array(arr));
            }
            serde_json::to_string(&rows).map_err(|_| wit_data_transform::Error::Parseerror)
        }
    }

    async fn json_to_csv(
        &mut self,
        json_input: String,
        options: Option<wit_data_transform::CsvOptions>,
    ) -> Result<String, wit_data_transform::Error> {
        let delimiter = options
            .as_ref()
            .and_then(|o| o.delimiter.as_deref())
            .and_then(|d| d.chars().next())
            .unwrap_or(',') as u8;

        let rows: Vec<serde_json::Value> =
            serde_json::from_str(&json_input).map_err(|_| wit_data_transform::Error::Parseerror)?;

        let mut output = Vec::new();
        {
            let mut wtr = csv::WriterBuilder::new()
                .delimiter(delimiter)
                .from_writer(&mut output);

            // Collect headers from first object.
            let headers: Vec<String> = rows
                .first()
                .and_then(|r| r.as_object())
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();

            if !headers.is_empty() {
                wtr.write_record(&headers)
                    .map_err(|_| wit_data_transform::Error::Invalidformat)?;
            }

            for row in &rows {
                if let Some(obj) = row.as_object() {
                    let record: Vec<String> = headers
                        .iter()
                        .map(|h| {
                            obj.get(h)
                                .map(|v| match v {
                                    serde_json::Value::String(s) => s.clone(),
                                    other => other.to_string(),
                                })
                                .unwrap_or_default()
                        })
                        .collect();
                    wtr.write_record(&record)
                        .map_err(|_| wit_data_transform::Error::Invalidformat)?;
                }
            }
            wtr.flush()
                .map_err(|_| wit_data_transform::Error::Ioerror)?;
        }

        String::from_utf8(output).map_err(|_| wit_data_transform::Error::Invalidformat)
    }

    async fn xml_to_json(&mut self, xml: String) -> Result<String, wit_data_transform::Error> {
        let value = xml_string_to_json(&xml)?;
        serde_json::to_string(&value).map_err(|_| wit_data_transform::Error::Parseerror)
    }

    async fn json_to_xml(
        &mut self,
        json: String,
        root_element: String,
    ) -> Result<String, wit_data_transform::Error> {
        let value: serde_json::Value =
            serde_json::from_str(&json).map_err(|_| wit_data_transform::Error::Parseerror)?;
        let xml = json_value_to_xml(&value, &root_element);
        Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>{}", xml))
    }
}

/// Very simple XML → JSON converter (element names become keys, text content becomes values).
fn xml_string_to_json(xml: &str) -> Result<serde_json::Value, wit_data_transform::Error> {
    use quick_xml::events::Event;
    use quick_xml::Reader;
    use std::collections::VecDeque;

    /// Maximum nesting depth to prevent stack exhaustion via deeply nested XML.
    const MAX_XML_DEPTH: usize = 1_000;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut stack: VecDeque<(String, serde_json::Map<String, serde_json::Value>)> = VecDeque::new();
    let mut root: Option<serde_json::Value> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                if stack.len() >= MAX_XML_DEPTH {
                    tracing::warn!("xml_to_json: nesting depth exceeded {}", MAX_XML_DEPTH);
                    return Err(wit_data_transform::Error::Parseerror);
                }
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                stack.push_back((name, serde_json::Map::new()));
            }
            Ok(Event::Text(e)) => {
                if let Some((_, obj)) = stack.back_mut() {
                    let text = e
                        .unescape()
                        .map_err(|_| wit_data_transform::Error::Parseerror)?;
                    if !text.trim().is_empty() {
                        obj.insert(
                            "#text".to_string(),
                            serde_json::Value::String(text.to_string()),
                        );
                    }
                }
            }
            Ok(Event::End(_)) => {
                if let Some((name, obj)) = stack.pop_back() {
                    let value = if obj.len() == 1 && obj.contains_key("#text") {
                        obj["#text"].clone()
                    } else {
                        serde_json::Value::Object(obj)
                    };
                    if let Some((_, parent)) = stack.back_mut() {
                        parent.insert(name, value);
                    } else {
                        root = Some(serde_json::json!({ name: value }));
                    }
                }
            }
            Ok(Event::Empty(e)) => {
                if let Some((_, parent)) = stack.back_mut() {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    parent.insert(name, serde_json::Value::Null);
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err(wit_data_transform::Error::Parseerror),
            _ => {}
        }
    }

    root.ok_or(wit_data_transform::Error::Parseerror)
}

/// Simple JSON → XML serialiser.
fn json_value_to_xml(value: &serde_json::Value, element: &str) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let inner: String = map.iter().map(|(k, v)| json_value_to_xml(v, k)).collect();
            format!("<{}>{}</{}>", element, inner, element)
        }
        serde_json::Value::Array(arr) => {
            arr.iter().map(|v| json_value_to_xml(v, element)).collect()
        }
        serde_json::Value::String(s) => {
            format!("<{}>{}</{}>", element, escape_xml(s), element)
        }
        other => format!("<{}>{}</{}>", element, other, element),
    }
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

use wasmtime_wasi_http::bindings::http::types::{
    FutureIncomingResponse, OutgoingRequest, RequestOptions,
};
use wasmtime_wasi_http::HttpError;

impl wasmtime_wasi_http::bindings::http::outgoing_handler::Host for TalosContext {
    fn handle(
        &mut self,
        _request: wasmtime::component::Resource<OutgoingRequest>,
        _options: Option<wasmtime::component::Resource<RequestOptions>>,
    ) -> std::result::Result<wasmtime::component::Resource<FutureIncomingResponse>, HttpError> {
        Err(HttpError::trap(anyhow::anyhow!("wasi:http/outgoing-handler is configured but not yet implemented. Please use talos:core/http instead.")))
    }
}

use crate::bindings::talos::core::governance;
impl governance::Host for TalosContext {
    async fn request_approval(&mut self, reason: String) -> bool {
        if let Some(ledger_mutex) = &self.audit_ledger {
            let mut ledger = ledger_mutex.lock().await;
            let event = ledger.append(
                "agent:wasm",
                "wasi:human_approval_request",
                &serde_json::json!({
                    "reason": reason
                })
                .to_string(),
            );
            // Optionally, publish the event to a WORM NATS stream
            if let Some(n) = &self.nats_client {
                let payload = serde_json::json!({
                    "event": event.clone(),
                    "hash": event.calculate_hash()
                });
                let _ = n
                    .publish(
                        "talos.audit.ledger".to_string(),
                        serde_json::to_vec(&payload).unwrap_or_default().into(),
                    )
                    .await;
            }
        }

        let exec_id = self
            .execution_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        let workflow_id = self
            .workflow_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        let nats = match &self.nats_client {
            Some(n) => n,
            None => {
                tracing::error!("NATS client not available for governance approvals");
                return false;
            }
        };

        let redis = match &self.redis_client {
            Some(r) => r,
            None => {
                tracing::error!("Redis client not available for governance approvals");
                return false;
            }
        };

        let reply_topic = format!("talos.approvals.wait.{}", exec_id);

        // 1. Subscribe to the reply topic FIRST so we don't miss the message
        let mut subscriber = match nats.subscribe(reply_topic.clone()).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to subscribe to NATS topic {}: {}", reply_topic, e);
                return false;
            }
        };

        // 2. Write to Redis
        let mut con = match redis.get_multiplexed_tokio_connection().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to get Redis connection: {}", e);
                return false;
            }
        };

        // The frontend UI is sending the overall `workflow_execution_id` to the API webhook,
        // not the node-specific `exec_id`.
        let redis_key = format!("approval:{}", workflow_id);
        let _: redis::RedisResult<()> = redis::cmd("SET")
            .arg(&redis_key)
            .arg(&reply_topic)
            .arg("EX")
            .arg(86400) // 24 hours
            .query_async(&mut con)
            .await;

        // 3. Publish pending notification
        let payload = serde_json::json!({
            "execution_id": exec_id,
            "reason": reason
        })
        .to_string();

        if let Err(e) = nats
            .publish("talos.approvals.pending".to_string(), payload.into())
            .await
        {
            tracing::error!("Failed to publish pending approval notification: {}", e);
            // Continue anyway, maybe it was logged elsewhere
        }

        tracing::info!(
            "Paused execution {} waiting for approval on {}",
            exec_id,
            reply_topic
        );

        // 4. Await the response
        use futures_util::stream::StreamExt;
        if let Some(msg) = subscriber.next().await {
            // Delete Redis key (best effort)
            let _: redis::RedisResult<()> = redis::cmd("DEL")
                .arg(&redis_key)
                .query_async(&mut con)
                .await;

            let response_str = String::from_utf8_lossy(&msg.payload);
            let approved = response_str.trim().to_lowercase() == "true";
            tracing::info!("Received approval response for {}: {}", exec_id, approved);

            if let Some(ledger_mutex) = &self.audit_ledger {
                let mut ledger = ledger_mutex.lock().await;
                let event = ledger.append(
                    "human:webhook",
                    "wasi:human_approval_response",
                    &serde_json::json!({
                        "approved": approved
                    })
                    .to_string(),
                );
                if let Some(n) = &self.nats_client {
                    let _ = n
                        .publish(
                            "talos.audit.ledger".to_string(),
                            serde_json::to_vec(&event).unwrap_or_default().into(),
                        )
                        .await;
                }
            }
            return approved;
        }

        false
    }
}
