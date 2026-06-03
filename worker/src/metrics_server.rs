use crate::TalosRuntime;
use std::collections::{HashMap, HashSet};
/// HTTP server for Prometheus metrics endpoint
///
/// This module provides a production-hardened HTTP server that exposes /metrics and /health
/// endpoints for monitoring with Prometheus and Kubernetes.
///
/// # Security Features
///
/// - **Connection limiting**: Max 100 concurrent connections to prevent DoS
/// - **Request timeouts**: 10s total timeout, 5s read timeout
/// - **Buffer limits**: 4KB max request size
/// - **Optional authentication**: Bearer token support via METRICS_AUTH_TOKENS env var
/// - **Rate limiting**: Per-IP rate limiting (60 requests/minute)
///
/// # Usage
/// ```rust
/// use worker::metrics_server::start_metrics_server;
/// use worker::TalosRuntime;
/// use std::sync::Arc;
///
/// #[tokio::main]
/// async fn main() {
///     let runtime = Arc::new(TalosRuntime::new().expect("Failed to serialize health status"));
///
///     // Provide a dummy token for the example environment
///     std::env::set_var("METRICS_AUTH_TOKENS", "example-token");
///
///     // Start metrics server on port 9090
///     let metrics_handle = start_metrics_server(runtime.clone(), 9090)
///         .expect("failed to start metrics server");
///
///     // ... do work ...
///
///     // Shutdown metrics server when done
///     metrics_handle.abort();
/// }
/// ```
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;
use tokio::sync::Semaphore;

/// Rate limiter for per-IP request limiting
struct RateLimiter {
    // IP -> (request_count, window_start)
    requests: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
    max_requests_per_window: u32,
    window_duration: std::time::Duration,
}

impl RateLimiter {
    fn new(max_requests_per_window: u32, window_duration: std::time::Duration) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests_per_window,
            window_duration,
        }
    }

    /// Check if request should be allowed for this IP
    fn check_rate_limit(&self, ip: &str) -> bool {
        let mut requests = match self.requests.lock() {
            Ok(r) => r,
            Err(_) => return true, // Fail open on poison error
        };

        let now = Instant::now();

        // SECURITY: Prevent unbounded memory growth if flooded with spoofed IPs
        if requests.len() > 10000 {
            requests.retain(|_, (_, window_start)| {
                now.duration_since(*window_start) <= self.window_duration
            });
            // If still too large after cleanup, drop randomly or deny
            if requests.len() > 10000 {
                return false; // Deny service to protect memory
            }
        }

        let entry = requests.entry(ip.to_string()).or_insert((0, now));

        // Reset window if expired
        if now.duration_since(entry.1) > self.window_duration {
            entry.0 = 0;
            entry.1 = now;
        }

        // Check limit
        if entry.0 >= self.max_requests_per_window {
            return false; // Rate limited
        }

        entry.0 += 1;
        true
    }

    /// Periodic cleanup of old entries (call from background task)
    fn cleanup(&self) {
        if let Ok(mut requests) = self.requests.lock() {
            let now = Instant::now();
            requests.retain(|_, (_, window_start)| {
                now.duration_since(*window_start) <= self.window_duration * 2
            });
        }
    }
}

/// Start the metrics HTTP server
/// Returns a JoinHandle that can be used to stop the server
///
/// # Arguments
/// * `runtime` - TalosRuntime instance to monitor
/// * `port` - Port to listen on (typically 9090 for Prometheus)
///
/// # Security
/// Set METRICS_AUTH_TOKENS environment variable (comma-separated) to require authentication:
/// ```bash
/// export METRICS_AUTH_TOKENS=secret-token-1,secret-token-2
/// curl -H "Authorization: Bearer secret-token-1" http://localhost:9090/metrics
/// ```
/// Starts the metrics HTTP server.
/// Returns an error if the required `METRICS_AUTH_TOKENS` environment variable is not set.
pub fn start_metrics_server(
    runtime: Arc<TalosRuntime>,
    port: u16,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    // Enforce authentication configuration — the env var must be set AND non-empty.
    let tokens_raw = std::env::var("METRICS_AUTH_TOKENS").map_err(|_| {
        anyhow::anyhow!("METRICS_AUTH_TOKENS must be set for the metrics server to run")
    })?;
    if tokens_raw.trim().is_empty() {
        return Err(anyhow::anyhow!(
            "METRICS_AUTH_TOKENS must not be empty — configure at least one valid token"
        ));
    }

    Ok(tokio::spawn(async move {
        if let Err(e) = run_metrics_server(runtime, port).await {
            eprintln!("[METRICS_SERVER] Error: {}", e);
        }
    }))
}

/// Internal metrics server implementation
async fn run_metrics_server(
    runtime: Arc<TalosRuntime>,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::net::SocketAddr;
    use std::str::FromStr;

    println!("[METRICS_SERVER] Starting on 0.0.0.0:{}", port);

    // MCP-932 (2026-05-15): authentication is enforced at the SOLE
    // entry point `start_metrics_server` (above) — it reads
    // `METRICS_AUTH_TOKENS`, rejects missing AND empty values via
    // `trim().is_empty()`, and only spawns this function if the
    // token list is valid. Pre-fix this function ALSO re-checked
    // the env var with `.is_ok()` — accepts `Ok("")` semantics
    // that don't match the outer gate, and the entire `if
    // !auth_configured` branch was unreachable in practice
    // (no caller skips `start_metrics_server`). Worse, the
    // conditional "Authentication: ENABLED/DISABLED" log was
    // misleading: by precondition the answer is always ENABLED,
    // so the DISABLED branch was advertising a code path that
    // can't fire.
    //
    // Cleaned up: trust the outer gate, log unconditionally.
    // `validate_bearer_token` (called per request) re-parses the
    // env at request time and is the live enforcement — it
    // handles the runtime case where the env mutates (test
    // harnesses) AND the empty-element comma-misconfig case
    // (MCP-674).
    let addr = SocketAddr::from_str(&format!("0.0.0.0:{}", port))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;

    println!("[METRICS_SERVER] Listening on http://{}", addr);
    println!("[METRICS_SERVER] Endpoints:");
    println!("[METRICS_SERVER]   - GET /metrics (Prometheus format)");
    println!("[METRICS_SERVER]   - GET /health (JSON status)");
    println!("[METRICS_SERVER]   - GET /healthz (unauthenticated liveness)");
    println!("[METRICS_SERVER] Security:");
    println!("[METRICS_SERVER]   - Max concurrent connections: 100");
    println!("[METRICS_SERVER]   - Rate limit: 60 req/min per IP");
    println!("[METRICS_SERVER]   - Request timeout: 10s");
    println!("[METRICS_SERVER]   - Max request size: 4KB");
    println!("[METRICS_SERVER]   - Authentication: ENABLED (Bearer token, validated per request)");

    // SECURITY: Limit concurrent connections to prevent DoS
    const MAX_CONNECTIONS: usize = 100;
    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    // SECURITY: Rate limiting (60 requests/minute per IP)
    let rate_limiter = Arc::new(RateLimiter::new(60, std::time::Duration::from_secs(60)));

    // Spawn cleanup task
    let rate_limiter_clone = rate_limiter.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(120)).await;
            rate_limiter_clone.cleanup();
        }
    });

    loop {
        // SECURITY: Acquire permit before accepting connection
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                eprintln!("[METRICS_SERVER] CRITICAL: Semaphore closed - shutting down");
                break;
            }
        };

        let (socket, remote_addr) = listener.accept().await?;
        let runtime_clone = runtime.clone();
        let rate_limiter_clone = rate_limiter.clone();

        tokio::spawn(async move {
            // Permit automatically released when _permit is dropped
            let _permit = permit;

            // SECURITY: Overall connection timeout
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                handle_connection(socket, runtime_clone, rate_limiter_clone, remote_addr),
            )
            .await;

            match result {
                Ok(Ok(_)) => {} // Success
                Ok(Err(e)) => eprintln!(
                    "[METRICS_SERVER] Connection error from {}: {}",
                    remote_addr, e
                ),
                Err(_) => eprintln!("[METRICS_SERVER] Connection timeout from {}", remote_addr),
            }
        });
    }

    Ok(())
}

/// Validate bearer token authentication
fn validate_bearer_token(auth_header: Option<&str>) -> bool {
    // SECURITY: Get allowed tokens from environment.
    // MCP-674 (2026-05-13): filter empty strings out of the HashSet
    // before the contains() check. Pre-fix `METRICS_AUTH_TOKENS=","`
    // or `="real,,"` produced a set containing the empty string, so a
    // request with `Authorization: Bearer ` (literal "Bearer " with
    // empty token) silently authenticated — `allowed_tokens.contains("")`
    // returns true. `start_metrics_server`'s `trim().is_empty()` rejects
    // a fully-empty `METRICS_AUTH_TOKENS=""`, but a value containing
    // ONLY commas/whitespace-around-commas (a real helm misconfig
    // pattern where an operator pastes a `"$TOKEN1,$TOKEN2"` template
    // and both variables expand to empty) sneaks past that check and
    // hits this code path. Same empty-element class as the
    // ct_eq-against-empty bypass family (MCP-590/591/592/674) — empty
    // strings should never be a member of an authentication set.
    let allowed_tokens = std::env::var("METRICS_AUTH_TOKENS")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect::<HashSet<String>>()
        })
        .unwrap_or_default();

    // All configured values were whitespace-only — treat as misconfiguration and deny.
    // We never fall open: callers must supply at least one valid token.
    if allowed_tokens.is_empty() {
        return false;
    }

    if let Some(auth) = auth_header {
        if let Some(token) = auth
            .strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))
        {
            // MCP-674: also defensively refuse an empty (post-trim)
            // bearer regardless of set contents. Pairs with the
            // empty-filter above so a future regression on either
            // side can't reopen the bypass alone.
            let token = token.trim();
            if token.is_empty() {
                return false;
            }
            // Constant-time membership test. `HashSet::contains` hashes the
            // input and byte-compares against the matching bucket — timing-
            // variable, leaking partial-match information about the operator
            // token (`METRICS_AUTH_TOKENS` has no enforced entropy floor, so it
            // may be guessable). OR-accumulate `ct_eq` over the whole set with
            // NO early exit, so the comparison time depends only on the
            // (non-secret) set size — matching the `subtle::ConstantTimeEq`
            // discipline the controller already uses for its admin / Prometheus
            // scrape secrets. `ct_eq` returns `Choice(0)` on length mismatch and
            // runs constant-time over equal-length contents.
            use subtle::ConstantTimeEq;
            let mut matched = subtle::Choice::from(0u8);
            for allowed in allowed_tokens.iter() {
                matched |= allowed.as_bytes().ct_eq(token.as_bytes());
            }
            return bool::from(matched);
        }
    }

    false
}

/// Handle a single HTTP connection with security hardening
async fn handle_connection(
    socket: tokio::net::TcpStream,
    runtime: Arc<TalosRuntime>,
    rate_limiter: Arc<RateLimiter>,
    remote_addr: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::AsyncWriteExt;

    // SECURITY: Check rate limit
    if !rate_limiter.check_rate_limit(&remote_addr.ip().to_string()) {
        let response = "HTTP/1.1 429 Too Many Requests\r\n\
                       Retry-After: 60\r\n\
                       Content-Length: 18\r\n\r\n\
                       Too Many Requests\n";
        let mut socket = socket;
        socket.write_all(response.as_bytes()).await?;
        socket.flush().await?;
        return Ok(());
    }

    // SECURITY: Read with timeout and size limit
    let mut buffer = vec![0u8; 4096]; // Reduced from 8192 for security

    let read_result =
        tokio::time::timeout(std::time::Duration::from_secs(5), socket.readable()).await;

    if read_result.is_err() {
        return Err("Read timeout".into());
    }

    socket.readable().await?;
    let n = socket.try_read(&mut buffer)?;

    // SECURITY: Validate request size
    if n == 0 || n > 4096 {
        return Err("Invalid request size".into());
    }

    let request = String::from_utf8_lossy(&buffer[..n]);
    let lines: Vec<&str> = request.lines().collect();

    if lines.is_empty() {
        return Ok(());
    }

    let request_line = lines[0];
    let parts: Vec<&str> = request_line.split_whitespace().collect();

    if parts.len() < 2 {
        return Ok(());
    }

    let (method, path) = (parts[0], parts[1]);

    // SECURITY: Extract and validate authorization header
    let auth_header = lines
        .iter()
        .find(|line| line.to_lowercase().starts_with("authorization:"))
        .and_then(|line| line.split(':').nth(1))
        .map(|s| s.trim());

    // SECURITY: Allowlist of unauthenticated paths. Everything else
    // (including /metrics, /health, and any future endpoint) requires a
    // bearer token. MCP-807 (2026-05-14): pre-fix this was a deny-list
    // gate (`if path == "/metrics" || path == "/health" { auth } else
    // { allow }`) that exempted ALL non-listed paths from auth — which
    // meant the orphaned `/ready` endpoint (dead code after MCP-797's
    // switch to `/healthz` for both kubelet probes) returned worker
    // runtime counters (uptime_seconds, active_executions,
    // total_executions) to any in-namespace pod without credentials.
    // Worker networkpolicy permits `podSelector: {}` on the metrics
    // port, so every Talos-namespace workload (and any future
    // workloads colocated by an operator) could poll `/ready` for
    // job-arrival timing inference. Switching to an allowlist closes
    // that disclosure AND makes "added a new endpoint without auth"
    // fail closed instead of fail open.
    let is_public_path = matches!(path, "/" | "/healthz");
    let is_authenticated = if is_public_path {
        true
    } else {
        validate_bearer_token(auth_header)
    };

    if !is_authenticated {
        let response = "HTTP/1.1 401 Unauthorized\r\n\
                       WWW-Authenticate: Bearer realm=\"metrics\"\r\n\
                       Content-Length: 13\r\n\r\n\
                       Unauthorized\n";
        let mut socket = socket;
        socket.write_all(response.as_bytes()).await?;
        socket.flush().await?;
        return Ok(());
    }

    let response = match (method, path) {
        // MCP-797 (2026-05-14): dedicated unauthenticated liveness probe.
        // Pre-fix the worker had only three paths exposed: `/metrics` and
        // `/health` (both require bearer-token auth when
        // METRICS_AUTH_TOKENS is set), and `/` (static HTML help page
        // that also disclosed whether METRICS_AUTH_TOKENS was set).
        // Kubelet probes used `/` because it was the only
        // unauthenticated endpoint — burning ~400 bytes of HTML on
        // every probe and revealing auth-state to anyone who could
        // reach the metrics port. `/healthz` is the canonical k8s
        // unauthenticated liveness convention; matches the controller's
        // `/live` shape (static "OK") and the chart helpers' assumption
        // referenced in worker/deployment.yaml. Auth gate at line ~358
        // already lets non-`/metrics`/`/health` paths through without
        // bearer-token validation, so no additional bypass is needed.
        ("GET", "/healthz") => {
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nOK\n"
                .to_string()
        }
        ("GET", "/metrics") => {
            let metrics = crate::metrics::get_prometheus_metrics();
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
                metrics.len(),
                metrics
            )
        }
        ("GET", "/health") => {
            let health = runtime.get_health_status();
            let json = serde_json::to_string(&health)?;
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                json.len(),
                json
            )
        }
        ("GET", "/") => {
            let auth_status = if std::env::var("METRICS_AUTH_TOKENS").is_ok() {
                "ENABLED (secure)"
            } else {
                "DISABLED (insecure - set METRICS_AUTH_TOKENS)"
            };

            let help = format!(
                r#"<!DOCTYPE html>
<html>
<head><title>Talos Worker Metrics</title></head>
<body>
<h1>Talos Worker Metrics Server</h1>
<h2>Endpoints</h2>
<ul>
<li><a href="/metrics">/metrics</a> - Prometheus metrics</li>
<li><a href="/health">/health</a> - Health status (JSON)</li>
<li><a href="/healthz">/healthz</a> - Unauthenticated liveness (200 OK)</li>
</ul>
<h2>Security</h2>
<ul>
<li>Authentication: {}</li>
<li>Rate Limit: 60 req/min per IP</li>
<li>Max Connections: 100</li>
<li>Request Timeout: 10s</li>
</ul>
</body>
</html>"#,
                auth_status
            );
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                help.len(),
                help
            )
        }
        // MCP-807 (2026-05-14): removed orphaned `/ready` arm. The
        // worker deployment uses `/healthz` for BOTH liveness AND
        // readiness probes (see deploy/helm/talos/templates/worker/
        // deployment.yaml). `/ready` was never referenced by any
        // probe, and pre-fix it was exempt from the auth gate (the
        // deny-list let any in-namespace pod read worker runtime
        // counters). Cleaner to delete than to add auth to dead code.
        // The auth gate is now an allowlist so any future endpoint
        // added here will require a token by default.
        _ => "HTTP/1.1 404 NOT FOUND\r\nContent-Length: 0\r\n\r\n".to_string(),
    };

    let mut socket = socket;
    socket.write_all(response.as_bytes()).await?;
    socket.flush().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn test_metrics_server_starts() {
        let runtime =
            Arc::new(crate::TalosRuntime::new().expect("Failed to serialize health status"));
        let handle =
            start_metrics_server(runtime, 19090).expect("Metrics server failed to start in test");

        // Give it a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Try to connect
        let result = tokio::net::TcpStream::connect("127.0.0.1:19090").await;
        assert!(result.is_ok(), "Metrics server should be listening");

        handle.abort();
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(5, std::time::Duration::from_secs(60));

        // Should allow first 5 requests
        for _ in 0..5 {
            assert!(limiter.check_rate_limit("192.168.1.1"));
        }

        // Should block 6th request
        assert!(!limiter.check_rate_limit("192.168.1.1"));

        // Different IP should be allowed
        assert!(limiter.check_rate_limit("192.168.1.2"));
    }

    // MCP-674: regression tests for the empty-token bypass.
    // `std::env::set_var` is process-wide so these tests serialise
    // against each other via a Mutex — same pattern as
    // talos-registry::env_var_lock.
    fn env_var_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn empty_string_token_does_not_authenticate_under_comma_misconfig() {
        let _g = env_var_lock();
        // Pre-fix `METRICS_AUTH_TOKENS=","` produced a HashSet
        // containing the empty string, so `Bearer ` (empty token)
        // authenticated. Real helm misconfig: operator pastes a
        // `"$T1,$T2"` template and both vars expand to "".
        std::env::set_var("METRICS_AUTH_TOKENS", ",");
        let prev_result = validate_bearer_token(Some("Bearer "));
        std::env::remove_var("METRICS_AUTH_TOKENS");
        assert!(
            !prev_result,
            "comma-only METRICS_AUTH_TOKENS must not accept empty bearer"
        );
    }

    #[test]
    fn empty_element_in_token_list_does_not_authenticate() {
        let _g = env_var_lock();
        // `"real,,"` — set was {"real", ""}; empty bearer matched.
        std::env::set_var("METRICS_AUTH_TOKENS", "real,,");
        let empty_bearer = validate_bearer_token(Some("Bearer "));
        let real_bearer = validate_bearer_token(Some("Bearer real"));
        std::env::remove_var("METRICS_AUTH_TOKENS");
        assert!(!empty_bearer, "empty element must be filtered out");
        assert!(real_bearer, "legitimate token must still authenticate");
    }

    #[test]
    fn whitespace_only_bearer_does_not_authenticate() {
        let _g = env_var_lock();
        std::env::set_var("METRICS_AUTH_TOKENS", "real");
        // Defense-in-depth: even if the set somehow contained a
        // non-empty whitespace string, `Bearer    ` (whitespace token)
        // is rejected at the post-trim is_empty check.
        let result = validate_bearer_token(Some("Bearer    "));
        std::env::remove_var("METRICS_AUTH_TOKENS");
        assert!(!result, "whitespace-only bearer must not authenticate");
    }

    #[test]
    fn wrong_non_empty_token_does_not_authenticate() {
        let _g = env_var_lock();
        // Pins the constant-time membership loop directly: a NON-EMPTY token
        // that isn't in the set bypasses the empty/whitespace short-circuits
        // and must be rejected by the `ct_eq` accumulation (a loop bug that
        // ignored content would slip past the existing empty-token tests).
        std::env::set_var("METRICS_AUTH_TOKENS", "correct-token-abc123");
        let wrong = validate_bearer_token(Some("Bearer wrong-token-xyz789"));
        let right = validate_bearer_token(Some("Bearer correct-token-abc123"));
        // A token sharing a prefix with the real one must also be rejected.
        let prefix = validate_bearer_token(Some("Bearer correct-token-abc"));
        std::env::remove_var("METRICS_AUTH_TOKENS");
        assert!(!wrong, "a non-matching token must not authenticate");
        assert!(right, "the configured token must authenticate");
        assert!(!prefix, "a prefix of the real token must not authenticate");
    }
}
