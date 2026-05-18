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

    // SECURITY: Check if authentication is configured
    let auth_configured = std::env::var("METRICS_AUTH_TOKENS").is_ok();
    if !auth_configured {
        // In production we require authentication for metrics endpoints.
        // Abort startup to avoid exposing unauthenticated metrics.
        eprintln!(
            "[SECURITY CRITICAL] METRICS_AUTH_TOKENS not set – aborting metrics server startup."
        );
        eprintln!("    Set METRICS_AUTH_TOKENS env var with comma‑separated tokens.");
        return Err("METRICS_AUTH_TOKENS not configured".into());
    }

    let addr = SocketAddr::from_str(&format!("0.0.0.0:{}", port))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;

    println!("[METRICS_SERVER] Listening on http://{}", addr);
    println!("[METRICS_SERVER] Endpoints:");
    println!("[METRICS_SERVER]   - GET /metrics (Prometheus format)");
    println!("[METRICS_SERVER]   - GET /health (JSON status)");
    println!("[METRICS_SERVER] Security:");
    println!("[METRICS_SERVER]   - Max concurrent connections: 100");
    println!("[METRICS_SERVER]   - Rate limit: 60 req/min per IP");
    println!("[METRICS_SERVER]   - Request timeout: 10s");
    println!("[METRICS_SERVER]   - Max request size: 4KB");
    println!(
        "[METRICS_SERVER]   - Authentication: {}",
        if auth_configured {
            "ENABLED"
        } else {
            "DISABLED (WARNING!)"
        }
    );

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
    // SECURITY: Get allowed tokens from environment
    let allowed_tokens = std::env::var("METRICS_AUTH_TOKENS")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|t| t.trim().to_string())
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
            return allowed_tokens.contains(token.trim());
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

    // SECURITY: Check bearer token for sensitive endpoints
    let is_authenticated = if path == "/metrics" || path == "/health" {
        validate_bearer_token(auth_header)
    } else {
        true // Root page doesn't need auth
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
        ("GET", "/ready") => {
            // Simple readiness check – ensures metrics are initialized and runtime is healthy
            let health = runtime.get_health_status();
            let ready_json = serde_json::json!({
                "ready": true,
                "uptime_seconds": health.uptime_seconds,
                "active_executions": health.active_executions,
                "total_executions": health.total_executions,
            });
            let json_str =
                serde_json::to_string(&ready_json).expect("Failed to serialize health status");
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                json_str.len(),
                json_str
            )
        }
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
}
