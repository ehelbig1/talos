//! Circuit breaker pattern for HTTP outbound requests.
//!
//! Prevents cascading failures when external APIs are down by temporarily
//! rejecting requests to failing hosts. Tracks failure rates per-host and
//! automatically recovers when the upstream service is healthy again.

use dashmap::DashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Global circuit breaker instance.
/// Initialized on first access with default configuration.
static GLOBAL_CIRCUIT_BREAKER: OnceLock<HttpCircuitBreaker> = OnceLock::new();

/// Get the global circuit breaker instance.
/// Initializes on first call with default configuration.
pub fn get_global_circuit_breaker() -> &'static HttpCircuitBreaker {
    GLOBAL_CIRCUIT_BREAKER.get_or_init(|| {
        let config = CircuitBreakerConfig::from_env();
        HttpCircuitBreaker::new(config)
    })
}

/// MCP-580: spawn a periodic-cleanup task for the global breaker. Call
/// once at worker startup. The breaker's per-host `records` DashMap
/// grows monotonically with distinct hosts seen — `cleanup` was
/// defined but had zero callers, so a worker that's fetched many
/// hosts (or a misbehaving module that fetches from a long tail of
/// short-lived domains) would accumulate `CircuitRecord` entries
/// forever. Open / HalfOpen circuits are preserved by `cleanup` (we
/// want them remembered until they recover); only stale Closed
/// circuits with no recent activity get evicted. Default sweep
/// every 5 minutes with 30-minute max-age, configurable via
/// `CIRCUIT_BREAKER_CLEANUP_SECS` / `CIRCUIT_BREAKER_MAX_AGE_SECS`.
/// Idempotent — calling twice spawns two tasks (harmless but wasteful);
/// design assumes one call from main.
pub fn spawn_periodic_cleanup() {
    let interval_secs: u64 = std::env::var("CIRCUIT_BREAKER_CLEANUP_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n >= 30)
        .unwrap_or(300);
    let max_age_secs: u64 = std::env::var("CIRCUIT_BREAKER_MAX_AGE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n >= 60)
        .unwrap_or(1800);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        // The first tick fires immediately — skip it so we don't sweep
        // a freshly-empty map.
        interval.tick().await;
        loop {
            interval.tick().await;
            get_global_circuit_breaker().cleanup(Duration::from_secs(max_age_secs));
        }
    });
    tracing::info!(
        target: "talos_worker",
        event_kind = "circuit_breaker_cleanup_spawned",
        interval_secs,
        max_age_secs,
        "Circuit-breaker periodic cleanup task started"
    );
}

/// Configuration for the circuit breaker.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening the circuit.
    pub failure_threshold: u32,
    /// Duration the circuit stays open before allowing test requests.
    pub open_duration: Duration,
    /// Duration to track failures (failures older than this are ignored).
    pub failure_window: Duration,
    /// Success rate required in half-open state to close the circuit (0.0-1.0).
    pub success_rate_threshold: f64,
    /// Number of test requests to allow in half-open state.
    pub test_requests: u32,
}

impl CircuitBreakerConfig {
    /// Create configuration from environment variables.
    ///
    /// MCP-689 (2026-05-13): three numeric envs routed through
    /// `positive_env_or_default`. Pre-fix `=0` for any of them was
    /// silently destructive:
    /// - `CIRCUIT_BREAKER_FAILURE_THRESHOLD=0` — circuit opens after
    ///   zero failures = permanently open. Every outbound HTTP call
    ///   returns CircuitOpen.
    /// - `CIRCUIT_BREAKER_OPEN_DURATION_SECS=0` — circuit re-closes
    ///   immediately after opening; defeats the breaker entirely.
    /// - `CIRCUIT_BREAKER_FAILURE_WINDOW_SECS=0` — every failure
    ///   counts as already expired; failure count stays at zero;
    ///   circuit never opens.
    ///
    /// MCP-711 (2026-05-13): MCP-689 missed two more sites:
    /// - `CIRCUIT_BREAKER_TEST_REQUESTS=0` — `test_requests_remaining`
    ///   starts at 0 on HalfOpen entry, so `allow_request` returns
    ///   false for every test (line 231-234). With no test allowed,
    ///   no success/failure can be recorded, so the circuit can never
    ///   transition back to Closed. Effectively pins every previously-
    ///   tripped host into permanent rejection.
    /// - `CIRCUIT_BREAKER_SUCCESS_RATE` — out-of-range values (≤0,
    ///   ≥1, NaN, Inf) silently produce nonsense:
    ///   * `0.0` → circuit closes on the first HalfOpen test
    ///     regardless of outcome → success-rate check is bypassed,
    ///     defeats half of the breaker's purpose.
    ///   * `>1.0` or `NaN` → `success_rate >= threshold` is always
    ///     false → circuit re-opens after every HalfOpen cycle and
    ///     never closes, similar to the test_requests=0 trap.
    ///   * `<0.0` → `success_rate >= threshold` always true → closes
    ///     on first success regardless of test_failures count.
    ///   Same `=0`/out-of-range footgun class as MCP-665/MCP-689.
    ///   Clamp to `[0.0, 1.0]` and reject NaN/Inf — the only
    ///   meaningful operator values.
    pub fn from_env() -> Self {
        // MCP-711: clamp success-rate to [0.0, 1.0] and reject NaN/Inf.
        let success_rate_threshold = std::env::var("CIRCUIT_BREAKER_SUCCESS_RATE")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|n| n.is_finite() && (0.0..=1.0).contains(n))
            .unwrap_or_else(|| {
                // If env was set to a parseable but out-of-range value
                // (e.g. `1.5`, `NaN`, `-1`), the filter drops it and we
                // fall through to the default. Emit a WARN at config
                // time so operators see the clamp without waiting for
                // a circuit-breaker event to surface the issue.
                if let Ok(raw) = std::env::var("CIRCUIT_BREAKER_SUCCESS_RATE") {
                    if !raw.is_empty() {
                        tracing::warn!(
                            target: "talos_worker",
                            event_kind = "circuit_breaker_success_rate_substituted",
                            configured = %raw,
                            default = 0.8,
                            "CIRCUIT_BREAKER_SUCCESS_RATE is not a finite value in [0.0, 1.0]; \
                             substituting default 0.8"
                        );
                    }
                }
                0.8
            });
        Self {
            failure_threshold: talos_config::positive_env_or_default(
                "CIRCUIT_BREAKER_FAILURE_THRESHOLD",
                5u32,
            ),
            open_duration: Duration::from_secs(talos_config::positive_env_or_default(
                "CIRCUIT_BREAKER_OPEN_DURATION_SECS",
                30u64,
            )),
            failure_window: Duration::from_secs(talos_config::positive_env_or_default(
                "CIRCUIT_BREAKER_FAILURE_WINDOW_SECS",
                60u64,
            )),
            success_rate_threshold,
            // MCP-711: same `positive_env_or_default` treatment as the
            // three above. `=0` would stick every previously-tripped
            // host in permanent rejection.
            test_requests: talos_config::positive_env_or_default(
                "CIRCUIT_BREAKER_TEST_REQUESTS",
                3u32,
            ),
        }
    }
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_duration: Duration::from_secs(30),
            failure_window: Duration::from_secs(60),
            success_rate_threshold: 0.8,
            test_requests: 3,
        }
    }
}

/// State of a circuit breaker for a specific host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitState {
    /// Circuit is closed, requests are allowed.
    Closed,
    /// Circuit is open, requests are rejected.
    Open,
    /// Circuit is half-open, allowing test requests.
    HalfOpen,
}

/// Record of circuit breaker state for a specific host.
struct CircuitRecord {
    state: CircuitState,
    consecutive_failures: u32,
    last_failure: Instant,
    last_state_change: Instant,
    test_requests_remaining: u32,
    test_successes: u32,
    test_failures: u32,
}

impl CircuitRecord {
    fn new() -> Self {
        Self {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            last_failure: Instant::now(),
            last_state_change: Instant::now(),
            test_requests_remaining: 0,
            test_successes: 0,
            test_failures: 0,
        }
    }
}

/// Circuit breaker for HTTP outbound requests.
///
/// Tracks failures per-host and prevents requests to failing hosts.
/// Uses a three-state model: Closed -> Open -> HalfOpen -> Closed.
pub struct HttpCircuitBreaker {
    records: Arc<DashMap<String, CircuitRecord>>,
    config: CircuitBreakerConfig,
}

impl HttpCircuitBreaker {
    /// Create a new circuit breaker with the given configuration.
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            records: Arc::new(DashMap::new()),
            config,
        }
    }

    /// Create a new circuit breaker with default configuration.
    pub fn new_default() -> Self {
        Self::new(CircuitBreakerConfig::default())
    }

    /// Check if a request to the given host should be allowed.
    ///
    /// Returns `true` if the request should proceed, `false` if it should be rejected.
    pub fn allow_request(&self, host: &str) -> bool {
        let now = Instant::now();
        let mut entry = self
            .records
            .entry(host.to_string())
            .or_insert_with(CircuitRecord::new);
        let record = entry.value_mut();

        // Check if we should transition from Open to HalfOpen
        if record.state == CircuitState::Open {
            if now.duration_since(record.last_state_change) >= self.config.open_duration {
                record.state = CircuitState::HalfOpen;
                record.test_requests_remaining = self.config.test_requests;
                record.test_successes = 0;
                record.test_failures = 0;
                record.last_state_change = now;
                tracing::info!(host = %host, "Circuit breaker entering half-open state");
            } else {
                // Circuit is still open, reject the request
                tracing::warn!(
                    host = %host,
                    remaining_secs = (record.last_state_change + self.config.open_duration)
                        .saturating_duration_since(now)
                        .as_secs(),
                    "Circuit breaker rejecting request"
                );
                return false;
            }
        }

        // In half-open state, only allow test requests
        if record.state == CircuitState::HalfOpen {
            if record.test_requests_remaining == 0 {
                // No more test requests allowed, reject
                return false;
            }
            record.test_requests_remaining -= 1;
        }

        true
    }

    /// Record a successful request to the given host.
    pub fn record_success(&self, host: &str) {
        let now = Instant::now();
        let mut entry = self
            .records
            .entry(host.to_string())
            .or_insert_with(CircuitRecord::new);
        let record = entry.value_mut();

        match record.state {
            CircuitState::Closed => {
                // Reset failure counter on success
                if record.consecutive_failures > 0 {
                    record.consecutive_failures = 0;
                    tracing::debug!(host = %host, "Circuit breaker: reset failure counter");
                }
            }
            CircuitState::HalfOpen => {
                record.test_successes += 1;
                // Check if we should close the circuit
                let total_tests = record.test_successes + record.test_failures;
                if total_tests >= self.config.test_requests {
                    let success_rate = record.test_successes as f64 / total_tests as f64;
                    if success_rate >= self.config.success_rate_threshold {
                        record.state = CircuitState::Closed;
                        record.consecutive_failures = 0;
                        record.last_state_change = now;
                        tracing::info!(
                            host = %host,
                            success_rate = %success_rate,
                            "Circuit breaker closed"
                        );
                    } else {
                        // Not enough successes, go back to open
                        record.state = CircuitState::Open;
                        record.last_state_change = now;
                        tracing::warn!(
                            host = %host,
                            success_rate = %success_rate,
                            "Circuit breaker re-opened due to low success rate"
                        );
                    }
                }
            }
            CircuitState::Open => {
                // Shouldn't happen, but just in case
            }
        }
    }

    /// Record a failed request to the given host.
    pub fn record_failure(&self, host: &str) {
        let now = Instant::now();
        let mut entry = self
            .records
            .entry(host.to_string())
            .or_insert_with(CircuitRecord::new);
        let record = entry.value_mut();

        // Reset if outside the failure window
        if now.duration_since(record.last_failure) >= self.config.failure_window {
            record.consecutive_failures = 0;
        }

        record.last_failure = now;

        match record.state {
            CircuitState::Closed => {
                record.consecutive_failures += 1;
                if record.consecutive_failures >= self.config.failure_threshold {
                    record.state = CircuitState::Open;
                    record.last_state_change = now;
                    tracing::warn!(
                        host = %host,
                        consecutive_failures = record.consecutive_failures,
                        "Circuit breaker opened"
                    );
                }
            }
            CircuitState::HalfOpen => {
                record.test_failures += 1;
                // Check if we should re-open
                let total_tests = record.test_successes + record.test_failures;
                if total_tests >= self.config.test_requests {
                    let success_rate = record.test_successes as f64 / total_tests as f64;
                    if success_rate < self.config.success_rate_threshold {
                        record.state = CircuitState::Open;
                        record.last_state_change = now;
                        tracing::warn!(
                            host = %host,
                            success_rate = %success_rate,
                            "Circuit breaker re-opened"
                        );
                    }
                }
            }
            CircuitState::Open => {
                // Already open, nothing to do
            }
        }
    }

    /// Get the current state of a circuit breaker for a host (for debugging/metrics).
    pub fn get_state(&self, host: &str) -> Option<String> {
        self.records.get(host).map(|r| match r.state {
            CircuitState::Closed => "closed".to_string(),
            CircuitState::Open => "open".to_string(),
            CircuitState::HalfOpen => "half_open".to_string(),
        })
    }

    /// Clean up old entries to prevent memory growth.
    /// Call periodically (e.g., every 5 minutes).
    pub fn cleanup(&self, max_age: Duration) {
        let now = Instant::now();
        self.records.retain(|host, record| {
            let retain = match record.state {
                CircuitState::Closed => {
                    // Keep closed circuits if they've had activity recently
                    now.duration_since(record.last_failure) < max_age
                        || now.duration_since(record.last_state_change) < max_age
                }
                CircuitState::Open | CircuitState::HalfOpen => {
                    // Always keep open/half-open circuits
                    true
                }
            };
            if !retain {
                tracing::debug!(host = %host, "Removing stale circuit breaker record");
            }
            retain
        });
    }
}

impl Default for HttpCircuitBreaker {
    fn default() -> Self {
        Self::new_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_closed_to_open() {
        let cb = HttpCircuitBreaker::default();
        let host = "example.com";

        // Initially closed, requests allowed
        assert!(cb.allow_request(host));

        // Record 5 failures to trip the circuit
        for _ in 0..5 {
            cb.record_failure(host);
        }

        // Circuit should now be open, requests rejected
        assert!(!cb.allow_request(host));
    }

    #[test]
    fn test_circuit_breaker_open_to_half_open() {
        let config = CircuitBreakerConfig {
            open_duration: Duration::from_millis(10),
            ..Default::default()
        };
        let cb = HttpCircuitBreaker::new(config);
        let host = "example.com";

        // Trip the circuit
        for _ in 0..5 {
            cb.record_failure(host);
        }
        assert!(!cb.allow_request(host));

        // Wait for open duration
        std::thread::sleep(Duration::from_millis(20));

        // Should now be half-open, allowing test requests
        assert!(cb.allow_request(host));
        assert_eq!(cb.get_state(host), Some("half_open".to_string()));
    }

    #[test]
    fn test_circuit_breaker_half_open_to_closed() {
        let config = CircuitBreakerConfig {
            open_duration: Duration::from_millis(0),
            test_requests: 3,
            success_rate_threshold: 0.7,
            ..Default::default()
        };
        let cb = HttpCircuitBreaker::new(config);
        let host = "example.com";

        // Trip the circuit
        for _ in 0..5 {
            cb.record_failure(host);
        }

        // Should be half-open immediately (open_duration = 0)
        // Allow and record 3 successful test requests
        for _ in 0..3 {
            assert!(cb.allow_request(host));
            cb.record_success(host);
        }

        // Circuit should now be closed
        assert_eq!(cb.get_state(host), Some("closed".to_string()));
    }

    /// MCP-711: CIRCUIT_BREAKER_TEST_REQUESTS=0 would pin every tripped
    /// host into permanent rejection because `test_requests_remaining`
    /// starts at 0 on HalfOpen entry, so `allow_request` returns false
    /// for every test → no success can be recorded → circuit never
    /// transitions back to Closed. Tripwire the fix.
    ///
    /// Uses `from_env` directly so the test exercises the same parse
    /// path production hits at boot. Env mutation is serialized via the
    /// test mutex (same pattern as talos-compilation::container tests).
    #[test]
    fn from_env_clamps_test_requests_zero_to_default() {
        let _g = env_lock_for_test();
        std::env::set_var("CIRCUIT_BREAKER_TEST_REQUESTS", "0");
        let cfg = CircuitBreakerConfig::from_env();
        std::env::remove_var("CIRCUIT_BREAKER_TEST_REQUESTS");
        assert_eq!(
            cfg.test_requests, 3,
            "test_requests=0 must be substituted with default 3 (positive_env_or_default contract)"
        );
    }

    /// MCP-711: NaN / out-of-range success-rate values silently produce
    /// nonsense before the fix. Confirm the clamp routes to the default.
    #[test]
    fn from_env_clamps_success_rate_out_of_range_to_default() {
        let _g = env_lock_for_test();
        for raw in ["1.5", "-0.1", "NaN", "Inf", "-Inf"] {
            std::env::set_var("CIRCUIT_BREAKER_SUCCESS_RATE", raw);
            let cfg = CircuitBreakerConfig::from_env();
            assert!(
                (cfg.success_rate_threshold - 0.8).abs() < f64::EPSILON,
                "success_rate={raw} must fall back to default 0.8, got {}",
                cfg.success_rate_threshold
            );
        }
        std::env::remove_var("CIRCUIT_BREAKER_SUCCESS_RATE");
    }

    /// MCP-711: an in-range success_rate must NOT be clamped. Locks in
    /// the boundary behavior so a future tightening of the predicate
    /// doesn't accidentally swallow legitimate operator config.
    #[test]
    fn from_env_honors_in_range_success_rate() {
        let _g = env_lock_for_test();
        for raw in ["0.0", "0.5", "1.0"] {
            std::env::set_var("CIRCUIT_BREAKER_SUCCESS_RATE", raw);
            let cfg = CircuitBreakerConfig::from_env();
            let expected: f64 = raw.parse().unwrap();
            assert!(
                (cfg.success_rate_threshold - expected).abs() < f64::EPSILON,
                "success_rate={raw} must be honored verbatim, got {}",
                cfg.success_rate_threshold
            );
        }
        std::env::remove_var("CIRCUIT_BREAKER_SUCCESS_RATE");
    }

    /// MCP-711: serialize env-var-touching tests inside this module so
    /// parallel test execution doesn't race `CIRCUIT_BREAKER_*` reads.
    /// Same pattern as `talos-compilation::container::env_lock` — module-
    /// local Mutex with poisoned-recovery.
    fn env_lock_for_test() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
