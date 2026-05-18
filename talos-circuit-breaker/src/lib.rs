//! Circuit breaker pattern for external service resilience.
//!
//! Provides automatic failure detection and recovery for:
//! - Redis connections
//! - NATS connections
//! - Database connections
//! - External APIs

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Circuit breaker error type for graceful failure handling
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitBreakerError {
    CircuitOpen,
    ServiceUnavailable(String),
}

impl fmt::Display for CircuitBreakerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitBreakerError::CircuitOpen => {
                write!(
                    f,
                    "Circuit breaker is open - service temporarily unavailable"
                )
            }
            CircuitBreakerError::ServiceUnavailable(service) => {
                write!(f, "Service '{}' is unavailable", service)
            }
        }
    }
}

impl std::error::Error for CircuitBreakerError {}

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CircuitState {
    #[default]
    /// Normal operation - requests pass through
    Closed,
    /// Failure threshold reached - requests fail fast
    Open,
    /// Testing if service recovered - limited requests allowed
    HalfOpen,
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening circuit
    pub failure_threshold: u32,
    /// Duration to wait before attempting recovery
    pub reset_timeout: Duration,
    /// Success threshold to close circuit in half-open state
    pub success_threshold: u32,
    /// Name for logging/metrics
    pub name: String,
}

impl CircuitBreakerConfig {
    /// Redis circuit breaker config
    pub fn redis() -> Self {
        Self {
            failure_threshold: 5,
            reset_timeout: Duration::from_secs(30),
            success_threshold: 2,
            name: "redis".to_string(),
        }
    }

    /// NATS circuit breaker config
    pub fn nats() -> Self {
        Self {
            failure_threshold: 3,
            reset_timeout: Duration::from_secs(30),
            success_threshold: 2,
            name: "nats".to_string(),
        }
    }

    /// Database circuit breaker config
    pub fn database() -> Self {
        Self {
            failure_threshold: 10,
            reset_timeout: Duration::from_secs(60),
            success_threshold: 3,
            name: "database".to_string(),
        }
    }
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            reset_timeout: Duration::from_secs(30),
            success_threshold: 2,
            name: "default".to_string(),
        }
    }
}

/// Circuit breaker for a single service
#[derive(Debug)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Arc<RwLock<CircuitState>>,
    failure_count: Arc<RwLock<u32>>,
    success_count: Arc<RwLock<u32>>,
    last_failure_time: Arc<RwLock<Option<Instant>>>,
}

impl Clone for CircuitBreaker {
    /// MCP-446: clone MUST share the `Arc<RwLock<_>>` handles so all
    /// callers of `CircuitBreakerRegistry::get(name)` observe and
    /// mutate the same breaker state. Pre-fix `clone` called
    /// `Self::new(config.clone())`, which created brand-new
    /// state/counter/timestamp Arcs — every consumer got a fresh
    /// state-less breaker and the failure threshold was never reached
    /// across the registry. That defeated the entire pattern: a Redis
    /// outage producing 100 failures across 100 callers left every
    /// per-caller breaker at failure_count=1.
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            state: self.state.clone(),
            failure_count: self.failure_count.clone(),
            success_count: self.success_count.clone(),
            last_failure_time: self.last_failure_time.clone(),
        }
    }
}

impl CircuitBreaker {
    /// Create new circuit breaker
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CircuitState::Closed)),
            failure_count: Arc::new(RwLock::new(0)),
            success_count: Arc::new(RwLock::new(0)),
            last_failure_time: Arc::new(RwLock::new(None)),
        }
    }

    /// Check if request should be allowed
    pub async fn allow(&self) -> bool {
        let mut state = self.state.write().await;

        match *state {
            CircuitState::Closed => {
                // Normal operation - allow request
                true
            }
            CircuitState::Open => {
                // Check if reset timeout has passed
                let should_attempt = {
                    let last = self.last_failure_time.read().await;
                    if let Some(last_time) = *last {
                        last_time.elapsed() >= self.config.reset_timeout
                    } else {
                        true
                    }
                };

                if should_attempt {
                    tracing::info!(
                        service = %self.config.name,
                        "Circuit breaker entering half-open state"
                    );
                    *state = CircuitState::HalfOpen;
                    // Reset counters
                    *self.success_count.write().await = 0;
                    *self.failure_count.write().await = 0;
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => {
                // Limited requests allowed for testing
                true
            }
        }
    }

    /// Record a success
    ///
    /// MCP-485: acquire `state(W)` FIRST and hold it through any
    /// other lock acquisitions. `allow()` acquires `state(W)` then
    /// nested `success_count(W) / failure_count(W) / last_failure_time(R)`;
    /// pre-fix this method took `success_count(W)` first, THEN
    /// `state(W)` — the opposite order. Under contention (one thread
    /// in allow's Open branch, another concurrently calling
    /// record_success while state is HalfOpen) the two threads
    /// formed a circular wait on `state(W) ↔ success_count(W)` and
    /// deadlocked. Tokio's RwLock does not detect cycles; the
    /// threads hang forever. By making `state(W)` the outermost lock
    /// in BOTH paths, the order is consistent and no cycle is
    /// possible.
    pub async fn record_success(&self) {
        let mut state = self.state.write().await;

        match *state {
            CircuitState::HalfOpen => {
                let mut success = self.success_count.write().await;
                *success += 1;

                if *success >= self.config.success_threshold {
                    tracing::info!(
                        service = %self.config.name,
                        "Circuit breaker closed - service recovered"
                    );
                    *state = CircuitState::Closed;
                    *self.failure_count.write().await = 0;
                }
            }
            CircuitState::Closed => {
                // Reset failure count on success
                *self.failure_count.write().await = 0;
            }
            _ => {}
        }
    }

    /// Record a failure
    ///
    /// MCP-485: same lock-order fix as `record_success`. Pre-fix took
    /// `failure_count(W)` before `state(W)`; `allow()` takes them in
    /// the opposite order, so the two could deadlock under
    /// contention. Hold `state(W)` for the whole method body so
    /// `state → others` ordering is consistent across every method
    /// that touches multiple locks.
    pub async fn record_failure(&self) {
        let mut state = self.state.write().await;

        match *state {
            CircuitState::Closed => {
                let mut count = self.failure_count.write().await;
                *count += 1;

                if *count >= self.config.failure_threshold {
                    tracing::warn!(
                        service = %self.config.name,
                        failures = *count,
                        "Circuit breaker opened - too many failures"
                    );
                    *state = CircuitState::Open;
                    *self.last_failure_time.write().await = Some(Instant::now());
                }
            }
            CircuitState::HalfOpen => {
                // Back to open on any failure in half-open
                tracing::warn!(
                    service = %self.config.name,
                    "Circuit breaker reopened - recovery failed"
                );
                *state = CircuitState::Open;
                *self.last_failure_time.write().await = Some(Instant::now());
            }
            _ => {}
        }
    }

    /// Get current state
    pub async fn state(&self) -> CircuitState {
        *self.state.read().await
    }

    /// Get metrics
    pub async fn metrics(&self) -> CircuitBreakerMetrics {
        CircuitBreakerMetrics {
            service: self.config.name.clone(),
            state: self.state().await,
            failure_count: *self.failure_count.read().await,
            success_count: *self.success_count.read().await,
        }
    }
}

/// Circuit breaker metrics
#[derive(Debug, Clone)]
pub struct CircuitBreakerMetrics {
    pub service: String,
    pub state: CircuitState,
    pub failure_count: u32,
    pub success_count: u32,
}

/// Circuit breaker registry for multiple services
#[derive(Debug, Default)]
pub struct CircuitBreakerRegistry {
    breakers: Arc<RwLock<HashMap<String, CircuitBreaker>>>,
}

impl CircuitBreakerRegistry {
    /// Create new registry
    pub fn new() -> Self {
        Self {
            breakers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get or create circuit breaker
    pub async fn get(&self, name: &str) -> Option<CircuitBreaker> {
        let breakers = self.breakers.read().await;
        breakers.get(name).cloned()
    }

    /// Register a circuit breaker
    pub async fn register(&self, name: impl Into<String>, config: CircuitBreakerConfig) {
        let mut breakers = self.breakers.write().await;
        breakers.insert(name.into(), CircuitBreaker::new(config));
    }

    /// Get all metrics
    pub async fn metrics(&self) -> Vec<CircuitBreakerMetrics> {
        let breakers = self.breakers.read().await;
        let mut metrics = Vec::new();

        for (_, breaker) in breakers.iter() {
            metrics.push(breaker.metrics().await);
        }

        metrics
    }
}

/// Execute with circuit breaker pattern
///
/// Returns `Err(CircuitBreakerError::CircuitOpen)` if the circuit is open,
/// otherwise executes the operation and records success/failure.
///
/// # Type Parameters
/// * `T` - Success return type
/// * `E` - Error type that must be convertible from CircuitBreakerError
/// * `F` - Operation factory closure
/// * `Fut` - Future returned by the operation
/// Execute with circuit breaker pattern
///
/// Returns `Err` with a CircuitBreakerError if the circuit is open,
/// otherwise executes the operation and records success/failure.
///
/// Note: The operation must return `anyhow::Result<T>` for error compatibility.
pub async fn with_circuit_breaker<T, F, Fut>(
    breaker: &CircuitBreaker,
    operation: F,
) -> anyhow::Result<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    if !breaker.allow().await {
        // Circuit is open - fail fast with proper error
        return Err(anyhow::anyhow!(CircuitBreakerError::CircuitOpen));
    }

    match operation().await {
        Ok(result) => {
            breaker.record_success().await;
            Ok(result)
        }
        Err(e) => {
            breaker.record_failure().await;
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_circuit_breaker_transitions() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            reset_timeout: Duration::from_millis(100),
            success_threshold: 2,
            name: "test".to_string(),
        };

        let breaker = CircuitBreaker::new(config);

        // Initially closed
        assert_eq!(breaker.state().await, CircuitState::Closed);
        assert!(breaker.allow().await);

        // Record failures
        for _ in 0..3 {
            breaker.record_failure().await;
        }

        // Should be open now
        assert_eq!(breaker.state().await, CircuitState::Open);
        assert!(!breaker.allow().await);

        // Wait for reset timeout
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should transition to half-open
        assert!(breaker.allow().await);
        assert_eq!(breaker.state().await, CircuitState::HalfOpen);

        // Success should close circuit
        breaker.record_success().await;
        breaker.record_success().await;

        assert_eq!(breaker.state().await, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_clone_shares_state_via_arc() {
        // MCP-446 regression: pre-fix Clone created fresh state and
        // every consumer of CircuitBreakerRegistry::get(name) got a
        // breaker that started at failure_count=0 — the threshold
        // could never be reached cluster-wide.
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            reset_timeout: Duration::from_secs(60),
            success_threshold: 1,
            name: "test".to_string(),
        };

        let breaker = CircuitBreaker::new(config);
        let clone = breaker.clone();

        // One failure on the clone.
        clone.record_failure().await;
        // One failure on the original.
        breaker.record_failure().await;
        // Threshold (2) reached — circuit MUST be open on BOTH handles.
        assert_eq!(
            breaker.state().await,
            CircuitState::Open,
            "original handle must see shared state after clone records a failure"
        );
        assert_eq!(
            clone.state().await,
            CircuitState::Open,
            "clone handle must see shared state after original records a failure"
        );
    }

    #[tokio::test]
    async fn test_registry_get_shares_breaker_state() {
        // MCP-446: CircuitBreakerRegistry::get returns a `.cloned()`
        // breaker; that clone MUST observe the same state as every
        // other clone from the same registry entry.
        let registry = CircuitBreakerRegistry::new();
        registry
            .register(
                "redis",
                CircuitBreakerConfig {
                    failure_threshold: 1,
                    reset_timeout: Duration::from_secs(60),
                    success_threshold: 1,
                    name: "redis".to_string(),
                },
            )
            .await;

        let a = registry.get("redis").await.expect("registered");
        let b = registry.get("redis").await.expect("registered");

        a.record_failure().await;
        // failure_threshold = 1 → a is open. b MUST see that too.
        assert_eq!(b.state().await, CircuitState::Open);
        assert!(!b.allow().await, "b must fail fast: it shares a's state");
    }

    #[tokio::test]
    async fn test_with_circuit_breaker_returns_error_on_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            reset_timeout: Duration::from_secs(60), // Long timeout to keep it open
            success_threshold: 1,
            name: "test".to_string(),
        };

        let breaker = CircuitBreaker::new(config);

        // Open the circuit
        breaker.record_failure().await;
        assert_eq!(breaker.state().await, CircuitState::Open);

        // with_circuit_breaker should return error, not panic
        let result: anyhow::Result<String> =
            with_circuit_breaker(&breaker, || async { Ok("success".to_string()) }).await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Circuit breaker is open"));
    }
}
