//! Integration tests for circuit breaker functionality

use controller::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitState};
use std::time::Duration;

#[tokio::test]
async fn test_circuit_breaker_integration() {
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

    // Trigger failures
    for _ in 0..3 {
        breaker.record_failure().await;
    }

    // Should be open
    assert_eq!(breaker.state().await, CircuitState::Open);
    assert!(!breaker.allow().await);

    // Wait for timeout
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Should be half-open
    assert!(breaker.allow().await);
    assert_eq!(breaker.state().await, CircuitState::HalfOpen);

    // Success should close
    breaker.record_success().await;
    breaker.record_success().await;

    assert_eq!(breaker.state().await, CircuitState::Closed);
}

#[tokio::test]
async fn test_circuit_breaker_recovery_failure() {
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        reset_timeout: Duration::from_millis(50),
        success_threshold: 2,
        name: "test".to_string(),
    };

    let breaker = CircuitBreaker::new(config);

    // Open circuit
    breaker.record_failure().await;
    breaker.record_failure().await;
    assert_eq!(breaker.state().await, CircuitState::Open);

    // Wait for timeout
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Half-open
    assert!(breaker.allow().await);

    // Failure should reopen
    breaker.record_failure().await;
    assert_eq!(breaker.state().await, CircuitState::Open);
}
