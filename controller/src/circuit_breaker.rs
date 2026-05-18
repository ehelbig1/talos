// Circuit breaker pattern moved to the `talos-circuit-breaker` workspace crate.
// Re-export so existing `use crate::circuit_breaker::*` imports keep working.
// MCP-706: the registry-pattern breaker is NOT currently wired into the
// controller's Redis / NATS / sqlx callsites (the lone boot allocation
// was removed). The `webhooks::CircuitBreaker` is the only live breaker.
#[allow(unused_imports)]
pub use talos_circuit_breaker::*;
