//! Retry policy for node execution.

use serde::{Deserialize, Serialize};

/// How the executor should retry a node when its dispatch fails.
///
/// Defaults to 2 retries with 500ms backoff, no conditional gate, and no
/// custom delay expression — a reasonable starting point that callers can
/// override per-node. Both Rhai-style expression fields are opaque here:
/// evaluation is the executor's job.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts after the first failure.
    pub max_retries: u32,
    /// Base backoff between attempts in milliseconds. The executor may
    /// apply exponential growth and jitter on top of this value.
    pub backoff_ms: u64,
    /// Optional expression evaluated against the error output. If present
    /// and it evaluates to `false`, retry is skipped and the error is
    /// returned immediately.
    pub retry_condition: Option<String>,
    /// Optional expression that returns a delay in milliseconds computed
    /// from the error output. If present and evaluates to a number, that
    /// value (capped at `60_000` ms by the executor) is used in place of
    /// exponential backoff.
    pub retry_delay_expression: Option<String>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 2,
            backoff_ms: 500,
            retry_condition: None,
            retry_delay_expression: None,
        }
    }
}

/// Retry count applied to a module with no explicit retry configuration
/// when the module is classified safe-to-retry (read-only / pure
/// compute). Kept in one place so the engine's absent-policy fallback,
/// the node-creation stamping path, and any future hygiene sweep agree.
pub const DEFAULT_TRANSIENT_RETRIES: u32 = 2;

/// Method-aware default retry count for a module with no explicit
/// retry configuration.
///
/// Blanket default retries are wrong in both directions: zero retries
/// let a 30-second network blip fail every scheduled read (the
/// 2026-07-23 outage failed ~125 read-only Gmail fetches that each ran
/// exactly once), while unconditional retries re-fire non-idempotent
/// sends (duplicate emails, duplicate DB writes). The safe line is
/// idempotency, and the two signals the platform already carries for
/// it are the module's `capability_world` and its `allowed_methods`:
///
/// * `minimal` / `secrets` worlds have no HTTP or side-effect surface
///   (pure compute + host-mediated LLM calls) — retrying is safe.
/// * `http` / `agent` worlds are safe only when every allowed method
///   is `GET`/`HEAD` (an empty list means the module cannot make any
///   outbound call at all, which is also safe).
/// * Everything else — `governance` (approval gates must not re-fire
///   on rejection), `messaging`, `database`, `network`, `filesystem`,
///   `cache`, `automation`, `trusted`, and any world this function
///   does not recognise — fails closed to 0 retries. Per-node
///   `retry_count` remains the explicit override for those.
///
/// Accepts both bare (`"http"`) and node-suffixed (`"http-node"`)
/// world spellings; `None`/empty world fails closed to 0.
///
/// The transient-vs-permanent error gate still applies on top of this
/// at dispatch time (the retry classifier skips retries for auth
/// errors, fuel exhaustion, etc.), so this value is a ceiling for
/// transient failures, not an unconditional re-fire count.
pub fn default_max_retries_for_module(
    allowed_methods: &[String],
    capability_world: Option<&str>,
) -> u32 {
    let world = capability_world
        .unwrap_or("")
        .trim()
        .trim_end_matches("-node")
        .to_ascii_lowercase();
    let methods_read_only = allowed_methods
        .iter()
        .all(|m| matches!(m.trim().to_ascii_uppercase().as_str(), "GET" | "HEAD"));
    match world.as_str() {
        "minimal" | "secrets" => DEFAULT_TRANSIENT_RETRIES,
        "http" | "agent" if methods_read_only => DEFAULT_TRANSIENT_RETRIES,
        _ => 0,
    }
}

impl RetryPolicy {
    /// Full [`RetryPolicy`] for a module with no explicit retry
    /// configuration — [`default_max_retries_for_module`] for the
    /// count, the standard 500 ms base backoff otherwise.
    pub fn default_for_module(allowed_methods: &[String], capability_world: Option<&str>) -> Self {
        Self {
            max_retries: default_max_retries_for_module(allowed_methods, capability_world),
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod default_for_module_tests {
    use super::*;

    fn methods(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn read_only_http_module_retries() {
        assert_eq!(
            default_max_retries_for_module(&methods(&["GET"]), Some("http-node")),
            DEFAULT_TRANSIENT_RETRIES
        );
        // Bare world spelling and mixed-case methods normalize.
        assert_eq!(
            default_max_retries_for_module(&methods(&["get", "Head"]), Some("http")),
            DEFAULT_TRANSIENT_RETRIES
        );
    }

    #[test]
    fn state_changing_http_module_does_not_retry() {
        assert_eq!(
            default_max_retries_for_module(&methods(&["GET", "POST"]), Some("http-node")),
            0
        );
        assert_eq!(
            default_max_retries_for_module(&methods(&["DELETE"]), Some("agent-node")),
            0
        );
    }

    #[test]
    fn pure_compute_worlds_retry() {
        assert_eq!(
            default_max_retries_for_module(&[], Some("minimal-node")),
            DEFAULT_TRANSIENT_RETRIES
        );
        // secrets world = LLM host calls; transient upstream errors retry.
        assert_eq!(
            default_max_retries_for_module(&[], Some("secrets-node")),
            DEFAULT_TRANSIENT_RETRIES
        );
    }

    #[test]
    fn governance_and_send_worlds_never_retry() {
        // Approval gate re-fire on rejection was the documented reason
        // the old creation-time default existed — preserved structurally.
        assert_eq!(
            default_max_retries_for_module(&[], Some("governance-node")),
            0
        );
        assert_eq!(
            default_max_retries_for_module(&[], Some("messaging-node")),
            0
        );
        assert_eq!(
            default_max_retries_for_module(&[], Some("database-node")),
            0
        );
        assert_eq!(default_max_retries_for_module(&[], Some("network-node")), 0);
    }

    #[test]
    fn unknown_or_missing_world_fails_closed() {
        assert_eq!(default_max_retries_for_module(&[], None), 0);
        assert_eq!(default_max_retries_for_module(&[], Some("")), 0);
        assert_eq!(
            default_max_retries_for_module(&methods(&["GET"]), Some("future-world")),
            0
        );
    }

    #[test]
    fn http_world_with_empty_methods_is_read_only() {
        // No allowed methods = no egress at all; retrying is safe.
        assert_eq!(
            default_max_retries_for_module(&[], Some("http-node")),
            DEFAULT_TRANSIENT_RETRIES
        );
    }

    #[test]
    fn default_for_module_keeps_standard_backoff() {
        let p = RetryPolicy::default_for_module(&methods(&["GET"]), Some("http-node"));
        assert_eq!(p.max_retries, DEFAULT_TRANSIENT_RETRIES);
        assert_eq!(p.backoff_ms, 500);
        assert!(p.retry_condition.is_none());
    }
}
