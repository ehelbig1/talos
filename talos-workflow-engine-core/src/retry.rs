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

/// Whether a declared idempotency key can safely UPGRADE a send node from 0
/// retries to [`DEFAULT_TRANSIENT_RETRIES`].
///
/// [`default_max_retries_for_module`] fails closed to 0 for side-effect worlds
/// because a blind retry re-fires a non-idempotent send. An OPT-IN idempotency
/// key removes that hazard — but only where the enforcement mechanism actually
/// reaches: the worker emits the key as an `Idempotency-Key` HTTP header on
/// mutating outbound HTTP (`fetch` / `webhook::send`), so the destination
/// deduplicates the retried request (Stripe-style). That covers the HTTP-egress
/// worlds:
///
/// * `http` — the HTTP suite (fetch / webhook / graphql / email).
/// * `network` — HTTP suite + raw sockets; HTTP sends still carry the header
///   (a raw-socket send would not be deduped, a documented caveat).
/// * `agent` — includes the HTTP suite.
///
/// Everything else stays at whatever it resolved to: the header CANNOT dedupe a
/// NATS publish (`messaging`), a SQL DML (`database`), an approval re-fire
/// (`governance`), a filesystem/cache write, or a pure-compute module (which
/// already retries). Accepts bare and `-node`-suffixed spellings.
#[must_use]
pub fn world_enables_idempotent_retry(capability_world: &str) -> bool {
    matches!(
        capability_world.trim().trim_end_matches("-node"),
        "http" | "network" | "agent"
    )
}

/// The Task-3c decision, factored out so its SAFETY PROPERTY is unit-tested
/// rather than only structurally guaranteed at the dispatch site: a send node
/// that did NOT declare idempotency is NEVER granted retries here.
///
/// Given a node's already-resolved `base_max_retries` (from an explicit policy
/// or the method-aware default) and whether the node declared an idempotency
/// key, return the effective retry count:
///
/// * `idempotency_declared == false` → returns `base_max_retries` UNCHANGED.
///   This is the safety line — a non-declaring send node keeps its 0.
/// * declared, base is 0, and the world is HTTP-egress
///   ([`world_enables_idempotent_retry`]) → upgrade to
///   [`DEFAULT_TRANSIENT_RETRIES`] (the Idempotency-Key header dedupes the
///   retried send at the destination).
/// * declared but base is already non-zero → returns `base_max_retries`
///   UNCHANGED (never LOWER an operator's explicit count).
/// * declared but the world can't carry the header (messaging/database/…) →
///   returns `base_max_retries` UNCHANGED.
#[must_use]
pub fn effective_retries_with_idempotency(
    base_max_retries: u32,
    capability_world: &str,
    idempotency_declared: bool,
) -> u32 {
    if idempotency_declared
        && base_max_retries == 0
        && world_enables_idempotent_retry(capability_world)
    {
        DEFAULT_TRANSIENT_RETRIES
    } else {
        base_max_retries
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
    fn idempotent_retry_only_for_http_egress_worlds() {
        // HTTP-egress worlds: the Idempotency-Key header dedupes the retry.
        for w in [
            "http",
            "http-node",
            "network",
            "network-node",
            "agent",
            "agent-node",
        ] {
            assert!(
                world_enables_idempotent_retry(w),
                "{w} should allow idempotent-send retries"
            );
        }
        // The header cannot dedupe these side effects → no upgrade.
        for w in [
            "messaging",
            "database",
            "governance",
            "filesystem",
            "cache",
            "minimal",
            "secrets",
            "trusted",
            "automation",
            "",
            "bogus",
        ] {
            assert!(
                !world_enables_idempotent_retry(w),
                "{w} must NOT allow idempotent-send retries"
            );
        }
    }

    #[test]
    fn non_declaring_send_node_never_gets_retries() {
        // THE SAFETY PROPERTY (Task 3): a send node that did NOT declare
        // idempotency keeps its 0 — the method-aware default is not weakened.
        for w in [
            "http",
            "network",
            "agent",
            "messaging",
            "database",
            "governance",
        ] {
            assert_eq!(
                effective_retries_with_idempotency(0, w, false),
                0,
                "{w}: non-declaring send node must stay at 0 retries"
            );
        }
    }

    #[test]
    fn declared_idempotency_upgrades_only_http_egress_from_zero() {
        // Declared + HTTP-egress + base 0 → transient retries (header dedupes).
        for w in ["http", "http-node", "network", "agent"] {
            assert_eq!(
                effective_retries_with_idempotency(0, w, true),
                DEFAULT_TRANSIENT_RETRIES,
                "{w}: declared idempotency should enable retries"
            );
        }
        // Declared but the header can't dedupe these side effects → stays 0.
        for w in ["messaging", "database", "governance", "filesystem", "cache"] {
            assert_eq!(
                effective_retries_with_idempotency(0, w, true),
                0,
                "{w}: header can't dedupe → no idempotent-retry upgrade"
            );
        }
    }

    #[test]
    fn declared_idempotency_never_lowers_explicit_count() {
        // An operator's explicit non-zero count is respected, not clobbered.
        assert_eq!(effective_retries_with_idempotency(5, "http", true), 5);
        assert_eq!(effective_retries_with_idempotency(1, "messaging", true), 1);
    }

    #[test]
    fn default_for_module_keeps_standard_backoff() {
        let p = RetryPolicy::default_for_module(&methods(&["GET"]), Some("http-node"));
        assert_eq!(p.max_retries, DEFAULT_TRANSIENT_RETRIES);
        assert_eq!(p.backoff_ms, 500);
        assert!(p.retry_condition.is_none());
    }
}
