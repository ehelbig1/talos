//! Retry policy for node execution.

use serde::{Deserialize, Serialize};

/// How the executor should retry a node when its dispatch fails.
///
/// This is a *declaration*, not a resolved plan: `max_retries` is
/// `Option<u32>` precisely because the graph parser that builds this
/// value cannot answer "how many". See the field docs.
///
/// The default is "nothing declared": no count, 500 ms base backoff, no
/// conditional gate, no custom delay expression. Both Rhai-style
/// expression fields are opaque here — evaluation is the executor's job.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts after the first failure, when the
    /// node author declared one (graph key `retry_count`).
    ///
    /// `None` means **the author did not say how many** — resolve it with
    /// [`RetryPolicy::resolved_max_retries`], which asks
    /// [`default_max_retries_for_module`] using the module's own
    /// `capability_world` / `allowed_methods`.
    ///
    /// This field is deliberately NOT a `u32` with a default. The four
    /// graph retry keys do not answer the same question: `retry_count`
    /// answers *how many*, `retry_backoff_ms` / `retry_delay_expression`
    /// answer *how far apart*, and `retry_condition` answers *when* (it
    /// is a restricting gate — it can only ever shrink the retry set).
    /// A parser that saw only a spacing or gating key used to synthesise
    /// `max_retries: 2` here, which suppressed the world-aware fallback
    /// entirely and handed blind retries to governance / messaging /
    /// database nodes that fail closed to 0 by design. Keeping the count
    /// optional makes that state unrepresentable rather than merely
    /// corrected.
    ///
    /// An explicitly declared `Some(0)` still always wins — the
    /// classifier must never override an author.
    pub max_retries: Option<u32>,
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
    /// "Nothing was declared." `max_retries: None` routes to the
    /// method-aware classifier at resolve time; it is NOT a synonym for
    /// [`DEFAULT_TRANSIENT_RETRIES`].
    fn default() -> Self {
        Self {
            max_retries: None,
            backoff_ms: DEFAULT_BACKOFF_MS,
            retry_condition: None,
            retry_delay_expression: None,
        }
    }
}

/// Base backoff applied when a node declares retries but no
/// `retry_backoff_ms`. Unlike the retry COUNT, spacing has no
/// safety-relevant classifier — 500 ms is safe for every world because it
/// only affects *when* an already-authorised retry fires, never whether
/// one fires at all.
pub const DEFAULT_BACKOFF_MS: u64 = 500;

/// Retry count applied to a module with no explicit retry configuration
/// when the module is classified safe-to-retry (read-only / pure
/// compute). Kept in one place so the engine's absent-policy fallback,
/// the node-creation stamping path, and any future hygiene sweep agree.
pub const DEFAULT_TRANSIENT_RETRIES: u32 = 2;

/// Max retries honoured for a workflow with **no bound actor**.
///
/// An actor-less execution cannot amortize retry cost against a per-actor
/// budget, so a DECLARED count is clamped here at graph load. Only a declared
/// count is clamped — the classifier's own answers are already below this.
///
/// Lives in core so the graph parser that APPLIES the clamp and any
/// authoring-time checker that must PREDICT the resolved count read the same
/// number. A checker using an unclamped count would report an envelope the
/// engine will never run.
pub const MAX_RETRIES_UNBUDGETED: u32 = 3;

/// Workflow-level wall-clock budget applied when a graph declares no
/// `execution_timeout_secs`.
///
/// This is the number a node's retry envelope actually has to fit inside on
/// the overwhelming majority of workflows, so it is defined once here rather
/// than as a literal in the engine's constructor.
pub const DEFAULT_WORKFLOW_EXECUTION_TIMEOUT_SECS: u64 = 300;

/// Per-attempt node timeout applied when a node declares no `timeout_secs`
/// and the operator sets no override. Matches the worker's single-op ceiling.
pub const DEFAULT_NODE_TIMEOUT_SECS_FALLBACK: u64 = 120;

/// Resolve the per-attempt node timeout the engine will actually enforce:
/// `WASM_EXECUTION_TIMEOUT_SECS` when the operator sets it, else
/// [`DEFAULT_NODE_TIMEOUT_SECS_FALLBACK`].
///
/// **Exists so the reported and the enforced value cannot drift.** The engine
/// caches this in a `LazyLock`; an authoring-time checker that hardcoded 120
/// would silently disagree with any deployment that sets the override, and a
/// checker that disagrees with the enforcer is worse than no checker.
#[must_use]
pub fn default_node_timeout_secs() -> u64 {
    std::env::var("WASM_EXECUTION_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_NODE_TIMEOUT_SECS_FALLBACK)
}

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
/// * `http` / `agent` worlds are safe only when the module DECLARES a
///   method allowlist and every entry in it is `GET`/`HEAD`.
/// * Everything else — `governance` (approval gates must not re-fire
///   on rejection), `messaging`, `database`, `network`, `filesystem`,
///   `cache`, `automation`, `trusted`, and any world this function
///   does not recognise — fails closed to 0 retries. Per-node
///   `retry_count` remains the explicit override for those.
///
/// # An EMPTY method list is UNKNOWN, not read-only
///
/// This function used to read an empty `allowed_methods` as read-only,
/// because `[].iter().all(..)` is vacuously true. That made the platform
/// disagree with itself: at the ENFORCEMENT point an empty list means
/// "allow every method" (`talos-worker-runtime/src/host/http.rs` on both
/// `fetch` and `fetch_all`, and `host/graphql.rs` for the always-POST
/// GraphQL call), so an undeclared module may `POST`/`PUT`/`DELETE`/
/// `PATCH` freely — and was nonetheless handed blind transient retries,
/// which is exactly the non-idempotent re-fire this function exists to
/// prevent. An absent declaration is an absence of evidence, so it now
/// resolves to 0.
///
/// Note that `allowed_methods` is the ODD ONE OUT among the per-module
/// declaration lists: an empty `allowed_hosts` and an empty
/// `allowed_secrets` both DENY ALL (`host/http.rs`, `host/webhook.rs`,
/// `job_protocol::vault_path_permitted`). Do not generalise "empty
/// means unrestricted" from this one field.
///
/// A module author who wants transient retries declares `["GET"]` (or
/// `["GET", "HEAD"]`); a node author who wants them regardless sets an
/// explicit `retry_count`. Both are explicit, which is the point.
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
    // `!is_empty()` is load-bearing, not defensive: `.all()` over an empty
    // slice is vacuously true, and empty means "allow every method" at the
    // worker's enforcement point. Read-only must be DECLARED.
    let methods_read_only = !allowed_methods.is_empty()
        && allowed_methods
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
    /// The node's effective retry count: the author's declared
    /// `retry_count` when there is one, otherwise
    /// [`default_max_retries_for_module`] for the module actually being
    /// dispatched.
    ///
    /// This is the ONLY place a missing count acquires a value, which is
    /// what keeps "author said nothing at all" and "author declared a
    /// backoff but no count" from diverging — before, the first went
    /// through the classifier and the second was silently stamped 2 for
    /// every world.
    ///
    /// The declared value is returned verbatim, including `Some(0)`: the
    /// classifier never overrides an author.
    #[must_use]
    pub fn resolved_max_retries(
        &self,
        allowed_methods: &[String],
        capability_world: Option<&str>,
    ) -> u32 {
        self.max_retries
            .unwrap_or_else(|| default_max_retries_for_module(allowed_methods, capability_world))
    }
}

#[cfg(test)]
mod retry_resolution_tests {
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
    fn undeclared_method_list_is_unknown_and_fails_closed() {
        // An EMPTY `allowed_methods` is an ABSENT declaration, not a
        // read-only one. `[].iter().all(..)` is vacuously true, and the
        // worker's enforcement point reads empty as "allow every method"
        // (`host/http.rs` fetch + fetch_all, `host/graphql.rs`), so an
        // undeclared module can POST. Resolve it to 0.
        //
        // If this assertion fails: the classifier has started granting
        // retries on the strength of an absent declaration again — check
        // the `!allowed_methods.is_empty()` conjunct in
        // `default_max_retries_for_module`, and re-read whether the
        // worker still treats an empty list as unrestricted.
        for world in ["http", "http-node", "agent", "agent-node"] {
            assert_eq!(
                default_max_retries_for_module(&[], Some(world)),
                0,
                "{world}: an undeclared method list must not earn retries"
            );
        }
        // A declared read-only list still does, so the fix narrows only
        // the undeclared case.
        assert_eq!(
            default_max_retries_for_module(&methods(&["GET"]), Some("http-node")),
            DEFAULT_TRANSIENT_RETRIES
        );
        assert_eq!(
            default_max_retries_for_module(&methods(&["GET", "HEAD"]), Some("agent-node")),
            DEFAULT_TRANSIENT_RETRIES
        );
        // A list of blank entries is a declaration of nothing recognisable
        // and must fail closed the same way (it is non-empty, so the
        // `is_empty` conjunct does not carry it — the GET/HEAD match does).
        assert_eq!(
            default_max_retries_for_module(&methods(&["", "   "]), Some("http-node")),
            0
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
    fn an_undeclared_count_resolves_through_the_classifier_not_a_literal() {
        // The invariant this module exists to hold: a policy whose count
        // was never declared asks the module, and gets DIFFERENT answers
        // for a read-only module and a side-effecting one. A literal
        // default cannot do that, which is why `max_retries` is optional.
        let undeclared = RetryPolicy::default();
        assert_eq!(
            undeclared.resolved_max_retries(&methods(&["GET"]), Some("http-node")),
            DEFAULT_TRANSIENT_RETRIES,
        );
        for world in ["governance", "messaging", "database", "network"] {
            assert_eq!(
                undeclared.resolved_max_retries(&[], Some(world)),
                0,
                "{world}: an undeclared count must fail closed, not inherit a literal"
            );
        }
    }

    #[test]
    fn a_declared_count_always_wins_including_zero() {
        // Documented platform rule: the classifier never overrides an author.
        let explicit_zero = RetryPolicy {
            max_retries: Some(0),
            ..RetryPolicy::default()
        };
        assert_eq!(
            explicit_zero.resolved_max_retries(&methods(&["GET"]), Some("minimal-node")),
            0,
            "a read-only world must not upgrade an author's explicit 0"
        );
        let explicit_seven = RetryPolicy {
            max_retries: Some(7),
            ..RetryPolicy::default()
        };
        assert_eq!(
            explicit_seven.resolved_max_retries(&[], Some("governance-node")),
            7,
            "a fail-closed world must not downgrade an author's explicit count"
        );
    }

    #[test]
    fn spacing_and_gating_fields_do_not_supply_a_count() {
        // `retry_backoff_ms` / `retry_delay_expression` answer "how far
        // apart"; `retry_condition` is a RESTRICTING gate ("skip the retry
        // unless this holds"). None of the three can decide "how many", so
        // each must still resolve through the classifier — and on a
        // fail-closed world that means 0, not a synthesised 2.
        for policy in [
            RetryPolicy {
                backoff_ms: 3_000,
                ..RetryPolicy::default()
            },
            RetryPolicy {
                retry_condition: Some("error_code == 429".to_string()),
                ..RetryPolicy::default()
            },
            RetryPolicy {
                retry_delay_expression: Some("retry_after * 1000".to_string()),
                ..RetryPolicy::default()
            },
        ] {
            assert_eq!(policy.max_retries, None);
            assert_eq!(policy.resolved_max_retries(&[], Some("messaging-node")), 0);
            assert_eq!(
                policy.resolved_max_retries(&methods(&["GET"]), Some("http-node")),
                DEFAULT_TRANSIENT_RETRIES,
            );
        }
    }
}
