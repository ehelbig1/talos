//! Reserved `__`-prefixed keys the engine reads and writes on node
//! input and output payloads.
//!
//! The executor exchanges small pieces of protocol-level metadata with
//! modules and sub-workflows through a set of `__`-prefixed keys on the
//! `serde_json::Value` input and output objects. These keys are
//! reserved: the engine strips them from user-visible output (where
//! documented) or uses them to propagate state across sub-workflow
//! boundaries. Consumers authoring modules should treat the set below
//! as off-limits for their own field names, and consumers consuming
//! node output should expect these keys to appear on objects the
//! engine has touched.
//!
//! # Categories
//!
//! * **Error reporting** — [`ERROR_FLAG`] + friends mark a failed node
//!   output, letting downstream branches distinguish failures from
//!   successful empty outputs.
//! * **Control flow** — [`SKIP_CONDITION`], [`CONTINUE_ON_ERROR`],
//!   [`SKIPPED`] carry node-level flow hints parsed from `graph_json`
//!   and evaluated at dispatch time.
//! * **Tracing / observability** — [`TRIGGER`], [`FUEL_CONSUMED`]
//!   surface engine-internal markers on output so consumers can
//!   distinguish synthetic nodes from user-graph nodes.
//! * **Actor memory** — [`MEMORY_WRITE`], [`ACTOR_CONTEXT`] ferry
//!   agent-memory hints between a dispatcher-configured memory
//!   backend and the module payload.
//! * **Input freshness** — [`REQUIRES_FRESH`] / [`ON_STALE`] declare a
//!   per-node max-age contract on the actor-memory keys the node reads;
//!   the engine answers with a [`STALENESS`] report on the node's input
//!   so a reader can never silently present stale data as current.
//! * **Sub-workflow output** — keys prefixed `__judge_*`,
//!   `__confidence_*`, `__ensemble_*`, `__verification_*`,
//!   `__reflective_retry_*` are written by the corresponding
//!   [`crate::SystemNodeKind`] handler onto the collapsed output of
//!   that sub-workflow.
//!
//! None of these keys are signed in the wire format; they are layer-7
//! protocol data, not authenticated transport. They must not be used
//! to carry secret values.

/// Error marker: boolean `true` on an output object flags the node
/// as having failed. Paired with a free-form `error_message` string.
///
/// **Engine writers always emit a literal `true`, but READERS must not
/// assume the shape.** `__error` is one of exactly two `__`-prefixed keys
/// that survive the reserved-key strip on a module's own output (the other
/// is [`CONTINUED`] — see the `retain` calls in
/// `engine_dispatch_system.rs`), and `collapse_subworkflow_output` returns
/// a single terminal node's output verbatim. So the value reaching a
/// reader can have been authored by a WASM module, a custom
/// `NodeDispatcher` (`docs/workflow-engine/custom-dispatcher.md` documents
/// returning `Ok` with an `__error` envelope), or an LLM's JSON — none of
/// which the engine validates. Classify it with [`classify_error_flag`] /
/// [`output_reports_error`]; never `.as_bool().unwrap_or(false)`, which
/// reads a present-but-mis-shaped marker as "no error".
pub const ERROR_FLAG: &str = "__error";

/// What an [`ERROR_FLAG`]-style marker's value actually says.
///
/// Returned by [`classify_error_flag`]. Three JSON values mean "this node
/// did not fail" and everything else means it did — see that function for
/// the rule and why it is drawn there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorFlag {
    /// No marker at all, or a marker whose value means "no failure":
    /// `null`, `false`, or the empty string.
    NoError,
    /// The marker is present with a value that means the node failed.
    /// `message` is the operator-facing rendering of that value.
    Failed {
        /// A non-empty string value verbatim; any other value rendered
        /// as compact JSON (so `true` renders as `"true"`).
        message: String,
    },
}

impl ErrorFlag {
    /// `true` for [`ErrorFlag::Failed`].
    pub fn is_failed(&self) -> bool {
        matches!(self, ErrorFlag::Failed { .. })
    }
}

/// Classify an [`ERROR_FLAG`] (or bare `error`) marker value.
///
/// **The rule: only a falsy-or-empty value means success.** Precisely,
/// these four inputs are [`ErrorFlag::NoError`] —
///
/// * `None` (the key is absent),
/// * `Null` — the success envelope `database-query`-style templates emit,
/// * `false` — an explicit "did not fail",
/// * `""` — a present but empty error message carries no error;
///
/// — and **every other value is [`ErrorFlag::Failed`]**, including a
/// non-empty string, a number, an array and an object.
///
/// Why the rule is drawn here rather than at either extreme:
///
/// * `.as_bool().unwrap_or(false)` (the shape this function replaces)
///   treats a mis-shaped marker as success. A module reporting
///   `{"__error": "upstream 502"}` — a natural shape, and one the engine
///   never validates away — reads as a clean run. A present error marker
///   nobody could parse is the one thing that must not read as success.
/// * A bare `.is_some()` is the opposite error: it makes `__error: false`
///   and `__error: null` mean *failed*, which would break every template
///   that emits an explicit success envelope. Presence is not the test.
///
/// This is the semantics `talos-engine`'s Rhai condition scope has always
/// used for `is_error` / `error_message`; it now has one implementation so
/// a skip-condition, an edge predicate and a contract test cannot disagree
/// about whether the same output errored.
pub fn classify_error_flag(value: Option<&serde_json::Value>) -> ErrorFlag {
    match value {
        None | Some(serde_json::Value::Null | serde_json::Value::Bool(false)) => ErrorFlag::NoError,
        Some(serde_json::Value::String(s)) if s.is_empty() => ErrorFlag::NoError,
        Some(serde_json::Value::String(s)) => ErrorFlag::Failed { message: s.clone() },
        Some(other) => ErrorFlag::Failed {
            message: other.to_string(),
        },
    }
}

/// `true` when `output`'s [`ERROR_FLAG`] marker reports a failure, per
/// [`classify_error_flag`].
///
/// A non-object `output` has no marker to read and is therefore not an
/// error (`Value::get` returns `None`), which matches how every caller
/// treated a bare string / array output before.
pub fn output_reports_error(output: &serde_json::Value) -> bool {
    classify_error_flag(output.get(ERROR_FLAG)).is_failed()
}

/// The operator-facing reason `output` reports a failure, or `None` when
/// it reports none.
///
/// Two places carry the reason and they are checked in that order:
///
/// 1. an explicit non-empty `error_message` string — what every envelope
///    the engine itself synthesizes writes;
/// 2. failing that, the [`ERROR_FLAG`] marker's own value, whenever the
///    marker is something other than a bare boolean.
///
/// The second source exists because [`classify_error_flag`] already
/// computes it and the bool-returning [`output_reports_error`] throws it
/// away. A module reporting the mis-shaped `{"__error": "upstream 502"}`
/// — the shape #733 taught the classifier to READ as a failure — has no
/// `error_message` field at all, so the run that #733 correctly began
/// failing was described to the operator as a generic "rejected output"
/// while the actual reason sat unread in the very key that triggered the
/// failure. A bare `true` is deliberately NOT used: rendering it would
/// put the string `"true"` where a reason belongs, which is worse than
/// the caller's own fallback wording.
pub fn error_reason(output: &serde_json::Value) -> Option<String> {
    let marker = output.get(ERROR_FLAG);
    let ErrorFlag::Failed { message } = classify_error_flag(marker) else {
        return None;
    };
    if let Some(msg) = output
        .get("error_message")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
    {
        return Some(msg.to_string());
    }
    // A boolean marker is a flag, not a message: `classify_error_flag`
    // renders `true` as the string "true", which is not a reason.
    if matches!(marker, Some(serde_json::Value::Bool(_))) {
        return None;
    }
    Some(message)
}

/// Signals downstream aggregators that input fan-in collapsed with
/// missing or erroring branches.
pub const AGGREGATION_FAILED: &str = "__aggregation_failed";

/// Per-node skip-condition expression parsed from `graph_json`. When
/// present and the expression evaluates to truthy at dispatch time,
/// the node short-circuits with a [`SKIPPED`] marker instead of
/// dispatching.
pub const SKIP_CONDITION: &str = "__skip_condition";

/// Per-node flag: when truthy, a dispatch failure on this node does
/// not fail the workflow — downstream nodes still run with the
/// failed node's error envelope as input.
pub const CONTINUE_ON_ERROR: &str = "__continue_on_error";

/// Engine-written output marker: the node was skipped (typically via
/// [`SKIP_CONDITION`]) and produced no user-visible output.
pub const SKIPPED: &str = "__skipped";

/// Synthetic node label used for the trigger injected at the root of
/// a sub-workflow. Engine-internal; downstream consumers will see it
/// as a sibling of the real nodes in the output.
pub const TRIGGER: &str = "__trigger__";

/// Engine-written output marker: accumulated wasmtime fuel consumed
/// by the node.
pub const FUEL_CONSUMED: &str = "__fuel_consumed__";

/// Written onto node input by the engine when an actor context is
/// configured. Carries a per-actor memory view for modules that
/// implement the agent-memory protocol.
pub const ACTOR_CONTEXT: &str = "__actor_context__";

/// Output-side hook: modules write under this key to append to the
/// actor-memory log. The engine's memory backend (if any) reads this
/// after dispatch and commits the writes.
pub const MEMORY_WRITE: &str = "__memory_write__";

/// Per-node config key that OPTS a send node into idempotent retries. When
/// present and truthy the engine stamps a stable idempotency key onto the
/// dispatch (see [`resolve_idempotency_key`]); the worker then emits that key as
/// an `Idempotency-Key` HTTP header on mutating outbound requests so a retried
/// send is deduplicated at the destination. Its presence is ALSO what lets the
/// method-aware retry default grant retries to a send world
/// ([`crate::world_enables_idempotent_retry`]). Engine metadata — STRIPPED from
/// the module input so it never reaches guest code.
pub const IDEMPOTENCY_KEY: &str = "__idempotency_key__";

/// Resolve the idempotency key for a node from its merged config, or `None`
/// when idempotency is not declared.
///
/// Semantics of the `__idempotency_key__` config value:
/// * a non-empty **string** → that literal is the key (the author controls it,
///   e.g. a per-resource token). Not templated in the engine — a literal.
/// * boolean `true`, or the string `"auto"`/`"true"` → an engine-derived
///   STABLE key `"<execution_id>:<node_id>"`. Stable across retry attempts of
///   the same dispatch (so the destination dedupes a retry) and unique per
///   logical send per execution (a genuine re-run is a new operation).
/// * `false`, `null`, empty string, or absent → `None` (not declared).
#[must_use]
pub fn resolve_idempotency_key(
    config: Option<&serde_json::Value>,
    execution_id: &uuid::Uuid,
    node_id: &uuid::Uuid,
) -> Option<String> {
    let v = config.and_then(|c| c.get(IDEMPOTENCY_KEY))?;
    let derived = || format!("{execution_id}:{node_id}");
    match v {
        serde_json::Value::String(s) => {
            let s = s.trim();
            if s.is_empty() {
                None
            } else if s.eq_ignore_ascii_case("auto") || s.eq_ignore_ascii_case("true") {
                Some(derived())
            } else {
                Some(s.to_string())
            }
        }
        serde_json::Value::Bool(true) => Some(derived()),
        _ => None,
    }
}

/// Engine-written onto node input: the freshness report for the
/// actor-memory keys the node declared via [`REQUIRES_FRESH`].
///
/// Shape:
/// ```json
/// { "any_stale": true,
///   "entries": [
///     {"key":"meeting_prep/today","age_hours":32.1,"max_age_hours":6.0,
///      "stale":true,"present":true}
///   ] }
/// ```
///
/// **Why this exists.** A workflow that synthesizes from actor memory has no
/// way to know its inputs are old: if an upstream writer failed (or simply
/// hasn't run yet), the reader confidently presents yesterday's data as
/// today's. This was observed live on the cross-domain briefing workflow —
/// 32-hour-old meeting data rendered as "today", with a passing judge,
/// because nothing in the pipeline measured input age. Declaring
/// [`REQUIRES_FRESH`] makes the age VISIBLE to the node (annotate) or stops
/// the run (fail), converting a silent-wrong into a visible-correct.
///
/// Engine-authored, so it is STRIPPED from inbound trigger/test payloads —
/// a caller-supplied `__staleness__` would be a trust-signal spoof.
pub const STALENESS: &str = "__staleness__";

/// Per-node graph-json field declaring the maximum acceptable age of the
/// actor-memory keys this node reads: `{"<key>": <max_age_hours>}`, e.g.
/// `{"requires_fresh": {"meeting_prep/today": 6, "daily_brief/latest": 6}}`.
/// The engine resolves each key's age against the node's bound actor and
/// injects a [`STALENESS`] report. Absent → no freshness contract (the
/// pre-feature behavior; fully backward-compatible).
pub const REQUIRES_FRESH: &str = "requires_fresh";

/// Per-node graph-json field selecting what happens when a
/// [`REQUIRES_FRESH`] requirement is violated: `"annotate"` (default —
/// inject [`STALENESS`] and let the node/downstream render the warning) or
/// `"fail"` (refuse to dispatch, so a stale-input run surfaces as a real
/// failure instead of a plausible-looking wrong answer).
pub const ON_STALE: &str = "on_stale";

/// What to do when a declared freshness requirement is violated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnStale {
    /// Inject the [`STALENESS`] report and continue. The default: visible,
    /// non-breaking, and lets a composer render "data is 32h old".
    #[default]
    Annotate,
    /// Fail the node. For pipelines where acting on stale data is worse
    /// than not acting (a send that would state something false).
    Fail,
}

/// A node's parsed freshness contract.
#[derive(Debug, Clone, PartialEq)]
pub struct FreshnessPolicy {
    /// `(memory_key, max_age_hours)` pairs, in declaration order.
    pub requirements: Vec<(String, f64)>,
    /// Violation behavior.
    pub on_stale: OnStale,
}

/// Parse a node's freshness contract from its merged config/`data`.
///
/// Returns `None` when [`REQUIRES_FRESH`] is absent, empty, or not an object
/// — i.e. "no contract", the backward-compatible default. Non-positive and
/// non-numeric max-ages are skipped (a `0`/garbage bound would make every
/// read permanently stale, which is a footgun, not a contract).
#[must_use]
pub fn resolve_freshness_policy(config: Option<&serde_json::Value>) -> Option<FreshnessPolicy> {
    let obj = config.and_then(|c| c.get(REQUIRES_FRESH))?.as_object()?;
    let requirements: Vec<(String, f64)> = obj
        .iter()
        .filter_map(|(k, v)| {
            let hours = v.as_f64()?;
            if hours.is_finite() && hours > 0.0 {
                Some((k.clone(), hours))
            } else {
                None
            }
        })
        .collect();
    if requirements.is_empty() {
        return None;
    }
    let on_stale = match config
        .and_then(|c| c.get(ON_STALE))
        .and_then(|v| v.as_str())
        .map(str::trim)
    {
        Some(s) if s.eq_ignore_ascii_case("fail") => OnStale::Fail,
        _ => OnStale::Annotate,
    };
    Some(FreshnessPolicy {
        requirements,
        on_stale,
    })
}

/// Build the [`STALENESS`] payload for a policy given each key's resolved
/// age in hours (`None` = the key is ABSENT from the actor's memory).
///
/// An absent key counts as STALE: "no data" is not "fresh data", and the
/// fail-closed reading is the trustworthy one for a report the user will act
/// on. Returns `(payload, any_stale)`.
#[must_use]
pub fn build_staleness_report<S: std::hash::BuildHasher>(
    policy: &FreshnessPolicy,
    ages_hours: &std::collections::HashMap<String, Option<f64>, S>,
) -> (serde_json::Value, bool) {
    let mut any_stale = false;
    let entries: Vec<serde_json::Value> = policy
        .requirements
        .iter()
        .map(|(key, max_age)| {
            let age = ages_hours.get(key).copied().flatten();
            let (present, stale) = match age {
                Some(a) => (true, a > *max_age),
                None => (false, true),
            };
            if stale {
                any_stale = true;
            }
            serde_json::json!({
                "key": key,
                "age_hours": age,
                "max_age_hours": max_age,
                "present": present,
                "stale": stale,
            })
        })
        .collect();
    (
        serde_json::json!({ "verified": true, "any_stale": any_stale, "entries": entries }),
        any_stale,
    )
}

/// The report injected when freshness could NOT be determined — no
/// [`crate::MemoryFreshnessResolver`] wired, or the store declined the lookup.
///
/// `verified: false` is deliberately explicit: the alternative (injecting
/// nothing, or an empty all-fresh report) would let a node believe its inputs
/// were checked when they weren't — reintroducing the silent-wrong this whole
/// mechanism exists to remove. A violation cannot be asserted either, so
/// `any_stale` is `false` and an `on_stale: "fail"` node does NOT fail on an
/// unverifiable check: a transient store blip must not take down a pipeline
/// (freshness is a trust signal, not a security boundary).
#[must_use]
pub fn unverified_staleness_report(reason: &str) -> serde_json::Value {
    serde_json::json!({
        "verified": false,
        "any_stale": false,
        "reason": reason,
        "entries": [],
    })
}

/// Human-readable one-line summary of a stale set, for a node failure
/// message or a rendered warning banner.
#[must_use]
pub fn describe_stale_entries(report: &serde_json::Value) -> String {
    let Some(entries) = report.get("entries").and_then(|e| e.as_array()) else {
        return String::new();
    };
    let parts: Vec<String> = entries
        .iter()
        .filter(|e| {
            e.get("stale")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
        })
        .map(|e| {
            let key = e.get("key").and_then(|v| v.as_str()).unwrap_or("?");
            match e.get("age_hours").and_then(serde_json::Value::as_f64) {
                Some(a) => format!("{key} is {a:.1}h old"),
                None => format!("{key} is missing"),
            }
        })
        .collect();
    parts.join("; ")
}

/// Per-node graph-json field: does this node consume the injected
/// [`ACTOR_CONTEXT`]? Defaults to `true` (see
/// [`node_needs_memory_from_config`]) so the field is fully
/// backward-compatible — an author or a Phase-2 pass opts a node OUT by
/// setting `needs_memory: false` in its `data`.
pub const NEEDS_MEMORY: &str = "needs_memory";

/// Read a node's `needs_memory` flag from its `data`/config object,
/// defaulting to `true` when absent, non-boolean, or the node has no
/// config. Keeping the default `true` means an existing graph (which has
/// no such field) behaves exactly as before — every node is treated as a
/// memory consumer.
pub fn node_needs_memory_from_config(config: Option<&serde_json::Value>) -> bool {
    explicit_needs_memory(config).unwrap_or(true)
}

/// Read ONLY an EXPLICIT `needs_memory` boolean from a node's `data`/config
/// object — `Some(true)`/`Some(false)` when the field is present and boolean,
/// `None` when absent, non-boolean, or the node has no config.
///
/// This separates "the author said X" from "the default." The engine composes
/// the `None` case with a capability-world-aware default
/// (`talos_capability_world::world_defaults_no_memory`) so pure-egress/send
/// nodes don't receive injected memory unless opted in, while an explicit flag
/// always wins — see `ParallelWorkflowEngine::node_needs_memory_for_world`.
pub fn explicit_needs_memory(config: Option<&serde_json::Value>) -> Option<bool> {
    config
        .and_then(|c| c.get(NEEDS_MEMORY))
        .and_then(serde_json::Value::as_bool)
}

/// Decide whether the engine should inject [`ACTOR_CONTEXT`] into a node's
/// input.
///
/// * `smart_enabled` = `talos_config::smart_memory_context_enabled()`.
/// * `node_needs_memory` = [`node_needs_memory_from_config`] for the node.
///
/// When smart-context is OFF this ALWAYS returns `true` — injection is
/// byte-identical to the legacy "inject into every node" behaviour,
/// ignoring `needs_memory` entirely. When ON, injection is scoped to
/// nodes that declare they consume memory.
pub fn should_inject_actor_context(smart_enabled: bool, node_needs_memory: bool) -> bool {
    !smart_enabled || node_needs_memory
}

/// Output-side hook: parser/triage modules write normalized operational
/// alerts under this key (`{"alerts": [...]}` — or a single alert object)
/// and the controller's node hook persists them into the `ops_alerts`
/// store with tenancy derived from the execution's bound actor. Sibling
/// of [`MEMORY_WRITE`]; same opt-in, fire-on-completion semantics.
pub const OPS_ALERT: &str = "__ops_alert__";

// ── Judge sub-workflow output ───────────────────────────────────────

/// Numeric score the judge returned (0.0..1.0 typical, impl-defined).
pub const JUDGE_SCORE: &str = "__judge_score__";

/// Boolean pass/fail the judge returned.
pub const JUDGE_PASSED: &str = "__judge_passed__";

/// Free-form reasoning the judge returned.
pub const JUDGE_REASONING: &str = "__judge_reasoning__";

/// Free-form feedback the judge returned.
pub const JUDGE_FEEDBACK: &str = "__judge_feedback__";

/// The judge declared that this run had NOTHING TO JUDGE (a quiet inbox,
/// an empty batch). Such a run is excluded from the quality trend rather
/// than counted as a pass or a failure — "nothing to measure" is not
/// evidence of quality, exactly as it is not evidence of failure.
///
/// This affects RECORDING only, never routing: `passed` continues to
/// drive gates exactly as authored, so an abstaining judge should also
/// set `passed` to whatever it wants downstream edges to do.
pub const JUDGE_NOT_APPLICABLE: &str = "__judge_not_applicable__";

// ── Confidence gate output ──────────────────────────────────────────

/// Default path into a parent output where a confidence value is
/// looked up when the node config omits an explicit path.
pub const CONFIDENCE_DEFAULT: &str = "__confidence__";

/// Confidence value the gate observed.
pub const CONFIDENCE_USED: &str = "__confidence_used__";

/// Written by the confidence gate when the confidence passed the
/// threshold.
pub const CONFIDENCE_GATE_PASSED: &str = "__confidence_gate_passed__";

/// Written by the confidence gate when the confidence fell below
/// threshold.
pub const CONFIDENCE_GATE_FAILED: &str = "__confidence_gate_failed__";

/// Written by the confidence gate when a human approver approved a
/// low-confidence result.
pub const CONFIDENCE_GATE_APPROVED: &str = "__confidence_gate_approved__";

/// Written when the gate is paused waiting for an approval decision.
pub const WAITING: &str = "__waiting__";

// ── Ensemble ────────────────────────────────────────────────────────

/// Consensus method the ensemble used (e.g. `"majority_vote"`).
pub const ENSEMBLE_METHOD: &str = "__ensemble_method__";

/// Number of children the ensemble dispatched.
pub const ENSEMBLE_SIZE: &str = "__ensemble_size__";

// ── LLM dispatch ────────────────────────────────────────────────────

/// Class label the classifier returned when no matching route was
/// configured, so the engine fell back.
pub const UNMATCHED_CLASS: &str = "__unmatched_class__";

/// Class label the engine dispatched on.
pub const DISPATCHED_CLASS: &str = "__dispatched_class__";

/// Workflow id the engine dispatched to.
pub const DISPATCHED_WORKFLOW_ID: &str = "__dispatched_workflow_id__";

// ── Verify ──────────────────────────────────────────────────────────

/// Boolean — did the `Verify` check pass?
pub const VERIFIED: &str = "__verified__";

/// Label identifying the verification check that ran.
pub const CHECK_LABEL: &str = "__check_label__";

/// Human-readable reason the verification failed.
pub const VERIFICATION_FAILED: &str = "__verification_failed__";

/// The expression that was evaluated (copied onto the failure output
/// so consumers don't need to re-resolve it).
pub const VERIFICATION_CONDITION: &str = "__verification_condition__";

// ── Reflective retry ────────────────────────────────────────────────

/// Number of attempts the reflective-retry node made before returning.
pub const REFLECTIVE_RETRY_ATTEMPTS: &str = "__reflective_retry_attempts__";

// ── Agent / ReAct loops ─────────────────────────────────────────────

/// Accumulator list written by loop nodes that concatenate
/// per-iteration outputs (synthesize / collect flavour).
pub const ACCUMULATED: &str = "__accumulated__";

/// Sliding-window history the agent loop injects on the next
/// iteration's input. Tuple-list of `(iteration, output)` values.
pub const AGENT_HISTORY: &str = "__agent_history__";

/// Index of the current iteration inside an agent / `ReAct` loop.
pub const AGENT_ITERATION: &str = "__agent_iteration__";

/// Flag written by the loop body signalling "continue iterating"
/// (the loop reads this to decide whether to halt early).
pub const CONTINUED: &str = "__continued";

// ── Dispatch routing outputs ────────────────────────────────────────

/// Label identifying which dispatch-kind routed this node
/// (e.g. `"capability_dispatch"`, `"dynamic_dispatch"`).
pub const DISPATCHED_BY: &str = "__dispatched_by";

/// Human-readable name of the workflow that was dispatched to.
pub const DISPATCHED_WORKFLOW_NAME: &str = "__dispatched_workflow_name";

/// Capability labels that matched for a capability-dispatch target.
pub const MATCHED_CAPABILITIES: &str = "__matched_capabilities";

// ── Loop primitives ─────────────────────────────────────────────────

/// Input captured at the start of a loop iteration so the body can
/// reference the parent input regardless of intermediate writes.
pub const LOOP_INPUT: &str = "__loop_input";

/// Index of the current loop iteration. Zero-based.
pub const LOOP_ITERATION: &str = "__loop_iteration";

// ── Trigger context ─────────────────────────────────────────────────

/// Original input payload that triggered this workflow execution —
/// injected onto the synthetic trigger node so downstream branches
/// can read the trigger payload even after intermediate transforms.
pub const TRIGGER_INPUT: &str = "__trigger_input__";

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn needs_memory_defaults_true_when_absent() {
        assert!(node_needs_memory_from_config(None));
        assert!(node_needs_memory_from_config(Some(&json!({}))));
        assert!(node_needs_memory_from_config(Some(&json!({ "other": 1 }))));
        // Non-boolean value → default true (don't silently drop context).
        assert!(node_needs_memory_from_config(Some(
            &json!({ "needs_memory": "no" })
        )));
    }

    #[test]
    fn needs_memory_honours_explicit_flag() {
        assert!(node_needs_memory_from_config(Some(
            &json!({ "needs_memory": true })
        )));
        assert!(!node_needs_memory_from_config(Some(
            &json!({ "needs_memory": false })
        )));
    }

    #[test]
    fn explicit_needs_memory_distinguishes_absent_from_false() {
        // Present + boolean → Some(bool). Everything else → None (the engine
        // then applies the world-aware default).
        assert_eq!(
            explicit_needs_memory(Some(&json!({ "needs_memory": true }))),
            Some(true)
        );
        assert_eq!(
            explicit_needs_memory(Some(&json!({ "needs_memory": false }))),
            Some(false)
        );
        assert_eq!(explicit_needs_memory(None), None);
        assert_eq!(explicit_needs_memory(Some(&json!({}))), None);
        assert_eq!(explicit_needs_memory(Some(&json!({ "other": 1 }))), None);
        // Non-boolean value is NOT an explicit opt-in/out → None (default path).
        assert_eq!(
            explicit_needs_memory(Some(&json!({ "needs_memory": "yes" }))),
            None
        );
    }

    #[test]
    fn idempotency_key_resolution() {
        let ex = uuid::Uuid::nil();
        let node = uuid::Uuid::from_u128(1);
        let derived = format!("{ex}:{node}");
        let r = |v: serde_json::Value| {
            resolve_idempotency_key(Some(&json!({ IDEMPOTENCY_KEY: v })), &ex, &node)
        };
        // Literal string → used verbatim (trimmed).
        assert_eq!(r(json!("order-42")).as_deref(), Some("order-42"));
        assert_eq!(r(json!("  order-42  ")).as_deref(), Some("order-42"));
        // Auto sentinels → engine-derived stable key.
        assert_eq!(r(json!(true)).as_deref(), Some(derived.as_str()));
        assert_eq!(r(json!("auto")).as_deref(), Some(derived.as_str()));
        assert_eq!(r(json!("TRUE")).as_deref(), Some(derived.as_str()));
        // Not declared / opted out → None.
        assert_eq!(r(json!(false)), None);
        assert_eq!(r(json!("")), None);
        assert_eq!(r(json!(null)), None);
        assert_eq!(r(json!(123)), None);
        // Absent key / no config → None.
        assert_eq!(
            resolve_idempotency_key(Some(&json!({ "other": 1 })), &ex, &node),
            None
        );
        assert_eq!(resolve_idempotency_key(None, &ex, &node), None);
    }

    #[test]
    fn inject_gate_off_always_injects() {
        // Flag OFF → inject regardless of needs_memory (byte-identical).
        assert!(should_inject_actor_context(false, true));
        assert!(should_inject_actor_context(false, false));
    }

    #[test]
    fn inject_gate_on_respects_needs_memory() {
        assert!(should_inject_actor_context(true, true));
        assert!(!should_inject_actor_context(true, false));
    }

    #[test]
    fn freshness_policy_absent_or_empty_is_none() {
        assert_eq!(resolve_freshness_policy(None), None);
        assert_eq!(resolve_freshness_policy(Some(&json!({}))), None);
        assert_eq!(
            resolve_freshness_policy(Some(&json!({ "requires_fresh": {} }))),
            None
        );
        // Non-object value → no contract.
        assert_eq!(
            resolve_freshness_policy(Some(&json!({ "requires_fresh": "6h" }))),
            None
        );
        // Non-positive / non-numeric bounds are skipped; all-skipped → None.
        assert_eq!(
            resolve_freshness_policy(Some(
                &json!({ "requires_fresh": {"a": 0, "b": -3, "c": "x"} })
            )),
            None
        );
    }

    #[test]
    fn freshness_policy_parses_keys_and_mode() {
        let p = resolve_freshness_policy(Some(&json!({
            "requires_fresh": { "daily_brief/latest": 6 },
            "on_stale": "fail"
        })))
        .expect("policy");
        assert_eq!(
            p.requirements,
            vec![("daily_brief/latest".to_string(), 6.0)]
        );
        assert_eq!(p.on_stale, OnStale::Fail);

        // Default mode is Annotate; case/whitespace tolerated on "fail".
        let d = resolve_freshness_policy(Some(&json!({ "requires_fresh": {"k": 1} }))).unwrap();
        assert_eq!(d.on_stale, OnStale::Annotate);
        let f = resolve_freshness_policy(Some(&json!({
            "requires_fresh": {"k": 1}, "on_stale": "  FAIL "
        })))
        .unwrap();
        assert_eq!(f.on_stale, OnStale::Fail);
        // Unknown mode falls back to the safe, non-breaking default.
        let u = resolve_freshness_policy(Some(&json!({
            "requires_fresh": {"k": 1}, "on_stale": "explode"
        })))
        .unwrap();
        assert_eq!(u.on_stale, OnStale::Annotate);
    }

    #[test]
    fn staleness_report_flags_old_and_missing_keys() {
        let policy = FreshnessPolicy {
            requirements: vec![
                ("fresh_key".to_string(), 6.0),
                ("old_key".to_string(), 6.0),
                ("absent_key".to_string(), 6.0),
            ],
            on_stale: OnStale::Annotate,
        };
        let mut ages = std::collections::HashMap::new();
        ages.insert("fresh_key".to_string(), Some(1.5));
        ages.insert("old_key".to_string(), Some(32.1));
        ages.insert("absent_key".to_string(), None);

        let (report, any_stale) = build_staleness_report(&policy, &ages);
        assert!(any_stale);
        let entries = report["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 3);
        // fresh
        assert_eq!(entries[0]["stale"], json!(false));
        assert_eq!(entries[0]["present"], json!(true));
        // too old
        assert_eq!(entries[1]["stale"], json!(true));
        assert_eq!(entries[1]["age_hours"], json!(32.1));
        // absent counts as stale, and is marked not-present
        assert_eq!(entries[2]["stale"], json!(true));
        assert_eq!(entries[2]["present"], json!(false));
        assert_eq!(entries[2]["age_hours"], json!(null));
        assert_eq!(report["any_stale"], json!(true));
    }

    #[test]
    fn staleness_report_all_fresh_is_not_stale() {
        let policy = FreshnessPolicy {
            requirements: vec![("k".to_string(), 6.0)],
            on_stale: OnStale::Annotate,
        };
        let mut ages = std::collections::HashMap::new();
        ages.insert("k".to_string(), Some(5.9));
        let (report, any_stale) = build_staleness_report(&policy, &ages);
        assert!(!any_stale);
        assert_eq!(report["any_stale"], json!(false));
        // Boundary: exactly at the bound is NOT stale (age > max is stale).
        let mut at_bound = std::collections::HashMap::new();
        at_bound.insert("k".to_string(), Some(6.0));
        let (_, stale_at_bound) = build_staleness_report(&policy, &at_bound);
        assert!(!stale_at_bound);
    }

    #[test]
    fn describe_stale_entries_summarizes_only_stale() {
        let policy = FreshnessPolicy {
            requirements: vec![
                ("ok".to_string(), 6.0),
                ("old".to_string(), 6.0),
                ("gone".to_string(), 6.0),
            ],
            on_stale: OnStale::Fail,
        };
        let mut ages = std::collections::HashMap::new();
        ages.insert("ok".to_string(), Some(1.0));
        ages.insert("old".to_string(), Some(32.14));
        ages.insert("gone".to_string(), None);
        let (report, _) = build_staleness_report(&policy, &ages);
        let desc = describe_stale_entries(&report);
        assert!(desc.contains("old is 32.1h old"), "got: {desc}");
        assert!(desc.contains("gone is missing"), "got: {desc}");
        assert!(!desc.contains("ok is"), "fresh key must not appear: {desc}");
        // Malformed input yields an empty summary rather than panicking.
        assert_eq!(describe_stale_entries(&json!({})), "");
    }

    #[test]
    fn reports_carry_explicit_verified_flag() {
        let policy = FreshnessPolicy {
            requirements: vec![("k".to_string(), 6.0)],
            on_stale: OnStale::Annotate,
        };
        let mut ages = std::collections::HashMap::new();
        ages.insert("k".to_string(), Some(1.0));
        let (verified, _) = build_staleness_report(&policy, &ages);
        assert_eq!(verified["verified"], json!(true));

        // Unverifiable: explicitly flagged, asserts NO staleness (so an
        // on_stale=fail node is not tripped by a store blip), carries a reason.
        let u = unverified_staleness_report("no resolver wired");
        assert_eq!(u["verified"], json!(false));
        assert_eq!(u["any_stale"], json!(false));
        assert_eq!(u["reason"], json!("no resolver wired"));
        assert_eq!(u["entries"].as_array().unwrap().len(), 0);
        // describe over an unverified report is empty, not a panic.
        assert_eq!(describe_stale_entries(&u), "");
    }

    // ---- __error polarity (classify_error_flag / output_reports_error) ----
    //
    // These drive the PRODUCTION classifier. The rule under test is that
    // only a falsy-or-empty marker means success; a present-but-mis-shaped
    // marker must read as a FAILURE, because it used to read as success
    // (`.as_bool().unwrap_or(false)`) on paths that decide execution
    // status, node_completed vs node_failed events, ensemble consensus,
    // loop termination reason and the sub-workflow contract test.

    #[test]
    fn error_flag_absent_or_falsy_is_not_an_error() {
        // The four shapes that legitimately mean "this node did not fail".
        assert_eq!(classify_error_flag(None), ErrorFlag::NoError);
        assert_eq!(
            classify_error_flag(Some(&serde_json::Value::Null)),
            ErrorFlag::NoError,
            "{{\"error\": null}} is the success envelope database-query-style \
             templates emit; presence alone must not mean failure"
        );
        assert_eq!(
            classify_error_flag(Some(&serde_json::json!(false))),
            ErrorFlag::NoError
        );
        assert_eq!(
            classify_error_flag(Some(&serde_json::json!(""))),
            ErrorFlag::NoError,
            "an empty error message carries no error"
        );
    }

    #[test]
    fn error_flag_bool_true_is_an_error_with_rendered_message() {
        // The shape every engine writer emits. Behaviour here must be
        // byte-identical to the pre-fix `.as_bool().unwrap_or(false)`.
        assert_eq!(
            classify_error_flag(Some(&serde_json::json!(true))),
            ErrorFlag::Failed {
                message: "true".to_string()
            }
        );
    }

    #[test]
    fn error_flag_non_empty_string_is_an_error_carrying_it_verbatim() {
        // THE DEFECT: a module reporting `{"__error": "upstream 502"}` read
        // as a clean run under `.as_bool()`, because as_bool() on a string
        // is None.
        assert_eq!(
            classify_error_flag(Some(&serde_json::json!("upstream 502"))),
            ErrorFlag::Failed {
                message: "upstream 502".to_string()
            }
        );
    }

    #[test]
    fn error_flag_any_other_shape_is_an_error() {
        // Numbers, arrays and objects are all mis-shaped markers, and a
        // mis-shaped marker must never be the benign answer. Rendered as
        // compact JSON so an operator sees what was actually there.
        for v in [
            serde_json::json!(500),
            serde_json::json!(0),
            serde_json::json!(["boom"]),
            serde_json::json!({"code": 500}),
        ] {
            let got = classify_error_flag(Some(&v));
            assert!(
                got.is_failed(),
                "a mis-shaped __error must read as failed, got {got:?} for {v}"
            );
        }
        assert_eq!(
            classify_error_flag(Some(&serde_json::json!({"code": 500}))),
            ErrorFlag::Failed {
                message: "{\"code\":500}".to_string()
            }
        );
    }

    #[test]
    fn output_reports_error_reads_the_error_flag_key_off_an_object() {
        assert!(!output_reports_error(&serde_json::json!({"ok": 1})));
        assert!(!output_reports_error(
            &serde_json::json!({ERROR_FLAG: false})
        ));
        assert!(output_reports_error(&serde_json::json!({ERROR_FLAG: true})));
        assert!(
            output_reports_error(&serde_json::json!({ERROR_FLAG: "boom"})),
            "the string form is the one that used to pass as success"
        );
    }

    #[test]
    fn output_reports_error_on_a_non_object_is_not_an_error() {
        // A bare string / array / number node output has no marker to
        // read; `Value::get` returns None. Matches how every caller
        // behaved before the classifier existed.
        for v in [
            serde_json::json!("just a string"),
            serde_json::json!([1, 2, 3]),
            serde_json::json!(7),
            serde_json::Value::Null,
        ] {
            assert!(!output_reports_error(&v), "non-object output: {v}");
        }
    }

    // ── error_reason ────────────────────────────────────────────────

    #[test]
    fn error_reason_is_none_when_the_output_reports_no_error() {
        for v in [
            json!({}),
            json!({ "__error": false }),
            json!({ "__error": null }),
            json!({ "__error": "" }),
            // An `error_message` with no failing marker is not a failure:
            // presence of the field is not the test, the marker is.
            json!({ "error_message": "stale field" }),
            json!("a bare string output"),
        ] {
            assert_eq!(error_reason(&v), None, "not a failure: {v}");
        }
    }

    #[test]
    fn error_reason_prefers_the_explicit_error_message_field() {
        assert_eq!(
            error_reason(&json!({ "__error": true, "error_message": "child 404" })),
            Some("child 404".to_string())
        );
        // …and prefers it over the marker's own text when both carry one.
        assert_eq!(
            error_reason(&json!({ "__error": "marker text", "error_message": "field text" })),
            Some("field text".to_string())
        );
    }

    #[test]
    fn error_reason_falls_back_to_a_string_marker() {
        // The #733 shape: the reason is IN the marker and there is no
        // `error_message` field to read it from.
        assert_eq!(
            error_reason(&json!({ "__error": "upstream 502" })),
            Some("upstream 502".to_string())
        );
    }

    #[test]
    fn error_reason_never_renders_a_boolean_marker_as_a_reason() {
        // `"true"` in a field an operator reads as the failure reason is
        // worse than the caller's own fallback wording.
        assert_eq!(error_reason(&json!({ "__error": true })), None);
        assert_eq!(
            error_reason(&json!({ "__error": true, "error_message": "" })),
            None,
            "an empty error_message must not be preferred over nothing"
        );
        assert_eq!(
            error_reason(&json!({ "__error": true, "error_message": "   " })),
            None,
            "whitespace is not a reason"
        );
    }

    #[test]
    fn error_reason_renders_a_non_string_non_bool_marker() {
        // Numbers / arrays / objects all classify as failures, so each has
        // to render as SOMETHING rather than silently becoming the generic
        // fallback — the marker is all the detail that exists.
        assert_eq!(error_reason(&json!({ "__error": 502 })), Some("502".into()));
        assert_eq!(
            error_reason(&json!({ "__error": {"code": 7} })),
            Some("{\"code\":7}".into())
        );
    }

    #[test]
    fn error_reason_agrees_with_output_reports_error() {
        // The two must never disagree about WHETHER an output failed —
        // `error_reason` returning `Some` is the strictly stronger claim.
        for v in [
            json!({}),
            json!({ "__error": false }),
            json!({ "__error": true }),
            json!({ "__error": "boom" }),
            json!({ "__error": true, "error_message": "boom" }),
            json!({ "__error": 0 }),
        ] {
            if error_reason(&v).is_some() {
                assert!(output_reports_error(&v), "reason without a failure: {v}");
            }
        }
    }
}
