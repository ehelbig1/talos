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
pub const ERROR_FLAG: &str = "__error";

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
}
