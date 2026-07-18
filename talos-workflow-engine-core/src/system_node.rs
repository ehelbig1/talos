//! Built-in node taxonomy and fan-in join modes.

#[cfg(feature = "llm-primitives")]
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Built-in system node kinds that receive special handling by the
/// executor, distinct from user-supplied module nodes.
///
/// # Choosing a variant
///
/// Most workflows reach for fewer than half of the variants. Group by
/// intent first, then narrow:
///
/// | Group | Variants | Use when |
/// |---|---|---|
/// | **Iteration** | [`Loop`], [`WhileLoop`], [`RepeatLoop`] | You need to repeat a body with a condition or fixed count. |
/// | **Coordination** | [`FanIn`], [`Collect`], [`Synthesize`] | Multiple branches converge and you need to join, gather, or transform their outputs. |
/// | **Control flow** | [`Wait`], [`Verify`], [`ErrorHandler`] | You need to pause for input, assert a condition, or branch on an upstream error. |
/// | **Sub-workflow** | [`SubWorkflow`] | Compose another workflow as a node. |
/// | **Runtime dispatch** | [`DynamicDispatch`], [`CapabilityDispatch`] | The target workflow / worker is chosen at runtime by an expression or capability set. |
///
#[cfg_attr(
    feature = "llm-primitives",
    doc = "The `llm-primitives` feature (default on) adds:\n\
           \n\
           | Group | Variants | Use when |\n\
           |---|---|---|\n\
           | **LLM judging** | [`Judge`], [`InlineJudge`], [`Ensemble`], [`ConfidenceGate`] | You're scoring or gating LLM output and need verdict / consensus / confidence semantics. Reach for `InlineJudge` when the rubric is a one-line scoring expression; promote to `Judge` once it grows its own prompt / model call. |\n\
           | **LLM agent loops** | [`AgentLoop`], [`ReActLoop`], [`ReflectiveRetry`] | You're running a tool-using agent body with iteration / retry on failure. |\n\
           | **LLM dispatch** | [`LlmDispatch`] | A classifier picks which downstream workflow handles the input. |\n"
)]
#[cfg_attr(
    not(feature = "llm-primitives"),
    doc = "An additional 8 LLM/agent-flavored variants — `Judge`, `InlineJudge`, \
           `Ensemble`, `ConfidenceGate`, `AgentLoop`, `ReActLoop`, \
           `ReflectiveRetry`, `LlmDispatch` — are gated behind the `llm-primitives` \
           feature (default on). They are absent from this enum when the feature \
           is disabled; the engine rejects equivalent JSON kinds at parse time."
)]
///
/// # Stability
///
/// Consumers that need a kind not listed here should extend the
/// executor's dispatcher registry rather than forking this enum. The
/// variants below reflect a practical production set drawn from real
/// workloads and are likely to be useful to other adopters; the list
/// may grow over time but existing variants will not silently change
/// shape.
///
/// `PartialEq` is derived but not `Eq`/`Hash`: two variants carry `f64`
/// thresholds, and `f64` is not totally ordered. Consumers that need a
/// hashable discriminator should project onto a dedicated `&'static str`
/// tag instead of hashing the whole value.
///
/// [`Loop`]: SystemNodeKind::Loop
/// [`WhileLoop`]: SystemNodeKind::WhileLoop
/// [`RepeatLoop`]: SystemNodeKind::RepeatLoop
/// [`FanIn`]: SystemNodeKind::FanIn
/// [`Collect`]: SystemNodeKind::Collect
/// [`Synthesize`]: SystemNodeKind::Synthesize
/// [`Wait`]: SystemNodeKind::Wait
/// [`Verify`]: SystemNodeKind::Verify
/// [`ErrorHandler`]: SystemNodeKind::ErrorHandler
/// [`SubWorkflow`]: SystemNodeKind::SubWorkflow
/// [`DynamicDispatch`]: SystemNodeKind::DynamicDispatch
/// [`CapabilityDispatch`]: SystemNodeKind::CapabilityDispatch
#[cfg_attr(
    feature = "llm-primitives",
    doc = "\n[`Judge`]: SystemNodeKind::Judge\n\
           [`InlineJudge`]: SystemNodeKind::InlineJudge\n\
           [`Ensemble`]: SystemNodeKind::Ensemble\n\
           [`ConfidenceGate`]: SystemNodeKind::ConfidenceGate\n\
           [`AgentLoop`]: SystemNodeKind::AgentLoop\n\
           [`ReActLoop`]: SystemNodeKind::ReActLoop\n\
           [`ReflectiveRetry`]: SystemNodeKind::ReflectiveRetry\n\
           [`LlmDispatch`]: SystemNodeKind::LlmDispatch"
)]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
// NOT marked `#[non_exhaustive]` — the dispatcher_coverage tripwire
// pattern relies on exhaustive cross-crate matches to fail at compile
// time when a new variant is added but a dispatcher / handler isn't
// updated. Adding new variants is therefore a (minor-bump) breaking
// change documented in RELEASING.md; downstream consumers must update
// their match arms when they bump their dep on this crate.
pub enum SystemNodeKind {
    /// Pause execution until resumed externally.
    Wait {
        /// Optional human-readable message surfaced to the resumer.
        message: Option<String>,
    },
    /// Execute the body while a condition holds, up to `max_iterations`.
    WhileLoop {
        /// Expression evaluated before each iteration.
        condition: String,
        /// Hard safety cap on iteration count.
        max_iterations: u32,
    },
    /// Execute the body a fixed number of times.
    RepeatLoop {
        /// Number of iterations.
        count: u32,
    },
    /// Handle an error from upstream, optionally matching a pattern.
    ErrorHandler {
        /// Optional regex or substring the error must match to trigger.
        error_pattern: Option<String>,
    },
    /// Synchronize multiple inbound branches.
    FanIn {
        /// How many branches must complete before the join releases.
        join_mode: JoinMode,
        /// Optional expression aggregating the branch outputs.
        aggregation_expr: Option<String>,
    },
    /// Invoke another workflow by id and return its collapsed output.
    SubWorkflow {
        /// Target workflow id.
        workflow_id: Uuid,
        /// Hard timeout for the sub-workflow in seconds.
        timeout_secs: u64,
    },
    /// General loop node combining a condition with an iteration cap.
    Loop {
        /// Hard safety cap on iteration count.
        max_iterations: u32,
        /// Expression evaluated before each iteration.
        condition: String,
    },
    /// Collect branch outputs without otherwise transforming them.
    Collect,
    /// Controller-side read of the ops-alerts triage store: digest
    /// counts over the active set plus the top-N active alerts. Output
    /// flows downstream as ordinary graph data (feeds daily-brief
    /// compose nodes). Executes via the injected
    /// [`crate::OpsAlertsReader`] — no worker dispatch, no secrets.
    OpsAlertsDigest {
        /// How many active alerts to include verbatim (clamped 1..=25).
        top_limit: u32,
    },
    /// Synthesize a value from prior outputs, optionally via expression.
    Synthesize {
        /// Optional expression building the synthesized value.
        synthesis_expr: Option<String>,
    },
    /// Assert a condition; branch on failure.
    Verify {
        /// Expression that must evaluate to `true`.
        condition: String,
        /// Optional label identifying the check in output.
        check_label: Option<String>,
        /// Handle name to route down when the check fails.
        on_failure: String,
    },
    /// ReAct-style agent loop running a body workflow with sliding-window
    /// history injection.
    ///
    /// Gated behind the `llm-primitives` feature (on by default).
    #[cfg(feature = "llm-primitives")]
    AgentLoop {
        /// Workflow id of the per-iteration body.
        body_workflow_id: Uuid,
        /// Hard safety cap on iteration count.
        max_iterations: u32,
        /// If `true`, inject prior iteration outputs as history.
        inject_history: bool,
        /// Hard timeout for each body invocation in seconds.
        timeout_secs: u64,
    },
    /// Run a judge workflow and parse its verdict.
    ///
    /// Gated behind the `llm-primitives` feature (on by default).
    #[cfg(feature = "llm-primitives")]
    Judge {
        /// Workflow id of the judge.
        judge_workflow_id: Uuid,
        /// Rubric prompt or description passed to the judge.
        rubric: String,
        /// Optional score threshold the verdict must meet to pass.
        pass_threshold: Option<f64>,
        /// Behavior on verdict rejection. `"error"` (default) emits
        /// an `__error: true` envelope that fails the node unless
        /// `continue_on_error` is set. `"passthrough"` forwards the
        /// parent output enriched with `__judge_passed__: false`
        /// (plus score / reasoning / feedback) so downstream edges
        /// can conditional-route without tripping the error path.
        /// Mirrors the `on_failure` field on
        /// [`SystemNodeKind::Verify`].
        on_failure: String,
        /// Hard timeout for the judge invocation in seconds.
        timeout_secs: u64,
    },

    /// Inline-expression judge: evaluate `verdict_expr` against the
    /// parent's gathered inputs and parse the result as a verdict
    /// (same `{score, passed, reasoning, feedback}` shape as
    /// [`Judge`](Self::Judge)). Use when the verdict is a one-line
    /// scoring function — no sub-workflow, no LLM round-trip, no
    /// `graph_store` lookup. Heavier judges with their own prompts /
    /// model calls / branching belong in [`Judge`](Self::Judge).
    ///
    /// Gated behind the `llm-primitives` feature (on by default).
    #[cfg(feature = "llm-primitives")]
    InlineJudge {
        /// Expression returning a JSON object with the verdict shape.
        /// Evaluated against the gathered parent inputs by the
        /// configured `ExpressionEvaluator`.
        verdict_expr: String,
        /// Optional score threshold the verdict must meet to pass.
        pass_threshold: Option<f64>,
        /// Behavior on verdict rejection. See
        /// [`Judge::on_failure`](Self::Judge) — same contract.
        on_failure: String,
    },
    /// Run N copies of a child workflow and consolidate their outputs.
    ///
    /// Gated behind the `llm-primitives` feature (on by default).
    #[cfg(feature = "llm-primitives")]
    Ensemble {
        /// Workflow id of the child to replicate.
        child_workflow_id: Uuid,
        /// Number of child invocations.
        count: u32,
        /// Consensus strategy label (executor-defined).
        consensus: String,
        /// Optional judge used to score candidates.
        judge_workflow_id: Option<Uuid>,
        /// Hard timeout for each child invocation in seconds.
        timeout_secs: u64,
    },
    /// Branch when a confidence signal falls below a threshold.
    ///
    /// Gated behind the `llm-primitives` feature (on by default).
    #[cfg(feature = "llm-primitives")]
    ConfidenceGate {
        /// Minimum confidence required to take the pass path.
        threshold: f64,
        /// Path into the parent output locating the confidence value.
        confidence_path: String,
        /// Handle name to route down when confidence is below threshold.
        on_low_confidence: String,
    },
    /// Dispatch to a target chosen at runtime by an expression.
    DynamicDispatch {
        /// Expression that resolves to a dispatch target.
        dispatch_expression: String,
        /// Hard timeout for the dispatched target in seconds.
        timeout_secs: u64,
    },
    /// Dispatch to any worker that advertises the required capabilities.
    CapabilityDispatch {
        /// Capability labels the target must all advertise.
        required_capabilities: Vec<String>,
        /// Optional fallback workflow id dispatched when
        /// [`crate::WorkflowGraphStore::resolve_by_capabilities`]
        /// returns `None`. Without this, an unmatched capability
        /// dispatch fails hard.
        fallback_workflow_id: Option<Uuid>,
        /// Hard timeout for the dispatched target in seconds.
        timeout_secs: u64,
    },
    /// Alternative agent-loop shape (reasoning + acting) with history.
    ///
    /// Gated behind the `llm-primitives` feature (on by default).
    #[cfg(feature = "llm-primitives")]
    ReActLoop {
        /// Workflow id of the per-iteration body.
        body_workflow_id: Uuid,
        /// Hard safety cap on iteration count.
        max_iterations: u32,
        /// If `true`, inject prior iteration outputs as history.
        inject_history: bool,
        /// Hard timeout for each body invocation in seconds.
        timeout_secs: u64,
    },
    /// Run a child; on failure, run a reflection workflow and retry.
    ///
    /// Gated behind the `llm-primitives` feature (on by default).
    #[cfg(feature = "llm-primitives")]
    ReflectiveRetry {
        /// Workflow id of the primary child.
        child_workflow_id: Uuid,
        /// Workflow id of the reflection step producing feedback.
        reflection_workflow_id: Uuid,
        /// Maximum retries after the first failure.
        max_retries: u32,
        /// Hard timeout per attempt in seconds.
        timeout_secs: u64,
    },
    /// Dispatch to one of several routes based on an LLM classifier.
    ///
    /// Gated behind the `llm-primitives` feature (on by default).
    #[cfg(feature = "llm-primitives")]
    LlmDispatch {
        /// Workflow id of the classifier whose output selects the route.
        classifier_workflow_id: Uuid,
        /// Route name -> target workflow id.
        routes: HashMap<String, Uuid>,
        /// Optional fallback when no route matches.
        fallback_workflow_id: Option<Uuid>,
        /// Hard timeout for the dispatched route in seconds.
        timeout_secs: u64,
    },
}

/// Fan-in join semantics for [`SystemNodeKind::FanIn`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum JoinMode {
    /// Release only after every inbound branch completes.
    All,
    /// Release as soon as any inbound branch completes.
    Any,
    /// Release once a strict majority of inbound branches complete.
    Majority,
    /// Release once exactly `N` inbound branches complete.
    N(u32),
}
