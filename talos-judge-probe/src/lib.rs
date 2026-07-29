//! Judge calibration probes — prove an inline judge CAN fail without
//! firing the real workflow.
//!
//! # The question this answers
//!
//! The operator digest flags a judge whose score never moves as
//! `saturated_pass` and tells the operator to "verify it in the FAILURE
//! direction before trusting the trend". Until this crate existed there was
//! no way to do that short of running the real workflow against live Gmail —
//! so the instruction was unactionable and the saturated judges stayed
//! unverified.
//!
//! [`JudgeProbeService::probe`] evaluates a graph's `inline_judge` node
//! against SYNTHETIC parent inputs and reports, per case, what the engine
//! would have done: the parsed verdict, the malformed-field count, the
//! effective pass after the threshold, and which of the three envelope
//! branches production would take.
//!
//! # Fidelity is the entire value
//!
//! A probe that disagrees with the engine is worse than no probe — it would
//! certify a judge as "can fail" on rules the engine no longer uses. So every
//! rule that matters is REUSED, never re-implemented:
//!
//! | rule | reused from |
//! |---|---|
//! | graph parse (node ids, labels, edges, `verdict_expr`/`pass_threshold`/`on_failure`) | [`ParallelWorkflowEngine::load_from_graph_json`] |
//! | scope binding + arity (single parent unwrapped, N parents label-keyed) + `unwrap_output` | [`ParallelWorkflowEngine::gather_inputs`] |
//! | expression evaluation + Rhai sandbox limits | [`talos_engine::rhai_helpers::evaluate_expression`] |
//! | verdict parse + `malformed_field_count` | [`JudgeVerdict::from_collapsed`] |
//! | pass / passthrough / error branch | [`talos_workflow_engine::build_judge_envelope`] |
//!
//! The only production step deliberately NOT replayed is
//! [`ParallelWorkflowEngine::dispatch_inline_judge`]'s `quality_gate` tracing
//! event: a probe is not a run, and emitting one would put synthetic verdicts
//! into the operator's own metrics. `probe_matches_dispatch_inline_judge`
//! (in this crate's tests) pins the resulting envelope byte-for-byte against
//! the real `dispatch_inline_judge`, so skipping the event cannot drift into
//! skipping anything else.
//!
//! # What a green probe does and does not prove
//!
//! It proves the EXPRESSION can reach a rejecting (or abstaining) verdict for
//! *some* input. It says nothing about whether production inputs ever look
//! like the synthetic ones — see [`SYNTHETIC_INPUT_NOTE`], which every
//! outcome carries.
//!
//! Two more ways a probe could be confidently wrong, both closed explicitly
//! rather than left to the reader:
//!
//! * A rejection is only counted toward [`ProbeSummary::can_fail`] when the
//!   RUBRIC produced it. An expression that fails to evaluate, or that returns
//!   something which is not a verdict at all (the commonest authoring mistake:
//!   writing the bare condition `covered >= total` as the whole
//!   `verdict_expr`), rejects EVERY input — reporting that as "this judge can
//!   fail" would certify a node that fails 100% of production runs. Those land
//!   in [`ProbeSummary::eval_errors`] and
//!   [`ProbeSummary::verdictless_rejections`] instead.
//! * A parent whose node label is `ctx` or `inputs` is bound and then
//!   OVERWRITTEN by the evaluator's own bindings, so it is unreachable from
//!   the expression. Such keys are reported as `shadowed_scope_keys` — see
//!   [`RESERVED_SCOPE_NAMES`] — because listing a variable as available when
//!   the engine has overwritten it is precisely the class of trap this tool
//!   exists to diagnose.
//!
//! # DLP
//!
//! Case inputs, the expression text, and verdict reasoning/feedback are
//! caller data that can carry interpolated secrets or email-derived content.
//! Nothing in this crate logs any of them: the outcome is returned to the
//! caller and echoed in the tool RESPONSE only. The one `tracing` call in the
//! service records ids and counts.
//!
//! [`ParallelWorkflowEngine::load_from_graph_json`]: talos_workflow_engine::ParallelWorkflowEngine::load_from_graph_json
//! [`ParallelWorkflowEngine::gather_inputs`]: talos_workflow_engine::ParallelWorkflowEngine::gather_inputs
//! [`ParallelWorkflowEngine::dispatch_inline_judge`]: talos_workflow_engine::ParallelWorkflowEngine::dispatch_inline_judge
//! [`JudgeVerdict::from_collapsed`]: talos_workflow_engine::JudgeVerdict::from_collapsed

use serde_json::{json, Map, Value as JsonValue};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use talos_workflow_engine::{build_judge_envelope, JudgeVerdict, ParallelWorkflowEngine};
use talos_workflow_engine_core::SystemNodeKind;

/// Hard cap on synthetic cases per probe. Each case is one Rhai evaluation
/// under the production 1000-operation ceiling, so the work is small — the
/// cap exists to bound the RESPONSE, which echoes every case's bound scope
/// and envelope back to the caller.
pub const MAX_CASES: usize = 20;

/// Scope names the evaluator binds ITSELF, after the parent keys.
///
/// `talos_engine::rhai_helpers::evaluate_expression` pushes every top-level
/// key of the bound input, then pushes `ctx` and `inputs` (both the whole
/// context). Rhai resolves a name to the LAST binding, so a parent whose node
/// label is one of these is unreachable from the expression — reading `ctx`
/// yields the context object, not that parent's output. Reported per case as
/// `shadowed_scope_keys` so the probe never lists a variable as available
/// when the engine has overwritten it.
pub const RESERVED_SCOPE_NAMES: [&str; 2] = ["ctx", "inputs"];

/// The honesty disclosure attached to every outcome.
///
/// A probe answers "can this expression reject anything?", which is a
/// property of the EXPRESSION. It cannot answer "does production ever feed it
/// something that rejects?", which is a property of the upstream nodes and
/// the live data — the same distinction the digest's `population_note` draws
/// between scored and total verdicts.
pub const SYNTHETIC_INPUT_NOTE: &str = "These verdicts were computed against SYNTHETIC inputs \
    supplied by the caller, bound through the engine's real arity rule for this node's actual \
    in-edges. A rejecting case proves the expression CAN fail; it does NOT prove that production \
    inputs ever exercise that branch. A probe where every case passes proves nothing at all about \
    the judge — it means the cases were not adversarial enough.";

// ─────────────────────────────────────────────────────────────────────────────
// Input
// ─────────────────────────────────────────────────────────────────────────────

/// One synthetic scenario to run the judge against.
///
/// The two shapes are EXPLICIT rather than inferred from the value, because
/// the ambiguity lands exactly where this tool is most valuable. A
/// single-parent judge binds its parent's output UNWRAPPED, so a case written
/// as `{"classify": {...}}` for a single-parent node would bind `classify` as
/// a scope variable that production never binds — and an expression reading
/// `classify.classifications` would PASS in the probe and abort at runtime.
/// Naming the shape makes that impossible to write by accident.
#[derive(Debug, Clone)]
pub struct ProbeCase {
    /// Caller-facing name for this case, echoed in the outcome. Defaults to
    /// `case_<index>` when absent.
    pub name: String,
    /// The binding, matched against the node's real in-edge count.
    pub binding: CaseBinding,
}

/// How a case supplies the judge's parent inputs.
#[derive(Debug, Clone)]
pub enum CaseBinding {
    /// The sole parent's output, verbatim. Valid only for a node with
    /// exactly one in-edge.
    SingleParent(JsonValue),
    /// One output per parent, keyed by the parent's node label. Valid only
    /// for a node with two or more in-edges, and the key set must match the
    /// parent set EXACTLY — a missing parent would silently drop the node to
    /// the single-parent arity and produce a differently-shaped scope.
    Parents(Map<String, JsonValue>),
}

/// Parse the wire form of `cases` into typed [`ProbeCase`]s.
///
/// Protocol-agnostic on purpose — the MCP handler is a thin wrapper over
/// this, and a future GraphQL resolver gets the same validation (and the same
/// error wording) for free. Returns a caller-facing message on the first
/// problem; the transport maps it to its own error shape.
///
/// Wire form, one object per case:
/// * `name` (optional) — defaults to `case_<index>`.
/// * EXACTLY ONE of `input` (single-parent judge) or `parents` (multi-parent,
///   an object keyed by parent node label).
///
/// The shape is explicit rather than inferred because the ambiguity lands
/// precisely where the tool is most valuable — see [`ProbeCase`].
pub fn parse_cases(raw: &[JsonValue]) -> Result<Vec<ProbeCase>, String> {
    if raw.is_empty() {
        return Err("at least one case is required".to_string());
    }
    if raw.len() > MAX_CASES {
        return Err(format!(
            "at most {MAX_CASES} cases per probe (got {})",
            raw.len()
        ));
    }
    let mut out = Vec::with_capacity(raw.len());
    for (i, v) in raw.iter().enumerate() {
        let obj = v
            .as_object()
            .ok_or_else(|| format!("cases[{i}] must be an object with 'input' or 'parents'"))?;
        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| talos_text_util::bounded_preview(s.trim(), 64).to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("case_{i}"));
        let binding = match (obj.get("input"), obj.get("parents")) {
            (Some(_), Some(_)) => {
                return Err(format!(
                    "cases[{i}] sets both 'input' and 'parents' — use 'input' for a judge with \
                     ONE parent (its output is bound unwrapped) and 'parents' for a judge with \
                     two or more (outputs keyed by node label)"
                ))
            }
            (Some(v), None) => CaseBinding::SingleParent(v.clone()),
            (None, Some(v)) => CaseBinding::Parents(v.as_object().cloned().ok_or_else(|| {
                format!("cases[{i}].parents must be an object keyed by parent node label")
            })?),
            (None, None) => {
                return Err(format!(
                    "cases[{i}] must set 'input' (single-parent judge) or 'parents' \
                     (multi-parent judge)"
                ))
            }
        };
        out.push(ProbeCase { name, binding });
    }
    Ok(out)
}

/// A probe request.
#[derive(Debug, Clone)]
pub struct ProbeInput {
    /// Workflow owning the judge node. Ownership is enforced by the graph
    /// read; a workflow the caller does not own is indistinguishable from one
    /// that does not exist.
    pub workflow_id: Uuid,
    /// The judge node, given either as its graph label (`"coverage_judge"`)
    /// or as the engine node UUID that `judge_scores` records (which is what
    /// the operator digest's probe pointer carries).
    pub node_ref: String,
    /// Synthetic scenarios, 1..=[`MAX_CASES`].
    pub cases: Vec<ProbeCase>,
    /// Try a REPLACEMENT expression without writing it to the graph — the
    /// iterate-on-a-fix loop. When absent the graph's persisted
    /// `verdict_expr` is used.
    pub verdict_expr_override: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Outcome
// ─────────────────────────────────────────────────────────────────────────────

/// How the node's scope was built — the arity rule the engine applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeSource {
    /// Exactly one in-edge: the parent's output is bound UNWRAPPED and
    /// UNKEYED. Its top-level fields become bare scope variables.
    SingleParentUnwrapped,
    /// Two or more in-edges: outputs are wrapped in an object keyed by node
    /// label. The LABELS become the bare scope variables, not the fields.
    MultiParentLabeled,
}

impl ScopeSource {
    /// Stable wire string for the tool response.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingleParentUnwrapped => "single_parent_unwrapped",
            Self::MultiParentLabeled => "multi_parent_labeled",
        }
    }
}

/// Which of `build_judge_envelope`'s three branches production would take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Branch {
    /// Verdict passed: parent output forwarded, enriched.
    Pass,
    /// Verdict rejected under `on_failure: "passthrough"`: parent output
    /// forwarded with `__judge_rejected__: true`.
    Passthrough,
    /// Verdict rejected under `on_failure: "error"` (the default), OR the
    /// expression failed to evaluate at all. The two are distinguished by
    /// [`CaseOutcome::eval_error`] — a rejection is the judge working, an
    /// eval error is the judge broken.
    Error,
}

impl Branch {
    /// Stable wire string for the tool response.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Passthrough => "passthrough",
            Self::Error => "error",
        }
    }
}

/// What the engine would have done for one synthetic case.
#[derive(Debug, Clone)]
pub struct CaseOutcome {
    /// Echo of [`ProbeCase::name`].
    pub name: String,
    /// The arity rule applied.
    pub scope_source: ScopeSource,
    /// Top-level keys of the bound scope — the bare variable names the
    /// expression can actually reference. The single highest-signal field
    /// when an expression silently reads an unbound variable.
    pub scope_keys: Vec<String>,
    /// Keys from [`Self::scope_keys`] that the evaluator OVERWRITES with its
    /// own bindings, so reading them does not yield the parent's output. See
    /// [`RESERVED_SCOPE_NAMES`].
    pub shadowed_scope_keys: Vec<String>,
    /// Raw value the expression returned, before verdict parsing. `None`
    /// when evaluation failed.
    pub raw_verdict: Option<JsonValue>,
    /// Parsed score (0.0 when the field was missing/mistyped).
    pub score: f64,
    /// The verdict's own `passed` field, BEFORE the threshold is applied.
    pub passed_raw: bool,
    /// The node's configured threshold, echoed so `passed_effective` is
    /// readable without cross-referencing the graph.
    pub pass_threshold: Option<f64>,
    /// `passed_raw && score >= threshold` (or just `passed_raw` when no
    /// threshold is set) — what actually gates the node.
    pub passed_effective: bool,
    /// The verdict abstained: this run had nothing to judge.
    pub not_applicable: bool,
    /// Fields missing or wrong-typed in the returned verdict, 0..=5. An
    /// expression returning a non-object (e.g. a bare `true`) scores 4 here
    /// and routes as a REJECTION — it does not error.
    pub malformed_field_count: u8,
    /// The returned value carried a usable `score` OR `passed` field — i.e.
    /// the rejection/pass below is the RUBRIC's opinion rather than the
    /// engine's default. `false` means the expression returned something that
    /// is not a verdict at all (a bare `true`, a number, `()`), which the
    /// engine rejects unconditionally on every input. See
    /// [`ProbeSummary::can_fail`].
    pub verdict_present: bool,
    /// The branch production would take.
    pub branch: Branch,
    /// Set when the expression itself failed (syntax error, unbound
    /// variable, operation-limit abort). The message is the Rhai error
    /// verbatim, which is what the runtime would put in the error envelope.
    pub eval_error: Option<String>,
    /// The exact envelope the node would forward downstream.
    pub envelope: JsonValue,
}

impl CaseOutcome {
    /// Serialize to the stable tool-response shape.
    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        json!({
            "name": self.name,
            "bound_scope_source": self.scope_source.as_str(),
            "bound_scope_keys": self.scope_keys,
            "shadowed_scope_keys": self.shadowed_scope_keys,
            "raw_verdict": self.raw_verdict,
            "score": self.score,
            "passed_raw": self.passed_raw,
            "pass_threshold": self.pass_threshold,
            "passed_effective": self.passed_effective,
            "not_applicable": self.not_applicable,
            "malformed_field_count": self.malformed_field_count,
            "verdict_present": self.verdict_present,
            "branch": self.branch.as_str(),
            "eval_error": self.eval_error,
            "envelope": self.envelope,
        })
    }
}

/// The saturation answer, in one struct.
#[derive(Debug, Clone, Copy)]
pub struct ProbeSummary {
    /// Cases run.
    pub cases: usize,
    /// At least one case produced a REJECTING verdict — the judge is a gate,
    /// not a shape check.
    ///
    /// Two kinds of rejection are excluded, because both reject EVERY input
    /// and so demonstrate nothing about the rubric:
    /// * expression failures ([`Self::eval_errors`]) — the expression never
    ///   produced a verdict;
    /// * verdict-less results ([`Self::verdictless_rejections`]) — the
    ///   expression evaluated fine but returned something that is not a
    ///   verdict, so `passed` DEFAULTED to false.
    ///
    /// The second exclusion matters most for the commonest authoring mistake
    /// there is: writing the condition itself (`covered >= total`) as the
    /// whole `verdict_expr`. That returns a bare bool, which
    /// [`JudgeVerdict::from_collapsed`] scores 0.0 / not-passed with four
    /// malformed fields — so every case "rejects" and a naive `can_fail`
    /// would certify a judge that fails 100% of production runs as "a real
    /// gate". Being confidently wrong in the operator's favour is worse here
    /// than saying nothing.
    ///
    /// [`JudgeVerdict::from_collapsed`]: talos_workflow_engine::JudgeVerdict::from_collapsed
    pub can_fail: bool,
    /// At least one case abstained (`not_applicable: true`).
    pub can_abstain: bool,
    /// Every case passed. Combined with adversarial cases this is the
    /// saturation smell; on its own it may just mean weak cases.
    pub all_pass: bool,
    /// Cases where the expression failed to evaluate. Non-zero means the
    /// node is erroring in production too, for any input of that shape.
    pub eval_errors: usize,
    /// Cases the engine rejected on a value that carried NO verdict — no
    /// usable `score`, no usable `passed`. Non-zero means the expression is
    /// not returning a verdict map at all, so the node rejects every run
    /// regardless of input. Excluded from [`Self::can_fail`]; reported
    /// separately because it is a DIFFERENT repair from a weak rubric.
    pub verdictless_rejections: usize,
}

impl ProbeSummary {
    /// Serialize to the stable tool-response shape.
    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        json!({
            "cases": self.cases,
            "can_fail": self.can_fail,
            "can_abstain": self.can_abstain,
            "all_pass": self.all_pass,
            "eval_errors": self.eval_errors,
            "verdictless_rejections": self.verdictless_rejections,
        })
    }
}

/// Full probe result.
#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    /// Workflow probed.
    pub workflow_id: Uuid,
    /// The resolved node's graph label.
    pub node_label: String,
    /// The resolved node's engine UUID — the value `judge_scores.node_id`
    /// carries, so an operator can correlate a probe with a trend row.
    pub node_id: Uuid,
    /// Labels of the node's REAL in-edges, in the order the engine walks
    /// them. Named on every outcome because "which parents does this node
    /// actually have" is the question behind most saturated judges.
    pub parents: Vec<String>,
    /// True when [`ProbeInput::verdict_expr_override`] was used — the
    /// verdicts below do NOT describe the persisted graph.
    pub used_expr_override: bool,
    /// Per-case results.
    pub cases: Vec<CaseOutcome>,
    /// Aggregate.
    pub summary: ProbeSummary,
}

impl ProbeOutcome {
    /// Serialize to the stable tool-response shape.
    ///
    /// The expression text is deliberately NOT echoed: it is already in the
    /// caller's graph, and a persisted `verdict_expr` can carry
    /// vault-interpolated values.
    #[must_use]
    pub fn to_tool_body(&self) -> JsonValue {
        json!({
            "workflow_id": self.workflow_id.to_string(),
            "node_label": self.node_label,
            "node_id": self.node_id.to_string(),
            "parents": self.parents,
            "used_expr_override": self.used_expr_override,
            "cases": self.cases.iter().map(CaseOutcome::to_json).collect::<Vec<_>>(),
            "summary": self.summary.to_json(),
            "note": SYNTHETIC_INPUT_NOTE,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Failure modes. Every variant is caller-actionable except
/// [`ProbeError::Internal`], which collapses to a generic message.
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    /// No workflow with that id owned by this caller. Deliberately fused
    /// with "not owned" so the probe is not an existence oracle.
    #[error("workflow not found or access denied")]
    WorkflowNotFound,
    /// `graph_json` did not parse, or the engine refused to load it.
    #[error("workflow graph could not be loaded: {0}")]
    GraphUnloadable(String),
    /// No node in the graph matched `node_ref`.
    #[error("node '{node_ref}' not found in this workflow. Judge nodes here: {candidates}")]
    NodeNotFound {
        /// What the caller asked for.
        node_ref: String,
        /// Comma-separated labels of the graph's judge-ish nodes, or a
        /// placeholder when there are none.
        candidates: String,
    },
    /// The node exists but is not an `inline_judge`.
    #[error("node '{node_label}' is {actual}, not an inline_judge — {hint}")]
    NotAnInlineJudge {
        /// The node's label.
        node_label: String,
        /// What it actually is.
        actual: String,
        /// Where to go instead.
        hint: String,
    },
    /// The judge node has no in-edges, so there is nothing to bind.
    #[error(
        "node '{node_label}' has no incoming edges — the engine binds an EMPTY object as its \
         input, so no synthetic case can change the verdict. Wire a parent first."
    )]
    NodeHasNoParents {
        /// The node's label.
        node_label: String,
    },
    /// No cases supplied.
    #[error("at least one case is required")]
    NoCases,
    /// Too many cases.
    #[error("at most {MAX_CASES} cases per probe (got {got})")]
    TooManyCases {
        /// How many were supplied.
        got: usize,
    },
    /// A case's binding shape does not match the node's real arity, or names
    /// a parent the node does not have. THIS IS USUALLY THE DIAGNOSIS, not a
    /// usage nit — see the message.
    #[error("case '{case}': {detail}")]
    CaseBindingMismatch {
        /// Which case.
        case: String,
        /// The full explanation, naming the node's actual parents.
        detail: String,
    },
    /// The override expression is empty or exceeds the persisted validator's
    /// bound.
    #[error("verdict_expr override {0}")]
    BadExprOverride(String),
    /// Database or other internal failure.
    #[error("internal error")]
    Internal(String),
}

impl ProbeError {
    /// Stable JSON-RPC code. `-32602` for caller-fixable input, `-32000`
    /// for everything else — the house mapping.
    #[must_use]
    pub fn jsonrpc_code(&self) -> i32 {
        match self {
            Self::WorkflowNotFound | Self::Internal(_) => -32000,
            Self::GraphUnloadable(_)
            | Self::NodeNotFound { .. }
            | Self::NotAnInlineJudge { .. }
            | Self::NodeHasNoParents { .. }
            | Self::NoCases
            | Self::TooManyCases { .. }
            | Self::CaseBindingMismatch { .. }
            | Self::BadExprOverride(_) => -32602,
        }
    }

    /// Caller-facing message. `Internal` collapses to a generic string so no
    /// schema or query detail crosses the protocol boundary; the detail is
    /// logged server-side by the caller.
    #[must_use]
    pub fn user_facing_message(&self) -> String {
        match self {
            Self::Internal(_) => "Internal error".to_string(),
            other => other.to_string(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Service
// ─────────────────────────────────────────────────────────────────────────────

/// Cross-protocol judge-probe service. Holds one repository Arc; the whole
/// evaluation is pure and lives in [`probe_graph`], so every rule below is
/// unit-tested without a database.
pub struct JudgeProbeService {
    advanced: Arc<talos_advanced_repository::AdvancedRepository>,
}

impl JudgeProbeService {
    /// Wire the service to the shared advanced repository.
    #[must_use]
    pub fn new(advanced: Arc<talos_advanced_repository::AdvancedRepository>) -> Self {
        Self { advanced }
    }

    /// Load the caller's OWN workflow graph and probe its judge node.
    ///
    /// Read-only: no execution row is minted, no module runs, no NATS
    /// message is published, nothing is written.
    pub async fn probe(
        &self,
        user_id: Uuid,
        input: &ProbeInput,
    ) -> Result<ProbeOutcome, ProbeError> {
        // Ownership-scoped read (`WHERE id = $1 AND user_id = $2`). A
        // workflow belonging to someone else returns None, identical to a
        // non-existent id.
        let graph_json = self
            .advanced
            .get_workflow_graph_json(input.workflow_id, user_id)
            .await
            .map_err(|e| ProbeError::Internal(e.to_string()))?
            .ok_or(ProbeError::WorkflowNotFound)?;

        let outcome = probe_graph(&graph_json, input)?;
        // DLP: ids and counts only. Never the expression, the cases, or the
        // verdict reasoning.
        tracing::info!(
            target: "talos_judge_probe",
            workflow_id = %input.workflow_id,
            node_id = %outcome.node_id,
            cases = outcome.summary.cases,
            can_fail = outcome.summary.can_fail,
            can_abstain = outcome.summary.can_abstain,
            eval_errors = outcome.summary.eval_errors,
            "judge probe completed"
        );
        Ok(outcome)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The pure core
// ─────────────────────────────────────────────────────────────────────────────

/// Probe a judge node against synthetic cases, given the workflow's raw
/// `graph_json`. Pure — no I/O, no DB, no clock.
///
/// The graph is parsed by the ENGINE's own loader, so node ids, labels,
/// edges, and the `inline_judge` config are resolved exactly as they are at
/// runtime.
pub fn probe_graph(graph_json: &str, input: &ProbeInput) -> Result<ProbeOutcome, ProbeError> {
    if input.cases.is_empty() {
        return Err(ProbeError::NoCases);
    }
    if input.cases.len() > MAX_CASES {
        return Err(ProbeError::TooManyCases {
            got: input.cases.len(),
        });
    }

    let graph: JsonValue = serde_json::from_str(graph_json)
        .map_err(|e| ProbeError::GraphUnloadable(format!("graph_json is not valid JSON: {e}")))?;
    let mut engine = ParallelWorkflowEngine::new();
    engine
        .load_from_graph_json(&graph)
        .map_err(|e| ProbeError::GraphUnloadable(e.to_string()))?;

    let (node_id, node_label) = resolve_node(&engine, &input.node_ref)?;

    let (graph_expr, pass_threshold, on_failure) = match engine.node_meta().get(&node_id) {
        Some((
            _,
            _,
            Some(SystemNodeKind::InlineJudge {
                verdict_expr,
                pass_threshold,
                on_failure,
            }),
        )) => (verdict_expr.clone(), *pass_threshold, on_failure.clone()),
        Some((_, _, Some(SystemNodeKind::Judge { .. }))) => {
            return Err(ProbeError::NotAnInlineJudge {
                node_label,
                actual: "an LLM-as-judge sub-workflow node (kind 'judge')".to_string(),
                hint: "its verdict comes from a sub-workflow, not an expression. Use \
                       test_subworkflow_contract(workflow_id=<the judge workflow>, \
                       contract='judge') to exercise it."
                    .to_string(),
            })
        }
        Some((_, _, Some(other))) => {
            return Err(ProbeError::NotAnInlineJudge {
                node_label,
                actual: format!("a {} system node", system_kind_name(other)),
                hint: "only inline_judge nodes have a verdict expression to probe".to_string(),
            })
        }
        _ => {
            return Err(ProbeError::NotAnInlineJudge {
                node_label,
                actual: "a module node".to_string(),
                hint: "only inline_judge nodes have a verdict expression to probe".to_string(),
            })
        }
    };

    // The persisted expression is bounded by the graph validator
    // (`MAX_RHAI_EXPRESSION_BYTES`, 8 KiB) and is NOT re-capped here — a
    // stricter probe-side cap would make long-but-legal judges unprobeable,
    // which is backwards. An OVERRIDE has never been through that validator,
    // so it is held to the same bound.
    let (verdict_expr, used_expr_override) = match input.verdict_expr_override.as_deref() {
        None => (graph_expr, false),
        Some(o) => {
            let trimmed = o.trim();
            if trimmed.is_empty() {
                return Err(ProbeError::BadExprOverride(
                    "must not be empty or whitespace-only".to_string(),
                ));
            }
            if trimmed.len() > talos_workflow_types::MAX_RHAI_EXPRESSION_BYTES {
                return Err(ProbeError::BadExprOverride(format!(
                    "must be at most {} bytes (the same bound the persisted graph validator \
                     enforces); got {}",
                    talos_workflow_types::MAX_RHAI_EXPRESSION_BYTES,
                    trimmed.len()
                )));
            }
            (trimmed.to_string(), true)
        }
    };

    let node_idx = *engine
        .node_map()
        .get(&node_id)
        .ok_or_else(|| ProbeError::GraphUnloadable("node missing from engine index".to_string()))?;

    // The node's REAL in-edges, resolved from the loaded graph. Everything
    // downstream binds against THIS, never against what the caller assumed.
    let parent_ids: Vec<Uuid> = engine
        .graph()
        .neighbors_directed(node_idx, petgraph::Direction::Incoming)
        .map(|idx| engine.graph()[idx])
        .collect();
    if parent_ids.is_empty() {
        return Err(ProbeError::NodeHasNoParents { node_label });
    }
    let parent_labels: Vec<String> = parent_ids
        .iter()
        .map(|pid| label_of(&engine, *pid))
        .collect();
    let scope_source = if parent_ids.len() == 1 {
        ScopeSource::SingleParentUnwrapped
    } else {
        ScopeSource::MultiParentLabeled
    };

    let mut cases = Vec::with_capacity(input.cases.len());
    for case in &input.cases {
        let results = bind_case(case, &parent_ids, &parent_labels, scope_source)?;
        // THE reuse: the engine's own arity rule, including `unwrap_output`.
        let parent_inputs = engine.gather_inputs(node_idx, &results);
        cases.push(evaluate_case(
            &case.name,
            scope_source,
            parent_inputs,
            &verdict_expr,
            pass_threshold,
            &on_failure,
        ));
    }

    let summary = summarize(&cases);
    Ok(ProbeOutcome {
        workflow_id: input.workflow_id,
        node_label,
        node_id,
        parents: parent_labels,
        used_expr_override,
        cases,
        summary,
    })
}

fn label_of(engine: &ParallelWorkflowEngine, node_id: Uuid) -> String {
    engine
        .node_labels()
        .get(&node_id)
        .cloned()
        .unwrap_or_else(|| node_id.to_string())
}

/// Resolve `node_ref` to `(engine uuid, label)`.
///
/// Accepts a graph label (`"coverage_judge"` — what an author writes) OR the
/// engine node UUID (what `judge_scores.node_id` stores, and therefore what
/// the operator digest's probe pointer carries). Labels win on collision,
/// since a label is what the author controls.
fn resolve_node(
    engine: &ParallelWorkflowEngine,
    node_ref: &str,
) -> Result<(Uuid, String), ProbeError> {
    let needle = node_ref.trim();
    if let Some((id, label)) = engine
        .node_labels()
        .iter()
        .find(|(_, label)| label.as_str() == needle)
    {
        return Ok((*id, label.clone()));
    }
    if let Ok(as_uuid) = Uuid::parse_str(needle) {
        if let Some(label) = engine.node_labels().get(&as_uuid) {
            return Ok((as_uuid, label.clone()));
        }
    }
    // Name the judge nodes specifically — a graph can have dozens of module
    // nodes, and listing them all buries the answer.
    let mut candidates: Vec<String> = engine
        .node_meta()
        .iter()
        .filter(|(_, (_, _, kind))| {
            matches!(
                kind,
                Some(SystemNodeKind::InlineJudge { .. }) | Some(SystemNodeKind::Judge { .. })
            )
        })
        .map(|(id, _)| label_of(engine, *id))
        .collect();
    candidates.sort();
    let candidates = if candidates.is_empty() {
        "(this workflow has no judge nodes)".to_string()
    } else {
        candidates.join(", ")
    };
    Err(ProbeError::NodeNotFound {
        node_ref: talos_text_util::bounded_preview(needle, 128).to_string(),
        candidates,
    })
}

/// Turn one case into the `results` map `gather_inputs` reads.
///
/// Every rejection here names the node's ACTUAL parents, because a
/// binding mismatch is the single most common cause of a judge that cannot
/// fail: an expression written for a multi-parent scope on a node that grew
/// down to one parent reads an unbound variable at runtime.
fn bind_case(
    case: &ProbeCase,
    parent_ids: &[Uuid],
    parent_labels: &[String],
    scope_source: ScopeSource,
) -> Result<HashMap<Uuid, JsonValue>, ProbeError> {
    let mismatch = |detail: String| ProbeError::CaseBindingMismatch {
        case: case.name.clone(),
        detail,
    };
    let mut results = HashMap::with_capacity(parent_ids.len());
    match (&case.binding, scope_source) {
        (CaseBinding::SingleParent(v), ScopeSource::SingleParentUnwrapped) => {
            results.insert(parent_ids[0], v.clone());
        }
        (CaseBinding::Parents(map), ScopeSource::MultiParentLabeled) => {
            for key in map.keys() {
                if !parent_labels.iter().any(|l| l == key) {
                    return Err(mismatch(format!(
                        "'{}' is not a parent of this node. Its actual parents are: {}. A case \
                         keyed by a non-parent binds a scope variable the engine never binds, so \
                         an expression reading it would pass here and abort at runtime — that \
                         mismatch is very likely the bug you are looking for.",
                        talos_text_util::bounded_preview(key, 64),
                        parent_labels.join(", ")
                    )));
                }
            }
            for (label, pid) in parent_labels.iter().zip(parent_ids.iter()) {
                let Some(v) = map.get(label) else {
                    return Err(mismatch(format!(
                        "missing parent '{label}'. This node has {} parents ({}) and every one \
                         must be supplied: omitting one drops the node to the single-parent \
                         binding, which produces a DIFFERENT scope shape than production.",
                        parent_labels.len(),
                        parent_labels.join(", ")
                    )));
                };
                results.insert(*pid, v.clone());
            }
        }
        (CaseBinding::Parents(_), ScopeSource::SingleParentUnwrapped) => {
            return Err(mismatch(format!(
                "this node has exactly ONE parent ('{}'), so the engine binds that parent's \
                 output UNWRAPPED and UNKEYED — its top-level fields become bare scope \
                 variables. A label-keyed case would bind '{}' itself as a variable, which \
                 production never does. Supply the parent's output directly instead.",
                parent_labels[0], parent_labels[0]
            )));
        }
        (CaseBinding::SingleParent(_), ScopeSource::MultiParentLabeled) => {
            return Err(mismatch(format!(
                "this node has {} parents ({}), so the engine binds an OBJECT KEYED BY NODE \
                 LABEL — the labels are the bare scope variables, not the parent's fields. \
                 Supply one output per parent, keyed by label.",
                parent_labels.len(),
                parent_labels.join(", ")
            )));
        }
    }
    Ok(results)
}

/// Replay the engine's verdict pipeline for one bound scope.
fn evaluate_case(
    name: &str,
    scope_source: ScopeSource,
    parent_inputs: JsonValue,
    verdict_expr: &str,
    pass_threshold: Option<f64>,
    on_failure: &str,
) -> CaseOutcome {
    // Exactly the variable names `evaluate_expression` will push into scope.
    let scope_keys: Vec<String> = parent_inputs
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    // ...except that the evaluator pushes `ctx` / `inputs` AFTER the parent
    // keys, and Rhai resolves a name to the LAST binding. A parent labelled
    // `ctx` is therefore invisible: `ctx.field` reads the whole context, not
    // that parent. Reporting such a key as available without qualification
    // would be a diagnostic lie in the one tool whose job is diagnosing
    // scope-binding traps.
    let shadowed_scope_keys: Vec<String> = scope_keys
        .iter()
        .filter(|k| RESERVED_SCOPE_NAMES.contains(&k.as_str()))
        .cloned()
        .collect();

    // Production limits BY REUSE — 1000 operations, 16 call levels, no
    // `eval`, no module resolver, and the same HTML-entity decode the
    // runtime applies to stored expressions.
    let raw = talos_engine::rhai_helpers::evaluate_expression(verdict_expr, &parent_inputs);
    let raw_verdict = match raw {
        Ok(v) => v,
        Err(e) => {
            // Byte-identical to `dispatch_inline_judge`'s evaluator-failure
            // envelope.
            let envelope = json!({
                "__error": true,
                "error_message": format!("InlineJudge expression failed: {e}"),
            });
            return CaseOutcome {
                name: name.to_string(),
                scope_source,
                scope_keys,
                shadowed_scope_keys,
                raw_verdict: None,
                score: 0.0,
                passed_raw: false,
                pass_threshold,
                passed_effective: false,
                not_applicable: false,
                malformed_field_count: 0,
                verdict_present: false,
                branch: Branch::Error,
                eval_error: Some(e),
                envelope,
            };
        }
    };

    let verdict = JudgeVerdict::from_collapsed(&raw_verdict);
    let JudgeVerdict {
        score,
        passed: passed_raw,
        reasoning,
        feedback,
        not_applicable,
        malformed_field_count,
    } = verdict;
    let passed_effective = match pass_threshold {
        Some(t) => passed_raw && score >= t,
        None => passed_raw,
    };
    let envelope = build_judge_envelope(
        "InlineJudge",
        parent_inputs,
        score,
        passed_effective,
        &reasoning,
        &feedback,
        not_applicable,
        on_failure,
    );
    let branch = if passed_effective {
        Branch::Pass
    } else if on_failure == "passthrough" {
        Branch::Passthrough
    } else {
        Branch::Error
    };

    CaseOutcome {
        name: name.to_string(),
        scope_source,
        scope_keys,
        shadowed_scope_keys,
        verdict_present: carries_a_verdict(&raw_verdict),
        raw_verdict: Some(raw_verdict),
        score,
        passed_raw,
        pass_threshold,
        passed_effective,
        not_applicable,
        malformed_field_count,
        branch,
        eval_error: None,
        envelope,
    }
}

/// Did the expression's result actually CARRY a verdict, or did
/// [`JudgeVerdict::from_collapsed`] have to default the whole thing?
///
/// The two accessor chains are the same ones `from_collapsed` applies to
/// `score` and `passed` — the one place this crate reads a verdict directly
/// rather than through the engine. It is confined to these two lines, and
/// `verdict_presence_matches_from_collapsed` cross-checks it against the real
/// parse so a change to either accessor fails a test rather than silently
/// re-arming the false `can_fail`.
///
/// [`JudgeVerdict::from_collapsed`]: talos_workflow_engine::JudgeVerdict::from_collapsed
fn carries_a_verdict(raw: &JsonValue) -> bool {
    raw.get("score").and_then(JsonValue::as_f64).is_some()
        || raw.get("passed").and_then(JsonValue::as_bool).is_some()
}

fn summarize(cases: &[CaseOutcome]) -> ProbeSummary {
    // A rejection counts as evidence only when the RUBRIC produced it: the
    // expression evaluated (no `eval_error`) AND returned something with a
    // usable `score`/`passed`. Both exclusions describe expressions that
    // reject every possible input, which is the opposite of a working gate.
    let rejected_by_rubric =
        |c: &&CaseOutcome| c.eval_error.is_none() && c.verdict_present && !c.passed_effective;
    ProbeSummary {
        cases: cases.len(),
        can_fail: cases.iter().any(|c| rejected_by_rubric(&c)),
        can_abstain: cases.iter().any(|c| c.not_applicable),
        all_pass: cases.iter().all(|c| c.passed_effective),
        eval_errors: cases.iter().filter(|c| c.eval_error.is_some()).count(),
        verdictless_rejections: cases
            .iter()
            .filter(|c| c.eval_error.is_none() && !c.verdict_present && !c.passed_effective)
            .count(),
    }
}

/// Human name for a system-node kind, for the "not an inline judge" error.
fn system_kind_name(kind: &SystemNodeKind) -> String {
    // `SystemNodeKind` has ~30 variants across two feature sets; the Debug
    // representation's leading identifier is the variant name, which is
    // exactly what we want and cannot go stale.
    let dbg = format!("{kind:?}");
    dbg.split(|c: char| !c.is_alphanumeric() && c != '_')
        .next()
        .unwrap_or("system")
        .to_string()
}

#[cfg(test)]
mod tests;
