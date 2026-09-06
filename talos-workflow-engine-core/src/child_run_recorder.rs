//! Write-side port for the child-run ledger (RFC 0012 P1).
//!
//! A sub-workflow runs IN-PROCESS through
//! `ParallelWorkflowEngine::execute_subworkflow_graph` and records no
//! `workflow_executions` row — measured platform-wide 2026-09-05 and again
//! 2026-09-06: ZERO rows carry a `parent_execution_id`, live table or archive.
//! Every reader that asks "did this workflow run, how often, how recently?"
//! reads that table, so a child is invisible to all of them. This port is how
//! the engine says a child ran.
//!
//! Same plugged-adapter architecture as [`crate::JudgeScoreRecorder`]: the
//! decision is the engine's, the Postgres impl lives outside it
//! (`talos-child-run-ledger`), and `None` — an out-of-tree consumer, a test
//! engine — simply records nothing.
//!
//! # Two non-negotiables, recorded here because they are easy to "fix"
//!
//! 1. **A ledger must never become a routing dependency.** Impls MUST swallow
//!    their own errors. A failed record must not fail the child, the parent, or
//!    the node. The engine awaits the call (a spawned write is the orphaning
//!    shape `docs/platform-primitive-checklist.md` warns about) but ignores its
//!    outcome by construction: [`ChildRunRecorder::record`] returns `()`.
//! 2. **A child run is NOT charged to the actor's hourly execution budget.**
//!    The parent's run was budgeted when it was created, and
//!    `talos_actor_repository::budget_precheck` counts `workflow_executions`
//!    rows only. Nothing here adds one.

use async_trait::async_trait;
use uuid::Uuid;

/// Which system-node kind dispatched this child.
///
/// **This set is derived from the code, not from a wish list.** It is exactly
/// the node kinds whose dispatcher routes through
/// `execute_subworkflow_graph`, so every variant has a live writer and the
/// table's CHECK constraint admits no value nothing writes.
///
/// `agent_loop` / `react_loop` (the per-iteration body) and `dispatch` /
/// `capability_dispatch` hydrate a child engine through a DIFFERENT site
/// (`AdapterSet::into_engine_with_graph` called directly in
/// `scheduler_handlers.rs`) and are deliberately NOT represented: P1 does not
/// record them, and admitting a variant with no writer would make "this child
/// has no rows" mean two different things with nothing to tell them apart.
/// They are named in `talos_child_run_ledger::UNRECORDED_DISPATCH_KINDS` and
/// disclosed by every consumer instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChildDispatchKind {
    /// A `sub_workflow` node.
    SubWorkflow,
    /// A `judge` node's judge workflow.
    Judge,
    /// An `ensemble` node — a candidate run, or its best-of-n judge run.
    /// `child_workflow_id` says which.
    Ensemble,
    /// A `reflective_retry` node — the child, or its reflection workflow.
    /// `child_workflow_id` says which.
    ReflectiveRetry,
    /// An `llm_dispatch` node — the classifier, a route target, or the
    /// fallback. `child_workflow_id` says which.
    LlmDispatch,
}

impl ChildDispatchKind {
    /// The wire/DB spelling. Must match the migration's CHECK constraint
    /// exactly; `sub_workflow_runs_dispatch_kind_check` is the second belt.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SubWorkflow => "sub_workflow",
            Self::Judge => "judge",
            Self::Ensemble => "ensemble",
            Self::ReflectiveRetry => "reflective_retry",
            Self::LlmDispatch => "llm_dispatch",
        }
    }

    /// Every kind, for a caller that needs to enumerate them (the DB round-trip
    /// test that proves each spelling satisfies the CHECK).
    pub const ALL: &'static [Self] = &[
        Self::SubWorkflow,
        Self::Judge,
        Self::Ensemble,
        Self::ReflectiveRetry,
        Self::LlmDispatch,
    ];
}

/// How a child run ended.
///
/// Two values, and the classification is NOT a shape assumption: a child whose
/// engine returned `Ok` but whose collapsed output
/// [`reports an error`](crate::reserved_keys::output_reports_error) is
/// [`Failed`](Self::Failed). That is check 77's classifier, the same one the
/// reactor uses to decide the parent node's fate, so the ledger and the run
/// cannot disagree about whether a child failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildRunStatus {
    /// The child ran and its collapsed output reports no error.
    Completed,
    /// The child's engine returned an error, or its collapsed output reports
    /// one.
    Failed,
}

impl ChildRunStatus {
    /// The DB spelling; must match `sub_workflow_runs_status_check`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

/// The longest `error_class` a record may carry. The writer truncates on a
/// CHAR boundary before the bind; the table's CHECK is the second belt.
pub const MAX_ERROR_CLASS_CHARS: usize = 512;

/// The longest `parent_node_id` a record may carry.
pub const MAX_PARENT_NODE_ID_CHARS: usize = 120;

/// One child run, as the engine observed it.
///
/// Timestamps are carried as UNIX MILLISECONDS rather than a `chrono` type on
/// purpose: this crate is the portable engine core and has no date-time
/// dependency, and the repository that writes the row already has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildRunRecord {
    /// The execution the PARENT ran under.
    pub parent_execution_id: Uuid,
    /// The parent's workflow DEFINITION id, denormalised so a purged parent
    /// execution still answers "who ran me".
    pub parent_workflow_id: Uuid,
    /// The parent's graph node id as authored, already scrubbed and capped to
    /// [`MAX_PARENT_NODE_ID_CHARS`].
    pub parent_node_id: String,
    /// Which node kind dispatched it.
    pub dispatch_kind: ChildDispatchKind,
    /// The workflow that ran as the child.
    pub child_workflow_id: Uuid,
    /// Tenancy. Every read of the ledger filters on this at the app layer AND
    /// under RLS.
    pub user_id: Uuid,
    /// The EFFECTIVE actor the child ran as — read off the sub-engine after
    /// the actor rebind, so a sub-workflow bound to its own actor is recorded
    /// as that actor and not as its parent's.
    pub actor_id: Option<Uuid>,
    /// Nesting depth; 1 = a direct child of a top-level execution.
    pub depth: i16,
    /// When the child engine started running, UNIX milliseconds.
    pub started_at_unix_ms: i64,
    /// Monotonic wall time of the child run.
    pub duration_ms: i64,
    /// How it ended.
    pub status: ChildRunStatus,
    /// A REDACTED, capped error summary — never a payload. Passed through the
    /// engine's output sanitizer (the same redaction
    /// `workflow_executions.error_message` gets) before it reaches here.
    pub error_class: Option<String>,
}

impl ChildRunRecord {
    /// The record as it may be BOUND: `parent_node_id` control-char-scrubbed
    /// and capped to [`MAX_PARENT_NODE_ID_CHARS`], `error_class` capped to
    /// [`MAX_ERROR_CLASS_CHARS`], both by CHARACTER (which is what the table's
    /// `char_length(...)` CHECKs count, and which is a char boundary by
    /// construction — a byte cap can split a multi-byte grapheme and produce a
    /// value the CHECK still accepts but nobody can read).
    ///
    /// Called by the repository immediately before the bind rather than by the
    /// engine that builds the record, so no future caller can forget it. It is
    /// idempotent, so calling it twice is free.
    ///
    /// This does NOT redact: `error_class` must already have passed through
    /// the engine's output sanitizer (the same redaction
    /// `workflow_executions.error_message` gets). A cap is not a redaction and
    /// must not be mistaken for one.
    #[must_use]
    pub fn sanitized(mut self) -> Self {
        self.parent_node_id = self
            .parent_node_id
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_PARENT_NODE_ID_CHARS)
            .collect();
        self.error_class = self.error_class.map(|e| {
            e.chars()
                .filter(|c| !c.is_control() || *c == '\n')
                .take(MAX_ERROR_CLASS_CHARS)
                .collect()
        });
        self
    }
}

/// Record one child run. **Best-effort by construction**: the return type is
/// `()`, so an impl has nowhere to put an error even if it wanted to. Impls
/// MUST log and drop their own failures and MUST count them on a pre-seeded
/// counter — a record that silently did not happen is indistinguishable from a
/// child that never ran, which is the exact reading this ledger exists to
/// remove.
#[async_trait]
pub trait ChildRunRecorder: Send + Sync {
    /// Persist one child run.
    async fn record(&self, record: ChildRunRecord);
}

/// WHERE a child dispatch came from, as the reactor loop knows it.
///
/// Threaded from the loop (which holds `execution_id` and `node_id`) down
/// through the five `dispatch_*` handlers to the one write site. It is an
/// ENUM with an explicit [`Untracked`](Self::Untracked) variant rather than an
/// `Option`, so a caller states an answer instead of defaulting to one, and a
/// SIXTH dispatch handler cannot be added without the compiler asking where it
/// came from.
///
/// The engine has no `execution_id` field — it is a parameter of `run_inner`,
/// and nodes dispatch concurrently — so this cannot be read off `&self` at the
/// write site. That is why it is an argument, exactly as `record_judge_score`
/// takes `(node_id, execution_id)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildRunSite {
    /// A graph node of a real execution.
    Node {
        /// The parent's execution id.
        execution_id: Uuid,
        /// The parent's engine node UUID. The graph-facing LABEL is resolved
        /// from it at the write site, so the mapping has one home.
        node_id: Uuid,
    },
    /// Not part of an execution — the `test_subworkflow_contract` probe, a
    /// one-off embedder invocation, a test. Nothing is recorded.
    Untracked,
}

impl ChildRunSite {
    /// Name the dispatch kind, producing the origin the write site takes.
    #[must_use]
    pub fn with_kind(self, kind: ChildDispatchKind) -> ChildRunOrigin {
        match self {
            Self::Node {
                execution_id,
                node_id,
            } => ChildRunOrigin::Node {
                execution_id,
                node_id,
                kind,
            },
            Self::Untracked => ChildRunOrigin::Untracked,
        }
    }
}

/// A [`ChildRunSite`] with its dispatch kind named — the argument
/// `execute_subworkflow_graph` takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildRunOrigin {
    /// Record this run.
    Node {
        /// The parent's execution id.
        execution_id: Uuid,
        /// The parent's engine node UUID.
        node_id: Uuid,
        /// Which node kind dispatched it.
        kind: ChildDispatchKind,
    },
    /// Record nothing.
    Untracked,
}
