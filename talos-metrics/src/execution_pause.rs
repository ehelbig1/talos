//! Closed label sets for `talos_execution_pause_refusals_total{path,reason}` —
//! the counter that says the deployment-wide execution pause is actually
//! stopping something.
//!
//! Why it exists (2026-09-14, package BF): the pause had never once taken
//! effect. Its writer bound a TEXT parameter into the `jsonb`
//! `system_settings.value` column, which Postgres refuses, so
//! `pause_executions` always answered "Failed to pause executions"; and even
//! a hand-written row would have stopped under 1% of real dispatch, because
//! the scheduler (67% of runs over the measured week) and the Gmail push
//! branch (32%) never read it. A control that silently does nothing is the
//! defect, so the repaired control carries a series that moves when it
//! refuses.
//!
//! Every value is an ENUM so the label set is closed by the compiler, and
//! every `(path, reason)` pair is pre-seeded at 0: each path reads the flag
//! itself, so each can see both a set flag and one it cannot classify — no
//! seeded pair is unreachable (check 58's rule). No alert: a refusal is the
//! operator's pause working, and the only thing that distinguishes a pause
//! from a fault is who set it.

/// Where a start was refused. One variant per surface that decides on its own
/// read of the flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PauseGatePath {
    /// The scheduler's poll, BEFORE it claims due schedules. One increment per
    /// deferred POLL (not per schedule): the rows are never claimed, so they
    /// are never counted individually — they stay due and fire on resume.
    SchedulerPoll,
    /// An inbound webhook (the router's workflow dispatch), answered 503.
    Webhook,
    /// A Gmail Pub/Sub push whose watch is bound to a workflow or module,
    /// answered 503 before the history cursor moves.
    GmailPush,
    /// `ExecutionOrchestrationService::trigger` (MCP `trigger_workflow`,
    /// GraphQL `triggerWorkflow`).
    Trigger,
    /// `ExecutionOrchestrationService::retry`.
    Retry,
    /// `ExecutionOrchestrationService::replay*`.
    Replay,
    /// The MCP handlers' shared entry gate (`enforce_executions_not_paused`),
    /// including `test_subworkflow_contract` since package BG.
    McpEntry,
    /// GraphQL `testWorkflow` (package BG).
    GraphqlTest,
    /// Actor handoff (`HandoffService::handoff`, MCP `handoff_to_actor`).
    Handoff,
    /// An approval-gate approval or a workflow-suspension resume that would
    /// dispatch a continuation workflow — MCP `resolve_approval_gate` /
    /// `resume_workflow_by_correlation_id` and their webhook twins. Refused
    /// BEFORE the gate is resolved or the suspension claimed, so the gate
    /// stays pending and the resume can be retried (package BG).
    Continuation,
    /// A Google Calendar push whose watch is bound to a module, answered 503
    /// before its message-number dedup and sync cursor move.
    GcalPush,
    /// A GCP Pub/Sub push whose watch is bound to a module, answered 503
    /// before the dispatch task starts.
    GcpPush,
    /// The row-creation chokepoint (`create_execution_under_concurrency_limit`
    /// and its batch twin) refusing a start that an entry gate admitted a
    /// moment earlier — the flag was set in between — or one whose caller has
    /// no entry gate of its own. This includes a scheduled fire CLAIMED just
    /// before the pause (its schedule is then re-armed, so the fire is
    /// deferred rather than dropped). Recorded ONCE, here, and never again by
    /// the caller: one refusal is one increment, so the family sums.
    RowCreation,
}

impl PauseGatePath {
    pub const ALL: &'static [Self] = &[
        Self::SchedulerPoll,
        Self::Webhook,
        Self::GmailPush,
        Self::Trigger,
        Self::Retry,
        Self::Replay,
        Self::McpEntry,
        Self::GraphqlTest,
        Self::Handoff,
        Self::Continuation,
        Self::GcalPush,
        Self::GcpPush,
        Self::RowCreation,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SchedulerPoll => "scheduler_poll",
            Self::Webhook => "webhook",
            Self::GmailPush => "gmail_push",
            Self::Trigger => "trigger",
            Self::Retry => "retry",
            Self::Replay => "replay",
            Self::McpEntry => "mcp_entry",
            Self::GraphqlTest => "graphql_test",
            Self::Handoff => "handoff",
            Self::Continuation => "continuation",
            Self::GcalPush => "gcal_push",
            Self::GcpPush => "gcp_push",
            Self::RowCreation => "row_creation",
        }
    }
}

/// Why a start was refused. `Unreadable` is a stored value the reader cannot
/// classify (anything but a JSON boolean): the gate REFUSES rather than
/// guessing, because a kill-switch that reads garbage as "running" is the
/// failure this counter exists to make visible. A database error is not a
/// verdict and is reported by the caller's own error path, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PauseRefusal {
    Paused,
    Unreadable,
}

impl PauseRefusal {
    pub const ALL: &'static [Self] = &[Self::Paused, Self::Unreadable];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Paused => "paused",
            Self::Unreadable => "unreadable",
        }
    }
}
