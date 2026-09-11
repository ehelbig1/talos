//! Closed label set for `talos_module_executions_total{status}` and the
//! `status` label of `talos_module_execution_duration_seconds` — the last
//! two module-side names in check 58's dead-metric baseline (registered
//! 2026-05, never incremented until 2026-09-11).
//!
//! The values ARE the `module_executions.status` terminal states, spelled
//! exactly as the column spells them, so an operator can join the series to
//! the table without a translation. `trigger_type` was dropped from the
//! counter's labels while it was still dead: measured on the reference fleet,
//! that column reads `webhook` on ALL 55 279 rows, so the label would have
//! carried no information at the cost of a series per value.

/// Terminal state of one module execution, as the row records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModuleExecutionOutcome {
    Completed,
    Failed,
    /// The per-execution timeout finalizer OR the stuck-execution sweep
    /// (`error_type = 'stuck'`), which are one outcome to an operator: the
    /// row ended without a result.
    Timeout,
    /// Written only by the engine's race-safe INSERT when the parent
    /// workflow had already failed or been cancelled: the row is born
    /// terminal and no duration is meaningful.
    Cancelled,
}

impl ModuleExecutionOutcome {
    pub const ALL: &'static [Self] = &[
        Self::Completed,
        Self::Failed,
        Self::Timeout,
        Self::Cancelled,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
        }
    }
}
