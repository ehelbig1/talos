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

    /// The outcome a `module_executions.status` string names, or `None` for a
    /// non-terminal or unknown spelling. The engine's finalizer hands the
    /// store a `&str` (`completed` / `failed` / `timeout`, from
    /// `engine_dispatch_single::classify`), so the mapping lives here — beside
    /// `as_str`, which it must invert — rather than at that call site.
    #[must_use]
    pub fn from_status(status: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|o| o.as_str() == status)
    }
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

#[cfg(test)]
mod from_status_tests {
    use super::ModuleExecutionOutcome;

    #[test]
    fn from_status_inverts_as_str_over_every_outcome() {
        for o in ModuleExecutionOutcome::ALL {
            assert_eq!(ModuleExecutionOutcome::from_status(o.as_str()), Some(*o));
        }
    }

    #[test]
    fn a_non_terminal_or_unknown_spelling_maps_to_nothing() {
        // The engine's finalizer must not count a `running`/`pending` row
        // under the nearest label, and a case or whitespace variant is not
        // the column's spelling.
        for s in [
            "running",
            "pending",
            "Completed",
            " completed",
            "",
            "success",
        ] {
            assert_eq!(ModuleExecutionOutcome::from_status(s), None, "{s:?}");
        }
    }
}
