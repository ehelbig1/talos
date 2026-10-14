//! How many child runs one ROOT run may start (security review 2026-10-14,
//! G-2).
//!
//! A sub-workflow chain was bounded by depth alone
//! ([`crate::DEFAULT_MAX_SUBFLOW_DEPTH`] = 16). Depth bounds the chain, not
//! its breadth: an `ensemble` of count 10 whose child is its own workflow
//! starts 10 children per level, so 16 levels is 10¹⁶ attempted child runs,
//! eight sub-engines in flight per level, no module dispatched (so no fuel
//! charged) and no execution row (so no execution budget sees it).
//!
//! [`ChildRunBudget`] is one counter per root run. The root engine makes it;
//! [`crate::AdapterSet`] carries the SAME counter (an `Arc`, never a fresh
//! one) into every sub-engine, at every depth; and the one place every
//! sub-workflow handler hydrates a child engine —
//! `AdapterSet::into_engine_with_graph`, beside the depth guard — takes one
//! unit or refuses with [`crate::WorkflowEngineError::ChildRunBudgetExhausted`].
//!
//! A child run is NOT charged to the actor's hourly execution budget — a
//! recorded decision (the child-run ledger digest). This budget is a
//! different thing: a bound on one run's tree, whoever owns it.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, LazyLock};

/// Default child runs one root run may start, across every depth.
pub const DEFAULT_MAX_CHILD_RUNS_PER_RUN: u32 = 256;

/// The largest value `TALOS_MAX_CHILD_RUNS_PER_RUN` may raise it to.
pub const MAX_CHILD_RUNS_PER_RUN_CEILING: u32 = 10_000;

/// `TALOS_MAX_CHILD_RUNS_PER_RUN`, read once: an integer in
/// `1..=MAX_CHILD_RUNS_PER_RUN_CEILING`. Anything else — unset, empty, zero,
/// out of range, not a number — is the default: a typo must not unbound the
/// budget, and a zero must not wedge every sub-workflow.
pub(crate) static MAX_CHILD_RUNS_PER_RUN: LazyLock<u32> = LazyLock::new(|| {
    resolve_max_child_runs(
        std::env::var("TALOS_MAX_CHILD_RUNS_PER_RUN")
            .ok()
            .as_deref(),
    )
});

pub(crate) fn resolve_max_child_runs(raw: Option<&str>) -> u32 {
    raw.and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|n| (1..=MAX_CHILD_RUNS_PER_RUN_CEILING).contains(n))
        .unwrap_or(DEFAULT_MAX_CHILD_RUNS_PER_RUN)
}

/// One root run's remaining child runs. `Clone` shares the counter.
#[derive(Clone, Debug)]
pub struct ChildRunBudget {
    remaining: Arc<AtomicU32>,
    limit: u32,
}

impl Default for ChildRunBudget {
    fn default() -> Self {
        Self::new(*MAX_CHILD_RUNS_PER_RUN)
    }
}

impl ChildRunBudget {
    /// A fresh counter of `limit` child runs, for one root run.
    #[must_use]
    pub fn new(limit: u32) -> Self {
        Self {
            remaining: Arc::new(AtomicU32::new(limit)),
            limit,
        }
    }

    /// The budget this counter started with.
    #[must_use]
    pub fn limit(&self) -> u32 {
        self.limit
    }

    /// Child runs still available to the whole tree.
    #[must_use]
    pub fn remaining(&self) -> u32 {
        self.remaining.load(Ordering::Acquire)
    }

    /// Take one child run, or refuse with the limit when none is left. Never
    /// wraps: the decrement is a compare-and-swap that stops at zero.
    pub(crate) fn take(&self) -> Result<(), u32> {
        // A compare-and-swap loop rather than `fetch_update`/`try_update`:
        // the crate's MSRV predates `try_update`, and `fetch_update` is
        // deprecated on the pinned toolchain.
        let mut current = self.remaining.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_sub(1) else {
                return Err(self.limit);
            };
            match self.remaining.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => current = actual,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_budget_is_shared_by_its_clones_and_stops_at_zero() {
        let budget = ChildRunBudget::new(2);
        let shared = budget.clone();
        assert!(budget.take().is_ok());
        assert!(shared.take().is_ok());
        assert_eq!(budget.take(), Err(2));
        assert_eq!(shared.remaining(), 0);
    }

    #[test]
    fn the_env_knob_is_bounded_and_falls_back_to_the_default() {
        assert_eq!(resolve_max_child_runs(None), DEFAULT_MAX_CHILD_RUNS_PER_RUN);
        assert_eq!(resolve_max_child_runs(Some("40")), 40);
        for bad in ["0", "-1", "", "lots", "10001", "4294967296"] {
            assert_eq!(
                resolve_max_child_runs(Some(bad)),
                DEFAULT_MAX_CHILD_RUNS_PER_RUN,
                "{bad:?}"
            );
        }
        assert_eq!(
            resolve_max_child_runs(Some("10000")),
            MAX_CHILD_RUNS_PER_RUN_CEILING
        );
    }
}
