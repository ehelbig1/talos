//! WHICH id space the WORM ledger is keyed by, and how per-job outcomes roll
//! up to the workflow execution an operator actually asks about.
//!
//! # The binding, established rather than assumed
//!
//! An [`ExecutionLedger`](talos_audit_event::ExecutionLedger) is constructed
//! ONCE per module dispatch, in the worker
//! (`talos-worker-runtime/src/runtime.rs`), from the `execution_context`
//! tuple that `worker/src/main.rs` builds as
//! `(req.workflow_execution_id, req.job_id, req.module_uri)`. So:
//!
//! | ledger field | wire field | DB column |
//! |---|---|---|
//! | `ExecutionLedger::workflow_id` | `JobRequest::workflow_execution_id` | `module_executions.workflow_execution_id` (= `workflow_executions.id`) |
//! | `ExecutionLedger::execution_id` | `JobRequest::job_id` | `module_executions.id` |
//!
//! `job_id` is not merely correlated with `module_executions.id` — it IS that
//! id: `engine_dispatch_single.rs` mints `let job_id = Uuid::new_v4()` and
//! passes it as `ExecutionStartedContext { id: job_id, .. }`, i.e. the primary
//! key of the row it then inserts.
//!
//! The S3 object key is `format!("{execution_id}/{min}_{max}_{nanos}.jsonl")`
//! over the audit EVENT's `execution_id` field — the ledger's, therefore the
//! module execution's. **The ledger is keyed PER JOB.**
//!
//! `verify_chain` re-derives the genesis hash from BOTH halves, so naming the
//! wrong `workflow_id` is not a near miss: it is a genesis mismatch and a
//! reported break.
//!
//! # Measured, both directions, live 2026-09-06
//!
//! * 200 of 200 most-recent settled `module_executions` ids ARE ledger
//!   prefixes; **0 empty**.
//! * 0 of 200 most-recent settled `workflow_executions` ids are ledger
//!   prefixes.
//! * 200 of 200 newest ledger prefixes resolve to a `module_executions` row;
//!   0 resolve to a `workflow_executions` row.
//! * Driving the REAL `verify_execution_chain` against the live store with
//!   read-capable credentials: the pair
//!   `(module_executions.workflow_execution_id, module_executions.id)` returns
//!   `ok=true total_events=1 breaks=0 sigs_checked=true` (6 of 6 sampled); the
//!   pair `(workflow_executions.workflow_id, module_executions.id)` — the
//!   binding a reader would guess from the field NAME `workflow_id` — returns
//!   `ok=false breaks=1`; and the pre-fix sweep's own shape
//!   (`workflow_executions.id` as the prefix) returns
//!   `ok=true total_events=0`, the "verified nothing" answer.
//!
//! That third line is why the population fix is part of the identity fix and
//! not a follow-up: with the credentials repaired and the id space left alone,
//! every pass would have reported perfect health while reading nothing.
//!
//! # Why the roll-up exists
//!
//! An operator asks "did execution X's audit trail verify?", and X is a
//! workflow execution — the thing `list_executions` returns and the thing
//! every other report is keyed on. The ledger cannot answer at that grain,
//! because it does not exist at that grain. So the sweep verifies at the grain
//! the writer keys (per job) and ROLLS UP to the grain the operator asks at,
//! WORST OUTCOME WINS: one broken chain among a workflow execution's four jobs
//! makes that workflow execution's audit trail broken, not three-quarters
//! clean.

use std::collections::HashMap;
use uuid::Uuid;

/// The id space the WORM ledger's object keys are drawn from, as a string an
/// operator-facing report can print. Named here so the report and the query
/// cannot drift into disagreeing about what was verified.
pub const LEDGER_KEY_SPACE: &str = "module_executions.id";

/// The DB column supplying the genesis `workflow_id` half of the binding.
pub const LEDGER_GENESIS_WORKFLOW_COLUMN: &str = "module_executions.workflow_execution_id";

/// One verifiable chain: a module execution and the workflow execution it ran
/// under.
///
/// Both halves are required and neither is optional, because `verify_chain`
/// needs both to re-derive the genesis hash. A module execution with a NULL
/// `workflow_execution_id` therefore cannot be represented — see
/// [`ChainSweepStats::unbound`](crate::ChainSweepStats::unbound) for how the
/// sweep reports those rather than silently dropping them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerTarget {
    /// `module_executions.id` — the S3 prefix AND the ledger's `execution_id`.
    pub module_execution_id: Uuid,
    /// `module_executions.workflow_execution_id` — the ledger's `workflow_id`.
    pub workflow_execution_id: Uuid,
}

impl LedgerTarget {
    /// The ledger's `execution_id` half, as `verify_execution_chain` wants it.
    #[must_use]
    pub fn execution_id(&self) -> String {
        self.module_execution_id.to_string()
    }

    /// The ledger's `workflow_id` half. Named `genesis_workflow_id` and not
    /// `workflow_id` on purpose: the value is a WORKFLOW EXECUTION id, and the
    /// field it feeds is called `workflow_id`, which is exactly the confusion
    /// that made the guessed binding above return `ok=false`.
    #[must_use]
    pub fn genesis_workflow_id(&self) -> String {
        self.workflow_execution_id.to_string()
    }
}

/// Split the enumeration's rows into verifiable targets and a COUNT of the
/// jobs that have no genesis pair.
///
/// Extracted for one reason, and it is a measured one rather than a stylistic
/// one: the increment lived inside `run_chain_verification_sweep`, which needs
/// an S3 endpoint, so no test in this workspace could drive it — deleting
/// `stats.unbound += 1` left all 43 ledger tests and all 84 security-audit
/// tests green (mutation M-E). A row silently dropped and a row counted as
/// unattempted are the same code path away from each other, and "we did not
/// look" arriving inside a clean count is precisely the class this change is
/// about.
///
/// Returns `(targets, unbound)` rather than filtering, so the caller cannot
/// obtain the targets without also being handed the number it must disclose.
#[must_use]
pub fn partition_sweep_rows(rows: &[(Uuid, Option<Uuid>)]) -> (Vec<LedgerTarget>, usize) {
    let mut targets = Vec::with_capacity(rows.len());
    let mut unbound = 0usize;
    for (module_execution_id, workflow_execution_id) in rows {
        match workflow_execution_id {
            Some(workflow_execution_id) => targets.push(LedgerTarget {
                module_execution_id: *module_execution_id,
                workflow_execution_id: *workflow_execution_id,
            }),
            None => unbound += 1,
        }
    }
    (targets, unbound)
}

/// What verifying ONE job's chain produced, ordered by SEVERITY.
///
/// The `Ord` derive is load-bearing: the roll-up is a `max` over a workflow
/// execution's jobs, so the declaration order IS the precedence and reordering
/// these variants silently changes what a mixed group reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum JobChainOutcome {
    /// Read back, at least one event, no breaks.
    VerifiedOk,
    /// Read cleanly, ZERO events — not verified, see
    /// [`ChainVerifyErrorKind::EmptyChain`](crate::ChainVerifyErrorKind::EmptyChain).
    Empty,
    /// Could not be read at all.
    Errored,
    /// Read back and DID NOT verify. Tamper evidence.
    Failed,
}

/// The sweep's per-job tally lifted to the grain operators ask at.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WorkflowExecutionRollup {
    /// Distinct workflow executions represented by the jobs that were checked.
    pub covered: usize,
    /// Every job of this workflow execution verified with at least one event.
    pub verified_ok: usize,
    /// No job failed or errored, and at least one read cleanly and empty.
    pub empty: usize,
    /// No job failed, and at least one could not be read.
    pub errored: usize,
    /// At least one job's chain DID NOT verify.
    pub failed: usize,
}

/// Roll per-job outcomes up to their workflow executions, worst outcome wins.
///
/// Pure and order-independent (`max` over each group), so the sweep's
/// classification is testable without Postgres or an object store — which is
/// the whole reason it is a free function rather than a loop body.
#[must_use]
pub fn roll_up_by_workflow_execution(jobs: &[(Uuid, JobChainOutcome)]) -> WorkflowExecutionRollup {
    let mut worst: HashMap<Uuid, JobChainOutcome> = HashMap::new();
    for (wf_exec, outcome) in jobs {
        worst
            .entry(*wf_exec)
            .and_modify(|w| {
                if *outcome > *w {
                    *w = *outcome;
                }
            })
            .or_insert(*outcome);
    }
    let mut rollup = WorkflowExecutionRollup {
        covered: worst.len(),
        ..WorkflowExecutionRollup::default()
    };
    for outcome in worst.values() {
        match outcome {
            JobChainOutcome::VerifiedOk => rollup.verified_ok += 1,
            JobChainOutcome::Empty => rollup.empty += 1,
            JobChainOutcome::Errored => rollup.errored += 1,
            JobChainOutcome::Failed => rollup.failed += 1,
        }
    }
    rollup
}

#[cfg(test)]
mod rollup_tests {
    use super::*;

    fn u(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn an_empty_input_rolls_up_to_nothing() {
        assert_eq!(
            roll_up_by_workflow_execution(&[]),
            WorkflowExecutionRollup::default()
        );
    }

    /// The mutation the sweep's DB test cannot cheaply reach: a workflow
    /// execution whose FOUR jobs are three clean and one broken is BROKEN.
    /// Dropping the failed job (or letting the last-seen outcome win) makes
    /// this read `verified_ok: 1`, which is the "three quarters clean" claim
    /// the roll-up exists to refuse.
    #[test]
    fn one_broken_job_makes_its_workflow_execution_broken() {
        let jobs = [
            (u(1), JobChainOutcome::VerifiedOk),
            (u(1), JobChainOutcome::VerifiedOk),
            (u(1), JobChainOutcome::Failed),
            (u(1), JobChainOutcome::VerifiedOk),
        ];
        let rollup = roll_up_by_workflow_execution(&jobs);
        assert_eq!(rollup.covered, 1);
        assert_eq!(rollup.failed, 1, "a broken job must not be averaged away");
        assert_eq!(rollup.verified_ok, 0);
        assert_eq!(rollup.empty, 0);
        assert_eq!(rollup.errored, 0);
    }

    /// Order must not decide the verdict — the sweep visits jobs in
    /// `completed_at DESC` order, which is not grouped by workflow execution.
    #[test]
    fn the_verdict_does_not_depend_on_visit_order() {
        let forward = [
            (u(7), JobChainOutcome::Failed),
            (u(7), JobChainOutcome::VerifiedOk),
        ];
        let reverse = [
            (u(7), JobChainOutcome::VerifiedOk),
            (u(7), JobChainOutcome::Failed),
        ];
        assert_eq!(
            roll_up_by_workflow_execution(&forward),
            roll_up_by_workflow_execution(&reverse)
        );
        assert_eq!(roll_up_by_workflow_execution(&forward).failed, 1);
    }

    /// Severity precedence, stated as a test rather than as a comment:
    /// Failed > Errored > Empty > VerifiedOk.
    #[test]
    fn severity_precedence_is_failed_errored_empty_verified() {
        assert!(JobChainOutcome::Failed > JobChainOutcome::Errored);
        assert!(JobChainOutcome::Errored > JobChainOutcome::Empty);
        assert!(JobChainOutcome::Empty > JobChainOutcome::VerifiedOk);

        // An unreadable job outranks an empty one: "we could not look" is a
        // worse answer about a workflow execution than "one of its jobs
        // emitted nothing".
        let mixed = [
            (u(2), JobChainOutcome::Empty),
            (u(2), JobChainOutcome::Errored),
        ];
        assert_eq!(roll_up_by_workflow_execution(&mixed).errored, 1);
        assert_eq!(roll_up_by_workflow_execution(&mixed).empty, 0);
    }

    /// Distinct workflow executions are counted separately and keep their own
    /// verdicts — a broken chain in one must not contaminate the other.
    #[test]
    fn groups_are_independent() {
        let jobs = [
            (u(1), JobChainOutcome::VerifiedOk),
            (u(2), JobChainOutcome::Failed),
            (u(3), JobChainOutcome::Empty),
            (u(3), JobChainOutcome::VerifiedOk),
            (u(4), JobChainOutcome::Errored),
        ];
        let rollup = roll_up_by_workflow_execution(&jobs);
        assert_eq!(rollup.covered, 4);
        assert_eq!(rollup.verified_ok, 1);
        assert_eq!(rollup.failed, 1);
        assert_eq!(rollup.empty, 1);
        assert_eq!(rollup.errored, 1);
        assert_eq!(
            rollup.verified_ok + rollup.failed + rollup.empty + rollup.errored,
            rollup.covered,
            "every covered workflow execution lands in exactly one bucket"
        );
    }

    /// A job with no workflow execution is COUNTED, not dropped.
    ///
    /// This test exists because the mutation it guards SURVIVED everything
    /// else: with the increment inside the S3-dependent sweep loop, deleting
    /// it left 43 + 84 tests green. Partitioning is where the fact is decided,
    /// so partitioning is where it is pinned.
    #[test]
    fn an_unbound_job_is_counted_not_dropped() {
        let rows = [
            (u(1), Some(u(100))),
            (u(2), None),
            (u(3), Some(u(100))),
            (u(4), None),
        ];
        let (targets, unbound) = partition_sweep_rows(&rows);
        assert_eq!(unbound, 2, "an unattempted job must be COUNTED");
        assert_eq!(targets.len(), 2);
        assert_eq!(
            targets.len() + unbound,
            rows.len(),
            "every enumerated row is either verified or disclosed; none vanishes"
        );
        assert_eq!(targets[0].module_execution_id, u(1));
        assert_eq!(targets[0].workflow_execution_id, u(100));
    }

    /// Order is preserved, because the sweep's `completed_at DESC` ordering is
    /// what makes its row cap take the NEWEST jobs — reordering here would
    /// silently change which rows a capped pass drops.
    #[test]
    fn partitioning_preserves_the_enumeration_order() {
        let rows = [(u(3), Some(u(9))), (u(1), Some(u(9))), (u(2), Some(u(9)))];
        let (targets, _) = partition_sweep_rows(&rows);
        let ids: Vec<Uuid> = targets.iter().map(|t| t.module_execution_id).collect();
        assert_eq!(ids, vec![u(3), u(1), u(2)]);
    }

    /// The binding, pinned as a value rather than as prose: `execution_id` is
    /// the MODULE execution (and therefore the S3 prefix) and
    /// `genesis_workflow_id` is the WORKFLOW execution. Swapping them is the
    /// mistake the live probe measured as `ok=false`.
    #[test]
    fn the_target_names_the_module_execution_as_the_prefix() {
        let target = LedgerTarget {
            module_execution_id: u(11),
            workflow_execution_id: u(22),
        };
        assert_eq!(target.execution_id(), u(11).to_string());
        assert_eq!(target.genesis_workflow_id(), u(22).to_string());
        assert_eq!(LEDGER_KEY_SPACE, "module_executions.id");
    }
}
