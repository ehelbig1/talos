//! In-flight job registry: the *addressing* half of operator cancellation.
//!
//! # Why this exists
//!
//! Before this module the worker retained **nothing** that mapped a workflow
//! execution to running work. The 20 `is_cancelled()` egress guards read
//! `TalosContext::cancelled`, an `Arc<AtomicBool>` minted per job inside
//! [`crate::runtime::TalosRuntime::execute_job_with_full_features`] and owned by
//! a stack local — reachable from nowhere else in the process. So even a
//! perfectly authenticated cancel command had no handle to flip.
//!
//! The gap is an *addressing* one, and it is worth naming precisely: the
//! operator cancels an **execution**; the worker's unit of work is a **job**,
//! and one execution dispatches many jobs over its life. The mapping is not
//! reconstructible after the fact — it has to be recorded while the job runs.
//!
//! # Why it cannot leak
//!
//! Registration returns an [`InFlightGuard`] whose `Drop` removes the entry by
//! its unique registration id. `Drop` runs on every exit path of the async
//! function that holds it:
//!
//! * normal return and `?`-propagated error — ordinary scope exit;
//! * **timeout** — `worker/src/main.rs` wraps the call in
//!   `tokio::time::timeout`, which DROPS the future; dropping a future drops
//!   its locals, so the guard fires;
//! * **panic** — unwinding runs destructors. (Under `panic = "abort"` the
//!   process is gone, so there is nothing to leak into.)
//!
//! Removal is by registration id, not by execution or job id, so it is exact:
//! two concurrent registrations can never remove each other's entry even if
//! they carry identical execution and job ids.
//!
//! **The bound is the number of jobs concurrently inside
//! `execute_job_with_full_features` in this process** — in the worker binary
//! that is `TALOS_MAX_CONCURRENT_JOBS` semaphore permits. There is no TTL and
//! no sweep task, and deliberately so: an entry with no owner is not
//! reachable, because the only way to create one is to hold the guard. This is
//! the RAII shape from `talos-memory`'s `IN_FLIGHT`, which the
//! keyed-DashMap-sweep rule names as the third valid mitigation alongside
//! len-threshold cleanup and a periodic sweep.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use uuid::Uuid;

/// One registered in-flight job.
#[derive(Clone)]
struct InFlight {
    /// The `workflow_executions.id` this job belongs to — what an operator
    /// cancels.
    execution_id: Uuid,
    /// The job-scoped cancellation flag every attempt's `TalosContext` adopts.
    flag: Arc<AtomicBool>,
}

/// Process-wide registry of jobs currently executing, keyed by an internal
/// monotonic registration id.
#[derive(Default)]
pub struct CancelRegistry {
    entries: DashMap<u64, InFlight>,
    next_id: AtomicU64,
}

impl std::fmt::Debug for CancelRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Execution ids are tenant data; the count is the useful part and the
        // only part safe to render into a log line.
        f.debug_struct("CancelRegistry")
            .field("in_flight", &self.entries.len())
            .finish()
    }
}

impl CancelRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a running job and return the guard that de-registers it.
    ///
    /// Hold the guard for exactly as long as the job runs. Dropping it early
    /// makes the job un-cancellable (a silent no-op, not an error), which is
    /// why the only caller binds it to the job's own scope.
    #[must_use]
    pub fn register(&self, execution_id: Uuid, flag: Arc<AtomicBool>) -> InFlightGuard<'_> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.entries.insert(id, InFlight { execution_id, flag });
        InFlightGuard { registry: self, id }
    }

    /// Set the cancellation flag on every in-flight job belonging to
    /// `execution_id`. Returns how many jobs were flagged.
    ///
    /// **A return of 0 is the expected, non-error outcome** on every worker in
    /// the fleet that does not hold the execution — the cancel is a plain
    /// (non-queue) broadcast precisely because the controller cannot know
    /// which worker does. It is also the outcome for an execution that has
    /// already finished. Callers must not treat 0 as a failure.
    ///
    /// Idempotent: flagging an already-flagged job is a no-op store.
    pub fn cancel_execution(&self, execution_id: Uuid) -> usize {
        let mut flagged = 0usize;
        for entry in self.entries.iter() {
            if entry.execution_id == execution_id {
                entry.flag.store(true, Ordering::Relaxed);
                flagged += 1;
            }
        }
        flagged
    }

    /// Number of jobs currently registered. Exposed so a test can assert the
    /// map drains, and so the bound is observable rather than asserted.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` iff no job is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The execution id an `execution_context` tuple makes addressable, if any.
///
/// `execute_job_with_full_features` receives
/// `Option<(workflow_execution_id, job_id, module_id)>` — the worker builds it
/// from `JobRequest` in `worker/src/main.rs`. Element **0** is the
/// `workflow_executions.id`, which is what an operator cancels; element 1 is
/// the job id, which the operator never sees.
///
/// Returns `None` for a caller with no execution row (`run_sandbox` /
/// `test_module` pass `None`) or one whose first element is not a uuid: there
/// is nothing an operator could address, so registering would only grow the
/// map. Split out as a named function so the selection rule is testable
/// without standing up a runtime, and so the "element 0, not element 1"
/// choice is asserted rather than assumed.
#[must_use]
pub fn addressable_execution_id(
    execution_context: Option<&(String, String, String)>,
) -> Option<Uuid> {
    execution_context
        .and_then(|(wf_exec_id, _job_id, _module)| addressable_execution_id_str(wf_exec_id))
}

/// The same rule for callers that already hold the execution id as a string —
/// `execute_pipeline` takes `workflow_execution_id: &str` directly and has no
/// tuple to pass. One function so the two dispatch shapes cannot drift on what
/// counts as addressable.
#[must_use]
pub fn addressable_execution_id_str(workflow_execution_id: &str) -> Option<Uuid> {
    Uuid::parse_str(workflow_execution_id).ok()
}

/// De-registers its entry on `Drop`. See the module docs for why this is the
/// only removal path and why that is sufficient.
pub struct InFlightGuard<'a> {
    registry: &'a CancelRegistry,
    id: u64,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.registry.entries.remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flag() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    #[test]
    fn cancel_flags_only_the_matching_execution() {
        let reg = CancelRegistry::new();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let (fa, fb) = (flag(), flag());
        let _ga = reg.register(a, fa.clone());
        let _gb = reg.register(b, fb.clone());

        assert_eq!(reg.cancel_execution(a), 1);
        assert!(fa.load(Ordering::Relaxed));
        assert!(
            !fb.load(Ordering::Relaxed),
            "cancelling one execution must not touch another's job"
        );
    }

    #[test]
    fn every_job_of_one_execution_is_flagged() {
        let reg = CancelRegistry::new();
        let exec = Uuid::new_v4();
        let flags: Vec<_> = (0..3).map(|_| flag()).collect();
        let _guards: Vec<_> = flags
            .iter()
            .map(|f| reg.register(exec, f.clone()))
            .collect();

        assert_eq!(reg.cancel_execution(exec), 3);
        assert!(flags.iter().all(|f| f.load(Ordering::Relaxed)));
    }

    /// An unknown execution is a NO-OP, not an error. Every worker that does
    /// not hold the job takes this path on every broadcast cancel.
    #[test]
    fn cancelling_an_unknown_execution_is_a_no_op() {
        let reg = CancelRegistry::new();
        let _g = reg.register(Uuid::new_v4(), flag());
        assert_eq!(reg.cancel_execution(Uuid::new_v4()), 0);
        assert_eq!(reg.len(), 1, "a miss must not disturb the registry");
    }

    #[test]
    fn the_guard_removes_its_entry_on_scope_exit() {
        let reg = CancelRegistry::new();
        {
            let _g = reg.register(Uuid::new_v4(), flag());
            assert_eq!(reg.len(), 1);
        }
        assert!(reg.is_empty(), "the registry must drain on scope exit");
    }

    /// The leak-direction test. A panicking scope unwinds through `Drop`, so
    /// the entry must be gone — this is the path a trapping module takes.
    #[test]
    fn a_panicking_scope_still_de_registers() {
        let reg = CancelRegistry::new();
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = reg.register(Uuid::new_v4(), flag());
            assert_eq!(reg.len(), 1);
            panic!("module trapped");
        }));
        assert!(res.is_err(), "the panic must actually have happened");
        assert!(reg.is_empty(), "unwinding must not orphan an entry");
    }

    /// Dropping a pending future drops its locals — the timeout path.
    #[tokio::test]
    async fn dropping_a_timed_out_future_de_registers() {
        let reg = CancelRegistry::new();
        let fut = async {
            let _g = reg.register(Uuid::new_v4(), flag());
            // Never completes; the timeout below drops this future.
            std::future::pending::<()>().await;
        };
        let timed_out = tokio::time::timeout(std::time::Duration::from_millis(20), fut).await;
        assert!(timed_out.is_err(), "the future must have timed out");
        assert!(
            reg.is_empty(),
            "a dropped (timed-out) future must not orphan an entry"
        );
    }

    /// The tuple element the registry keys on is element 0 (the workflow
    /// EXECUTION id), not element 1 (the job id). Getting this backwards would
    /// build a registry addressed by an identifier the operator never sees —
    /// a cancel that verifies, scans, and always matches nothing.
    #[test]
    fn addressing_reads_the_execution_id_not_the_job_id() {
        let exec = Uuid::new_v4();
        let job = Uuid::new_v4();
        let ctx = (exec.to_string(), job.to_string(), "oci://m".to_string());
        assert_eq!(addressable_execution_id(Some(&ctx)), Some(exec));
        assert_ne!(addressable_execution_id(Some(&ctx)), Some(job));
    }

    /// Callers with no execution row, or a non-uuid first element, register
    /// nothing — there is nothing an operator could address, and registering
    /// would only grow the map.
    #[test]
    fn a_context_with_no_addressable_execution_registers_nothing() {
        assert_eq!(addressable_execution_id(None), None);
        let junk = (
            "not-a-uuid".to_string(),
            Uuid::new_v4().to_string(),
            "oci://m".to_string(),
        );
        assert_eq!(addressable_execution_id(Some(&junk)), None);
    }

    /// The two dispatch shapes must agree on what is addressable. The
    /// single-node path passes a tuple; `execute_pipeline` passes a bare
    /// `&str`. If these ever disagreed, cancellation would become
    /// PROTOCOL-DEPENDENT — the exact asymmetry wiring the pipeline path was
    /// meant to avoid.
    #[test]
    fn both_dispatch_shapes_agree_on_what_is_addressable() {
        let exec = Uuid::new_v4();
        let ctx = (
            exec.to_string(),
            Uuid::new_v4().to_string(),
            "m".to_string(),
        );
        assert_eq!(
            addressable_execution_id(Some(&ctx)),
            addressable_execution_id_str(&exec.to_string())
        );
        assert_eq!(addressable_execution_id_str("not-a-uuid"), None);
        assert_eq!(addressable_execution_id_str(""), None);
    }

    /// Two registrations with IDENTICAL execution and job identity must not
    /// remove each other — removal is by registration id, not by content.
    #[test]
    fn identical_registrations_do_not_remove_each_other() {
        let reg = CancelRegistry::new();
        let exec = Uuid::new_v4();
        let outer = reg.register(exec, flag());
        {
            let _inner = reg.register(exec, flag());
            assert_eq!(reg.len(), 2);
        }
        assert_eq!(reg.len(), 1, "the inner guard must remove only its own");
        drop(outer);
        assert!(reg.is_empty());
    }
}
