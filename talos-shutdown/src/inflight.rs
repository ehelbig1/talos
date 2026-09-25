//! The workflow runs THIS process is driving, and the drain that waits for
//! them at shutdown.
//!
//! A workflow run is an in-process task: the engine lives in the controller
//! and dispatches each node over NATS. Until 2026-09-21 a `SIGTERM` stopped
//! the HTTP server and then `main` returned, so every run in flight died with
//! the runtime and its row stayed `running` until the stale sweep failed it
//! about an hour later (10 such rows in 30 days on the reference deployment;
//! the affected workflows normally finish in 17–115 s).
//!
//! Three things live here, and all are deliberately process-local:
//!
//! * [`InFlightRuns::track`] — called at the engine-run chokepoints. The
//!   returned guard removes the run when it drops, however the run ends, and
//!   carries the run's stop signal ([`RunGuard::stop_signal`]), which the
//!   chokepoint races against the run.
//! * [`InFlightRuns::cancel`] — an operator cancel: fires the stop signal of
//!   the run this process is driving, so the engine dispatches nothing more.
//!   Until 2026-09-25 a cancel updated the row and told the WORKERS; the
//!   engine here, which decides what is dispatched next, was never told, and
//!   kept dispatching every remaining node of the "cancelled" run.
//! * [`InFlightRuns::drain`] — waits until no run is tracked or the grace
//!   period ends, and returns what is still running so the caller can fail
//!   exactly those rows at once with an honest reason.
//!
//! **Why a registry and not a query.** `workflow_executions` records no owning
//! controller, so "every `running` row older than my start" would, at two
//! replicas, fail a sibling's live runs. A process may only speak for the runs
//! it is driving itself, and this set is that.
//!
//! **Bounded.** One entry per run in flight, and runs in flight are bounded by
//! the per-workflow and per-actor admission gates at row creation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// How long a controller waits at shutdown for the runs it is driving. The
/// container's stop timeout must exceed this (compose `stop_grace_period`,
/// the chart's `terminationGracePeriodSeconds`), or the drain is cut short by
/// `SIGKILL` and the leftover rows are never failed.
pub const RUN_DRAIN_GRACE: Duration = Duration::from_secs(120);

/// The set of runs one process is driving.
#[derive(Debug, Default)]
pub struct InFlightRuns {
    // A count per id, not a set: the same execution id can legitimately be
    // tracked twice in sequence-with-overlap (a fenced wrapper around an inner
    // run), and the outer guard dropping must not hide the inner one. The
    // overlapping trackers share ONE stop signal, so a cancel reaches both.
    runs: Mutex<HashMap<Uuid, Tracked>>,
    draining: AtomicBool,
    changed: Notify,
}

#[derive(Debug)]
struct Tracked {
    count: usize,
    stop: CancellationToken,
}

/// Removes its run from the set when dropped.
#[derive(Debug)]
#[must_use = "dropping the guard immediately un-tracks the run"]
pub struct RunGuard {
    runs: Arc<InFlightRuns>,
    execution_id: Uuid,
    stop: CancellationToken,
}

impl RunGuard {
    /// Fired by [`InFlightRuns::cancel`] for this execution. The run
    /// chokepoint races the run against it and stops the run when it fires.
    #[must_use]
    pub fn stop_signal(&self) -> CancellationToken {
        self.stop.clone()
    }
}

/// What [`InFlightRuns::drain`] saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainOutcome {
    /// Runs in flight when the drain began.
    pub at_start: usize,
    /// Runs still in flight when it ended; empty means a clean drain.
    pub remaining: Vec<Uuid>,
    /// How long the drain waited.
    pub waited: Duration,
}

impl InFlightRuns {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Track `execution_id` until the returned guard drops.
    pub fn track(self: &Arc<Self>, execution_id: Uuid) -> RunGuard {
        let stop = {
            let mut runs = self.lock();
            let tracked = runs.entry(execution_id).or_insert_with(|| Tracked {
                count: 0,
                stop: CancellationToken::new(),
            });
            tracked.count += 1;
            tracked.stop.clone()
        };
        RunGuard {
            runs: Arc::clone(self),
            execution_id,
            stop,
        }
    }

    /// Stop the run of `execution_id` if THIS process is driving it: fires
    /// the stop signal every tracker of that execution holds. Returns whether
    /// a run was tracked here — `false` means this process is not driving it
    /// (another replica is, it has not started yet, or it already ended),
    /// which the caller must report rather than claim the run was stopped.
    pub fn cancel(&self, execution_id: Uuid) -> bool {
        let stop = self.lock().get(&execution_id).map(|t| t.stop.clone());
        match stop {
            Some(stop) => {
                stop.cancel();
                true
            }
            None => false,
        }
    }

    /// Shutdown has begun: periodic starters (the scheduler) stop claiming
    /// work. Runs already admitted are still tracked and still drained.
    pub fn begin_drain(&self) {
        self.draining.store(true, Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    /// The runs in flight right now, sorted so a log line is stable.
    #[must_use]
    pub fn snapshot(&self) -> Vec<Uuid> {
        let mut ids: Vec<Uuid> = self.lock().keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// Wait until nothing is in flight or `grace` has passed.
    pub async fn drain(&self, grace: Duration) -> DrainOutcome {
        let started = Instant::now();
        let deadline = tokio::time::Instant::now() + grace;
        let at_start = self.lock().len();
        loop {
            // Arm the wake-up BEFORE reading the set, so a guard dropping
            // between the read and the wait is not missed.
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.lock().is_empty() {
                break;
            }
            if tokio::time::timeout_at(deadline, changed).await.is_err() {
                break;
            }
        }
        DrainOutcome {
            at_start,
            remaining: self.snapshot(),
            waited: started.elapsed(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, Tracked>> {
        // A panic while holding this lock cannot leave the map half-written
        // (every critical section is one map operation), so a poisoned lock
        // is still a usable one — and shutdown must not panic on it.
        self.runs.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        {
            let mut runs = self.runs.lock();
            if let Some(tracked) = runs.get_mut(&self.execution_id) {
                tracked.count -= 1;
                if tracked.count == 0 {
                    runs.remove(&self.execution_id);
                }
            }
        }
        self.runs.changed.notify_waiters();
    }
}

/// The process-wide set the engine-run chokepoints and `main` share.
#[must_use]
pub fn global() -> &'static Arc<InFlightRuns> {
    static GLOBAL: OnceLock<Arc<InFlightRuns>> = OnceLock::new();
    GLOBAL.get_or_init(InFlightRuns::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_empty_set_drains_at_once() {
        let runs = InFlightRuns::new();
        let out = runs.drain(Duration::from_secs(30)).await;
        assert_eq!((out.at_start, out.remaining.len()), (0, 0));
        assert!(out.waited < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn the_drain_returns_as_soon_as_the_last_run_ends() {
        let runs = InFlightRuns::new();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let (ga, gb) = (runs.track(a), runs.track(b));
        let ender = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(ga);
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(gb);
        });
        let out = runs.drain(Duration::from_secs(30)).await;
        ender.await.unwrap();
        assert_eq!(out.at_start, 2);
        assert!(out.remaining.is_empty(), "{:?}", out.remaining);
        assert!(
            out.waited >= Duration::from_millis(90) && out.waited < Duration::from_secs(5),
            "must wait for BOTH runs and no longer: {:?}",
            out.waited
        );
    }

    #[tokio::test]
    async fn a_run_that_outlasts_the_grace_is_named() {
        let runs = InFlightRuns::new();
        let (slow, quick) = (Uuid::new_v4(), Uuid::new_v4());
        let _held = runs.track(slow);
        drop(runs.track(quick));
        let out = runs.drain(Duration::from_millis(80)).await;
        assert_eq!(out.remaining, vec![slow], "only the run still in flight");
        assert!(out.waited >= Duration::from_millis(80));
    }

    #[tokio::test]
    async fn one_id_tracked_twice_stays_until_both_guards_drop() {
        let runs = InFlightRuns::new();
        let id = Uuid::new_v4();
        let (outer, inner) = (runs.track(id), runs.track(id));
        drop(outer);
        assert_eq!(runs.snapshot(), vec![id], "the inner run is still going");
        drop(inner);
        assert!(runs.snapshot().is_empty());
    }

    /// The drain is only as long as the container lets the process live.
    /// Every shipped stop timeout for the controller must exceed
    /// `RUN_DRAIN_GRACE` with room to fail the leftovers (package S's lesson:
    /// a cadence changed on one side of a coupling and not the other).
    #[test]
    fn every_shipped_stop_timeout_outlasts_the_drain() {
        const MARGIN_SECS: u64 = 15;
        let need = RUN_DRAIN_GRACE.as_secs() + MARGIN_SECS;

        fn controller_block(compose: &str) -> &str {
            let start = compose
                .find("\n  controller:\n")
                .expect("controller service");
            let rest = &compose[start + 1..];
            // The next two-space-indented service key ends the block.
            let end = rest[2..]
                .match_indices("\n  ")
                .find(|(i, _)| {
                    rest[2 + i + 3..]
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_alphabetic())
                })
                .map_or(rest.len(), |(i, _)| 2 + i);
            &rest[..end]
        }
        fn secs_after(hay: &str, key: &str) -> u64 {
            let at = hay.find(key).unwrap_or_else(|| panic!("`{key}` not found"));
            hay[at + key.len()..]
                .chars()
                .skip_while(|c| !c.is_ascii_digit())
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse()
                .expect("seconds")
        }

        for (name, compose) in [
            (
                "docker-compose.yml",
                include_str!("../../docker-compose.yml"),
            ),
            (
                "docker-compose.prod.yml",
                include_str!("../../docker-compose.prod.yml"),
            ),
        ] {
            let secs = secs_after(controller_block(compose), "stop_grace_period:");
            assert!(
                secs >= need,
                "{name}: controller stop_grace_period {secs}s < {need}s"
            );
        }
        let template = include_str!("../../deploy/helm/talos/templates/controller/deployment.yaml");
        let default = secs_after(template, "terminationGracePeriodSeconds | default");
        assert!(
            default >= need,
            "chart template default {default}s < {need}s"
        );
        let values = include_str!("../../deploy/helm/talos/values.yaml");
        let ctrl = &values[values.find("\ncontroller:\n").expect("controller values")..];
        let value = secs_after(ctrl, "terminationGracePeriodSeconds:");
        assert!(value >= need, "chart value {value}s < {need}s");
    }

    #[test]
    fn draining_is_off_until_begun() {
        let runs = InFlightRuns::new();
        assert!(!runs.is_draining());
        runs.begin_drain();
        assert!(runs.is_draining());
    }

    /// A run admitted after the drain began is still tracked and still waited
    /// for: refusing it here would fail a row that was just created.
    #[tokio::test]
    async fn a_run_started_during_the_drain_is_still_drained() {
        let runs = InFlightRuns::new();
        runs.begin_drain();
        let late = runs.track(Uuid::new_v4());
        let r2 = Arc::clone(&runs);
        let waiter = tokio::spawn(async move { r2.drain(Duration::from_secs(30)).await });
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            !waiter.is_finished(),
            "the drain must wait for the late run"
        );
        drop(late);
        assert!(waiter.await.unwrap().remaining.is_empty());
    }

    #[test]
    fn cancel_fires_the_stop_signal_of_the_tracked_run_only() {
        let runs = InFlightRuns::new();
        let (mine, other) = (Uuid::new_v4(), Uuid::new_v4());
        let g_mine = runs.track(mine);
        let g_other = runs.track(other);
        assert!(
            runs.cancel(mine),
            "a tracked run reports it was stopped here"
        );
        assert!(g_mine.stop_signal().is_cancelled());
        assert!(
            !g_other.stop_signal().is_cancelled(),
            "a cancel must not reach another execution's run"
        );
    }

    #[test]
    fn cancel_of_a_run_this_process_is_not_driving_says_so() {
        let runs = InFlightRuns::new();
        assert!(!runs.cancel(Uuid::new_v4()), "never tracked");
        let id = Uuid::new_v4();
        drop(runs.track(id));
        assert!(!runs.cancel(id), "already ended");
    }

    #[test]
    fn overlapping_trackers_of_one_execution_share_the_stop_signal() {
        // A fenced wrapper around an inner run tracks the same id twice; the
        // cancel must reach both, and the second guard's signal must be the
        // same one even though it was tracked after the first.
        let runs = InFlightRuns::new();
        let id = Uuid::new_v4();
        let outer = runs.track(id);
        let inner = runs.track(id);
        assert!(runs.cancel(id));
        assert!(outer.stop_signal().is_cancelled());
        assert!(inner.stop_signal().is_cancelled());
        // A LATER run of the same execution id (a resume after this one
        // ended) starts with a fresh signal.
        drop((outer, inner));
        assert!(!runs.track(id).stop_signal().is_cancelled());
    }
}
