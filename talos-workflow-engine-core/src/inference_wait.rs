//! Time spent WAITING for the local-inference slot is not charged to a job's
//! deadlines — RFC 0014 P2, and **the one home for that arithmetic**.
//!
//! # Why
//!
//! A worker serializes its local (Ollama) LLM calls through a gate, because the
//! backend serves one request at a time and concurrency there is pure overhead.
//! When several workflows start together, a call can spend a minute in that
//! queue behind other runs' inference. Every deadline a job has — the worker's
//! own job timeout, the wasmtime wall-clock bound and the controller's attempt
//! window — measured that minute as if the job had been working, so a job
//! could fail because OTHER workflows existed. Measured over 30 days: 94 % of
//! local calls waited under 10 ms, ~56 waited over 30 s and 9 over 60 s, every
//! long wait inside a scheduled herd (the 06:00, 07:00 and 08:00 starts).
//!
//! The rule: **deadlines measure work; waiting has its own bound.** While a job
//! is waiting for the slot its deadlines stand still, up to
//! [`LOCAL_INFERENCE_WAIT_CREDIT_CAP_SECS`] in total.
//!
//! # Two clocks, one rule
//!
//! The worker measures the wait on its own clock, from the moment the call
//! queues to the moment the slot is granted (or the queue wait expires). The
//! controller cannot see the worker's clock; it measures the same interval on
//! ITS clock, from receipt of the signed `waiting` progress message to receipt
//! of `admitted` (or the result). The two intervals differ by the delivery
//! latency of two NATS messages, which the dispatcher's existing grace absorbs.
//! Both clocks use THIS type so they cannot disagree about the rule, and both
//! cap at the same constant, so the controller can never give up on a job the
//! worker is still legitimately holding open.
//!
//! # Why a cap
//!
//! Without one, a job that made many local calls in a busy period could hold a
//! worker slot, and the controller's attention, indefinitely. The cap also bounds
//! what a party holding the fleet signing key could achieve by forging
//! `waiting` messages: at most this much extra patience for one attempt.

use std::time::{Duration, Instant};

/// The most waiting-for-the-slot time excluded from one job's deadlines.
///
/// 300 s. One gated call waits at most `LOCAL_LLM_QUEUE_WAIT_SECS` (120 s)
/// before it proceeds ungated; the longest wait observed in 30 days of the
/// reference fleet was under that, and a job making two or three local calls in
/// one herd can queue for each. 300 s covers that without letting a job's
/// lifetime run away: past the cap the job's own deadlines tick again.
///
/// Shared by the worker and the controller on purpose — see the module docs.
pub const LOCAL_INFERENCE_WAIT_CREDIT_CAP_SECS: u64 = 300;

/// Accumulated waiting time, as a pure function of the instants it is told
/// about. No clock of its own, so it is exact under test.
///
/// `begin` / `end` are idempotent: a duplicated or reordered notification
/// cannot open two intervals or close one twice. An interval still open counts
/// up to `now`.
#[derive(Debug, Clone)]
pub struct WaitAccounting {
    cap: Duration,
    closed: Duration,
    open_since: Option<Instant>,
}

impl WaitAccounting {
    /// Accounting capped at [`LOCAL_INFERENCE_WAIT_CREDIT_CAP_SECS`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_cap(Duration::from_secs(LOCAL_INFERENCE_WAIT_CREDIT_CAP_SECS))
    }

    /// Accounting with an explicit cap (tests).
    #[must_use]
    pub fn with_cap(cap: Duration) -> Self {
        Self {
            cap,
            closed: Duration::ZERO,
            open_since: None,
        }
    }

    /// The job started waiting at `now`. A second `begin` while already
    /// waiting changes nothing.
    pub fn begin(&mut self, now: Instant) {
        if self.open_since.is_none() {
            self.open_since = Some(now);
        }
    }

    /// The job stopped waiting at `now`. Without an open interval, nothing
    /// changes.
    pub fn end(&mut self, now: Instant) {
        if let Some(since) = self.open_since.take() {
            self.closed = self
                .closed
                .saturating_add(now.saturating_duration_since(since));
        }
    }

    /// Whether an interval is open.
    #[must_use]
    pub fn is_waiting(&self) -> bool {
        self.open_since.is_some()
    }

    /// Waiting time excluded from the deadlines as of `now`, capped.
    #[must_use]
    pub fn excluded(&self, now: Instant) -> Duration {
        let open = self
            .open_since
            .map_or(Duration::ZERO, |since| now.saturating_duration_since(since));
        self.closed.saturating_add(open).min(self.cap)
    }

    /// `base` pushed back by the excluded waiting time as of `now`.
    #[must_use]
    pub fn deadline(&self, base: Instant, now: Instant) -> Instant {
        base + self.excluded(now)
    }
}

impl Default for WaitAccounting {
    fn default() -> Self {
        Self::new()
    }
}

/// One RUN's waiting account: the union of its jobs' reported waits, measured
/// on the controller's clock — RFC 0014 P2b.
///
/// A run's wall-clock budget stands still while ANY of its jobs is queued for
/// the local-inference slot, and runs again once none is. Two parallel branches
/// queued at the same time pause the budget once, not twice: the run lost that
/// interval once. Capped at [`LOCAL_INFERENCE_WAIT_CREDIT_CAP_SECS`] per run,
/// the same cap as a job, so a busy period can hold a run open at most that much
/// longer than its budget.
///
/// **Sub-workflows.** A child run gets its own clock with its parent's as
/// `parent`; every `begin`/`end` is forwarded, keyed by the same job id, so the
/// parent's budget pauses while the child's job waits. Job ids are unique across
/// runs, so forwarded waits cannot collide with the parent's own.
///
/// `begin` / `end` are keyed and idempotent: a duplicated report cannot open two
/// intervals, and `end` for a job that is not waiting changes nothing.
#[derive(Debug)]
pub struct RunWaitClock {
    parent: Option<std::sync::Arc<RunWaitClock>>,
    state: std::sync::Mutex<RunWaits>,
}

#[derive(Debug)]
struct RunWaits {
    waiting: std::collections::HashSet<uuid::Uuid>,
    account: WaitAccounting,
}

impl RunWaitClock {
    /// A run clock with the production cap, forwarding to `parent` if any.
    #[must_use]
    pub fn new(parent: Option<std::sync::Arc<RunWaitClock>>) -> Self {
        Self::with_account(WaitAccounting::new(), parent)
    }

    /// A run clock over explicit accounting (tests set a small cap).
    #[must_use]
    pub fn with_account(
        account: WaitAccounting,
        parent: Option<std::sync::Arc<RunWaitClock>>,
    ) -> Self {
        Self {
            parent,
            state: std::sync::Mutex::new(RunWaits {
                waiting: std::collections::HashSet::new(),
                account,
            }),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, RunWaits> {
        // Nothing below can panic while holding the lock; recover rather than
        // turn a deadline read into a run failure.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// `job` started waiting at `now`.
    pub fn begin(&self, job: uuid::Uuid, now: Instant) {
        {
            let mut s = self.state();
            if s.waiting.insert(job) && s.waiting.len() == 1 {
                s.account.begin(now);
            }
        }
        if let Some(p) = &self.parent {
            p.begin(job, now);
        }
    }

    /// `job` stopped waiting at `now` (also called when its attempt ends, so a
    /// lost `admitted` cannot hold the run open).
    pub fn end(&self, job: uuid::Uuid, now: Instant) {
        {
            let mut s = self.state();
            if s.waiting.remove(&job) && s.waiting.is_empty() {
                s.account.end(now);
            }
        }
        if let Some(p) = &self.parent {
            p.end(job, now);
        }
    }

    /// The run's excluded waiting time as of `now`, capped.
    #[must_use]
    pub fn excluded(&self, now: Instant) -> Duration {
        self.state().account.excluded(now)
    }

    /// `base` (the run's stamped deadline) pushed back by the excluded time.
    #[must_use]
    pub fn deadline(&self, base: Instant, now: Instant) -> Instant {
        base + self.excluded(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(t0: Instant, secs: u64) -> Instant {
        t0 + Duration::from_secs(secs)
    }

    #[test]
    fn no_wait_leaves_the_deadline_where_it_was() {
        let t0 = Instant::now();
        let w = WaitAccounting::new();
        assert_eq!(w.deadline(at(t0, 120), at(t0, 500)), at(t0, 120));
        assert!(!w.is_waiting());
    }

    #[test]
    fn a_closed_wait_moves_the_deadline_by_exactly_its_length() {
        let t0 = Instant::now();
        let mut w = WaitAccounting::new();
        w.begin(at(t0, 10));
        w.end(at(t0, 70));
        assert_eq!(w.excluded(at(t0, 1000)), Duration::from_secs(60));
        assert_eq!(w.deadline(at(t0, 120), at(t0, 1000)), at(t0, 180));
    }

    #[test]
    fn an_open_wait_holds_the_deadline_still_while_it_lasts() {
        let t0 = Instant::now();
        let mut w = WaitAccounting::new();
        w.begin(at(t0, 100));
        // However long the wait runs, the job is always 20 s from its deadline.
        for now in [100, 150, 250, 350] {
            assert_eq!(
                w.deadline(at(t0, 120), at(t0, now)),
                at(t0, now + 20),
                "at t={now}"
            );
        }
    }

    #[test]
    fn several_waits_add_up() {
        let t0 = Instant::now();
        let mut w = WaitAccounting::new();
        w.begin(at(t0, 0));
        w.end(at(t0, 30));
        w.begin(at(t0, 50));
        w.end(at(t0, 95));
        assert_eq!(w.excluded(at(t0, 200)), Duration::from_secs(75));
    }

    #[test]
    fn duplicate_and_orphan_notifications_change_nothing() {
        let t0 = Instant::now();
        let mut w = WaitAccounting::new();
        w.end(at(t0, 5)); // end with nothing open
        w.begin(at(t0, 10));
        w.begin(at(t0, 40)); // a second begin does not restart the interval
        w.end(at(t0, 70));
        w.end(at(t0, 90)); // a second end does not extend it
        assert_eq!(w.excluded(at(t0, 200)), Duration::from_secs(60));
    }

    #[test]
    fn the_credit_never_exceeds_the_cap() {
        let t0 = Instant::now();
        let mut w = WaitAccounting::with_cap(Duration::from_secs(50));
        w.begin(at(t0, 0));
        w.end(at(t0, 40));
        w.begin(at(t0, 100));
        // Open for 900 s, closed 40 s: capped at 50 s either way.
        assert_eq!(w.excluded(at(t0, 1000)), Duration::from_secs(50));
        w.end(at(t0, 1000));
        assert_eq!(w.excluded(at(t0, 2000)), Duration::from_secs(50));
    }

    fn job(n: u128) -> uuid::Uuid {
        uuid::Uuid::from_u128(n)
    }

    #[test]
    fn a_run_pauses_while_any_of_its_jobs_waits_and_counts_overlap_once() {
        let t0 = Instant::now();
        let run = RunWaitClock::new(None);
        run.begin(job(1), at(t0, 10));
        run.begin(job(2), at(t0, 20)); // overlaps job 1
        run.end(job(1), at(t0, 40));
        assert_eq!(
            run.excluded(at(t0, 50)),
            Duration::from_secs(40),
            "still open via job 2"
        );
        run.end(job(2), at(t0, 60));
        // The union is 10..60: 50 s, not 30 + 40.
        assert_eq!(run.excluded(at(t0, 500)), Duration::from_secs(50));
        assert_eq!(run.deadline(at(t0, 300), at(t0, 500)), at(t0, 350));
    }

    #[test]
    fn duplicate_and_unknown_job_reports_change_nothing_on_a_run() {
        let t0 = Instant::now();
        let run = RunWaitClock::new(None);
        run.end(job(9), at(t0, 1));
        run.begin(job(1), at(t0, 10));
        run.begin(job(1), at(t0, 20));
        run.end(job(9), at(t0, 30)); // another job ending does not close job 1's wait
        run.end(job(1), at(t0, 40));
        run.end(job(1), at(t0, 90));
        assert_eq!(run.excluded(at(t0, 100)), Duration::from_secs(30));
    }

    #[test]
    fn a_child_run_forwards_its_waits_to_its_parent() {
        let t0 = Instant::now();
        let parent = std::sync::Arc::new(RunWaitClock::new(None));
        let child = RunWaitClock::new(Some(parent.clone()));
        parent.begin(job(1), at(t0, 0));
        child.begin(job(2), at(t0, 5));
        parent.end(job(1), at(t0, 10)); // parent still waiting via the child's job
        child.end(job(2), at(t0, 30));
        assert_eq!(child.excluded(at(t0, 100)), Duration::from_secs(25));
        assert_eq!(parent.excluded(at(t0, 100)), Duration::from_secs(30));
    }

    #[test]
    fn a_run_is_capped_like_a_job() {
        let t0 = Instant::now();
        let run =
            RunWaitClock::with_account(WaitAccounting::with_cap(Duration::from_secs(20)), None);
        run.begin(job(1), t0);
        assert_eq!(run.excluded(at(t0, 1000)), Duration::from_secs(20));
    }

    #[test]
    fn the_production_cap_is_the_shared_constant() {
        let t0 = Instant::now();
        let mut w = WaitAccounting::new();
        w.begin(t0);
        assert_eq!(
            w.excluded(t0 + Duration::from_secs(10_000)),
            Duration::from_secs(LOCAL_INFERENCE_WAIT_CREDIT_CAP_SECS)
        );
    }
}
