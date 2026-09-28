//! One dispatch attempt's wait for its reply — with the attempt window standing
//! still while the worker reports the job is queued for the local-inference
//! slot (RFC 0014 P2).
//!
//! # What changes
//!
//! Before P2 the attempt window was one `tokio::time::timeout` around the send.
//! A job that spent a minute queued behind other workflows' local inference had
//! that minute charged to its window, and the dispatcher could give up on a job
//! that was never slow — the other workflows were. Now the worker publishes a
//! signed `JobProgress` (`waiting`, then `admitted`) on `<reply_inbox>.progress`,
//! and while a `waiting` report is open the window does not run down, up to
//! `LOCAL_INFERENCE_WAIT_CREDIT_CAP_SECS` per attempt — the same cap the worker
//! applies to its own deadlines, so the controller never abandons a job the
//! worker is still legitimately holding open.
//!
//! # What does NOT change
//!
//! * **The workflow's own budget.** The extended window never passes the run's
//!   deadline less `BUDGET_RESERVE_SECS`, exactly as the clamp already bounds
//!   the window at the attempt's start. (Pausing the run budget itself is a
//!   later RFC 0014 package.)
//! * **Reports are evidence, not orders.** A report is honoured only when it
//!   parses, names THIS job and THIS attempt, verifies under the same keys and
//!   rules as the job's result, and comes from the first worker that reported
//!   for this attempt. Anything else is ignored and the window runs down as it
//!   always did — the pre-P2 behaviour is the failure mode of every refusal.
//! * **Nothing here decides the job.** A report cannot change a result, skip a
//!   gate or extend the worker's own deadlines; the worst a forged `waiting`
//!   buys is that the controller waits longer for that attempt, capped.

use std::time::{Duration, Instant};

use talos_workflow_engine_core::{
    BoxError, JobTransport, RunWaitClock, WaitAccounting, WorkerKeyRing,
};
use talos_workflow_job_protocol::{subjects, JobProgress, JobProgressState};
use uuid::Uuid;

/// The attempt's (wait-adjusted) window ran out.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AttemptElapsed {
    /// Local-inference queueing excluded from the window before it ran out.
    pub(crate) excluded: Duration,
}

/// What the dispatcher needs to judge a progress report.
pub(crate) struct ProgressCheck<'a> {
    /// The job this attempt dispatched.
    pub(crate) expected_job_id: Uuid,
    /// The exact signed payload this attempt sent. Its `dispatch_attempt` is
    /// read off it only when a report arrives (rare), so the attempt a report
    /// is checked against is, by construction, the one the worker received.
    pub(crate) sent_payload: &'a [u8],
    /// `None` only in test harnesses, exactly as for the job's result.
    pub(crate) verify_ring: Option<&'a WorkerKeyRing>,
}

/// Why a report was not applied. Never surfaced to anyone but the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProgressVerdict {
    /// The report moved the attempt's wait account.
    Applied(JobProgressState),
    /// Not for this attempt: another job, another attempt, another worker, or
    /// bytes that are not a progress report. Expected in small numbers (a late
    /// report from a previous attempt shares the inbox).
    Ignored(&'static str),
    /// It claimed to be for this attempt and failed verification.
    Refused(String),
}

/// The one field of the sent `JobRequest` a report is checked against. Read
/// with a two-field view rather than the whole request: serde skips the rest,
/// and `dispatch_attempt` is omitted on the wire when it is 0.
#[derive(serde::Deserialize)]
struct SentAttempt {
    #[serde(default)]
    dispatch_attempt: u32,
}

/// One attempt's progress state: the wait account plus the checks that decide
/// which reports may move it.
pub(crate) struct AttemptProgress {
    waits: WaitAccounting,
    /// The worker whose report was accepted first. Later reports for this
    /// attempt must come from the same worker.
    reporter: Option<String>,
    /// Read lazily off the sent payload; `None` until the first report.
    attempt: std::cell::OnceCell<Option<u32>>,
}

impl AttemptProgress {
    pub(crate) fn new(waits: WaitAccounting) -> Self {
        Self {
            waits,
            reporter: None,
            attempt: std::cell::OnceCell::new(),
        }
    }

    /// The window's deadline as of `now`: `base` pushed back by the reported
    /// queueing, never past `limit` (the run's deadline less the reserve).
    pub(crate) fn deadline(&self, base: Instant, limit: Option<Instant>, now: Instant) -> Instant {
        let d = self.waits.deadline(base, now);
        match limit {
            Some(l) => d.min(l.max(base)),
            None => d,
        }
    }

    pub(crate) fn excluded(&self, now: Instant) -> Duration {
        self.waits.excluded(now)
    }

    fn sent_attempt(&self, payload: &[u8]) -> Option<u32> {
        *self.attempt.get_or_init(|| {
            serde_json::from_slice::<SentAttempt>(payload)
                .ok()
                .map(|r| r.dispatch_attempt)
        })
    }

    /// Judge one raw report and, if it is admissible, apply it at `now`.
    ///
    /// Check order mirrors the result path: identity before signature, so a
    /// stray report never records its nonce into this process's replay cache.
    pub(crate) fn apply(
        &mut self,
        bytes: &[u8],
        check: &ProgressCheck<'_>,
        now: Instant,
    ) -> ProgressVerdict {
        let Ok(report) = serde_json::from_slice::<JobProgress>(bytes) else {
            return ProgressVerdict::Ignored("not a progress report");
        };
        if report.job_id != check.expected_job_id {
            return ProgressVerdict::Ignored("another job");
        }
        match self.sent_attempt(check.sent_payload) {
            Some(a) if a == report.dispatch_attempt => {}
            Some(_) => return ProgressVerdict::Ignored("another attempt"),
            None => return ProgressVerdict::Ignored("sent payload has no readable attempt"),
        }
        if let Some(pinned) = &self.reporter {
            if pinned != &report.worker_id {
                return ProgressVerdict::Ignored("another worker");
            }
        }
        if let Some(ring) = check.verify_ring {
            let keys = talos_workflow_job_protocol::worker_public_keys(&report.worker_id);
            if let Err(e) = report.verify_dispatch(
                ring,
                &keys,
                300,
                talos_workflow_job_protocol::result_accept_legacy_hmac(),
            ) {
                return ProgressVerdict::Refused(e.to_string());
            }
        }
        self.reporter
            .get_or_insert_with(|| report.worker_id.clone());
        match report.state {
            JobProgressState::Waiting => self.waits.begin(now),
            JobProgressState::Admitted => self.waits.end(now),
        }
        ProgressVerdict::Applied(report.state)
    }
}

/// The clock every instant here is read from: tokio's, as `std`. In production
/// the two are the same clock; under a paused test clock only tokio's moves,
/// and the timers below sleep on it.
pub(crate) fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// The run's LIVE deadline: the stamped one pushed back by the run's excluded
/// local-inference queueing (RFC 0014 P2b). One home, shared by the attempt
/// clamp and the attempt window.
pub(crate) fn live_run_deadline(
    stamped: Option<Instant>,
    waits: Option<&RunWaitClock>,
) -> Option<Instant> {
    stamped.map(|d| match waits {
        Some(w) => w.deadline(d, now()),
        None => d,
    })
}

/// What bounds an attempt from ABOVE: the run's deadline less the reserve,
/// re-read live every time the window is evaluated (P2b), so the run's own
/// pause lets the attempt run on.
pub(crate) struct RunLimit<'a> {
    /// The run's STAMPED deadline; `None` when the run has no cap.
    pub(crate) deadline: Option<Instant>,
    pub(crate) reserve: Duration,
    /// The run's waiting account; this attempt's verified waits are reported
    /// here too, keyed by the job id.
    pub(crate) waits: Option<&'a RunWaitClock>,
}

impl RunLimit<'_> {
    fn at(&self) -> Option<Instant> {
        live_run_deadline(self.deadline, self.waits)
            .map(|d| d.checked_sub(self.reserve).unwrap_or(d))
    }
}

/// Send one attempt and wait for its reply under a window of `attempt_secs`,
/// paused while the worker reports the job is queued for local inference.
///
/// `limit` is the run's deadline less the reserve (`None` when the run has no
/// budget). Without a reply inbox there is no progress channel, and this is
/// exactly the old `tokio::time::timeout` around `request`.
pub(crate) async fn await_attempt(
    transport: &dyn JobTransport,
    topic: &str,
    reply_inbox: Option<&str>,
    payload: Vec<u8>,
    attempt_secs: u64,
    limit: RunLimit<'_>,
    check: ProgressCheck<'_>,
) -> Result<Result<Vec<u8>, BoxError>, AttemptElapsed> {
    let window = Duration::from_secs(attempt_secs);
    let Some(inbox) = reply_inbox else {
        return tokio::time::timeout(window, transport.request(topic, payload))
            .await
            .map_err(|_| AttemptElapsed {
                excluded: Duration::ZERO,
            });
    };

    // Reports are rare (one pair per queued LLM call); a small bound keeps a
    // flood from a fleet-key holder from growing memory, and a report dropped
    // here fails safe (the window runs down as before).
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
    let on_progress = move |bytes: Vec<u8>| {
        let _ = tx.try_send(bytes);
    };
    let progress_subject = subjects::job_progress_for(inbox);
    let send = transport.request_with_reply_inbox_and_progress(
        topic,
        inbox,
        &progress_subject,
        payload,
        &on_progress,
    );
    tokio::pin!(send);

    let base = now() + window;
    let mut progress = AttemptProgress::new(WaitAccounting::new());
    let outcome = loop {
        let deadline = progress.deadline(base, limit.at(), now());
        tokio::select! {
            reply = &mut send => break Ok(reply),
            Some(bytes) = rx.recv() => {
                let verdict = progress.apply(&bytes, &check, now());
                // RFC 0014 P2b: a VERIFIED report also moves the run's clock,
                // so the run's budget and its siblings' windows see the wait.
                if let (ProgressVerdict::Applied(state), Some(run)) = (&verdict, limit.waits) {
                    match state {
                        JobProgressState::Waiting => run.begin(check.expected_job_id, now()),
                        JobProgressState::Admitted => run.end(check.expected_job_id, now()),
                    }
                }
                log_verdict(&verdict, &check, progress.excluded(now()));
            }
            () = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                let now = now();
                if now >= progress.deadline(base, limit.at(), now) {
                    break Err(AttemptElapsed { excluded: progress.excluded(now) });
                }
            }
        }
    };
    // However the attempt ended, this job is no longer waiting: a lost
    // `admitted` must not hold the RUN open (it cannot hold the attempt open,
    // which has just ended). Idempotent when the wait was already closed.
    if let Some(run) = limit.waits {
        run.end(check.expected_job_id, now());
    }
    outcome
}

fn log_verdict(verdict: &ProgressVerdict, check: &ProgressCheck<'_>, excluded: Duration) {
    let job_id = check.expected_job_id;
    match verdict {
        ProgressVerdict::Applied(JobProgressState::Waiting) => tracing::info!(
            job_id = %job_id,
            event_kind = "attempt_paused_for_local_inference",
            "job is queued for the local-inference slot; attempt window paused"
        ),
        ProgressVerdict::Applied(JobProgressState::Admitted) => tracing::info!(
            job_id = %job_id,
            event_kind = "attempt_resumed_after_local_inference",
            excluded_ms = excluded.as_millis() as u64,
            "job has the local-inference slot; attempt window running again"
        ),
        ProgressVerdict::Ignored(why) => tracing::debug!(
            job_id = %job_id,
            reason = why,
            "job progress report ignored"
        ),
        ProgressVerdict::Refused(e) => tracing::warn!(
            target: "talos_security",
            job_id = %job_id,
            error = %e,
            "job progress report refused at verification; attempt window not paused"
        ),
    }
}

#[cfg(test)]
#[path = "attempt_wait_tests.rs"]
mod tests;
