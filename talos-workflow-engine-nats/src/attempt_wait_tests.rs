//! RFC 0014 P2: the attempt window pauses on verified `waiting` reports, and on
//! nothing else.

use async_trait::async_trait;
use talos_workflow_engine_core::WorkerSharedKey;

use super::*;

fn ring() -> WorkerKeyRing {
    WorkerKeyRing::single(WorkerSharedKey::new(vec![0x42u8; 32]))
}

fn job() -> Uuid {
    Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap()
}

/// The sent request, as far as the check reads it.
fn sent(attempt: u32) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "job_id": job(), "dispatch_attempt": attempt }))
        .unwrap()
}

fn report(
    job_id: Uuid,
    attempt: u32,
    state: JobProgressState,
    worker: &str,
    key: &[u8],
) -> Vec<u8> {
    let mut p = JobProgress::new(job_id, attempt, state);
    p.sign_with_worker_id(key, worker).unwrap();
    serde_json::to_vec(&p).unwrap()
}

fn good(state: JobProgressState) -> Vec<u8> {
    report(job(), 1, state, "worker-a", ring().signing_key().as_bytes())
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

// ---------------------------------------------------------------------------
// The admission rules, as a pure function of the report and the attempt
// ---------------------------------------------------------------------------

#[test]
fn a_verified_waiting_then_admitted_moves_the_deadline_by_the_interval() {
    let ring = ring();
    let payload = sent(1);
    let check = ProgressCheck {
        expected_job_id: job(),
        sent_payload: &payload,
        verify_ring: Some(&ring),
    };
    let t0 = Instant::now();
    let mut p = AttemptProgress::new(WaitAccounting::new());
    assert_eq!(
        p.apply(&good(JobProgressState::Waiting), &check, t0 + secs(5)),
        ProgressVerdict::Applied(JobProgressState::Waiting)
    );
    assert_eq!(
        p.apply(&good(JobProgressState::Admitted), &check, t0 + secs(65)),
        ProgressVerdict::Applied(JobProgressState::Admitted)
    );
    assert_eq!(
        p.deadline(t0 + secs(30), None, t0 + secs(100)),
        t0 + secs(90)
    );
}

#[test]
fn reports_for_anything_but_this_attempt_are_ignored() {
    let ring = ring();
    let payload = sent(1);
    let check = ProgressCheck {
        expected_job_id: job(),
        sent_payload: &payload,
        verify_ring: Some(&ring),
    };
    let key = ring.signing_key().as_bytes().to_vec();
    let now = Instant::now();
    let mut p = AttemptProgress::new(WaitAccounting::new());
    assert_eq!(
        p.apply(b"not json", &check, now),
        ProgressVerdict::Ignored("not a progress report")
    );
    assert_eq!(
        p.apply(
            &report(Uuid::nil(), 1, JobProgressState::Waiting, "worker-a", &key),
            &check,
            now
        ),
        ProgressVerdict::Ignored("another job")
    );
    assert_eq!(
        p.apply(
            &report(job(), 0, JobProgressState::Waiting, "worker-a", &key),
            &check,
            now
        ),
        ProgressVerdict::Ignored("another attempt"),
        "a late report from the previous attempt shares the inbox"
    );
    assert!(!p.waits.is_waiting(), "none of them may open a wait");
}

#[test]
fn a_report_that_fails_verification_is_refused_and_moves_nothing() {
    let ring = ring();
    let payload = sent(1);
    let check = ProgressCheck {
        expected_job_id: job(),
        sent_payload: &payload,
        verify_ring: Some(&ring),
    };
    let now = Instant::now();
    let mut p = AttemptProgress::new(WaitAccounting::new());
    let forged = report(
        job(),
        1,
        JobProgressState::Waiting,
        "worker-a",
        &[0x99u8; 32],
    );
    assert!(matches!(
        p.apply(&forged, &check, now),
        ProgressVerdict::Refused(_)
    ));
    let mut unsigned = JobProgress::new(job(), 1, JobProgressState::Waiting);
    unsigned.worker_id = "worker-a".into();
    let unsigned = serde_json::to_vec(&unsigned).unwrap();
    assert!(matches!(
        p.apply(&unsigned, &check, now),
        ProgressVerdict::Refused(_)
    ));
    assert!(!p.waits.is_waiting());
}

#[test]
fn a_replayed_report_is_refused() {
    let ring = ring();
    let payload = sent(1);
    let check = ProgressCheck {
        expected_job_id: job(),
        sent_payload: &payload,
        verify_ring: Some(&ring),
    };
    let now = Instant::now();
    let mut p = AttemptProgress::new(WaitAccounting::new());
    let w = good(JobProgressState::Waiting);
    assert!(matches!(
        p.apply(&w, &check, now),
        ProgressVerdict::Applied(_)
    ));
    assert!(
        matches!(p.apply(&w, &check, now), ProgressVerdict::Refused(e) if e.contains("already seen"))
    );
}

#[test]
fn only_the_first_reporting_worker_may_report_for_the_attempt() {
    let ring = ring();
    let payload = sent(1);
    let check = ProgressCheck {
        expected_job_id: job(),
        sent_payload: &payload,
        verify_ring: Some(&ring),
    };
    let key = ring.signing_key().as_bytes().to_vec();
    let t0 = Instant::now();
    let mut p = AttemptProgress::new(WaitAccounting::new());
    assert!(matches!(
        p.apply(&good(JobProgressState::Admitted), &check, t0),
        ProgressVerdict::Applied(_)
    ));
    // A second worker holding the fleet key cannot open a wait on this attempt.
    let other = report(job(), 1, JobProgressState::Waiting, "worker-b", &key);
    assert_eq!(
        p.apply(&other, &check, t0),
        ProgressVerdict::Ignored("another worker")
    );
    assert!(!p.waits.is_waiting());
}

#[test]
fn the_window_never_extends_past_the_run_limit() {
    let t0 = Instant::now();
    let mut p = AttemptProgress::new(WaitAccounting::new());
    p.waits.begin(t0);
    let base = t0 + secs(30);
    let limit = t0 + secs(50);
    assert_eq!(p.deadline(base, Some(limit), t0 + secs(200)), limit);
    // A limit already behind the base never pulls the window in.
    assert_eq!(p.deadline(base, Some(t0 + secs(10)), t0), base);
}

// ---------------------------------------------------------------------------
// The whole attempt, on tokio's paused clock, through the transport seam
// ---------------------------------------------------------------------------

/// Replies after `work` of its own time, having been queued for `queued` in the
/// middle and reported it — or not, when `report_progress` is off (the pre-P2
/// worker).
struct QueueingTransport {
    queued: Duration,
    work: Duration,
    report_progress: bool,
    key: Vec<u8>,
    admitted: bool,
}

#[async_trait]
impl JobTransport for QueueingTransport {
    async fn request(&self, _: &str, _: Vec<u8>) -> Result<Vec<u8>, BoxError> {
        unreachable!("the inbox path is taken")
    }
    async fn request_with_reply_inbox_and_progress(
        &self,
        _topic: &str,
        _inbox: &str,
        progress_subject: &str,
        _payload: Vec<u8>,
        on_progress: &(dyn Fn(Vec<u8>) + Send + Sync),
    ) -> Result<Vec<u8>, BoxError> {
        assert_eq!(progress_subject, "_INBOX.t.progress");
        if self.report_progress {
            on_progress(report(
                job(),
                1,
                JobProgressState::Waiting,
                "worker-a",
                &self.key,
            ));
        }
        tokio::time::sleep(self.queued).await;
        if self.report_progress && self.admitted {
            on_progress(report(
                job(),
                1,
                JobProgressState::Admitted,
                "worker-a",
                &self.key,
            ));
        }
        tokio::time::sleep(self.work).await;
        Ok(b"reply".to_vec())
    }
}

async fn run(
    t: QueueingTransport,
    attempt_secs: u64,
    limit: Option<Duration>,
) -> (Result<Result<Vec<u8>, BoxError>, AttemptElapsed>, Duration) {
    run_in(t, attempt_secs, limit, None).await
}

/// [`run`] inside a run whose waiting account is `waits` (RFC 0014 P2b).
async fn run_in(
    t: QueueingTransport,
    attempt_secs: u64,
    limit: Option<Duration>,
    waits: Option<&RunWaitClock>,
) -> (Result<Result<Vec<u8>, BoxError>, AttemptElapsed>, Duration) {
    let ring = ring();
    let payload = sent(1);
    let started = tokio::time::Instant::now();
    let limit = limit.map(|l| tokio::time::Instant::now().into_std() + l);
    let out = await_attempt(
        &t,
        "workflow.jobs",
        Some("_INBOX.t"),
        payload.clone(),
        attempt_secs,
        RunLimit {
            deadline: limit,
            reserve: Duration::ZERO,
            waits,
        },
        ProgressCheck {
            expected_job_id: job(),
            sent_payload: &payload,
            verify_ring: Some(&ring),
        },
    )
    .await;
    (out, started.elapsed())
}

fn transport(queued: u64, work: u64, report_progress: bool) -> QueueingTransport {
    QueueingTransport {
        queued: secs(queued),
        work: secs(work),
        report_progress,
        key: ring().signing_key().as_bytes().to_vec(),
        admitted: true,
    }
}

/// THE regression. 20 s of work inside a 30 s window, after 90 s queued behind
/// other workflows' inference: the reply arrives and is accepted.
#[tokio::test(start_paused = true)]
async fn a_job_queued_for_local_inference_is_not_abandoned() {
    let (out, took) = run(transport(90, 20, true), 30, None).await;
    assert_eq!(out.expect("window paused while queued").unwrap(), b"reply");
    assert_eq!(took, secs(110));
}

/// The control: the same job from a worker that does not report (pre-P2) is
/// abandoned at 30 s — exactly the behaviour P2 replaces.
#[tokio::test(start_paused = true)]
async fn without_reports_the_same_job_is_abandoned_at_the_window() {
    let (out, took) = run(transport(90, 20, false), 30, None).await;
    assert!(out.is_err());
    assert_eq!(took, secs(30));
}

/// Work still counts: queued 90 s, then 31 s of work in a 30 s window.
#[tokio::test(start_paused = true)]
async fn work_beyond_the_window_still_times_out() {
    let (out, took) = run(transport(90, 31, true), 30, None).await;
    let e = out.unwrap_err();
    assert_eq!(e.excluded, secs(90));
    assert_eq!(took, secs(120));
}

/// A `waiting` never followed by `admitted` (lost message, or a forger) holds
/// the window open for the cap and no longer.
#[tokio::test(start_paused = true)]
async fn an_unclosed_wait_is_capped() {
    let mut t = transport(10_000, 0, true);
    t.admitted = false;
    let (out, took) = run(t, 30, None).await;
    assert!(out.is_err());
    assert_eq!(
        took,
        secs(30 + talos_workflow_engine_core::LOCAL_INFERENCE_WAIT_CREDIT_CAP_SECS)
    );
}

/// A forged `waiting` pauses nothing.
#[tokio::test(start_paused = true)]
async fn a_forged_report_pauses_nothing() {
    let mut t = transport(90, 20, true);
    t.key = vec![0x13u8; 32];
    let (out, took) = run(t, 30, None).await;
    assert!(out.is_err());
    assert_eq!(took, secs(30));
}

/// The run's own deadline still bounds the attempt.
#[tokio::test(start_paused = true)]
async fn the_run_limit_bounds_a_paused_window() {
    let (out, took) = run(transport(90, 20, true), 30, Some(secs(60))).await;
    assert!(out.is_err());
    assert_eq!(took, secs(60));
}

/// Without a reply inbox there is no progress channel and nothing changes.
#[tokio::test(start_paused = true)]
async fn without_an_inbox_the_window_is_the_plain_timeout() {
    struct Slow;
    #[async_trait]
    impl JobTransport for Slow {
        async fn request(&self, _: &str, _: Vec<u8>) -> Result<Vec<u8>, BoxError> {
            tokio::time::sleep(secs(100)).await;
            Ok(vec![])
        }
    }
    let payload = sent(0);
    let started = tokio::time::Instant::now();
    let out = await_attempt(
        &Slow,
        "t",
        None,
        payload.clone(),
        30,
        RunLimit {
            deadline: None,
            reserve: Duration::ZERO,
            waits: None,
        },
        ProgressCheck {
            expected_job_id: job(),
            sent_payload: &payload,
            verify_ring: None,
        },
    )
    .await;
    assert!(out.is_err());
    assert_eq!(started.elapsed(), secs(30));
}

// ---------------------------------------------------------------------------
// RFC 0014 P2b — the RUN's clock
// ---------------------------------------------------------------------------

/// A verified wait is reported to the run's clock, and closed with the attempt.
#[tokio::test(start_paused = true)]
async fn verified_waits_are_reported_to_the_run_clock() {
    let run_clock = RunWaitClock::new(None);
    let (out, _) = run_in(transport(90, 20, true), 30, None, Some(&run_clock)).await;
    assert!(out.is_ok());
    assert_eq!(run_clock.excluded(now()), secs(90));
}

/// THE P2b regression at the attempt: the run's stamped deadline is 60 s away,
/// but the run itself stands still while this job is queued, so the attempt
/// may run past the STAMPED limit. Before P2b it was cut at 60 s (the control,
/// `the_run_limit_bounds_a_paused_window`, still is when there is no run clock).
#[tokio::test(start_paused = true)]
async fn the_run_limit_moves_with_the_runs_own_pause() {
    let run_clock = RunWaitClock::new(None);
    let (out, took) = run_in(
        transport(90, 20, true),
        30,
        Some(secs(60)),
        Some(&run_clock),
    )
    .await;
    assert_eq!(
        out.expect("run budget paused while queued").unwrap(),
        b"reply"
    );
    assert_eq!(took, secs(110));
}

/// A lost `admitted` cannot hold the run open once the attempt is over.
#[tokio::test(start_paused = true)]
async fn an_attempt_that_ends_closes_its_wait_on_the_run() {
    let run_clock = RunWaitClock::new(None);
    let mut t = transport(10, 5, true);
    t.admitted = false;
    let (out, _) = run_in(t, 30, None, Some(&run_clock)).await;
    assert!(out.is_ok());
    let at_end = run_clock.excluded(now());
    tokio::time::advance(secs(100)).await;
    assert_eq!(
        run_clock.excluded(now()),
        at_end,
        "the run's wait was closed with the attempt"
    );
}

/// A forged report moves neither clock.
#[tokio::test(start_paused = true)]
async fn a_forged_report_does_not_move_the_run() {
    let run_clock = RunWaitClock::new(None);
    let mut t = transport(90, 20, true);
    t.key = vec![0x13u8; 32];
    let _ = run_in(t, 30, None, Some(&run_clock)).await;
    assert_eq!(run_clock.excluded(now()), Duration::ZERO);
}
