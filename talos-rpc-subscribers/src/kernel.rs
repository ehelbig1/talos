//! Generic signed-RPC subscriber kernel.
//!
//! Extracted 2026-07-01: the five `spawn_*_subscriber` entry points in
//! `lib.rs` each re-implemented the same loop skeleton (NATS subscribe
//! with exponential-backoff retry, MCP-1126..1130 supervisor re-bind on
//! stream-end, per-subject concurrency semaphore, tracked `JoinSet`
//! spawn, shutdown-aware select, graceful drain). `graceful_drain` had
//! already been shared (L-24) after a real divergence bug — the other
//! four request/reply subscribers dropped in-flight work on shutdown —
//! and this module extracts the rest of the skeleton so a sixth
//! primitive cannot drift from the family shape.
//!
//! ## What the kernel owns
//!
//! * The NATS subscription and the supervisor re-bind loop
//!   (MCP-1126/1127/1128/1129/1130): stream-end → structured warn +
//!   1 s shutdown-aware sleep → re-subscribe; subscribe error →
//!   exponential backoff doubling to a 60 s cap, also shutdown-aware.
//! * The per-subject semaphore. It is created here (capacity from the
//!   spec) and lives OUTSIDE the supervisor loop, so in-flight work and
//!   held permits survive a re-bind. A clone is handed to every handler
//!   invocation.
//! * Tracked task spawning via `JoinSet` — never bare `tokio::spawn`,
//!   which orphans tasks at shutdown (docs/platform-primitive-checklist.md
//!   §3) and was one of the memory_rpc-era gaps the checklist records.
//! * Shutdown propagation and [`graceful_drain`] with `abort_all` at
//!   the deadline. The abort also reclaims any permits still held by
//!   stuck handlers — the shutdown half of the zombie-permit
//!   protection.
//! * The per-op permit-guard timeout ([`guard_op`]) — the runtime half
//!   of the zombie-permit protection. Checklist §3: "Per-op timeout
//!   wraps the DB future so a stalled Postgres doesn't zombie-hold
//!   semaphore permits indefinitely (gap in the existing RPC family)."
//! * The structured `target = "talos_rpc"` completion metric with the
//!   split `queue_ms` / `exec_ms` fields ([`record_rpc_metric`]).
//!
//! ## What stays per-protocol in the handler closures (`lib.rs`)
//!
//! * Reply-inbox handling. Request/reply protocols publish a typed
//!   reply; `talos.state.write` is fire-and-forget and never replies.
//!   The kernel is deliberately agnostic — reply semantics are part of
//!   the per-protocol handler, not a kernel mode switch.
//! * Admission — but as of 2026-07-24 the parse → `verify()` →
//!   cross-replica replay → process-local nonce ordering is
//!   TYPE-ENFORCED via `admission.rs`: the `Admitted<T>` proof token's
//!   only constructor is `admit_from_bytes`, which runs the full
//!   Tier-0 sequence fail-closed, so a handler cannot compile with a
//!   step missing or reordered. What stays per-protocol in each
//!   handler is the surface around the gate: reply semantics, the
//!   typed error reply / log wording / metric outcome tag for each
//!   `AdmitError` arm, and the permit-acquisition point. Per-site
//!   greppability is preserved via the `admit_from_bytes::<T>`
//!   turbofish at each call site.
//! * The permit acquisition POINT. Handlers acquire their permit AFTER
//!   verify/nonce (and any pre-flight validation) and BEFORE DB/service
//!   work — exactly where the pre-extraction subscribers acquired it.
//!   Moving the acquire earlier (e.g. ahead of `sub.next()`) would let
//!   an unauthenticated flood consume permits ahead of legitimate
//!   traffic AND would invert the `queue_ms` / `exec_ms` split that
//!   operator dashboards are keyed on. Don't.
//! * Outcome-tag mapping (each protocol's error enum → metric tag).

use futures::StreamExt;
use std::future::Future;
use std::sync::Arc;
use talos_metrics::{OutcomeClass, RpcOutcome, RpcSubject};
use talos_task_supervision::{spawn_supervised, BackgroundTask, TaskExit};

/// Per-subscriber wiring for [`spawn_rpc_subscriber`].
///
/// The log-message fields hold the exact pre-extraction literals —
/// operators may have alerts keyed on the rendered text, so the kernel
/// renders them byte-identically (`"{}"` with a `&'static str` produces
/// the same message as the original literal).
#[derive(Clone, Copy)]
pub(crate) struct RpcSubscriberSpec {
    /// The supervised-task identity for this subscriber. A CLOSED enum
    /// value named at each of the seven call sites — never derived from
    /// `subject`, which is a `&'static str` and would put a string into
    /// a metric label.
    pub task: BackgroundTask,
    /// NATS subject to subscribe on (also the drain/metric label).
    pub subject: &'static str,
    /// Semaphore capacity — the per-subject concurrency cap
    /// (`MAX_IN_FLIGHT` from the protocol module).
    pub max_in_flight: usize,
    /// Startup info message, e.g. `"Graph-RPC subscriber active"`.
    pub active_msg: &'static str,
    /// Warn message when `nats.subscribe` fails (logged with
    /// `subject`, `error`, `backoff_secs` fields).
    pub subscribe_failed_msg: &'static str,
    /// `event_kind` field value for the stream-end re-bind warn,
    /// e.g. `"graph_rpc_subscriber_rebinding"`.
    pub rebind_event_kind: &'static str,
    /// Warn message for the stream-end re-bind.
    pub rebind_msg: &'static str,
}

/// L-24 drain deadline: how long shutdown waits for in-flight handlers
/// before aborting the remainder. Matches the pre-extraction literal
/// `10` every subscriber passed to `graceful_drain`.
pub(crate) const DRAIN_DEADLINE_SECS: u64 = 10;

/// Per-op permit-guard timeout (docs/platform-primitive-checklist.md
/// §3). Bounds how long a single handler may hold a semaphore permit
/// while its DB/service future is stalled — without it, a Postgres or
/// Neo4j outage zombie-holds all `MAX_IN_FLIGHT` permits and the
/// subject deadlocks until the controller restarts.
///
/// 30 s matches `database_rpc::QUERY_TIMEOUT_SECS` (the one per-op
/// timeout the RPC family already had) and is ~10× the worker-side
/// `REQUEST_TIMEOUT_MS` of the fast RPCs (memory 3 s, graph 4 s,
/// integration_state 3 s) — no operation a worker could still be
/// waiting on is ever cut short; this is purely permit reclamation
/// under downstream outage. The database subscriber does not use this
/// guard: `execute_guest_query` already wraps its whole transaction in
/// `QUERY_TIMEOUT_SECS`, which covers the permit-holding window.
pub(crate) const PERMIT_GUARD_TIMEOUT_SECS: u64 = 30;

/// Run a permit-holding DB/service future under the
/// [`PERMIT_GUARD_TIMEOUT_SECS`] guard. On `Err(Elapsed)` the future is
/// dropped (cancelling the in-flight query) and the caller's permit is
/// released when its scope exits — the handler maps the timeout to its
/// protocol's existing `Timeout` variant / `"timeout"` outcome tag.
pub(crate) async fn guard_op<T>(
    fut: impl Future<Output = T>,
) -> Result<T, tokio::time::error::Elapsed> {
    guard_op_with(
        std::time::Duration::from_secs(PERMIT_GUARD_TIMEOUT_SECS),
        fut,
    )
    .await
}

/// Timeout-parameterized inner form of [`guard_op`], split out so the
/// guard is unit-testable with millisecond deadlines.
pub(crate) async fn guard_op_with<T>(
    timeout: std::time::Duration,
    fut: impl Future<Output = T>,
) -> Result<T, tokio::time::error::Elapsed> {
    tokio::time::timeout(timeout, fut).await
}

/// Exponential subscribe-retry backoff: double, capped at 60 s.
/// Pure so the progression is unit-tested; reachable values (1→2→…→60)
/// never overflow, `saturating_mul` is belt-and-suspenders.
pub(crate) fn next_backoff_secs(current: u64) -> u64 {
    current.saturating_mul(2).min(60)
}

/// THE bind site for every signed-RPC subject: a QUEUE subscribe in
/// [`CONTROLLER_RPC_QUEUE_GROUP`], so each worker request reaches exactly one
/// controller replica. See that constant for the measurement behind it.
///
/// [`CONTROLLER_RPC_QUEUE_GROUP`]: talos_workflow_job_protocol::subjects::CONTROLLER_RPC_QUEUE_GROUP
pub(crate) async fn bind_subscription(
    nats: &async_nats::Client,
    subject: &'static str,
) -> Result<async_nats::Subscriber, async_nats::SubscribeError> {
    nats.queue_subscribe(
        subject,
        talos_workflow_job_protocol::subjects::CONTROLLER_RPC_QUEUE_GROUP.to_string(),
    )
    .await
}

/// The shared subscriber loop. Owns subscription, supervisor re-bind,
/// semaphore creation, tracked spawn, shutdown, and drain — see the
/// module docs for the exact split of responsibilities.
///
/// `handler` is invoked once per inbound message and must return the
/// complete per-message future (parse → verify → nonce → permit →
/// execute → reply → metric). The future is spawned into the tracked
/// `JoinSet`; panics inside it are contained by the JoinSet and never
/// kill the loop.
pub(crate) fn spawn_rpc_subscriber<H, Fut>(
    nats: Arc<async_nats::Client>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    spec: RpcSubscriberSpec,
    handler: H,
) where
    H: Fn(async_nats::Message, Arc<tokio::sync::Semaphore>) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    spawn_supervised(spec.task, async move {
        let sem = Arc::new(tokio::sync::Semaphore::new(spec.max_in_flight));
        tracing::info!(
            subject = spec.subject,
            max_in_flight = spec.max_in_flight,
            "{}",
            spec.active_msg
        );

        // The JoinSet AND the semaphore live OUTSIDE the supervisor
        // loop so existing in-flight work survives a re-bind
        // (MCP-1126..1130: permit-leak-safe re-binds).
        let mut in_flight: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        let mut backoff_secs: u64 = 1;
        'supervisor: loop {
            let mut sub = match bind_subscription(&nats, spec.subject).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        subject = spec.subject,
                        error = %e,
                        backoff_secs,
                        "{}",
                        spec.subscribe_failed_msg
                    );
                    // Respect shutdown signal DURING the backoff so a
                    // controller stop doesn't have to wait the full
                    // backoff window before draining.
                    tokio::select! {
                        _ = shutdown.changed() => break 'supervisor,
                        _ = tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)) => {}
                    }
                    backoff_secs = next_backoff_secs(backoff_secs);
                    continue 'supervisor;
                }
            };
            backoff_secs = 1;
            let mut shutdown_requested = false;
            loop {
                let msg = tokio::select! {
                    biased;
                    _ = shutdown.changed() => {
                        tracing::info!("RPC subscriber shutting down");
                        shutdown_requested = true;
                        break;
                    }
                    Some(_) = in_flight.join_next(), if !in_flight.is_empty() => continue,
                    maybe_msg = sub.next() => match maybe_msg {
                        Some(m) => m,
                        None => break,
                    },
                };
                in_flight.spawn(handler(msg, sem.clone()));
            }
            // Inner loop exited.
            if shutdown_requested {
                break 'supervisor;
            }
            // Stream ended (NATS reconnect / server-side unsub /
            // async-nats subscription handoff); supervisor re-binds.
            tracing::warn!(
                target: "talos_rpc",
                event_kind = spec.rebind_event_kind,
                "{}",
                spec.rebind_msg
            );
            tokio::select! {
                _ = shutdown.changed() => break 'supervisor,
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
            }
        } // end 'supervisor

        // L-24: shared graceful-drain helper.
        graceful_drain(in_flight, DRAIN_DEADLINE_SECS, spec.subject).await;
        // Every `break 'supervisor` above is shutdown-driven — a stream
        // end re-binds rather than exiting — so reaching here means the
        // process is going away, not that the loop fell out.
        TaskExit::ShuttingDown
    });
}

/// L-24: graceful-drain helper for subscriber loops.
///
/// Stops waiting once `in_flight` empties OR the deadline elapses,
/// whichever comes first. On deadline-elapsed the remaining tasks are
/// `abort_all()`d so a stuck request doesn't hang the controller's
/// pod-termination grace window.
///
/// Pre-extraction this drain logic only existed in `spawn_memory_rpc_subscriber`;
/// the other request/reply subscribers (graph, database,
/// integration_state) dropped in-flight tasks on shutdown. A worker
/// mid-query would see a NATS request timeout instead of a clean
/// "subscriber shut down" reply. This helper is now invoked by every
/// request/reply subscriber for a uniform shutdown experience.
pub(crate) async fn graceful_drain(
    mut in_flight: tokio::task::JoinSet<()>,
    deadline_secs: u64,
    subject: &'static str,
) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(deadline_secs);
    while !in_flight.is_empty() {
        tokio::select! {
            biased;
            _ = in_flight.join_next() => {}
            _ = tokio::time::sleep_until(deadline) => {
                tracing::warn!(
                    subject,
                    remaining = in_flight.len(),
                    deadline_secs,
                    "RPC drain deadline reached — aborting remaining tasks"
                );
                in_flight.abort_all();
                break;
            }
        }
    }
}

/// Emit a structured completion event for an RPC subscriber, and record it on
/// `talos_rpc_calls_total` / `talos_rpc_duration_seconds`.
///
/// Fields are tagged `target = "talos_rpc"` so ops can filter logs; the metric
/// is what makes the same facts machine-readable. Until 2026-09-09 this
/// function's NAME asserted a metric and its body was two `tracing` calls, so
/// `curl /metrics/prometheus | grep '^talos_rpc'` returned only #760's six
/// write-ceiling series and the whole data plane — every actor-memory access,
/// every graph search, every sandbox statement, every inference — was
/// uncounted.
///
/// `queue` measures time from request receipt to semaphore permit acquisition;
/// `exec` measures permit-to-reply. Splitting these lets operators distinguish
/// backpressure (queue rising) from downstream slowdowns (exec rising). For
/// handlers that never acquire a permit (fast-path rejections like HMAC
/// failure), `queue == total` and `exec` is zero. **The split lives in the LOG
/// only**: the histogram observes the total. The saturation signal survives
/// that collapse as its own outcome — `stale_deadline` is the queue outrunning
/// the caller's own deadline.
///
/// Both are `Duration`, not pre-rounded milliseconds, because a histogram fed
/// `as_millis()` could not resolve anything below 1 ms and every `exec_ms`
/// this fleet has logged is 0. The log fields are still rendered as
/// milliseconds, so the line is byte-identical to the pre-2026-09-09 one.
///
/// `actor_id` is a LOG FIELD and is deliberately NOT a metric label: it is
/// caller-supplied and unbounded, i.e. a cardinality DoS surface reachable by
/// anything that can publish to the subject.
pub(crate) fn record_rpc_metric(
    subject: RpcSubject,
    actor_id: uuid::Uuid,
    outcome: RpcOutcome,
    queue: std::time::Duration,
    exec: std::time::Duration,
) {
    talos_metrics::record_rpc_call(subject, outcome, queue, exec);

    let outcome_class = outcome.class();
    let subject = subject.as_str();
    let queue_ms = queue.as_millis() as u64;
    let exec_ms = exec.as_millis() as u64;
    let duration_ms = queue_ms + exec_ms;
    let outcome = outcome.as_str();

    // THE LEVEL PARTITION, and it rests on exactly one decision:
    // `RpcOutcome::class()`, which is also the `class` metric label and
    // therefore what `TalosRPCSubjectFailing` selects on. A second copy of
    // this judgement is how a log level and an alert come to disagree.
    //
    // Before 2026-09-09 the partition was binary — `ok` was `debug!` and
    // EVERYTHING else was `warn!` — and the comment here claimed a
    // `warn!/info!` split the code did not have. The cost was measured: of 32
    // WARN lines in the controller's whole log, 17 were one designed
    // pre-promotion state (`talos.ml.predict` / `not_promoted`, from an
    // `llm_only` model that by definition serves nothing), one per hour,
    // unbroken. That is check 69's harm — a level that fires forever on a
    // healthy fleet trains operators to ignore that level — on the only
    // channel this subsystem had.
    //
    // `Served` stays at `debug!` because it is the high-volume routine case
    // and it is now COUNTED, which is the half that was missing: the question
    // "how many memory RPCs did we serve, and how fast" is answerable from
    // `talos_rpc_calls_total` / `talos_rpc_duration_seconds` without turning
    // on a log level.
    match outcome_class {
        OutcomeClass::Served => tracing::debug!(
            target: "talos_rpc",
            subject, actor_id = %actor_id, outcome, queue_ms, exec_ms, duration_ms,
            "rpc completed"
        ),
        OutcomeClass::Declined => tracing::info!(
            target: "talos_rpc",
            subject, actor_id = %actor_id, outcome, queue_ms, exec_ms, duration_ms,
            "rpc declined"
        ),
        OutcomeClass::Finding => tracing::warn!(
            target: "talos_rpc",
            subject, actor_id = %actor_id, outcome, queue_ms, exec_ms, duration_ms,
            "rpc completed (non-ok outcome)"
        ),
    }
}

/// Live-broker behaviour of TWO subscriber kernels on one subject — the
/// shape of two controller replicas (chart default `replicaCount: 2`).
/// Gated on `TALOS_TEST_NATS_URL` / `TALOS_TEST_NATS_PERM_URL`; named
/// explicitly in `scripts/test-integration.sh`, because a gated test nobody
/// names is a green skip.
#[cfg(test)]
mod kernel_two_replica_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const REQUESTS: usize = 120;

    fn spec(subject: &'static str) -> RpcSubscriberSpec {
        RpcSubscriberSpec {
            task: BackgroundTask::MemoryRpcSubscriber,
            subject,
            max_in_flight: 8,
            active_msg: "test subscriber active",
            subscribe_failed_msg: "test subscribe failed",
            rebind_event_kind: "test_rebinding",
            rebind_msg: "test rebinding",
        }
    }

    fn unique_subject(tag: &str) -> &'static str {
        Box::leak(
            format!("talos.test.kernel.{tag}.{}", uuid::Uuid::new_v4().simple()).into_boxed_str(),
        )
    }

    /// What two replicas observed.
    struct Replicas {
        /// Handler runs that EXECUTED (won the modelled replay guard, or ran
        /// with it off), per replica.
        executed: [Arc<AtomicUsize>; 2],
        /// Handler runs that REFUSED (lost the modelled guard).
        refused: Arc<AtomicUsize>,
        /// Every handler run, per replica — proof that replica's SUB is live.
        seen: [Arc<AtomicUsize>; 2],
        _shutdown: tokio::sync::watch::Sender<bool>,
    }

    impl Replicas {
        fn executed_total(&self) -> usize {
            self.executed.iter().map(|c| c.load(Ordering::SeqCst)).sum()
        }
    }

    /// Two production kernels on `subject`, one per connection. The handler
    /// models admission: with `guard_on`, the first replica to see request
    /// `i` executes (1 ms of "work", then replies `ok`) and any other replica
    /// replies `unauthorized` at once — `crossreplica_replay_ok`'s shape.
    async fn spawn_two_replicas(
        conns: [Arc<async_nats::Client>; 2],
        subject: &'static str,
        guard_on: bool,
    ) -> Replicas {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let claimed: Arc<Vec<AtomicBool>> =
            Arc::new((0..REQUESTS).map(|_| AtomicBool::new(false)).collect());
        let executed = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
        let refused = Arc::new(AtomicUsize::new(0));
        let seen = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
        for (replica, conn) in conns.iter().enumerate() {
            let (claimed, executed, refused, seen, reply_conn) = (
                claimed.clone(),
                executed[replica].clone(),
                refused.clone(),
                seen[replica].clone(),
                conn.clone(),
            );
            spawn_rpc_subscriber(conn.clone(), rx.clone(), spec(subject), move |msg, _sem| {
                let (claimed, executed, refused, seen, reply_conn) = (
                    claimed.clone(),
                    executed.clone(),
                    refused.clone(),
                    seen.clone(),
                    reply_conn.clone(),
                );
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    let i: usize = std::str::from_utf8(&msg.payload)
                        .expect("utf8")
                        .parse()
                        .expect("index");
                    let won = !guard_on || !claimed[i].swap(true, Ordering::SeqCst);
                    let body = if won {
                        executed.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                        "ok"
                    } else {
                        refused.fetch_add(1, Ordering::SeqCst);
                        "unauthorized"
                    };
                    if let Some(reply) = msg.reply {
                        reply_conn
                            .publish(reply, body.into())
                            .await
                            .expect("reply publish");
                    }
                }
            });
        }
        Replicas {
            executed,
            refused,
            seen,
            _shutdown: tx,
        }
    }

    /// Both kernels' subscriptions are live once BOTH replicas have answered
    /// a warm-up request. `flush()` is not a server round trip, and the
    /// kernel subscribes inside a spawned task, so the only proof a SUB
    /// landed is a message it answered.
    async fn wait_until_both_serve(
        requester: &async_nats::Client,
        subject: &'static str,
        replicas: &Replicas,
    ) {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        // Index 0 is reserved for warm-up.
        loop {
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                requester.request(subject, "0".into()),
            )
            .await;
            if replicas.seen.iter().all(|c| c.load(Ordering::SeqCst) > 0) {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "both replicas never served the subject"
            );
        }
    }

    async fn drive(requester: &async_nats::Client, subject: &'static str) -> (usize, usize) {
        let (mut ok, mut refused) = (0, 0);
        for i in 1..REQUESTS {
            let reply = requester
                .request(subject, i.to_string().into())
                .await
                .expect("a reply");
            if &reply.payload[..] == b"ok" {
                ok += 1;
            } else {
                refused += 1;
            }
        }
        // Let any second delivery finish its handler before counting.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        (ok, refused)
    }

    async fn plain_conns(url: &str) -> [Arc<async_nats::Client>; 2] {
        [
            Arc::new(async_nats::connect(url).await.expect("connect a")),
            Arc::new(async_nats::connect(url).await.expect("connect b")),
        ]
    }

    /// The defect, guard ON: with a plain subscribe the losing replica's
    /// `unauthorized` beat the winner's `ok` for every request while the
    /// mutation still landed. A queue group delivers each request once, so
    /// nothing is refused and the requester always gets the executor's reply.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_request_is_never_refused_by_a_sibling_replica() {
        let Ok(url) = std::env::var("TALOS_TEST_NATS_URL") else {
            eprintln!("SKIP: TALOS_TEST_NATS_URL unset");
            return;
        };
        let subject = unique_subject("guard_on");
        let replicas = spawn_two_replicas(plain_conns(&url).await, subject, true).await;
        let requester = async_nats::connect(&url).await.expect("requester");
        wait_until_both_serve(&requester, subject, &replicas).await;
        let refused_before = replicas.refused.load(Ordering::SeqCst);

        let (ok, refused) = drive(&requester, subject).await;
        assert_eq!(
            refused, 0,
            "a requester received a sibling replica's refusal"
        );
        assert_eq!(ok, REQUESTS - 1);
        assert_eq!(
            replicas.refused.load(Ordering::SeqCst),
            refused_before,
            "a second replica was delivered a request it then refused"
        );
    }

    /// The defect, guard OFF (or Redis down — fail-open is the default):
    /// every replica executed every request. Exactly one must.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_request_executes_on_exactly_one_replica() {
        let Ok(url) = std::env::var("TALOS_TEST_NATS_URL") else {
            eprintln!("SKIP: TALOS_TEST_NATS_URL unset");
            return;
        };
        let subject = unique_subject("guard_off");
        let replicas = spawn_two_replicas(plain_conns(&url).await, subject, false).await;
        let requester = async_nats::connect(&url).await.expect("requester");
        wait_until_both_serve(&requester, subject, &replicas).await;
        let before = replicas.executed_total();

        let (ok, _) = drive(&requester, subject).await;
        assert_eq!(ok, REQUESTS - 1);
        assert_eq!(
            replicas.executed_total() - before,
            REQUESTS - 1,
            "requests executed on more than one replica"
        );
        // Both replicas are MEMBERS: the group shares work rather than
        // starving one of them (which a second group name would not show).
        for (i, c) in replicas.executed.iter().enumerate() {
            assert!(c.load(Ordering::SeqCst) > 0, "replica {i} served nothing");
        }
    }

    /// `talos.state.write` is fire-and-forget: no reply to race, so the only
    /// symptom of fan-out is the write running once per replica.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_fire_and_forget_message_executes_once() {
        let Ok(url) = std::env::var("TALOS_TEST_NATS_URL") else {
            eprintln!("SKIP: TALOS_TEST_NATS_URL unset");
            return;
        };
        let subject = unique_subject("ff");
        let replicas = spawn_two_replicas(plain_conns(&url).await, subject, false).await;
        let requester = async_nats::connect(&url).await.expect("requester");
        wait_until_both_serve(&requester, subject, &replicas).await;
        let before = replicas.executed_total();

        for i in 1..REQUESTS {
            requester
                .publish(subject, i.to_string().into())
                .await
                .expect("publish");
        }
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while replicas.executed_total() - before < REQUESTS - 1 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "writes never arrived"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(replicas.executed_total() - before, REQUESTS - 1);
    }

    /// CONTROL: this broker DOES fan a plain subscribe out to both
    /// connections, so "exactly once" above is the queue group's doing and
    /// not a property of the test rig.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn control_a_plain_subscribe_delivers_to_every_connection() {
        let Ok(url) = std::env::var("TALOS_TEST_NATS_URL") else {
            eprintln!("SKIP: TALOS_TEST_NATS_URL unset");
            return;
        };
        let subject = unique_subject("control");
        let [a, b] = plain_conns(&url).await;
        let mut sub_a = a.subscribe(subject).await.expect("sub a");
        let mut sub_b = b.subscribe(subject).await.expect("sub b");
        // Same-connection round trips order each SUB before the publish.
        for c in [&a, &b] {
            let inbox = c.new_inbox();
            let mut s = c.subscribe(inbox.clone()).await.expect("barrier sub");
            c.publish(inbox, "x".into()).await.expect("barrier pub");
            s.next().await.expect("barrier echo");
        }
        let publisher = async_nats::connect(&url).await.expect("publisher");
        for i in 0..10 {
            publisher
                .publish(subject, i.to_string().into())
                .await
                .expect("publish");
        }
        let wait = std::time::Duration::from_secs(5);
        for _ in 0..10 {
            tokio::time::timeout(wait, sub_a.next())
                .await
                .expect("a")
                .expect("a msg");
            tokio::time::timeout(wait, sub_b.next())
                .await
                .expect("b")
                .expect("b msg");
        }
    }

    /// The permissioned broker (the compose `nats.conf`, the worker's real
    /// credential and `_WINBOX` inbox prefix): a worker's request on a REAL
    /// signed-RPC subject is answered once by a controller-credential queue
    /// member. A queue group changes no subject, and this proves the broker
    /// agrees.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_worker_credential_is_served_through_the_queue_group() {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let (Some(url), Some(cu), Some(cp), Some(wu), Some(wp)) = (
            env("TALOS_TEST_NATS_PERM_URL"),
            env("TALOS_TEST_NATS_PERM_CONTROLLER_USER"),
            env("TALOS_TEST_NATS_PERM_CONTROLLER_PASSWORD"),
            env("TALOS_TEST_NATS_PERM_WORKER_USER"),
            env("TALOS_TEST_NATS_PERM_WORKER_PASSWORD"),
        ) else {
            eprintln!("SKIP: TALOS_TEST_NATS_PERM_* unset");
            return;
        };
        let controller = || async {
            Arc::new(
                async_nats::ConnectOptions::with_user_and_password(cu.clone(), cp.clone())
                    .connect(&url)
                    .await
                    .expect("controller connect"),
            )
        };
        let subject = talos_memory::memory_rpc::SUBJECT_MEMORY_OP;
        let replicas =
            spawn_two_replicas([controller().await, controller().await], subject, true).await;
        let worker = async_nats::ConnectOptions::with_user_and_password(wu, wp)
            .custom_inbox_prefix(talos_workflow_job_protocol::nats_permissions::WORKER_INBOX_PREFIX)
            .connect(&url)
            .await
            .expect("worker connect");
        wait_until_both_serve(&worker, subject, &replicas).await;
        let refused_before = replicas.refused.load(Ordering::SeqCst);

        let (ok, refused) = drive(&worker, subject).await;
        assert_eq!((ok, refused), (REQUESTS - 1, 0));
        assert_eq!(replicas.refused.load(Ordering::SeqCst), refused_before);
    }
}

#[cfg(test)]
mod kernel_tests {
    use super::*;

    use std::sync::{Arc, Mutex};
    use tracing::level_filters::LevelFilter;
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
    use tracing_subscriber::Registry;

    /// Captures `(level, target, message)` for every event on the
    /// `talos_rpc` target.
    #[derive(Clone, Default)]
    struct LevelCapture(Arc<Mutex<Vec<(tracing::Level, String)>>>);

    impl<S: tracing::Subscriber> Layer<S> for LevelCapture {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let meta = event.metadata();
            if meta.target() == "talos_rpc" {
                self.0
                    .lock()
                    .expect("capture lock")
                    .push((*meta.level(), meta.name().to_string()));
            }
        }
    }

    /// THE LEVEL PARTITION, driven through the production function.
    ///
    /// The class table is pinned by name in `talos_metrics::rpc`; this pins
    /// the OTHER half — that the level actually rests on it. Moving a
    /// `Declined` outcome back to `warn!` is the exact defect this package
    /// removed (a designed pre-promotion state producing 53% of the
    /// controller's WARN volume, hourly), and without this test that revert
    /// is behaviourally invisible to every other guard in the workspace.
    #[test]
    fn the_log_level_rests_on_the_outcome_class() {
        let cap = LevelCapture::default();
        let subscriber = Registry::default()
            .with(LevelFilter::TRACE)
            .with(cap.clone());
        let actor = uuid::Uuid::nil();
        let z = std::time::Duration::ZERO;

        tracing::subscriber::with_default(subscriber, || {
            // One outcome per class, chosen as the three this package argued
            // about rather than three arbitrary ones.
            record_rpc_metric(RpcSubject::MemoryOp, actor, RpcOutcome::Ok, z, z);
            record_rpc_metric(RpcSubject::MlPredict, actor, RpcOutcome::NotPromoted, z, z);
            record_rpc_metric(RpcSubject::MemoryOp, actor, RpcOutcome::Internal, z, z);
        });

        let seen: Vec<tracing::Level> = cap
            .0
            .lock()
            .expect("capture lock")
            .iter()
            .map(|(l, _)| *l)
            .collect();
        assert_eq!(
            seen,
            vec![
                tracing::Level::DEBUG,
                tracing::Level::INFO,
                tracing::Level::WARN
            ],
            "served must stay at debug (high-volume, and now COUNTED); a DESIGNED \
             decline must be info, not an alarm; and a platform failure must stay \
             loud. If this moved, so did the `class` label and therefore the alert."
        );

        // And the mapping is exhaustive over the class enum: every outcome the
        // table declares must land on one of those three levels, so a fourth
        // class cannot be added without deciding its level here.
        for outcome in RpcOutcome::ALL {
            let expected = match outcome.class() {
                OutcomeClass::Served => tracing::Level::DEBUG,
                OutcomeClass::Declined => tracing::Level::INFO,
                OutcomeClass::Finding => tracing::Level::WARN,
            };
            let cap = LevelCapture::default();
            let subscriber = Registry::default()
                .with(LevelFilter::TRACE)
                .with(cap.clone());
            tracing::subscriber::with_default(subscriber, || {
                record_rpc_metric(RpcSubject::MemoryOp, actor, *outcome, z, z);
            });
            let got = cap.0.lock().expect("capture lock")[0].0;
            assert_eq!(got, expected, "wrong level for `{}`", outcome.as_str());
        }
    }

    #[test]
    fn backoff_doubles_and_caps_at_sixty() {
        // Progression from the initial 1 s: 1→2→4→8→16→32→60(cap).
        let mut b = 1u64;
        let mut seen = Vec::new();
        for _ in 0..7 {
            seen.push(b);
            b = next_backoff_secs(b);
        }
        assert_eq!(seen, vec![1, 2, 4, 8, 16, 32, 60]);
        // Cap is sticky.
        assert_eq!(next_backoff_secs(60), 60);
        // Saturation guard (unreachable in practice, but pinned).
        assert_eq!(next_backoff_secs(u64::MAX), 60);
    }

    #[tokio::test]
    async fn guard_op_passes_through_fast_work() {
        let out = guard_op_with(std::time::Duration::from_secs(5), async { 42u32 }).await;
        assert_eq!(out.expect("fast future must not time out"), 42);
    }

    #[tokio::test]
    async fn guard_op_times_out_and_releases_permit() {
        // The zombie-permit scenario: a handler holds a permit while
        // its DB future stalls. The guard must (a) surface Elapsed and
        // (b) drop the stalled future so the permit frees when the
        // handler scope exits.
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let permit = sem
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore is open");
        let res = guard_op_with(std::time::Duration::from_millis(10), async move {
            let _held = permit; // permit rides inside the stalled op
            std::future::pending::<()>().await;
        })
        .await;
        assert!(res.is_err(), "stalled op must report Elapsed");
        // Dropping the timed-out future dropped the permit with it.
        assert_eq!(sem.available_permits(), 1);
    }

    #[tokio::test]
    async fn graceful_drain_returns_when_tasks_complete() {
        let mut set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        set.spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        });
        // Generous deadline — must return via task completion, well
        // before the deadline.
        let started = std::time::Instant::now();
        graceful_drain(set, 10, "test.subject").await;
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[tokio::test]
    async fn graceful_drain_aborts_stuck_tasks_at_deadline() {
        let mut set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        set.spawn(async {
            std::future::pending::<()>().await;
        });
        // Zero-second deadline: the drain must take the abort path
        // immediately rather than hanging on the pending task.
        let started = std::time::Instant::now();
        graceful_drain(set, 0, "test.subject").await;
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[tokio::test]
    async fn graceful_drain_noops_on_empty_set() {
        let set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        graceful_drain(set, 10, "test.subject").await;
    }
}
