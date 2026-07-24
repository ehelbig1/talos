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

/// Per-subscriber wiring for [`spawn_rpc_subscriber`].
///
/// The log-message fields hold the exact pre-extraction literals —
/// operators may have alerts keyed on the rendered text, so the kernel
/// renders them byte-identically (`"{}"` with a `&'static str` produces
/// the same message as the original literal).
#[derive(Clone, Copy)]
pub(crate) struct RpcSubscriberSpec {
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
    tokio::spawn(async move {
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
            let mut sub = match nats.subscribe(spec.subject).await {
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

/// Emit a structured completion event for an RPC subscriber. Fields
/// are tagged `target = "talos_rpc"` so ops can filter logs or
/// aggregate them into Prometheus/OTel pipelines without each
/// subscriber growing its own metrics code path.
///
/// `queue_ms` measures time from request receipt to semaphore
/// permit acquisition; `exec_ms` measures permit-to-reply. Splitting
/// these lets operators distinguish backpressure (queue rising) from
/// downstream slowdowns (exec rising). For handlers that never
/// acquire a permit (fast-path rejections like HMAC failure),
/// `queue_ms == total` and `exec_ms == 0`.
pub(crate) fn record_rpc_metric(
    subject: &'static str,
    actor_id: uuid::Uuid,
    outcome: &'static str, // "ok" | "not_found" | "unauthorized" | "invalid" | "internal" | "timeout" | …
    queue_ms: u64,
    exec_ms: u64,
) {
    // L-22: success outcomes are high-volume and routine; demote to
    // debug! so production INFO logs aren't dominated by `rpc completed`
    // baseline noise. Failure outcomes stay at warn!/info! so they
    // remain visible without a level filter — failures are the
    // operationally interesting class. Operators who want every-RPC
    // tracing for capacity planning enable debug! for the talos_rpc
    // target.
    if outcome == "ok" {
        tracing::debug!(
            target: "talos_rpc",
            subject,
            actor_id = %actor_id,
            outcome,
            queue_ms,
            exec_ms,
            duration_ms = queue_ms + exec_ms,
            "rpc completed"
        );
    } else {
        tracing::warn!(
            target: "talos_rpc",
            subject,
            actor_id = %actor_id,
            outcome,
            queue_ms,
            exec_ms,
            duration_ms = queue_ms + exec_ms,
            "rpc completed (non-ok outcome)"
        );
    }
}

#[cfg(test)]
mod kernel_tests {
    use super::*;

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
