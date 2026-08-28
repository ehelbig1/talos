//! The cancellation RECEIVER contract: a tripped `is_cancelled()` guard must
//! reach the controller as a **non-transient** failure.
//!
//! ## Why this file exists
//!
//! `TalosContext::cancel()` has no production caller yet, so none of these
//! guards fire in the field. That makes the receiving end easy to get wrong
//! silently — and it was wrong. The `wit_http` / `wit_graphql` error enums are
//! payload-less discriminants that render the bare token `networkerror`, which
//! BOTH transient gates —
//! [`crate::runtime::is_transient_error`] in-worker and
//! `talos_retry_intelligence::classify_error` on the controller — classify as
//! `network_transient`. A retried job builds a FRESH `TalosContext` whose
//! `cancelled` flag is `false`, so the cancellation is lost and the work keeps
//! going.
//!
//! `http::fetch` was already carved out: it stamps
//! `[reason_class=cancelled]`, and both gates hoist a `cancelled` arm ABOVE
//! their `networkerror` arm. Its two siblings — `http::fetch_all` and
//! `graphql::execute` — did not, and were retried.
//!
//! Every assertion below is taken in BOTH directions: the marker present
//! (non-transient) and the marker absent (transient). A one-directional test
//! here would pass against the broken tree, because the broken tree also
//! "classifies successfully" — it just classifies wrong.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use talos_workflow_job_protocol::LlmTier;

use super::{wit_http, TalosContext};
use crate::reason_class;
use crate::wit_inspector::CapabilityWorld;

/// The literal shape a WIT error takes on the wire, quoted from the
/// `talos_retry_intelligence` comment that added the `networkerror` arm.
const GUEST_NETWORKERROR: &str =
    r#"Component returned error: list fetch: Error { code: 2, name: "networkerror", message: "" }"#;

fn bare_context() -> TalosContext {
    TalosContext::new(
        CapabilityWorld::Http,
        vec![],
        vec![],
        128,
        HashMap::new(),
        None,
        None,
        false,
        None,
        Arc::new(crate::expose_fallback::ExposeFallback::new()),
        LlmTier::Tier2,
        None,
    )
    .expect("context builds")
}

fn a_request() -> wit_http::Request {
    wit_http::Request {
        method: wit_http::Method::Get,
        url: "https://example.invalid/v1/thing".to_string(),
        headers: vec![],
        body: vec![],
        timeout_ms: None,
    }
}

// ---------------------------------------------------------------------------
// The guard itself
// ---------------------------------------------------------------------------

/// `http::fetch_all`'s cancel guard must latch the reason class, not just
/// return. Before the fix it returned a bare `Networkerror` with the latch
/// untouched — which is the whole retry hole.
#[tokio::test]
async fn fetch_all_cancel_guard_latches_the_reason_class() {
    let mut ctx = bare_context();
    ctx.cancelled.store(true, Ordering::Relaxed);

    let latch = ctx.network_reason_handle();
    assert!(
        latch.lock().unwrap().is_none(),
        "precondition: nothing has latched a network reason yet"
    );

    let out =
        <TalosContext as wit_http::Host>::fetch_all(&mut ctx, vec![a_request(), a_request()]).await;

    assert_eq!(out.len(), 2, "one result per request, even when cancelled");
    for r in &out {
        assert!(
            matches!(r, Err(wit_http::Error::Networkerror)),
            "cancelled batch fetch must not reach the network"
        );
    }
    assert_eq!(
        *latch.lock().unwrap(),
        Some(reason_class::CANCELLED),
        "the guard returned without stamping [reason_class=cancelled]; the \
         controller will classify this bare `networkerror` as network_transient \
         and RE-DISPATCH the job onto a fresh, uncancelled context"
    );
}

/// The guard is the FIRST check in `fetch_all` — ahead of the capability-world
/// gate — so a cancelled Minimal-world module is reported as cancelled rather
/// than as a capability denial. Pins the ordering, which is what makes the
/// guard reachable in this test at all.
#[tokio::test]
async fn fetch_all_cancellation_precedes_the_capability_gate() {
    let mut ctx = TalosContext::new(
        CapabilityWorld::Minimal,
        vec![],
        vec![],
        128,
        HashMap::new(),
        None,
        None,
        false,
        None,
        Arc::new(crate::expose_fallback::ExposeFallback::new()),
        LlmTier::Tier2,
        None,
    )
    .expect("context builds");
    ctx.cancelled.store(true, Ordering::Relaxed);
    let latch = ctx.network_reason_handle();

    let out = <TalosContext as wit_http::Host>::fetch_all(&mut ctx, vec![a_request()]).await;

    assert!(matches!(out[0], Err(wit_http::Error::Networkerror)));
    assert_eq!(*latch.lock().unwrap(), Some(reason_class::CANCELLED));
}

// ---------------------------------------------------------------------------
// Guard → suffix → transient gate, in both directions
// ---------------------------------------------------------------------------

/// The marker the runtime appends is what flips the classification. Asserted
/// with the marker AND without it, because the without-it case is the bug: a
/// test that only checked the fixed direction passes against the broken tree.
#[test]
fn the_marker_is_what_makes_a_cancelled_egress_non_transient() {
    let latch: Arc<std::sync::Mutex<Option<&'static str>>> =
        Arc::new(std::sync::Mutex::new(Some(reason_class::CANCELLED)));

    let suffix = crate::runtime::last_network_reason_suffix(&latch, GUEST_NETWORKERROR);
    assert_eq!(suffix, " [reason_class=cancelled]");

    let marked = format!("{GUEST_NETWORKERROR}{suffix}");
    assert!(
        !crate::runtime::is_transient_error_text(&marked),
        "a marked cancellation must not be retried in-worker: {marked}"
    );
    assert!(
        crate::runtime::is_transient_error_text(GUEST_NETWORKERROR),
        "FALSIFICATION DIRECTION: the same guest error WITHOUT the marker must \
         still read transient. If this fails the test proves nothing — the \
         marker would not be load-bearing and the fix would be a no-op."
    );
}

/// An unlatched context appends nothing, which is precisely the pre-fix
/// behaviour of `fetch_all` / `graphql::execute`. Pins the mechanism the two
/// guards depend on rather than trusting the guards' own logging.
#[test]
fn an_unlatched_context_appends_no_marker() {
    let latch: Arc<std::sync::Mutex<Option<&'static str>>> = Arc::new(std::sync::Mutex::new(None));
    assert_eq!(
        crate::runtime::last_network_reason_suffix(&latch, GUEST_NETWORKERROR),
        ""
    );
}

/// `cancelled` is in the closed NON_TRANSIENT set the two hand-written
/// classifier arms are pinned against (`reason_class::closed_set_snapshot`).
/// Restated here so that removing it fails a test whose name says why.
#[test]
fn cancelled_is_declared_non_transient() {
    assert!(reason_class::ALL.contains(&reason_class::CANCELLED));
    assert!(reason_class::NON_TRANSIENT.contains(&reason_class::CANCELLED));
}

// ---------------------------------------------------------------------------
// PRODUCER → registry → context → real egress guard
//
// Everything above this line tests the RECEIVER (#689). The tests below close
// the loop the receiver was waiting for: they drive the same handoff
// `execute_job_with_full_features` performs — one `Arc<AtomicBool>` minted per
// job, registered by execution id, adopted by the context — and then call the
// REAL host function to show that the work stops.
//
// ## Why no test here calls `fetch_all` on an UNCANCELLED Http-world context
//
// `fetch_all`'s validation block reads `*ALLOW_PRIVATE_HOST_TARGETS`, a
// process-global `LazyLock<bool>` over `WORKER_ALLOW_PRIVATE_HOST_TARGETS`
// (`host/limits.rs`). First read wins for the life of the process. An
// unrelated test — `host_impl_tests::fetch_with_bearer_sends_single_bearer_prefix`
// — `set_var`s that variable and then needs the LazyLock to observe it, and
// its own comment explains the isolation it relies on: "nextest runs each test
// in its own process". True under `cargo nextest` (what CI runs) and NOT true
// under plain `cargo test`, where any earlier test that forces the LazyLock
// freezes it at `false` and the bearer test fails with `forbiddenhost`.
//
// So the cancelled direction — where the guard returns BEFORE that read — is
// the only one taken through `fetch_all` here. The falsification directions
// below are taken without initialising the static.
// ---------------------------------------------------------------------------

use crate::cancel_registry::CancelRegistry;
use uuid::Uuid;

/// **The load-bearing test: cancelling an EXECUTION stops in-flight WORK.**
///
/// Not "a flag flipped" — the assertion runs through the production egress
/// path. The context adopts the registered flag exactly as
/// `execute_job_with_full_features` does (`context.cancelled = job_cancel_flag`),
/// a cancel arrives addressed to the execution, and the module's next off-host
/// call is refused and stamped `[reason_class=cancelled]` — which the transient
/// gate treats as non-retryable, so the job is not re-dispatched onto a fresh,
/// uncancelled context.
///
/// Falsified in three directions, none of which is vacuous:
/// * before the cancel the context reports itself uncancelled and nothing is
///   latched;
/// * the registry reports exactly ONE job flagged, so the scan is not a
///   blanket store;
/// * the SAME guest error WITHOUT the marker still classifies transient, so
///   the marker is what makes the difference.
#[tokio::test]
async fn cancelling_an_execution_stops_the_next_egress_call() {
    let registry = CancelRegistry::new();
    let execution_id = Uuid::new_v4();

    // The job-scoped flag, minted once per job and handed to the context —
    // the two lines `execute_job_with_full_features` runs for every job.
    let job_cancel_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let _guard = registry.register(execution_id, job_cancel_flag.clone());

    let mut ctx = bare_context();
    ctx.cancelled = job_cancel_flag;
    let latch = ctx.network_reason_handle();

    // FALSIFICATION 1 — the starting state is genuinely uncancelled.
    assert!(!ctx.is_cancelled(), "precondition: nothing cancelled yet");
    assert!(
        latch.lock().unwrap().is_none(),
        "precondition: nothing has latched a network reason yet"
    );

    // ── THE PRODUCER ────────────────────────────────────────────────────
    // What the worker's cancel listener calls after verifying the signed
    // command. FALSIFICATION 2 — exactly one job, not a blanket store.
    assert_eq!(
        registry.cancel_execution(execution_id),
        1,
        "the cancel must reach exactly the job registered for this execution"
    );
    assert!(
        ctx.is_cancelled(),
        "the context must observe the registry's store — same Arc, no copy"
    );

    // ── THE WORK CEASES ─────────────────────────────────────────────────
    let after = <TalosContext as wit_http::Host>::fetch_all(&mut ctx, vec![a_request()]).await;
    assert!(
        matches!(after[0], Err(wit_http::Error::Networkerror)),
        "a cancelled module must not reach the network"
    );
    assert_eq!(
        *latch.lock().unwrap(),
        Some(reason_class::CANCELLED),
        "the egress refusal must be stamped `cancelled`"
    );

    // …and stays stopped: the marker is what keeps the controller from
    // re-dispatching this job onto a fresh context whose flag is false.
    let suffix = crate::runtime::last_network_reason_suffix(&latch, GUEST_NETWORKERROR);
    let marked = format!("{GUEST_NETWORKERROR}{suffix}");
    assert!(
        !crate::runtime::is_transient_error_text(&marked),
        "a cancelled job must not be retried in-worker: {marked}"
    );
    // FALSIFICATION 3 — without the marker the same error is retryable, so
    // the assertion above is load-bearing rather than incidental.
    assert!(
        crate::runtime::is_transient_error_text(GUEST_NETWORKERROR),
        "the unmarked form must stay transient, or the marker proves nothing"
    );
    // The controller-side half of the same classification is asserted in
    // `talos_retry_intelligence`'s own tests (#689). This crate does not
    // depend on it, and re-implementing the classifier here would shadow a
    // production path.
}

/// A cancel addressed to a DIFFERENT execution must not stop this one.
///
/// The registry is process-wide state on a worker running many tenants' jobs
/// at once, so a scan bug here is a cross-tenant abort. Both jobs are real
/// registrations with real contexts; only the addressed one is expected to
/// reach the egress guard.
#[tokio::test]
async fn a_cancel_for_another_execution_does_not_stop_this_one() {
    let registry = CancelRegistry::new();
    let (mine, theirs) = (Uuid::new_v4(), Uuid::new_v4());

    let my_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let their_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let _g1 = registry.register(mine, my_flag.clone());
    let _g2 = registry.register(theirs, their_flag.clone());

    let mut my_ctx = bare_context();
    my_ctx.cancelled = my_flag;
    let mut their_ctx = bare_context();
    their_ctx.cancelled = their_flag;

    // Cancel MINE only.
    assert_eq!(registry.cancel_execution(mine), 1);
    assert!(my_ctx.is_cancelled());
    assert!(
        !their_ctx.is_cancelled(),
        "another tenant's job must be untouched by my cancel"
    );

    // Mine stops at the guard, with the marker.
    let my_latch = my_ctx.network_reason_handle();
    let out = <TalosContext as wit_http::Host>::fetch_all(&mut my_ctx, vec![a_request()]).await;
    assert!(matches!(out[0], Err(wit_http::Error::Networkerror)));
    assert_eq!(*my_latch.lock().unwrap(), Some(reason_class::CANCELLED));

    // Theirs never latched anything — the guard was never reached for it.
    // (Its `fetch_all` is deliberately not called; see the module note above
    // on the `ALLOW_PRIVATE_HOST_TARGETS` LazyLock.)
    assert!(their_ctx.network_reason_handle().lock().unwrap().is_none());
}

/// An execution this worker is not running is a NO-OP, not an error — the
/// path EVERY other worker in the fleet takes on EVERY broadcast cancel,
/// because the command is a plain (non-queue) subscribe.
#[test]
fn a_cancel_for_an_unknown_execution_is_a_no_op() {
    let registry = CancelRegistry::new();
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let _g = registry.register(Uuid::new_v4(), flag.clone());

    assert_eq!(registry.cancel_execution(Uuid::new_v4()), 0);
    assert!(!flag.load(Ordering::Relaxed));
}
