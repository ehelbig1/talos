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
