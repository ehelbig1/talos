//! The SSE `connect` silent-failure gap, and the proof it is closed.
//!
//! ## What was broken, measured on the unmodified tree before anything was written
//!
//! `wit_http_stream::connect` established the connection inside a
//! `tokio::spawn`, so every failure of the establishment phase — the send, the
//! 30 s pre-header budget, and the response status — died inside that task with
//! no path back to the guest. The guest had already been handed `Ok(stream_id)`.
//!
//! Driven through the real host function on a real [`TalosContext`], the
//! pre-fix observation was:
//!
//! ```text
//! connect    -> Ok("33e12986-…")
//! latched    -> None
//! next_event -> None after 795.5 µs
//! ```
//!
//! A module could not distinguish that from an endpoint that legitimately sent
//! nothing. It could not retry, report, or log what it never learned about —
//! **absence reading as a negative result**, and unlike the classification gaps
//! #717 fixed, no marker or classifier could help, because no error existed to
//! classify.
//!
//! ## What the guest observes, per failure mode
//!
//! | mode | pre-fix | post-fix |
//! |---|---|---|
//! | connect-phase transport failure | `Ok` + empty stream | `Err(connection-failed)` + class |
//! | pre-header stall (30 s) | `Ok` + empty stream after 30 s | `Err(connection-failed)` + `connect-failed` |
//! | upstream non-2xx | `Ok` + empty stream | `Err(connection-failed)`, latch CLEARED |
//! | mid-stream transport error | `next_event -> None` | unchanged + operator diagnostic |
//! | byte-cap trip | `next_event -> None` | unchanged + operator diagnostic |
//! | cancellation | `next_event -> None` | unchanged + operator diagnostic |
//! | clean upstream close | `next_event -> None` | unchanged, and silent — correct |
//!
//! The bottom four cannot reach the guest at all: `next-event` is
//! `option<sse-event>` in `wit/talos.wit` and has no error arm, and widening it
//! would invalidate the checked-in `bindings.rs` of every catalog template. So
//! they are routed to the OPERATOR instead, which is the honest ceiling
//! without an ABI break.
//!
//! ## Why the tests are shaped the way they are
//!
//! The transport path cannot be reached hermetically through the front door
//! with a REAL socket failure — every route passes the SSRF gate, which is the
//! point of the gate. So there are two complementary shapes, and both drive
//! production code:
//!
//! * **End to end** through `connect`, using an invalid header NAME. `reqwest`
//!   stores that error in the builder and surfaces it at `send()`, so the
//!   establishment path is reached with ZERO packets on the wire. This is the
//!   test that fails on the pre-fix tree.
//! * **At the production recorder**, fed a real `reqwest::Error` (its inner
//!   `Kind` is private, so no test can forge one) from a closed loopback port —
//!   the same call, with the same argument, that the production site makes.
//!   Same technique as `sibling_egress_reason_tests::hermetic_connect_error`.

use std::sync::Arc;

use super::sibling_egress_reason_tests::{
    ctx_with, hermetic_connect_error, latched_class, message_for, GUEST_STREAM_CONNECTION_FAILED,
    PUBLIC_IP_LITERAL,
};
use super::{wit_http_stream, TalosContext};
use crate::context::{HostDiagSink, SseStreamEnd};
use crate::reason_class;
use crate::wit_inspector::CapabilityWorld;

fn sink() -> HostDiagSink {
    Arc::new(std::sync::Mutex::new(Vec::new()))
}

fn lines(s: &HostDiagSink) -> Vec<String> {
    s.lock().unwrap().clone()
}

/// A header NAME `http::HeaderName` refuses. `RequestBuilder::header` stores
/// the error and `send()` returns it, so the establishment path runs without a
/// single packet leaving the process.
const INVALID_HEADER_NAME: &str = "bad header name";

/// A URL that clears every gate: TEST-NET-3 is public (so `denied_ip_literal`
/// passes it) and an IP LITERAL (so the DNS-rebinding gate is skipped
/// entirely, which is the only way to reach the gates below it without a
/// resolver). RFC 5737 reserves it for documentation; it is never routed.
fn reachable_url() -> String {
    format!("https://{PUBLIC_IP_LITERAL}/sse")
}

// ---------------------------------------------------------------------------
// THE GAP. This is the test that fails on the pre-fix tree.
// ---------------------------------------------------------------------------

/// **The headline.** A `connect` whose transport fails must reach the guest as
/// an ERROR, not as a stream id that will only ever be empty.
///
/// Every assertion here is a direct negation of a measured pre-fix
/// observation, so the test cannot pass on the broken tree:
///   * pre-fix `connect` answered `Ok(stream_id)`; now `Err`.
///   * pre-fix the latch was `None`; now a transport class is latched.
///   * pre-fix a stream id was registered even though nothing could arrive on
///     it; now none is.
#[tokio::test]
async fn a_failed_sse_connect_now_reaches_the_guest_as_an_error() {
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    let s = sink();
    ctx.host_diag_sink = Some(s.clone());

    assert!(
        latched_class(&ctx).is_none(),
        "precondition: nothing latched"
    );

    let out = <TalosContext as wit_http_stream::Host>::connect(
        &mut ctx,
        reachable_url(),
        vec![(INVALID_HEADER_NAME.to_string(), "v".to_string())],
    )
    .await;

    // 1. The guest learns at all. Pre-fix: `Ok("<uuid>")`.
    assert!(
        matches!(out, Err(wit_http_stream::Error::ConnectionFailed)),
        "a transport failure must surface as connection-failed, got {out:?}"
    );

    // 2. It learns WHICH failure. Pre-fix: `None`.
    let class = latched_class(&ctx).expect("a transport class must be latched");
    assert!(
        reason_class::ALL.contains(&class),
        "{class:?} is outside the closed set"
    );
    let msg = message_for(&ctx, GUEST_STREAM_CONNECTION_FAILED);
    assert!(
        msg.contains(&reason_class::marker(class)),
        "the class must reach the node-failure message: {msg}"
    );

    // 3. No stream id was minted for a connection that never opened, so no
    //    slot is burned against MAX_SSE_STREAMS_PER_EXECUTION.
    assert_eq!(
        ctx.streams.sse.lock().unwrap().len(),
        0,
        "a failed connect must not register a stream"
    );

    // 4. The operator gets a line too, and it is the sanitized one.
    let diag = lines(&s);
    assert_eq!(diag.len(), 1, "exactly one diagnostic: {diag:?}");
    assert!(
        diag[0].contains(PUBLIC_IP_LITERAL),
        "the declared host is nameable: {diag:?}"
    );

    // 5. FALSIFICATION DIRECTION. The whole point of the constraint: this
    //    surface must not GAIN a retry. Both readings asserted, so a marker
    //    that flipped transience would fail here rather than in review.
    assert!(
        !crate::runtime::is_transient_error_text(GUEST_STREAM_CONNECTION_FAILED),
        "premise: a bare connection-failed reads non-transient"
    );
    assert!(
        !crate::runtime::is_transient_error_text(&msg),
        "the new class made a connection-failed message TRANSIENT: {msg}"
    );
}

/// The same failure, driven at the production recorder with a REAL
/// `reqwest::Error` from a closed loopback port — a genuine
/// connect-refused, which the front door cannot produce because the SSRF gate
/// (correctly) refuses loopback.
///
/// Also the totality check: a swallowed earlier DENIAL must not be left
/// explaining this call.
#[tokio::test]
async fn a_real_connect_refusal_is_classified_and_overwrites_a_stale_denial() {
    let mut ctx = ctx_with(CapabilityWorld::Minimal, vec!["*".to_string()]);
    // A real denial the guest then swallows.
    let _ = <TalosContext as wit_http_stream::Host>::connect(
        &mut ctx,
        "https://ex.test/sse".to_string(),
        vec![],
    )
    .await;
    assert_eq!(latched_class(&ctx), Some(reason_class::CAPABILITY_WORLD));

    let err = hermetic_connect_error().await;
    let out = ctx
        .record_stream_transport_outcome("allowed.test", &err)
        .await;

    assert!(matches!(out, wit_http_stream::Error::ConnectionFailed));
    assert_eq!(
        latched_class(&ctx),
        Some(reason_class::CONNECT_REFUSED),
        "the transport site must overwrite the stale deny class"
    );
    let msg = message_for(&ctx, GUEST_STREAM_CONNECTION_FAILED);
    assert!(msg.contains("[reason_class=connect-refused]"), "{msg}");
    assert!(!crate::runtime::is_transient_error_text(&msg), "{msg}");
}

// ---------------------------------------------------------------------------
// The security invariant on the sanitized path
// ---------------------------------------------------------------------------

/// The raw `reqwest` string, the resolved IP, the full URL and its query
/// string must never reach the guest-visible diagnostic. Only
/// `sanitized_transport_detail` may look at the raw error, and its output is
/// worker-log only.
///
/// Asserted against a REAL error carrying a real URL with a real query
/// parameter, so the test would catch a future site that interpolated `e`.
#[tokio::test]
async fn the_transport_diagnostic_never_leaks_the_raw_error_or_the_url() {
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    let s = sink();
    ctx.host_diag_sink = Some(s.clone());

    let err = hermetic_connect_error().await;
    let raw = err.to_string();
    let _ = ctx
        .record_stream_transport_outcome("allowed.test", &err)
        .await;

    let diag = lines(&s);
    assert_eq!(diag.len(), 1, "{diag:?}");
    let line = &diag[0];
    assert!(!line.contains(&raw), "raw reqwest Display leaked: {line}");
    assert!(!line.contains("127.0.0.1"), "loopback IP leaked: {line}");
    assert!(!line.contains("http://"), "a URL leaked: {line}");
    assert!(
        line.contains("allowed.test"),
        "the declared host SHOULD be nameable: {line}"
    );
    // The sanitizer is still the only thing that ever reads the raw error, and
    // it is still doing its job — proven positively so this is not a vacuous
    // "nothing leaked because nothing was produced".
    let sanitized = reason_class::sanitized_transport_detail(&err);
    assert!(!sanitized.contains("127.0.0.1"), "{sanitized}");
    assert!(!sanitized.contains("http://"), "{sanitized}");
}

// ---------------------------------------------------------------------------
// The riskiest decision, taken in the falsifying direction
// ---------------------------------------------------------------------------

/// **The pre-header stall must not mint `timeout`.**
///
/// The honest token for "no response headers in 30 s" is `timeout`. It is
/// deliberately NOT used, because `runtime::is_transient_error_text` matches
/// the bare substring `timeout` — so that marker on `connection-failed` would
/// move the message from non-transient to TRANSIENT and newly grant a retry to
/// a surface that has never had one. That is the one direction this workspace
/// has already paid for.
///
/// Both directions asserted. The second half is what makes this a real test
/// rather than a restatement: it PROVES the rejected token would have flipped
/// the gate, so if `is_transient_error_text` ever stops matching `timeout` the
/// premise fails loudly instead of the collapse quietly becoming pointless.
#[tokio::test]
async fn a_stream_connect_stall_must_not_mint_timeout() {
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    let out = ctx.record_stream_connect_stall("allowed.test", 30).await;
    assert!(matches!(out, wit_http_stream::Error::ConnectionFailed));
    assert_eq!(latched_class(&ctx), Some(reason_class::CONNECT_FAILED));

    let msg = message_for(&ctx, GUEST_STREAM_CONNECTION_FAILED);
    assert!(
        !crate::runtime::is_transient_error_text(&msg),
        "the stall must stay non-transient: {msg}"
    );

    // FALSIFICATION: the rejected token really would have flipped it.
    let would_have = format!(
        "{GUEST_STREAM_CONNECTION_FAILED} {}",
        reason_class::marker(reason_class::TIMEOUT)
    );
    assert!(
        crate::runtime::is_transient_error_text(&would_have),
        "premise: `[reason_class=timeout]` on a connection-failed message DOES \
         grant a retry — if this stops holding, the collapse to connect-failed \
         is no longer load-bearing and should be revisited"
    );
}

/// A non-2xx answer to the connect fails the call and CLEARS the latch.
///
/// Clearing rather than latching is #717's totality rule taken literally:
/// every failing return DECIDES the latch. There is no honest token in the
/// closed set for "the upstream said 404", and minting one would force a new
/// `talos_reason_class::Family` — which is not `#[non_exhaustive]`, so every
/// controller-side classifier would have to be edited in the same change. The
/// status still reaches the operator through the diagnostic channel.
#[tokio::test]
async fn a_non_2xx_sse_connect_fails_the_call_and_clears_the_latch() {
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    let s = sink();
    ctx.host_diag_sink = Some(s.clone());

    // Latch something first, so "cleared" is distinguishable from "never set".
    ctx.record_http_denial(
        reason_class::ALLOWED_HOSTS,
        reason_class::WIT_FORBIDDEN_HOST_HYPHENATED,
    );
    assert_eq!(latched_class(&ctx), Some(reason_class::ALLOWED_HOSTS));

    let out = ctx.record_stream_upstream_status("allowed.test", 404).await;
    assert!(matches!(out, wit_http_stream::Error::ConnectionFailed));
    assert_eq!(
        latched_class(&ctx),
        None,
        "a stale denial must not be left explaining an upstream status"
    );

    let diag = lines(&s);
    assert_eq!(diag.len(), 1, "{diag:?}");
    assert!(diag[0].contains("404"), "{diag:?}");
    assert!(diag[0].contains("allowed.test"), "{diag:?}");

    // Unmarked `connection-failed` keeps its correct non-transient reading.
    assert!(!crate::runtime::is_transient_error_text(&message_for(
        &ctx,
        GUEST_STREAM_CONNECTION_FAILED
    )));
    // And a status that the retry gate matches as a bare substring ("503")
    // must not reach the node-failure message, only the diagnostic channel.
    let mut ctx2 = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    let _ = ctx2
        .record_stream_upstream_status("allowed.test", 503)
        .await;
    let msg2 = message_for(&ctx2, GUEST_STREAM_CONNECTION_FAILED);
    assert!(
        !msg2.contains("503") && !crate::runtime::is_transient_error_text(&msg2),
        "the upstream status must not ride the retry-classified message: {msg2}"
    );
}

// ---------------------------------------------------------------------------
// The stream-slot leak found while measuring
// ---------------------------------------------------------------------------

/// A `connect` that fails AFTER validation must not burn a stream slot.
///
/// Found by measurement, not by reading: pre-fix the receiver was registered
/// above the header cap and the vault resolve, so three connects with an
/// unresolvable `vault://` header grew `streams.sse` 1 → 2 → 3 while every
/// call returned `forbidden-host`. `MAX_SSE_STREAMS_PER_EXECUTION` is 5, so a
/// handful of FAILED connects permanently exhausted an execution's budget and
/// the next legitimate `connect` was refused `rate-limited`.
///
/// Uses two hosts because the per-host connect cap is 3 — with one host the
/// rate limiter masks the leak at exactly the point it starts to matter, which
/// is why the pre-fix measurement saw the map stop growing at 3.
#[tokio::test]
async fn a_connect_that_fails_after_validation_leaks_no_stream_slot() {
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    for host in ["203.0.113.10", "203.0.113.11"] {
        for _ in 0..3 {
            let out = <TalosContext as wit_http_stream::Host>::connect(
                &mut ctx,
                format!("https://{host}/sse"),
                vec![("x-k".to_string(), "vault://nope/missing".to_string())],
            )
            .await;
            assert!(
                matches!(out, Err(wit_http_stream::Error::ForbiddenHost)),
                "premise: an unresolvable vault header still denies, got {out:?}"
            );
            assert_eq!(latched_class(&ctx), Some(reason_class::SECRET_LOOKUP));
        }
    }
    assert_eq!(
        ctx.streams.sse.lock().unwrap().len(),
        0,
        "six failed connects leaked stream slots — pre-fix this reached 5 and \
         exhausted MAX_SSE_STREAMS_PER_EXECUTION for the whole execution"
    );
}

// ---------------------------------------------------------------------------
// The mid-stream endings the WIT cannot express
// ---------------------------------------------------------------------------

/// Each abnormal ending produces exactly ONE operator line, with fixed text.
///
/// The guest still sees `None` — that is the ABI ceiling — so this is the
/// operator half of the fix, and the assertion that matters is that the three
/// endings are TOLD APART. "the stream died mid-body", "your event exceeded a
/// Talos cap" and "the execution was cancelled" have three different
/// remediations, and pre-fix all three were `next_event -> None`.
#[tokio::test]
async fn each_abnormal_stream_ending_yields_one_distinct_operator_line() {
    let mut seen: Vec<String> = Vec::new();
    for end in [
        SseStreamEnd::TransportError,
        SseStreamEnd::EventBytesCap,
        SseStreamEnd::Cancelled,
    ] {
        let mut ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
        let s = sink();
        ctx.host_diag_sink = Some(s.clone());
        ctx.report_stream_end(end).await;

        let diag = lines(&s);
        assert_eq!(diag.len(), 1, "one line per ending, got {diag:?}");
        let (tag, _) = end.describe();
        assert!(
            diag[0].starts_with(&format!("[host:{tag}]")),
            "{end:?} -> {diag:?}"
        );
        // Reporting must not disturb the latch: nothing was returned to the
        // guest here for a class to explain, and a class with no paired
        // discriminant is the stale-marker hazard the pairing rule prevents.
        assert_eq!(latched_class(&ctx), None, "{end:?} latched something");
        seen.push(diag[0].clone());
    }
    let mut uniq = seen.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(
        uniq.len(),
        seen.len(),
        "two endings produced the same operator line, so they cannot be told \
         apart: {seen:?}"
    );
}

/// A stream that ends abnormally reports it exactly once, through the REAL
/// `next_event`, and the guest's own observation is byte-identical to before
/// (`None`). Driven by planting the terminal marker on a real channel — which
/// is exactly what the spawned reader does.
#[tokio::test]
async fn next_event_reports_an_abnormal_end_once_and_still_answers_none() {
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    let s = sink();
    ctx.host_diag_sink = Some(s.clone());

    let (tx, rx) = tokio::sync::mpsc::channel(8);
    tx.send(crate::context::SseChannelItem::Event(
        crate::context::SseEventInternal {
            event_type: None,
            data: "first".to_string(),
            id: None,
        },
    ))
    .await
    .unwrap();
    tx.send(crate::context::SseChannelItem::End(
        SseStreamEnd::TransportError,
    ))
    .await
    .unwrap();
    ctx.streams.sse.lock().unwrap().insert("s1".to_string(), rx);

    // The event still arrives unchanged, and reports nothing.
    let first = <TalosContext as wit_http_stream::Host>::next_event(&mut ctx, "s1".to_string())
        .await
        .expect("the event must still be delivered");
    assert_eq!(first.data, "first");
    assert!(lines(&s).is_empty(), "an event must not emit a diagnostic");

    // The ending answers `None` to the guest — unchanged ABI — and reports.
    let second =
        <TalosContext as wit_http_stream::Host>::next_event(&mut ctx, "s1".to_string()).await;
    assert!(second.is_none(), "the guest must still see a plain None");
    assert_eq!(lines(&s).len(), 1, "exactly one report");

    // And it does not repeat: the receiver is not reinserted.
    let third =
        <TalosContext as wit_http_stream::Host>::next_event(&mut ctx, "s1".to_string()).await;
    assert!(third.is_none());
    assert_eq!(
        lines(&s).len(),
        1,
        "a second poll re-reported the same ending"
    );
}

/// A CLEAN upstream close stays silent. The signal must mean "this stream
/// died", not "this stream finished" — otherwise every well-behaved SSE
/// consumer emits a scary operator line on every successful run, and the
/// operator learns to ignore the channel. Same defect one level up.
#[tokio::test]
async fn a_clean_upstream_close_emits_nothing() {
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    let s = sink();
    ctx.host_diag_sink = Some(s.clone());

    let (tx, rx) = tokio::sync::mpsc::channel::<crate::context::SseChannelItem>(8);
    drop(tx); // clean close: sender dropped with no marker
    ctx.streams.sse.lock().unwrap().insert("s1".to_string(), rx);

    let out = <TalosContext as wit_http_stream::Host>::next_event(&mut ctx, "s1".to_string()).await;
    assert!(out.is_none());
    assert!(
        lines(&s).is_empty(),
        "a clean close must not look like a failure: {:?}",
        lines(&s)
    );
}

/// The stream-end channel spends the SAME `HOST_DIAG_CAP` budget as every
/// other diagnostic, so it cannot become a second, unbounded log stream.
#[tokio::test]
async fn stream_end_reports_are_bounded_by_the_shared_diagnostic_cap() {
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    let s = sink();
    ctx.host_diag_sink = Some(s.clone());
    for _ in 0..(TalosContext::HOST_DIAG_CAP + 25) {
        ctx.report_stream_end(SseStreamEnd::TransportError).await;
    }
    assert_eq!(lines(&s).len() as u64, TalosContext::HOST_DIAG_CAP);
}
