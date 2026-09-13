//! The AUDIT_LEDGER JetStream stream must be BOUNDED, and an existing
//! unbounded stream must be brought to the bound IN PLACE without losing what
//! it holds.
//!
//! # Why a live broker
//!
//! `get_or_create_stream` never updates an existing stream — that is the
//! defect this guards: the production stream was created with
//! `..Default::default()` on 2026-07-08 and every boot since re-used it
//! unbounded. Only a real JetStream can prove that `ensure_bounded_stream`
//! (a) creates a fresh stream with the bound, (b) applies the bound to a
//! pre-existing unbounded stream, and (c) keeps that stream's messages while
//! doing so. Runs under `make test-integration`, which starts a disposable
//! `nats:2.10-alpine -js` and exports `TALOS_TEST_NATS_URL`; without that
//! variable the tests skip LOUDLY (stderr) rather than fail, the
//! `nats_worker_permissions` convention.

use async_nats::jetstream::{self, stream::Config as StreamConfig};
use talos_audit_ledger::{ensure_bounded_stream, AUDIT_LEDGER_STREAM_MAX_AGE};

fn nats_url() -> Option<String> {
    std::env::var("TALOS_TEST_NATS_URL")
        .ok()
        .filter(|v| !v.is_empty())
}

async fn js() -> Option<jetstream::Context> {
    let url = nats_url()?;
    let nc = async_nats::connect(&url)
        .await
        .expect("connect to the test NATS");
    Some(jetstream::new(nc))
}

fn unique(prefix: &str) -> (String, String) {
    let id = uuid::Uuid::new_v4().simple().to_string();
    (format!("{prefix}_{id}"), format!("talos.test.audit.{id}"))
}

#[tokio::test]
async fn a_fresh_stream_is_created_with_the_age_bound() {
    let Some(js) = js().await else {
        eprintln!("TALOS_TEST_NATS_URL unset — skipping (make test-integration sets it)");
        return;
    };
    let (name, subject) = unique("AUDIT_LEDGER_FRESH");
    let mut stream = ensure_bounded_stream(&js, &name, &subject)
        .await
        .expect("ensure");
    let info = stream.info().await.expect("info");
    assert_eq!(info.config.max_age, AUDIT_LEDGER_STREAM_MAX_AGE);
    assert_eq!(info.config.subjects, vec![subject.clone()]);
    js.delete_stream(&name).await.expect("cleanup");
}

#[tokio::test]
async fn an_existing_unbounded_stream_is_bounded_in_place_and_keeps_its_messages() {
    let Some(js) = js().await else {
        eprintln!("TALOS_TEST_NATS_URL unset — skipping (make test-integration sets it)");
        return;
    };
    let (name, subject) = unique("AUDIT_LEDGER_LEGACY");
    // The 2026-07-08 shape: name + subjects, everything else default — no bound.
    let mut legacy = js
        .create_stream(StreamConfig {
            name: name.clone(),
            subjects: vec![subject.clone()],
            ..Default::default()
        })
        .await
        .expect("create the legacy stream");
    for i in 0..3 {
        js.publish(subject.clone(), format!("event-{i}").into())
            .await
            .expect("publish")
            .await
            .expect("ack");
    }
    let before = legacy.info().await.expect("info").clone();
    assert_eq!(
        before.config.max_age.as_secs(),
        0,
        "control: the legacy stream is unbounded"
    );
    assert_eq!(
        before.state.messages, 3,
        "control: three messages in the legacy stream"
    );

    let mut bounded = ensure_bounded_stream(&js, &name, &subject)
        .await
        .expect("ensure");
    let after = bounded.info().await.expect("info");
    assert_eq!(
        after.config.max_age, AUDIT_LEDGER_STREAM_MAX_AGE,
        "the bound was applied in place"
    );
    assert_eq!(
        after.state.messages, 3,
        "applying the bound must not drop what the stream holds"
    );
    assert_eq!(after.state.first_sequence, before.state.first_sequence);
    js.delete_stream(&name).await.expect("cleanup");
}

#[tokio::test]
async fn ensuring_an_already_bounded_stream_is_a_no_op() {
    let Some(js) = js().await else {
        eprintln!("TALOS_TEST_NATS_URL unset — skipping (make test-integration sets it)");
        return;
    };
    let (name, subject) = unique("AUDIT_LEDGER_IDEMPOTENT");
    ensure_bounded_stream(&js, &name, &subject)
        .await
        .expect("first");
    let mut again = ensure_bounded_stream(&js, &name, &subject)
        .await
        .expect("second");
    let info = again.info().await.expect("info");
    assert_eq!(info.config.max_age, AUDIT_LEDGER_STREAM_MAX_AGE);
    js.delete_stream(&name).await.expect("cleanup");
}
