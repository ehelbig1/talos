//! Integration test for [`talos_nats_tls::apply_nats_ca`] against a REAL
//! TLS nats-server. Env-gated + `#[ignore]` so normal `cargo test` (and CI
//! without a server) skips it; run it by hand against a server:
//!
//! ```text
//! NATS_TEST_URL=tls://localhost:4222 \
//! NATS_CA_FILE=/tmp/natstest/nats.crt \
//! NATS_TEST_USER=talos NATS_TEST_PASS=testpw \
//!   cargo test -p talos-nats-tls --test tls_connect -- --ignored --nocapture
//! ```
//!
//! It exercises the exact code path the controller + worker use: build
//! `ConnectOptions`, run them through `apply_nats_ca` (which reads
//! `NATS_CA_FILE` → adds the root cert + `require_tls`), connect over the
//! `tls://` URL, and round-trip a message.

use async_nats::ConnectOptions;
use futures::StreamExt;

fn opts_with_creds() -> ConnectOptions {
    let opts = ConnectOptions::new();
    match (
        std::env::var("NATS_TEST_USER"),
        std::env::var("NATS_TEST_PASS"),
    ) {
        (Ok(u), Ok(p)) if !u.is_empty() => opts.user_and_password(u, p),
        _ => opts,
    }
}

#[tokio::test]
#[ignore = "requires a running TLS nats-server + NATS_CA_FILE; run manually"]
async fn tls_round_trip_with_ca_succeeds() {
    let url = std::env::var("NATS_TEST_URL").expect("set NATS_TEST_URL");
    // The code under test.
    let client = talos_nats_tls::apply_nats_ca(opts_with_creds())
        .connect(&url)
        .await
        .expect("connect over tls:// with CA trust must succeed");

    let mut sub = client.subscribe("talos.test.tls").await.unwrap();
    client.publish("talos.test.tls", "ok".into()).await.unwrap();
    client.flush().await.unwrap();
    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), sub.next())
        .await
        .expect("receive timed out")
        .expect("subscription closed");
    assert_eq!(&msg.payload[..], b"ok", "round-trip payload mismatch");
}

#[tokio::test]
#[ignore = "requires a running TLS nats-server; run manually"]
async fn tls_without_ca_fails() {
    // Same server + URL, but WITHOUT NATS_CA_FILE in scope: a self-signed
    // server cert must NOT be trusted by default → connect fails closed.
    let url = std::env::var("NATS_TEST_URL").expect("set NATS_TEST_URL");
    std::env::remove_var(talos_nats_tls::NATS_CA_FILE_ENV);
    let res = talos_nats_tls::apply_nats_ca(opts_with_creds())
        .require_tls(true)
        .connect(&url)
        .await;
    assert!(
        res.is_err(),
        "tls:// connect to a self-signed server WITHOUT the CA must fail"
    );
}
