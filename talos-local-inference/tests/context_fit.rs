//! `context::check_prompt_fit` against a loopback `/api/ps`: the truncation
//! signature, the unknown cases, and how often `/api/ps` is read.
//!
//! The cache is process-global and keyed by base URL, so every case binds its
//! own port.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use talos_local_inference::context::{check_prompt_fit, PromptFit};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Serves `GET /api/ps` from `ps` (None → HTTP 500) and counts reads.
async fn serve(ps: Arc<Mutex<Option<Value>>>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let reads = Arc::new(AtomicUsize::new(0));
    let r = reads.clone();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let ps = ps.clone();
            let reads = r.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
                assert!(
                    head.starts_with("get /api/ps"),
                    "unexpected request: {head}"
                );
                reads.fetch_add(1, Ordering::SeqCst);
                let current = ps.lock().unwrap().clone();
                let (status, body) = match current {
                    Some(v) => (200, v.to_string()),
                    None => (500, "{}".to_string()),
                };
                let reply = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(reply.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (format!("http://{addr}"), reads)
}

fn loaded(name: &str, ctx: u64) -> Value {
    json!({"models": [{"name": name, "model": name, "context_length": ctx}]})
}

/// The measured signature: a 4 096-context model reporting 2 050 evaluated
/// tokens was truncated; the same model reporting 3 000 was not. One `/api/ps`
/// read serves both checks.
#[tokio::test]
async fn the_signature_is_truncation_and_one_read_serves_repeated_checks() {
    let (base, reads) = serve(Arc::new(Mutex::new(Some(loaded("m:latest", 4_096))))).await;
    let c = reqwest::Client::new();
    assert_eq!(
        check_prompt_fit(&c, &base, "m", Some(2_050)).await,
        PromptFit::Truncated {
            evaluated: 2_050,
            context_length: 4_096
        }
    );
    assert_eq!(
        check_prompt_fit(&c, &base, "m", Some(3_000)).await,
        PromptFit::Fits
    );
    assert_eq!(reads.load(Ordering::SeqCst), 1);
}

/// A small prompt is not checked at all — no request is made.
#[tokio::test]
async fn a_small_prompt_is_not_checked() {
    let (base, reads) = serve(Arc::new(Mutex::new(Some(loaded("m:latest", 1_000))))).await;
    let c = reqwest::Client::new();
    assert_eq!(
        check_prompt_fit(&c, &base, "m", Some(500)).await,
        PromptFit::Fits
    );
    assert_eq!(reads.load(Ordering::SeqCst), 0);
}

/// The detector never claims a verdict it could not make: an unreadable
/// `/api/ps`, a model that is not loaded, and a response without a count are
/// all Unknown — and an unreadable read is not cached.
#[tokio::test]
async fn what_cannot_be_checked_is_unknown_not_fits() {
    let state = Arc::new(Mutex::new(None));
    let (base, reads) = serve(state.clone()).await;
    let c = reqwest::Client::new();
    assert!(matches!(
        check_prompt_fit(&c, &base, "m", Some(2_050)).await,
        PromptFit::Unknown { .. }
    ));
    *state.lock().unwrap() = Some(loaded("other:latest", 4_096));
    assert!(matches!(
        check_prompt_fit(&c, &base, "m", Some(2_050)).await,
        PromptFit::Unknown { .. }
    ));
    assert_eq!(
        reads.load(Ordering::SeqCst),
        2,
        "a failed read must not be cached"
    );
    assert!(matches!(
        check_prompt_fit(&c, &base, "m", None).await,
        PromptFit::Unknown { .. }
    ));
}

/// A model loaded after the listing was cached is found by one extra read.
#[tokio::test]
async fn a_model_missing_from_a_cached_listing_reads_again() {
    let state = Arc::new(Mutex::new(Some(loaded("a:latest", 8_192))));
    let (base, reads) = serve(state.clone()).await;
    let c = reqwest::Client::new();
    assert_eq!(
        check_prompt_fit(&c, &base, "a", Some(3_000)).await,
        PromptFit::Fits
    );
    *state.lock().unwrap() = Some(loaded("b:latest", 8_192));
    assert_eq!(
        check_prompt_fit(&c, &base, "b", Some(4_098)).await,
        PromptFit::Truncated {
            evaluated: 4_098,
            context_length: 8_192
        }
    );
    assert_eq!(reads.load(Ordering::SeqCst), 2);
}
