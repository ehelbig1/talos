//! `locality::model_locality` against a loopback `/api/tags`: what it reads,
//! how often, and what it does when the read fails.
//!
//! The cache is process-global and keyed by base URL, so every case binds its
//! own port and cannot see another case's listing.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use talos_local_inference::locality::{model_locality, ModelLocality};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Serves `GET /api/tags` from `listing` (None → HTTP 500) and counts reads.
async fn serve(listing: Arc<Mutex<Option<Value>>>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let reads = Arc::new(AtomicUsize::new(0));
    let r = reads.clone();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let listing = listing.clone();
            let reads = r.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
                assert!(
                    head.starts_with("get /api/tags"),
                    "unexpected request: {head}"
                );
                reads.fetch_add(1, Ordering::SeqCst);
                let current = listing.lock().unwrap().clone();
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

fn listing(names: &[(&str, Option<&str>)]) -> Value {
    let models: Vec<Value> = names
        .iter()
        .map(|(n, host)| match host {
            Some(h) => json!({"name": n, "model": n, "remote_host": h}),
            None => json!({"name": n, "model": n}),
        })
        .collect();
    json!({ "models": models })
}

#[tokio::test]
async fn the_listing_is_read_once_per_ttl_and_decides_local_and_remote() {
    let state = Arc::new(Mutex::new(Some(listing(&[
        ("qwen3.6:latest", None),
        ("alias:latest", Some("https://ollama.com")),
    ]))));
    let (base, reads) = serve(state).await;
    let client = reqwest::Client::new();

    assert_eq!(
        model_locality(&client, &base, "qwen3.6").await.unwrap(),
        ModelLocality::Local
    );
    assert_eq!(
        model_locality(&client, &base, "alias").await.unwrap(),
        ModelLocality::Remote {
            host: "https://ollama.com".into()
        }
    );
    assert_eq!(
        reads.load(Ordering::SeqCst),
        1,
        "a fresh listing must be reused"
    );

    // A cloud tag is decided by name: no read at all.
    assert!(matches!(
        model_locality(&client, &base, "glm-5.3-flash:cloud")
            .await
            .unwrap(),
        ModelLocality::Remote { .. }
    ));
    assert_eq!(reads.load(Ordering::SeqCst), 1);
}

/// A model pulled after the listing was cached is found by one extra read
/// instead of being refused until the TTL runs out.
#[tokio::test]
async fn a_miss_against_a_cached_listing_reads_again() {
    let state = Arc::new(Mutex::new(Some(listing(&[("qwen3.6:latest", None)]))));
    let (base, reads) = serve(state.clone()).await;
    let client = reqwest::Client::new();

    assert_eq!(
        model_locality(&client, &base, "qwen3.6").await.unwrap(),
        ModelLocality::Local
    );
    *state.lock().unwrap() = Some(listing(&[
        ("qwen3.6:latest", None),
        ("qwen3.8:27b-mlx", None),
    ]));
    assert_eq!(
        model_locality(&client, &base, "qwen3.8:27b-mlx")
            .await
            .unwrap(),
        ModelLocality::Local
    );
    assert_eq!(reads.load(Ordering::SeqCst), 2);

    // Still absent after a fresh read: an answer, not an error.
    assert_eq!(
        model_locality(&client, &base, "never-pulled")
            .await
            .unwrap(),
        ModelLocality::Unlisted
    );
}

/// A failed read is an error — never Local — and is not cached, so the next
/// call reads again.
#[tokio::test]
async fn an_unreadable_listing_is_an_error_and_is_not_cached() {
    let state = Arc::new(Mutex::new(None));
    let (base, reads) = serve(state.clone()).await;
    let client = reqwest::Client::new();

    let err = model_locality(&client, &base, "qwen3.6").await.unwrap_err();
    assert!(err.to_string().contains("status 500"), "{err}");
    assert!(!err.to_string().contains("HTTP 400"));

    *state.lock().unwrap() = Some(listing(&[("qwen3.6:latest", None)]));
    assert_eq!(
        model_locality(&client, &base, "qwen3.6").await.unwrap(),
        ModelLocality::Local
    );
    assert_eq!(reads.load(Ordering::SeqCst), 2);
}

/// A 200 that is not an Ollama listing is unreadable, not an empty listing
/// (which would make every model `Unlisted` and hide the real fault).
#[tokio::test]
async fn a_body_without_a_models_list_is_unreadable() {
    let state = Arc::new(Mutex::new(Some(json!({"error": "nope"}))));
    let (base, _) = serve(state).await;
    let client = reqwest::Client::new();
    let err = model_locality(&client, &base, "qwen3.6").await.unwrap_err();
    assert!(err.to_string().contains("no `models` list"), "{err}");
}
