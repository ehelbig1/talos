//! A stand-in for a local embedding provider that serves ONE request at a
//! time, like the bundled Ollama embedder (`--parallel 1`): every request is
//! read, then waits its turn, then takes `service` to answer.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub struct SerialEmbedder {
    pub url: String,
    /// Requests received and not yet answered, at the highest point.
    pub peak_in_backend: Arc<AtomicUsize>,
    /// Requests received in total (retries included).
    pub received: Arc<AtomicUsize>,
}

/// Start the mock on a loopback port. `dims` is the vector length returned.
pub async fn start(service: Duration, dims: usize) -> SerialEmbedder {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!(
        "http://{}/v1/embeddings",
        listener.local_addr().expect("local addr")
    );
    let peak = Arc::new(AtomicUsize::new(0));
    let received = Arc::new(AtomicUsize::new(0));
    let in_backend = Arc::new(AtomicUsize::new(0));
    let turn = Arc::new(tokio::sync::Mutex::new(()));
    let (peak_c, received_c) = (peak.clone(), received.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let (peak, received, in_backend, turn) = (
                peak_c.clone(),
                received_c.clone(),
                in_backend.clone(),
                turn.clone(),
            );
            tokio::spawn(async move {
                // Read the whole request: headers, then Content-Length bytes.
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let body_start = loop {
                    let Ok(n) = sock.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..body_start]).to_ascii_lowercase();
                let want: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                while buf.len() < body_start + want {
                    let Ok(n) = sock.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                received.fetch_add(1, Ordering::SeqCst);
                let now = in_backend.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                {
                    // One at a time, in arrival order; a request whose client
                    // has gone still takes its turn, like a server-side queue.
                    let _turn = turn.lock().await;
                    tokio::time::sleep(service).await;
                }
                in_backend.fetch_sub(1, Ordering::SeqCst);
                let vector: Vec<f32> = (0..dims).map(|i| i as f32 / 10.0).collect();
                let body = serde_json::json!({ "data": [{ "embedding": vector }] }).to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    SerialEmbedder {
        url,
        peak_in_backend: peak,
        received,
    }
}

/// Point the embedding client at the mock. Must run before the first
/// `generate_embedding` call of the process: the config is read once.
pub fn configure(url: &str, dims: usize, timeout_secs: u64, max_in_flight: Option<&str>) {
    std::env::set_var("EMBEDDING_API_URL", url);
    std::env::set_var("EMBEDDING_MODEL", "mock-embedder");
    std::env::set_var("EMBEDDING_DIMENSIONS", dims.to_string());
    std::env::set_var("EMBEDDING_TIMEOUT_SECS", timeout_secs.to_string());
    std::env::remove_var("EMBEDDING_API_KEY");
    std::env::remove_var("OPENAI_API_KEY");
    match max_in_flight {
        Some(v) => std::env::set_var("TALOS_EMBEDDING_MAX_IN_FLIGHT", v),
        None => std::env::remove_var("TALOS_EMBEDDING_MAX_IN_FLIGHT"),
    }
}
