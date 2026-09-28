//! RFC 0014 P4a: the exchange counts each deadline that fires, by kind, once,
//! through the process's `TimeoutSink`. Its own test binary because the sink is
//! a process-global `OnceLock`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use talos_local_inference::stream::{
    exchange_local_stream, set_timeout_sink, LocalExchangeError, ProgressDeadlines, StallKind,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DEADLINES: ProgressDeadlines = ProgressDeadlines {
    first_byte: Duration::from_millis(300),
    idle: Duration::from_millis(300),
    ceiling: Duration::from_millis(1500),
};

fn line(done: bool) -> String {
    format!(
        "{}\n",
        serde_json::json!({"message": {"role": "assistant", "content": "x"}, "done": done})
    )
}

/// A one-shot server: headers, then `chunks` (each after its delay), then it
/// holds the connection open.
async fn serve(chunks: Vec<(Duration, String)>, send_headers: bool) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let _ = sock.read(&mut buf).await;
        if send_headers {
            let _ = sock
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nConnection: close\r\n\r\n",
                )
                .await;
        }
        for (delay, c) in chunks {
            tokio::time::sleep(delay).await;
            let _ = sock.write_all(c.as_bytes()).await;
            let _ = sock.flush().await;
        }
        std::future::pending::<()>().await;
    });
    format!("http://{addr}/api/chat")
}

async fn exchange(url: String) -> Result<Vec<u8>, LocalExchangeError> {
    let req = reqwest::Client::new().post(url).body(r#"{"stream":true}"#);
    exchange_local_stream(req, DEADLINES, 1 << 20).await
}

#[tokio::test]
async fn each_deadline_is_counted_once_by_kind() {
    let seen: Arc<Mutex<Vec<StallKind>>> = Arc::default();
    let s = seen.clone();
    set_timeout_sink(Arc::new(move |k| s.lock().unwrap().push(k)));

    // Nothing ever arrives: first byte.
    let e = exchange(serve(vec![], false).await).await.unwrap_err();
    assert!(
        matches!(e, LocalExchangeError::Timeout(StallKind::FirstByte)),
        "{e:?}"
    );

    // One chunk, then nothing: idle.
    let e = exchange(serve(vec![(Duration::ZERO, line(false))], true).await)
        .await
        .unwrap_err();
    assert!(
        matches!(e, LocalExchangeError::Timeout(StallKind::Idle)),
        "{e:?}"
    );

    // Steady chunks past the backstop: ceiling.
    let steady = (0..20)
        .map(|_| (Duration::from_millis(100), line(false)))
        .collect();
    let e = exchange(serve(steady, true).await).await.unwrap_err();
    assert!(
        matches!(e, LocalExchangeError::Timeout(StallKind::Ceiling)),
        "{e:?}"
    );

    // A complete answer counts nothing.
    let ok = exchange(serve(vec![(Duration::ZERO, line(true))], true).await).await;
    assert!(ok.is_ok(), "{ok:?}");

    assert_eq!(
        *seen.lock().unwrap(),
        vec![StallKind::FirstByte, StallKind::Idle, StallKind::Ceiling]
    );
}
