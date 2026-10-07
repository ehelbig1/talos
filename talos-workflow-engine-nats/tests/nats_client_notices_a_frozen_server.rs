//! A client that keeps publishing still notices that the server has stopped
//! answering.
//!
//! The client finds a dead connection by pinging: a ping every interval, and
//! a reconnect once more than two go unanswered. `async-nats` 0.47 restarted
//! that interval on every command the CLIENT issued, so a client publishing
//! more often than the interval never pinged at all. Measured against a
//! frozen nats-server (2026-10-07, interval 1 s): an idle client disconnected
//! after 2.2 s on both versions; one publishing five times a second
//! disconnected after 2.3 s on 0.50 and not at all, in the 18 s watched, on
//! 0.47. A worker publishes a heartbeat every 30 s and pings every 60 s (the
//! library's default), so on 0.47 a worker never pinged.
//!
//! No nats-server is needed: the "server" here is a socket that completes the
//! handshake and then says nothing, which is the failure itself — a peer that
//! is still connected and no longer there.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Accept one connection, complete the NATS handshake, then read and discard
/// everything without ever answering again. Returns the address.
async fn spawn_server_that_goes_silent() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let (read, mut write) = stream.into_split();
        let info = format!(
            "INFO {{\"server_id\":\"made-up\",\"server_name\":\"made-up\",\"version\":\"2.10.0\",\
             \"go\":\"go\",\"host\":\"127.0.0.1\",\"port\":{},\"headers\":true,\
             \"max_payload\":1048576,\"proto\":1}}\r\n",
            address.port()
        );
        write.write_all(info.as_bytes()).await.expect("INFO");
        let mut lines = BufReader::new(read).lines();
        let mut answered_the_handshake = false;
        // Hold the socket open for the whole test; a closed socket would be
        // noticed by anything.
        while let Ok(Some(line)) = lines.next_line().await {
            if !answered_the_handshake && line.starts_with("PING") {
                write.write_all(b"PONG\r\n").await.expect("PONG");
                answered_the_handshake = true;
            }
        }
    });
    address.to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_publishing_client_notices_a_server_that_stopped_answering() {
    let address = spawn_server_that_goes_silent().await;
    let disconnected_at: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
    let seen = disconnected_at.clone();
    let client = async_nats::ConnectOptions::new()
        .ping_interval(Duration::from_millis(200))
        .event_callback(move |event| {
            let seen = seen.clone();
            async move {
                if matches!(event, async_nats::Event::Disconnected) {
                    seen.lock().unwrap().get_or_insert_with(Instant::now);
                }
            }
        })
        .connect(format!("nats://{address}"))
        .await
        .expect("the handshake completes");

    // Busier than the ping interval, which is what kept 0.47 from pinging.
    let publisher = client.clone();
    let publishing = tokio::spawn(async move {
        loop {
            let _ = publisher.publish("made-up.subject", "x".into()).await;
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    });

    let started = Instant::now();
    let noticed = loop {
        if let Some(at) = *disconnected_at.lock().unwrap() {
            break Some(at.duration_since(started));
        }
        if started.elapsed() > Duration::from_secs(8) {
            break None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    publishing.abort();
    let noticed = noticed.expect(
        "a client that keeps publishing never noticed the server had gone silent \
         (8 s, at a 200 ms ping interval)",
    );
    // Three unanswered pings at 200 ms is the mechanism; eight seconds is the
    // bound, loose enough for a loaded CI runner.
    assert!(
        noticed < Duration::from_secs(8),
        "noticed after {noticed:?}"
    );
}
