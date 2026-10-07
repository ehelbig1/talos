// ci-store: services — scripts/test-integration.sh runs this with that store (scripts/ci_test_targets.py)
//! Two things the NATS client must do for the dispatcher, checked on a LIVE
//! nats-server through [`NatsTransport`] — the transport every job goes out
//! on. Both were measured as broken on `async-nats` 0.47 and fixed by 0.50
//! (2026-10-07, `docs/engineering-log/packages/2026-10-07-async-nats-0.50.md`),
//! and neither shows at compile time: the bump needed no source change.
//!
//! * **A message larger than the server accepts is refused before it is
//!   sent.** 0.47 checked the size on plain `publish` only. The dispatcher
//!   publishes with a reply subject and headers, so an oversized job was
//!   handed to the server, which answered `Maximum Payload Violation`, closed
//!   the connection, and left the dispatch waiting out its whole deadline for
//!   a reply nobody would send.
//! * **A subject that is not UTF-8 does not end the client.** nats-server
//!   forwards arbitrary bytes in a subject. On 0.47 one such message arriving
//!   on a wildcard subscription panicked the client's connection task: every
//!   later publish and request failed for the life of the process, with no
//!   event and no reconnect. Every client holds a wildcard subscription — its
//!   reply inbox — so any credential allowed to publish could do that to the
//!   controller.
//!
//! `scripts/test-integration.sh` starts a scratch nats-server and exports
//! `TALOS_TEST_NATS_URL`. Without it each test returns early and says so.

use futures::StreamExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use talos_workflow_engine_core::JobTransport;
use talos_workflow_engine_nats::NatsTransport;

fn nats_url() -> Option<String> {
    std::env::var("TALOS_TEST_NATS_URL")
        .ok()
        .filter(|url| !url.is_empty())
}

type Events = Arc<Mutex<Vec<String>>>;

async fn connect(url: &str) -> (async_nats::Client, Events) {
    let events: Events = Arc::new(Mutex::new(Vec::new()));
    let seen = events.clone();
    let client = async_nats::ConnectOptions::new()
        .event_callback(move |event| {
            let seen = seen.clone();
            async move {
                seen.lock().unwrap().push(event.to_string());
            }
        })
        .connect(url)
        .await
        .expect("connect to the scratch nats-server");
    (client, events)
}

/// Answer every message on `subject` with its length, and count them.
async fn spawn_responder(client: &async_nats::Client, subject: String) -> Arc<Mutex<Vec<usize>>> {
    let delivered = Arc::new(Mutex::new(Vec::new()));
    let seen = delivered.clone();
    let replier = client.clone();
    let mut sub = client.subscribe(subject).await.expect("subscribe");
    client.flush().await.expect("flush");
    tokio::spawn(async move {
        while let Some(message) = sub.next().await {
            seen.lock().unwrap().push(message.payload.len());
            if let Some(reply) = message.reply {
                let _ = replier
                    .publish(reply, message.payload.len().to_string().into())
                    .await;
            }
        }
    });
    delivered
}

#[tokio::test(flavor = "multi_thread")]
async fn an_oversized_job_is_refused_before_it_is_sent() {
    let Some(url) = nats_url() else {
        eprintln!("skipping: set TALOS_TEST_NATS_URL to run (scripts/test-integration.sh does)");
        return;
    };
    let (worker, _) = connect(&url).await;
    let subject = format!("made-up.resilience.size.{}", worker.new_inbox());
    let delivered = spawn_responder(&worker, subject.clone()).await;

    let (client, events) = connect(&url).await;
    let limit = client.server_info().max_payload;
    assert!(limit > 0, "the server states its limit");
    let transport = NatsTransport::new(Arc::new(client.clone()));

    // The control: a job well inside the limit goes out and is answered.
    // Without it, a transport that refused everything would pass below.
    let inbox = client.new_inbox();
    let reply = tokio::time::timeout(
        Duration::from_secs(5),
        transport.request_with_reply_inbox(&subject, &inbox, vec![b'a'; limit / 2]),
    )
    .await
    .expect("a job inside the limit is answered")
    .expect("a job inside the limit is delivered");
    assert_eq!(reply, (limit / 2).to_string().into_bytes());

    // One byte over.
    let inbox = client.new_inbox();
    let started = Instant::now();
    let refused = tokio::time::timeout(
        Duration::from_secs(5),
        transport.request_with_reply_inbox(&subject, &inbox, vec![b'a'; limit + 1]),
    )
    .await
    .expect(
        "an oversized job must be refused at once, not sent and then waited on \
         for the whole deadline",
    );
    let refusal = refused
        .expect_err("one byte over the server's limit")
        .to_string();
    assert!(
        refusal.contains("max payload") && refusal.contains(&limit.to_string()),
        "the refusal names the limit: {refusal}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "refused in {:?}",
        started.elapsed()
    );

    // It never reached the server: nothing was delivered, and the connection
    // the other dispatches share was not closed over it.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        *delivered.lock().unwrap(),
        vec![limit / 2],
        "only the control job was delivered"
    );
    let seen = events.lock().unwrap().clone();
    assert!(
        !seen.iter().any(|event| event.contains("disconnected")
            || event.to_lowercase().contains("payload")),
        "the connection must survive an oversized job: {seen:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_subject_that_is_not_utf8_does_not_end_the_client() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Some(url) = nats_url() else {
        eprintln!("skipping: set TALOS_TEST_NATS_URL to run (scripts/test-integration.sh does)");
        return;
    };
    let (worker, _) = connect(&url).await;
    let echo = format!("made-up.resilience.echo.{}", worker.new_inbox());
    let _delivered = spawn_responder(&worker, echo.clone()).await;

    let (client, _) = connect(&url).await;
    let prefix = format!("made-up.resilience.wild.{}", client.new_inbox());
    let mut wildcard = client
        .subscribe(format!("{prefix}.*"))
        .await
        .expect("subscribe");
    client.flush().await.expect("flush");
    client
        .request(echo.clone(), "before".into())
        .await
        .expect("the client works before the message arrives");

    // A raw connection: no client library will write this subject.
    let address = url
        .trim_start_matches("nats://")
        .rsplit('@')
        .next()
        .unwrap()
        .to_string();
    let mut raw = tokio::net::TcpStream::connect(&address)
        .await
        .expect("raw connection to the scratch nats-server");
    let mut scratch = [0u8; 4096];
    let _ = raw.read(&mut scratch).await.expect("INFO");
    raw.write_all(b"CONNECT {\"verbose\":false,\"pedantic\":false}\r\n")
        .await
        .unwrap();
    let mut publish = format!("PUB {prefix}.").into_bytes();
    publish.push(0xFF);
    publish.extend_from_slice(b" 2\r\nhi\r\nPING\r\n");
    raw.write_all(&publish).await.unwrap();
    let read = tokio::time::timeout(Duration::from_secs(2), raw.read(&mut scratch))
        .await
        .expect("the server answers the PING")
        .expect("read");
    let answer = String::from_utf8_lossy(&scratch[..read]).to_string();
    assert!(
        answer.contains("PONG"),
        "the scratch server must accept the publish (it needs no credentials): {answer}"
    );

    // The client may drop and re-establish its connection over the message.
    // What it may not do is stop: within ten seconds it must answer requests
    // and deliver to the same subscription again.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_error = String::from("never tried");
    let recovered = loop {
        match tokio::time::timeout(
            Duration::from_secs(1),
            client.request(echo.clone(), "after".into()),
        )
        .await
        {
            Ok(Ok(_)) => break true,
            Ok(Err(e)) => last_error = e.to_string(),
            Err(_) => last_error = "timed out".to_string(),
        }
        if Instant::now() > deadline {
            break false;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    assert!(
        recovered,
        "one message with a non-UTF-8 subject ended the client: {last_error}"
    );

    client
        .publish(format!("{prefix}.ok"), "still subscribed".into())
        .await
        .expect("publish after the message");
    client.flush().await.expect("flush");
    let mut delivered_after = None;
    while let Ok(Some(message)) =
        tokio::time::timeout(Duration::from_secs(3), wildcard.next()).await
    {
        if message.subject.as_str() == format!("{prefix}.ok") {
            delivered_after = Some(message.payload.to_vec());
            break;
        }
    }
    assert_eq!(
        delivered_after.as_deref(),
        Some(&b"still subscribed"[..]),
        "the wildcard subscription must still deliver"
    );
}
