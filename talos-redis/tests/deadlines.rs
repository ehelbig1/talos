//! The two deadlines `talos-redis` decides, shown on the wire.
//!
//! No Redis is needed: the "server" is a socket that speaks just enough of
//! the protocol, which is the only way to make a reply late on purpose.

use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// How long the fake server sits on a `GET`. Longer than the 500 ms the
/// `redis` library puts on every response by default from 1.0.
const SLOW_REPLY: Duration = Duration::from_millis(900);

/// Count the commands in `buffer` (RESP arrays of bulk strings), returning
/// each command's name and how many bytes were consumed.
fn take_commands(buffer: &[u8]) -> (Vec<String>, usize) {
    fn line(buffer: &[u8], from: usize) -> Option<(&[u8], usize)> {
        let end = buffer[from..].windows(2).position(|w| w == b"\r\n")? + from;
        Some((&buffer[from..end], end + 2))
    }
    let mut names = Vec::new();
    let mut consumed = 0;
    'commands: while let Some((header, mut at)) = line(buffer, consumed) {
        if header.first() != Some(&b'*') {
            break;
        }
        let parts: usize = std::str::from_utf8(&header[1..]).unwrap().parse().unwrap();
        let mut name = String::new();
        for part in 0..parts {
            let Some((length, body)) = line(buffer, at) else {
                break 'commands;
            };
            let length: usize = std::str::from_utf8(&length[1..]).unwrap().parse().unwrap();
            if buffer.len() < body + length + 2 {
                break 'commands;
            }
            if part == 0 {
                name = String::from_utf8_lossy(&buffer[body..body + length]).to_uppercase();
            }
            at = body + length + 2;
        }
        names.push(name);
        consumed = at;
    }
    (names, consumed)
}

/// A server that answers `+OK` to everything at once, except `GET`, which it
/// answers `hi` after [`SLOW_REPLY`].
async fn spawn_server_with_a_slow_get() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let Ok(read) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                    let (names, consumed) = take_commands(&buffer);
                    buffer.drain(..consumed);
                    for name in names {
                        let reply: &[u8] = if name == "GET" {
                            tokio::time::sleep(SLOW_REPLY).await;
                            b"$2\r\nhi\r\n"
                        } else {
                            b"+OK\r\n"
                        };
                        if stream.write_all(reply).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    format!("redis://{address}")
}

/// A server that accepts the connection and never says anything.
async fn spawn_server_that_never_answers() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    format!("redis://{address}")
}

/// A reply slower than the library's 500 ms default still arrives, on both
/// kinds of connection: a response has no library deadline here.
///
/// It fails if either opener stops passing its configuration — the reply
/// would be cut off at 500 ms with `timed out`.
#[tokio::test(flavor = "multi_thread")]
async fn a_reply_slower_than_the_library_default_still_arrives() {
    let url = spawn_server_with_a_slow_get().await;
    let client = redis::Client::open(url).expect("url");

    let mut multiplexed = talos_redis::multiplexed(&client).await.expect("connect");
    let mut manager = talos_redis::manager(client.clone()).await.expect("connect");

    let get = redis::cmd("GET").arg("k").to_owned();
    let started = Instant::now();
    let (a, b) = tokio::join!(
        get.query_async::<String>(&mut multiplexed),
        get.query_async::<String>(&mut manager),
    );
    assert_eq!(a.expect("multiplexed: the slow reply arrives"), "hi");
    assert_eq!(b.expect("manager: the slow reply arrives"), "hi");
    assert!(
        started.elapsed() >= SLOW_REPLY,
        "the reply was meant to be slow: {:?}",
        started.elapsed()
    );
}

/// Connecting gives up after [`talos_redis::CONNECT_TIMEOUT`] — not after the
/// library's 1 s, and not never.
#[tokio::test(flavor = "multi_thread")]
async fn connecting_gives_up_after_the_decided_time() {
    let url = spawn_server_that_never_answers().await;
    let client = redis::Client::open(url).expect("url");

    let started = Instant::now();
    let refused = talos_redis::multiplexed(&client).await;
    let took = started.elapsed();

    let error = refused.expect_err("a server that never answers is not a connection");
    assert!(error.is_timeout(), "a timeout, not {error}");
    let decided = talos_redis::CONNECT_TIMEOUT;
    assert!(
        took >= decided - Duration::from_millis(250) && took < decided + Duration::from_secs(3),
        "gave up after {took:?}; the decided time is {decided:?}"
    );
}
