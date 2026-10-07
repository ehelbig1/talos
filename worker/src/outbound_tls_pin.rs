//! Which TLS library an outbound HTTPS request from THIS binary uses.
//!
//! Every manifest in the workspace asked `reqwest` for rustls from the start.
//! Until 2026-10-07 what ran was OpenSSL: one crate enabled a third-party
//! dependency's default features, those switched on `reqwest`'s native-tls
//! backend, Cargo merged that into the one `reqwest` build the binary links,
//! and `reqwest` 0.12 preferred native-tls whenever it was compiled in. The
//! manifests said one thing and the binary did another, and nothing looked.
//!
//! A manifest cannot settle it, and neither can a test in a library crate:
//! features are merged across everything a binary links, so only a test built
//! with the binary sees what the binary gets. This one speaks TLS to a port
//! that answers in plain HTTP and reads whose error comes back.

use std::error::Error as _;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A server that answers anything with a plain HTTP response.
async fn spawn_plain_http_server() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("address").port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut hello = [0u8; 1024];
                let _ = stream.read(&mut hello).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n")
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });
    port
}

#[tokio::test]
async fn outbound_tls_is_rustls() {
    let port = spawn_plain_http_server().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");

    let error = client
        .get(format!("https://127.0.0.1:{port}/"))
        .send()
        .await
        .expect_err("a plain-HTTP answer is not a TLS handshake");
    let mut said = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        said.push_str(" <- ");
        said.push_str(&cause.to_string());
        source = cause.source();
    }

    // rustls: "received corrupt message of type InvalidContentType".
    // OpenSSL: "error:0A00010B:SSL routines:tls_validate_record_header:wrong
    // version number". Secure Transport and SChannel have wordings of their
    // own; none of them says this.
    assert!(
        said.contains("corrupt message"),
        "the TLS failure is not rustls's — another TLS backend has been compiled into \
         reqwest and is being preferred (look for a dependency enabling its native-tls \
         feature): {said}"
    );
    assert!(
        error.is_connect(),
        "a handshake failure is a connect failure: {said}"
    );
}
