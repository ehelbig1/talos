//! The WebSocket handshake refuses an absent `Origin` wherever browser
//! hardening is required — `RUST_ENV=staging` included (2026-10-14).
//!
//! A process of its own: it sets `RUST_ENV`, which the verdict reads, and no
//! other test may see that. One test, so nothing in this binary races it.

use talos_metrics::WsHandshakeOutcome;
use talos_ws_auth::origin_verdict;

#[test]
fn an_absent_origin_is_refused_outside_development() {
    let before = std::env::var("RUST_ENV").ok();
    let verdict_under = |rust_env: Option<&str>| {
        match rust_env {
            Some(v) => std::env::set_var("RUST_ENV", v),
            None => std::env::remove_var("RUST_ENV"),
        }
        origin_verdict(None)
    };

    let staging = verdict_under(Some("staging"));
    let production = verdict_under(Some("production"));
    let development = verdict_under(Some("development"));
    let unset = verdict_under(None);
    match &before {
        Some(v) => std::env::set_var("RUST_ENV", v),
        None => std::env::remove_var("RUST_ENV"),
    }

    assert_eq!(
        staging,
        Err(WsHandshakeOutcome::OriginMissing),
        "RUST_ENV=staging must refuse a WebSocket upgrade with no Origin"
    );
    assert_eq!(production, Err(WsHandshakeOutcome::OriginMissing));
    // A non-browser development client may omit it.
    assert_eq!(development, Ok(()));
    assert_eq!(unset, Ok(()));
}
