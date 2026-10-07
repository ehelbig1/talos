//! # One place a Redis connection is opened
//!
//! Every Redis connection in the workspace is opened by [`multiplexed`] or
//! [`manager`], so the deadlines a connection carries are decided here, once.
//! `clippy.toml` disallows the `redis` constructors everywhere else.
//!
//! ## Why this exists
//!
//! `redis` 0.27 put no deadline on an async connection. From 1.0 the library
//! defaults are **500 ms for a response and 1 s to connect**, on every async
//! connection, with no client-wide setting — only a config passed where each
//! connection is opened. When the workspace moved to 1.7 (2026-10-07) it
//! opened connections at 44 call sites in 19 crates, none of which passed
//! one. Taking the bump as it came would have put a 500 ms deadline on every
//! Redis call behind login, rate limiting, replay protection and idempotency,
//! and the module cache's multi-megabyte values, without anyone choosing it.
//!
//! ## The deadlines
//!
//! * [`CONNECT_TIMEOUT`] — 5 s. Connecting was unbounded; it is now bounded
//!   at the workspace's floor for any connect timeout. That floor was set
//!   after a cold name lookup was measured at 2.0–2.1 s inside the
//!   containers, which failed every client with a shorter one; the library's
//!   1 s is below it.
//! * [`RESPONSE_TIMEOUT`] — none, which is what every call site had before.
//!   A caller that needs a deadline on one operation wraps that operation, as
//!   the rate limiter does (3 s). Bounding all of them is a decision to make
//!   with the fleet's Redis latencies in hand; it is this one constant.
//!
//! The reconnect policy of a [`ConnectionManager`] is the library's default,
//! unchanged from 0.27: six attempts, backing off from 100 ms by a factor of
//! two.

use redis::aio::{ConnectionManager, ConnectionManagerConfig, MultiplexedConnection};
use redis::{AsyncConnectionConfig, Client, RedisResult};
use std::time::Duration;

/// How long opening a connection may take, name lookup and handshake included.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long one command may wait for its reply: no library deadline.
pub const RESPONSE_TIMEOUT: Option<Duration> = None;

/// The configuration of a multiplexed connection opened by [`multiplexed`].
#[must_use]
pub fn connection_config() -> AsyncConnectionConfig {
    AsyncConnectionConfig::new()
        .set_connection_timeout(Some(CONNECT_TIMEOUT))
        .set_response_timeout(RESPONSE_TIMEOUT)
}

/// The configuration of a connection manager opened by [`manager`].
#[must_use]
pub fn manager_config() -> ConnectionManagerConfig {
    ConnectionManagerConfig::new()
        .set_connection_timeout(Some(CONNECT_TIMEOUT))
        .set_response_timeout(RESPONSE_TIMEOUT)
}

/// Open a multiplexed connection: one socket, safe to clone and share.
///
/// # Errors
///
/// Whatever the connect fails with, a timeout after [`CONNECT_TIMEOUT`]
/// included.
// disallowed-method: redis::Client::get_multiplexed_async_connection_with_config — the one sanctioned opener of a multiplexed connection
#[allow(clippy::disallowed_methods)]
pub async fn multiplexed(client: &Client) -> RedisResult<MultiplexedConnection> {
    client
        .get_multiplexed_async_connection_with_config(&connection_config())
        .await
}

/// Open a connection manager: a multiplexed connection that reconnects.
///
/// # Errors
///
/// Whatever the first connect fails with, once its retries are spent.
// disallowed-method: redis::aio::ConnectionManager::new_with_config — the one sanctioned opener of a connection manager
#[allow(clippy::disallowed_methods)]
pub async fn manager(client: Client) -> RedisResult<ConnectionManager> {
    ConnectionManager::new_with_config(client, manager_config()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two decisions, stated so that changing either is an edit to a
    /// test as well as to a constant.
    #[test]
    fn the_deadlines_are_the_decided_ones() {
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(5));
        assert_eq!(RESPONSE_TIMEOUT, None);
        let manager = manager_config();
        assert_eq!(manager.connection_timeout(), Some(CONNECT_TIMEOUT));
        assert_eq!(manager.response_timeout(), RESPONSE_TIMEOUT);
        // The reconnect policy is the library's, and is what 0.27 had.
        assert_eq!(manager.number_of_retries(), 6);
        assert_eq!(manager.min_delay(), Duration::from_millis(100));
        assert!((manager.exponent_base() - 2.0).abs() < f32::EPSILON);
    }
}
