//! Pluggable error classification for retry decisions.
//!
//! When a node dispatch fails, the executor asks: "is this worth
//! retrying?" Timeout / rate-limit / connection-reset errors generally
//! yes; auth failures / invalid-input / 4xx responses generally no.
//! The concrete policy — what error-message shapes count as
//! "transient" — is consumer-specific; impls plug their own rules in.
//!
//! The trait splits classification and transient-decision into two
//! methods so impls can store the class for telemetry separately from
//! driving the retry loop.

/// Classify dispatch errors to decide whether to retry.
pub trait RetryClassifier: Send + Sync {
    /// Map an error message to a short stable class tag (e.g.
    /// `"timeout"`, `"rate_limit"`, `"auth"`, `"invalid_input"`,
    /// `"server_error"`, `"unknown"`). The returned tag is recorded
    /// in retry-event telemetry and passed to [`is_transient`] to
    /// decide whether to try again.
    ///
    /// [`is_transient`]: Self::is_transient
    fn classify(&self, error: &str) -> String;

    /// Given a class tag produced by [`classify`], decide whether
    /// the executor should retry. A default-ish impl returns `true`
    /// for `"timeout"` / `"rate_limit"` / `"server_error"` and
    /// `false` otherwise.
    ///
    /// [`classify`]: Self::classify
    fn is_transient(&self, class: &str) -> bool;
}
