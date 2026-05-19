//! Retry policy for node execution.

use serde::{Deserialize, Serialize};

/// How the executor should retry a node when its dispatch fails.
///
/// Defaults to 2 retries with 500ms backoff, no conditional gate, and no
/// custom delay expression — a reasonable starting point that callers can
/// override per-node. Both Rhai-style expression fields are opaque here:
/// evaluation is the executor's job.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts after the first failure.
    pub max_retries: u32,
    /// Base backoff between attempts in milliseconds. The executor may
    /// apply exponential growth and jitter on top of this value.
    pub backoff_ms: u64,
    /// Optional expression evaluated against the error output. If present
    /// and it evaluates to `false`, retry is skipped and the error is
    /// returned immediately.
    pub retry_condition: Option<String>,
    /// Optional expression that returns a delay in milliseconds computed
    /// from the error output. If present and evaluates to a number, that
    /// value (capped at `60_000` ms by the executor) is used in place of
    /// exponential backoff.
    pub retry_delay_expression: Option<String>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 2,
            backoff_ms: 500,
            retry_condition: None,
            retry_delay_expression: None,
        }
    }
}
