//! The worker's answer to a VERIFIED dispatch it did not run because the
//! shared replay store could not vouch for its nonce under a fail-closed
//! policy (security review 2026-10-15, B2-3).
//!
//! Until then the worker dropped such a dispatch with no reply, and the
//! dispatcher waited out the whole attempt window; under a Redis outage every
//! dispatch stalled that way. The worker now answers the request's own
//! (signed) reply topic with a `Failed` result whose error is
//! [`REPLAY_STORE_UNAVAILABLE_MESSAGE`], and the controller's retry
//! classifier reads the marker as transient: the dispatcher re-sends under a
//! fresh nonce after its backoff, which runs once the store answers again.
//!
//! A REPLAY (the store has seen the nonce) is never answered: the reply topic
//! belongs to the original dispatcher, which may be waiting on the live
//! attempt.
//!
//! This is not one of the runtime's host tokens ([`crate::ALL`]): the worker
//! binary mints it, before any module runs.

/// The marker token.
pub const REPLAY_STORE_UNAVAILABLE: &str = "replay-store-unavailable";

/// The whole error text of the answer, marker included.
pub const REPLAY_STORE_UNAVAILABLE_MESSAGE: &str =
    "dispatch not run: the shared replay store could not vouch for its nonce \
     [reason_class=replay-store-unavailable]";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_message_carries_the_marker() {
        assert!(REPLAY_STORE_UNAVAILABLE_MESSAGE
            .contains(&format!("[reason_class={REPLAY_STORE_UNAVAILABLE}]")));
        assert_eq!(
            crate::token(REPLAY_STORE_UNAVAILABLE_MESSAGE),
            Some(REPLAY_STORE_UNAVAILABLE)
        );
    }
}
