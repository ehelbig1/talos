//! What a push transport is told when the watch lookup does not produce a row.
//!
//! Every push integration asks the same question immediately after
//! authenticating a delivery: *which watch is this for?* The lookup is
//! three-valued, and the two non-`Found` answers mean opposite things:
//!
//! * **Absent** (`Ok(None)`) — a determinate answer. The watch was revoked, or
//!   renewed while the old channel id was still in flight. There is nothing to
//!   do and there never will be, so the delivery is ACKED. Deferring instead
//!   would make the transport redeliver forever.
//! * **Unreadable** (`Err`) — a pool timeout, a Postgres restart, projection
//!   drift. The row's existence is UNKNOWN. Acking here tells the transport the
//!   delivery was handled, so it is dropped permanently — and nothing else
//!   retries it. The delivery is therefore DEFERRED: Pub/Sub and Google's
//!   webhook both redeliver a non-2xx within their retention window.
//!
//! This is the same fail-closed rule the rest of the platform already applies
//! to a rule it cannot read (`write_ceiling` refuses on an unreadable ceiling;
//! `push_admission` returns `DeferReadFailed`). It lives here, in one place,
//! because it had been decided THREE times and answered two different ways:
//! `talos-google-calendar`'s webhook — the first integration, and the one
//! `docs/integration-pattern.md` is distilled from — returned 500 on an
//! unreadable lookup and 200 on an absent one, correctly; the Gmail and GCP
//! Pub/Sub handlers, written second and third by copying the pattern, returned
//! **200 for both**. The rule did not replicate, which is exactly what check
//! 79's own entry predicted would happen to the next integration — and check
//! 79 is structurally green over it, because it proves the arms are SPLIT and
//! never that the `Err` arm is right.
//!
//! The deferral is COUNTED rather than only logged: deferring is the safe
//! direction, but a deferral that repeats past the subscription's retention
//! becomes real loss, and a per-occurrence ERROR line cannot be aggregated into
//! that judgement.

use axum::http::StatusCode;
use talos_metrics::PushDeferReason;

// Re-exported so a push handler needs ONE import and no direct
// `talos-metrics` dependency edge of its own (talos-gmail has none).
pub use talos_metrics::PushIntegration;

/// The outcome of a push transport's watch/channel lookup, for the two cases
/// that produce no row. `#[must_use]` because the whole point is that the
/// status code comes from [`Self::status`] and is not chosen at the call site.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushWatchLookup {
    /// `Ok(None)` — the watch is definitely not there.
    Absent,
    /// `Err(_)` — the lookup did not answer.
    Unreadable,
}

impl PushWatchLookup {
    /// The status code the transport must receive.
    ///
    /// `Absent` acks (200): a determinate negative, and redelivering it would
    /// loop for the life of the subscription. `Unreadable` defers (503): the
    /// transport retries with backoff, which is the only thing that can still
    /// save the delivery.
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            Self::Absent => StatusCode::OK,
            Self::Unreadable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// Whether this outcome hands the delivery back for redelivery.
    #[must_use]
    pub const fn defers(self) -> bool {
        matches!(self, Self::Unreadable)
    }
}

/// Record one push deferred because its watch lookup could not be read, and
/// return the status code to send. One call site per transport, so the count
/// and the wire answer cannot disagree.
pub fn defer_unreadable_watch(integration: PushIntegration) -> StatusCode {
    talos_metrics::record_google_push_deferred(integration, PushDeferReason::WatchLookupUnreadable);
    PushWatchLookup::Unreadable.status()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two sides must DIFFER. A test asserting only that each arm returns
    /// "a status" would pass over the defect this module exists to remove,
    /// which is precisely that both arms returned the SAME code.
    #[test]
    fn an_unreadable_lookup_does_not_answer_like_an_absent_one() {
        assert_ne!(
            PushWatchLookup::Absent.status(),
            PushWatchLookup::Unreadable.status(),
            "acking an unreadable lookup discards the delivery permanently"
        );
    }

    #[test]
    fn an_absent_watch_is_acked_so_the_transport_stops_redelivering() {
        assert_eq!(PushWatchLookup::Absent.status(), StatusCode::OK);
        assert!(!PushWatchLookup::Absent.defers());
    }

    #[test]
    fn an_unreadable_watch_is_deferred_so_the_transport_retries() {
        let s = PushWatchLookup::Unreadable.status();
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
        assert!(s.is_server_error(), "a 2xx would be read as handled");
        assert!(PushWatchLookup::Unreadable.defers());
    }

    /// The deferral recorder must return the deferring status, not merely
    /// count. Reverting it to `StatusCode::OK` would leave the counter moving
    /// while the delivery is still dropped — a metric that contradicts the wire.
    #[test]
    fn the_recorder_returns_the_deferring_status() {
        for integration in PushIntegration::ALL {
            assert_eq!(
                defer_unreadable_watch(*integration),
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
    }
}

/// The call sites, which no unit test in this crate can reach: the watch
/// lookup sits AFTER JWT verification, so driving either handler needs forged
/// signing material. The decision above is pure and tested; these pins are the
/// second copy, and they are stated as pins rather than implied to be
/// behavioural coverage.
///
/// Comments are stripped before matching. The explanatory comments at both
/// call sites quote `StatusCode::OK` while explaining why it is wrong, and an
/// unstripped pin would read that as the defect (or, worse, read a comment
/// naming the helper as the fix) — the self-report trap that has now caught
/// checks 73, 87, 97, EG's check 4 and EQ.
#[cfg(test)]
mod call_site_pins {
    /// Drop `//` line comments outside string literals.
    fn strip_line_comments(src: &str) -> String {
        let mut out = String::with_capacity(src.len());
        for line in src.lines() {
            let mut in_str = false;
            let mut prev_backslash = false;
            let b: Vec<char> = line.chars().collect();
            // CHARS, not bytes: these files carry em-dashes, and
            // `line.len()` would index past the end of `b`.
            let mut cut = b.len();
            let mut i = 0;
            while i < b.len() {
                let c = b[i];
                if in_str {
                    if c == '\\' && !prev_backslash {
                        prev_backslash = true;
                    } else {
                        if c == '"' && !prev_backslash {
                            in_str = false;
                        }
                        prev_backslash = false;
                    }
                } else if c == '"' {
                    in_str = true;
                } else if c == '/' && i + 1 < b.len() && b[i + 1] == '/' {
                    cut = i;
                    break;
                }
                i += 1;
            }
            out.push_str(&b[..cut].iter().collect::<String>());
            out.push('\n');
        }
        out
    }

    /// From the lookup call, the enclosing `match`'s arms.
    fn arms_after(src: &str, lookup: &str) -> String {
        let i = src.find(lookup).unwrap_or_else(|| {
            panic!(
                "anchor {lookup} not found — the pin matched nothing, \
                 which is a green tick over zero statements; re-point it"
            )
        });
        let rest = &src[i..];
        rest[..rest.len().min(1200)].to_string()
    }

    fn assert_transport(src: &str, lookup: &str, integration: &str) {
        let stripped = strip_line_comments(src);
        let arms = arms_after(&stripped, lookup);
        assert!(
            arms.contains("defer_unreadable_watch"),
            "{lookup}: the unreadable arm must defer through the shared decision"
        );
        assert!(
            arms.contains(integration),
            "{lookup}: the deferral must name its own integration"
        );
        assert!(
            arms.contains("PushWatchLookup::Absent"),
            "{lookup}: the absent arm must ack through the shared decision"
        );
        assert!(
            !arms.contains("StatusCode::OK"),
            "{lookup}: a bare StatusCode::OK here acks a delivery the transport \
             would otherwise redeliver — that is the defect this module removes"
        );
    }

    #[test]
    fn the_gmail_push_handler_defers_an_unreadable_watch() {
        assert_transport(
            include_str!("../../talos-gmail/src/handlers.rs"),
            "find_by_email(",
            "PushIntegration::Gmail",
        );
    }

    #[test]
    fn the_gcp_push_handler_defers_an_unreadable_watch() {
        assert_transport(
            include_str!("../../talos-google-cloud/src/handlers.rs"),
            "find_by_push_token(",
            "PushIntegration::Gcp",
        );
    }

    /// The reference implementation, and the reason this module exists:
    /// Calendar had the rule right before either Pub/Sub transport did. It is
    /// deliberately NOT rewritten to use `push_ack` — its 500 already defers
    /// and churning a correct handler is an unrelated behaviour change — so it
    /// is pinned in its own vocabulary instead.
    #[test]
    fn the_calendar_webhook_already_distinguished_the_two() {
        let src = strip_line_comments(include_str!("../../talos-google-calendar/src/handlers.rs"));
        let arms = arms_after(&src, "find_channel_by_google_id(");
        assert!(
            arms.contains("StatusCode::INTERNAL_SERVER_ERROR"),
            "Calendar's unreadable arm must keep deferring"
        );
        assert!(
            arms.contains("StatusCode::OK"),
            "Calendar's absent arm must keep acking"
        );
    }
}
