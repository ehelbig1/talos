//! Job messages the worker dropped BEFORE they could be verified: oversized
//! (> 32 MiB) or undecodable payloads on `talos.jobs` / `talos.pipeline.jobs`.
//!
//! These used to be one ERROR per message and nothing else, so a steady
//! stream of them was invisible to anything but a log grep while the
//! controller simply waited out its dispatch timeout.
//!
//! **Why there is no fail-fast reply.** Nothing in a rejected message is
//! authenticated: its `job_id` and `reply_topic` are exactly as trustworthy
//! as the bytes that failed to decode. A signed failure published to
//! `talos.results.<job_id>` would let any publisher on the job subject make
//! this worker sign a `Failed` result for a job id of its choosing, which the
//! `talos.results.*` observer then finalizes — i.e. kill someone else's
//! in-flight run. Replying to the wire reply subject is ruled out for the
//! same reason (`pick_trusted_reply_topic`). So the drop stays a drop; the
//! counter and a rate-limited WARN make it SAYABLE.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy)]
pub(crate) enum JobKind {
    Single,
    Pipeline,
}

impl JobKind {
    const ALL: [JobKind; 2] = [JobKind::Single, JobKind::Pipeline];
    fn label(self) -> &'static str {
        match self {
            JobKind::Single => "single",
            JobKind::Pipeline => "pipeline",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum RejectReason {
    Oversized,
    Undecodable,
}

impl RejectReason {
    const ALL: [RejectReason; 2] = [RejectReason::Oversized, RejectReason::Undecodable];
    fn label(self) -> &'static str {
        match self {
            RejectReason::Oversized => "oversized",
            RejectReason::Undecodable => "undecodable",
        }
    }
}

/// One WARN per `(kind, reason)` per this many seconds; the rest are counted.
const WARN_INTERVAL_SECS: u64 = 60;

static COUNTER: LazyLock<Option<prometheus::IntCounterVec>> = LazyLock::new(|| {
    let c = prometheus::IntCounterVec::new(
        prometheus::Opts::new(
            "talos_worker_rejected_job_messages_total",
            "Job messages dropped before verification, by kind (single|pipeline) and \
             reason (oversized|undecodable). No reply is sent: nothing in such a message \
             is authenticated, so the controller waits out its dispatch timeout.",
        ),
        &["kind", "reason"],
    )
    .ok()?;
    prometheus::default_registry()
        .register(Box::new(c.clone()))
        .ok()?;
    Some(c)
});

/// Last-WARN time (unix secs) per `(kind, reason)`, index `kind * 2 + reason`.
static LAST_WARN: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

fn slot(kind: JobKind, reason: RejectReason) -> usize {
    (kind as usize) * 2 + reason as usize
}

/// Pre-seed every `(kind, reason)` pair at 0 — its healthy value is 0
/// forever, which an ABSENT series would render identically.
pub(crate) fn seed() {
    if let Some(c) = COUNTER.as_ref() {
        for kind in JobKind::ALL {
            for reason in RejectReason::ALL {
                c.with_label_values(&[kind.label(), reason.label()])
                    .inc_by(0);
            }
        }
    }
}

/// Whether a WARN is due now; claims the slot when it is.
pub(crate) fn warn_due(last: &AtomicU64, now_secs: u64, interval: u64) -> bool {
    let prev = last.load(Ordering::Relaxed);
    (prev == 0 || now_secs.saturating_sub(prev) >= interval)
        && last
            .compare_exchange(prev, now_secs.max(1), Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
}

pub(crate) fn record(kind: JobKind, reason: RejectReason, payload_bytes: usize) {
    if let Some(c) = COUNTER.as_ref() {
        c.with_label_values(&[kind.label(), reason.label()]).inc();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if warn_due(&LAST_WARN[slot(kind, reason)], now, WARN_INTERVAL_SECS) {
        ::tracing::warn!(
            kind = kind.label(),
            reason = reason.label(),
            payload_bytes,
            "SECURITY: dropped a job message before verification (no reply is sent; \
             further drops of this kind are counted on \
             talos_worker_rejected_job_messages_total for the next minute)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warn_is_rate_limited_per_slot() {
        let last = AtomicU64::new(0);
        assert!(warn_due(&last, 1_000, 60));
        assert!(!warn_due(&last, 1_030, 60));
        assert!(warn_due(&last, 1_060, 60));
    }

    #[test]
    fn every_pair_is_seeded_and_counted() {
        seed();
        record(JobKind::Pipeline, RejectReason::Undecodable, 3);
        let text = {
            use prometheus::Encoder as _;
            let mut buf = Vec::new();
            prometheus::TextEncoder::new()
                .encode(&prometheus::default_registry().gather(), &mut buf)
                .unwrap();
            String::from_utf8(buf).unwrap()
        };
        for kind in ["single", "pipeline"] {
            for reason in ["oversized", "undecodable"] {
                assert!(
                    text.contains(&format!(
                        "talos_worker_rejected_job_messages_total{{kind=\"{kind}\",reason=\"{reason}\"}}"
                    )),
                    "{kind}/{reason} must be exported:\n{text}"
                );
            }
        }
        assert!(text.contains(
            "talos_worker_rejected_job_messages_total{kind=\"pipeline\",reason=\"undecodable\"} "
        ));
    }
}
