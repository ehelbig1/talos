//! The closed label set for `talos_webhook_duplicate_suppressed_total{format}`
//! — the counter that says an inbound webhook delivery was answered 200 and
//! dispatched nothing.
//!
//! Why it exists (2026-09-17, package CI): the GitHub signature format signs
//! the body ALONE, so it carries no timestamp and can have no freshness
//! window; its only replay defence is the Redis deduplication store, and the
//! delivery's dedup fingerprint IS its signature value — `HMAC(secret, body)`,
//! deterministic in the body. GitHub's manual *Redeliver* re-sends that same
//! body, so a legitimate redelivery and a captured replay are identical in
//! every AUTHENTICATED field: the replay-suppression horizon and the
//! legitimate-redelivery-suppression horizon are the same number. Package CI
//! widened the GitHub horizon from one hour to twenty-four, which shrinks the
//! attack window 24× and lengthens the window in which an operator clicking
//! "Redeliver" gets a 200 and no execution. That second half must be VISIBLE,
//! so the suppression is counted.
//!
//! `format` is the scheme that AUTHENTICATED the request, never a header the
//! verifier did not check. Every value is pre-seeded at 0 and every one is
//! reachable: each format's own deliveries can repeat.
//!
//! **No alert.** A suppression is deduplication working as designed, and there
//! is deliberately no denominator series to form a ratio against — this is an
//! absolute count an operator reads directly (a webhook request counter was
//! deleted in the 2026-09-11 dead-metric burn-down because its only label was
//! the per-row `trigger_id`, which this file does not re-admit).

/// How a webhook request was authenticated, as a metric label. The mirror of
/// `talos_webhooks::signature::WebhookAuthOutcome`, which cannot be imported
/// here without inverting the layering; the mapping is an exhaustive match in
/// that crate and is pinned by its own test (#787's precedent for the RPC
/// subject strings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebhookAuthFormat {
    /// `X-Slack-Signature` over `v0:<ts>:<body>` — timestamp bound, ±5 min.
    Slack,
    /// `X-Hub-Signature-256` over the body alone — no timestamp, no window.
    GitHub,
    /// `X-Signature` over `<ts>.<body>` with `X-Webhook-Timestamp`.
    Generic,
    /// The static `X-Verification-Token` matched; no signature was checked, so
    /// the fingerprint is the body hash.
    StaticToken,
    /// The trigger has neither a signing secret nor a verification token.
    Open,
}

impl WebhookAuthFormat {
    pub const ALL: &'static [Self] = &[
        Self::Slack,
        Self::GitHub,
        Self::Generic,
        Self::StaticToken,
        Self::Open,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Slack => "slack",
            Self::GitHub => "github",
            Self::Generic => "generic",
            Self::StaticToken => "static_token",
            Self::Open => "open",
        }
    }
}
