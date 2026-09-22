//! Webhook request authenticity — WHICH format verified, and the dedup
//! fingerprint that must be derived from it.
//!
//! Two functions used to answer one question in two different orders.
//! `verify_hmac_signature` tried Slack → GitHub → generic and returned a bare
//! `bool`; the dedup step then picked the event fingerprint by HEADER
//! PRECEDENCE — `x-signature` → `x-hub-signature-256` → `x-slack-signature` →
//! `x-github-delivery` → `x-request-id` → body hash. So a captured GitHub
//! delivery (valid `x-hub-signature-256`, which signs the body alone and
//! carries no timestamp) replayed with a FRESH RANDOM `X-Signature` header
//! verified through the GitHub branch and deduplicated on the attacker's
//! header: every replay was a "new" event, and dedup is the ONLY replay
//! defence the GitHub format has (see the MCP-1100 comment in `router.rs`).
//!
//! The fix is structural rather than a re-ordering of the header list: the
//! verifier now reports the [`VerifiedSignatureFormat`] that actually
//! authenticated the request, and [`dedup_fingerprint`] is derived from THAT
//! format's own signature value. A header the verifier did not check can never
//! become the fingerprint. In the static-token and open modes there is no
//! verified signature at all, so the fingerprint is the body hash and nothing
//! else — never a caller-chosen delivery/request id.

use axum::body::Bytes;
use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::types::webhook_timestamp_skew_secs;

/// The signature scheme that authenticated a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedSignatureFormat {
    /// `X-Slack-Signature: v0=<hex>` over `v0:<ts>:<body>`, ±5-minute window.
    Slack,
    /// `X-Hub-Signature-256: sha256=<hex>` over the body alone (no timestamp).
    GitHub,
    /// `X-Signature: <hex>` over `<ts>.<body>` with `X-Webhook-Timestamp`.
    Generic,
}

impl VerifiedSignatureFormat {
    /// The request header whose value IS this format's signature.
    pub fn signature_header(self) -> &'static str {
        match self {
            VerifiedSignatureFormat::Slack => "x-slack-signature",
            VerifiedSignatureFormat::GitHub => "x-hub-signature-256",
            VerifiedSignatureFormat::Generic => "x-signature",
        }
    }
}

/// How a webhook request was authenticated — the input the dedup fingerprint
/// is derived from. Constructed only by the auth gate in `handle_webhook`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookAuthOutcome {
    /// An HMAC signature in the named format verified.
    Hmac(VerifiedSignatureFormat),
    /// The static `X-Verification-Token` matched. No signature was checked, so
    /// no header value is trustworthy as an event identity.
    StaticToken,
    /// The trigger has neither a signing secret nor a verification token.
    Open,
}

/// Hex SHA-256 of the request body — the fingerprint of last resort, and the
/// ONLY fingerprint when no signature was verified.
pub fn body_fingerprint(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

/// Derive the deduplication fingerprint from the authentication outcome.
///
/// * `Hmac(fmt)` → the value of `fmt`'s own signature header. That value was
///   just verified against the signing secret, so it is bound to the body (and,
///   for Slack/generic, to the timestamp); two deliveries with the same
///   signature are the same event. If the header is somehow unreadable as a
///   string the body hash is used — it cannot be absent, since the verifier
///   read it.
/// * `StaticToken` / `Open` → the body hash. No header on such a request was
///   verified, and an unverified header is caller-chosen.
pub fn dedup_fingerprint(outcome: WebhookAuthOutcome, headers: &HeaderMap, body: &[u8]) -> String {
    match outcome {
        WebhookAuthOutcome::Hmac(fmt) => headers
            .get(fmt.signature_header())
            .and_then(|h| h.to_str().ok())
            .map(str::to_string)
            .unwrap_or_else(|| body_fingerprint(body)),
        WebhookAuthOutcome::StaticToken | WebhookAuthOutcome::Open => body_fingerprint(body),
    }
}

/// How long a deduplication claim is retained for every format whose signature
/// binds a timestamp — Slack and generic (±5 min) — and for the token / open
/// modes, whose fingerprint is the body hash. For these the store is not the
/// replay defence: the signed timestamp is, and a delivery repeated past its
/// own freshness window fails verification before it ever reaches dedup. One
/// hour is the concurrent-redelivery guard the store has always been here.
pub const DEDUP_WINDOW_SECS: u64 = 3600;

/// How long a deduplication claim is retained for the GitHub format.
///
/// The GitHub HMAC signs the body ALONE, so no timestamp is bound and no
/// freshness window is possible from the sender's side; this store is the
/// ONLY replay defence the format has, and outside the window a captured,
/// still-valid delivery replays. Package CI (operator decision 2026-09-17)
/// widened it from one hour to twenty-four.
///
/// **This number is two things at once, and the second is the cost.** The
/// GitHub dedup fingerprint is the signature value, `HMAC(secret, body)`,
/// deterministic in the body, and GitHub's manual *Redeliver* re-sends that
/// same body — so a legitimate redelivery is identical to a replay in every
/// authenticated field, and nothing can tell them apart. The replay window and
/// the window in which an operator clicking "Redeliver" gets a 200 with no
/// execution are the SAME number. That is why the suppression is counted on
/// `talos_webhook_duplicate_suppressed_total{format="github"}` rather than
/// only logged: widening the horizon without making its cost visible would be
/// a control whose price nobody can read.
///
/// A longer horizon was considered and left to the operator: cost is not the
/// constraint (measured on the pinned `redis:7-alpine`, 239 bytes per claim,
/// so 1 000 deliveries/day is ~5.7 MB at 24 h and ~7.2 MB at 30 days), the
/// redelivery blackout is.
pub const GITHUB_DEDUP_WINDOW_SECS: u64 = 86_400;

/// The deduplication retention for a request, from the scheme that
/// AUTHENTICATED it. One home: the router reads the window here and passes it
/// to the store, which keeps none of its own.
#[must_use]
pub fn dedup_window(outcome: WebhookAuthOutcome) -> std::time::Duration {
    match outcome {
        WebhookAuthOutcome::Hmac(VerifiedSignatureFormat::GitHub) => {
            std::time::Duration::from_secs(GITHUB_DEDUP_WINDOW_SECS)
        }
        WebhookAuthOutcome::Hmac(VerifiedSignatureFormat::Slack)
        | WebhookAuthOutcome::Hmac(VerifiedSignatureFormat::Generic)
        | WebhookAuthOutcome::StaticToken
        | WebhookAuthOutcome::Open => std::time::Duration::from_secs(DEDUP_WINDOW_SECS),
    }
}

/// The metric label for the scheme that authenticated a request. An exhaustive
/// match, so a sixth outcome cannot reach the counter unlabelled;
/// `talos_metrics` cannot import this enum without inverting the layering, and
/// this mapping plus its test is what keeps the two vocabularies paired
/// (#787's precedent for the RPC subject strings).
#[must_use]
pub fn metrics_format(outcome: WebhookAuthOutcome) -> talos_metrics::WebhookAuthFormat {
    match outcome {
        WebhookAuthOutcome::Hmac(VerifiedSignatureFormat::Slack) => {
            talos_metrics::WebhookAuthFormat::Slack
        }
        WebhookAuthOutcome::Hmac(VerifiedSignatureFormat::GitHub) => {
            talos_metrics::WebhookAuthFormat::GitHub
        }
        WebhookAuthOutcome::Hmac(VerifiedSignatureFormat::Generic) => {
            talos_metrics::WebhookAuthFormat::Generic
        }
        WebhookAuthOutcome::StaticToken => talos_metrics::WebhookAuthFormat::StaticToken,
        WebhookAuthOutcome::Open => talos_metrics::WebhookAuthFormat::Open,
    }
}

/// Is this request header one whose VALUE must never be persisted?
///
/// ONE classifier for every place a webhook's headers are written to a
/// table — the DLQ entry and `webhook_request_log`. Substring-based rather
/// than an exact allowlist so custom auth schemes are caught too. Before this
/// was hoisted out of `enqueue_dlq`, `log_request` persisted
/// `X-Verification-Token` and every signature header in plaintext (F7d).
pub fn header_is_sensitive(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "cookie"
        || n == "set-cookie"
        || n.contains("auth")
        || n.contains("token")
        || n.contains("secret")
        || n.contains("key")
        || n.contains("credential")
        || n.contains("password")
        || n.contains("signature")
}

fn hmac_sha256_hex(secret: &str, parts: &[&[u8]]) -> Option<String> {
    let mut mac = match Hmac::<Sha256>::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => {
            tracing::error!("Invalid HMAC secret size");
            return None;
        }
    };
    for p in parts {
        mac.update(p);
    }
    Some(hex::encode(mac.finalize().into_bytes()))
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Verify an HMAC signature from a webhook request, reporting WHICH format
/// verified. `None` means no format verified (or none was present).
///
/// Format precedence and per-format semantics are unchanged from the
/// pre-refactor `bool` verifier: Slack is tried first and, when its headers
/// are present and well-formed, its verdict is FINAL (a Slack mismatch is not
/// retried as GitHub); then GitHub; then the generic `X-Signature`.
pub fn verify_hmac_signature(
    headers: &HeaderMap,
    body: &Bytes,
    signing_secret: &str,
) -> Option<VerifiedSignatureFormat> {
    // MCP-628 (2026-05-12): defense-in-depth empty-secret rejection.
    // `Hmac::<Sha256>::new_from_slice` accepts ANY length key
    // (including empty) — for HMAC-SHA256 the spec defines the
    // computation deterministically on every key length. So with
    // `signing_secret = ""`, the verifier would happily compute
    // `HMAC-SHA256("", body)` and an attacker who knows the body
    // could trivially forge a "valid" signature.
    //
    // The storage path (MCP `create_webhook` handler) enforces a
    // 16-char minimum (MCP-202), so empty secrets cannot be stored
    // via that path. But the runtime should still fail closed in
    // case a legacy migration / direct-SQL write / future code path
    // produces an empty secret — the verify function is the last
    // line of defense and shouldn't trust the storage invariant.
    if signing_secret.is_empty() {
        tracing::warn!(
            target: "talos_webhooks",
            event_kind = "webhook_hmac_secret_empty",
            "HMAC signing_secret is empty — failing closed (storage path enforces ≥16 chars; \
             a non-empty-then-empty value here means storage was bypassed)"
        );
        return None;
    }

    // Try Slack signature format first (X-Slack-Signature)
    if let Some(signature) = headers.get("x-slack-signature") {
        if let Ok(sig_str) = signature.to_str() {
            // Slack format: v0=<hash>
            if let Some(hash_hex) = sig_str.strip_prefix("v0=") {
                if let Some(timestamp) = headers.get("x-slack-request-timestamp") {
                    if let Ok(ts_str) = timestamp.to_str() {
                        // Enforce timestamp freshness (±5 minutes) to prevent replay attacks.
                        // Slack's own documentation recommends this check.
                        if let Ok(ts_secs) = ts_str.parse::<i64>() {
                            let now_secs = now_unix_secs();
                            // Overflow-free skew (see webhook_timestamp_skew_secs).
                            if webhook_timestamp_skew_secs(now_secs, ts_secs) > 300 {
                                tracing::warn!(
                                    timestamp = ts_secs,
                                    now = now_secs,
                                    "Slack request timestamp is outside the ±5 minute window — replay attack?"
                                );
                                return None;
                            }
                        } else {
                            tracing::warn!(
                                "Slack X-Slack-Request-Timestamp is not a valid integer"
                            );
                            return None;
                        }

                        // Basestring: version:timestamp:body
                        let base_string = format!("v0:{}:", ts_str);
                        let expected =
                            hmac_sha256_hex(signing_secret, &[base_string.as_bytes(), body])?;
                        return (expected.as_bytes().ct_eq(hash_hex.as_bytes()).unwrap_u8() == 1)
                            .then_some(VerifiedSignatureFormat::Slack);
                    }
                }
            }
        }
    }

    // Try GitHub signature format (X-Hub-Signature-256)
    if let Some(signature) = headers.get("x-hub-signature-256") {
        if let Ok(sig_str) = signature.to_str() {
            if let Some(hash_hex) = sig_str.strip_prefix("sha256=") {
                let expected = hmac_sha256_hex(signing_secret, &[body])?;
                return (expected.as_bytes().ct_eq(hash_hex.as_bytes()).unwrap_u8() == 1)
                    .then_some(VerifiedSignatureFormat::GitHub);
            }
        }
    }

    // Try generic X-Signature header
    if let Some(signature) = headers.get("x-signature") {
        if let Ok(sig_str) = signature.to_str() {
            // Enforce timestamp freshness (±5 minutes) to prevent replay attacks.
            // Senders must include X-Webhook-Timestamp (Unix seconds, UTC).
            // Requests without a timestamp header are rejected — this is a breaking
            // change for callers that do not send the header, but prevents indefinite
            // replay of any captured signed request.
            let timestamp_valid = if let Some(ts_hdr) = headers.get("x-webhook-timestamp") {
                if let Ok(ts_str) = ts_hdr.to_str() {
                    if let Ok(ts_secs) = ts_str.parse::<i64>() {
                        let now_secs = now_unix_secs();
                        // Overflow-free skew (see webhook_timestamp_skew_secs):
                        // the timestamp-bound HMAC below is the primary replay
                        // defense, but the freshness gate must hold on its own.
                        let skew = webhook_timestamp_skew_secs(now_secs, ts_secs);
                        if skew > 300 {
                            tracing::warn!(
                                timestamp = ts_secs,
                                now = now_secs,
                                skew_secs = skew,
                                "Generic webhook timestamp outside ±5 minute window — replay attack?"
                            );
                            false
                        } else {
                            true
                        }
                    } else {
                        tracing::warn!("X-Webhook-Timestamp is not a valid integer");
                        false
                    }
                } else {
                    tracing::warn!("X-Webhook-Timestamp header contains non-UTF8 bytes");
                    false
                }
            } else {
                tracing::warn!("Generic webhook HMAC request missing X-Webhook-Timestamp header — replay protection requires this header");
                false
            };

            if !timestamp_valid {
                return None;
            }

            // Include timestamp in the HMAC to bind the signature to a specific
            // point in time (prevents timestamp-stripping attacks).
            let ts_bytes = headers
                .get("x-webhook-timestamp")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .as_bytes();

            // Sign timestamp + body so the signature commits to when the request was made.
            // Senders must use the same construction: HMAC-SHA256(secret, timestamp + "." + body)
            let expected = hmac_sha256_hex(signing_secret, &[ts_bytes, b".", body])?;
            return (expected.as_bytes().ct_eq(sig_str.as_bytes()).unwrap_u8() == 1)
                .then_some(VerifiedSignatureFormat::Generic);
        }
    }

    // No recognized signature header found
    tracing::warn!("No recognized signature header found in request");
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::collections::HashSet;

    /// The long horizon must actually BE longer than the base window — a
    /// compile-time pin, so a constant edited down to the base window fails
    /// the build rather than a test run.
    const _: () = assert!(
        GITHUB_DEDUP_WINDOW_SECS > DEDUP_WINDOW_SECS,
        "GITHUB_DEDUP_WINDOW_SECS must exceed DEDUP_WINDOW_SECS"
    );

    const SECRET: &str = "a-signing-secret-of-adequate-length";

    /// Every outcome the auth gate can produce, so the two tests below are
    /// exhaustive by construction rather than by a list someone maintains.
    const ALL_OUTCOMES: &[WebhookAuthOutcome] = &[
        WebhookAuthOutcome::Hmac(VerifiedSignatureFormat::Slack),
        WebhookAuthOutcome::Hmac(VerifiedSignatureFormat::GitHub),
        WebhookAuthOutcome::Hmac(VerifiedSignatureFormat::Generic),
        WebhookAuthOutcome::StaticToken,
        WebhookAuthOutcome::Open,
    ];

    /// The GitHub format — and ONLY the GitHub format — holds its dedup claim
    /// for the long horizon, because it is the only one whose signature binds
    /// no timestamp and whose replay defence is therefore this claim alone.
    #[test]
    fn only_the_timestampless_format_gets_the_long_dedup_horizon() {
        assert_eq!(
            dedup_window(WebhookAuthOutcome::Hmac(VerifiedSignatureFormat::GitHub)),
            std::time::Duration::from_secs(GITHUB_DEDUP_WINDOW_SECS)
        );
        for outcome in ALL_OUTCOMES {
            if matches!(
                outcome,
                WebhookAuthOutcome::Hmac(VerifiedSignatureFormat::GitHub)
            ) {
                continue;
            }
            assert_eq!(
                dedup_window(*outcome),
                std::time::Duration::from_secs(DEDUP_WINDOW_SECS),
                "{outcome:?} binds a timestamp (or has no signature at all) — the store \
                 is not its replay defence and must not hold its claim longer"
            );
        }
        // The long horizon must actually BE longer (pinned at compile time
        // by the `const _` assertion at the top of this module), and it must
        // be the 24 h the operator picked: a constant edited down to the base
        // window would silently restore the one-hour replay window package CI
        // closed.
        assert_eq!(GITHUB_DEDUP_WINDOW_SECS, 24 * 3600);
        assert_eq!(DEDUP_WINDOW_SECS, 3600);
    }

    /// The router must take the retention from this one home, and the store
    /// must keep none of its own. TEXTUAL, and stated as such: it proves the
    /// call is spelled that way, never that the value is honoured — a caller
    /// computing `dedup_window` and then passing a literal would pass it. The
    /// behaviour is pinned by the live-Redis TTL test in `talos-idempotency`.
    #[test]
    fn the_router_takes_the_dedup_window_from_this_home() {
        let router = include_str!("router.rs");
        assert!(
            router.contains("let window = signature::dedup_window(auth_outcome);"),
            "the router no longer derives the dedup retention from dedup_window"
        );
        assert!(
            router.contains(".is_duplicate(trigger_id, &event_id, window)"),
            "the dedup call no longer passes the derived window"
        );
        // A second window would be a second policy. The only `Duration`
        // literals near the dedup call would be a re-derived horizon.
        assert!(
            !router.contains("Duration::from_secs(3600)")
                && !router.contains("Duration::from_secs(86_400)")
                && !router.contains("Duration::from_secs(86400)"),
            "a webhook retention literal reappeared in the router"
        );
        let store = include_str!("../../talos-idempotency/src/lib.rs");
        assert!(
            !store.contains("self.window"),
            "WebhookDeduplication grew a stored window again — one configured \
             value the caller overrides is a value nothing applies"
        );
    }

    /// The auditor-facing documents state the GitHub replay horizon in HOURS,
    /// and it is the one number a pentester plans around. Package S's class —
    /// a cadence changed in code with the rule that reads it left behind — is
    /// what this pins: the three documents must name the horizon the constants
    /// actually hold, in both directions.
    #[test]
    fn the_auditor_docs_state_the_horizon_the_code_holds() {
        let docs = [
            ("THREAT_MODEL", include_str!("../../docs/THREAT_MODEL.md")),
            (
                "pentest-scope",
                include_str!("../../docs/security/pentest-scope.md"),
            ),
            (
                "soc2-control-mapping",
                include_str!("../../docs/compliance/soc2-control-mapping.md"),
            ),
        ];
        let github_hours = GITHUB_DEDUP_WINDOW_SECS / 3600;
        let base_hours = DEDUP_WINDOW_SECS / 3600;
        for (name, doc) in docs {
            let lines: Vec<&str> = doc
                .lines()
                .filter(|l| {
                    // In scope: a line that states a HORIZON for the GitHub
                    // format's deduplication. A line that merely mentions the
                    // fail-closed refusal states no number and pins nothing.
                    let l = l.to_ascii_lowercase();
                    l.contains("dedup")
                        && (l.contains("github") || l.contains("hub-signature"))
                        && (l.contains("hour") || l.contains(" h "))
                })
                .collect();
            assert!(
                !lines.is_empty(),
                "{name} no longer states the GitHub deduplication horizon at all"
            );
            for line in &lines {
                assert!(
                    line.contains(&format!("{github_hours}-hour"))
                        || line.contains(&format!("{github_hours} h"))
                        || line.contains(&format!("{github_hours}-h")),
                    "{name} states a GitHub horizon that is not {github_hours} h: {line}"
                );
                // The number the code no longer holds must not survive beside
                // it — the pre-CI text read "1-hour window" and would still
                // parse as a sentence about deduplication.
                assert!(
                    !line.contains(&format!("{base_hours}-hour window")),
                    "{name} still calls the GitHub horizon a {base_hours}-hour window: {line}"
                );
            }
        }
    }

    /// Each outcome maps to its own metric label. A collision would merge two
    /// schemes into one series, and `format="github"` is the only value whose
    /// suppressions can mean a lost redelivery.
    #[test]
    fn every_outcome_has_a_distinct_metric_label() {
        let mut seen = HashSet::new();
        for outcome in ALL_OUTCOMES {
            assert!(
                seen.insert(metrics_format(*outcome).as_str()),
                "two outcomes share a label at {outcome:?}"
            );
        }
        assert_eq!(seen.len(), talos_metrics::WebhookAuthFormat::ALL.len());
        assert_eq!(
            metrics_format(WebhookAuthOutcome::Hmac(VerifiedSignatureFormat::GitHub)).as_str(),
            "github"
        );
    }

    fn github_headers(body: &[u8]) -> HeaderMap {
        let sig = hmac_sha256_hex(SECRET, &[body]).unwrap();
        let mut h = HeaderMap::new();
        h.insert(
            "x-hub-signature-256",
            HeaderValue::from_str(&format!("sha256={sig}")).unwrap(),
        );
        h.insert(
            "x-github-delivery",
            HeaderValue::from_static("72d3162e-cc78-11e3-81ab-4c9367dc0958"),
        );
        h
    }

    /// The in-memory stand-in for the dedup store's `is_duplicate`: the first
    /// sighting of a fingerprint records it and reports "new"; a second
    /// sighting reports "duplicate". Same semantics as
    /// `WebhookDeduplication::is_duplicate` for one trigger.
    fn is_duplicate(seen: &mut HashSet<String>, fingerprint: String) -> bool {
        !seen.insert(fingerprint)
    }

    /// F1 reproducer: a captured, VALID GitHub delivery replayed twice, each
    /// time with a different random `X-Signature`. Pre-fix the fingerprint was
    /// `x-signature` (first in the header-precedence list) so the second
    /// delivery was a "new" event. Now the verifier reports GitHub and the
    /// fingerprint is GitHub's own signature value: the second is suppressed.
    #[test]
    fn github_delivery_replayed_with_random_x_signature_is_suppressed() {
        let body = Bytes::from_static(br#"{"action":"opened","number":1}"#);
        let mut seen = HashSet::new();

        let mut first = github_headers(&body);
        first.insert(
            "x-signature",
            HeaderValue::from_static("c0ffee0000000000aa"),
        );
        let fmt = verify_hmac_signature(&first, &body, SECRET).expect("valid GitHub delivery");
        assert_eq!(fmt, VerifiedSignatureFormat::GitHub);
        let fp1 = dedup_fingerprint(WebhookAuthOutcome::Hmac(fmt), &first, &body);
        assert!(
            !is_duplicate(&mut seen, fp1.clone()),
            "first delivery is new"
        );

        let mut second = github_headers(&body);
        second.insert(
            "x-signature",
            HeaderValue::from_static("deadbeef111111112222"),
        );
        let fmt = verify_hmac_signature(&second, &body, SECRET).expect("still a valid delivery");
        assert_eq!(fmt, VerifiedSignatureFormat::GitHub);
        let fp2 = dedup_fingerprint(WebhookAuthOutcome::Hmac(fmt), &second, &body);
        assert_eq!(
            fp1, fp2,
            "fingerprint must not depend on the unverified header"
        );
        assert!(
            is_duplicate(&mut seen, fp2),
            "second delivery must be suppressed as a duplicate"
        );

        // Control: the fingerprint really is the verified signature, not the
        // random header and not the delivery id.
        assert_eq!(
            fp1,
            first.get("x-hub-signature-256").unwrap().to_str().unwrap()
        );
        assert_ne!(fp1, "c0ffee0000000000aa");
    }

    /// A request carrying BOTH a valid GitHub signature and a garbage
    /// `X-Signature` must not be rejected: GitHub is tried before generic and
    /// its verdict wins. (Pinned because the fix depends on it — if generic
    /// were tried first, the random header would fail the whole request and
    /// the replay would be a DoS rather than a bypass, but a legitimate
    /// GitHub sender behind a proxy that adds `X-Signature` would break too.)
    #[test]
    fn github_verdict_is_not_disturbed_by_an_extra_generic_header() {
        let body = Bytes::from_static(b"payload");
        let mut h = github_headers(&body);
        h.insert("x-signature", HeaderValue::from_static("nonsense"));
        assert_eq!(
            verify_hmac_signature(&h, &body, SECRET),
            Some(VerifiedSignatureFormat::GitHub)
        );
    }

    #[test]
    fn slack_and_generic_fingerprints_come_from_their_own_header() {
        let body = Bytes::from_static(b"{}");
        let ts = now_unix_secs().to_string();

        let slack_sig = format!(
            "v0={}",
            hmac_sha256_hex(SECRET, &[format!("v0:{ts}:").as_bytes(), &body]).unwrap()
        );
        let mut h = HeaderMap::new();
        h.insert(
            "x-slack-signature",
            HeaderValue::from_str(&slack_sig).unwrap(),
        );
        h.insert(
            "x-slack-request-timestamp",
            HeaderValue::from_str(&ts).unwrap(),
        );
        h.insert("x-signature", HeaderValue::from_static("attacker-chosen"));
        h.insert(
            "x-request-id",
            HeaderValue::from_static("attacker-chosen-2"),
        );
        let fmt = verify_hmac_signature(&h, &body, SECRET).unwrap();
        assert_eq!(fmt, VerifiedSignatureFormat::Slack);
        assert_eq!(
            dedup_fingerprint(WebhookAuthOutcome::Hmac(fmt), &h, &body),
            slack_sig
        );

        let generic_sig = hmac_sha256_hex(SECRET, &[ts.as_bytes(), b".", &body]).unwrap();
        let mut h = HeaderMap::new();
        h.insert("x-signature", HeaderValue::from_str(&generic_sig).unwrap());
        h.insert("x-webhook-timestamp", HeaderValue::from_str(&ts).unwrap());
        h.insert("x-request-id", HeaderValue::from_static("attacker-chosen"));
        let fmt = verify_hmac_signature(&h, &body, SECRET).unwrap();
        assert_eq!(fmt, VerifiedSignatureFormat::Generic);
        assert_eq!(
            dedup_fingerprint(WebhookAuthOutcome::Hmac(fmt), &h, &body),
            generic_sig
        );
    }

    /// Static-token and open triggers verify no signature, so no header may
    /// become the fingerprint — a sender could otherwise mint a fresh
    /// `X-Request-Id` per replay of an identical body.
    #[test]
    fn unsigned_modes_fingerprint_the_body_and_ignore_every_header() {
        let body = b"{\"event\":\"x\"}";
        let mut h = HeaderMap::new();
        h.insert("x-signature", HeaderValue::from_static("random-1"));
        h.insert("x-github-delivery", HeaderValue::from_static("random-2"));
        h.insert("x-request-id", HeaderValue::from_static("random-3"));
        h.insert(
            "x-verification-token",
            HeaderValue::from_static("the-token"),
        );
        let expected = body_fingerprint(body);
        assert_eq!(
            dedup_fingerprint(WebhookAuthOutcome::StaticToken, &h, body),
            expected
        );
        assert_eq!(
            dedup_fingerprint(WebhookAuthOutcome::Open, &h, body),
            expected
        );
        assert_eq!(
            dedup_fingerprint(WebhookAuthOutcome::Open, &HeaderMap::new(), body),
            expected
        );
    }

    #[test]
    fn invalid_signature_reports_none_for_every_format() {
        let body = Bytes::from_static(b"payload");
        let mut h = HeaderMap::new();
        h.insert(
            "x-hub-signature-256",
            HeaderValue::from_static("sha256=00000000000000000000000000000000"),
        );
        assert_eq!(verify_hmac_signature(&h, &body, SECRET), None);
        assert_eq!(
            verify_hmac_signature(&HeaderMap::new(), &body, SECRET),
            None
        );
        // MCP-628: an empty secret never verifies anything.
        assert_eq!(
            verify_hmac_signature(&github_headers(&body), &body, ""),
            None
        );
    }

    #[test]
    fn sensitive_header_classifier_covers_the_persisted_secrets() {
        for name in [
            "Authorization",
            "Proxy-Authorization",
            "Cookie",
            "Set-Cookie",
            "X-Verification-Token",
            "X-Hub-Signature-256",
            "X-Slack-Signature",
            "X-Signature",
            "X-Api-Key",
            "X-Goog-Channel-Token",
            "X-Amz-Security-Token",
        ] {
            assert!(header_is_sensitive(name), "{name} must be redacted");
        }
        for name in [
            "Content-Type",
            "User-Agent",
            "X-GitHub-Delivery",
            "X-Request-Id",
        ] {
            assert!(!header_is_sensitive(name), "{name} is safe to persist");
        }
    }
}
