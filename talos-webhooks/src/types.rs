use axum::http::HeaderMap;
use uuid::Uuid;

#[derive(Clone, sqlx::FromRow)]
pub struct WebhookTrigger {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub module_id: Option<Uuid>,
    pub workflow_id: Option<Uuid>,
    pub verification_token: Option<String>,
    /// Encrypted signing secret (nonce || ciphertext). Decrypted on demand via SecretsManager.
    /// The legacy plaintext `signing_secret` column has been removed.
    pub signing_secret_enc: Option<Vec<u8>>,
    pub signing_key_id: Option<Uuid>,
    /// MCP-S2: AEAD AAD format version for `signing_secret_enc`.
    /// 0 = legacy no-AAD, 1 = AAD-bound to `id`. Decrypt dispatches via
    /// `SecretsManager::decrypt_versioned`.
    #[sqlx(default)]
    pub signing_secret_format: i16,
    pub allowed_ips: Option<Vec<String>>,
    pub enabled: bool,
    pub auto_respond: bool,
    pub queue_events: bool,
    pub max_requests_per_minute: i32,
    /// When true, the webhook handler waits for workflow completion and returns
    /// the output in the HTTP response body. Enables synchronous request-response
    /// patterns (e.g., Slack slash commands, API gateways).
    pub sync_response: bool,
    /// Maximum seconds to wait for workflow completion in sync mode.
    /// Returns HTTP 504 Gateway Timeout if exceeded.
    pub sync_timeout_secs: i32,
    /// RFC 0007: optional provider-agnostic event filter. When set, the handler
    /// evaluates it AFTER signature verification and skips (200, no dispatch)
    /// deliveries that don't match. `NULL` = fire on every verified delivery.
    /// Shape: `{ "header": "X-GitHub-Event", "values": [...], "payload_match":
    /// { "action": [...] } }`. See `event_filter_matches`.
    #[sqlx(default)]
    pub event_filter: Option<serde_json::Value>,
}

// Custom Debug so a stray `{:?}` never prints the trigger's auth material:
// `verification_token` (static bearer token) and `signing_secret_enc` (HMAC
// signing-secret ciphertext — logging raw ciphertext bytes is noise at best and
// a sensitivity-signal leak at worst). Both show presence only.
impl std::fmt::Debug for WebhookTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookTrigger")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("name", &self.name)
            .field("module_id", &self.module_id)
            .field("workflow_id", &self.workflow_id)
            .field(
                "verification_token",
                &self.verification_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "signing_secret_enc",
                &self.signing_secret_enc.as_ref().map(|_| "[REDACTED]"),
            )
            .field("signing_key_id", &self.signing_key_id)
            .field("signing_secret_format", &self.signing_secret_format)
            .field("allowed_ips", &self.allowed_ips)
            .field("enabled", &self.enabled)
            .field("auto_respond", &self.auto_respond)
            .field("queue_events", &self.queue_events)
            .field("max_requests_per_minute", &self.max_requests_per_minute)
            .field("sync_response", &self.sync_response)
            .field("sync_timeout_secs", &self.sync_timeout_secs)
            .finish()
    }
}

/// Auth-downgrade guard predicate (MEDIUM finding).
///
/// Returns `true` when the webhook MUST fail closed because an HMAC
/// signing secret was CONFIGURED on the trigger (`signing_secret_enc`
/// present) but could not be RESOLVED (decryption failed, so the
/// decrypted secret is `None`). In that state the handler must NOT fall
/// through to the static `verification_token` branch — doing so would be
/// a silent HMAC -> static-token auth downgrade, re-enabling a long-lived
/// UUID token the operator was told is permanently off once a signing
/// secret is set.
///
/// Pure function so the security-critical predicate is unit-tested without
/// a DB pool / SecretsManager / NATS (`handle_webhook` is not isolatable).
pub(crate) fn webhook_must_fail_closed_on_hmac(
    hmac_configured: bool,
    hmac_secret_resolved: bool,
) -> bool {
    hmac_configured && !hmac_secret_resolved
}

/// RFC 0007: does a verified delivery match the trigger's `event_filter`?
///
/// `filter` is the JSONB from `webhook_triggers.event_filter`; `header_value` is
/// the request header named by `filter.header` (resolved by the caller, since the
/// matcher is DB/HeaderMap-free for testability); `body` is the parsed JSON body.
///
/// Match = (header clause) AND (payload_match clause). A clause that is absent
/// passes. Semantics:
/// - `values` (array): if present and non-empty, `header_value` MUST be one of
///   them — an absent header when `values` is required is a non-match.
/// - `payload_match` (object `{key: [allowed]}`): for EACH key with a non-empty
///   allowed list, the body's top-level `key` (as a string) MUST be one of the
///   allowed values; a missing/non-string field is a non-match for that key.
///   All keys are ANDed.
///
/// Fail-OPEN on a malformed filter (not an object) — per RFC 0007 D6, silently
/// dropping a delivery is worse than an occasional over-fire, and write-time
/// validation is the primary guard. Returns `true` (fire) for `{}`.
pub(crate) fn event_filter_matches(
    filter: &serde_json::Value,
    header_value: Option<&str>,
    body: &serde_json::Value,
) -> bool {
    let Some(obj) = filter.as_object() else {
        return true; // malformed → fire (D6)
    };

    // Header clause.
    if let Some(values) = obj.get("values").and_then(|v| v.as_array()) {
        if !values.is_empty() {
            let Some(hv) = header_value else { return false };
            if !values.iter().any(|v| v.as_str() == Some(hv)) {
                return false;
            }
        }
    }

    // payload_match clause (AND over keys).
    if let Some(pm) = obj.get("payload_match").and_then(|v| v.as_object()) {
        for (key, allowed) in pm {
            let Some(allowed) = allowed.as_array() else {
                continue;
            };
            if allowed.is_empty() {
                continue;
            }
            let actual = body.get(key).and_then(|v| v.as_str());
            match actual {
                Some(a) if allowed.iter().any(|v| v.as_str() == Some(a)) => {}
                _ => return false,
            }
        }
    }

    true
}

/// RFC 0007 D6: validate an `event_filter` at WRITE time so a malformed filter
/// never persists. This is the fail-CLOSED counterpart to the fail-OPEN
/// [`event_filter_matches`] (which fires on a malformed stored filter rather
/// than silently dropping a delivery) — write-time validation is the primary
/// guard, so the trigger-CRUD surface must call this before persisting.
///
/// The accepted shape mirrors exactly what the matcher interprets:
/// ```jsonc
/// { "header": "X-GitHub-Event",                 // optional; REQUIRED if `values` is non-empty
///   "values": ["pull_request"],                 // optional; non-empty strings
///   "payload_match": { "action": ["opened"] } } // optional; {key: [non-empty strings]}
/// ```
/// Unknown top-level keys are rejected (catches `value` vs `values` typos that
/// would otherwise silently match nothing / everything). A filter with no active
/// clause is rejected — an empty filter matches every delivery, so it's almost
/// certainly a mistake; the caller should omit `event_filter` instead.
pub fn validate_event_filter(filter: &serde_json::Value) -> Result<(), String> {
    // Size cap: bounds the stored row AND the per-fire match cost. 8 KiB is far
    // above any realistic header/action allow-list.
    const MAX_BYTES: usize = 8 * 1024;
    let encoded = serde_json::to_string(filter)
        .map_err(|_| "event_filter is not serializable".to_string())?;
    if encoded.len() > MAX_BYTES {
        return Err(format!(
            "event_filter must be ≤ {MAX_BYTES} bytes (got {})",
            encoded.len()
        ));
    }

    let obj = filter
        .as_object()
        .ok_or_else(|| "event_filter must be a JSON object".to_string())?;

    for k in obj.keys() {
        if !matches!(k.as_str(), "header" | "values" | "payload_match") {
            return Err(format!(
                "event_filter: unknown key '{k}'; allowed keys are header, values, payload_match"
            ));
        }
    }

    if let Some(h) = obj.get("header") {
        let s = h
            .as_str()
            .ok_or_else(|| "event_filter.header must be a string".to_string())?;
        if s.trim().is_empty() {
            return Err("event_filter.header must be a non-empty string".to_string());
        }
    }

    if let Some(v) = obj.get("values") {
        let arr = v
            .as_array()
            .ok_or_else(|| "event_filter.values must be an array of strings".to_string())?;
        for item in arr {
            let s = item
                .as_str()
                .ok_or_else(|| "event_filter.values entries must be strings".to_string())?;
            if s.is_empty() {
                return Err("event_filter.values entries must be non-empty".to_string());
            }
        }
        // A non-empty `values` clause is matched against the request header named
        // by `header`; without `header` the matcher has nothing to compare.
        if !arr.is_empty() && obj.get("header").is_none() {
            return Err(
                "event_filter.values requires event_filter.header (the request header that \
                 carries the event type, e.g. \"X-GitHub-Event\")"
                    .to_string(),
            );
        }
    }

    if let Some(pm) = obj.get("payload_match") {
        let pmobj = pm
            .as_object()
            .ok_or_else(|| "event_filter.payload_match must be an object".to_string())?;
        for (key, allowed) in pmobj {
            if key.is_empty() {
                return Err("event_filter.payload_match keys must be non-empty".to_string());
            }
            let arr = allowed.as_array().ok_or_else(|| {
                format!("event_filter.payload_match.{key} must be an array of strings")
            })?;
            for item in arr {
                let s = item.as_str().ok_or_else(|| {
                    format!("event_filter.payload_match.{key} entries must be strings")
                })?;
                if s.is_empty() {
                    return Err(format!(
                        "event_filter.payload_match.{key} entries must be non-empty"
                    ));
                }
            }
        }
    }

    let has_values = obj
        .get("values")
        .and_then(|v| v.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    let has_payload = obj
        .get("payload_match")
        .and_then(|v| v.as_object())
        .map(|o| !o.is_empty())
        .unwrap_or(false);
    if !has_values && !has_payload {
        return Err(
            "event_filter must specify at least one of a non-empty `values` or `payload_match` \
             (an empty filter matches every delivery — omit event_filter instead)"
                .to_string(),
        );
    }

    Ok(())
}

/// RFC 0007 D5: build the `__webhook__` metadata object surfaced to the workflow
/// alongside the body. It exposes the inbound *event type* + *delivery id* (which
/// live in request HEADERS — otherwise invisible to a workflow, which only sees
/// the body) plus the body's `action`, so a workflow reads the event type from
/// one authoritative place rather than re-parsing headers it can't reach.
///
/// **Curated, not a header dump.** Only three named fields are surfaced — never
/// arbitrary headers — so signature/auth headers (`X-Hub-Signature-256`,
/// `Authorization`, `X-Verification-Token`, …) can't leak into trigger input.
/// Each field is `null` when absent (stable shape for `{{__trigger_input__.__webhook__.event}}`).
///
/// `event` reads the header named by the trigger's `event_filter.header` when a
/// filter is set (the same header the server matched on — one source of truth),
/// else the conventional GitHub `X-GitHub-Event`.
pub(crate) fn build_webhook_meta(
    headers: &HeaderMap,
    event_filter: Option<&serde_json::Value>,
    body: &serde_json::Value,
) -> serde_json::Value {
    let event_header_name = event_filter
        .and_then(|f| f.get("header"))
        .and_then(|h| h.as_str())
        .unwrap_or("X-GitHub-Event");
    let event = headers.get(event_header_name).and_then(|v| v.to_str().ok());
    let delivery = headers
        .get("X-GitHub-Delivery")
        .and_then(|v| v.to_str().ok());
    let action = body.get("action").and_then(|v| v.as_str());
    serde_json::json!({
        "event": event,
        "delivery": delivery,
        "action": action,
    })
}

/// Inject the RFC 0007 D5 `__webhook__` metadata as a reserved top-level key in
/// the trigger-input body. Only applies when `target` is a JSON object — a
/// non-object body (a bare string / array) has no field-access surface for a
/// workflow anyway, so there's nothing to attach the key to. The key is
/// reserved: a body that legitimately carries `__webhook__` is overwritten
/// (documented; real providers don't send it).
pub(crate) fn inject_webhook_meta(target: &mut serde_json::Value, meta: serde_json::Value) {
    if let Some(obj) = target.as_object_mut() {
        obj.insert("__webhook__".to_string(), meta);
    }
}

/// Absolute difference in seconds between `now_secs` and a caller-supplied
/// `ts_secs` (a webhook timestamp header), using overflow-free `i64::abs_diff`.
///
/// `(now_secs - ts_secs).abs()` is NOT safe here: `ts_secs` is parsed from an
/// attacker-controlled header, so a value near `i64::MIN` overflows the
/// subtraction. In debug builds that panics (a request-triggered DoS); in
/// release the wrapped result can land on `i64::MIN`, whose `.abs()` stays
/// negative — so a `> window` freshness check silently PASSES a stale request.
/// `abs_diff` returns `u64` and cannot overflow, so the freshness gate holds
/// for every possible `ts_secs`.
pub(crate) fn webhook_timestamp_skew_secs(now_secs: i64, ts_secs: i64) -> u64 {
    now_secs.abs_diff(ts_secs)
}

#[cfg(test)]
mod timestamp_skew_tests {
    use super::webhook_timestamp_skew_secs;

    // The webhook freshness gate (`skew > 300 → reject`) must hold for EVERY
    // caller-supplied timestamp. `(now - ts).abs()` did not: ts near i64::MIN
    // overflows (debug panic; release .abs()-of-wrapped-MIN is negative, so the
    // `> 300` check silently passes a stale request). abs_diff is overflow-free.
    #[test]
    fn normal_skew_is_exact() {
        assert_eq!(
            webhook_timestamp_skew_secs(1_700_000_300, 1_700_000_000),
            300
        );
        assert_eq!(
            webhook_timestamp_skew_secs(1_700_000_000, 1_700_000_300),
            300
        );
        assert_eq!(webhook_timestamp_skew_secs(1_700_000_000, 1_700_000_000), 0);
    }

    #[test]
    fn extreme_timestamps_yield_huge_skew_not_panic_or_negative() {
        let now = 1_700_000_000i64;
        // The exact crafted value that made `(now - ts)` wrap to i64::MIN under
        // the old code (now - 2^63), plus the i64 extremes. All must produce a
        // huge skew that is comfortably > the 300s window — i.e. REJECTED.
        for ts in [
            i64::MIN,
            i64::MAX,
            now.wrapping_sub(i64::MIN), // = now + 2^63 region
            -9_223_372_035_154_775_808, // ≈ now - 2^63: old code → skew == i64::MIN (negative!)
        ] {
            let skew = webhook_timestamp_skew_secs(now, ts);
            assert!(
                skew > 300,
                "ts={ts} produced skew={skew}, which would PASS the freshness gate"
            );
        }
    }
}

#[cfg(test)]
mod auth_downgrade_tests {
    use super::webhook_must_fail_closed_on_hmac;

    // MEDIUM (auth downgrade): the predicate must fail closed ONLY when an
    // HMAC signing secret was configured but could not be resolved.
    #[test]
    fn configured_but_unresolved_fails_closed() {
        // signing_secret_enc present, decryption failed -> 401, no fallback.
        assert!(webhook_must_fail_closed_on_hmac(true, false));
    }

    #[test]
    fn configured_and_resolved_does_not_fail_closed() {
        // Normal HMAC path — verification proceeds against the secret.
        assert!(!webhook_must_fail_closed_on_hmac(true, true));
    }

    #[test]
    fn not_configured_allows_static_token_fallback() {
        // No signing secret configured -> static verification_token branch
        // is legitimately reachable; the guard must NOT fire.
        assert!(!webhook_must_fail_closed_on_hmac(false, false));
        // Degenerate (resolved-but-not-configured) is impossible in practice
        // but must also not fail closed.
        assert!(!webhook_must_fail_closed_on_hmac(false, true));
    }
}

#[cfg(test)]
mod event_filter_tests {
    use super::{
        build_webhook_meta, event_filter_matches, inject_webhook_meta, validate_event_filter,
    };
    use http::HeaderMap;
    use serde_json::json;

    // Canonical GitHub PR filter: only pull_request opened/synchronize/reopened.
    fn gh_pr_filter() -> serde_json::Value {
        json!({
            "header": "X-GitHub-Event",
            "values": ["pull_request"],
            "payload_match": { "action": ["opened", "synchronize", "reopened"] }
        })
    }

    #[test]
    fn empty_filter_fires() {
        assert!(event_filter_matches(&json!({}), Some("push"), &json!({})));
    }

    #[test]
    fn malformed_filter_fails_open() {
        // D6: a non-object filter fires rather than silently dropping.
        assert!(event_filter_matches(&json!("nonsense"), None, &json!({})));
        assert!(event_filter_matches(&json!([1, 2, 3]), None, &json!({})));
    }

    #[test]
    fn github_pr_opened_matches() {
        let f = gh_pr_filter();
        assert!(event_filter_matches(
            &f,
            Some("pull_request"),
            &json!({ "action": "opened", "number": 7 })
        ));
    }

    #[test]
    fn wrong_event_header_no_match() {
        let f = gh_pr_filter();
        // `push` is not in values → skip even though there's no `action`.
        assert!(!event_filter_matches(
            &f,
            Some("push"),
            &json!({ "ref": "refs/heads/main" })
        ));
    }

    #[test]
    fn right_event_wrong_action_no_match() {
        let f = gh_pr_filter();
        // pull_request but action=closed → not in the allowed actions.
        assert!(!event_filter_matches(
            &f,
            Some("pull_request"),
            &json!({ "action": "closed" })
        ));
    }

    #[test]
    fn required_header_absent_no_match() {
        let f = gh_pr_filter();
        assert!(!event_filter_matches(
            &f,
            None,
            &json!({ "action": "opened" })
        ));
    }

    #[test]
    fn missing_payload_field_no_match() {
        let f = gh_pr_filter();
        // Header matches but the body has no `action` → payload clause fails.
        assert!(!event_filter_matches(
            &f,
            Some("pull_request"),
            &json!({ "number": 1 })
        ));
    }

    #[test]
    fn empty_values_array_is_no_header_constraint() {
        // values: [] means "don't constrain the header" — only payload_match gates.
        let f = json!({ "header": "X-GitHub-Event", "values": [], "payload_match": { "action": ["opened"] } });
        assert!(event_filter_matches(
            &f,
            Some("anything"),
            &json!({ "action": "opened" })
        ));
        assert!(!event_filter_matches(
            &f,
            Some("anything"),
            &json!({ "action": "closed" })
        ));
    }

    #[test]
    fn header_only_filter_ignores_body() {
        // No payload_match → only the event type gates; body is irrelevant.
        let f = json!({ "header": "X-GitHub-Event", "values": ["push"] });
        assert!(event_filter_matches(&f, Some("push"), &json!({})));
        assert!(!event_filter_matches(&f, Some("pull_request"), &json!({})));
    }

    // ---- validate_event_filter (RFC 0007 D6, write-time fail-CLOSED) ----

    #[test]
    fn validate_accepts_github_pr_filter() {
        assert!(validate_event_filter(&gh_pr_filter()).is_ok());
    }

    #[test]
    fn validate_accepts_payload_match_only() {
        // No header/values is fine when payload_match carries the constraint.
        let f = json!({ "payload_match": { "action": ["opened"] } });
        assert!(validate_event_filter(&f).is_ok());
    }

    #[test]
    fn validate_accepts_values_with_header() {
        let f = json!({ "header": "X-GitHub-Event", "values": ["push", "pull_request"] });
        assert!(validate_event_filter(&f).is_ok());
    }

    #[test]
    fn validate_rejects_non_object() {
        assert!(validate_event_filter(&json!("pull_request")).is_err());
        assert!(validate_event_filter(&json!(["pull_request"])).is_err());
    }

    #[test]
    fn validate_rejects_empty_filter() {
        // Empty object matches everything → almost certainly a mistake.
        assert!(validate_event_filter(&json!({})).is_err());
    }

    #[test]
    fn validate_rejects_unknown_key() {
        // Classic `value` vs `values` typo — must not persist silently.
        let f = json!({ "header": "X-GitHub-Event", "value": ["push"] });
        assert!(validate_event_filter(&f).is_err());
    }

    #[test]
    fn validate_rejects_values_without_header() {
        let f = json!({ "values": ["pull_request"] });
        assert!(validate_event_filter(&f).is_err());
    }

    #[test]
    fn validate_rejects_non_string_values() {
        let f = json!({ "header": "X-GitHub-Event", "values": [42] });
        assert!(validate_event_filter(&f).is_err());
    }

    #[test]
    fn validate_rejects_empty_string_values() {
        let f = json!({ "header": "X-GitHub-Event", "values": [""] });
        assert!(validate_event_filter(&f).is_err());
    }

    #[test]
    fn validate_rejects_payload_match_non_array() {
        let f = json!({ "payload_match": { "action": "opened" } });
        assert!(validate_event_filter(&f).is_err());
    }

    #[test]
    fn validate_rejects_payload_match_non_string_entry() {
        let f = json!({ "payload_match": { "action": ["opened", 7] } });
        assert!(validate_event_filter(&f).is_err());
    }

    #[test]
    fn validate_rejects_header_only_no_clause() {
        // header present but no values + no payload_match → no active clause.
        let f = json!({ "header": "X-GitHub-Event" });
        assert!(validate_event_filter(&f).is_err());
        // header + empty values is the same no-op.
        let f2 = json!({ "header": "X-GitHub-Event", "values": [] });
        assert!(validate_event_filter(&f2).is_err());
    }

    #[test]
    fn validate_rejects_oversize_filter() {
        let big: Vec<String> = (0..2000)
            .map(|i| format!("event_type_number_{i}"))
            .collect();
        let f = json!({ "header": "X-GitHub-Event", "values": big });
        assert!(validate_event_filter(&f).is_err());
    }

    // ---- build_webhook_meta / inject_webhook_meta (RFC 0007 D5) ----

    fn headers_of(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn meta_reads_github_headers_and_action() {
        let h = headers_of(&[
            ("X-GitHub-Event", "pull_request"),
            ("X-GitHub-Delivery", "abc-123"),
        ]);
        let body = json!({ "action": "opened", "number": 7 });
        let meta = build_webhook_meta(&h, None, &body);
        assert_eq!(meta["event"], json!("pull_request"));
        assert_eq!(meta["delivery"], json!("abc-123"));
        assert_eq!(meta["action"], json!("opened"));
    }

    #[test]
    fn meta_header_lookup_is_case_insensitive() {
        // HeaderMap is case-insensitive; the conventional default still resolves.
        let h = headers_of(&[("x-github-event", "push")]);
        let meta = build_webhook_meta(&h, None, &json!({}));
        assert_eq!(meta["event"], json!("push"));
    }

    #[test]
    fn meta_event_uses_filter_configured_header() {
        // When a filter names a custom header, `event` reads THAT header — one
        // source of truth with what the server matched on.
        let h = headers_of(&[("X-Custom-Event", "deploy")]);
        let filter = json!({ "header": "X-Custom-Event", "values": ["deploy"] });
        let meta = build_webhook_meta(&h, Some(&filter), &json!({}));
        assert_eq!(meta["event"], json!("deploy"));
    }

    #[test]
    fn meta_absent_fields_are_null_stable_shape() {
        let meta = build_webhook_meta(&HeaderMap::new(), None, &json!({}));
        assert_eq!(meta["event"], json!(null));
        assert_eq!(meta["delivery"], json!(null));
        assert_eq!(meta["action"], json!(null));
    }

    #[test]
    fn meta_does_not_surface_signature_or_auth_headers() {
        // Curated allowlist: secret-bearing headers must never appear.
        let h = headers_of(&[
            ("X-Hub-Signature-256", "sha256=deadbeef"),
            ("Authorization", "Bearer sk-secret"),
            ("X-Verification-Token", "tok-secret"),
            ("X-GitHub-Event", "pull_request"),
        ]);
        let meta = build_webhook_meta(&h, None, &json!({}));
        let s = serde_json::to_string(&meta).unwrap();
        assert!(!s.contains("deadbeef"));
        assert!(!s.contains("sk-secret"));
        assert!(!s.contains("tok-secret"));
        assert_eq!(meta["event"], json!("pull_request"));
    }

    #[test]
    fn inject_adds_reserved_key_to_object() {
        let mut body = json!({ "action": "opened" });
        inject_webhook_meta(&mut body, json!({ "event": "pull_request" }));
        assert_eq!(body["action"], json!("opened"));
        assert_eq!(body["__webhook__"]["event"], json!("pull_request"));
    }

    #[test]
    fn inject_is_noop_on_non_object() {
        // A bare string/array body has no field surface — leave it untouched.
        let mut s = json!("raw text body");
        inject_webhook_meta(&mut s, json!({ "event": "x" }));
        assert_eq!(s, json!("raw text body"));
        let mut arr = json!([1, 2, 3]);
        inject_webhook_meta(&mut arr, json!({ "event": "x" }));
        assert_eq!(arr, json!([1, 2, 3]));
    }
}
