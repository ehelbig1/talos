//! Data Loss Prevention (DLP) / PII redaction module.
//!
//! This module provides a pluggable DLP abstraction:
//! - [`DlpProvider`] — sync, infallible redaction trait
//! - [`BuiltinDlpProvider`] — regex-based PII patterns (default)
//! - [`PassthroughDlpProvider`] — no-op for `DLP_PROVIDER=none`
//! - [`ExternalDlpProvider`] — HTTP webhook to a custom DLP endpoint
//! - [`DlpService`] — injectable `Arc`-wrapped service
//!
//! The module-level free functions ([`redact_str`], [`redact_json`]) delegate
//! to a process-wide `LazyLock<DlpService>` so that engine, scheduler, and
//! audit_ledger code that cannot receive the service via DI continues to work
//! without threading changes.
//!
//! **Environment variables**
//! | Variable | Description |
//! |---|---|
//! | `DLP_PROVIDER` | `builtin` (default), `none`, or `external` |
//! | `DLP_WEBHOOK_URL` | Required when `DLP_PROVIDER=external` |
//! | `DLP_WEBHOOK_TOKEN` | Optional `Authorization: Bearer` token for external provider |

use regex::{Regex, RegexSet};
use serde_json::Value;
use std::sync::{Arc, LazyLock};

/// MCP-559: maximum recursion depth for `DlpProvider::redact_json`.
/// The default trait impl recurses through every array/object level
/// of the input tree. DLP runs on attacker-influenced JSON
/// (webhook payloads via `talos-webhooks::lib.rs::handle_dlq`, LLM
/// response bodies via `talos-llm::generate_text`, Rhai evaluation
/// context via `talos-engine::rhai_helpers`) so a deeply-nested JSON
/// could stack-overflow the tokio worker thread (~2 MB stack →
/// ~16-32k recursion frames at 64-128 bytes each). A 1 MB JSON of
/// `[[[[[...]]]]]` is ~500k levels — well past the threshold and
/// would crash the controller for ALL users.
///
/// 128 matches `talos-workflow-validation::MAX_SCHEMA_DEPTH`
/// (MCP-558) and `talos-memory`'s `MAX_CANONICAL_DEPTH` — all three
/// fail-closed depth limits on user-controlled JSON tree-walkers
/// share the same ceiling so a future change doesn't drift one site
/// out of sync.
pub const MAX_DLP_REDACT_DEPTH: usize = 128;

// ============================================================================
// DlpProvider trait
// ============================================================================

/// Synchronous, infallible PII redaction interface.
///
/// Implementations **must** be `Send + Sync` (they live behind `Arc`).
/// On any internal error the original input is returned unchanged so that
/// DLP never blocks execution.
pub trait DlpProvider: Send + Sync {
    /// Redact PII from a plain string.
    fn redact_str(&self, input: &str) -> String;

    /// Allocation-light variant of `redact_str` — returns
    /// `Cow::Borrowed` when no PII is detected so callers on hot
    /// paths avoid the per-pattern allocation cycle. The default
    /// implementation falls back to `redact_str` and always allocates;
    /// builtin providers override with a fast-path match-then-allocate
    /// pattern. Used by the WASM-log broadcast scrubber and other
    /// per-message-volume call sites.
    fn redact_str_cow<'a>(&self, input: &'a str) -> std::borrow::Cow<'a, str> {
        std::borrow::Cow::Owned(self.redact_str(input))
    }

    /// Recursively redact string leaves in a JSON value tree.
    ///
    /// The default implementation walks the tree and calls `redact_str` on
    /// every `Value::String` leaf.  Override this to send the entire JSON
    /// object to an external service in a single round-trip.
    ///
    /// MCP-559: depth-bounded via a private helper. The pub trait method
    /// keeps the same signature so every caller inherits the limit
    /// without explicit opt-in.
    fn redact_json(&self, value: &Value) -> Value {
        self.redact_json_depth(value, 0)
    }

    /// MCP-559: internal depth-counted variant of `redact_json`. The default
    /// trait method delegates here with `depth = 0`. Recurses with
    /// `depth + 1` on each Array/Object level; bails (returns the
    /// subtree CLONED but UNREDACTED) once depth exceeds
    /// [`MAX_DLP_REDACT_DEPTH`]. Returning the unredacted subtree past
    /// the cap is the safer fail-mode because DLP is documented as
    /// infallible and the alternative (panic on stack overflow)
    /// crashes the controller process. Strings ABOVE the depth cap
    /// still get redacted on the way down; only the deepest tail of
    /// a pathologically nested attack input is skipped.
    fn redact_json_depth(&self, value: &Value, depth: usize) -> Value {
        if depth > MAX_DLP_REDACT_DEPTH {
            // Don't recurse; clone and return. Logged once at TRACE so
            // a flood doesn't drown out operators — DLP runs on every
            // log entry and a noisier level would amplify the issue.
            tracing::trace!(
                target: "talos_dlp_provider",
                event_kind = "dlp_recurse_depth_capped",
                depth,
                max = MAX_DLP_REDACT_DEPTH,
                "DLP recursion bailed at max depth (possible DoS attempt or pathological input)"
            );
            return value.clone();
        }
        match value {
            Value::String(s) => Value::String(self.redact_str(s)),
            Value::Array(arr) => Value::Array(
                arr.iter()
                    .map(|v| self.redact_json_depth(v, depth + 1))
                    .collect(),
            ),
            Value::Object(map) => {
                let mut new_map = serde_json::Map::with_capacity(map.len());
                for (k, v) in map {
                    new_map.insert(k.clone(), self.redact_json_depth(v, depth + 1));
                }
                Value::Object(new_map)
            }
            other => other.clone(),
        }
    }
}

// ============================================================================
// BuiltinDlpProvider — regex-based PII patterns
// ============================================================================

/// Validate a credit card number using the Luhn algorithm.
/// Returns true if the number passes the Luhn check.
fn luhn_check(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c.to_digit(10).unwrap_or(0))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let mut sum = 0;
    let mut alternate = false;

    for &digit in digits.iter().rev() {
        let mut d = digit;
        if alternate {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        alternate = !alternate;
    }

    sum % 10 == 0
}

/// Check whether the first digit matches a real-world card-issuer prefix
/// (Issuer Identification Number leading digit).
///
/// Card networks universally begin numbers with 3 (Amex, JCB, Diners),
/// 4 (Visa), 5 (MasterCard), or 6 (Discover, Maestro). No issuer starts
/// with 0/1/2/7/8/9. Filtering on this **before** Luhn eliminates a
/// large class of false positives — most notably 13-digit epoch-ms
/// timestamps (e.g. `1776192000000` — 2026 in ms) which occasionally
/// pass Luhn by coincidence (the check is modular and ~10% of random
/// 13-digit numbers pass).
///
/// Returns true iff `number`'s first digit character is in {3,4,5,6}.
/// A candidate with punctuation (`4111 1111 1111 1111`) resolves to
/// the first ASCII-digit character, matching real-world grouping.
fn has_card_issuer_prefix(number: &str) -> bool {
    number
        .chars()
        .find(|c| c.is_ascii_digit())
        .map(|c| matches!(c, '3' | '4' | '5' | '6'))
        .unwrap_or(false)
}

/// Compiled regex for credit card pattern matching.
/// NOTE: use `r"\b"` (single backslash in raw string = word-boundary assertion in regex).
/// `r"\\b"` would send `\\b` to the engine = literal backslash + b, which never matches.
///
/// MCP-1141 (2026-05-16): the pre-fix fallback was `.unwrap_or_else(|_|
/// Regex::new(".*").expect("fallback regex"))` — if the primary regex
/// ever failed to compile (a future edit breaking the pattern, etc.),
/// the fallback `.*` would match the ENTIRE input as one giant match,
/// then the redaction loop's per-match `is_valid_luhn` filter would
/// reject it (not enough digits in "hello world") and append the input
/// verbatim. Net effect: credit-card redaction silently no-ops on a
/// regex-compile failure — fail-OPEN behaviour exactly the
/// MCP-1009 sweep closed (Slack mention regex per-call compile +
/// fail-OPEN on unwrap_or). Canonical workspace pattern is `.expect()`
/// — loud panic at first use surfaces the deployment-time regression
/// instead of silently dropping a DLP control.
static CARD_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // Credit card regex pattern (compiled once)
    // NOTE: This pattern uses word boundaries to avoid matching numbers embedded in
    // larger strings (e.g., IDs, timestamps that happen to contain card-like digits).
    Regex::new(r"\b(?:\d{4}[-\s]?){3,4}\d{1,4}\b|\b\d{13,19}\b")
        .expect("BUG: credit-card DLP regex failed to compile — fail-closed at first use")
});

/// Redact potential credit card numbers with Luhn validation.
/// This prevents false positives on random digit strings.
fn redact_credit_cards(input: &str) -> String {
    let card_pattern = &*CARD_PATTERN;

    let mut last_end = 0;
    // Pre-allocate with capacity - may grow if many redactions occur
    let mut output_str = String::with_capacity(input.len());

    for mat in card_pattern.find_iter(input) {
        // Append text before this match
        output_str.push_str(&input[last_end..mat.start()]);

        let candidate = mat.as_str();

        // Two-gate filter:
        //   1. Issuer prefix (3/4/5/6) — rejects epoch-ms timestamps (17xx…),
        //      snowflake IDs, sequence numbers that happen to coincide.
        //   2. Luhn — rejects random digits that happen to start with 3/4/5/6.
        // Both gates required, Luhn last (cheaper to fail on prefix first).
        if has_card_issuer_prefix(candidate) && luhn_check(candidate) {
            output_str.push_str("[REDACTED:CARD]");
        } else {
            output_str.push_str(candidate);
        }

        last_end = mat.end();
    }

    output_str.push_str(&input[last_end..]);
    output_str // was: `output` (original input) — dead code, redaction never applied
}

/// Source-of-truth `(pattern, replacement_token)` pairs. Both [`PATTERNS`]
/// (compiled regexes for per-match replacement) and [`PATTERN_SET`] (a single
/// combined automaton for the cheap "does anything match" gate) derive from
/// this ONE list, so the detection set and the replacement set can never
/// drift apart.
///
/// Ordered by specificity (more specific patterns first) to minimize false
/// positives and unnecessary allocations.
const PATTERN_SPECS: &[(&str, &str)] = &[
    // Talos platform API keys — most specific pattern first to avoid partial matches.
    // Format: talos_sk_ + 8 hex (prefix) + 64 hex (secret) = 72 hex chars total.
    (r"\btalos_sk_[0-9a-f]{72}\b", "[REDACTED:TALOS_API_KEY]"),
    // Email addresses (checked before phone to avoid partial matches)
    (
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        "[REDACTED:EMAIL]",
    ),
    // US Social Security Number  123-45-6789
    (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED:SSN]"),
    // Credit/debit card — two complementary patterns:
    //
    // Pattern A (grouped format): 4-4-4-4 or 4-4-4-4-3 with mandatory space/dash
    // separators. Requires at least one separator between groups so that bare
    // long numeric strings (Twitter/X snowflake IDs, transaction IDs, Unix
    // timestamps) are NOT matched. Real card numbers typed or printed by users
    // almost always appear with group separators.
    (
        r"\b\d{4}[ \-]\d{4}[ \-]\d{4}[ \-]\d{4,7}\b",
        "[REDACTED:CARD]",
    ),
    // Pattern B (keyword-prefixed bare number): matches card numbers preceded by
    // card-related keywords even without separators (e.g. JSON field "card_number":
    // 4111111111111111). The keyword requirement prevents false positives on raw
    // numeric IDs found in URLs, API responses, or log lines.
    (
        r#"(?i)(?:card[\s_]?(?:number|num|no)?|credit[\s_]card|debit[\s_]card|cc[\s_]?(?:number|num)?|pan)\s*[=:"\s]\s*\d{13,19}"#,
        "[REDACTED:CARD]",
    ),
    // Bearer / API key header values  (Bearer xyz, token=xyz, api_key=xyz)
    (
        r"(?i)(?:bearer|token|api[_-]?key)\s*[=:\s]\s*[A-Za-z0-9\-._~+/]{8,}",
        "[REDACTED:TOKEN]",
    ),
    // Google API keys  AIza + 35 alphanumeric chars
    (r"\bAIza[0-9A-Za-z\-_]{35}\b", "[REDACTED:GOOGLE_API_KEY]"),
    // Google OAuth 2.0 access tokens  ya29.<long string>
    (
        r"\bya29\.[0-9A-Za-z\-_]{40,}\b",
        "[REDACTED:GOOGLE_OAUTH_TOKEN]",
    ),
    // HashiCorp Vault tokens  hvs_... / hvb_...
    (
        r"\b(?:hvs_|hvb_)[A-Za-z0-9_\.]{20,}\b",
        "[REDACTED:VAULT_TOKEN]",
    ),
    // Slack app-level tokens  xoxs-...
    (r"\bxoxs-[0-9A-Za-z\-]{40,}\b", "[REDACTED:SLACK_TOKEN]"),
    // Prefixed secret keys  sk-..., ghp_..., xoxb-..., glpat-...
    //
    // IMPORTANT: `sk` requires a separator char (`-` or `_`) to avoid false-positives
    // on common English words that start with "sk" (e.g. "skepticism", "skeleton").
    // Real OpenAI keys are `sk-proj-...` / `sk-...`; Stripe keys are `sk_live_...` /
    // `sk_test_...` — both always have a separator immediately after the prefix.
    //
    // MCP-575 (2026-05-12): GitHub OAuth (`gho_`) + user-to-server
    // (`ghu_`) + refresh-token (`ghr_`) prefixes added. `ghp_`
    // (PAT) and `ghs_` (server-to-server) were already covered;
    // missing the OAuth-flow variants was a real gap (we have an
    // OAuth integration that returns these). Also added Slack
    // `xoxa-` (app-level token used by `apps.manifest.create`)
    // and `xoxr-` (refresh token), plus Stripe restricted keys
    // (`rk_test_` / `rk_live_`) — distinct from regular `sk_*`
    // and represent scoped credentials operators use to limit
    // blast radius on automation flows.
    //
    // MCP-1134 (2026-05-16): added `hf_` (Hugging Face access
    // tokens — common in LLM/embedding workflows that route
    // through huggingface_hub) and `xai-` (xAI / Grok API keys
    // — listed as `xai-...` in xAI's `Authorization: Bearer`
    // docs). Same canonical-format-coverage class as MCP-575
    // and MCP-1001 (PEM block variants). Real-world copy/paste
    // exfiltration: `hf_AbCd1234...` in a workflow input
    // accidentally pasted by an operator, or `xai-...` in a
    // module config. Both prefixes are short alphabetic +
    // delimiter so the existing `[A-Za-z0-9\-_]{6,}` body
    // suffix covers the token tail.
    //
    // 2026-06-02: two FIRST-CLASS-integration secret formats that
    // slipped the prior sweeps:
    //   * `whsec_` — Stripe webhook SIGNING secret. Stripe is a
    //     built-in template integration (Create_Checkout_Session,
    //     Create_Subscription, …); the `sk_`/`rk_` API keys were
    //     covered but the webhook-signing secret (distinct prefix,
    //     lives in module config to verify inbound events) was not.
    //   * `ATATT` — Atlassian API token (id.atlassian.com), used by
    //     the talos-atlassian Jira/Confluence integration. Uppercase
    //     `ATATT` doesn't occur in prose (the pattern is
    //     case-sensitive, so lowercase "attachment" etc. can't match),
    //     so the shared `{6,}` body is safe.
    //
    // 2026-06-02 (b): common EXTERNAL automation-provider token prefixes a
    // module might handle (modules are arbitrary WASM that can call any API; a
    // failed call echoing an auth header or a config dumped in an error would
    // otherwise persist the secret to the DB). All are DISTINCTIVE prefixes
    // with no English-prose collision, so the shared `{6,}` body is safe and
    // false-positive-free:
    //   * `shpat_`/`shpss_`/`shpca_`/`shppa_` — Shopify admin/storefront/
    //     custom-app/private-app access tokens (e-commerce automation).
    //   * `dop_v1_` — DigitalOcean personal access token (infra automation).
    //   * `sq0atp-`/`sq0csp-` — Square access / OAuth-app secret (payments).
    //   * `lin_api_` — Linear API key (issue-tracker automation).
    //   * `PMAK-` — Postman API key (uppercase, distinctive).
    (
        r"\b(?:sk[-_]|ghp_|ghs_|gho_|ghu_|ghr_|github_pat_|xoxb-|xoxp-|xoxa-|xoxr-|xapp-|glpat-|npm_|rk_test_|rk_live_|hf_|xai-|SG\.|whsec_|ATATT|shpat_|shpss_|shpca_|shppa_|dop_v1_|sq0atp-|sq0csp-|lin_api_|PMAK-)[A-Za-z0-9\-_]{6,}",
        "[REDACTED:API_KEY]",
    ),
    // MCP-521: AWS Access Key IDs. Real AWS access key IDs are
    // EXACTLY 20 characters: `AKIA` (long-term IAM user) or
    // `ASIA` (STS temporary credential) followed by exactly 16
    // uppercase alphanumeric chars. The previous pattern lumped
    // these into the `sk-/ghp_/…` alternation and required 6+
    // additional trailing chars via `[A-Za-z0-9\-_]{6,}` — so a
    // standalone `AKIAIOSFODNN7EXAMPLE` (20 chars, no trailing)
    // matched nothing and passed through DLP unscrubbed. The
    // canonical exfiltration shape is a 20-char value in an env
    // file or terminal copy/paste, which is exactly what this
    // gap let through.
    //
    // Anchor with word boundaries on both ends so `AKIA…20chars`
    // followed by ANY non-word char (newline, space, quote, `=`,
    // comma) still matches.
    (r"\bA[KS]IA[0-9A-Z]{16}\b", "[REDACTED:AWS_ACCESS_KEY]"),
    // Database connection URLs with embedded credentials.
    // Matches postgresql://, postgres://, mysql://, mongodb://, mongodb+srv:// etc.
    // where a user:password@ component is present.
    (
        r"(?i)(?:postgresql|postgres|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp(?:s)?|clickhouse)://[^:@\s]+:[^@\s]+@[^\s]+",
        "[REDACTED:DB_CONNECTION]",
    ),
    // US/international phone numbers  +1-800-555-1234 | (800) 555-1234 | 800.555.1234
    //
    // IMPORTANT: at least ONE separator (space, dash, or dot) is required somewhere
    // in the number.  Making all separators optional caused false positives on bare
    // digit strings embedded in URLs (e.g. Twitter/X status IDs, transaction IDs).
    // Requires at least TWO separators to further reduce false positives on
    // numeric identifiers that happen to contain one dash (e.g., "order-1234567890").
    // Three accepted sub-forms:
    //   1. Country-code prefix with separator: +1-800-555-1234
    //   2. Parenthesised area code: (800) 555-1234  or  (800)555-1234
    //   3. Plain format with mandatory separators: 800-555-1234 (both separators required)
    (
        r"(?:\+\d{1,3}[\s\-.]\(?\d{3}\)?[\s\-.]\d{3}[\s\-.]\d{4}|\(\d{3}\)[\s\-.]?\d{3}[\s\-.]\d{4}|\b\d{3}[\s\-.]\d{3}[\s\-.]\d{4})\b",
        "[REDACTED:PHONE]",
    ),
    // JWT tokens — three base64url segments separated by dots (header.payload.signature).
    // Requires the header to start with "eyJ" (base64 of `{"`) which is true for all
    // valid JWTs. This catches tokens that appear outside Bearer/Authorization headers.
    (
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        "[REDACTED:JWT]",
    ),
    // Private key PEM blocks — prevents accidental logging of key material.
    //
    // MCP-1001 (2026-05-15): extended the variant list to cover the
    // formats actually emitted by mainstream tooling. Pre-fix pattern
    // `(?:RSA |EC |ED25519 )?` covered only PKCS#1, SEC1, and the
    // (rare) explicit-ed25519 PEM tag — but missed:
    //   * `-----BEGIN OPENSSH PRIVATE KEY-----` — the default
    //     `ssh-keygen` output since OpenSSH 7.8 (2018). The most
    //     common copy/paste exfil shape today.
    //   * `-----BEGIN DSA PRIVATE KEY-----` — legacy, still in
    //     circulation on old systems.
    //   * `-----BEGIN ENCRYPTED PRIVATE KEY-----` — PKCS#8 encrypted
    //     variant.
    //   * `-----BEGIN PGP PRIVATE KEY BLOCK-----` — GPG export, the
    //     `BLOCK` suffix distinguishes it from the X.509 family.
    // The `(?: BLOCK)?` suffix lets the PGP variant share the same
    // alternation. Word-level enumeration is explicit so false
    // positives on user prose (`"BEGIN VAULTING PRIVATE KEYSTORE"`)
    // are impossible.
    (
        r"-----BEGIN (?:RSA |EC |ED25519 |DSA |ENCRYPTED |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        "[REDACTED:PRIVATE_KEY]",
    ),
];

/// Compiled per-pattern regexes used for replacement, built once at startup
/// from [`PATTERN_SPECS`].
static PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    // MCP-1141 (2026-05-16): the pre-fix `.filter_map(|(p, t)|
    // Regex::new(p).ok().map(...))` silently dropped any pattern that
    // failed to compile. A regression in any one of the DLP patterns
    // above (PRIVATE_KEY / API_KEY / AWS / JWT / DB_CONNECTION / PHONE
    // / OAUTH / SLACK / VAULT) would land an UNREDACTED match shape in
    // every downstream caller (`redact_str`, `redact_json`,
    // `redact_credit_cards`) with no operator-visible signal.
    //
    // Same fail-OPEN class as MCP-1009 (Slack mention regex per-call
    // compile + unwrap_or fall-through) and the sibling `CARD_PATTERN`
    // fix above. Canonical workspace pattern is `.expect()` — loud
    // panic at first use surfaces the deployment-time regression
    // instead of silently dropping a DLP control. The patterns above
    // are hardcoded; a compile failure can only mean a code-edit bug.
    PATTERN_SPECS
        .iter()
        .map(|(pattern, tag)| {
            let re = Regex::new(pattern).unwrap_or_else(|e| {
                panic!(
                    "BUG: DLP redaction pattern {:?} (tag {}) failed to compile: {} \
                     — fail-closed at first use rather than silently disable the rule",
                    pattern, tag, e
                )
            });
            (re, *tag)
        })
        .collect()
});

/// Single combined automaton over every pattern in [`PATTERN_SPECS`].
/// `is_match` answers "does ANY pattern match?" in ONE pass over the input
/// instead of the N separate `Regex::is_match` scans the fast path used to
/// pay — an ~Nx reduction in scan work on the common no-secret input that
/// dominates the hot broadcast/log scrubber path. Semantically identical to
/// `PATTERNS.iter().any(|(re, _)| re.is_match(input))`, pinned by the
/// `regexset_fastpath_matches_per_pattern_any` test.
///
/// Same fail-closed discipline as [`PATTERNS`] / `CARD_PATTERN`: a compile
/// failure panics at first use rather than silently disabling detection.
static PATTERN_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new(PATTERN_SPECS.iter().map(|(p, _)| *p)).unwrap_or_else(|e| {
        panic!(
            "BUG: DLP RegexSet failed to compile from PATTERN_SPECS: {e} \
             — fail-closed rather than silently disable secret detection"
        )
    })
});

/// True when `input` contains anything any DLP rule would redact — the
/// combined pattern set OR the Luhn-gated card pattern. A single
/// combined-automaton pass plus one card scan; this is the cheap gate that
/// lets both redactors skip the full per-pattern replacement walk (and its
/// ~N allocations) on the common no-secret input. Conservative for cards:
/// `CARD_PATTERN` matching without a valid Luhn check still routes to the
/// full walk (which then correctly leaves the value unredacted), so the
/// gate never skips real redaction.
fn input_needs_redaction(input: &str) -> bool {
    PATTERN_SET.is_match(input) || CARD_PATTERN.is_match(input)
}

/// Regex-based PII redaction — the default provider.
pub struct BuiltinDlpProvider;

impl BuiltinDlpProvider {
    /// Optimized redaction that minimizes allocations for common cases.
    /// Returns `Cow::Borrowed` if no redaction needed, avoiding the
    /// ~14-allocation per-pattern walk that `redact_str` (the trait
    /// method) pays unconditionally. Wired through the public
    /// `redact_str_cow` free function and used on hot paths like the
    /// WASM log broadcast scrubber (`controller::scrub_wasm_log_for_broadcast`)
    /// where the typical message has zero matches and the trait method
    /// burns CPU on dead allocations.
    pub fn redact_str_optimized<'a>(&self, input: &'a str) -> std::borrow::Cow<'a, str> {
        // Fast path: one combined-automaton pass (+ one card scan) decides
        // whether anything needs redacting before we allocate.
        if !input_needs_redaction(input) {
            return std::borrow::Cow::Borrowed(input);
        }

        // Apply redaction
        std::borrow::Cow::Owned(self.redact_str(input))
    }
}

impl DlpProvider for BuiltinDlpProvider {
    fn redact_str(&self, input: &str) -> String {
        // Fast path: skip the per-pattern replacement walk (and its ~N
        // `replace_all` allocations) when a single combined-automaton pass
        // proves nothing matches — the common case on most
        // persistence-boundary writes. Behaviourally identical to the walk,
        // which would leave a no-match input unchanged anyway.
        if !input_needs_redaction(input) {
            return input.to_owned();
        }

        // First apply credit card validation with Luhn check
        let mut result = redact_credit_cards(input);

        // Then apply other patterns
        for (re, tag) in PATTERNS.iter() {
            result = re.replace_all(&result, *tag).into_owned();
        }
        result
    }

    fn redact_str_cow<'a>(&self, input: &'a str) -> std::borrow::Cow<'a, str> {
        self.redact_str_optimized(input)
    }
}

// ============================================================================
// PassthroughDlpProvider — no-op
// ============================================================================

/// No-op provider — returns inputs unchanged.  Used when `DLP_PROVIDER=none`.
pub struct PassthroughDlpProvider;

impl DlpProvider for PassthroughDlpProvider {
    fn redact_str(&self, input: &str) -> String {
        input.to_owned()
    }

    fn redact_str_cow<'a>(&self, input: &'a str) -> std::borrow::Cow<'a, str> {
        std::borrow::Cow::Borrowed(input)
    }

    fn redact_json(&self, value: &Value) -> Value {
        value.clone()
    }
}

// ============================================================================
// ExternalDlpProvider — HTTP webhook
// ============================================================================

/// HTTP contract (POST to `DLP_WEBHOOK_URL`):
///
/// String redaction:
/// - Request:  `{ "text": "...", "type": "string" }`
/// - Response: `{ "redacted": "..." }`
///
/// JSON redaction:
/// - Request:  `{ "json": {...}, "type": "json" }`
/// - Response: `{ "redacted": {...} }`
///
/// On any transport or parse error the request falls back silently to
/// `BuiltinDlpProvider` (infallible principle preserved).
pub struct ExternalDlpProvider {
    endpoint: String,
    client: reqwest::blocking::Client,
    token: Option<String>,
    fallback: BuiltinDlpProvider,
}

impl ExternalDlpProvider {
    fn new(endpoint: String, token: Option<String>) -> Self {
        // MCP-497: external DLP provider receives plaintext sensitive
        // data (the whole point of DLP is to scrub it on the wire).
        // `Client::new()` re-enables default redirect following — a
        // 302 from the configured DLP endpoint to a different host
        // would carry the sensitive payload AND the bearer token to
        // the redirect target. The endpoint is operator-configured;
        // a compromised provider with an open-redirect bug becomes a
        // data exfiltration vector.
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("ExternalDlpProvider: failed to build hardened blocking client");
        Self {
            endpoint,
            client,
            token,
            fallback: BuiltinDlpProvider,
        }
    }

    fn send(&self, body: serde_json::Value) -> Option<serde_json::Value> {
        let mut req = self.client.post(&self.endpoint).json(&body);
        if let Some(tok) = &self.token {
            req = req.header("Authorization", format!("Bearer {tok}"));
        }
        // block_in_place allows blocking calls inside a tokio multi-threaded runtime.
        tokio::task::block_in_place(|| req.send().ok()?.json::<serde_json::Value>().ok())
    }
}

impl DlpProvider for ExternalDlpProvider {
    fn redact_str(&self, input: &str) -> String {
        let body = serde_json::json!({ "text": input, "type": "string" });
        match self.send(body) {
            Some(resp) => resp
                .get("redacted")
                .and_then(|v| v.as_str())
                .map(|s| s.to_owned())
                .unwrap_or_else(|| self.fallback.redact_str(input)),
            None => self.fallback.redact_str(input),
        }
    }

    fn redact_json(&self, value: &Value) -> Value {
        let body = serde_json::json!({ "json": value, "type": "json" });
        match self.send(body) {
            Some(resp) => resp
                .get("redacted")
                .cloned()
                .unwrap_or_else(|| self.fallback.redact_json(value)),
            None => self.fallback.redact_json(value),
        }
    }
}

// ============================================================================
// DlpService — injectable wrapper
// ============================================================================

/// Injectable DLP service wrapping any [`DlpProvider`].
///
/// Clone is cheap — the inner provider is behind `Arc`.
#[derive(Clone)]
pub struct DlpService(Arc<dyn DlpProvider>);

impl DlpService {
    /// Construct from environment variables.
    ///
    /// | `DLP_PROVIDER` | Behavior |
    /// |---|---|
    /// | `builtin` (default) | Regex-based PII patterns |
    /// | `none` | Passthrough — no redaction |
    /// | `external` | HTTP webhook; `DLP_WEBHOOK_URL` required |
    pub fn from_env() -> Self {
        let provider_name = std::env::var("DLP_PROVIDER")
            .unwrap_or_else(|_| "builtin".to_string())
            .to_lowercase();

        let provider: Arc<dyn DlpProvider> = match provider_name.as_str() {
            "none" => {
                // MCP-574: passthrough DLP in production is a security
                // regression. Every persistence-boundary call site that
                // pipes user/third-party text through redact_str/redact_json
                // (see the persistence_boundary_dlp_rule memory note for
                // the 15+ sites this affects) becomes a no-op — secrets
                // pasted into workflow descriptions, OAuth error bodies,
                // upstream API responses all land in the DB plaintext.
                //
                // Loud at startup so an operator who set DLP_PROVIDER=none
                // for a test run and forgot to revert before promoting to
                // production gets a paging-quality signal. Pre-fix this
                // was INFO-level — trivially missed in normal log volume.
                // Not fail-CLOSED because some operators have a custom DLP
                // sidecar that intercepts traffic upstream of the
                // controller and rightfully wants the in-process layer off.
                let env_warn_emit = if talos_config::is_production() {
                    tracing::error!(
                        target: "talos_dlp_provider",
                        event_kind = "dlp_disabled_in_production",
                        "DLP_PROVIDER=none in production — all redact_str / redact_json calls are NO-OPS. Sensitive values WILL be persisted to admin_event_log, workflow_executions.error_message, actor_action_log, etc. Verify this is intentional or rotate any secrets that may have already been logged."
                    );
                    "ERROR"
                } else {
                    tracing::warn!(
                        target: "talos_dlp_provider",
                        event_kind = "dlp_disabled",
                        "DLP_PROVIDER=none — passthrough mode (no redaction). Acceptable in dev; set DLP_PROVIDER=builtin or 'external' before promoting to production."
                    );
                    "WARN"
                };
                let _ = env_warn_emit; // silence unused warning under #[allow(dead_code)]
                Arc::new(PassthroughDlpProvider)
            }
            "external" => {
                let url = std::env::var("DLP_WEBHOOK_URL").unwrap_or_default();
                if url.is_empty() {
                    tracing::warn!(
                        "DLP_PROVIDER=external but DLP_WEBHOOK_URL is not set; \
                         falling back to builtin"
                    );
                    Arc::new(BuiltinDlpProvider)
                } else {
                    // MCP-936 (2026-05-15): filter empty-string env so a
                    // Helm-placeholder `DLP_WEBHOOK_TOKEN=""` doesn't
                    // propagate `Some("")` into the provider. Pre-fix
                    // every external-DLP request would send a literal
                    // `Authorization: Bearer ` (empty token, trailing
                    // space) — most webhook servers respond 401, the
                    // internal `BuiltinDlpProvider` fallback fires per
                    // request, and the operator pays an HTTP round-trip
                    // for every redaction without realising auth is
                    // misconfigured. With the filter, an empty token
                    // means "no Authorization header" (matches the
                    // intent of `if let Some(tok)` at the send site).
                    // Same empty-env-var-bypass class as MCP-590..631 /
                    // MCP-934 / MCP-935.
                    let token = std::env::var("DLP_WEBHOOK_TOKEN")
                        .ok()
                        .filter(|v| !v.is_empty());
                    tracing::info!(
                        "DLP provider: external ({})",
                        url.split('?').next().unwrap_or(&url)
                    );
                    Arc::new(ExternalDlpProvider::new(url, token))
                }
            }
            _ => {
                if provider_name != "builtin" {
                    tracing::warn!("Unknown DLP_PROVIDER '{}'; using builtin", provider_name);
                }
                tracing::info!("DLP provider: builtin (regex patterns)");
                Arc::new(BuiltinDlpProvider)
            }
        };

        Self(provider)
    }

    pub fn redact_str(&self, s: &str) -> String {
        self.0.redact_str(s)
    }

    pub fn redact_str_cow<'a>(&self, s: &'a str) -> std::borrow::Cow<'a, str> {
        self.0.redact_str_cow(s)
    }

    pub fn redact_json(&self, v: &Value) -> Value {
        self.0.redact_json(v)
    }
}

// ============================================================================
// Process-wide fallback (for code that cannot receive DlpService via DI)
// ============================================================================

/// Global `DlpService` initialized from environment variables on first use.
///
/// Engine, scheduler, and audit_ledger code that cannot receive the service
/// via dependency injection uses this via the free functions below.
static GLOBAL_DLP: LazyLock<DlpService> = LazyLock::new(DlpService::from_env);

/// Apply DLP patterns to a string, returning the redacted version.
///
/// Delegates to the process-wide `DlpService`.  Returns the original string
/// unchanged if an internal error occurs (infallible).
pub fn redact_str(s: &str) -> String {
    GLOBAL_DLP.redact_str(s)
}

/// Allocation-light variant of [`redact_str`]. Returns `Cow::Borrowed`
/// when the input contains no PII patterns, avoiding the per-pattern
/// allocation cycle that `redact_str` pays unconditionally.
///
/// Use this on hot paths where most inputs are expected to be
/// pattern-free (per-log-line WASM broadcast, per-event subscriber
/// fan-out). The trait method is still appropriate on persistence-
/// boundary writes where a single allocation per row is acceptable.
///
/// Dispatches via the `DlpProvider::redact_str_cow` trait method;
/// builtin + passthrough providers override with zero-alloc fast
/// paths, external provider falls back to the alloc-once shape.
pub fn redact_str_cow(s: &str) -> std::borrow::Cow<'_, str> {
    GLOBAL_DLP.redact_str_cow(s)
}

/// Recursively redact string leaves in a JSON value tree.
///
/// Delegates to the process-wide `DlpService`.  Clones the value — never
/// mutates in place.
pub fn redact_json(v: &Value) -> Value {
    GLOBAL_DLP.redact_json(v)
}

/// Canonical 1 MiB cap on JSONB log-metadata columns.
///
/// Matches the bound applied at `actor_action_log.details` /
/// `admin_event_log.details` (MCP-1195) and the
/// `workflow_execution_logs.metadata` / `module_execution_logs.metadata`
/// caps enforced via `validate_jsonb_size`.
pub const MAX_LOG_METADATA_BYTES: usize = 1_048_576;

/// Canonical 10 MiB cap on `workflow_executions.{input_data,output_data}`
/// JSONB columns.
///
/// Matches the workflow-INPUT ceiling enforced by
/// `talos_api::validation::MAX_PAYLOAD_SIZE`. Symmetric ceiling for the
/// output and queued-input persistence boundaries (MCP-1204 / MCP-1205).
/// Workflow input/output is the aggregated terminal-node payload of a
/// full execution: LLM responses, scraped HTML, large JSON datasets,
/// approval-gate webhook bodies, suspension-resume payloads — all
/// plausible multi-MB.
pub const MAX_EXECUTION_PAYLOAD_BYTES: usize = 10 * 1024 * 1024;

/// Measure-first bound on workflow-execution payload JSONB columns.
///
/// Returns `Cow::Borrowed(input)` on under-cap (zero clone cost on
/// the happy path) or `Cow::Owned(sentinel)` on over-cap. Sentinel
/// shape preserves valid JSON for consumers reading the column
/// post-write while explicitly surfacing the truncation:
///
/// ```json
/// {
///   "_truncated": true,
///   "_original_size_bytes": <N>,
///   "_reason": "execution payload exceeded 10 MiB persistence cap"
/// }
/// ```
///
/// Structured WARN (`event_kind = "execution_payload_oversized"`)
/// fires for operator log pipelines. Sibling helper to
/// `redact_json_bounded` (1 MiB log-metadata cap) — same
/// measure-first discipline, different ceiling and different
/// over-cap action (sentinel vs. drop-to-None) chosen per the
/// surface's semantics.
///
/// Applied at:
/// - `workflow_executions.output_data` writers (MCP-1204):
///   `mark_execution_completed`, `mark_execution_waiting`,
///   `mark_execution_failed`, `update_execution_output`.
/// - `workflow_executions.input_data` writer (MCP-1205):
///   `AdvancedRepository::insert_queued_execution`.
pub fn bound_execution_payload(v: &Value) -> std::borrow::Cow<'_, Value> {
    let approx_size = serde_json::to_string(v).map(|s| s.len()).unwrap_or(0);
    if approx_size > MAX_EXECUTION_PAYLOAD_BYTES {
        tracing::warn!(
            target: "talos_audit",
            event_kind = "execution_payload_oversized",
            size_bytes = approx_size,
            limit_bytes = MAX_EXECUTION_PAYLOAD_BYTES,
            "execution payload exceeded 10 MiB cap — storing truncation sentinel"
        );
        std::borrow::Cow::Owned(serde_json::json!({
            "_truncated": true,
            "_original_size_bytes": approx_size,
            "_reason": "execution payload exceeded 10 MiB persistence cap"
        }))
    } else {
        std::borrow::Cow::Borrowed(v)
    }
}

/// Measure-first-then-redact for JSONB log-metadata columns.
///
/// Returns `None` when the serialised form exceeds 1 MiB — caller should
/// bind `NULL` (or omit the column) and the summary fields covering the
/// same event still persist.  Returning `None` is a load-shedding signal,
/// not a data-loss bug: log metadata is best-effort context, not the
/// authoritative event record.
///
/// Pre-fix sweep (MCP-1197) found four integration audit-log writers
/// across `talos-gmail`, `talos-slack`, and `talos-google-calendar` that
/// scrubbed metadata via `redact_json` but never bounded the input size.
/// The `stop_all` admin endpoint in particular packs `e.to_string()` of
/// every failed `stop_watch` call into a `failed` array — under a wide
/// outage the metadata blob can exceed 1 MiB and bloat the audit table /
/// WAL.  Same defense-in-depth pattern as the sibling
/// `bound_log_details` helper in `talos-actor-repository`.
pub fn redact_json_bounded(v: &Value) -> Option<Value> {
    let approx_size = serde_json::to_string(v).map(|s| s.len()).unwrap_or(0);
    if approx_size > MAX_LOG_METADATA_BYTES {
        tracing::warn!(
            target: "talos_audit",
            event_kind = "log_metadata_oversized_dropped",
            size_bytes = approx_size,
            limit_bytes = MAX_LOG_METADATA_BYTES,
            "log metadata exceeded 1 MiB cap — dropping field (summary still persisted)"
        );
        return None;
    }
    Some(GLOBAL_DLP.redact_json(v))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// SAFETY PIN for the fast-path optimization: the combined `PATTERN_SET`
    /// automaton must be EXACTLY equivalent to "any individual pattern
    /// matches". `redact_str` / `redact_str_optimized` skip the full
    /// redaction walk when `input_needs_redaction` is false, so any input
    /// where the RegexSet says "no match" but some individual pattern WOULD
    /// match is a fail-open hole (a secret passes through unredacted). This
    /// battery — no-match strings plus a real-shaped instance of each pattern
    /// family — pins the equivalence so a future RegexSet/Regex divergence is
    /// caught at PR time.
    #[test]
    fn regexset_fastpath_matches_per_pattern_any() {
        let inputs = [
            // no-match
            "nothing sensitive here",
            "order-1234567890 has shipped",
            "just some prose with numbers 42 and words",
            // one real-shaped instance per pattern family
            "contact alice@example.com for details",
            "key AKIAIOSFODNN7EXAMPLE in env",
            "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQabcdef",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "dsn postgres://user:secret@db.host:5432/app",
            "call 800-555-1234 now",
            "ssn 123-45-6789 on file",
            "talos_sk_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567",
        ];
        for input in inputs {
            let via_set = PATTERN_SET.is_match(input);
            let via_any = PATTERNS.iter().any(|(re, _)| re.is_match(input));
            assert_eq!(
                via_set, via_any,
                "RegexSet fast-path disagreed with per-pattern OR on {input:?} \
                 (set={via_set}, any={via_any}) — fast path would skip redaction"
            );
        }
    }

    /// The gate must also recognise Luhn-valid card numbers (handled by the
    /// separate `CARD_PATTERN`, NOT in `PATTERN_SET`) so the fast path never
    /// skips card redaction; and it must return false on benign input.
    #[test]
    fn input_needs_redaction_gates_cards_and_clean_input() {
        assert!(!input_needs_redaction("totally benign text"));
        assert!(
            input_needs_redaction("card 4111 1111 1111 1111 on file"),
            "Luhn-valid card must route through the full redaction walk"
        );
    }

    #[test]
    fn redacts_ssn() {
        assert_eq!(redact_str("SSN: 123-45-6789"), "SSN: [REDACTED:SSN]");
    }

    #[test]
    fn redacts_card_grouped_format() {
        // Standard grouped format must be redacted
        assert!(redact_str("Card: 4111 1111 1111 1111").contains("[REDACTED:CARD]"));
        assert!(redact_str("4111-1111-1111-1111").contains("[REDACTED:CARD]"));
    }

    #[test]
    fn card_pattern_no_false_positive_on_bare_sequences() {
        // Bare long numeric sequences (Twitter IDs, snowflake IDs, timestamps) must NOT be redacted
        let twitter_url = "https://twitter.com/user/status/1234567890123456789";
        let result = redact_str(twitter_url);
        assert!(
            !result.contains("[REDACTED:CARD]"),
            "Twitter URL should not be redacted: {result}"
        );

        // Unix timestamps and transaction IDs
        assert!(!redact_str("txn_id: 1750000000000001").contains("[REDACTED:CARD]"));
    }

    #[test]
    fn card_pattern_no_false_positive_on_epoch_ms_timestamps() {
        // Regression: actor_memory keys embed epoch-ms timestamps like
        // `recall/1776192000000/hash`. 13-digit numbers starting with 1 or 2
        // occasionally pass the Luhn check by coincidence (~10% rate on random
        // digits) — before the issuer-prefix gate, these got redacted as
        // `[REDACTED:CARD]`, corrupting trace output and logs.
        //
        // Real card networks use leading digits 3 (Amex/JCB/Diners), 4 (Visa),
        // 5 (MasterCard), or 6 (Discover). 13-digit numbers starting with
        // anything else are never cards; rejecting them removes the FP class.
        for ms_ts in [
            // Actual values observed during pa-recall development:
            "recall/1776192000000/abc",
            "recall/1776191361697/xyz",
            "capture/1776470400000/def",
            // Synthetic edge cases that happen to pass Luhn:
            "timestamp: 1234567890123", // standard 13-digit, Luhn-pass
            "timestamp: 2000000000000", // upper range (year 2033)
        ] {
            let result = redact_str(ms_ts);
            assert!(
                !result.contains("[REDACTED:CARD]"),
                "epoch-ms timestamp should not be redacted as card: {ms_ts} → {result}"
            );
        }
    }

    #[test]
    fn card_pattern_still_redacts_real_card_numbers() {
        // Positive control: the issuer-prefix gate must NOT break redaction
        // of actual card-like numbers. These all start with 3/4/5/6 and
        // pass Luhn.
        for real_card in [
            "Card: 4111111111111111",    // Visa, 16-digit
            "Card: 4111-1111-1111-1111", // Visa, grouped
            "Card: 5555555555554444",    // MasterCard, 16-digit
            "Card: 378282246310005",     // Amex, 15-digit
            "Card: 6011111111111117",    // Discover, 16-digit
        ] {
            let result = redact_str(real_card);
            assert!(
                result.contains("[REDACTED:CARD]"),
                "real card number should be redacted: {real_card} → {result}"
            );
        }
    }

    #[test]
    fn redacts_card_with_keyword_context() {
        // Keyword-prefixed bare number
        assert!(redact_str("card_number: 4111111111111111").contains("[REDACTED:CARD]"));
        assert!(redact_str("credit card: 5500000000000004").contains("[REDACTED:CARD]"));
    }

    #[test]
    fn redacts_bearer_token() {
        let input = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        assert!(redact_str(input).contains("[REDACTED:TOKEN]"));
    }

    #[test]
    fn redacts_api_key() {
        let input = "key=sk-proj-abc123DEFGHIJKLMNOP";
        assert!(redact_str(input).contains("[REDACTED:API_KEY]"));
    }

    #[test]
    fn sk_prefix_requires_separator_no_false_positive() {
        // Words like "skepticism" and "skeleton" must NOT be redacted.
        assert_eq!(redact_str("skepticism"), "skepticism");
        assert_eq!(redact_str("skeleton key"), "skeleton key");
        // Real keys with separator MUST be redacted.
        assert!(redact_str("sk-proj-abc123DEFGHIJKLMNOP").contains("[REDACTED:API_KEY]"));
        assert!(redact_str("sk_live_abcdefghijklmno").contains("[REDACTED:API_KEY]"));
    }

    #[test]
    fn redacts_stripe_webhook_signing_secret() {
        // Stripe `whsec_` webhook signing secret (first-class integration) —
        // distinct from the `sk_`/`rk_` API keys, lives in module config.
        assert!(redact_str("whsec_AbCd1234EfGh5678IjKl9012MnOp").contains("[REDACTED:API_KEY]"));
        assert!(redact_str("STRIPE_WEBHOOK_SECRET=whsec_xY9zAbCdEfGhIjKl")
            .contains("[REDACTED:API_KEY]"));
        // The original secret must not survive.
        assert!(!redact_str("whsec_AbCd1234EfGh5678IjKl9012MnOp").contains("AbCd1234EfGh"));
    }

    #[test]
    fn redacts_atlassian_api_token() {
        // Atlassian `ATATT...` API token (talos-atlassian Jira/Confluence).
        assert!(redact_str("ATATT3xFfGF0abcDEF123ghiJKL456").contains("[REDACTED:API_KEY]"));
        // Case-sensitive prefix: lowercase prose like "attachment" / "attatt"
        // must NOT match (no false positive).
        assert_eq!(redact_str("attachment list"), "attachment list");
        assert_eq!(redact_str("the attribute value"), "the attribute value");
    }

    #[test]
    fn redacts_common_external_provider_tokens() {
        // Distinctive-prefix tokens for common automation providers.
        for tok in [
            "shpat_abc123DEF456ghi789",      // Shopify admin
            "shpss_0123456789abcdefABCDEF",  // Shopify storefront
            "dop_v1_abcdef0123456789abcdef", // DigitalOcean PAT
            "sq0atp-AbCdEf0123456789xyz",    // Square access token
            "sq0csp-AbCdEf0123456789xyz",    // Square app secret
            "lin_api_abcDEF123ghiJKL456mno", // Linear
            "PMAK-abcdef0123456789ABCDEF",   // Postman
        ] {
            assert!(
                redact_str(tok).contains("[REDACTED:API_KEY]"),
                "must redact provider token {tok}"
            );
            // The token's trailing body must not survive verbatim.
            assert!(!redact_str(tok).contains(&tok[tok.len() - 12..]));
        }
    }

    #[test]
    fn external_provider_prefixes_no_prose_false_positive() {
        // None of the prefixes collide with English prose / common identifiers.
        for clean in [
            "shopping cart total",
            "linear regression model",
            "dropbox sync status",
            "the square root function",
            "postmaster general",
        ] {
            assert_eq!(redact_str(clean), clean, "must not redact prose: {clean}");
        }
    }

    #[test]
    fn redacts_email() {
        let input = "Contact us at user@corp.com for more info.";
        let redacted = redact_str(input);
        assert!(redacted.contains("[REDACTED:EMAIL]"), "got: {redacted}");
        assert!(!redacted.contains("user@corp.com"));
    }

    #[test]
    fn redacts_phone() {
        let input = "Call us at +1-800-555-1234 anytime.";
        let redacted = redact_str(input);
        assert!(redacted.contains("[REDACTED:PHONE]"), "got: {redacted}");
    }

    #[test]
    fn redacts_phone_formats() {
        // Parenthesised area code
        assert!(redact_str("(800) 555-1234").contains("[REDACTED:PHONE]"));
        // Parenthesised area code, no space
        assert!(redact_str("(800)555-1234").contains("[REDACTED:PHONE]"));
        // Plain format with dash
        assert!(redact_str("800-555-1234").contains("[REDACTED:PHONE]"));
        // Plain format with dot
        assert!(redact_str("800.555.1234").contains("[REDACTED:PHONE]"));
        // Plain format with space
        assert!(redact_str("800 555 1234").contains("[REDACTED:PHONE]"));
    }

    #[test]
    fn phone_no_false_positive_on_url_numeric_ids() {
        // Twitter/X status IDs are long bare digit strings — must NOT be redacted as phone
        let twitter = "https://twitter.com/user/status/1234567890123456789";
        let result = redact_str(twitter);
        assert!(
            !result.contains("[REDACTED:PHONE]"),
            "Twitter URL should not be phone-redacted: {result}"
        );

        // Bare 10-digit numeric strings with no separators
        assert!(
            !redact_str("txn: 8005551234").contains("[REDACTED:PHONE]"),
            "Bare 10-digit string should not be redacted without separators"
        );

        // 19-digit snowflake ID in structured output
        assert!(
            !redact_str("{\"id\": 1585524724498554880}").contains("[REDACTED:PHONE]"),
            "Snowflake ID should not be redacted as phone"
        );
    }

    #[test]
    fn redacts_json_leaves() {
        let val = serde_json::json!({
            "ssn": "123-45-6789",
            "count": 42,
            "nested": { "token": "Bearer mytoken123456" }
        });
        let redacted = redact_json(&val);
        assert_eq!(redacted["ssn"].as_str().unwrap(), "[REDACTED:SSN]");
        assert_eq!(redacted["count"].as_u64().unwrap(), 42);
        assert!(redacted["nested"]["token"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:TOKEN]"));
    }

    #[test]
    fn empty_string_is_safe() {
        assert_eq!(redact_str(""), "");
    }

    // MCP-1001: private-key PEM-block coverage. The pre-fix pattern only
    // matched RSA/EC/ED25519/generic forms; the OpenSSH (modern default
    // `ssh-keygen` output), DSA (legacy), Encrypted PKCS#8, and PGP
    // (BLOCK suffix) variants slipped through. A user pasting their SSH
    // private key into a workflow input or pasting an exported GPG key
    // for signing would have the body persist unredacted to module-
    // execution output, audit logs, and execution-event broadcasts.

    #[test]
    fn redacts_rsa_private_key_pem() {
        let pem =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        assert!(redact_str(pem).contains("[REDACTED:PRIVATE_KEY]"));
    }

    #[test]
    fn redacts_generic_pkcs8_private_key() {
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAA...\n-----END PRIVATE KEY-----";
        assert!(redact_str(pem).contains("[REDACTED:PRIVATE_KEY]"));
    }

    #[test]
    fn redacts_openssh_private_key_pem() {
        // Default ssh-keygen output since OpenSSH 7.8 (2018) — the
        // dominant SSH key format in the wild today.
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAA...\n-----END OPENSSH PRIVATE KEY-----";
        let result = redact_str(pem);
        assert!(
            result.contains("[REDACTED:PRIVATE_KEY]"),
            "OPENSSH PRIVATE KEY block must be redacted, got: {result}"
        );
    }

    #[test]
    fn redacts_dsa_private_key_pem() {
        let pem = "-----BEGIN DSA PRIVATE KEY-----\nMIIBuwIBAAKB...\n-----END DSA PRIVATE KEY-----";
        assert!(redact_str(pem).contains("[REDACTED:PRIVATE_KEY]"));
    }

    #[test]
    fn redacts_encrypted_pkcs8_private_key_pem() {
        let pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFLTBXBgkq...\n-----END ENCRYPTED PRIVATE KEY-----";
        assert!(redact_str(pem).contains("[REDACTED:PRIVATE_KEY]"));
    }

    #[test]
    fn redacts_pgp_private_key_block() {
        // The PGP variant uses the `BLOCK` suffix — distinct shape from
        // the X.509 family. Operators exporting GPG signing keys for use
        // in a workflow paste this format.
        let pem = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBGE2...\n-----END PGP PRIVATE KEY BLOCK-----";
        let result = redact_str(pem);
        assert!(
            result.contains("[REDACTED:PRIVATE_KEY]"),
            "PGP PRIVATE KEY BLOCK must be redacted, got: {result}"
        );
    }

    #[test]
    fn redacts_ec_private_key_pem() {
        let pem = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIA...\n-----END EC PRIVATE KEY-----";
        assert!(redact_str(pem).contains("[REDACTED:PRIVATE_KEY]"));
    }

    #[test]
    fn private_key_pattern_no_false_positive_on_public_key() {
        // The pattern must NOT eat public-key PEM blocks (operators
        // legitimately paste these in workflow configs for verification).
        let pubkey =
            "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEF...\n-----END PUBLIC KEY-----";
        let result = redact_str(pubkey);
        assert!(
            !result.contains("[REDACTED:PRIVATE_KEY]"),
            "PUBLIC KEY block must NOT be private-key-redacted, got: {result}"
        );
    }

    #[test]
    fn private_key_pattern_no_false_positive_on_certificate() {
        let cert =
            "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIE...\n-----END CERTIFICATE-----";
        let result = redact_str(cert);
        assert!(
            !result.contains("[REDACTED:PRIVATE_KEY]"),
            "CERTIFICATE block must NOT be private-key-redacted, got: {result}"
        );
    }

    #[test]
    fn passthrough_provider_returns_unchanged() {
        let svc = DlpService(std::sync::Arc::new(PassthroughDlpProvider));
        assert_eq!(svc.redact_str("123-45-6789"), "123-45-6789");
        let val = serde_json::json!({"ssn": "123-45-6789"});
        assert_eq!(svc.redact_json(&val), val);
    }

    #[test]
    fn builtin_provider_redacts_email_in_service() {
        let svc = DlpService(std::sync::Arc::new(BuiltinDlpProvider));
        let result = svc.redact_str("user@example.com");
        assert_eq!(result, "[REDACTED:EMAIL]");
    }

    // MCP-521: AWS Access Key ID redaction. The pre-fix pattern
    // required 6+ trailing chars after `A[KS]IA + 16`, so real
    // 20-char standalone keys passed unredacted. Each test below
    // covers a real exfiltration shape (env-file, terminal paste,
    // JSON output) for both long-term (AKIA) and STS-temporary
    // (ASIA) credential types.

    #[test]
    fn redacts_standalone_aws_access_key_id_akia() {
        // AWS docs canonical example: AKIAIOSFODNN7EXAMPLE
        let result = redact_str("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(
            result, "[REDACTED:AWS_ACCESS_KEY]",
            "20-char standalone AKIA key must be redacted, got: {result}"
        );
    }

    #[test]
    fn redacts_standalone_aws_access_key_id_asia() {
        // STS temporary credential, 20 chars starting with ASIA
        let result = redact_str("ASIAQ3EGRX5ZTKZN52E7");
        assert_eq!(
            result, "[REDACTED:AWS_ACCESS_KEY]",
            "20-char standalone ASIA key must be redacted, got: {result}"
        );
    }

    #[test]
    fn redacts_aws_key_in_env_file_shape() {
        // The exact shape an exfiltration finds: env var assignment
        // followed by the 20-char value with NO trailing chars.
        let inputs = [
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
            "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE",
            "aws_access_key_id: ASIAQ3EGRX5ZTKZN52E7",
        ];
        for input in &inputs {
            let result = redact_str(input);
            assert!(
                result.contains("[REDACTED:AWS_ACCESS_KEY]"),
                "AWS key in env-file shape must be redacted: {input} → {result}"
            );
            assert!(
                !result.contains("AKIAIOSFODNN7EXAMPLE")
                    && !result.contains("ASIAQ3EGRX5ZTKZN52E7"),
                "Redaction must strip the key literal, got: {result}"
            );
        }
    }

    #[test]
    fn redacts_aws_key_followed_by_comma_or_quote() {
        // JSON shape and quoted shape — both common in logs/configs
        for input in &[
            "{\"key\": \"AKIAIOSFODNN7EXAMPLE\"}",
            "AKIAIOSFODNN7EXAMPLE,other_field",
            "[AKIAIOSFODNN7EXAMPLE]",
        ] {
            let result = redact_str(input);
            assert!(
                result.contains("[REDACTED:AWS_ACCESS_KEY]"),
                "AWS key with trailing delimiter must redact: {input} → {result}"
            );
        }
    }

    #[test]
    fn aws_key_pattern_no_false_positive_on_unrelated_aroa_aida() {
        // AROA = IAM role identifier, AIDA = IAM user identifier.
        // These are 20-char resource IDs, NOT access keys, and live
        // freely in CloudTrail logs / IAM policy JSON. They MUST
        // pass through DLP unchanged so operators can correlate
        // identities in logs. The pattern anchors on AKIA/ASIA
        // specifically.
        for input in &[
            "AROAEXAMPLEID0000001",
            "AIDAEXAMPLEID0000001",
            // Other AWS resource ID prefixes that happen to be 20
            // chars and uppercase — must not match.
            "ANPAEXAMPLEID0000001", // managed policy
            "APKAEXAMPLEID0000001", // public key
        ] {
            let result = redact_str(input);
            assert!(
                !result.contains("[REDACTED:AWS_ACCESS_KEY]"),
                "non-access-key AWS resource ID must pass through, got: {input} → {result}"
            );
        }
    }

    #[test]
    fn aws_key_pattern_no_false_positive_on_short_or_long_strings() {
        // Short: 19 chars starting with AKIA — must not match
        let short = "AKIAIOSFODNN7EXAMPL"; // 19 chars
        assert!(
            !redact_str(short).contains("[REDACTED:AWS_ACCESS_KEY]"),
            "19-char AKIA-prefixed string must not match"
        );
        // Long: 21+ chars — word boundary stops the match; trailing
        // content stays present and the 20-char prefix matches the
        // pattern. The 21st char being a word char fails the \b
        // anchor, so the WHOLE thing should not match.
        let long = "AKIAIOSFODNN7EXAMPLEX"; // 21 chars
        let result = redact_str(long);
        assert!(
            !result.contains("[REDACTED:AWS_ACCESS_KEY]"),
            "21-char AKIA-prefixed string must not match (\\b anchor): {result}"
        );
    }

    // MCP-559: tripwire — confirm the default `redact_json` trait impl
    // bails at MAX_DLP_REDACT_DEPTH instead of stack-overflowing on a
    // pathologically deep input. Previously a 1 MB webhook payload of
    // `[[[[[...]]]]]` (~500k levels) would crash the controller for ALL
    // users via tokio worker thread stack exhaustion.
    #[test]
    fn redact_json_bails_on_deep_nesting() {
        // Build a Value tree with depth far past MAX_DLP_REDACT_DEPTH.
        // Use Array since it's the cheapest nesting shape per level
        // (one Value per Vec slot).
        let mut deep = Value::String("ssn 123-45-6789".to_string());
        for _ in 0..(super::MAX_DLP_REDACT_DEPTH + 50) {
            deep = Value::Array(vec![deep]);
        }
        // Should NOT panic. Use the public free function so the test
        // exercises the dispatch path operators rely on.
        let _redacted = redact_json(&deep);
        // Sanity: also verify shallow inputs still redact normally —
        // the depth gate didn't accidentally short-circuit the
        // happy path.
        let shallow = serde_json::json!({
            "ssn": "123-45-6789",
            "nested": { "card": "4111 1111 1111 1111" }
        });
        let out = redact_json(&shallow);
        let out_str = out.to_string();
        assert!(
            out_str.contains("[REDACTED:SSN]"),
            "shallow SSN should redact: {out_str}"
        );
        assert!(
            out_str.contains("[REDACTED:CARD]"),
            "shallow CARD should redact: {out_str}"
        );
    }

    // MCP-575: token-prefix gap fixes. Pre-fix the PATTERNS list only
    // matched ghp_ + ghs_ + xoxb-/xoxp- — missing GitHub OAuth (gho_),
    // user-to-server (ghu_), refresh (ghr_), Slack app-level (xoxa-),
    // Slack refresh (xoxr-), and Stripe restricted keys (rk_test_ /
    // rk_live_). These tests pin the new coverage so a future regex
    // refactor can't quietly drop a prefix.
    #[test]
    fn redacts_github_oauth_token() {
        let input = "Authorization: token gho_16C7e42F292c6912E7710c838347Ae178B4a";
        let result = redact_str(input);
        assert!(
            result.contains("[REDACTED:API_KEY]") || result.contains("[REDACTED:TOKEN]"),
            "GitHub OAuth gho_ token must redact: {result}"
        );
        assert!(
            !result.contains("16C7e42F292c6912E7710c838347Ae178B4a"),
            "token body must not leak through: {result}"
        );
    }

    #[test]
    fn redacts_github_user_to_server_token() {
        let input = "ghu_16C7e42F292c6912E7710c838347Ae178B4a";
        let result = redact_str(input);
        assert!(
            result.contains("[REDACTED:API_KEY]"),
            "GitHub ghu_ token must redact: {result}"
        );
    }

    #[test]
    fn redacts_github_refresh_token() {
        let input = "ghr_16C7e42F292c6912E7710c838347Ae178B4a";
        let result = redact_str(input);
        assert!(
            result.contains("[REDACTED:API_KEY]"),
            "GitHub ghr_ token must redact: {result}"
        );
    }

    #[test]
    fn redacts_slack_app_level_token() {
        let input = "xoxa-2-1234567890-ABCdefGHIjklMNOpqr";
        let result = redact_str(input);
        assert!(
            result.contains("[REDACTED:API_KEY]"),
            "Slack xoxa- token must redact: {result}"
        );
    }

    #[test]
    fn redacts_slack_socket_mode_app_token() {
        // `xapp-` is the Slack app-level token (Socket Mode) — distinct from the
        // `xoxa-` app config token above. It was the one prefix missing from the
        // Slack family in the redaction alternation.
        let input = "xapp-1-A01234567-1234567890-abcdefABCDEF1234567890";
        let result = redact_str(input);
        assert!(
            result.contains("[REDACTED:API_KEY]"),
            "Slack xapp- app-level token must redact: {result}"
        );
    }

    #[test]
    fn redacts_slack_refresh_token() {
        let input = "xoxr-1234567890-ABCdefGHIjkl";
        let result = redact_str(input);
        assert!(
            result.contains("[REDACTED:API_KEY]"),
            "Slack xoxr- token must redact: {result}"
        );
    }

    #[test]
    fn redacts_stripe_restricted_key() {
        let input = "rk_live_abcdefghijklmno";
        let result = redact_str(input);
        assert!(
            result.contains("[REDACTED:API_KEY]"),
            "Stripe rk_live_ restricted key must redact: {result}"
        );
        let input_test = "rk_test_abcdefghijklmno";
        let result_test = redact_str(input_test);
        assert!(
            result_test.contains("[REDACTED:API_KEY]"),
            "Stripe rk_test_ restricted key must redact: {result_test}"
        );
    }

    #[test]
    fn no_false_positive_on_words_starting_with_token_prefixes() {
        // The new prefixes are unlikely to collide with English words
        // (xoxa-/xoxr-/gho_/ghu_/ghr_/rk_live_/rk_test_ all have
        // distinctive separator chars), but verify nothing common
        // accidentally trips. "gho" by itself is not a real prefix
        // (no `_` separator) so it must pass.
        let input = "ghost story has nothing to do with API keys";
        let result = redact_str(input);
        assert_eq!(
            result, input,
            "non-token prefix substrings must not redact: {result}"
        );
    }

    #[test]
    fn redacts_huggingface_token() {
        // MCP-1134: `hf_` is Hugging Face's standard access-token
        // prefix (e.g. `hf_AbCdEfGhIjKlMnOpQrStUvWxYz123456`).
        let input = "hf_AbCdEfGhIjKlMnOpQrStUvWxYz123456";
        let result = redact_str(input);
        assert!(
            result.contains("[REDACTED:API_KEY]"),
            "Hugging Face hf_ token must redact: {result}"
        );
    }

    #[test]
    fn redacts_xai_token() {
        // MCP-1134: `xai-` is xAI / Grok's API-key prefix.
        let input = "xai-1234567890ABCDEFghijklmnop";
        let result = redact_str(input);
        assert!(
            result.contains("[REDACTED:API_KEY]"),
            "xAI xai- token must redact: {result}"
        );
    }

    #[test]
    fn no_false_positive_on_hf_or_xai_prefix_in_prose() {
        // `xai` and `hf` by themselves (no separator) must not redact.
        // The pattern requires `hf_` (with underscore) or `xai-`
        // (with dash) so prose like "hf is a great library" passes.
        let input = "hf is short for Hugging Face; xai is the company";
        let result = redact_str(input);
        assert_eq!(
            result, input,
            "non-token prefix substrings must not redact: {result}"
        );
    }

    #[test]
    fn redact_json_bounded_passes_through_small_payloads() {
        // MCP-1197: small structured payloads (the common case) should
        // be redacted and returned. 1 KiB is well under the 1 MiB cap.
        let input = serde_json::json!({
            "channel_id": "abc-123",
            "old_token": "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        });
        let result = redact_json_bounded(&input).expect("under cap should return Some");
        let s = serde_json::to_string(&result).expect("serialise");
        assert!(
            s.contains("[REDACTED"),
            "secrets must still be redacted: {s}"
        );
        assert!(s.contains("abc-123"), "non-secret fields preserved: {s}");
    }

    #[test]
    fn redact_json_bounded_drops_oversized_payloads() {
        // MCP-1197: a metadata blob over 1 MiB must drop to None so the
        // audit log column gets NULL (load-shedding), and the structured
        // warn fires for operator visibility.
        let huge = "x".repeat(MAX_LOG_METADATA_BYTES + 1);
        let input = serde_json::json!({ "padding": huge });
        let result = redact_json_bounded(&input);
        assert!(result.is_none(), "over-cap payload must drop to None");
    }

    #[test]
    fn redact_json_bounded_accepts_exactly_at_cap() {
        // Boundary check: payload whose serialised form fits in 1 MiB
        // exactly must still pass through. The size check uses `>`, not
        // `>=`, so an at-cap payload survives.
        let padding_size = MAX_LOG_METADATA_BYTES - 32;
        let huge = "x".repeat(padding_size);
        let input = serde_json::json!({ "p": huge });
        let serialized_len = serde_json::to_string(&input).unwrap().len();
        assert!(
            serialized_len <= MAX_LOG_METADATA_BYTES,
            "test fixture must fit under cap: {serialized_len}"
        );
        assert!(
            redact_json_bounded(&input).is_some(),
            "under-cap payload must pass through"
        );
    }

    #[test]
    fn bound_execution_payload_passes_small_value_as_borrowed() {
        // MCP-1204/1205: typical workflow input/output (small structured
        // JSON) must pass through as Cow::Borrowed — zero clone cost.
        let v = serde_json::json!({ "trigger": "manual", "rows": 100 });
        let bounded = bound_execution_payload(&v);
        assert!(matches!(bounded, std::borrow::Cow::Borrowed(_)));
        assert_eq!(&*bounded, &v);
    }

    #[test]
    fn bound_execution_payload_substitutes_sentinel_on_over_cap() {
        // MCP-1204/1205: payloads above 10 MiB collapse to a sentinel
        // object so persistence-completion semantics survive (consumers
        // still get valid JSON) while the heap pressure is bounded.
        let huge = "x".repeat(MAX_EXECUTION_PAYLOAD_BYTES + 1024);
        let v = serde_json::json!({ "leak": huge });
        let bounded = bound_execution_payload(&v);
        let owned = match bounded {
            std::borrow::Cow::Owned(v) => v,
            std::borrow::Cow::Borrowed(_) => panic!("over-cap must own"),
        };
        assert_eq!(owned["_truncated"], serde_json::json!(true));
        let original_size = owned["_original_size_bytes"]
            .as_u64()
            .expect("size present");
        assert!(
            original_size > MAX_EXECUTION_PAYLOAD_BYTES as u64,
            "size must exceed cap: {original_size}"
        );
        assert!(
            owned["_reason"]
                .as_str()
                .map(|s| s.contains("10 MiB"))
                .unwrap_or(false),
            "reason must mention the cap"
        );
    }

    #[test]
    fn bound_execution_payload_at_cap_passes_through() {
        // Boundary: payload at exactly MAX_EXECUTION_PAYLOAD_BYTES must
        // pass (the size check uses `>`, not `>=`).
        let target = MAX_EXECUTION_PAYLOAD_BYTES - 32;
        let v = serde_json::json!({ "p": "x".repeat(target) });
        let serialized_len = serde_json::to_string(&v).unwrap().len();
        assert!(
            serialized_len <= MAX_EXECUTION_PAYLOAD_BYTES,
            "fixture must fit under cap: {serialized_len}"
        );
        let bounded = bound_execution_payload(&v);
        assert!(matches!(bounded, std::borrow::Cow::Borrowed(_)));
    }
}
