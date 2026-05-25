//! Shared job protocol between Controller and Workers.
//!
//! Security model:
//! - Secrets are AES-256-GCM encrypted before transmission over NATS.
//! - Every JobRequest is HMAC-SHA256 signed using a pre-shared key
//!   (WORKER_SHARED_KEY) to prevent injection of malicious jobs.
//! - A `job_nonce` (timestamp + random hex) is included to prevent replay attacks.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hmac::{Hmac, Mac};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Maximum future-skew tolerance for nonce timestamps (seconds).
///
/// Controller and worker sit on the same NATS cluster and should be
/// within a few seconds via NTP. A larger tolerance would extend the
/// effective replay window (a future-dated signature stays valid for
/// `FUTURE_SKEW + max_age_secs` total). A 5 s ≈ 5000 ms asymmetric
/// window is a common choice for signed-NATS RPC.
const MAX_FUTURE_SKEW_SECS: u64 = 5;

// ============================================================================
// Verifier role marker (L-4, 2026-05-22)
// ============================================================================
//
// Pre-r300/r301 the controller had two consumers of every JobResult —
// the primary inline dispatcher AND a background audit subscriber —
// and BOTH called `verify()`, which inserts the result nonce into the
// process-local `JOB_NONCE_CACHE`. The second verifier always lost
// the race with "result_nonce already seen", failing every workflow.
// The fix was twofold: (a) the worker single-publishes each result
// to one subject; (b) the split `verify` / `verify_no_replay` API.
//
// `verify` / `verify_no_replay` are still correct, but the choice
// between them is encoded only in the method name — a future caller
// can grep for one and copy-paste it into the wrong role. The
// `Verifier` enum forces the caller to declare intent at the type
// level, and `verify_as` dispatches on it. New code should prefer
// this API; the bare `verify` / `verify_no_replay` are kept for
// existing callers and tests.

/// L-4 marker that selects which verification flavour a caller wants.
///
/// Declaring intent at the type level prevents the regression class
/// behind the r300 incident: an audit subscriber accidentally calling
/// `verify()` instead of `verify_no_replay()` and racing the primary
/// verifier into "result_nonce already seen" errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verifier {
    /// **Primary** verifier: the single inline consumer that converts
    /// the signed result into a durable side effect (DB write, reply
    /// to a NATS request inbox, return to a webhook caller). Records
    /// the nonce in the process-local replay cache so the same
    /// signed result cannot be applied twice. There must be EXACTLY
    /// ONE primary verifier per result per controller process.
    Primary,
    /// **Observer** verifier: a passive consumer (audit subscriber,
    /// metrics emitter) whose only side effect is idempotent under
    /// replay. HMAC + freshness are checked; the nonce is NOT
    /// inserted into the replay cache. Use this whenever the same
    /// signed result might reach another consumer that already runs
    /// as the [`Primary`](Self::Primary).
    Observer,
}

// ============================================================================
// Replay-resistant nonce cache (single-use within freshness window)
// ============================================================================
//
// The freshness check on its own (now - ts <= max_age_secs) is necessary
// but not sufficient — within that window, an attacker who captures a
// signed JobRequest from NATS can replay it any number of times. The
// nonce cache turns that into a single-use guarantee: each (nonce, ts)
// pair is admitted exactly once; subsequent attempts return a "replay
// detected" error.
//
// Implementation: std-only (`Mutex<HashMap<String, u64>>`) keyed on the
// nonce string with the timestamp as value. On each insert we sweep
// entries older than `2 × max_age_secs` (some slack for clock skew),
// which keeps memory bounded at `rate × 2 × max_age_secs`. With
// max_age_secs = 300 and 100 verify/sec that's ~60k entries — small.
// A hard cap of 200k entries triggers a more aggressive sweep under
// abnormal load to keep the worker from OOMing.
//
// Workspace consistency: this mirrors the two-generation pattern in
// `talos-memory::rpc_auth` but uses a single Mutex<HashMap> rather than
// rotating DashMaps because (a) this crate is published to crates.io
// and we don't want to add `dashmap` + `arc-swap` as required deps,
// and (b) under realistic load (sub-millisecond Mutex contention) the
// simpler form is performant enough. Revisit if profiling shows the
// Mutex becoming a hot spot.

const NONCE_CACHE_HARD_CAP: usize = 200_000;

struct JobNonceCache {
    seen: std::sync::Mutex<HashMap<String, u64>>,
}

impl JobNonceCache {
    fn new() -> Self {
        Self {
            seen: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` if the nonce is fresh (and atomically records it),
    /// `false` if it's a replay within the freshness window.
    fn check_and_record(&self, nonce: &str, ts: u64, max_age_secs: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(ts);
        // Poison-tolerant: rebuild the lock state on poison rather than
        // hard-failing every subsequent call. A poisoned mutex here only
        // means a previous panic happened mid-update; the data itself is
        // a HashMap that's safe to keep using.
        let mut g = match self.seen.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Sweep entries older than 2× max_age_secs. The 2× slack absorbs
        // clock skew and avoids an admitting-then-rejecting race when
        // (now, ts) straddle the boundary.
        let cutoff = now.saturating_sub(max_age_secs.saturating_mul(2));
        if g.len() > 1024 {
            // Skip the sweep at small sizes — pure overhead. Above 1k
            // entries it's worth it.
            g.retain(|_, t| *t > cutoff);
        }
        if g.contains_key(nonce) {
            return false;
        }
        // Hard cap: if rate × 2× max_age_secs exceeds 200k entries,
        // we're under abnormal load (or a flood). Drop everything older
        // than the strict freshness window to free space.
        if g.len() >= NONCE_CACHE_HARD_CAP {
            let aggressive_cutoff = now.saturating_sub(max_age_secs);
            g.retain(|_, t| *t > aggressive_cutoff);
        }
        g.insert(nonce.to_string(), ts);
        true
    }
}

static JOB_NONCE_CACHE: std::sync::LazyLock<JobNonceCache> =
    std::sync::LazyLock::new(JobNonceCache::new);

/// Check whether `nonce` (with stamped timestamp `ts`) has been seen
/// within the freshness window. Returns `true` on first observation
/// (and atomically records it), `false` on replay. Used by every
/// `verify()` impl in this crate after HMAC verification succeeds.
fn check_and_record_job_nonce(nonce: &str, ts: u64, max_age_secs: u64) -> bool {
    JOB_NONCE_CACHE.check_and_record(nonce, ts, max_age_secs)
}

/// Current entry count of the process-local job-nonce replay cache.
///
/// Surfaced for `/health` / metrics endpoints so operators can correlate
/// "approaching `NONCE_CACHE_HARD_CAP`" (200k) with upstream traffic
/// rate. Sustained near-cap usage suggests either legitimate high
/// throughput (raise the cap) or a replay flood (gate at the NATS
/// subject level upstream).
///
/// Reading the cache size takes the same mutex as
/// `check_and_record_job_nonce`. The lock is held only long enough to
/// call `.len()`; the contention impact at typical query rates is
/// negligible (microseconds).
///
/// Returns `0` if the cache lock is currently poisoned (which only
/// happens if a previous panic occurred mid-mutation). The
/// `check_and_record` path itself is poison-tolerant so the cache
/// remains functional — this accessor errs on the side of "0" rather
/// than panic-on-read.
pub fn job_nonce_cache_size() -> usize {
    JOB_NONCE_CACHE
        .seen
        .lock()
        .map(|g| g.len())
        .unwrap_or(0)
}

/// Maximum length of a `worker_id` in bytes. Pod names and host names
/// in practice fit well under 64 bytes (Kubernetes' RFC-1123 label cap
/// is 63 chars); 128 leaves slack for synthetic prefixes/suffixes.
pub const MAX_WORKER_ID_LEN: usize = 128;

/// Validate a self-reported worker identity before binding it into a
/// HMAC-signed result. The charset (`A-Z`, `a-z`, `0-9`, `.`, `-`, `_`)
/// is restricted so the colon-delimited signing-payload format stays
/// unambiguous — without this, a worker_id containing `:` could shift
/// the field boundary and let the same HMAC verify under a different
/// interpretation of the payload.
///
/// An empty `worker_id` is permitted (the back-compat `sign()` wrapper
/// passes the empty string) and renders as `""` in the signing payload.
/// Production worker code is expected to supply a non-empty value.
pub fn validate_worker_id(worker_id: &str) -> Result<(), String> {
    if worker_id.len() > MAX_WORKER_ID_LEN {
        return Err(format!(
            "worker_id too long: {} bytes (max {MAX_WORKER_ID_LEN})",
            worker_id.len()
        ));
    }
    if !worker_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err(
            "worker_id contains invalid chars (allowed: A-Z a-z 0-9 . - _)".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod worker_id_validation_tests {
    use super::validate_worker_id;

    #[test]
    fn accepts_empty() {
        validate_worker_id("").unwrap();
    }

    #[test]
    fn accepts_typical_pod_name() {
        validate_worker_id("talos-worker-abc-12345").unwrap();
    }

    #[test]
    fn accepts_uuid_style() {
        validate_worker_id("ab12cd34-ef56-7890-1234-567890abcdef").unwrap();
    }

    #[test]
    fn rejects_colon() {
        // The signing payload is colon-delimited; embedded `:` would
        // shift the field boundary.
        assert!(validate_worker_id("worker:1").is_err());
    }

    #[test]
    fn rejects_whitespace() {
        assert!(validate_worker_id("worker 1").is_err());
        assert!(validate_worker_id("worker\n1").is_err());
    }

    #[test]
    fn rejects_null_byte() {
        assert!(validate_worker_id("worker\0").is_err());
    }

    #[test]
    fn rejects_overlong() {
        let big = "a".repeat(super::MAX_WORKER_ID_LEN + 1);
        assert!(validate_worker_id(&big).is_err());
    }

    #[test]
    fn accepts_max_length() {
        let max = "a".repeat(super::MAX_WORKER_ID_LEN);
        validate_worker_id(&max).unwrap();
    }
}

/// Hard cap for the job-nonce replay cache.
///
/// Exposed so health endpoints can report the headroom (`size / cap`)
/// alongside the raw size. The constant lives in this crate to keep a
/// single source of truth.
pub const JOB_NONCE_CACHE_CAPACITY: usize = NONCE_CACHE_HARD_CAP;

#[cfg(test)]
#[allow(dead_code)] // helper for future tests that exercise replay protection
fn clear_job_nonce_cache_for_test() {
    if let Ok(mut g) = JOB_NONCE_CACHE.seen.lock() {
        g.clear();
    }
}

fn default_priority() -> u8 {
    100
}

// ============================================================================
// Reserved host vault paths — LLM provider API keys
// ============================================================================
//
// These paths name the canonical LLM provider API keys that the controller
// pre-fetches into every worker job's secrets map so the host-side `llm::*`
// functions can resolve them. THE LIST HAS SECURITY IMPLICATIONS:
//
// - Controller-side (`engine::parallel::prefetch_llm_vault_keys` +
//   `secrets::SecretsManager::get_llm_vault_keys`): every job gets a snapshot
//   of these paths injected so LLM host calls can find them without the
//   module declaring them in `allowed_secrets`.
// - Worker-side (`host_impl::check_secret_allowlist`): guest-reachable
//   secret resolution MUST deny these paths even when a module has
//   `allowed_secrets: ["*"]` — otherwise a wildcard-grant module could
//   exfiltrate the user's LLM API keys via `secrets::get_secret` or a
//   `vault://anthropic/api_key` header interpolation.
//
// The list lives here, not per-crate, so adding a provider happens in one
// place and the controller prefetch + cache-invalidation + worker deny-list
// stay in lockstep. If you're adding a new provider (say, Mistral), update
// this constant and the corresponding branch in `worker::host_impl::llm_key_lookup_paths`.
//
// Rules for the list:
// - Entries are literal, case-sensitive vault paths.
// - The worker does a case-sensitive exact match; casing/prefix games can't
//   bypass the deny-list.
// - Add only paths that are genuinely host-only. User-facing secrets
//   (OAuth tokens, per-integration keys) do NOT belong here.
pub const LLM_PROVIDER_VAULT_PATHS: &[&str] =
    &["anthropic/api_key", "openai/api_key", "gemini/api_key"];

/// True iff `path` is one of the canonical LLM provider vault paths that
/// are reserved for host-internal consumption. Consumers use this as:
/// - worker: deny `secrets::get_secret` from returning these to WASM
/// - controller: trigger cache invalidation when the key is rotated
pub fn is_llm_provider_vault_path(path: &str) -> bool {
    LLM_PROVIDER_VAULT_PATHS.contains(&path)
}

/// Re-export so controller + worker can `use talos_workflow_job_protocol::LlmTier`
/// without pulling engine-core directly. The underlying type lives in
/// engine-core because `DispatchJob` carries it through the dispatch
/// pipeline and engine-core sits below job-protocol in the dep graph.
pub use talos_workflow_engine_core::LlmTier;

/// Map a provider name (case-insensitive) to its data-egress tier.
/// Anthropic / OpenAI / Gemini = Tier 2 (external). Ollama = Tier 1
/// (local). Unknown providers default to Tier 2 (treat as external
/// until proven local) — fail-closed against future providers that
/// haven't been classified yet.
pub fn provider_tier(provider_name: &str) -> LlmTier {
    // The explicit Tier2 arm is intentional: it documents which
    // providers we have classified. Unknown providers also fall
    // through to Tier2 (fail-closed against unclassified entries).
    // Removing the explicit arm would lose that documentation.
    #[allow(clippy::match_same_arms)]
    match provider_name.to_ascii_lowercase().as_str() {
        "ollama" => LlmTier::Tier1,
        "anthropic" | "openai" | "gemini" => LlmTier::Tier2,
        _ => LlmTier::Tier2,
    }
}

/// DNS hostnames that belong to external LLM providers. Tier-1 actors
/// must not be allowed to reach these even via the generic
/// `wit_http::fetch` host function — otherwise the `llm::*`-level
/// refusal is trivially bypassed by a guest that writes its own
/// `POST https://api.anthropic.com/v1/messages` + `vault://anthropic/api_key`
/// header.
///
/// Matching is case-insensitive exact-match on the host portion of
/// the URL + suffix match to catch region-specific subdomains (e.g.
/// `generativelanguage.googleapis.com` → also `*.generativelanguage.googleapis.com`).
///
/// Extend this list whenever `LLM_PROVIDER_VAULT_PATHS` grows; the
/// two are parallel (vault-path side deny-lists the key, host-side
/// deny-lists the destination).
pub const EXTERNAL_LLM_HOSTS: &[&str] = &[
    // Anthropic — API endpoint.
    "api.anthropic.com",
    // OpenAI — primary + Azure mirror.
    "api.openai.com",
    // Google Gemini — current + legacy names.
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
];

/// True iff `host` (already lowercased) matches one of the reserved
/// external LLM hostnames. Uses exact + suffix match so region
/// subdomains (`eu.api.openai.com`) also trigger.
///
/// **Trailing-dot normalisation.** `url::Url::parse("https://api.anthropic.com./...")`
/// returns `"api.anthropic.com."` (the FQDN trailing dot is preserved per
/// RFC 1738 / RFC 3986). DNS resolution treats the trailing dot as
/// equivalent to the dotless form — the same A/AAAA record is returned —
/// so leaving the deny-list strict would let a guest reach
/// `api.anthropic.com.` while the matcher silently passed. We strip the
/// trailing dot defensively at the matcher entry so every one of the five
/// worker enforcement surfaces (`fetch`, `fetch_all`, `graphql::execute`,
/// `webhook::send`, `http_stream::connect`) inherits the fix from one
/// place. Repeating the strip at every call site would be brittle.
pub fn is_external_llm_host(host_lower: &str) -> bool {
    // Defense in depth — callers are documented to pass an already-lowercased
    // host but we normalise here too: an upstream regression that forwards a
    // mixed-case or trailing-dot value shouldn't silently bypass the gate.
    let normalised = host_lower
        .trim_end_matches('.')
        .to_ascii_lowercase();
    EXTERNAL_LLM_HOSTS
        .iter()
        .any(|reserved| *reserved == normalised || normalised.ends_with(&format!(".{reserved}")))
}

/// True iff `vault_path` references a Tier-2 LLM provider's credentials.
/// Used to block `vault://anthropic/api_key` substitution in HTTP headers
/// for Tier-1 jobs — the tier gate on `llm::*` host fns doesn't help if
/// the guest fetches directly and interpolates the key through
/// `resolve_vault_header`.
pub fn is_tier2_llm_vault_path(vault_path: &str) -> bool {
    is_llm_provider_vault_path(vault_path)
}

/// Postgres function names that WASM modules must never invoke from
/// `database::execute_query`. Canonical single-source-of-truth for both
/// the worker (`worker::sql_validator`) and the controller's database-RPC
/// re-parse path (`talos-rpc-subscribers`).
///
/// **Why a function deny-list is needed.** The statement-level deny-list
/// blocks `COPY`, `SET ROLE`, `PREPARE`, etc. — but a benign-looking
/// `SELECT pg_read_server_files('/etc/passwd')` parses as a Query and
/// passes every other gate. The validator must walk `Expr::Function`
/// nodes inside SELECT bodies and refuse any whose unqualified name (or
/// `pg_catalog.*` qualified form) appears below.
///
/// **Three risk classes:**
///
/// 1. **Filesystem read.** `pg_read_server_files` / `pg_read_file` /
///    `pg_read_binary_file` / `pg_ls_dir` / `pg_stat_file` /
///    `pg_ls_logdir` / `pg_ls_waldir` / `pg_ls_archive_statusdir` /
///    `pg_ls_tmpdir` — read arbitrary files on the database host. The
///    `talos_guest` role wrap (M-2) revokes EXECUTE where possible, but
///    PUBLIC keeps the default grant on many of these in stock
///    PostgreSQL — relying on the role alone is fragile. Block AST-side
///    for defense in depth.
///
/// 2. **Sleep / budget burn.** `pg_sleep` / `pg_sleep_for` /
///    `pg_sleep_until` — consume the full `statement_timeout` (60 s
///    default) without releasing the controller-side semaphore permit
///    (`MAX_IN_FLIGHT = 8`). 8 concurrent sleeping queries from a
///    malicious actor stalls every other actor's DB RPC for the
///    timeout window. Combined with the 500 queries-per-execution
///    cap, the validator catches the DoS vector at parse time.
///
/// 3. **Backend / config manipulation.** `pg_terminate_backend` /
///    `pg_cancel_backend` — kill arbitrary Postgres sessions belonging
///    to other tenants. `pg_reload_conf` / `pg_rotate_logfile` —
///    operator-only maintenance ops. `lo_import` / `lo_export` —
///    large-object FS I/O (the LO equivalent of `COPY FROM/TO`).
///
/// **Match rules:**
///
/// - Case-insensitive (Postgres normalises identifier case to lower for
///   unquoted identifiers; `PG_SLEEP(1)` is the same call as `pg_sleep(1)`).
/// - Matches both bare (`pg_sleep`) and schema-qualified (`pg_catalog.pg_sleep`)
///   forms — the visitor handles the schema strip before consulting this
///   list.
/// - Does NOT match user-defined functions with the same name. User code
///   that defines a `public.pg_sleep` is a footgun on its own (search_path
///   shadowing) and the validator can't disambiguate from the AST alone;
///   the role-wrap (M-2) is the fence for that case.
///
/// **Extending the list.** Adding a new entry requires updating both the
/// worker tests (`worker/src/sql_validator.rs`) and the controller-side
/// mirror tests (`talos-rpc-subscribers`). The deliberate-duplication
/// comment in the subscriber documents why both sides exist.
pub const DISALLOWED_SQL_FUNCTIONS: &[&str] = &[
    // ── Filesystem read ─────────────────────────────────────────────────
    "pg_read_server_files",
    "pg_read_file",
    "pg_read_binary_file",
    "pg_ls_dir",
    "pg_stat_file",
    "pg_ls_logdir",
    "pg_ls_waldir",
    "pg_ls_archive_statusdir",
    "pg_ls_tmpdir",
    // ── Sleep / budget burn ─────────────────────────────────────────────
    "pg_sleep",
    "pg_sleep_for",
    "pg_sleep_until",
    // ── Backend control ─────────────────────────────────────────────────
    "pg_terminate_backend",
    "pg_cancel_backend",
    // ── Config / maintenance ────────────────────────────────────────────
    "pg_reload_conf",
    "pg_rotate_logfile",
    "pg_promote",
    // ── Large object FS I/O (lo_import / lo_export) ─────────────────────
    "lo_import",
    "lo_export",
    // ── dblink — bypass network egress controls via PG-side connection ──
    "dblink",
    "dblink_exec",
    "dblink_connect",
    "dblink_send_query",
    "dblink_open",
    // ── PL/perl / PL/python untrusted variants — RCE via stored proc ────
    // These are typically not installed but if they ARE installed in the
    // operator's cluster, calling them from guest SQL is RCE.
    "plperlu_call_handler",
    "plpythonu_call_handler",
    "plpython3u_call_handler",
];

/// True iff `name` (case-insensitive, schema component already stripped)
/// appears in [`DISALLOWED_SQL_FUNCTIONS`]. The schema strip is the
/// caller's responsibility — the AST visitor walks `ObjectName` and
/// passes the trailing identifier here, also re-checking the `pg_catalog`
/// qualified form because user code may write `pg_catalog.pg_sleep` to
/// bypass search-path tricks.
///
/// Constant-time match isn't needed — function names are not secrets and
/// the entire deny-list is public. The linear scan over ~25 short strings
/// is faster than the hash-table setup cost.
pub fn is_disallowed_sql_function(name: &str) -> bool {
    // Lowercase comparison. PG normalises unquoted identifiers to lower
    // at parse time, but sqlparser preserves the original case so we
    // normalise here for the comparison.
    let lower = name.to_ascii_lowercase();
    DISALLOWED_SQL_FUNCTIONS
        .iter()
        .any(|denied| *denied == lower.as_str())
}

/// True iff `path` is consumed by a controller-internal subsystem (LLM
/// client cache, OAuth refresh loop) rather than by any WASM module's
/// `allowed_secrets` grant. Used by the orphaned-secrets hygiene check
/// to suppress false positives — these paths are by-design absent from
/// every module's grant list.
///
/// Recognized patterns:
/// - LLM provider keys: every entry of [`LLM_PROVIDER_VAULT_PATHS`]
/// - OAuth refresh tokens:
///   `oauth/<provider>/<user_id>/<provider_key>/refresh_token`.
///   Access tokens are NOT considered host-internal because workflow
///   modules legitimately read them via `vault://` in node config.
///
/// Hygiene checks must use this rather than `is_llm_provider_vault_path`
/// alone — flagging an OAuth refresh_token as orphan would suggest an
/// operator delete it, silently breaking the next refresh cycle.
pub fn is_controller_internal_vault_path(path: &str) -> bool {
    if is_llm_provider_vault_path(path) {
        return true;
    }
    // Defensive: refuse to match shapes like "oauth/refresh_token" that
    // lack the {provider}/{user}/{key} segments — those wouldn't be
    // produced by the canonical refresh_token_path() builder, so they'd
    // be a genuine orphan worth surfacing.
    if let Some(rest) = path.strip_prefix("oauth/") {
        if let Some(prefix) = rest.strip_suffix("/refresh_token") {
            // Require at least three intermediate segments (provider /
            // user_id / provider_key) before the refresh_token suffix.
            if prefix.split('/').filter(|s| !s.is_empty()).count() >= 3 {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod llm_provider_path_tests {
    use super::{
        is_controller_internal_vault_path, is_llm_provider_vault_path, LLM_PROVIDER_VAULT_PATHS,
    };

    #[test]
    fn canonical_paths_are_recognised() {
        for p in LLM_PROVIDER_VAULT_PATHS {
            assert!(
                is_llm_provider_vault_path(p),
                "canonical path {} not recognised",
                p
            );
        }
    }

    #[test]
    fn non_llm_paths_are_not_recognised() {
        assert!(!is_llm_provider_vault_path(""));
        assert!(!is_llm_provider_vault_path("github/pat"));
        assert!(!is_llm_provider_vault_path("oauth/gmail/access_token"));
    }

    #[test]
    fn casing_and_nesting_do_not_bypass() {
        // Case-sensitive exact match only — attackers can't wrap the path
        // in a subpath or alter casing to bypass.
        assert!(!is_llm_provider_vault_path("ANTHROPIC/API_KEY"));
        assert!(!is_llm_provider_vault_path("anthropic/api_key/child"));
        assert!(!is_llm_provider_vault_path("prefix/anthropic/api_key"));
    }

    #[test]
    fn controller_internal_recognises_llm_keys() {
        for p in LLM_PROVIDER_VAULT_PATHS {
            assert!(is_controller_internal_vault_path(p));
        }
    }

    #[test]
    fn controller_internal_recognises_oauth_refresh_tokens() {
        // Canonical shape from oauth/credentials.rs::refresh_token_path:
        // oauth/{provider}/{user_id}/{provider_key}/refresh_token
        assert!(is_controller_internal_vault_path(
            "oauth/google_calendar/1a361562-e551-41aa-9cb4-6f8988b035f7/primary/refresh_token"
        ));
        assert!(is_controller_internal_vault_path(
            "oauth/atlassian/abc123/site/refresh_token"
        ));
    }

    #[test]
    fn controller_internal_rejects_oauth_access_tokens() {
        // Access tokens are consumed by sandbox modules via vault:// in node
        // config (e.g. pa-meeting-fetch). Including them would suppress
        // legitimate orphan warnings.
        assert!(!is_controller_internal_vault_path(
            "oauth/google_calendar/1a361562-e551-41aa-9cb4-6f8988b035f7/primary/access_token"
        ));
    }

    #[test]
    fn controller_internal_rejects_malformed_oauth_paths() {
        // Missing intermediate segments — these wouldn't be produced by the
        // canonical builder, so they're genuine orphans worth surfacing.
        assert!(!is_controller_internal_vault_path("oauth/refresh_token"));
        assert!(!is_controller_internal_vault_path(
            "oauth/provider/refresh_token"
        ));
        assert!(!is_controller_internal_vault_path(
            "oauth/provider/user/refresh_token"
        ));
        // Wrong prefix.
        assert!(!is_controller_internal_vault_path(
            "auth/google/user/key/refresh_token"
        ));
        // Misleading suffix.
        assert!(!is_controller_internal_vault_path(
            "oauth/google/user/key/refresh_token_backup"
        ));
    }

    #[test]
    fn controller_internal_rejects_unrelated_paths() {
        assert!(!is_controller_internal_vault_path(""));
        assert!(!is_controller_internal_vault_path("github/pat"));
        assert!(!is_controller_internal_vault_path("custom/secret"));
    }
}

// ============================================================================
// Wasm-security review 2026-05-23: is_external_llm_host normalisation tests
// ============================================================================
//
// Threat model. The five worker call sites that gate Tier-1 LLM egress —
// `wit_http::fetch` / `fetch_all`, `wit_graphql::execute`,
// `wit_webhook::send`, `wit_http_stream::connect` — feed `host_str()` from a
// `url::Url` into `is_external_llm_host`. `url::Url::parse` preserves the
// trailing dot on an FQDN, so a Tier-1 actor could write
// `https://api.anthropic.com./v1/messages` and the strict equality check
// would silently pass: DNS resolves the trailing-dot form to the same
// record. These tests pin the defensive normalisation at the matcher entry.
#[cfg(test)]
mod external_llm_host_normalisation_tests {
    use super::is_external_llm_host;

    #[test]
    fn bare_host_matches() {
        assert!(is_external_llm_host("api.anthropic.com"));
        assert!(is_external_llm_host("api.openai.com"));
        assert!(is_external_llm_host("generativelanguage.googleapis.com"));
    }

    #[test]
    fn trailing_dot_does_not_bypass() {
        // The exploit shape: `https://api.anthropic.com./v1/messages` —
        // `url::Url::host_str()` returns the trailing-dot form. Pre-fix the
        // matcher returned false; post-fix the strip normalises before
        // compare.
        assert!(is_external_llm_host("api.anthropic.com."));
        assert!(is_external_llm_host("api.openai.com."));
        assert!(is_external_llm_host("generativelanguage.googleapis.com."));
    }

    #[test]
    fn trailing_dot_on_subdomain_does_not_bypass() {
        // Suffix-match limb must also normalise — region subdomains are
        // the documented suffix-match motivator.
        assert!(is_external_llm_host("eu.api.openai.com."));
        assert!(is_external_llm_host("us-east-1.api.anthropic.com."));
    }

    #[test]
    fn mixed_case_does_not_bypass() {
        // Documented as caller-responsibility, but defense-in-depth at the
        // matcher entry guards against an upstream regression that forgets
        // to lowercase. The normalisation must apply BOTH lowercasing AND
        // trailing-dot strip — neither alone is sufficient.
        assert!(is_external_llm_host("API.ANTHROPIC.COM"));
        assert!(is_external_llm_host("API.ANTHROPIC.COM."));
        assert!(is_external_llm_host("Eu.Api.OpenAI.com."));
    }

    #[test]
    fn unrelated_hosts_still_do_not_match() {
        // Negative path — the strip must not be so aggressive that it
        // matches dot-suffixed lookalikes.
        assert!(!is_external_llm_host("example.com"));
        assert!(!is_external_llm_host("example.com."));
        assert!(!is_external_llm_host("anthropic.com")); // bare apex is NOT in deny list
        assert!(!is_external_llm_host("badanthropic.com."));
        assert!(!is_external_llm_host("api.anthropic.com.attacker.example"));
    }

    #[test]
    fn empty_and_dot_only_do_not_match() {
        // Edge cases that the trim could theoretically corrupt — confirm
        // they remain non-matches.
        assert!(!is_external_llm_host(""));
        assert!(!is_external_llm_host("."));
        assert!(!is_external_llm_host(".."));
    }
}

// ============================================================================
// Wasm-security review 2026-05-22 (MEDIUM-1): SQL function deny-list tests
// ============================================================================
#[cfg(test)]
mod disallowed_sql_function_tests {
    use super::{is_disallowed_sql_function, DISALLOWED_SQL_FUNCTIONS};

    #[test]
    fn every_canonical_entry_is_matched() {
        // Tripwire: if the const and the matcher ever drift the matcher
        // would silently miss entries the operator THOUGHT were blocked.
        for f in DISALLOWED_SQL_FUNCTIONS {
            assert!(
                is_disallowed_sql_function(f),
                "canonical deny-list entry `{f}` is not matched by is_disallowed_sql_function"
            );
        }
    }

    #[test]
    fn match_is_case_insensitive() {
        // PG normalises unquoted identifiers to lower; `PG_SLEEP(1)`,
        // `Pg_Sleep(1)`, and `pg_sleep(1)` are the same call. The
        // sqlparser AST may preserve original case, so the matcher
        // must normalise.
        assert!(is_disallowed_sql_function("PG_SLEEP"));
        assert!(is_disallowed_sql_function("Pg_Sleep"));
        assert!(is_disallowed_sql_function("pg_sleep"));
        assert!(is_disallowed_sql_function("PG_READ_SERVER_FILES"));
        assert!(is_disallowed_sql_function("LO_IMPORT"));
    }

    #[test]
    fn unrelated_function_names_not_matched() {
        // Tripwire against an overly-broad refactor (e.g. switching to
        // a `starts_with("pg_")` check that would block legitimate
        // user functions like `pg_my_custom_func`).
        for f in [
            "count",
            "sum",
            "now",
            "current_user",
            "json_agg",
            "row_number",
            "version", // Note: version() is allowed (read-only info)
            "pg_typeof", // diagnostic, no escalation
            "pg_my_custom_business_func",
        ] {
            assert!(
                !is_disallowed_sql_function(f),
                "benign function `{f}` must NOT be matched by the deny-list"
            );
        }
    }

    #[test]
    fn empty_string_not_matched() {
        // Edge case: empty function name (shouldn't happen from the
        // parser, but defensively).
        assert!(!is_disallowed_sql_function(""));
    }

    #[test]
    fn deny_list_covers_three_risk_classes() {
        // Pin the categorical coverage so a future refactor that drops
        // any class (e.g. "let's only block filesystem reads") shows up
        // as a failing test rather than a silent policy regression.

        // Filesystem read
        for f in [
            "pg_read_server_files",
            "pg_read_file",
            "pg_read_binary_file",
            "pg_ls_dir",
            "pg_stat_file",
        ] {
            assert!(is_disallowed_sql_function(f), "filesystem-read `{f}` must be denied");
        }

        // Sleep / budget burn
        for f in ["pg_sleep", "pg_sleep_for", "pg_sleep_until"] {
            assert!(is_disallowed_sql_function(f), "sleep `{f}` must be denied");
        }

        // Backend control / config
        for f in [
            "pg_terminate_backend",
            "pg_cancel_backend",
            "pg_reload_conf",
            "pg_rotate_logfile",
        ] {
            assert!(is_disallowed_sql_function(f), "backend-control `{f}` must be denied");
        }

        // Large-object I/O + dblink network bypass
        for f in ["lo_import", "lo_export", "dblink", "dblink_connect"] {
            assert!(is_disallowed_sql_function(f), "io/dblink `{f}` must be denied");
        }
    }
}

// ============================================================================
// Vault path allowlist matcher — shared between controller and worker
// ============================================================================

/// Returns true if `key_path` is permitted by this module's `allowed_secrets` grant.
///
/// This is the single source of truth for vault path matching semantics. Both
/// the controller (static validation, hygiene reports, engine dispatch) and
/// the worker (runtime enforcement in `secrets::get_secret()`) call this
/// function so they agree on exactly which paths a module can access.
///
/// Semantics:
///   - `[]` (empty)  → deny all (no secret is permitted)
///   - `["*"]`       → allow any key (wildcard)
///   - `["prefix"]`  → allow exactly `"prefix"` and any `"prefix/<child>"` subpath
///   - `["pfx/*"]`   → explicit glob form, equivalent to the plain prefix form above
///
/// The separator must be `/` — `["stripe"]` grants `"stripe"` and `"stripe/key"`
/// but NOT `"stripe-live/key"` (different separator).
pub fn vault_path_permitted(allowed: &[String], key_path: &str) -> bool {
    if allowed.is_empty() {
        return false;
    }
    allowed.iter().any(|s| {
        s == "*"
            || s.as_str() == key_path
            || key_path.starts_with(&format!("{}/", s))
            || (s.ends_with("/*") && key_path.starts_with(&s[..s.len() - 1]))
    })
}

#[cfg(test)]
mod vault_matcher_tests {
    use super::vault_path_permitted;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn empty_list_denies_everything() {
        assert!(!vault_path_permitted(&[], "anthropic/api_key"));
        assert!(!vault_path_permitted(&[], ""));
    }

    #[test]
    fn wildcard_allows_anything() {
        assert!(vault_path_permitted(&s(&["*"]), "anthropic/api_key"));
        assert!(vault_path_permitted(&s(&["*"]), "oauth/gmail/user/access"));
    }

    #[test]
    fn exact_match_allowed() {
        assert!(vault_path_permitted(
            &s(&["anthropic/api_key"]),
            "anthropic/api_key"
        ));
    }

    #[test]
    fn prefix_match_allowed() {
        assert!(vault_path_permitted(
            &s(&["oauth/gmail"]),
            "oauth/gmail/user/access"
        ));
        assert!(vault_path_permitted(&s(&["oauth/gmail"]), "oauth/gmail"));
    }

    #[test]
    fn glob_suffix_allowed() {
        assert!(vault_path_permitted(
            &s(&["oauth/gmail/*"]),
            "oauth/gmail/user/access"
        ));
    }

    #[test]
    fn different_separator_denied() {
        // `stripe` should NOT match `stripe-live/key` — separator must be `/`
        assert!(!vault_path_permitted(&s(&["stripe"]), "stripe-live/key"));
    }

    #[test]
    fn partial_prefix_denied() {
        assert!(!vault_path_permitted(
            &s(&["oauth/gmail"]),
            "oauth/atlassian/token"
        ));
    }
}

// ============================================================================
// Encrypted secrets transport
// ============================================================================

/// Encrypted secret store for transit over untrusted channels (e.g. NATS).
///
/// The plaintext is JSON-serialized `HashMap<String, String>` encrypted
/// with AES-256-GCM using the pre-shared `WORKER_SHARED_KEY`.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct EncryptedSecrets {
    /// AES-256-GCM ciphertext.
    pub ciphertext: Vec<u8>,
    /// 12-byte random nonce (unique per encryption).
    pub nonce: Vec<u8>,
}

/// Reference [`SecretEnvelope`] impl backing the workspace's default
/// dispatch path. Seals the plaintext secrets map with AES-256-GCM,
/// using a caller-supplied 32-byte key as the AEAD key and a fresh
/// random 12-byte nonce per call. The AEAD tag authenticates the
/// ciphertext in-place, so callers do not need to add an outer MAC.
///
/// Construct as `AesGcmSecretEnvelope` (unit struct — no state). The
/// engine holds an `Arc<dyn SecretEnvelope>` and calls
/// [`SecretEnvelope::seal`] once per dispatch.
///
/// # Security properties
///
/// * Fresh 96-bit nonce per call (`rand::thread_rng`).
/// * Authenticated (AES-GCM's GMAC covers the ciphertext).
/// * Key length is validated — a non-32-byte key returns an error
///   rather than silently truncating.
///
/// [`SecretEnvelope`]: talos_workflow_engine_core::SecretEnvelope
/// [`SecretEnvelope::seal`]: talos_workflow_engine_core::SecretEnvelope::seal
#[derive(Debug, Clone, Copy, Default)]
pub struct AesGcmSecretEnvelope;

#[async_trait::async_trait]
impl talos_workflow_engine_core::SecretEnvelope for AesGcmSecretEnvelope {
    async fn seal(
        &self,
        secrets: &HashMap<String, String>,
        shared_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), talos_workflow_engine_core::BoxError> {
        // Empty map is a valid input — return the sentinel (empty
        // ciphertext + empty nonce) so the engine can short-circuit
        // without running AES on nothing.
        if secrets.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let enc = EncryptedSecrets::encrypt(secrets, shared_key)
            .map_err(|e| -> talos_workflow_engine_core::BoxError { e.into() })?;
        Ok((enc.ciphertext, enc.nonce))
    }

    /// L-1: override the default to actually bind `aad` into the
    /// AES-GCM tag.
    async fn seal_with_aad(
        &self,
        secrets: &HashMap<String, String>,
        shared_key: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), talos_workflow_engine_core::BoxError> {
        if secrets.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let enc = EncryptedSecrets::encrypt_with_aad(secrets, shared_key, aad)
            .map_err(|e| -> talos_workflow_engine_core::BoxError { e.into() })?;
        Ok((enc.ciphertext, enc.nonce))
    }
}

impl EncryptedSecrets {
    /// Encrypt a secrets map using AES-256-GCM.
    ///
    /// `key` must be exactly 32 bytes (256 bits).
    ///
    /// L-1 (2026-05-22): backwards-compatible no-AAD wrapper. New
    /// call sites should prefer [`Self::encrypt_with_aad`] passing
    /// `workflow_execution_id.as_bytes()` as the AAD — that ties the
    /// AES-GCM authentication tag to the specific execution and makes
    /// a transposed ciphertext (lifted from one execution into another
    /// with the same shared key) fail to decrypt rather than relying
    /// solely on the wider JobRequest HMAC to catch the tamper.
    pub fn encrypt(secrets: &HashMap<String, String>, key: &[u8]) -> Result<Self, String> {
        Self::encrypt_with_aad(secrets, key, &[])
    }

    /// L-1: Encrypt a secrets map with `aad` bound into the AES-GCM
    /// authentication tag.
    ///
    /// The `aad` is the dispatching workflow execution id (e.g.
    /// `workflow_execution_id.as_bytes()`) — that produces an
    /// in-protocol binding between the ciphertext and the execution
    /// it travels in.
    /// Decryption MUST be done with the same `aad` via
    /// [`Self::decrypt_with_aad`]; otherwise the tag will not
    /// validate and decryption will fail closed.
    ///
    /// Empty `aad` is equivalent to [`Self::encrypt`] — the
    /// AES-GCM construction degenerates to "no AAD" and ciphertext
    /// is byte-identical to the no-AAD path (assuming the same
    /// nonce, which is randomly generated per call).
    pub fn encrypt_with_aad(
        secrets: &HashMap<String, String>,
        key: &[u8],
        aad: &[u8],
    ) -> Result<Self, String> {
        if key.len() != 32 {
            return Err(format!(
                "WORKER_SHARED_KEY must be 32 bytes, got {}",
                key.len()
            ));
        }

        let plaintext =
            serde_json::to_vec(secrets).map_err(|e| format!("serialize secrets: {e}"))?;

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("create cipher: {e}"))?;

        // OsRng (CSPRNG via getrandom) for nonce parity with the rest of
        // the Talos signing surface — see talos-memory/src/rpc_auth.rs's
        // random_nonce. thread_rng() (ChaCha-12) is practically safe at
        // the per-message scale we hit, but using the same source
        // workspace-wide makes audit easier and removes the ChaCha-12
        // birthday-bound footnote from this primitive.
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_ref(),
                    aad,
                },
            )
            .map_err(|e| format!("encrypt secrets: {e}"))?;

        Ok(Self {
            ciphertext,
            nonce: nonce_bytes.to_vec(),
        })
    }

    /// Decrypt back into a secrets map.
    ///
    /// `key` must be the same 32-byte key used for encryption.
    /// Backwards-compatible no-AAD wrapper — passes empty AAD.
    /// Use [`Self::decrypt_with_aad`] for new call sites.
    pub fn decrypt(&self, key: &[u8]) -> Result<HashMap<String, String>, String> {
        self.decrypt_with_aad(key, &[])
    }

    /// L-1: Decrypt with `aad` bound into the AES-GCM tag check.
    ///
    /// The AAD passed here MUST byte-equal the AAD used at encrypt
    /// time. If they differ, the tag will not validate and this
    /// method returns the standard "wrong key or tampered ciphertext"
    /// error — same fail-closed surface as a bit-flipped ciphertext.
    pub fn decrypt_with_aad(
        &self,
        key: &[u8],
        aad: &[u8],
    ) -> Result<HashMap<String, String>, String> {
        if key.len() != 32 {
            return Err(format!(
                "WORKER_SHARED_KEY must be 32 bytes, got {}",
                key.len()
            ));
        }
        if self.nonce.len() != 12 {
            return Err("invalid nonce length".to_string());
        }

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("create cipher: {e}"))?;

        let nonce = Nonce::from_slice(&self.nonce);

        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: self.ciphertext.as_ref(),
                    aad,
                },
            )
            .map_err(|_| "decryption failed — wrong key or tampered ciphertext".to_string())?;

        serde_json::from_slice(&plaintext).map_err(|e| format!("deserialize secrets: {e}"))
    }

    /// Returns `true` if no secrets are stored.
    pub fn is_empty(&self) -> bool {
        self.ciphertext.is_empty()
    }
}

// ============================================================================
// Job request / result
// ============================================================================

/// A job dispatched by the Controller to a Worker via NATS.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JobRequest {
    pub job_id: Uuid,
    pub workflow_execution_id: Uuid,
    pub module_uri: String,
    pub input_payload: serde_json::Value,

    /// AES-256-GCM encrypted `HashMap<String, String>` of secret values.
    /// Encrypted with the pre-shared `WORKER_SHARED_KEY`.
    /// Never log or expose directly.
    #[serde(default)]
    pub encrypted_secrets: EncryptedSecrets,

    pub timeout_ms: u64,

    /// Job priority (0 = lowest, 255 = highest). Default: 100.
    /// Higher-priority jobs are dequeued before lower-priority ones.
    #[serde(default = "default_priority")]
    pub priority: u8,

    /// Absolute deadline as Unix timestamp (seconds). If set, the job MUST
    /// complete before this time or be treated as failed.  0 = no deadline.
    #[serde(default)]
    pub deadline_unix_secs: u64,

    /// Opaque cancellation token.  If set, the worker checks this token
    /// periodically and aborts execution if the token is revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancellation_token: Option<String>,

    pub allowed_hosts: Vec<String>,
    /// HTTP method allowlist. Empty = allow all methods. Non-empty = restrict to listed methods.
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    /// Secret allowlist. Empty = deny all. `["*"]` = allow all. Otherwise explicit secret names.
    #[serde(default)]
    pub allowed_secrets: Vec<String>,
    /// SQL operation allowlist. Empty = allow all. Otherwise explicit types (SELECT, INSERT, etc.).
    #[serde(default)]
    pub allowed_sql_operations: Vec<String>,
    /// When true, the module may call `expose_secret` (Tier-2) to receive
    /// raw secret plaintext in WASM guest memory. Default: false (blocked).
    #[serde(default)]
    pub allow_tier2_exposure: bool,

    /// HMAC-SHA256 over the canonical job fields (see [`JobRequest::sign`]).
    pub signature: Vec<u8>,

    /// Nonce used for replay-attack prevention: `"{unix_secs}:{random_hex}"`.
    pub job_nonce: String,

    /// Actor ID that owns this execution. When set, the worker routes
    /// WIT agent-memory get/set/search calls to the persistent actor_memory
    /// Postgres table instead of the ephemeral in-memory HashMap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Uuid>,

    /// Optional WASM module bytes.  When present the worker uses these
    /// directly instead of reading from `module_uri`, avoiding file-system
    /// coupling and improving performance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wasm_bytes: Option<Vec<u8>>,

    /// Capability world hint for the worker's tiered linker selection.
    ///
    /// When present and not "unknown", the worker uses this instead of
    /// re-inspecting the WASM binary.  This is critical for sandbox modules
    /// (stored in `node_templates.precompiled_wasm`) whose world name may
    /// not survive the Wizer snapshot step.
    ///
    /// Accepts both bare names ("minimal") and WIT world names ("minimal-node",
    /// "automation-node").
    ///
    /// H-3 (2026-05-23): NOW HMAC-bound at the end of the signing payload.
    /// The previous "performance hint, linker enforces real security at
    /// instantiation time" disclaimer was only true when the worker
    /// re-derived the world from the WASM binary; for precompiled (Wizer)
    /// modules whose embedded world name doesn't survive, the controller's
    /// hint IS the policy decision. Binding it into the signature closes
    /// the tampering path where an attacker on the NATS subject would flip
    /// `minimal-node` → `automation-node` and trick the worker into
    /// selecting a wider tiered linker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_world: Option<String>,

    /// Integration name this module was compiled under, if any. When set,
    /// the module can call integration-scoped host functions (e.g. an
    /// `integration-state::*` WIT interface) and the worker signs every
    /// downstream RPC request with this value. When None, the host
    /// function returns `unauthorized` — non-integration modules cannot
    /// write to the shared integration-state table.
    ///
    /// Populated by the engine from `wasm_modules.integration_name` /
    /// `node_templates.integration_name`. Guest code has no way to
    /// supply or change this value — the worker reads it from the
    /// request, never from WIT arguments.
    ///
    /// Not part of the HMAC commitment (it's not a capability, just a
    /// scoping identifier); the RPC layer signs it separately.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integration_name: Option<String>,

    /// Expected SHA-256 hex digest of the WASM binary loaded from `module_uri`.
    ///
    /// Set by the controller from `wasm_modules.content_hash` (recorded at
    /// compile/registration time).  When present and `wasm_bytes` is absent
    /// (i.e. the worker will load the binary from the registry or Redis), the
    /// worker MUST verify that `sha256(loaded_bytes) == expected_wasm_hash`
    /// before execution.  A mismatch indicates tampering in the storage layer.
    ///
    /// Included in the HMAC signing payload so the commitment is tamper-evident.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_wasm_hash: Option<String>,

    /// Maximum fuel (WASM instructions) for this job.
    ///
    /// Set by the controller from the node's `max_fuel` config key or the
    /// module's stored `max_fuel` column.  When non-zero the worker SHOULD use
    /// this value instead of its global `WASM_FUEL_LIMIT` default.
    /// Capped at 50_000_000 (50M) by the controller to prevent abuse.
    /// Zero means "use the worker's default fuel limit".
    #[serde(default)]
    pub max_fuel: u64,

    /// User ID that owns this execution — used for ownership-scoped
    /// resources (integration_state writes, per-user rate limiting,
    /// audit trails). Populated by the controller from the workflow
    /// owner's user_id. Nil UUID indicates 'no user context' (system
    /// executions); integration_state host fns reject those.
    ///
    /// Added to JobRequest alongside `actor_id` so host fns that need
    /// user scoping (integration_state::{set,get,...}) don't have to
    /// conflate it with actor_id.
    #[serde(default)]
    pub user_id: Uuid,

    /// Maximum LLM data-egress tier this job is allowed to reach.
    /// Sourced from `actors.max_llm_tier` for actor-bound executions,
    /// `Tier2` (no restriction) for system jobs and pre-actor workflows.
    ///
    /// Worker enforcement: when this is `Tier1`, the worker's
    /// `get_llm_api_key` refuses to resolve keys for Anthropic / OpenAI
    /// / Gemini and the job fails closed with a clear "actor X is
    /// tier-1, provider Y forbidden" error.
    ///
    /// HMAC-bound: included in the signing payload so an on-wire
    /// attacker can't downgrade a tier-1 ceiling to tier-2 to redirect
    /// a sensitive actor's data to an external provider.
    #[serde(default)]
    pub max_llm_tier: LlmTier,

    /// When true, non-GET HTTP requests are mocked (returns 200 with dry_run metadata).
    /// GET requests execute normally for data fetching.
    #[serde(default)]
    pub dry_run: bool,

    /// H-1: signed reply-inbox commitment.
    ///
    /// When `Some(subject)`, the worker MUST publish its `JobResult`
    /// to exactly this NATS subject — regardless of what arrives in
    /// the unsigned `msg.reply` NATS header. Pre-fix, an on-wire
    /// attacker (or anyone with NATS publish rights) could substitute
    /// `msg.reply` with an arbitrary subject (e.g. `talos.admin.*`)
    /// and the worker would happily publish a legitimately-signed
    /// JobResult there, leaking execution output.
    ///
    /// Populated by the dispatcher when the transport supports
    /// inbox pre-allocation (`JobTransport::new_reply_inbox`).
    /// `None` falls back to the legacy "trust msg.reply" path for
    /// backward compatibility with older controllers / transports.
    ///
    /// HMAC-bound via the signing payload (appended at end per the
    /// wire-format stability rule).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_topic: Option<String>,
}

impl JobRequest {
    /// Canonical byte string signed / verified by HMAC-SHA256.
    ///
    /// All security-sensitive fields are covered so that an attacker cannot
    /// substitute `input_payload`, secrets, WASM bytes, timeout, or allowed
    /// hosts without invalidating the signature.
    ///
    /// Format:
    /// `job_id:wex_id:module_uri:job_nonce:sha256(input):sha256(secrets_ciphertext):timeout_ms:sorted_hosts:sorted_methods:sha256(wasm_bytes)|expected_wasm_hash|none`
    ///
    /// When `wasm_bytes` is inline, the field is `sha256(wasm_bytes)`.
    /// When `wasm_bytes` is absent but `expected_wasm_hash` is set, the field is that hash
    /// (tamper-evident commitment to the content the worker will load from `module_uri`).
    /// Otherwise the sentinel "none" is used.
    fn signing_payload(&self) -> Vec<u8> {
        use sha2::Digest;

        // Hash large/variable fields to fixed-size hex representations.
        // This prevents payload-substitution attacks where an attacker could
        // replace input_payload, secrets, or wasm_bytes with malicious content.
        let input_hash = hex::encode(Sha256::digest(self.input_payload.to_string().as_bytes()));
        let secrets_hash = hex::encode(Sha256::digest(&self.encrypted_secrets.ciphertext));

        // Sort allowed_hosts so the signature is stable regardless of array order.
        let mut hosts = self.allowed_hosts.clone();
        hosts.sort_unstable();
        let hosts_str = hosts.join(",");

        // Sort allowed_methods for the same reason: order must not matter.
        let mut methods = self.allowed_methods.clone();
        methods.sort_unstable();
        let methods_str = methods.join(",");

        // Wasm integrity commitment:
        // - Inline bytes → sha256(bytes) (already covers the content)
        // - No inline bytes + expected hash → that hash (tamper-evident URI-content binding)
        // - Neither → "none"
        let wasm_hash = if let Some(b) = self.wasm_bytes.as_deref() {
            hex::encode(Sha256::digest(b))
        } else if let Some(ref h) = self.expected_wasm_hash {
            h.clone()
        } else {
            "none".to_string()
        };

        // integration_name is part of the module's identity for
        // integration-state scoping — a NATS-channel tampering attacker
        // could otherwise swap "gcal" → "gmail" in flight and redirect
        // a module's writes into a different integration's namespace
        // without invalidating the signature. The sentinel "-" is used
        // for modules that aren't integrations so an absent value is
        // still tamper-evident (distinct from the empty string).
        //
        // Wire-format stability rule: this field is appended at the END
        // of the format string — adding it here is safe during a
        // coordinated controller+worker restart; reordering the
        // existing positions would break every deployed signature.
        let integration_name = self.integration_name.as_deref().unwrap_or("-");

        // M-4: actor_id bound. Pre-fix, an on-wire attacker could
        // change A→B without invalidating the signature; the worker
        // would then sign every downstream MemoryRpcRequest with the
        // tampered actor_id and the controller would accept it
        // (correctly signed by the worker key with the wrong actor_id).
        // Sentinel "-" for None so absence is tamper-evident.
        let actor_id_str = self
            .actor_id
            .map(|u| u.to_string())
            .unwrap_or_else(|| "-".to_string());

        // M-5: capability-grant fields bound (defense-in-depth). Even
        // though the encrypted_secrets blob and worker host-internal
        // deny-list together prevent any unauthorised secret read,
        // capability claims should be self-consistent with the signed
        // message. Pre-fix, allowed_secrets / allowed_sql_operations /
        // allow_tier2_exposure could be tampered without invalidating
        // the signature.
        let mut allowed_secrets_sorted = self.allowed_secrets.clone();
        allowed_secrets_sorted.sort_unstable();
        let allowed_secrets_str = allowed_secrets_sorted.join(",");
        let mut allowed_sql_sorted = self.allowed_sql_operations.clone();
        allowed_sql_sorted.sort_unstable();
        let allowed_sql_str = allowed_sql_sorted.join(",");

        // L-9: every variable-length field is now length-prefixed in
        // its hashed/encoded form. Field-internal `:` characters can no
        // longer cause a collision between two semantically-different
        // payloads. The legacy fixed-width fields (UUIDs, hex digests,
        // numbers, sentinel "-") use unambiguous formats so a `:`
        // delimiter remains safe. The user-controlled string fields
        // (module_uri, hosts_str, methods_str, integration_name,
        // allowed_secrets_str, allowed_sql_str, actor_id_str) are
        // emitted as `<len>:<bytes>` to remove the ambiguity.
        //
        // Defense-in-depth: today the existing fixed-width-prefix
        // header already disambiguates, but an extension that adds a
        // new free-form string field could re-introduce the collision
        // class. The length-prefix discipline is forward-safe.
        fn lp(s: &str) -> String {
            format!("{}:{}", s.as_bytes().len(), s)
        }

        // H-1: reply_topic. Sentinel `-` for None so absence is
        // tamper-evident (an attacker can't strip the field to
        // downgrade verification). Length-prefixed because the inbox
        // subject is variable-length and contains `.` separators (so
        // it could collide against adjacent fields under naive
        // concatenation).
        let reply_topic_str = self.reply_topic.as_deref().unwrap_or("-");

        // Wasm-security review 2026-05-23 (H-3, H-7): bind the remaining
        // policy-controlling fields. Each was previously unsigned, which
        // gave anyone with NATS-publish rights on the job subject a
        // tamper window:
        //
        // - `capability_world` (H-3). Pre-fix doc described it as a
        //   performance hint, "linker enforces real security at
        //   instantiation time." That's only true if the worker
        //   ALWAYS re-derives the world from the WASM binary. For
        //   `precompiled_wasm` (Wizer-snapshotted) the world name may
        //   not survive — in which case the controller's hint IS the
        //   policy. An attacker who flips `minimal-node` → `automation-node`
        //   on the wire could select a wider tiered linker that resolves
        //   host fns the module would otherwise lack. Sentinel `-` for
        //   None.
        // - `dry_run` (H-7). Tamperer flips `true → false` to convert
        //   planning-mode into a real-side-effect run (real HTTP POSTs,
        //   real webhooks, real DB writes).
        // - `priority` (H-7). Queue-jumping / starving — a NATS-publish
        //   attacker can promote arbitrary jobs to drown out legitimate
        //   high-priority work.
        // - `deadline_unix_secs` (H-7). Tamperer sets a past timestamp
        //   to force premature failure; reading the field is one of
        //   the worker's loop conditions.
        // - `cancellation_token` (H-7). Stripping the token leaves an
        //   in-flight job uncancellable — resource hog / cost overrun.
        let capability_world_str = self.capability_world.as_deref().unwrap_or("-");
        let cancellation_token_str = self.cancellation_token.as_deref().unwrap_or("-");

        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.job_id,
            self.workflow_execution_id,
            lp(&self.module_uri),
            self.job_nonce,
            input_hash,
            secrets_hash,
            self.timeout_ms,
            lp(&hosts_str),
            lp(&methods_str),
            wasm_hash,
            lp(integration_name),
            // Appended AT THE END per the wire-format stability rule —
            // inserting in the middle would break every deployed
            // signature. user_id bound so an on-wire attacker can't
            // redirect a module's writes to a different user's
            // integration-state namespace.
            self.user_id,
            // Appended AT THE END for the same reason. Tier-ceiling
            // bound so an attacker can't downgrade a tier-1 actor's
            // ceiling on the wire to redirect data to an external LLM.
            self.max_llm_tier.as_signing_str(),
            // M-4: actor_id appended AT THE END.
            lp(&actor_id_str),
            // M-5: capability grants appended AT THE END.
            lp(&allowed_secrets_str),
            lp(&allowed_sql_str),
            self.allow_tier2_exposure,
            // H-1: reply_topic appended AT THE END so an on-wire
            // attacker can't redirect a worker's signed JobResult to
            // an attacker-controlled subject via the unsigned
            // msg.reply NATS header.
            lp(&reply_topic_str),
            // H-3 (2026-05-23): capability_world appended AT THE END.
            lp(capability_world_str),
            // H-7 (2026-05-23): dry_run appended AT THE END.
            self.dry_run,
            // H-7 (2026-05-23): priority appended AT THE END.
            self.priority,
            // H-7 (2026-05-23): deadline_unix_secs appended AT THE END.
            self.deadline_unix_secs,
            // H-7 (2026-05-23): cancellation_token appended AT THE END.
            lp(cancellation_token_str),
        )
        .into_bytes()
    }

    /// Diagnostic snapshot of the per-field hashes that
    /// [`Self::signing_payload`] consumes for `input_payload` and
    /// `encrypted_secrets.ciphertext`, plus the input's serialized byte
    /// length. Surfaced by the dispatcher's `signature_diag` WARN log
    /// (controller side) and the worker's `signature verification failed`
    /// `output_payload.diag` (worker side) so operators can field-by-field
    /// compare what the two sides hashed when verification mismatched.
    /// Cheap to compute; safe to call on production traffic. Not
    /// security-sensitive (the same hashes already go into the signature).
    pub fn diag_hashes(&self) -> (String, String, usize) {
        use sha2::Digest;
        let input_str = self.input_payload.to_string();
        let input_hash = hex::encode(Sha256::digest(input_str.as_bytes()));
        let secrets_hash = hex::encode(Sha256::digest(&self.encrypted_secrets.ciphertext));
        (input_hash, secrets_hash, input_str.len())
    }

    /// Sign the request using the pre-shared `key`.
    ///
    /// Sets `self.signature` and `self.job_nonce` (timestamp + random hex).
    /// Call this after all other fields have been populated.
    pub fn sign(&mut self, key: &[u8]) -> Result<(), String> {
        // Build nonce: "<unix_seconds>:<16 random hex bytes>"
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("system time error: {e}"))?
            .as_secs();
        let rand_bytes: [u8; 16] = rand::thread_rng().gen();
        self.job_nonce = format!("{}:{}", ts, hex::encode(rand_bytes));

        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).map_err(|e| format!("HMAC key error: {e}"))?;
        mac.update(&self.signing_payload());
        self.signature = mac.finalize().into_bytes().to_vec();
        Ok(())
    }

    /// Verify the HMAC signature and nonce freshness.
    ///
    /// Returns `Err` if the signature is invalid or the nonce is older than
    /// `max_age_secs` (default recommendation: 300 s / 5 minutes).
    pub fn verify(&self, key: &[u8], max_age_secs: u64) -> Result<(), String> {
        // 1. Verify nonce freshness to prevent replay attacks.
        let parts: Vec<&str> = self.job_nonce.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err("malformed job_nonce".to_string());
        }
        let ts: u64 = parts[0]
            .parse()
            .map_err(|_| "invalid timestamp in job_nonce".to_string())?;
        if hex::decode(parts[1]).is_err() {
            return Err("invalid hex in job_nonce".to_string());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now.saturating_sub(ts) > max_age_secs {
            return Err(format!(
                "job_nonce is too old ({} s, max {})",
                now.saturating_sub(ts),
                max_age_secs
            ));
        }
        if ts.saturating_sub(now) > MAX_FUTURE_SKEW_SECS {
            return Err(format!(
                "job_nonce is in the future ({} s ahead, max {})",
                ts.saturating_sub(now),
                MAX_FUTURE_SKEW_SECS
            ));
        }

        // 2. Constant-time HMAC verification.
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).map_err(|e| format!("HMAC key error: {e}"))?;
        mac.update(&self.signing_payload());
        mac.verify_slice(&self.signature)
            .map_err(|_| "HMAC signature verification failed".to_string())?;

        // 3. Replay protection: refuse a nonce we have seen before
        // within the freshness window. HMAC alone catches forgery;
        // without this check, anyone with NATS-publish access can
        // capture a signed JobRequest and re-fire it any number of
        // times until ts + max_age_secs expires.
        if !check_and_record_job_nonce(&self.job_nonce, ts, max_age_secs) {
            return Err(format!(
                "job_nonce already seen (replay attempt within {}-second window)",
                max_age_secs
            ));
        }
        Ok(())
    }
}

/// Job status reported by a Worker.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum JobStatus {
    Success,
    Failed,
    TimedOut,
}

/// Result returned by a Worker to the Controller via NATS.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JobResult {
    pub job_id: Uuid,
    pub status: JobStatus,
    pub output_payload: serde_json::Value,
    pub logs: Vec<String>,
    pub execution_time_ms: u64,
    /// HMAC-SHA256 signature over canonical result fields (see [`JobResult::sign`]).
    /// Allows the controller to verify the result came from a legitimate worker.
    #[serde(default)]
    pub signature: Vec<u8>,
    /// Nonce for replay prevention: `"{unix_secs}:{random_hex}"`.
    #[serde(default)]
    pub result_nonce: String,
    /// Self-reported worker identity, HMAC-bound by [`JobResult::sign_with_worker_id`].
    ///
    /// Plain pre-shared HMAC keys cannot distinguish results from worker-A vs.
    /// worker-B — any process holding `WORKER_SHARED_KEY` can sign for any
    /// `job_id`. Binding the worker's own id into the signed payload gives the
    /// controller forensic visibility (which pod produced which result) and
    /// opens the path to per-worker HKDF subkeys in a future rev.
    ///
    /// Charset is restricted (`[A-Za-z0-9._-]{0,128}`) so the colon-delimited
    /// signing payload format stays unambiguous. Empty string is permitted for
    /// the [`JobResult::sign`] back-compat wrapper; production worker code uses
    /// [`JobResult::sign_with_worker_id`].
    #[serde(default)]
    pub worker_id: String,
}

impl JobResult {
    /// Canonical byte string signed / verified by HMAC-SHA256.
    ///
    /// Format:
    /// `job_id:status:result_nonce:sha256(output_payload):execution_time_ms:sha256(logs_canonical)`
    ///
    /// L-10: `logs` is now part of the signing payload via a SHA-256 of
    /// the canonical newline-joined form. Pre-fix, an attacker tampering
    /// with the logs field in flight could inject misleading log lines
    /// without invalidating the signature. No capability impact, but
    /// audit-trail integrity matters for incident response.
    ///
    /// L-11 (2026-05-22): `worker_id` is appended at the end of the
    /// signing payload so a result captured from one worker can't be
    /// re-published as if it came from another. The charset is enforced
    /// by [`validate_worker_id`] so the colon-delimited format stays
    /// unambiguous (no `:` smuggling). Empty `worker_id` is permitted
    /// (renders as `""`) — the [`JobResult::sign`] back-compat wrapper
    /// leaves it empty; production worker code calls
    /// [`JobResult::sign_with_worker_id`].
    fn signing_payload(&self) -> Vec<u8> {
        use sha2::Digest;
        let status_str = match self.status {
            JobStatus::Success => "success",
            JobStatus::Failed => "failed",
            JobStatus::TimedOut => "timedout",
        };
        let output_hash = hex::encode(Sha256::digest(self.output_payload.to_string().as_bytes()));
        // Canonicalise logs by joining with `\n` (a stable separator
        // that no individual log line can contain — Vec<String> elements
        // are pre-split on newlines by the worker). Hash to a fixed
        // 64-char hex digest so the signing payload size is bounded.
        let logs_hash = hex::encode(Sha256::digest(self.logs.join("\n").as_bytes()));
        format!(
            "{}:{}:{}:{}:{}:{}:{}",
            self.job_id,
            status_str,
            self.result_nonce,
            output_hash,
            self.execution_time_ms,
            // L-10: appended AT THE END per the wire-format stability rule.
            logs_hash,
            // L-11: appended AT THE END (after L-10) per the same rule.
            self.worker_id,
        )
        .into_bytes()
    }

    /// Sign the result using the pre-shared `key`. **Back-compat wrapper —
    /// production worker code should call
    /// [`JobResult::sign_with_worker_id`] so the worker identity is bound
    /// into the signature.**
    ///
    /// Sets `self.signature` and `self.result_nonce`. The `worker_id`
    /// field is left untouched (empty by default), so the signed payload
    /// commits to an empty identity. Test fixtures that don't care about
    /// per-worker attribution use this path; the worker process must use
    /// `sign_with_worker_id`. A `lint-structural.sh` check rejects raw
    /// `.sign(` in the `worker/` tree to prevent regressions.
    pub fn sign(&mut self, key: &[u8]) -> Result<(), String> {
        self.sign_with_worker_id(key, "")
    }

    /// Sign the result and bind the worker's self-reported identity.
    ///
    /// `worker_id` is validated by [`validate_worker_id`] (charset
    /// `[A-Za-z0-9._-]{0,128}`); invalid ids fail closed before any HMAC
    /// is computed so a misconfigured worker can't accidentally publish a
    /// malformed-but-signed result.
    pub fn sign_with_worker_id(
        &mut self,
        key: &[u8],
        worker_id: &str,
    ) -> Result<(), String> {
        validate_worker_id(worker_id)?;
        self.worker_id = worker_id.to_string();

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("system time error: {e}"))?
            .as_secs();
        let rand_bytes: [u8; 16] = rand::thread_rng().gen();
        self.result_nonce = format!("{}:{}", ts, hex::encode(rand_bytes));

        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).map_err(|e| format!("HMAC key error: {e}"))?;
        mac.update(&self.signing_payload());
        self.signature = mac.finalize().into_bytes().to_vec();
        Ok(())
    }

    /// Verify the HMAC signature and nonce freshness, *and* record the
    /// nonce in the process-local replay cache. Subsequent `verify()`
    /// calls against the same nonce within the freshness window will
    /// fail with `"result_nonce already seen"`.
    ///
    /// Use this at the **primary action point** for a result — the
    /// place where the message is converted into a side effect that
    /// would be wrong to apply twice. There must be EXACTLY ONE
    /// primary verifier per `JobResult` per controller process.
    /// Passive observers (e.g. an audit/DB-update subscriber that
    /// already runs downstream of the primary) MUST call
    /// [`verify_no_replay`](Self::verify_no_replay) instead — calling
    /// `verify()` from two consumers of the same signed result causes
    /// the second one to fail with a spurious replay error.
    pub fn verify(&self, key: &[u8], max_age_secs: u64) -> Result<(), String> {
        let ts = self.verify_no_replay(key, max_age_secs)?;
        // Replay protection: refuse a nonce we have seen before within
        // the freshness window. HMAC alone catches forgery; without
        // this check, anyone with NATS-publish access can capture a
        // signed JobResult and re-fire it any number of times until
        // ts + max_age_secs expires.
        if !check_and_record_job_nonce(&self.result_nonce, ts, max_age_secs) {
            return Err(format!(
                "result_nonce already seen (replay attempt within {}-second window)",
                max_age_secs
            ));
        }
        Ok(())
    }

    /// L-4 typed verifier: dispatches to [`Self::verify`] for
    /// [`Verifier::Primary`] and [`Self::verify_no_replay`] for
    /// [`Verifier::Observer`]. New code should prefer this method —
    /// the role becomes explicit at the call site instead of being
    /// encoded only in the method name.
    pub fn verify_as(
        &self,
        key: &[u8],
        max_age_secs: u64,
        role: Verifier,
    ) -> Result<(), String> {
        match role {
            Verifier::Primary => self.verify(key, max_age_secs),
            Verifier::Observer => {
                self.verify_no_replay(key, max_age_secs).map(|_| ())
            }
        }
    }

    /// Verify HMAC signature and nonce freshness **without** recording
    /// the nonce in the replay cache. Returns the parsed timestamp on
    /// success, allowing the caller to chain a manual cache update if
    /// desired.
    ///
    /// Use this at **passive observer** call sites that consume a
    /// signed result already verified-with-replay-protection by some
    /// other primary verifier in the same process — e.g. a
    /// `talos.results.*` audit subscriber whose only side effect is an
    /// idempotent DB write. HMAC continues to gate forgery and the
    /// freshness window continues to gate stale-replay; replay
    /// protection is the responsibility of the primary verifier.
    ///
    /// **Security invariant**: there must be at least one primary
    /// `verify()` caller in the chain for any given result. If you're
    /// adding a NEW result-consumer and it's the only verifier in its
    /// chain, use `verify()` (not this method).
    pub fn verify_no_replay(&self, key: &[u8], max_age_secs: u64) -> Result<u64, String> {
        // 1. Parse + freshness window check.
        let parts: Vec<&str> = self.result_nonce.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err("malformed result_nonce".to_string());
        }
        let ts: u64 = parts[0]
            .parse()
            .map_err(|_| "invalid timestamp in result_nonce".to_string())?;
        if hex::decode(parts[1]).is_err() {
            return Err("invalid hex in result_nonce".to_string());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now.saturating_sub(ts) > max_age_secs {
            return Err(format!(
                "result_nonce is too old ({} s, max {})",
                now.saturating_sub(ts),
                max_age_secs
            ));
        }
        if ts.saturating_sub(now) > MAX_FUTURE_SKEW_SECS {
            return Err(format!(
                "result_nonce is in the future ({} s ahead, max {})",
                ts.saturating_sub(now),
                MAX_FUTURE_SKEW_SECS
            ));
        }

        // 2. Constant-time HMAC verification.
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).map_err(|e| format!("HMAC key error: {e}"))?;
        mac.update(&self.signing_payload());
        mac.verify_slice(&self.signature)
            .map_err(|_| "HMAC signature verification failed".to_string())?;

        Ok(ts)
    }
}

// ============================================================================
// Pipeline job protocol
// ============================================================================

/// A single step in a pipeline job dispatched via NATS.
///
/// **Security invariant: no per-step LLM tier override.** The tier
/// ceiling applies uniformly to every step in a pipeline and is sourced
/// from `PipelineJobRequest::max_llm_tier`. Do NOT add a
/// `max_llm_tier` field here. Per-step tier granularity is precisely
/// the surface area we don't want — it would create a path where a
/// subtle refactor accidentally sets one step to Tier2 inside an
/// otherwise-Tier1 pipeline, leaking the data the pipeline was supposed
/// to keep local.
///
/// If a future requirement genuinely needs per-step tiering (e.g.
/// "step 1 enriches with public data via Anthropic, step 2 processes
/// private data locally"), the right shape is to split into two
/// pipelines with explicit hand-off — not to widen this struct. The
/// worker stamps `PipelineJobRequest::max_llm_tier` uniformly onto
/// every step's `TalosContext` (see `Runtime::execute_pipeline` at the
/// `context.max_llm_tier = max_llm_tier` line); a per-step override
/// would have to land there too, and breaking that single stamp is
/// where any tier-leak regression would show up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStep {
    pub module_id: Uuid,
    /// URI for the module (e.g. "redis:wasm:uuid" or "file://...")
    pub module_uri: String,
    /// Optional WASM module bytes for this step (overrides module_uri if provided).
    pub wasm_bytes: Option<Vec<u8>>,
    /// Module configuration (merged into input as `{"config": ..., "input": ...}`).
    pub config: serde_json::Value,
    pub allowed_hosts: Vec<String>,
    pub allowed_methods: Vec<String>,
    /// Secret allowlist. Empty = deny all. `["*"]` = allow all.
    #[serde(default)]
    pub allowed_secrets: Vec<String>,
    /// SQL operation allowlist. Empty = allow all.
    #[serde(default)]
    pub allowed_sql_operations: Vec<String>,
    /// When true, expose_secret (Tier-2) is allowed. Default: false.
    #[serde(default)]
    pub allow_tier2_exposure: bool,
    /// AES-256-GCM encrypted secret map for this step.
    pub encrypted_secrets: EncryptedSecrets,
    /// Maximum fuel (WASM instructions) for this step.
    pub max_fuel: u64,
    pub max_memory_mb: usize,
    /// Per-step timeout in milliseconds.
    pub timeout_ms: u64,

    /// Step priority (inherited from JobRequest if not set). Default: 100.
    #[serde(default = "default_priority")]
    pub priority: u8,

    /// Cancellation token for this step. Checked by the worker during execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancellation_token: Option<String>,

    /// Expected SHA-256 hex digest of the WASM binary at `module_uri`.
    ///
    /// Set by the controller from `wasm_modules.content_hash`.  When present
    /// and `wasm_bytes` is absent, the worker verifies the loaded bytes match
    /// before execution.  Included in the pipeline HMAC signing payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_wasm_hash: Option<String>,

    /// Integration this step's module belongs to. Same semantics as
    /// `JobRequest::integration_name`. Pipeline steps may belong to
    /// different integrations within one pipeline (rare but valid),
    /// so it's per-step rather than at the pipeline level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integration_name: Option<String>,
}

/// A pipeline job dispatched by the Controller to a Worker via NATS.
///
/// The signing payload covers the job identity, step count, WASM integrity hashes,
/// and nonce — making it impossible for an attacker to add/remove/replace steps
/// without invalidating the signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineJobRequest {
    pub job_id: Uuid,
    pub workflow_execution_id: Uuid,
    pub steps: Vec<PipelineStep>,
    /// Total timeout for the entire pipeline in milliseconds.
    pub total_timeout_ms: u64,
    /// If true, all steps share a single ephemeral filesystem sandbox.
    pub share_sandbox: bool,
    /// HMAC-SHA256 signature over the canonical pipeline fields.
    pub signature: Vec<u8>,
    /// Nonce for replay-attack prevention: `"{unix_secs}:{random_hex}"`.
    pub job_nonce: String,
    /// User ID for global rate limiting and audit logging.
    pub user_id: Uuid,

    /// LLM data-egress ceiling — MUST match the owning workflow's
    /// actor's `max_llm_tier`. Worker stamps this into every step's
    /// `TalosContext` before execution so each pipeline step enforces
    /// the same tier gate as a single-node JobRequest.
    ///
    /// HMAC-bound via the signing payload (appended at end per the
    /// wire-format stability rule). `#[serde(default)]` for backward
    /// compat with older controllers — deserialized as Tier2 which
    /// matches pre-feature behavior for unrestricted actors.
    #[serde(default)]
    pub max_llm_tier: LlmTier,

    /// H-1: signed reply-inbox commitment. Same semantics as
    /// [`JobRequest::reply_topic`] — the worker MUST publish its
    /// `PipelineJobResult` to this exact NATS subject when set,
    /// regardless of `msg.reply`. `None` falls back to the legacy
    /// trust-msg.reply path. HMAC-bound at the end of the signing
    /// payload (wire-format stability rule).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_topic: Option<String>,
}

impl PipelineJobRequest {
    /// Canonical signing payload.
    ///
    /// Format:
    /// `pipeline:{job_id}:{wex_id}:{nonce}:{total_timeout_ms}:{share_sandbox}:
    ///  {num_steps}:{user_id}:{sha256(step0_wasm)}:{sha256(step1_wasm)}:...`
    fn signing_payload(&self) -> Vec<u8> {
        use sha2::Digest;

        let step_hashes: Vec<String> = self
            .steps
            .iter()
            .map(|s| {
                if let Some(b) = s.wasm_bytes.as_deref() {
                    // Inline bytes: hash the actual content.
                    hex::encode(Sha256::digest(b))
                } else if let Some(ref h) = s.expected_wasm_hash {
                    // No inline bytes but controller committed to a content hash.
                    h.clone()
                } else {
                    // No hash commitment: fall back to URI (unchanged legacy behavior).
                    hex::encode(Sha256::digest(s.module_uri.as_bytes()))
                }
            })
            .collect();

        // Per-step integration_name commitment. Same reasoning as
        // JobRequest::signing_payload — a NATS-channel tamperer could
        // otherwise swap a step's integration_name and redirect that
        // step's integration_state writes into a different namespace.
        // Sentinel "-" for non-integration steps (distinct from empty).
        //
        // Wire-format stability: appended at the END of the format
        // string — safe during coordinated deploys; reordering would
        // break every deployed pipeline signature.
        let step_integrations: Vec<&str> = self
            .steps
            .iter()
            .map(|s| s.integration_name.as_deref().unwrap_or("-"))
            .collect();

        // M-5 (pipeline): per-step capability grants. Each step can
        // carry its own allowlists; bind all of them so a NATS-channel
        // attacker can't widen `allowed_secrets` or flip
        // `allow_tier2_exposure` on a single step without invalidating
        // the whole pipeline signature.
        //
        // Encoded as `step0_secrets|step0_sql|step0_tier2 ;; step1_…`
        // with length-prefixed segments so concatenation can't collide
        // across step boundaries.
        let step_caps: Vec<String> = self
            .steps
            .iter()
            .map(|s| {
                let mut secrets = s.allowed_secrets.clone();
                secrets.sort_unstable();
                let secrets_str = secrets.join(",");
                let mut sql = s.allowed_sql_operations.clone();
                sql.sort_unstable();
                let sql_str = sql.join(",");
                format!(
                    "{}:{}|{}:{}|{}",
                    secrets_str.as_bytes().len(),
                    secrets_str,
                    sql_str.as_bytes().len(),
                    sql_str,
                    s.allow_tier2_exposure,
                )
            })
            .collect();
        let step_caps_str = step_caps.join(";;");

        // L-9 (pipeline): length-prefix the user-controlled string
        // segments so internal `:` / `,` characters can't cause
        // payload-collisions. Existing fixed-width fields stay
        // unchanged.
        fn lp(s: &str) -> String {
            format!("{}:{}", s.as_bytes().len(), s)
        }
        let step_hashes_joined = step_hashes.join(":");
        let step_integrations_joined = step_integrations.join(",");

        // H-1 (pipeline): reply_topic — same semantics as JobRequest.
        let reply_topic_str = self.reply_topic.as_deref().unwrap_or("-");

        // C-2 (2026-05-23, critical fix): per-step policy commitment.
        //
        // Pre-fix `PipelineJobRequest::signing_payload` bound the
        // wasm-integrity hash + integration_name + capability grants per
        // step, plus job-level fields (user, tier, reply_topic). It did
        // NOT bind any of `config` (the step input!), `allowed_hosts`,
        // `allowed_methods`, `encrypted_secrets.{ciphertext,nonce}`,
        // `max_fuel`, `max_memory_mb`, `timeout_ms`, `priority`,
        // `cancellation_token`. Anyone with NATS publish on the pipeline
        // subject could:
        //   - rewrite a step's config — the signed-and-attested module
        //     executes attacker-supplied input under signed secrets;
        //   - widen `allowed_hosts` / `allowed_methods` to exfiltrate
        //     via attacker-controlled URL + still-signed `vault://`
        //     header;
        //   - swap one step's `encrypted_secrets.ciphertext` for
        //     another's (engine.rs uses `workflow_execution_id` as AAD,
        //     which is shared across steps — both blobs are decryptable
        //     by the worker for this pipeline);
        //   - inflate `max_fuel` / `max_memory_mb` / `timeout_ms` for
        //     resource exhaustion;
        //   - strip `cancellation_token` to keep an in-flight pipeline
        //     uncancellable;
        //   - promote `priority` for queue-jumping.
        //
        // The fix mirrors the single-node `JobRequest::signing_payload`
        // shape: hash each variable-length field (input / secrets) to
        // fixed-width hex, length-prefix the string-valued segments
        // (sorted hosts / methods, cancellation_token), and encode the
        // u8/u64 numerics as decimal. Steps are separated by `;;` (the
        // same separator already used by `step_caps_str`) and each
        // intra-step field by `|`.
        let step_policies: Vec<String> = self
            .steps
            .iter()
            .map(|s| {
                let config_hash =
                    hex::encode(Sha256::digest(s.config.to_string().as_bytes()));
                let secrets_ct_hash =
                    hex::encode(Sha256::digest(&s.encrypted_secrets.ciphertext));
                let mut hosts = s.allowed_hosts.clone();
                hosts.sort_unstable();
                let hosts_str = hosts.join(",");
                let mut methods = s.allowed_methods.clone();
                methods.sort_unstable();
                let methods_str = methods.join(",");
                let cancellation_token_str = s.cancellation_token.as_deref().unwrap_or("-");
                // Length-prefix every user-controlled string so a `|`
                // or `;;` inside a field cannot collide with the inter-
                // field / inter-step separator.
                //
                // Field order (positional, do not reorder — this is
                // wire-format-stable from this revision forward):
                //   1. config_hash               (64-char hex)
                //   2. secrets_ct_hash           (64-char hex)
                //   3. lp(hosts_str)             (length-prefixed)
                //   4. lp(methods_str)           (length-prefixed)
                //   5. max_fuel                  (u64 decimal)
                //   6. max_memory_mb             (usize decimal)
                //   7. timeout_ms                (u64 decimal)
                //   8. priority                  (u8 decimal)
                //   9. lp(cancellation_token)    (length-prefixed)
                format!(
                    "{}|{}|{}|{}|{}|{}|{}|{}|{}",
                    config_hash,
                    secrets_ct_hash,
                    lp(&hosts_str),
                    lp(&methods_str),
                    s.max_fuel,
                    s.max_memory_mb,
                    s.timeout_ms,
                    s.priority,
                    lp(cancellation_token_str),
                )
            })
            .collect();
        let step_policies_str = step_policies.join(";;");

        format!(
            "pipeline:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.job_id,
            self.workflow_execution_id,
            self.job_nonce,
            self.total_timeout_ms,
            self.share_sandbox,
            self.steps.len(),
            self.user_id,
            // step_hashes is fixed-width hex per element joined by `:`,
            // length-prefix the joined form so the boundary against the
            // next segment is unambiguous.
            lp(&step_hashes_joined),
            lp(&step_integrations_joined),
            // Appended AT THE END per the wire-format stability rule
            // (same reasoning as `JobRequest::signing_payload`). A
            // tamperer on the wire can't downgrade a tier-1 pipeline
            // to tier-2 without invalidating the signature.
            self.max_llm_tier.as_signing_str(),
            // M-5 (pipeline): per-step capability grants appended AT THE END.
            lp(&step_caps_str),
            // H-1 (pipeline): reply_topic appended AT THE END.
            lp(&reply_topic_str),
            // C-2 (2026-05-23): per-step policy (config, hosts, methods,
            // secrets ciphertext, fuel/mem/timeout, priority,
            // cancellation_token) appended AT THE END per the
            // wire-format stability rule.
            lp(&step_policies_str),
        )
        .into_bytes()
    }

    /// Sign the pipeline request using the pre-shared `key`.
    pub fn sign(&mut self, key: &[u8]) -> Result<(), String> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("system time error: {e}"))?
            .as_secs();
        let rand_bytes: [u8; 16] = rand::thread_rng().gen();
        self.job_nonce = format!("{}:{}", ts, hex::encode(rand_bytes));

        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).map_err(|e| format!("HMAC key error: {e}"))?;
        mac.update(&self.signing_payload());
        self.signature = mac.finalize().into_bytes().to_vec();
        Ok(())
    }

    /// Verify the HMAC signature and nonce freshness.
    pub fn verify(&self, key: &[u8], max_age_secs: u64) -> Result<(), String> {
        let parts: Vec<&str> = self.job_nonce.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err("malformed job_nonce".to_string());
        }
        let ts: u64 = parts[0]
            .parse()
            .map_err(|_| "invalid timestamp in job_nonce".to_string())?;
        if hex::decode(parts[1]).is_err() {
            return Err("invalid hex in job_nonce".to_string());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now.saturating_sub(ts) > max_age_secs {
            return Err(format!(
                "job_nonce is too old ({} s, max {})",
                now.saturating_sub(ts),
                max_age_secs
            ));
        }
        if ts.saturating_sub(now) > MAX_FUTURE_SKEW_SECS {
            return Err(format!(
                "job_nonce is in the future ({} s ahead, max {})",
                ts.saturating_sub(now),
                MAX_FUTURE_SKEW_SECS
            ));
        }

        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).map_err(|e| format!("HMAC key error: {e}"))?;
        mac.update(&self.signing_payload());
        mac.verify_slice(&self.signature)
            .map_err(|_| "HMAC signature verification failed".to_string())?;

        // 3. Replay protection: refuse a nonce we have seen before
        // within the freshness window. HMAC alone catches forgery;
        // without this check, anyone with NATS-publish access can
        // capture a signed JobRequest and re-fire it any number of
        // times until ts + max_age_secs expires.
        if !check_and_record_job_nonce(&self.job_nonce, ts, max_age_secs) {
            return Err(format!(
                "job_nonce already seen (replay attempt within {}-second window)",
                max_age_secs
            ));
        }
        Ok(())
    }
}

/// Per-step result within a `PipelineJobResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStepResult {
    pub module_id: Uuid,
    pub status: JobStatus,
    pub output: serde_json::Value,
    pub execution_time_ms: u64,
    pub error: Option<String>,
}

/// Result of a pipeline job returned by the Worker via NATS.
///
/// **Verify-once invariant** (mirrors [`JobResult`]). A signed
/// `PipelineJobResult` MUST be `verify()`-ed exactly once per
/// controller process at its **primary action point** — the site
/// where the result becomes a durable side effect that would be
/// wrong to apply twice (the dispatcher's result-handling path).
/// Any passive observer (audit subscriber, metrics emitter,
/// idempotent-DB-write subscriber, etc.) MUST use
/// [`verify_no_replay`](Self::verify_no_replay) instead.
///
/// Reason: `verify()` mutates the process-local `JOB_NONCE_CACHE` to
/// reject the same nonce on subsequent calls. Two `verify()` calls
/// against the same signed message land in the same shared cache —
/// the second deterministically fails with
/// `"result_nonce already seen"`. This is the same regression class
/// that broke `JobResult` in r300/r301 (see CLAUDE.md "Verify-once
/// rule for signed NATS messages"); adding the split API to
/// `PipelineJobResult` up front is the prophylactic — cheap when the
/// type is born, total when a second subscriber slips in later.
///
/// The worker MUST single-publish each `PipelineJobResult` to ONE
/// NATS subject (reply inbox OR audit topic, branched on `reply_topic`
/// presence). Dual-publishing primes the cache race even when both
/// consumers correctly use the split API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineJobResult {
    pub job_id: Uuid,
    pub overall_status: JobStatus,
    pub step_results: Vec<PipelineStepResult>,
    pub final_output: serde_json::Value,
    pub total_time_ms: u64,
    /// HMAC-SHA256 signature over the canonical result fields.
    pub signature: Vec<u8>,
    /// Nonce for replay prevention.
    pub result_nonce: String,
    /// Self-reported worker identity, HMAC-bound by
    /// [`PipelineJobResult::sign_with_worker_id`]. See [`JobResult::worker_id`]
    /// for the security rationale — same model for both result types.
    #[serde(default)]
    pub worker_id: String,
}

impl PipelineJobResult {
    /// Canonical signing payload.
    ///
    /// Format:
    /// `pipeline_result:{job_id}:{overall_status}:{result_nonce}:
    ///  {total_time_ms}:{sha256(final_output_json)}:{sha256(canonical_step_results)}`
    ///
    /// L-10 (analog): per-step results are now bound. Pre-fix only the
    /// final_output was hashed; an attacker tampering with step outputs
    /// or error strings could mislead audit/error-reporting without
    /// invalidating the signature. Each step contributes
    /// `module_id|status|sha256(output_json)|sha256(error)` (sentinel
    /// "none" for missing error). Joined with `\n` then SHA-256'd to
    /// keep the payload size bounded regardless of step count.
    fn signing_payload(&self) -> Vec<u8> {
        use sha2::Digest;
        let status_str = match self.overall_status {
            JobStatus::Success => "success",
            JobStatus::Failed => "failed",
            JobStatus::TimedOut => "timedout",
        };
        let output_hash = hex::encode(Sha256::digest(self.final_output.to_string().as_bytes()));

        // Canonical per-step digest: each step contributes a fixed-shape
        // line; the complete sequence is hashed once.
        let step_digests: Vec<String> = self
            .step_results
            .iter()
            .map(|s| {
                let s_status = match s.status {
                    JobStatus::Success => "success",
                    JobStatus::Failed => "failed",
                    JobStatus::TimedOut => "timedout",
                };
                let s_output = hex::encode(Sha256::digest(s.output.to_string().as_bytes()));
                let s_error = match s.error.as_deref() {
                    Some(e) => hex::encode(Sha256::digest(e.as_bytes())),
                    None => "none".to_string(),
                };
                format!("{}|{}|{}|{}", s.module_id, s_status, s_output, s_error)
            })
            .collect();
        let step_results_hash =
            hex::encode(Sha256::digest(step_digests.join("\n").as_bytes()));

        format!(
            "pipeline_result:{}:{}:{}:{}:{}:{}:{}",
            self.job_id,
            status_str,
            self.result_nonce,
            self.total_time_ms,
            output_hash,
            // Appended AT THE END per the wire-format stability rule.
            step_results_hash,
            // L-11 (2026-05-22): worker_id appended AT THE END (after the
            // step-results hash) per the same rule. See
            // [`JobResult::signing_payload`] for the full rationale.
            self.worker_id,
        )
        .into_bytes()
    }

    /// Sign the pipeline result using the pre-shared `key`. **Back-compat
    /// wrapper — production worker code should call
    /// [`PipelineJobResult::sign_with_worker_id`] so the worker identity
    /// is bound into the signature.** See [`JobResult::sign`] for the
    /// matching contract on single-node results.
    pub fn sign(&mut self, key: &[u8]) -> Result<(), String> {
        self.sign_with_worker_id(key, "")
    }

    /// Sign the pipeline result and bind the worker's self-reported
    /// identity. Mirror of [`JobResult::sign_with_worker_id`] — same
    /// charset validation, same fail-closed-on-invalid-id contract.
    pub fn sign_with_worker_id(
        &mut self,
        key: &[u8],
        worker_id: &str,
    ) -> Result<(), String> {
        validate_worker_id(worker_id)?;
        self.worker_id = worker_id.to_string();

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("system time error: {e}"))?
            .as_secs();
        let rand_bytes: [u8; 16] = rand::thread_rng().gen();
        self.result_nonce = format!("{}:{}", ts, hex::encode(rand_bytes));

        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).map_err(|e| format!("HMAC key error: {e}"))?;
        mac.update(&self.signing_payload());
        self.signature = mac.finalize().into_bytes().to_vec();
        Ok(())
    }

    /// Verify the HMAC signature, nonce freshness, *and* record the
    /// nonce in the process-local replay cache.
    ///
    /// See [`JobResult::verify`] for the full primary/observer
    /// contract — same rules apply: exactly one primary verifier per
    /// `PipelineJobResult` per controller process. Passive observers
    /// (audit subscribers, metrics emitters) MUST use
    /// [`PipelineJobResult::verify_no_replay`] to avoid the
    /// dual-verify race that broke `JobResult` pre-r300. Today
    /// pipeline results have only one verifier (the engine
    /// dispatcher), so the bug is latent — this API split makes the
    /// safe option available BEFORE a future second consumer is
    /// added, not after the same regression hits production.
    pub fn verify(&self, key: &[u8], max_age_secs: u64) -> Result<(), String> {
        let ts = self.verify_no_replay(key, max_age_secs)?;
        if !check_and_record_job_nonce(&self.result_nonce, ts, max_age_secs) {
            return Err(format!(
                "result_nonce already seen (replay attempt within {}-second window)",
                max_age_secs
            ));
        }
        Ok(())
    }

    /// L-4 typed verifier — same dispatch as
    /// [`JobResult::verify_as`]. Use this method in new code.
    pub fn verify_as(
        &self,
        key: &[u8],
        max_age_secs: u64,
        role: Verifier,
    ) -> Result<(), String> {
        match role {
            Verifier::Primary => self.verify(key, max_age_secs),
            Verifier::Observer => {
                self.verify_no_replay(key, max_age_secs).map(|_| ())
            }
        }
    }

    /// Verify HMAC signature and nonce freshness without recording the
    /// nonce in the replay cache. Returns the parsed timestamp on
    /// success.
    ///
    /// See [`JobResult::verify_no_replay`] for the security contract.
    /// HMAC continues to gate forgery; freshness continues to gate
    /// stale-replay; within-window-replay protection is the
    /// responsibility of the primary `verify()` caller.
    pub fn verify_no_replay(&self, key: &[u8], max_age_secs: u64) -> Result<u64, String> {
        let parts: Vec<&str> = self.result_nonce.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err("malformed result_nonce".to_string());
        }
        if hex::decode(parts[1]).is_err() {
            return Err("invalid hex in result_nonce".to_string());
        }
        let ts: u64 = parts[0]
            .parse()
            .map_err(|_| "invalid timestamp in result_nonce".to_string())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now.saturating_sub(ts) > max_age_secs {
            return Err(format!(
                "result_nonce is too old ({} s, max {})",
                now.saturating_sub(ts),
                max_age_secs
            ));
        }
        if ts.saturating_sub(now) > MAX_FUTURE_SKEW_SECS {
            return Err(format!(
                "result_nonce is in the future ({} s ahead, max {})",
                ts.saturating_sub(now),
                MAX_FUTURE_SKEW_SECS
            ));
        }

        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).map_err(|e| format!("HMAC key error: {e}"))?;
        mac.update(&self.signing_payload());
        mac.verify_slice(&self.signature)
            .map_err(|_| "HMAC signature verification failed".to_string())?;

        Ok(ts)
    }
}

// ============================================================================
// Worker heartbeat
// ============================================================================

/// Heartbeat message published by workers so the controller can track fleet health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerHeartbeat {
    pub worker_id: Uuid,
    /// Self-reported capabilities (e.g. ["wasm", "gpu", "network"]).
    pub capabilities: Vec<String>,
    /// Current CPU usage as a percentage (0.0 – 100.0).
    pub cpu_usage_pct: f32,
    /// HMAC-SHA256 signature for tamper detection.
    #[serde(default)]
    pub signature: Vec<u8>,
    /// Nonce for replay prevention: `"{unix_secs}:{random_hex}"`.
    #[serde(default)]
    pub heartbeat_nonce: String,
}

impl WorkerHeartbeat {
    /// Canonical signing payload — includes capabilities to prevent forgery.
    fn signing_payload(&self) -> Vec<u8> {
        format!(
            "heartbeat:{}:{}:{}:{}",
            self.worker_id,
            self.heartbeat_nonce,
            self.cpu_usage_pct,
            self.capabilities.join(","),
        )
        .into_bytes()
    }

    /// Sign the heartbeat using the pre-shared `key`.
    pub fn sign(&mut self, key: &[u8]) -> Result<(), String> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("system time error: {e}"))?
            .as_secs();
        let rand_bytes: [u8; 16] = rand::thread_rng().gen();
        self.heartbeat_nonce = format!("{}:{}", ts, hex::encode(rand_bytes));

        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).map_err(|e| format!("HMAC key error: {e}"))?;
        mac.update(&self.signing_payload());
        self.signature = mac.finalize().into_bytes().to_vec();
        Ok(())
    }

    /// Verify the HMAC signature and nonce freshness.
    pub fn verify(&self, key: &[u8], max_age_secs: u64) -> Result<(), String> {
        let parts: Vec<&str> = self.heartbeat_nonce.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err("malformed heartbeat_nonce".to_string());
        }
        let ts: u64 = parts[0]
            .parse()
            .map_err(|_| "invalid timestamp in heartbeat_nonce".to_string())?;
        if hex::decode(parts[1]).is_err() {
            return Err("invalid hex in heartbeat_nonce".to_string());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now.saturating_sub(ts) > max_age_secs {
            return Err(format!(
                "heartbeat_nonce is too old ({} s, max {})",
                now.saturating_sub(ts),
                max_age_secs
            ));
        }
        if ts.saturating_sub(now) > MAX_FUTURE_SKEW_SECS {
            return Err(format!(
                "heartbeat_nonce is in the future ({} s ahead, max {})",
                ts.saturating_sub(now),
                MAX_FUTURE_SKEW_SECS
            ));
        }

        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).map_err(|e| format!("HMAC key error: {e}"))?;
        mac.update(&self.signing_payload());
        mac.verify_slice(&self.signature)
            .map_err(|_| "HMAC signature verification failed".to_string())?;

        // 3. Replay protection: refuse a nonce we have seen before
        // within the freshness window. HMAC alone catches forgery;
        // without this check, anyone with NATS-publish access can
        // capture a signed JobRequest and re-fire it any number of
        // times until ts + max_age_secs expires.
        if !check_and_record_job_nonce(&self.heartbeat_nonce, ts, max_age_secs) {
            return Err(format!(
                "heartbeat_nonce already seen (replay attempt within {}-second window)",
                max_age_secs
            ));
        }
        Ok(())
    }
}

// ============================================================================
// Shared-key helper
// ============================================================================

/// Decode the `WORKER_SHARED_KEY` environment variable (64 hex chars → 32 bytes)
/// and return it wrapped in a [`WorkerSharedKey`].
///
/// Both the controller and the worker must call this at startup and fail-fast
/// if the key is absent or malformed.
///
/// # Key rotation
///
/// The key is loaded once via `OnceLock` on both sides — subsequent calls
/// return the cached value. **Rotating this key requires restarting both
/// the controller and all workers simultaneously.** A rolling restart
/// (workers first, then controller, or vice-versa) creates a window where
/// HMAC verification fails and all NATS RPC requests are rejected.
///
/// This is intentional: live rotation of a symmetric signing key without
/// a key-ID negotiation protocol is strictly harder to get right than a
/// coordinated restart, and the failure mode of a botched live rotation
/// (silent signature bypass) is worse than the failure mode of a staggered
/// restart (loud, temporary request rejection).
///
/// [`WorkerSharedKey`]: talos_workflow_engine_core::WorkerSharedKey
pub fn load_worker_shared_key() -> Result<talos_workflow_engine_core::WorkerSharedKey, String> {
    // Support Docker secrets via WORKER_SHARED_KEY_FILE in addition to direct env var
    let hex_key = std::env::var("WORKER_SHARED_KEY")
        .ok()
        .or_else(|| {
            std::env::var("WORKER_SHARED_KEY_FILE").ok().and_then(|path| {
                std::fs::read_to_string(&path)
                    .map(|s| s.trim_end_matches('\n').trim_end_matches('\r').to_string())
                    .ok()
                    .filter(|s| !s.is_empty())
            })
        })
        .ok_or_else(|| {
            "WORKER_SHARED_KEY environment variable is not set (or WORKER_SHARED_KEY_FILE for Docker secrets). \
             Generate with: openssl rand -hex 32"
                .to_string()
        })?;

    let key = hex::decode(hex_key.trim())
        .map_err(|e| format!("WORKER_SHARED_KEY is not valid hex: {e}"))?;

    if key.len() != 32 {
        return Err(format!(
            "WORKER_SHARED_KEY must be 32 bytes (64 hex chars), got {} bytes",
            key.len()
        ));
    }

    Ok(talos_workflow_engine_core::WorkerSharedKey::new(key))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        vec![0x42u8; 32] // 32-byte test key
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let mut secrets = HashMap::new();
        secrets.insert("slack/token".to_string(), "xoxb-secret".to_string());
        secrets.insert("api/key".to_string(), "sk-12345".to_string());

        let encrypted = EncryptedSecrets::encrypt(&secrets, &key).unwrap();
        assert!(!encrypted.ciphertext.is_empty());
        assert_eq!(encrypted.nonce.len(), 12);

        let decrypted = encrypted.decrypt(&key).unwrap();
        assert_eq!(decrypted, secrets);
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let key1 = test_key();
        let key2 = vec![0xFFu8; 32];
        let mut secrets = HashMap::new();
        secrets.insert("key".to_string(), "value".to_string());

        let encrypted = EncryptedSecrets::encrypt(&secrets, &key1).unwrap();
        let result = encrypted.decrypt(&key2);
        assert!(result.is_err());
    }

    /// L-1: AAD round-trip — encrypt with AAD, decrypt with the same
    /// AAD, get the original plaintext back.
    #[test]
    fn aad_round_trip_succeeds() {
        let key = test_key();
        let mut secrets = HashMap::new();
        secrets.insert("anthropic/api_key".to_string(), "sk-xyz".to_string());
        let aad = b"job:abc-123";
        let enc = EncryptedSecrets::encrypt_with_aad(&secrets, &key, aad).unwrap();
        let dec = enc.decrypt_with_aad(&key, aad).unwrap();
        assert_eq!(dec, secrets);
    }

    /// L-1: decrypting with a DIFFERENT AAD must fail. This is the
    /// core anti-transposition property — an attacker who lifts an
    /// EncryptedSecrets blob from one JobRequest into another (under
    /// the same shared key) cannot decrypt the lifted ciphertext if
    /// the new JobRequest's AAD differs from the original.
    #[test]
    fn aad_mismatch_fails_decryption() {
        let key = test_key();
        let mut secrets = HashMap::new();
        secrets.insert("anthropic/api_key".to_string(), "sk-xyz".to_string());
        let enc = EncryptedSecrets::encrypt_with_aad(&secrets, &key, b"job:abc").unwrap();
        // Same key, same ciphertext — but different AAD context.
        let bad = enc.decrypt_with_aad(&key, b"job:zzz");
        assert!(
            bad.is_err(),
            "decrypt with different AAD must fail (anti-transposition gate)"
        );
        let msg = bad.unwrap_err();
        assert!(
            msg.contains("decryption failed"),
            "expected GCM tag error, got: {msg}"
        );
    }

    /// L-1: backwards compatibility — `encrypt`/`decrypt` (no AAD)
    /// continue to interoperate with each other. Critical so
    /// existing dispatch paths that haven't migrated to the AAD form
    /// keep working.
    #[test]
    fn no_aad_round_trip_still_works() {
        let key = test_key();
        let mut secrets = HashMap::new();
        secrets.insert("k".to_string(), "v".to_string());
        let enc = EncryptedSecrets::encrypt(&secrets, &key).unwrap();
        let dec = enc.decrypt(&key).unwrap();
        assert_eq!(dec, secrets);
    }

    /// L-1: encrypt-no-AAD + decrypt-with-AAD must fail. Confirms the
    /// AES-GCM tag binding is one-way — there's no "matches when one
    /// side is empty" silent-success path.
    #[test]
    fn mixed_aad_modes_fail_decryption() {
        let key = test_key();
        let mut secrets = HashMap::new();
        secrets.insert("k".to_string(), "v".to_string());
        let enc = EncryptedSecrets::encrypt(&secrets, &key).unwrap();
        // Encrypted with empty AAD; decrypt with non-empty AAD.
        let bad = enc.decrypt_with_aad(&key, b"any");
        assert!(bad.is_err());

        let enc2 = EncryptedSecrets::encrypt_with_aad(&secrets, &key, b"any").unwrap();
        // Encrypted with AAD; decrypt with empty (legacy `decrypt`).
        let bad2 = enc2.decrypt(&key);
        assert!(bad2.is_err());
    }

    #[test]
    fn test_replay_within_window_is_rejected() {
        // Sign a request, verify it once (admitted), then verify the
        // same bytes again — the nonce cache should reject the second
        // verify as a replay even though HMAC + freshness still pass.
        let key = test_key();
        let mut req = JobRequest {
            job_id: Uuid::new_v4(),
            workflow_execution_id: Uuid::new_v4(),
            module_uri: "wasm://module/v1".to_string(),
            input_payload: serde_json::json!({"replay_test": true}),
            encrypted_secrets: EncryptedSecrets::default(),
            timeout_ms: 30000,
            priority: 100,
            deadline_unix_secs: 0,
            cancellation_token: None,
            allowed_hosts: vec![],
            allowed_methods: vec![],
            allowed_secrets: vec![],
            allowed_sql_operations: vec![],
            allow_tier2_exposure: false,
            signature: vec![],
            max_llm_tier: LlmTier::default(),
            job_nonce: String::new(),
            actor_id: None,
            wasm_bytes: None,
            capability_world: None,
            integration_name: None,
            user_id: Uuid::nil(),
            expected_wasm_hash: None,
            max_fuel: 0,
            dry_run: false,
            reply_topic: None,
        };
        req.sign(&key).unwrap();

        // First verification admits the nonce.
        req.verify(&key, 300).expect("first verify should succeed");

        // Second verification of the same JobRequest must now fail —
        // the nonce was already recorded. Error message should mention
        // replay so operators can correlate logs.
        let err = req
            .verify(&key, 300)
            .expect_err("second verify should be rejected as replay");
        assert!(
            err.contains("replay"),
            "replay rejection message should contain 'replay'; got: {err}"
        );
    }

    #[test]
    fn test_sign_and_verify() {
        let key = test_key();
        let mut req = JobRequest {
            job_id: Uuid::new_v4(),
            workflow_execution_id: Uuid::new_v4(),
            module_uri: "wasm://module/v1".to_string(),
            input_payload: serde_json::json!({}),
            encrypted_secrets: EncryptedSecrets::default(),
            timeout_ms: 30000,
            priority: 100,
            deadline_unix_secs: 0,
            cancellation_token: None,
            allowed_hosts: vec![],
            allowed_methods: vec![],
            allowed_secrets: vec![],
            allowed_sql_operations: vec![],
            allow_tier2_exposure: false,
            signature: vec![],
            max_llm_tier: LlmTier::default(),
            job_nonce: String::new(),
            actor_id: None,
            wasm_bytes: None,
            capability_world: None,
            integration_name: None,
            user_id: Uuid::nil(),
            expected_wasm_hash: None,
            max_fuel: 0,
            dry_run: false,
            reply_topic: None,
        };

        req.sign(&key).unwrap();
        assert!(!req.signature.is_empty());
        assert!(!req.job_nonce.is_empty());

        // Verification should pass
        req.verify(&key, 300).unwrap();
    }

    #[test]
    fn test_tampered_signature_fails() {
        let key = test_key();
        let mut req = JobRequest {
            job_id: Uuid::new_v4(),
            workflow_execution_id: Uuid::new_v4(),
            module_uri: "wasm://module/v1".to_string(),
            input_payload: serde_json::json!({}),
            encrypted_secrets: EncryptedSecrets::default(),
            timeout_ms: 30000,
            priority: 100,
            deadline_unix_secs: 0,
            cancellation_token: None,
            allowed_hosts: vec![],
            allowed_methods: vec![],
            allowed_secrets: vec![],
            allowed_sql_operations: vec![],
            allow_tier2_exposure: false,
            signature: vec![],
            max_llm_tier: LlmTier::default(),
            job_nonce: String::new(),
            actor_id: None,
            wasm_bytes: None,
            capability_world: None,
            integration_name: None,
            user_id: Uuid::nil(),
            expected_wasm_hash: None,
            max_fuel: 0,
            dry_run: false,
            reply_topic: None,
        };
        req.sign(&key).unwrap();
        req.module_uri = "wasm://evil-module/v1".to_string(); // tamper
        let result = req.verify(&key, 300);
        assert!(result.is_err());
    }

    #[test]
    fn test_job_result_sign_and_verify() {
        let key = test_key();
        let mut result = JobResult {
            job_id: Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({"answer": 42}),
            logs: vec![],
            execution_time_ms: 150,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };

        result.sign(&key).unwrap();
        assert!(!result.signature.is_empty());
        assert!(!result.result_nonce.is_empty());

        result.verify(&key, 300).unwrap();
    }

    #[test]
    fn test_job_result_tampered_fails() {
        let key = test_key();
        let mut result = JobResult {
            job_id: Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({"answer": 42}),
            logs: vec![],
            execution_time_ms: 150,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
        result.sign(&key).unwrap();
        result.output_payload = serde_json::json!({"answer": 99}); // tamper
        assert!(result.verify(&key, 300).is_err());
    }

    /// L-4: `verify_as(Verifier::Primary)` matches `verify()` exactly —
    /// records the nonce, so a second `Primary` call against the same
    /// result trips the replay cache. `verify_as(Verifier::Observer)`
    /// matches `verify_no_replay()` — no cache mutation, so repeated
    /// `Observer` calls succeed and an `Observer` followed by a
    /// `Primary` also succeeds (the primary records the nonce on its
    /// first call).
    #[test]
    fn verifier_primary_records_replay_observer_does_not() {
        let key = test_key();
        let mut a = JobResult {
            job_id: Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({}),
            logs: vec![],
            execution_time_ms: 1,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
        a.sign(&key).unwrap();

        // Observer is idempotent — repeated calls succeed.
        a.verify_as(&key, 300, Verifier::Observer).unwrap();
        a.verify_as(&key, 300, Verifier::Observer).unwrap();

        // Primary records the nonce — second Primary call must fail.
        a.verify_as(&key, 300, Verifier::Primary).unwrap();
        let second = a.verify_as(&key, 300, Verifier::Primary);
        assert!(
            second.is_err(),
            "second Primary verify must trip the replay cache"
        );
        let msg = second.unwrap_err();
        assert!(
            msg.contains("already seen"),
            "expected replay-cache error, got: {msg}"
        );
    }

    /// L-4: an Observer-first-then-Primary sequence is the canonical
    /// production pattern (audit subscriber runs concurrently with
    /// the primary). Both must succeed; only the second Primary
    /// would fail (covered by the test above).
    #[test]
    fn verifier_observer_then_primary_both_succeed() {
        let key = test_key();
        let mut a = JobResult {
            job_id: Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({}),
            logs: vec![],
            execution_time_ms: 1,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
        a.sign(&key).unwrap();
        a.verify_as(&key, 300, Verifier::Observer).unwrap();
        a.verify_as(&key, 300, Verifier::Primary).unwrap();
    }

    /// L-4: tampering still gates both roles via the HMAC check.
    #[test]
    fn verifier_rejects_tampered_signature_in_both_roles() {
        let key = test_key();
        let mut a = JobResult {
            job_id: Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({"answer": 42}),
            logs: vec![],
            execution_time_ms: 1,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
        a.sign(&key).unwrap();
        a.output_payload = serde_json::json!({"answer": 99});
        assert!(a.verify_as(&key, 300, Verifier::Observer).is_err());
        assert!(a.verify_as(&key, 300, Verifier::Primary).is_err());
    }

    #[test]
    fn test_tampered_allowed_methods_fails() {
        let key = test_key();
        let mut req = JobRequest {
            job_id: Uuid::new_v4(),
            workflow_execution_id: Uuid::new_v4(),
            module_uri: "wasm://module/v1".to_string(),
            input_payload: serde_json::json!({}),
            encrypted_secrets: EncryptedSecrets::default(),
            timeout_ms: 30000,
            priority: 100,
            deadline_unix_secs: 0,
            cancellation_token: None,
            allowed_hosts: vec!["api.example.com".to_string()],
            allowed_methods: vec!["GET".to_string()],
            allowed_secrets: vec![],
            allowed_sql_operations: vec![],
            allow_tier2_exposure: false,
            signature: vec![],
            max_llm_tier: LlmTier::default(),
            job_nonce: String::new(),
            actor_id: None,
            wasm_bytes: None,
            capability_world: None,
            integration_name: None,
            user_id: Uuid::nil(),
            expected_wasm_hash: None,
            max_fuel: 0,
            dry_run: false,
            reply_topic: None,
        };
        req.sign(&key).unwrap();
        // An attacker cannot escalate from GET-only to POST by modifying the field.
        req.allowed_methods = vec!["GET".to_string(), "POST".to_string()];
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered allowed_methods must fail verification"
        );
    }

    #[test]
    fn test_allowed_methods_order_independent() {
        let key = test_key();
        let mut req = JobRequest {
            job_id: Uuid::new_v4(),
            workflow_execution_id: Uuid::new_v4(),
            module_uri: "wasm://module/v1".to_string(),
            input_payload: serde_json::json!({}),
            encrypted_secrets: EncryptedSecrets::default(),
            timeout_ms: 30000,
            priority: 100,
            deadline_unix_secs: 0,
            cancellation_token: None,
            allowed_hosts: vec![],
            allowed_methods: vec!["POST".to_string(), "GET".to_string()],
            allowed_secrets: vec![],
            allowed_sql_operations: vec![],
            allow_tier2_exposure: false,
            signature: vec![],
            max_llm_tier: LlmTier::default(),
            job_nonce: String::new(),
            actor_id: None,
            wasm_bytes: None,
            capability_world: None,
            integration_name: None,
            user_id: Uuid::nil(),
            expected_wasm_hash: None,
            max_fuel: 0,
            dry_run: false,
            reply_topic: None,
        };
        req.sign(&key).unwrap();
        // Reordering must not affect verification (sorted before hashing).
        req.allowed_methods = vec!["GET".to_string(), "POST".to_string()];
        req.verify(&key, 300)
            .expect("order-independent allowed_methods must still verify");
    }

    #[test]
    fn test_job_result_unsigned_fails() {
        let key = test_key();
        let result = JobResult {
            job_id: Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({}),
            logs: vec![],
            execution_time_ms: 0,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
        assert!(result.verify(&key, 300).is_err());
    }

    /// Helper for the new wire-format binding tests below: build a
    /// minimal JobRequest with the named overrides applied. Callers
    /// `.sign()` themselves before tampering / re-verifying.
    fn make_test_request(actor_id: Option<Uuid>) -> JobRequest {
        JobRequest {
            job_id: Uuid::new_v4(),
            workflow_execution_id: Uuid::new_v4(),
            module_uri: "wasm://m/v1".to_string(),
            input_payload: serde_json::json!({}),
            encrypted_secrets: EncryptedSecrets::default(),
            timeout_ms: 30000,
            priority: 100,
            deadline_unix_secs: 0,
            cancellation_token: None,
            allowed_hosts: vec![],
            allowed_methods: vec![],
            allowed_secrets: vec!["slack/token".to_string()],
            allowed_sql_operations: vec!["SELECT".to_string()],
            allow_tier2_exposure: false,
            signature: vec![],
            max_llm_tier: LlmTier::default(),
            job_nonce: String::new(),
            actor_id,
            wasm_bytes: None,
            capability_world: None,
            integration_name: None,
            user_id: Uuid::nil(),
            expected_wasm_hash: None,
            max_fuel: 0,
            dry_run: false,
            reply_topic: None,
        }
    }

    /// M-4: tampering with `actor_id` MUST invalidate the signature.
    /// Pre-fix the field was excluded from the signing payload, so a
    /// NATS-channel attacker could redirect the worker's downstream
    /// `MemoryRpcRequest` writes to a different actor's memory namespace.
    #[test]
    fn tampered_actor_id_fails_verification() {
        let key = test_key();
        let actor_a = Uuid::new_v4();
        let actor_b = Uuid::new_v4();
        let mut req = make_test_request(Some(actor_a));
        req.sign(&key).unwrap();

        // Tamper: swap actor_a → actor_b. Pre-fix this passed.
        req.actor_id = Some(actor_b);
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered actor_id must fail verification (M-4)"
        );
    }

    /// M-4: actor_id None → Some MUST also be tamper-evident.
    #[test]
    fn actor_id_none_to_some_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.sign(&key).unwrap();

        req.actor_id = Some(Uuid::new_v4());
        assert!(
            req.verify(&key, 300).is_err(),
            "swapping actor_id from None to Some must fail (M-4)"
        );
    }

    /// M-5: tampering with `allowed_secrets` MUST invalidate signature.
    /// Even though encrypted_secrets is the active enforcement layer,
    /// capability claims should be self-consistent with the signed
    /// message.
    #[test]
    fn tampered_allowed_secrets_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.sign(&key).unwrap();

        req.allowed_secrets = vec!["openai/api_key".to_string(), "*".to_string()];
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered allowed_secrets must fail verification (M-5)"
        );
    }

    /// M-5: tampering with `allow_tier2_exposure` MUST invalidate.
    /// Pre-fix an attacker could flip the tier-2 bit on the wire,
    /// granting the module Tier-2 capability the operator never
    /// intended.
    #[test]
    fn tampered_allow_tier2_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.allow_tier2_exposure = false;
        req.sign(&key).unwrap();

        req.allow_tier2_exposure = true;
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered allow_tier2_exposure must fail verification (M-5)"
        );
    }

    /// M-5: tampering with `allowed_sql_operations` MUST invalidate.
    #[test]
    fn tampered_allowed_sql_operations_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.sign(&key).unwrap();

        req.allowed_sql_operations =
            vec!["SELECT".to_string(), "INSERT".to_string(), "DELETE".to_string()];
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered allowed_sql_operations must fail verification (M-5)"
        );
    }

    /// M-5: order-independence — re-ordering allowed_secrets must NOT
    /// invalidate. Same property as `test_allowed_methods_order_independent`
    /// but for the new fields.
    #[test]
    fn allowed_secrets_order_independent() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.allowed_secrets = vec!["b".to_string(), "a".to_string(), "c".to_string()];
        req.sign(&key).unwrap();

        req.allowed_secrets = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        req.verify(&key, 300)
            .expect("order-independent allowed_secrets must still verify (M-5)");
    }

    /// L-9: payload-collision regression guard. Two semantically-distinct
    /// requests whose `module_uri` + `job_nonce` could collide under the
    /// pre-length-prefix scheme MUST produce different signatures.
    /// Pre-fix the colon delimiter could collide between
    /// `(module_uri="a", job_nonce="b:c")` and `(module_uri="a:b", job_nonce="c")`
    /// — same signing-payload bytes. The length-prefix on module_uri
    /// disambiguates.
    #[test]
    fn length_prefix_prevents_module_uri_collision() {
        let key = test_key();
        let mut req_a = make_test_request(None);
        req_a.module_uri = "a".to_string();
        req_a.sign(&key).unwrap();

        let mut req_b = make_test_request(None);
        // Try to construct a colliding payload by stuffing bytes into
        // module_uri that, under the pre-fix concatenation, would have
        // matched req_a's bytes. With length-prefixing the byte counts
        // differ so no collision is possible.
        req_b.module_uri = "a:b".to_string();
        req_b.job_id = req_a.job_id;
        req_b.workflow_execution_id = req_a.workflow_execution_id;
        req_b.job_nonce = req_a.job_nonce.clone();
        // Sign req_b with its own values but check that the resulting
        // signing_payload bytes differ from req_a's even under
        // adversarial field choices. (Direct inspection of the payload
        // bytes — we don't need to actually swap signatures.)
        let payload_a = req_a.signing_payload();
        let payload_b = req_b.signing_payload();
        assert_ne!(
            payload_a, payload_b,
            "length-prefixed module_uri must prevent collision between adversarially-chosen field values (L-9)"
        );
    }

    /// L-10: tampering with `JobResult.logs` MUST invalidate the
    /// signature. Pre-fix the logs field was unsigned; an attacker
    /// could inject misleading audit-trail entries in flight.
    #[test]
    fn tampered_job_result_logs_fails_verification() {
        let key = test_key();
        let mut result = JobResult {
            job_id: Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({"answer": 42}),
            logs: vec!["legit log line".to_string()],
            execution_time_ms: 100,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
        result.sign(&key).unwrap();

        // Tamper: append a misleading log line.
        result
            .logs
            .push("FAKE: user authorized critical action".to_string());
        assert!(
            result.verify(&key, 300).is_err(),
            "tampered logs must fail verification (L-10)"
        );
    }

    /// H-1: tampering with `reply_topic` MUST invalidate the signature.
    /// Pre-fix the field was excluded from the signing payload, so a
    /// NATS-channel attacker could redirect the worker's signed
    /// JobResult to an attacker-controlled subject.
    #[test]
    fn tampered_reply_topic_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.reply_topic = Some("_INBOX.legit.abc123".to_string());
        req.sign(&key).unwrap();

        // Tamper: swap to a malicious subject.
        req.reply_topic = Some("talos.admin.commands".to_string());
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered reply_topic must fail verification (H-1)"
        );
    }

    /// H-1: reply_topic None → Some MUST also be tamper-evident
    /// (sentinel `-` differs from a real subject).
    #[test]
    fn reply_topic_none_to_some_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.sign(&key).unwrap();
        req.reply_topic = Some("talos.admin.commands".to_string());
        assert!(
            req.verify(&key, 300).is_err(),
            "injecting reply_topic must fail verification (H-1)"
        );
    }

    /// H-1: reply_topic Some → None MUST also be tamper-evident
    /// (stripping the field shouldn't downgrade verification to the
    /// legacy "trust msg.reply" path).
    #[test]
    fn reply_topic_some_to_none_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.reply_topic = Some("_INBOX.legit.abc123".to_string());
        req.sign(&key).unwrap();
        req.reply_topic = None;
        assert!(
            req.verify(&key, 300).is_err(),
            "stripping reply_topic must fail verification (H-1)"
        );
    }

    /// H-1: tampering at the pipeline level — same property as
    /// JobRequest. PipelineJobRequest tampering is per-pipeline,
    /// not per-step, so we tamper the field at the root.
    #[test]
    fn tampered_pipeline_reply_topic_fails_verification() {
        let key = test_key();
        let mut req = PipelineJobRequest {
            job_id: Uuid::new_v4(),
            workflow_execution_id: Uuid::new_v4(),
            steps: vec![],
            total_timeout_ms: 60_000,
            share_sandbox: false,
            signature: vec![],
            job_nonce: String::new(),
            user_id: Uuid::nil(),
            max_llm_tier: LlmTier::default(),
            reply_topic: Some("_INBOX.legit.xyz".to_string()),
        };
        req.sign(&key).unwrap();
        req.reply_topic = Some("talos.admin.commands".to_string());
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered pipeline reply_topic must fail verification (H-1)"
        );
    }

    /// L-10: empty-logs case — signature must round-trip correctly.
    #[test]
    fn job_result_with_empty_logs_round_trips() {
        let key = test_key();
        let mut result = JobResult {
            job_id: Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({}),
            logs: vec![],
            execution_time_ms: 0,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
        };
        result.sign(&key).unwrap();
        result.verify(&key, 300).expect("empty-logs result should verify");
    }

    // ========================================================================
    // Wasm-security review 2026-05-23: tampering tests for the H-3 / H-7 / C-2
    // signing-payload extensions.
    // ========================================================================
    //
    // Each `tampered_<field>_fails_verification` test follows the same shape:
    // 1. Build a clean request and sign it.
    // 2. Mutate exactly one field that USED to be unsigned.
    // 3. Re-verify and assert failure.
    //
    // Pre-fix, every one of these mutations would have passed verification —
    // anyone with NATS publish on the job subject could perform the mutation
    // in flight without the worker detecting it.

    /// H-3: `capability_world` is now HMAC-bound. Pre-fix an attacker could
    /// flip `minimal-node` → `automation-node` to trick the worker into
    /// selecting a wider tiered linker (important for precompiled WASM
    /// where the embedded world name may not survive Wizer).
    #[test]
    fn tampered_capability_world_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.capability_world = Some("minimal-node".to_string());
        req.sign(&key).unwrap();

        req.capability_world = Some("automation-node".to_string());
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered capability_world must fail verification (H-3)"
        );
    }

    /// H-3: stripping the `capability_world` (Some → None) must also be
    /// tamper-evident — the sentinel `-` for None makes the absence
    /// signed.
    #[test]
    fn capability_world_some_to_none_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.capability_world = Some("minimal-node".to_string());
        req.sign(&key).unwrap();

        req.capability_world = None;
        assert!(
            req.verify(&key, 300).is_err(),
            "stripping capability_world must fail verification (H-3)"
        );
    }

    /// H-7: `dry_run` is now HMAC-bound. Pre-fix an attacker could flip
    /// `true → false` to convert a planning-mode run into a real one
    /// (real HTTP POSTs, real webhooks).
    #[test]
    fn tampered_dry_run_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.dry_run = true;
        req.sign(&key).unwrap();

        req.dry_run = false;
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered dry_run must fail verification (H-7)"
        );
    }

    /// H-7: `priority` is now HMAC-bound. Pre-fix an attacker could
    /// promote arbitrary jobs to starve legitimate high-priority work.
    #[test]
    fn tampered_priority_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.priority = 100;
        req.sign(&key).unwrap();

        req.priority = 1;
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered priority must fail verification (H-7)"
        );
    }

    /// H-7: `deadline_unix_secs` is now HMAC-bound. Pre-fix an attacker
    /// could set a past timestamp to force premature failure.
    #[test]
    fn tampered_deadline_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.deadline_unix_secs = 0;
        req.sign(&key).unwrap();

        req.deadline_unix_secs = 1;
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered deadline_unix_secs must fail verification (H-7)"
        );
    }

    /// H-7: `cancellation_token` is now HMAC-bound. Pre-fix an attacker
    /// could strip the token, leaving an in-flight job uncancellable.
    #[test]
    fn tampered_cancellation_token_fails_verification() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.cancellation_token = Some("token-abc".to_string());
        req.sign(&key).unwrap();

        req.cancellation_token = None;
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered cancellation_token must fail verification (H-7)"
        );
    }

    /// H-3 + H-7 (combined positive case): a clean round-trip with all
    /// the newly-bound fields populated must verify.
    #[test]
    fn newly_bound_fields_round_trip() {
        let key = test_key();
        let mut req = make_test_request(None);
        req.capability_world = Some("automation-node".to_string());
        req.dry_run = true;
        req.priority = 200;
        req.deadline_unix_secs = 1_700_000_000;
        req.cancellation_token = Some("abc-123".to_string());
        req.sign(&key).unwrap();

        req.verify(&key, 300).expect(
            "clean request with newly-bound H-3/H-7 fields must verify",
        );
    }

    // ========================================================================
    // C-2: PipelineJobRequest::signing_payload extension tests.
    // ========================================================================
    //
    // Pre-fix the pipeline signing payload bound only step_hashes,
    // step_integrations, step_caps (allowed_secrets / sql / tier2),
    // max_llm_tier, reply_topic, and the job-level fields — it did NOT
    // bind per-step config, allowed_hosts, allowed_methods, encrypted
    // secrets ciphertext, max_fuel, max_memory_mb, timeout_ms, priority,
    // or cancellation_token. Each of the tests below mutates exactly
    // one of those fields and asserts the signature no longer verifies.

    fn make_test_pipeline_step() -> PipelineStep {
        PipelineStep {
            module_id: Uuid::new_v4(),
            module_uri: "wasm://m/v1".to_string(),
            wasm_bytes: None,
            config: serde_json::json!({"input": "original"}),
            allowed_hosts: vec!["api.example.com".to_string()],
            allowed_methods: vec!["GET".to_string()],
            allowed_secrets: vec!["slack/token".to_string()],
            allowed_sql_operations: vec!["SELECT".to_string()],
            allow_tier2_exposure: false,
            encrypted_secrets: EncryptedSecrets::default(),
            max_fuel: 1_000_000,
            max_memory_mb: 64,
            timeout_ms: 30_000,
            priority: 100,
            cancellation_token: None,
            expected_wasm_hash: None,
            integration_name: None,
        }
    }

    fn make_test_pipeline(steps: Vec<PipelineStep>) -> PipelineJobRequest {
        PipelineJobRequest {
            job_id: Uuid::new_v4(),
            workflow_execution_id: Uuid::new_v4(),
            steps,
            total_timeout_ms: 60_000,
            share_sandbox: false,
            signature: vec![],
            job_nonce: String::new(),
            user_id: Uuid::nil(),
            max_llm_tier: LlmTier::default(),
            reply_topic: None,
        }
    }

    /// C-2: pipeline `config` is now HMAC-bound. Pre-fix the worker
    /// would execute the signed-and-attested module against
    /// attacker-supplied config under the signed secrets blob.
    #[test]
    fn pipeline_tampered_step_config_fails_verification() {
        let key = test_key();
        let mut req = make_test_pipeline(vec![make_test_pipeline_step()]);
        req.sign(&key).unwrap();

        req.steps[0].config = serde_json::json!({"input": "tampered"});
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered pipeline step config must fail verification (C-2)"
        );
    }

    /// C-2: pipeline `allowed_hosts` is now HMAC-bound. Pre-fix an
    /// attacker could widen the allowlist to exfiltrate via
    /// attacker-controlled URL + signed `vault://` header.
    #[test]
    fn pipeline_tampered_step_hosts_fails_verification() {
        let key = test_key();
        let mut req = make_test_pipeline(vec![make_test_pipeline_step()]);
        req.sign(&key).unwrap();

        req.steps[0].allowed_hosts.push("attacker.example".to_string());
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered pipeline allowed_hosts must fail verification (C-2)"
        );
    }

    /// C-2: pipeline `allowed_methods` is now HMAC-bound.
    #[test]
    fn pipeline_tampered_step_methods_fails_verification() {
        let key = test_key();
        let mut req = make_test_pipeline(vec![make_test_pipeline_step()]);
        req.sign(&key).unwrap();

        req.steps[0].allowed_methods.push("DELETE".to_string());
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered pipeline allowed_methods must fail verification (C-2)"
        );
    }

    /// C-2: pipeline `encrypted_secrets.ciphertext` is now HMAC-bound.
    /// Pre-fix the AAD (workflow_execution_id) was shared across all
    /// steps in one pipeline, so an attacker could swap one step's
    /// ciphertext for another's and the worker would happily decrypt.
    #[test]
    fn pipeline_tampered_step_secrets_fails_verification() {
        let key = test_key();
        let mut req = make_test_pipeline(vec![make_test_pipeline_step()]);
        req.sign(&key).unwrap();

        req.steps[0].encrypted_secrets.ciphertext = vec![0xff; 32];
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered pipeline encrypted_secrets must fail verification (C-2)"
        );
    }

    /// C-2: pipeline `max_fuel` / `max_memory_mb` / `timeout_ms` are now
    /// HMAC-bound. Pre-fix an attacker could inflate any of them for
    /// resource exhaustion / cost overrun.
    #[test]
    fn pipeline_tampered_step_resource_caps_fail_verification() {
        let key = test_key();
        let mut req = make_test_pipeline(vec![make_test_pipeline_step()]);
        req.sign(&key).unwrap();

        // Inflate fuel.
        req.steps[0].max_fuel = 1_000_000_000;
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered pipeline max_fuel must fail (C-2)"
        );
        req.steps[0].max_fuel = 1_000_000;
        req.signature = vec![]; // resign baseline
        req.sign(&key).unwrap();

        // Inflate memory.
        req.steps[0].max_memory_mb = 4096;
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered pipeline max_memory_mb must fail (C-2)"
        );
        req.steps[0].max_memory_mb = 64;
        req.signature = vec![];
        req.sign(&key).unwrap();

        // Inflate timeout.
        req.steps[0].timeout_ms = 600_000;
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered pipeline timeout_ms must fail (C-2)"
        );
    }

    /// C-2: pipeline `priority` is now HMAC-bound.
    #[test]
    fn pipeline_tampered_step_priority_fails_verification() {
        let key = test_key();
        let mut req = make_test_pipeline(vec![make_test_pipeline_step()]);
        req.sign(&key).unwrap();

        req.steps[0].priority = 1;
        assert!(
            req.verify(&key, 300).is_err(),
            "tampered pipeline priority must fail verification (C-2)"
        );
    }

    /// C-2: pipeline `cancellation_token` is now HMAC-bound. None → Some
    /// and Some → None must both fail.
    #[test]
    fn pipeline_tampered_step_cancellation_token_fails_verification() {
        let key = test_key();
        let mut req = make_test_pipeline(vec![make_test_pipeline_step()]);
        req.steps[0].cancellation_token = Some("tok-1".to_string());
        req.sign(&key).unwrap();

        req.steps[0].cancellation_token = None;
        assert!(
            req.verify(&key, 300).is_err(),
            "stripping pipeline cancellation_token must fail (C-2)"
        );
    }

    /// C-2: clean round-trip — a pipeline with all the C-2 fields
    /// populated must verify successfully.
    #[test]
    fn pipeline_signing_round_trip() {
        let key = test_key();
        let mut step = make_test_pipeline_step();
        step.config = serde_json::json!({"k": "v", "n": 42});
        step.cancellation_token = Some("tok-xyz".to_string());
        let mut req = make_test_pipeline(vec![step]);
        req.sign(&key).unwrap();

        req.verify(&key, 300).expect(
            "clean pipeline with C-2 fields populated must verify",
        );
    }

    /// C-2: per-step independence — mutating step 1 must invalidate the
    /// whole signature even though step 0 is untouched.
    #[test]
    fn pipeline_tampered_second_step_config_fails() {
        let key = test_key();
        let s0 = make_test_pipeline_step();
        let mut s1 = make_test_pipeline_step();
        s1.config = serde_json::json!({"step": 1});
        let mut req = make_test_pipeline(vec![s0, s1]);
        req.sign(&key).unwrap();

        // Tamper the SECOND step's config.
        req.steps[1].config = serde_json::json!({"step": "tampered"});
        assert!(
            req.verify(&key, 300).is_err(),
            "tampering a non-first step's config must still fail (C-2)"
        );
    }

    /// C-2: order-independence — re-ordering `allowed_hosts` within a
    /// step must NOT invalidate. Mirrors the existing
    /// `test_allowed_methods_order_independent` invariant.
    #[test]
    fn pipeline_step_hosts_order_independent() {
        let key = test_key();
        let mut step = make_test_pipeline_step();
        step.allowed_hosts = vec!["b.com".to_string(), "a.com".to_string()];
        let mut req = make_test_pipeline(vec![step]);
        req.sign(&key).unwrap();

        req.steps[0].allowed_hosts = vec!["a.com".to_string(), "b.com".to_string()];
        req.verify(&key, 300)
            .expect("re-ordered allowed_hosts must still verify");
    }
}
