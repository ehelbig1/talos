//! Shared job protocol between Controller and Workers.
//!
//! Security model:
//! - Secrets are AES-256-GCM encrypted before transmission over NATS.
//! - Every JobRequest is HMAC-SHA256 signed using a pre-shared key
//!   (WORKER_SHARED_KEY) to prevent injection of malicious jobs.
//! - A `job_nonce` (timestamp + random hex) is included to prevent replay attacks.

use aes_gcm::{
    aead::{Aead, KeyInit},
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
pub fn is_external_llm_host(host_lower: &str) -> bool {
    EXTERNAL_LLM_HOSTS
        .iter()
        .any(|reserved| *reserved == host_lower || host_lower.ends_with(&format!(".{reserved}")))
}

/// True iff `vault_path` references a Tier-2 LLM provider's credentials.
/// Used to block `vault://anthropic/api_key` substitution in HTTP headers
/// for Tier-1 jobs — the tier gate on `llm::*` host fns doesn't help if
/// the guest fetches directly and interpolates the key through
/// `resolve_vault_header`.
pub fn is_tier2_llm_vault_path(vault_path: &str) -> bool {
    is_llm_provider_vault_path(vault_path)
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
}

impl EncryptedSecrets {
    /// Encrypt a secrets map using AES-256-GCM.
    ///
    /// `key` must be exactly 32 bytes (256 bits).
    pub fn encrypt(secrets: &HashMap<String, String>, key: &[u8]) -> Result<Self, String> {
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
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| format!("encrypt secrets: {e}"))?;

        Ok(Self {
            ciphertext,
            nonce: nonce_bytes.to_vec(),
        })
    }

    /// Decrypt back into a secrets map.
    ///
    /// `key` must be the same 32-byte key used for encryption.
    pub fn decrypt(&self, key: &[u8]) -> Result<HashMap<String, String>, String> {
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
            .decrypt(nonce, self.ciphertext.as_ref())
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
    /// "automation-node").  Not included in the HMAC signing payload — it is a
    /// performance hint, not a capability grant (the linker enforces real
    /// security at instantiation time).
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

        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
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
            "{}:{}:{}:{}:{}:{}",
            self.job_id,
            status_str,
            self.result_nonce,
            output_hash,
            self.execution_time_ms,
            // L-10: appended AT THE END per the wire-format stability rule.
            logs_hash,
        )
        .into_bytes()
    }

    /// Sign the result using the pre-shared `key`.
    ///
    /// Sets `self.signature` and `self.result_nonce`.
    /// Call this after all other fields have been populated.
    pub fn sign(&mut self, key: &[u8]) -> Result<(), String> {
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

        format!(
            "pipeline:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
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
            "pipeline_result:{}:{}:{}:{}:{}:{}",
            self.job_id,
            status_str,
            self.result_nonce,
            self.total_time_ms,
            output_hash,
            // Appended AT THE END per the wire-format stability rule.
            step_results_hash,
        )
        .into_bytes()
    }

    /// Sign the pipeline result using the pre-shared `key`.
    pub fn sign(&mut self, key: &[u8]) -> Result<(), String> {
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
        };
        result.sign(&key).unwrap();
        result.output_payload = serde_json::json!({"answer": 99}); // tamper
        assert!(result.verify(&key, 300).is_err());
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
        };
        result.sign(&key).unwrap();
        result.verify(&key, 300).expect("empty-logs result should verify");
    }
}
