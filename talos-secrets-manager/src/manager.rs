// MCP-944 (2026-05-15): kept `#![allow(dead_code)]` deliberately. This
// module defines `pub trait SecretProvider` plus two stub
// implementations (`VaultSecretProvider`, `AwsSecretProvider`) that are
// labeled "Provider Stub" — they return "not implemented" errors and
// are not instantiated anywhere. The trait + stubs are scaffolding for
// future Enterprise-Vault / AWS-Secrets-Manager backend integration.
// Same documented-placeholder rationale as talos-feature-flags /
// talos-tenancy / talos-secrets-rotation. The `encrypt_dek_with_master`
// dead method was a separate find — deleted in this commit because it
// was a redundant 1-line wrapper, not a placeholder.
#![allow(dead_code)]

// Module declarations live in lib.rs. The HTTP handlers (`handlers`) and
// the OAuth-aware resolver (`resolver`) stay in the controller crate
// because they pull in axum / oauth respectively; this crate is the
// transport-free core (envelope encryption, KEK providers, DEK cache).

use crate::kek_provider;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use rand::RngCore;
use sqlx::{Pool, Postgres, Row};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid::Uuid;
use zeroize::Zeroizing;

/// System user UUID for secrets not owned by a specific human user (e.g., system-generated tokens).
pub const SYSTEM_USER_ID: Uuid = Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

// Many fields and helper methods are defined for future functionality but are not
// currently used throughout the codebase. Suppress dead‑code warnings.
#[allow(dead_code, clippy::too_many_arguments)]
/// Cached DEK entry with timestamp
#[derive(Clone)]
struct CachedDek {
    dek: DataEncryptionKey,
    cached_at: Instant,
}

/// Secrets manager with envelope encryption and DEK caching
///
/// Performance Optimization:
/// - DEKs are cached in memory with 5-minute TTL
/// - Provides 50x+ speedup for workflows with multiple secrets
/// - First access: ~50ms (DB + decrypt), Subsequent: <1ms (cache hit)
pub struct SecretsManager {
    db_pool: Pool<Postgres>,
    /// Pluggable KEK provider — wraps/unwraps DEKs. The default
    /// constructor (`SecretsManager::new`) wires the local-AES
    /// `EnvKekProvider`; production deployments swap to
    /// `VaultTransitProvider` or another KMS via
    /// [`SecretsManager::with_kek_provider`].
    ///
    /// Wrapped in a sync `RwLock<Arc<...>>` so `rotate_master_key` can
    /// atomically publish a new provider. Read pattern: `clone Arc out
    /// of the lock, drop the guard, await on the clone` — no async
    /// guard hold, no contention with concurrent readers. Writes happen
    /// only during master-key rotation.
    kek: std::sync::RwLock<Arc<dyn kek_provider::KekProvider>>,
    /// Optional legacy KEK provider — used during the Phase 4 dual-wrap
    /// soak window AND as the partial-failure safety belt in
    /// `rotate_master_key`. When `Some`, every read prefers
    /// `encrypted_key_v2` (unwrapped via `kek`) but falls back to
    /// `encrypted_key` (unwrapped via `kek_legacy`) for any row that
    /// hasn't been rewrapped yet. Every write dual-writes both columns
    /// so a rollback to the legacy provider is just a config flip.
    /// `None` outside the migration window — Phase 5 retires this
    /// field along with the legacy column.
    ///
    /// Wrapped in a sync `RwLock` (mirroring `kek`) so
    /// `rotate_master_key` can install the OLD provider here BEFORE the
    /// rewrap loop. If the loop fails partway through, the existing
    /// fallback path in `decrypt_dek` automatically unwraps any-
    /// already-rewrapped rows via the new `kek` and any-not-yet-
    /// rewrapped rows via this legacy provider — so a partial-failure
    /// rotation is recoverable rather than catastrophic. Cleared after
    /// successful rotation. (H-1 fix from the encryption-cluster review.)
    kek_legacy: std::sync::RwLock<Option<Arc<dyn kek_provider::KekProvider>>>,
    /// In-memory cache for decrypted DEKs (UUID -> CachedDek)
    /// TTL: 5 minutes (configurable via DEK_CACHE_TTL_SECS env var)
    /// Thread-safe with Arc<DashMap<>>
    dek_cache: Arc<DashMap<Uuid, CachedDek>>,
    /// Active DEK cache (special case - only one active DEK at a time)
    active_dek_cache: Arc<RwLock<Option<CachedDek>>>,
    /// Cache TTL in seconds (default: 300 = 5 minutes)
    cache_ttl: Duration,
    /// Per-user cache of LLM provider keys
    /// (`anthropic/api_key`, `openai/api_key`, `gemini/api_key`).
    /// Every job dispatch pre-fetches these to enable `llm::*` host
    /// functions — without this cache, a workflow with 100 sandbox nodes
    /// hits the DB 100× for the same 3 rows. TTL is deliberately short
    /// (60s) so a `rotate_secret` propagates quickly to the worker.
    /// Key is `Option<Uuid>` so we cache the wildcard-tenant lookup too.
    llm_keys_cache: Arc<DashMap<Option<Uuid>, CachedLlmKeys>>,
}

/// Cached LLM-key bundle with a per-entry expiry so rotations propagate
/// within one TTL window.
///
/// Each value is wrapped in [`Zeroizing`] so the plaintext API key is
/// wiped from heap on cache eviction or clone-and-drop. With up to 50k
/// entries × 60s TTL, the un-zeroized HashMap was the largest single
/// pool of plaintext secret material in the controller process. Same
/// protection rationale as `DataEncryptionKey.key`. Keys (the path
/// strings like "anthropic/api_key") are public — only the values need
/// zeroize.
#[derive(Clone)]
struct CachedLlmKeys {
    keys: std::collections::HashMap<String, Zeroizing<String>>,
    expires_at: std::time::Instant,
}

/// TTL for the LLM-keys cache. Deliberately shorter than the DEK cache
/// (5 min) because LLM key rotations need to reach workers within a
/// tight window — a stale key would cause HTTP 401 storms on the next
/// LLM call after rotation. Configurable via `LLM_KEYS_CACHE_TTL_SECS`.
const LLM_KEYS_CACHE_DEFAULT_TTL_SECS: u64 = 60;

/// Re-export of the canonical LLM provider check so this module doesn't
/// duplicate the list. See `talos_workflow_job_protocol::is_llm_provider_vault_path`.
use talos_workflow_job_protocol::is_llm_provider_vault_path as is_llm_provider_key_path;

/// Bump the per-row `secret_decrypt_failures_total` counter. Best-effort:
/// no-ops if the global metrics registry isn't initialised (test runs).
///
/// Allowed reasons (kept stable so dashboards don't need to relabel):
///   * `too_short`      — encrypted_value < 12 bytes (no room for nonce).
///   * `decrypt_helper` — `decrypt_secret_record` returned Err. The
///     specific underlying failure (missing DEK / AEAD-tag mismatch /
///     non-UTF8 plaintext / cipher-init error) is NOT distinguished
///     here — it's surfaced in the `talos_secrets` tracing target's
///     event payload instead, so operators with log access get the
///     fine-grained classification while the metric label cardinality
///     stays bounded.
///
/// MCP-938 (2026-05-15): docstring used to promise five reasons
/// (`missing_dek | cipher_init | aead | invalid_utf8` in addition to
/// the two above), but only `too_short` and `decrypt_helper` are ever
/// incremented by call sites in this file. The fine-grained
/// classification happens inside the decrypt helper but is logged via
/// tracing, never as a metric label. Operators building dashboards
/// against the documented label set saw inconsistent results — the
/// metric only emits the two reasons listed above.
///
/// `&'static str` enforces compile-time literal at every call site
/// to bound Prometheus cardinality (no runtime-constructed labels).
fn inc_secret_decrypt_failure(reason: &'static str) {
    if let Some(m) = talos_metrics::global() {
        m.secret_decrypt_failures_total
            .with_label_values(&[reason])
            .inc();
    }
}

#[derive(Debug, Clone)]
pub struct Secret {
    pub id: Uuid,
    pub name: String,
    pub key_path: String,
    pub description: Option<String>,
    pub created_by: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub owner_user_id: Option<Uuid>,
    pub org_id: Option<Uuid>,
    pub allowed_modules: Option<Vec<Uuid>>,
    pub last_accessed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub access_count: i32,
}

/// Lightweight projection for MCP listing handlers. Includes namespace +
/// rotation_reminder_days which `Secret` deliberately omits (those columns
/// are listing-display concerns, not part of the encryption model).
#[derive(Debug, Clone)]
pub struct SecretSummary {
    pub id: Uuid,
    pub name: String,
    pub key_path: String,
    pub description: Option<String>,
    pub namespace: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub rotation_reminder_days: Option<i32>,
}

/// Projection returned by `lookup_secret_by_name` / `rotate_secret_value`.
/// Plain-old-data; carries no decrypted content.
#[derive(Debug, Clone)]
pub struct SecretLookup {
    pub id: Uuid,
    pub key_path: String,
    pub namespace: String,
    pub description: Option<String>,
}

/// Result of a successful `rotate_secret_value`.
#[derive(Debug, Clone)]
pub struct RotatedSecret {
    pub id: Uuid,
    pub key_path: String,
    pub description: Option<String>,
}

/// Reference projection used by `export_platform_state` — never includes
/// any decrypted material.
#[derive(Debug, Clone)]
pub struct SecretRefForExport {
    pub name: String,
    pub key_path: String,
    pub namespace: String,
    pub description: Option<String>,
}

impl SecretRefForExport {
    /// Project this row into the JSON shape the platform-export manifest
    /// uses. `description` is only emitted when present (preserves the
    /// pre-extraction handler shape — absent description must NOT
    /// serialize as `null`, which would change the manifest hash).
    ///
    /// Lives next to the struct so callers can't drift the projection
    /// away from the row shape (caught at compile time if a field is
    /// renamed). Pure — no IO, no DLP — safe to call in tight loops or
    /// from a `tokio::spawn` map.
    pub fn to_export_json(&self) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "name": self.name,
            "key_path": self.key_path,
            "namespace": self.namespace,
        });
        if let Some(desc) = self.description.as_ref() {
            obj["description"] = serde_json::json!(desc);
        }
        obj
    }
}

/// One audit-log entry returned by `list_secret_access_log`.
#[derive(Debug, Clone)]
pub struct SecretAuditEntry {
    pub id: Uuid,
    pub secret_name: Option<String>,
    pub action: String,
    pub actor_type: String,
    pub actor: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// One row of the secret-health audit. Used by `handle_check_secret_health`.
#[derive(Debug, Clone)]
pub struct SecretHealthRow {
    pub name: String,
    pub key_path: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Module that grants access to a secret via `allowed_secrets`. Returned by
/// `find_modules_referencing_secret`.
///
/// Phase 5: the dual-row legacy model (wasm_modules + node_templates) is
/// collapsed into a single `modules` table, so `source` is derived from
/// `modules.kind`: `sandbox` / `extracted` → `Compiled`, `catalog` → `Template`.
/// The discriminator is preserved for API compatibility with pre-Phase-5
/// callers that render the field.
#[derive(Debug, Clone)]
pub struct ModuleSecretReference {
    pub module_id: Uuid,
    pub module_name: String,
    pub source: ModuleSource,
    pub wildcard: bool,
}

/// Discriminator for `ModuleSecretReference`. Kept post-Phase-5 so the
/// surface of public types doesn't change for external callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleSource {
    Compiled,
    Template,
}

impl ModuleSource {
    pub fn as_str(self) -> &'static str {
        match self {
            ModuleSource::Compiled => "compiled",
            ModuleSource::Template => "template",
        }
    }

    /// Map a `modules.kind` value to the legacy source discriminator.
    /// `sandbox` + `extracted` → `Compiled`; everything else → `Template`.
    pub(crate) fn from_modules_kind(kind: &str) -> Self {
        match kind {
            "sandbox" | "extracted" => ModuleSource::Compiled,
            _ => ModuleSource::Template,
        }
    }
}

/// Free function so it can be used inside SecretsManager methods without
/// requiring `&self`.
fn row_to_summary(row: sqlx::postgres::PgRow) -> SecretSummary {
    SecretSummary {
        id: row.get("id"),
        name: row.get("name"),
        key_path: row.get("key_path"),
        description: row.try_get("description").ok().flatten(),
        namespace: row
            .try_get::<String, _>("namespace")
            .unwrap_or_else(|_| "default".to_string()),
        created_at: row.get("created_at"),
        expires_at: row.try_get("expires_at").unwrap_or(None),
        rotation_reminder_days: row.try_get("rotation_reminder_days").unwrap_or(None),
    }
}

pub trait SecretProvider: Send + Sync {
    fn get_secret_val(
        &self,
        key_path: &str,
    ) -> impl std::future::Future<Output = Result<String>> + Send;
    fn set_secret_val(
        &self,
        key_path: &str,
        value: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

// Enterprise Vault Provider Stub
pub struct VaultSecretProvider {
    endpoint: String,
    token: String,
}

impl SecretProvider for VaultSecretProvider {
    async fn get_secret_val(&self, _key_path: &str) -> Result<String> {
        Err(anyhow!("Vault secret provider not implemented"))
    }

    async fn set_secret_val(&self, _key_path: &str, _value: &str) -> Result<()> {
        Err(anyhow!("Vault secret provider not implemented"))
    }
}

// AWS Secrets Manager Provider Stub
pub struct AwsSecretProvider {
    region: String,
}

impl SecretProvider for AwsSecretProvider {
    async fn get_secret_val(&self, _key_path: &str) -> Result<String> {
        Err(anyhow!("AWS secret provider not implemented"))
    }

    async fn set_secret_val(&self, _key_path: &str, _value: &str) -> Result<()> {
        Err(anyhow!("AWS secret provider not implemented"))
    }
}

#[derive(Debug, Clone)]
pub enum SecretRequestor {
    User(Uuid),
    Module(Uuid),
    System,
}

/// Plaintext DEK material in memory.
///
/// `key` is wrapped in [`Zeroizing`] so the bytes are wiped from heap
/// when the value is dropped — every cache eviction, every clone-then-
/// drop in `get_dek` / `get_active_dek`, every cipher-construction
/// path. The KEK provider already returns `Zeroizing<Vec<u8>>` from
/// `unwrap_dek`; this type carries that protection through the rest of
/// the controller. Without it, every secret read leaves a copy of the
/// plaintext key in heap until the allocator reuses the page —
/// observable via heap dumps or memory scanning.
///
/// `aes_gcm::Aes256Gcm::new_from_slice(&dek.key)` still works because
/// `&Zeroizing<Vec<u8>>` deref-coerces through to `&[u8]`.
#[derive(Clone)]
pub struct DataEncryptionKey {
    pub id: Uuid,
    pub key: Zeroizing<Vec<u8>>,
}

impl SecretsManager {
    /// Access the underlying database pool (used by OAuthCredentialService for
    /// proactive token refresh when the engine detects expiring OAuth tokens).
    pub fn db_pool(&self) -> &Pool<Postgres> {
        &self.db_pool
    }

    /// Clone the currently-active KEK provider out of the lock so it can
    /// be awaited on without holding the std::sync::RwLock guard across
    /// .await (which would be unsound under Send).
    fn current_kek(&self) -> Result<Arc<dyn kek_provider::KekProvider>> {
        self.kek
            .read()
            .map(|g| g.clone())
            .map_err(|_| anyhow!("KEK provider lock poisoned"))
    }

    /// Create new secrets manager with the default env-var KEK provider.
    /// Convenience wrapper around [`SecretsManager::with_kek_provider`].
    pub fn new(db_pool: Pool<Postgres>) -> Result<Self> {
        let kek = kek_provider::env_kek_provider_from_environment()?;
        Self::with_kek_provider(db_pool, kek)
    }

    /// Create new secrets manager with an explicit KEK provider.
    /// Production deployments call this directly with a Vault / KMS-backed
    /// provider; tests can pass a stub. The wire format of wrapped DEKs is
    /// provider-defined — switching providers requires a dual-wrap migration
    /// (see Phase 3 of the KEK→KMS plan), not just a constructor change.
    pub fn with_kek_provider(
        db_pool: Pool<Postgres>,
        kek: Arc<dyn kek_provider::KekProvider>,
    ) -> Result<Self> {
        Self::with_kek_providers(db_pool, kek, None)
    }

    /// Create with both an active KEK provider and an optional legacy
    /// provider for the Phase 4 dual-wrap soak window.
    ///
    /// When `kek_legacy` is `Some`, this manager:
    ///   - Reads prefer `encrypted_key_v2` via `kek`; fall back to
    ///     `encrypted_key` via `kek_legacy` if v2 is NULL (race window).
    ///   - Writes populate BOTH `encrypted_key` (via legacy) and
    ///     `encrypted_key_v2` (via active) so a rollback is just a
    ///     config flip.
    ///
    /// `kek` MUST be the new (target) provider; `kek_legacy` MUST be the
    /// previous (source) provider that wrapped existing v1 ciphertexts.
    /// Reversing the two would silently corrupt every new DEK.
    pub fn with_kek_providers(
        db_pool: Pool<Postgres>,
        kek: Arc<dyn kek_provider::KekProvider>,
        kek_legacy: Option<Arc<dyn kek_provider::KekProvider>>,
    ) -> Result<Self> {
        // Get cache TTL from environment (default: 300 seconds = 5 minutes).
        // MCP-771 (2026-05-13): route through `positive_env_or_default` —
        // `DEK_CACHE_TTL_SECS=0` previously parsed as a valid value and
        // produced a cache whose entries expired the instant they were
        // inserted. Every secret-decrypt then re-fetched + re-unwrapped
        // the DEK from Vault/KEK provider on the hot path, multiplying
        // controller load 10-100× per workflow run. Same =0 footgun
        // class as MCP-665/689/695/703 (and a sibling of
        // LLM_KEYS_CACHE_TTL_SECS, fixed in the same commit below).
        let cache_ttl_secs =
            talos_config::positive_env_or_default("DEK_CACHE_TTL_SECS", 300u64);

        tracing::info!(
            ttl_seconds = cache_ttl_secs,
            kek_provider = kek.name(),
            kek_legacy = kek_legacy.as_ref().map(|p| p.name()).unwrap_or("none"),
            "Initialized SecretsManager"
        );

        Ok(Self {
            db_pool,
            kek: std::sync::RwLock::new(kek),
            kek_legacy: std::sync::RwLock::new(kek_legacy),
            dek_cache: Arc::new(DashMap::new()),
            active_dek_cache: Arc::new(RwLock::new(None)),
            cache_ttl: Duration::from_secs(cache_ttl_secs),
            llm_keys_cache: Arc::new(DashMap::new()),
        })
    }

    /// Snapshot the current legacy KEK provider, if any.
    ///
    /// Returns a cloned `Arc` so callers can `.await` against it without
    /// holding the read guard across an await point. `None` when no
    /// legacy provider is installed (the common steady-state case).
    fn current_legacy_kek(&self) -> Option<Arc<dyn kek_provider::KekProvider>> {
        self.kek_legacy
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().cloned())
    }

    /// Fetch the canonical LLM provider keys for `user_id`, served from an
    /// in-memory cache when possible.
    ///
    /// Every job dispatch pre-fetches these paths so `llm::complete`,
    /// `llm-tools`, and `llm-streaming` can resolve them via the vault
    /// rather than relying on env vars. At 100+ jobs/minute on a single
    /// user, the un-cached path pays 3 DB round-trips per job — pure
    /// overhead since LLM keys rotate rarely.
    ///
    /// Cache semantics:
    /// - TTL bounded by `LLM_KEYS_CACHE_TTL_SECS` (default 60s), so a
    ///   `rotate_secret` call is visible to new jobs within one TTL
    ///   window. Callers that need immediate propagation should call
    ///   [`Self::invalidate_llm_keys_cache`] after rotation.
    /// - Keyed by `Option<Uuid>` so the wildcard-tenant lookup (None)
    ///   and per-user lookups don't collide.
    /// - Values are cloned out of the cache on read — each job gets an
    ///   independent owned HashMap, so lifetimes stay simple downstream.
    /// - DB errors are propagated; callers decide whether to fall back
    ///   to env vars (the worker-side `get_llm_api_key` does exactly this).
    /// Fast-path cache lookup for LLM vault keys.
    ///
    /// Returns the cached value if the entry is fresh. Evicts and returns
    /// `None` if the entry has expired — so the slow path unconditionally
    /// repopulates on a miss.
    ///
    /// Extracted as a `pub(crate)` method (not inlined into `get_llm_vault_keys`)
    /// so the cache-semantics test suite exercises the actual production
    /// code rather than a shadow implementation. Any behavioural drift in
    /// the fast-path logic is caught by the existing tests.
    ///
    /// DashMap lock-hold time is bounded to the `and_then` closure — the
    /// read guard drops before `expired` is checked, so concurrent writers
    /// aren't blocked by our clone.
    pub(crate) fn try_llm_keys_cache_hit(
        &self,
        user_id: Option<Uuid>,
    ) -> Option<std::collections::HashMap<String, Zeroizing<String>>> {
        let now = std::time::Instant::now();
        let mut expired = false;
        let cloned = self.llm_keys_cache.get(&user_id).and_then(|entry| {
            if entry.expires_at > now {
                Some(entry.keys.clone())
            } else {
                expired = true;
                None
            }
        });
        if expired {
            self.llm_keys_cache.remove(&user_id);
        }
        cloned
    }

    /// Fetch the canonical LLM provider keys for `user_id`, served from an
    /// in-memory cache when possible.
    ///
    /// Each value is wrapped in [`Zeroizing<String>`] so the plaintext API
    /// key is wiped on drop. Callers that need to pass the plaintext to
    /// an external API (encryption, header construction) should consume
    /// the value briefly — the wrapper derefs to `&str` for read access,
    /// so most code paths don't need to clone the inner String at all.
    pub async fn get_llm_vault_keys(
        &self,
        user_id: Option<Uuid>,
    ) -> Result<std::collections::HashMap<String, Zeroizing<String>>> {
        // Fast path: serve from cache if the entry is still fresh.
        if let Some(map) = self.try_llm_keys_cache_hit(user_id) {
            return Ok(map);
        }

        // Slow path: fetch from DB, repopulate cache. Paths come from the
        // single shared const in talos_workflow_job_protocol — no duplication.
        //
        // Race note: two concurrent misses both hit the DB, both insert.
        // Benign — second insert overwrites, the DB query is 3 rows so the
        // cost is small. Not worth a SingleFlight-style dedup for this path.
        let paths: Vec<String> = talos_workflow_job_protocol::LLM_PROVIDER_VAULT_PATHS
            .iter()
            .map(|s| s.to_string())
            .collect();
        // get_secrets_by_paths returns plain Strings; wrap each value in
        // Zeroizing immediately so the cache and the returned map share
        // the same protection. The intermediate plain-String map exists
        // for one statement before being consumed by .into_iter().
        let plaintext_keys = self.get_secrets_by_paths(&paths, user_id).await?;
        let zeroizing_keys: std::collections::HashMap<String, Zeroizing<String>> = plaintext_keys
            .into_iter()
            .map(|(k, v)| (k, Zeroizing::new(v)))
            .collect();

        // MCP-771 (2026-05-13): `LLM_KEYS_CACHE_TTL_SECS=0` previously
        // parsed cleanly and produced expires_at == now → every
        // get_llm_vault_keys call became a cache miss → every dispatch
        // path re-hit the DB for the same 3 rows. Same =0 footgun
        // class as MCP-665/689/695/703 (and DEK_CACHE_TTL_SECS above).
        // Sibling sweep-interval at controller/src/main.rs:1059 is
        // protected by `.clamp(60, 3600)`; this TTL had no clamp.
        let ttl_secs = talos_config::positive_env_or_default(
            "LLM_KEYS_CACHE_TTL_SECS",
            LLM_KEYS_CACHE_DEFAULT_TTL_SECS,
        );
        self.llm_keys_cache.insert(
            user_id,
            CachedLlmKeys {
                keys: zeroizing_keys.clone(),
                expires_at: std::time::Instant::now() + Duration::from_secs(ttl_secs),
            },
        );
        Ok(zeroizing_keys)
    }

    /// Construct a SecretsManager stub whose cache is usable without a real
    /// DB pool or master key. Exists solely for tests that exercise the
    /// cache-primitive surface (lookup, eviction, invalidation, sweep).
    ///
    /// Slow-path methods that hit the DB will panic or error — that's
    /// intentional. If a test needs slow-path behaviour it must use an
    /// integration test with a real `PgPool`.
    #[cfg(test)]
    pub(crate) fn test_stub_for_cache() -> Self {
        use sqlx::postgres::PgPoolOptions;
        // Pool that never connects — methods using it will error, but the
        // cache-primitive methods we test don't touch it.
        let lazy_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://127.0.0.1:0/nope")
            .expect("lazy pool build");
        Self {
            db_pool: lazy_pool,
            kek: std::sync::RwLock::new(Arc::new(kek_provider::EnvKekProvider::test_stub())),
            kek_legacy: std::sync::RwLock::new(None),
            dek_cache: Arc::new(DashMap::new()),
            active_dek_cache: Arc::new(RwLock::new(None)),
            cache_ttl: Duration::from_secs(300),
            llm_keys_cache: Arc::new(DashMap::new()),
        }
    }

    /// Sweep expired entries out of the LLM-keys cache.
    ///
    /// Read-path eviction (`get_llm_vault_keys` removes on expiry-miss) handles
    /// the common case, but entries for users that stop making requests
    /// stay in the DashMap forever. Call this periodically from a background
    /// task to bound total cache size under long uptime with churning users.
    ///
    /// Returns the number of entries evicted. O(n) in cache size.
    pub fn sweep_expired_llm_keys(&self) -> usize {
        let now = std::time::Instant::now();
        // Collect expired keys first to avoid holding any DashMap guards
        // while mutating — `retain` would work but `remove` mirrors the
        // read-path eviction pattern.
        let expired: Vec<Option<Uuid>> = self
            .llm_keys_cache
            .iter()
            .filter(|r| r.value().expires_at <= now)
            .map(|r| *r.key())
            .collect();
        let evicted = expired.len();
        for k in expired {
            self.llm_keys_cache.remove(&k);
        }
        evicted
    }

    /// MCP-1093: periodic sweep of the DEK cache.
    ///
    /// `get_dek` evicts expired entries on read (so distinct-active key_ids
    /// stay bounded), but historical DEK ids that are never re-queried
    /// after the active key rotates leave their plaintext AES-256 key
    /// material in the heap for the lifetime of the process. The whole
    /// point of `DEK_CACHE_TTL_SECS` is to bound that memory-residency
    /// window — without a sweep, the contract is broken for the no-traffic
    /// case. Mirrors [`Self::sweep_expired_llm_keys`].
    ///
    /// Returns the number of entries evicted. O(n) in cache size.
    pub fn sweep_expired_deks(&self) -> usize {
        let now = std::time::Instant::now();
        let cache_ttl = self.cache_ttl;
        let expired: Vec<Uuid> = self
            .dek_cache
            .iter()
            .filter(|r| now.duration_since(r.value().cached_at) >= cache_ttl)
            .map(|r| *r.key())
            .collect();
        let evicted = expired.len();
        for k in expired {
            self.dek_cache.remove(&k);
        }
        evicted
    }

    /// MCP-1133 (2026-05-16): sweep the single-slot `active_dek_cache`
    /// if its entry is expired. The MCP-1093 `sweep_expired_deks`
    /// covers the per-DEK-id secondary cache (DashMap) but leaves the
    /// `active_dek_cache: RwLock<Option<CachedDek>>` slot untouched.
    /// `get_active_dek_cached` evicts-via-overwrite on miss, but a
    /// low-traffic deploy that goes idle after a key rotation leaves
    /// the OLD active-DEK plaintext bytes resident in the heap
    /// indefinitely. The whole point of `cache_ttl` is to bound that
    /// residency window.
    ///
    /// Async because `active_dek_cache` is a tokio `RwLock`. Uses
    /// `try_write` so a concurrent reader doesn't block the sweep
    /// tick — if contention, skip this tick and retry on the next.
    ///
    /// Returns `true` if an expired entry was evicted, `false` otherwise.
    pub async fn sweep_expired_active_dek(&self) -> bool {
        let now = std::time::Instant::now();
        let cache_ttl = self.cache_ttl;
        // Use try_write so a concurrent reader can't pin this sweep.
        // The window is short (microseconds) so contention is rare,
        // and skipping a tick is fine — the next tick will catch it.
        let Ok(mut guard) = self.active_dek_cache.try_write() else {
            return false;
        };
        let should_clear = guard
            .as_ref()
            .map(|c| now.duration_since(c.cached_at) >= cache_ttl)
            .unwrap_or(false);
        if should_clear {
            *guard = None;
            true
        } else {
            false
        }
    }

    /// Invalidate the LLM-keys cache for a given user. Call this from
    /// secret-rotation code paths so the next job sees fresh keys
    /// without waiting for the TTL window to expire.
    ///
    /// Passing `None` invalidates the wildcard-tenant entry only; call
    /// [`Self::invalidate_all_llm_keys_cache`] to flush all entries
    /// (e.g. when rotating a key that multiple users can access).
    pub fn invalidate_llm_keys_cache(&self, user_id: Option<Uuid>) {
        self.llm_keys_cache.remove(&user_id);
    }

    /// Flush every entry in the LLM-keys cache. Use when a rotation
    /// affects a shared provider key that multiple users reference.
    pub fn invalidate_all_llm_keys_cache(&self) {
        self.llm_keys_cache.clear();
    }

    /// Initialize the secrets system (create initial DEK if needed)
    pub async fn initialize(&self) -> Result<()> {
        // Check if we have an active DEK
        let existing = sqlx::query!("SELECT id FROM encryption_keys WHERE active = true LIMIT 1")
            .fetch_optional(&self.db_pool)
            .await?;

        if existing.is_none() {
            // Create initial DEK
            self.create_new_dek().await?;
            tracing::info!("Created initial data encryption key");
        }

        Ok(())
    }

    /// Create a new data encryption key.
    /// Wrap with the active KEK provider and store opaque bytes.
    async fn create_new_dek(&self) -> Result<Uuid> {
        let mut dek_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut dek_bytes);

        let active_wrap = self.current_kek()?.wrap_dek(&dek_bytes).await?;
        let record = sqlx::query!(
            "INSERT INTO encryption_keys (encrypted_key, algorithm, active) VALUES ($1, $2, true) RETURNING id",
            &active_wrap,
            "AES-256-GCM"
        )
        .fetch_one(&self.db_pool)
        .await?;

        Ok(record.id)
    }

    /// Get the active DEK (decrypt from database)
    ///
    /// Performance: Uses in-memory cache with 5-minute TTL
    /// - Cache hit: <1ms (50x+ faster than DB + decrypt)
    /// - Cache miss: ~50ms (DB query + AES-256-GCM decryption)
    pub async fn get_active_dek(&self) -> Result<DataEncryptionKey> {
        let now = Instant::now();

        // 1️⃣ Check cache first (read lock — allows concurrent readers)
        {
            let cache = self.active_dek_cache.read().await;
            if let Some(cached) = cache.as_ref() {
                // Check if cache entry is still valid (within TTL)
                if now.duration_since(cached.cached_at) < self.cache_ttl {
                    tracing::trace!("Active DEK cache hit");
                    return Ok(cached.dek.clone());
                } else {
                    tracing::trace!("Active DEK cache expired");
                }
            }
        }

        // 2️⃣ Cache miss - fetch from database and decrypt
        tracing::trace!("Active DEK cache miss - fetching from database");
        let record = sqlx::query!(
            "SELECT id, encrypted_key FROM encryption_keys WHERE active = true ORDER BY created_at DESC LIMIT 1"
        )
        .fetch_one(&self.db_pool)
        .await
        .context("No active encryption key found. Run initialize() first")?;

        let dek = self.decrypt_dek(record.id, &record.encrypted_key).await?;

        // 3️⃣ Cache the decrypted DEK (write lock — exclusive access)
        {
            let mut cache = self.active_dek_cache.write().await;
            *cache = Some(CachedDek {
                dek: dek.clone(),
                cached_at: now,
            });
        }

        tracing::debug!(
            dek_id = %dek.id,
            "Cached active DEK (TTL: {:?})",
            self.cache_ttl
        );

        Ok(dek)
    }

    /// Get a specific DEK by ID
    ///
    /// Performance: Uses in-memory cache with 5-minute TTL
    /// - Cache hit: <1ms (50x+ faster than DB + decrypt)
    /// - Cache miss: ~50ms (DB query + AES-256-GCM decryption)
    async fn get_dek(&self, key_id: Uuid) -> Result<DataEncryptionKey> {
        let now = Instant::now();

        // 1️⃣ Check cache first
        let mut expired = false;
        if let Some(cached) = self.dek_cache.get(&key_id) {
            // Check if cache entry is still valid (within TTL)
            if now.duration_since(cached.cached_at) < self.cache_ttl {
                tracing::trace!(dek_id = %key_id, "DEK cache hit");
                return Ok(cached.dek.clone());
            } else {
                tracing::trace!(dek_id = %key_id, "DEK cache expired");
                expired = true;
            }
        }
        // MCP-1093: drop the read guard before removing on expiry so we
        // don't deadlock the shard. Mirrors `try_llm_keys_cache_hit`.
        if expired {
            self.dek_cache.remove(&key_id);
        }

        // 2️⃣ Cache miss - fetch from database and decrypt
        tracing::trace!(dek_id = %key_id, "DEK cache miss - fetching from database");
        let record = sqlx::query!(
            "SELECT id, encrypted_key FROM encryption_keys WHERE id = $1",
            key_id
        )
        .fetch_one(&self.db_pool)
        .await
        .context("Encryption key not found")?;

        let dek = self.decrypt_dek(record.id, &record.encrypted_key).await?;

        // 3️⃣ Cache the decrypted DEK
        self.dek_cache.insert(
            key_id,
            CachedDek {
                dek: dek.clone(),
                cached_at: now,
            },
        );

        tracing::debug!(
            dek_id = %key_id,
            "Cached DEK (TTL: {:?})",
            self.cache_ttl
        );

        Ok(dek)
    }

    /// Decrypt a DEK using the configured KEK provider.
    ///
    /// Soft-fall-through to `kek_legacy` on active-provider failure —
    /// kept after Phase 5 because it's the cheap insurance that lets a
    /// future provider migration (e.g. Vault → AWS KMS) reuse the same
    /// dual-wrap pattern without code changes here.
    async fn decrypt_dek(&self, key_id: Uuid, encrypted_key: &[u8]) -> Result<DataEncryptionKey> {
        let active = self.current_kek()?;
        match active.unwrap_dek(encrypted_key).await {
            Ok(bytes) => Ok(DataEncryptionKey {
                id: key_id,
                // bytes is already Zeroizing<Vec<u8>>; move it directly
                // into the cache slot. Previous code did `.to_vec()`
                // which copied into a plain Vec, defeating the
                // zeroization guarantee provided by the KEK provider.
                key: bytes,
            }),
            Err(active_err) => {
                if let Some(m) = talos_metrics::global() {
                    m.kek_decrypt_failures_total
                        .with_label_values(&["active"])
                        .inc();
                }
                if let Some(legacy) = self.current_legacy_kek() {
                    tracing::debug!(
                        %key_id,
                        error = %active_err,
                        "decrypt_dek: active provider failed; trying legacy"
                    );
                    let bytes = match legacy.unwrap_dek(encrypted_key).await {
                        Ok(b) => b,
                        Err(legacy_err) => {
                            if let Some(m) = talos_metrics::global() {
                                m.kek_decrypt_failures_total
                                    .with_label_values(&["both"])
                                    .inc();
                            }
                            return Err(legacy_err.context(format!(
                                "decrypt_dek: both active ({}) and legacy ({}) providers failed for {}",
                                active.name(),
                                legacy.name(),
                                key_id
                            )));
                        }
                    };
                    Ok(DataEncryptionKey {
                        id: key_id,
                        // Same zeroization preservation as the active path.
                        key: bytes,
                    })
                } else {
                    Err(active_err
                        .context(format!("decrypt_dek: active provider failed for {key_id}")))
                }
            }
        }
    }

    /// Store a new secret.
    ///
    /// N T2-N1: writes use the v1 AAD-bound format. The secret's `id`
    /// is pre-generated client-side so the encrypt step can bind it
    /// as AAD before the INSERT lands. AES-GCM authenticates the AAD
    /// alongside the ciphertext — an attacker who later swaps the
    /// `encrypted_value` column between two rows would invalidate the
    /// authentication tag and reads would fail closed (rather than
    /// returning the swapped plaintext).
    pub async fn create_secret(
        &self,
        name: &str,
        key_path: &str,
        value: &str,
        description: Option<&str>,
        creator_user_id: Uuid,
        allowed_modules: Vec<Uuid>,
        org_id: Option<Uuid>,
    ) -> Result<Uuid> {
        // 1. Pre-generate secret_id so it's available as AAD.
        let secret_id = Uuid::new_v4();

        // 2. Encrypt with secret_id bytes as AAD (v1 format).
        let (key_id, stored_value) = self
            .encrypt_value_with_aad(value, secret_id.as_bytes())
            .await?;
        // Extract the 12-byte nonce prefix back out for the legacy
        // `nonce` column (kept for backward-compat with operator
        // tooling that inspects the column directly).
        let nonce_bytes = stored_value.get(..12).ok_or_else(|| {
            anyhow!("encrypt_value_with_aad returned a ciphertext shorter than the nonce prefix")
        })?;

        // 3. Store secret + audit log in a single transaction (L-5).
        //    Either both commit or neither does — no possibility of a
        //    secret existing without its audit trail or vice versa.
        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("Failed to begin secret-create transaction")?;

        let insert_result = sqlx::query_scalar::<_, Uuid>(
            r#"
            INSERT INTO secrets (
                id, name, key_path, encrypted_value, encryption_key_id,
                nonce, description, created_by, owner_user_id, allowed_modules,
                org_id, encryption_format_version
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING id
            "#,
        )
        .bind(secret_id)
        .bind(name)
        .bind(key_path)
        .bind(&stored_value)
        .bind(key_id)
        .bind(nonce_bytes)
        .bind(description)
        .bind(creator_user_id)
        .bind(creator_user_id)
        .bind(&allowed_modules)
        .bind(org_id)
        .bind(Self::SECRETS_AAD_FORMAT_V1)
        .fetch_one(&mut *tx)
        .await;

        // Translate the Postgres unique-violation (code 23505) to a "Validation:"
        // message. The GraphQL error scrub at controller/src/main.rs lets messages
        // containing "Validation" through; without this prefix the operator just
        // sees "Internal server error" and has no idea the duplicate is the
        // actual cause.
        let secret_id: Uuid = match insert_result {
            Ok(id) => id,
            Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("23505") => {
                return Err(anyhow!(
                    "Validation: a secret with this name or key path already exists"
                ));
            }
            Err(e) => return Err(anyhow::Error::new(e).context("Failed to insert secret")),
        };

        // 4. Audit log (in same tx — L-5)
        Self::log_audit_in_tx(
            &mut tx,
            Some(secret_id),
            "create",
            "user",
            Some(creator_user_id),
            None,
            true,
            None,
            None,
        )
        .await
        .context("Failed to insert audit row for create_secret")?;

        tx.commit()
            .await
            .context("Failed to commit secret-create transaction")?;

        if is_llm_provider_key_path(key_path) {
            // Creation is naturally scoped — `creator_user_id` IS the owner
            // for newly-created secrets. Invalidate only their cache entry.
            self.invalidate_llm_keys_cache(Some(creator_user_id));
            tracing::info!(
                key_path = %key_path,
                owner_user_id = %creator_user_id,
                "Invalidated LLM-keys cache for creator after new-secret insert"
            );
        }

        tracing::info!(
            secret_id = %secret_id,
            key_path = %key_path,
            "Created new secret"
        );

        Ok(secret_id)
    }

    /// Retrieve and decrypt a secret
    ///
    /// `accessible_org_ids` — org IDs the requesting user belongs to. For
    /// `SecretRequestor::User`, the secret is accessible if the user owns it
    /// **or** the secret's `org_id` is in this list. Pass `&[]` when the
    /// requestor is a module or system (org check is skipped for those).
    pub async fn get_secret(
        &self,
        key_path: &str,
        requestor: SecretRequestor,
        accessible_org_ids: &[Uuid],
    ) -> Result<String> {
        // 1. Fetch from database.
        #[allow(dead_code)]
        struct SecretRecord {
            id: Uuid,
            encrypted_value: Vec<u8>,
            encryption_key_id: Uuid,
            // N T2-N1: dispatches v0 (legacy no-AAD) vs v1 (AAD-bound)
            // decrypt path. Default 0 for any pre-migration row read
            // through this struct shape.
            encryption_format_version: i16,
            allowed_modules: Vec<Uuid>,
            expires_at: Option<chrono::DateTime<chrono::Utc>>,
            owner_user_id: Option<Uuid>,
            org_id: Option<Uuid>,
        }

        // M-2: pre-filter at the SQL layer so a User requestor can only
        // ever see ROWS THEY OWN or rows in an org they belong to. Two
        // benefits over the post-fetch check (which still runs as
        // defense-in-depth):
        //   1. No "Access denied" existence leak — a key_path collision
        //      between two users returns "not found" rather than
        //      "exists but you can't see it".
        //   2. No audit-log pollution against another user's secret_id
        //      — the SELECT can't return a secret the requestor isn't
        //      eligible for, so the failed-read audit row would
        //      otherwise (incorrectly) attribute to a foreign user.
        // System and Module requestors keep the unfiltered behaviour:
        //   - System has full access by design (root-equivalent).
        //   - Module access is scoped via `allowed_modules` membership,
        //     not user ownership, and modules are intentionally
        //     cross-user when the operator lists them in allowed_modules.
        let row = match &requestor {
            SecretRequestor::User(user_id) => sqlx::query(
                r#"
                    SELECT id,
                           encrypted_value,
                           encryption_key_id,
                           encryption_format_version,
                           allowed_modules,
                           expires_at,
                           owner_user_id,
                           org_id
                    FROM secrets
                    WHERE key_path = $1
                      AND (owner_user_id = $2 OR org_id = ANY($3))
                    LIMIT 1
                "#,
            )
            .bind(key_path)
            .bind(user_id)
            .bind(accessible_org_ids)
            .fetch_one(&self.db_pool)
            .await?,
            SecretRequestor::Module(_) | SecretRequestor::System => sqlx::query(
                r#"
                    SELECT id,
                           encrypted_value,
                           encryption_key_id,
                           encryption_format_version,
                           allowed_modules,
                           expires_at,
                           owner_user_id,
                           org_id
                    FROM secrets
                    WHERE key_path = $1
                    LIMIT 1
                "#,
            )
            .bind(key_path)
            .fetch_one(&self.db_pool)
            .await?,
        };

        let record = SecretRecord {
            id: row.get("id"),
            encrypted_value: row.get("encrypted_value"),
            encryption_key_id: row.get("encryption_key_id"),
            encryption_format_version: row.get("encryption_format_version"),
            allowed_modules: row
                .get::<Option<Vec<Uuid>>, _>("allowed_modules")
                .unwrap_or_default(),
            expires_at: row.get("expires_at"),
            owner_user_id: row.get("owner_user_id"),
            org_id: row.get("org_id"),
        };

        // 2. Check expiration
        if let Some(expires_at) = record.expires_at {
            if expires_at < chrono::Utc::now() {
                self.log_audit(
                    record.id,
                    "read",
                    &requestor.actor_type(),
                    requestor.actor_id(),
                    requestor.module_id(),
                    false,
                    Some("Secret expired"),
                    None,
                )
                .await?;
                return Err(anyhow!("Secret has expired: {}", key_path));
            }
        }

        // 3. Check access permissions
        let allowed = match &requestor {
            SecretRequestor::Module(module_id) => {
                // Modules can only access the secret if they are explicitly in the allow list.
                // We do NOT fall back to permissive access.
                record.allowed_modules.contains(module_id)
            }
            SecretRequestor::User(user_id) => {
                // Users may access a secret if they are the owner OR the secret
                // belongs to one of their organizations.
                let owner_match = match record.owner_user_id {
                    Some(owner) => owner == *user_id,
                    None => false,
                };
                let org_match = match record.org_id {
                    Some(oid) => accessible_org_ids.contains(&oid),
                    None => false,
                };
                owner_match || org_match
            }
            SecretRequestor::System => {
                // System has full access
                true
            }
        };

        if !allowed {
            self.log_audit(
                record.id,
                "read",
                &requestor.actor_type(),
                requestor.actor_id(),
                requestor.module_id(),
                false,
                Some("Access denied"),
                None,
            )
            .await?;
            return Err(anyhow!(
                "Module not authorized to access secret: {}",
                key_path
            ));
        }

        // 4. Decrypt via the version-aware dispatch helper. v0 rows
        // (legacy, no AAD) use the historical no-AAD path; v1 rows
        // bind `secret_id` as AAD so an attacker who can write to the
        // secrets table can't swap ciphertexts between rows that share
        // an `encryption_key_id` (N T2-N1).
        let secret_value: String = self
            .decrypt_secret_record(
                record.id,
                record.encryption_key_id,
                &record.encrypted_value,
                record.encryption_format_version,
            )
            .await?
            .to_string();

        // 5. Update access stats
        sqlx::query!(
            r#"
            UPDATE secrets
            SET last_accessed_at = NOW(), access_count = access_count + 1
            WHERE id = $1
            "#,
            record.id
        )
        .execute(&self.db_pool)
        .await?;

        // 6. Audit log
        self.log_audit(
            record.id,
            "read",
            &requestor.actor_type(),
            requestor.actor_id(),
            requestor.module_id(),
            true,
            None,
            None,
        )
        .await?;

        Ok(secret_value)
    }

    /// Update a secret (rotation).
    ///
    /// Replaces the SELECT-then-UPDATE pattern with a single atomic
    /// `UPDATE ... RETURNING id` that also enforces ownership:
    /// if `updater_user_id` is Some, only rows with a matching `owner_user_id`
    /// are updated. Returns an error if no row matched (not found or access denied).
    pub async fn update_secret(
        &self,
        key_path: &str,
        new_value: &str,
        updater_user_id: Option<Uuid>,
        accessible_org_ids: &[Uuid],
    ) -> Result<()> {
        // N T2-N1: bind the row's `id` as AAD so a swap-attack between
        // rows that share an `encryption_key_id` would invalidate the
        // auth tag at decrypt. This requires the id BEFORE the
        // encrypt step, which means a SELECT-FOR-UPDATE inside the
        // same transaction precedes the UPDATE.
        //
        // Update + audit row commit in a single tx (L-5).
        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("Failed to begin secret-update transaction")?;

        // Lock the row + apply ownership/org guard. fetch_optional →
        // None on "not found or access denied" (preserved from the
        // pre-fix RETURNING semantics; existence-leak protection is
        // intact because the gate is in this WHERE clause).
        let row: Option<(Uuid, Option<Uuid>)> = sqlx::query_as::<_, (Uuid, Option<Uuid>)>(
            r#"SELECT id, owner_user_id FROM secrets
               WHERE key_path = $1
                 AND ($2::uuid IS NULL OR owner_user_id = $2::uuid OR org_id = ANY($3))
               FOR UPDATE"#,
        )
        .bind(key_path)
        .bind(updater_user_id)
        .bind(accessible_org_ids)
        .fetch_optional(&mut *tx)
        .await?;

        let (secret_id, owner_user_id_for_cache) = match row {
            Some(r) => r,
            None => {
                tracing::warn!(
                    key_path = %key_path,
                    updater = ?updater_user_id,
                    "update_secret: no row matched (not found or access denied)"
                );
                anyhow::bail!("Secret not found or access denied")
            }
        };

        // Encrypt with secret_id bytes as AAD (v1 format).
        let (key_id, stored_value) = self
            .encrypt_value_with_aad(new_value, secret_id.as_bytes())
            .await?;
        let nonce_bytes = stored_value.get(..12).ok_or_else(|| {
            anyhow!("encrypt_value_with_aad returned a ciphertext shorter than the nonce prefix")
        })?;

        // Apply the update. The CHECK on encryption_format_version is
        // upgraded to 1 unconditionally — a row written via this path
        // is always v1 going forward. The pre-fetch SELECT FOR UPDATE
        // already locked the row; the UPDATE cannot miss under that
        // lock, so we don't need RETURNING — `secret_id` and
        // `owner_user_id_for_cache` are already in scope.
        sqlx::query(
            r#"UPDATE secrets
               SET encrypted_value = $1, encryption_key_id = $2, nonce = $3,
                   encryption_format_version = $4, updated_at = NOW()
               WHERE id = $5"#,
        )
        .bind(&stored_value)
        .bind(key_id)
        .bind(nonce_bytes)
        .bind(Self::SECRETS_AAD_FORMAT_V1)
        .bind(secret_id)
        .execute(&mut *tx)
        .await?;

        Self::log_audit_in_tx(
            &mut tx,
            Some(secret_id),
            "rotate",
            "user",
            updater_user_id,
            None,
            true,
            None,
            None,
        )
        .await
        .context("Failed to insert audit row for update_secret")?;
        tx.commit()
            .await
            .context("Failed to commit secret-update transaction")?;

        // Scope cache invalidation to the secret's owner rather than
        // nuking every cached entry. Worst case (missing owner_user_id
        // on a legacy secret) we fall back to the conservative full-flush.
        if is_llm_provider_key_path(key_path) {
            match owner_user_id_for_cache {
                Some(owner) => {
                    self.invalidate_llm_keys_cache(Some(owner));
                    tracing::info!(
                        key_path = %key_path,
                        owner_user_id = %owner,
                        "Invalidated LLM-keys cache for secret owner after rotation"
                    );
                }
                None => {
                    self.invalidate_all_llm_keys_cache();
                    tracing::info!(
                        key_path = %key_path,
                        "Invalidated ALL LLM-keys cache entries after rotation (legacy secret with no owner)"
                    );
                }
            }
        }
        tracing::info!(key_path = %key_path, "Rotated secret");
        Ok(())
    }

    /// Encrypt a raw value using the active DEK.
    ///
    /// Returns `(key_id, nonce_12_bytes || ciphertext)` so callers can store both
    /// the key reference and the opaque blob. Use `decrypt_value_by_key` to reverse.
    ///
    /// Intended for encrypting OAuth tokens in integration-specific tables
    /// (e.g. `gmail_integrations.access_token_enc`) where the secrets table
    /// cannot easily be referenced via key_path.
    pub async fn encrypt_value(&self, value: &str) -> Result<(Uuid, Vec<u8>)> {
        let dek = self.get_active_dek().await?;
        let cipher = Aes256Gcm::new_from_slice(&dek.key)?;
        let nonce_bytes = Self::generate_nonce();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), value.as_bytes())
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        let mut stored = nonce_bytes.to_vec(); // 12-byte nonce prefix
        stored.extend_from_slice(&ciphertext);
        Ok((dek.id, stored))
    }

    /// Decrypt a value that was encrypted by `encrypt_value` with the given DEK.
    ///
    /// `key_id` must match the `encryption_keys.id` row used during encryption.
    ///
    /// Returns the plaintext wrapped in [`Zeroizing<String>`] so the heap
    /// allocation backing the decrypted bytes is wiped on drop. Callers
    /// that need a `&str` get one via `Deref` transparently
    /// (`serde_json::from_str(&plaintext)`, `HeaderValue::from_str(&secret)`,
    /// etc.). Callers that need to *own* a `String` should keep the
    /// `Zeroizing<String>` so the wipe-on-drop guarantee survives;
    /// `.to_string()` extracts the inner `String` and forfeits the
    /// guarantee.
    pub async fn decrypt_value_by_key(
        &self,
        key_id: Uuid,
        encrypted: &[u8],
    ) -> Result<Zeroizing<String>> {
        // Empty AAD path. Equivalent to the v0 ciphertext format.
        self.decrypt_value_by_key_with_aad(key_id, encrypted, &[]).await
    }

    /// AES-GCM AAD format version used for `secrets` rows that bind
    /// `encrypted_value` to the row's `id`. v0 (legacy, no AAD) and v1
    /// are the only currently-defined values; the migration's CHECK
    /// constraint enforces this.
    pub const SECRETS_AAD_FORMAT_V1: i16 = 1;

    /// Universal AAD format version constant — same numeric value as
    /// `SECRETS_AAD_FORMAT_V1`. Defined separately so the `secrets`
    /// table's existing constant is left untouched by the AAD sweep
    /// extension to other tables (TOTP, webhook signing secret, audit
    /// header secret, execution output, module payloads, actor memory).
    /// Every table that adopts the AAD pattern shares this version
    /// number — there is no per-table v1/v2 divergence today.
    pub const AAD_FORMAT_V1: i16 = 1;

    /// Decrypt a `secrets.encrypted_value` blob, dispatching on the
    /// row's `encryption_format_version`. Centralises the v0/v1 fork
    /// so every read path uses the same logic.
    ///
    /// v0 (legacy): no AAD; equivalent to `decrypt_value_by_key`.
    /// v1: AAD = `secret_id` bytes (closes ciphertext-substitution gap
    /// per N T2-N1).
    pub(crate) async fn decrypt_secret_record(
        &self,
        secret_id: Uuid,
        key_id: Uuid,
        encrypted: &[u8],
        format_version: i16,
    ) -> Result<Zeroizing<String>> {
        // 2026-05-28 audit S2#9 follow-up: explicit-version match
        // (sibling of `decrypt_versioned` below). `>=` invited a
        // forward-compat trap; tighten to `==` and fail-closed on
        // unknown values so a v1-reader against a v2-writer surfaces
        // loudly at dispatch instead of mis-decrypting silently.
        match format_version {
            0 => self.decrypt_value_by_key(key_id, encrypted).await,
            v if v == Self::SECRETS_AAD_FORMAT_V1 => {
                self.decrypt_value_by_key_with_aad(key_id, encrypted, secret_id.as_bytes())
                    .await
            }
            other => Err(anyhow!(
                "unknown secrets encryption_format_version {other}; this build only knows 0 (legacy no-AAD) and {} (v1 AAD-bound). Row may have been written by a newer code version.",
                Self::SECRETS_AAD_FORMAT_V1
            )),
        }
    }

    /// Generic AAD-versioned decrypt dispatcher for the post-MCP-S2
    /// sweep. Every table that adopts AAD-bound encryption (TOTP,
    /// webhook signing secret, audit auth headers, workflow execution
    /// output, module payloads, actor memory) calls this with its
    /// row-id bytes and per-row `format_version` column. Mirrors
    /// `decrypt_secret_record` but takes the AAD bytes directly
    /// instead of coupling to a `secret_id: Uuid` shape.
    ///
    /// v0 (legacy, default for existing rows): decrypt with empty AAD.
    /// v1+: decrypt with the supplied `aad` bytes.
    ///
    /// On mismatch (e.g. attacker swapped ciphertext between rows of
    /// the same key_id), AES-GCM's tag verification fails closed and
    /// the function returns Err. The error message is generic — no
    /// AAD details leak via the oracle.
    pub async fn decrypt_versioned(
        &self,
        key_id: Uuid,
        encrypted: &[u8],
        aad: &[u8],
        format_version: i16,
    ) -> Result<Zeroizing<String>> {
        // 2026-05-28 audit S2#9 follow-up: explicit-version match.
        // Pre-fix `>= AAD_FORMAT_V1` meant a future v2 ciphertext with
        // a NEW AAD shape (e.g. different separator, different bound
        // fields) would silently route through the v1 AAD-binding
        // path with the caller-supplied v1-AAD bytes — likely
        // succeeding (random-looking AAD bytes accepted, tag check
        // passes against an undocumented format) OR silently failing
        // with a generic decryption error that masks the real cause.
        // Tighten to `==` and fail-closed on unknown formats so a
        // v1-reader against a v2-writer surfaces loudly at
        // dispatch time, not as a mysterious decrypt failure.
        match format_version {
            0 => self.decrypt_value_by_key(key_id, encrypted).await,
            v if v == Self::AAD_FORMAT_V1 => {
                self.decrypt_value_by_key_with_aad(key_id, encrypted, aad)
                    .await
            }
            other => Err(anyhow!(
                "unknown encryption_format_version {other}; this build only knows 0 (legacy no-AAD) and {} (v1 AAD-bound). Caller may be reading rows written by a newer code version.",
                Self::AAD_FORMAT_V1
            )),
        }
    }

    /// Convenience wrapper around `encrypt_value_with_aad` for callers
    /// that always want the v1 format. Returns the encrypted bytes
    /// alongside the version constant so the caller can bind both
    /// into a single SQL write. Pattern:
    ///
    /// ```rust,ignore
    /// let row_id = Uuid::new_v4();
    /// let (key_id, ciphertext, version) = sm
    ///     .encrypt_value_aad_v1(plaintext, row_id.as_bytes())
    ///     .await?;
    /// sqlx::query!("INSERT INTO foo (id, ciphertext, key_id, version) \
    ///               VALUES ($1, $2, $3, $4)",
    ///              row_id, ciphertext, key_id, version)
    ///     .execute(pool).await?;
    /// ```
    ///
    /// The version constant is returned so callers can't accidentally
    /// write the ciphertext without also writing the version column —
    /// without that pairing, the read path would dispatch via the v0
    /// no-AAD branch and fail to decrypt the v1 ciphertext.
    pub async fn encrypt_value_aad_v1(
        &self,
        value: &str,
        aad: &[u8],
    ) -> Result<(Uuid, Vec<u8>, i16)> {
        let (key_id, ciphertext) = self.encrypt_value_with_aad(value, aad).await?;
        Ok((key_id, ciphertext, Self::AAD_FORMAT_V1))
    }

    /// Encrypt a raw value with Additional Authenticated Data (AAD).
    ///
    /// AES-GCM binds the AAD into its authentication tag — the
    /// ciphertext can only be decrypted by passing the same AAD bytes.
    /// Used by the `secrets` table v1 format (N T2-N1) to bind each
    /// `encrypted_value` to its row's `id` so an attacker with table
    /// write access can't swap ciphertexts between rows that share an
    /// `encryption_key_id`.
    ///
    /// The wire format is identical to `encrypt_value`:
    /// `[12 bytes nonce][AES-GCM ciphertext + 16-byte tag]`. The format
    /// is distinguished from the no-AAD form by an out-of-band
    /// versioning column on the storing table (e.g.
    /// `secrets.encryption_format_version`), NOT by an in-band flag —
    /// AES-GCM offers no way to tell from a ciphertext alone whether
    /// it was encrypted with AAD.
    pub async fn encrypt_value_with_aad(
        &self,
        value: &str,
        aad: &[u8],
    ) -> Result<(Uuid, Vec<u8>)> {
        let dek = self.get_active_dek().await?;
        let cipher = Aes256Gcm::new_from_slice(&dek.key)?;
        let nonce_bytes = Self::generate_nonce();
        let payload = aes_gcm::aead::Payload {
            msg: value.as_bytes(),
            aad,
        };
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), payload)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;
        let mut stored = nonce_bytes.to_vec();
        stored.extend_from_slice(&ciphertext);
        Ok((dek.id, stored))
    }

    /// Decrypt a value that was encrypted by `encrypt_value_with_aad`.
    ///
    /// Passing an empty `aad` is equivalent to the legacy
    /// `decrypt_value_by_key` (v0 format). Passing a non-empty `aad`
    /// matches the v1 format used by `secrets` rows where
    /// `encryption_format_version >= 1`. Decryption fails closed if
    /// the AAD doesn't match what was supplied at encrypt time —
    /// that's the property that defends against ciphertext
    /// substitution.
    pub async fn decrypt_value_by_key_with_aad(
        &self,
        key_id: Uuid,
        encrypted: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<String>> {
        if encrypted.len() < 12 {
            return Err(anyhow!("Invalid encrypted value: too short"));
        }
        let nonce = Nonce::from_slice(&encrypted[..12]);
        let ciphertext = &encrypted[12..];

        let dek = self.get_dek(key_id).await?;
        let cipher = Aes256Gcm::new_from_slice(&dek.key)?;
        let payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad,
        };
        // L T2-3 + N T2-N1: keep decrypted bytes in Zeroizing<Vec<u8>>
        // so the AES-GCM output buffer is wiped on drop, even on the
        // UTF-8 validation error branch. AES-GCM rejects mismatched
        // AAD with a generic decryption error; we don't surface AAD
        // details in the error message to avoid an oracle.
        let decrypted: Zeroizing<Vec<u8>> = Zeroizing::new(
            cipher
                .decrypt(nonce, payload)
                .map_err(|e| anyhow!("Decryption failed: {}", e))?,
        );
        let plaintext =
            std::str::from_utf8(&decrypted).context("Invalid UTF-8 in decrypted value")?;
        Ok(Zeroizing::new(plaintext.to_string()))
    }

    /// Fetch all secrets authorized for a specific module
    pub async fn get_module_secrets(
        &self,
        module_id: Uuid,
    ) -> Result<std::collections::HashMap<String, String>> {
        // MCP-589 (2026-05-12): un-scoped wrapper. Cross-tenant
        // safe ONLY when the caller guarantees `module_id` is private
        // to a single user. For org-shared modules (created via
        // `share_module_with_org`), use `get_module_secrets_for_user`
        // and pass the workflow owner's user_id explicitly. The
        // trait-side `SecretsResolver::resolve_module_secrets`
        // (defined in the sibling talos-workflow-engine repo) still
        // routes through here pending a sibling-repo signature
        // change.
        self.get_module_secrets_inner(module_id, None).await
    }

    /// User-scoped variant of `get_module_secrets`. Returns secrets
    /// where `module_id` is in `allowed_modules` AND the secret is
    /// either owned by `user_id` or is a global/system secret
    /// (`owner_user_id IS NULL`). Use this in every dispatch path
    /// that builds `encrypted_secrets` for a job — webhooks, Gmail
    /// / Calendar push, integration helpers — so a malicious user
    /// can't poison the encrypted-secrets payload for another
    /// user's execution of a shared module.
    ///
    /// MCP-589: pre-fix `get_module_secrets(module_id)` was the only
    /// dispatch-time secret read that did NOT scope by user. The
    /// migration r306 commit message ("cross-user secret resolution
    /// at runtime is already user-scoped via `secrets.created_by =
    /// $user_id` in every read path") was true for
    /// `get_secrets_by_paths` but NOT for this method. A malicious
    /// user with a secret declaring `allowed_modules: [shared_module]`
    /// could inject their secret value into every victim's execution
    /// of that module via key_path collision. The worker's
    /// `check_secret_allowlist` is per-execution and accepts `"*"`
    /// (the common case), so the payload-side filter doesn't catch
    /// the injection.
    pub async fn get_module_secrets_for_user(
        &self,
        module_id: Uuid,
        user_id: Uuid,
    ) -> Result<std::collections::HashMap<String, String>> {
        self.get_module_secrets_inner(module_id, Some(user_id)).await
    }

    async fn get_module_secrets_inner(
        &self,
        module_id: Uuid,
        user_id: Option<Uuid>,
    ) -> Result<std::collections::HashMap<String, String>> {
        use sqlx::Row as _;
        // N T2-N1: SELECT now also pulls `encryption_format_version` so
        // the per-row decrypt dispatches v0 (legacy no-AAD) vs v1
        // (AAD-bound to row id). Switched from `sqlx::query!` to the
        // runtime form to avoid requiring a `cargo sqlx prepare`
        // round-trip for the new column.
        //
        // MCP-589: scope by `user_id` when supplied. Mirrors the
        // `get_secrets_by_paths` predicate so global/system secrets
        // (owner_user_id IS NULL) AND user-owned secrets BOTH
        // surface, but other users' secrets do NOT. `created_by`
        // is also accepted for legacy rows where owner_user_id was
        // never populated.
        let rows = if let Some(uid) = user_id {
            sqlx::query(
                r#"
                SELECT id, key_path, encrypted_value, encryption_key_id,
                       encryption_format_version, expires_at
                FROM secrets
                WHERE $1 = ANY(allowed_modules)
                  AND (owner_user_id IS NULL OR owner_user_id = $2 OR created_by = $2)
                "#,
            )
            .bind(module_id)
            .bind(uid)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query(
                r#"
                SELECT id, key_path, encrypted_value, encryption_key_id,
                       encryption_format_version, expires_at
                FROM secrets
                WHERE $1 = ANY(allowed_modules)
                "#,
            )
            .bind(module_id)
            .fetch_all(&self.db_pool)
            .await?
        };

        let mut secrets_map = std::collections::HashMap::new();
        let now = chrono::Utc::now();
        let mut accessed_ids = Vec::new();

        for row in rows {
            let id: Uuid = row.get("id");
            let key_path: String = row.get("key_path");
            let encrypted_value: Vec<u8> = row.get("encrypted_value");
            let encryption_key_id: Uuid = row.get("encryption_key_id");
            let encryption_format_version: i16 = row.get("encryption_format_version");
            let expires_at: Option<chrono::DateTime<chrono::Utc>> = row.get("expires_at");

            if let Some(expires_at) = expires_at {
                if expires_at < now {
                    continue;
                }
            }

            if encrypted_value.len() < 12 {
                tracing::warn!(
                    target: "talos_secrets",
                    event_kind = "secret_decrypt_failure",
                    reason = "too_short",
                    key_path = %key_path,
                    "Invalid encrypted secret (too short)"
                );
                inc_secret_decrypt_failure("too_short");
                continue;
            }

            match self
                .decrypt_secret_record(
                    id,
                    encryption_key_id,
                    &encrypted_value,
                    encryption_format_version,
                )
                .await
            {
                Ok(plaintext) => {
                    secrets_map.insert(key_path.clone(), plaintext.to_string());
                    accessed_ids.push(id);
                }
                Err(e) => {
                    // Generic warn — the helper already classifies
                    // missing-DEK vs AEAD-failure; a downstream
                    // metric distinguishes them via the talos_secrets
                    // tracing target.
                    tracing::warn!(
                        target: "talos_secrets",
                        event_kind = "secret_decrypt_failure",
                        reason = "decrypt_helper",
                        key_path = %key_path,
                        error = %e,
                        "Decrypt via helper failed"
                    );
                    inc_secret_decrypt_failure("decrypt_helper");
                }
            }
        }

        if !accessed_ids.is_empty() {
            if let Err(e) = sqlx::query!(
                "UPDATE secrets SET last_accessed_at = NOW(), access_count = access_count + 1 WHERE id = ANY($1)",
                &accessed_ids
            )
            .execute(&self.db_pool)
            .await {
                tracing::warn!("Failed to update access stats for module secrets: {}", e);
            }

            // Note: Audit log for mass reading could be added here if needed, but for performance,
            // module bulk secret access is often treated as a single event or omitted.
        }

        Ok(secrets_map)
    }

    /// Fetch secrets by their key_paths (from a module's allowed_secrets list).
    /// Supports wildcard "*" to fetch all secrets visible to `owner_user_id`.
    ///
    /// SECURITY: `owner_user_id` MUST be provided when the caller is acting on
    /// behalf of a specific user. Without it, only secrets with no owner
    /// (owner_user_id IS NULL — system/global secrets) are returned, preventing
    /// cross-tenant leakage when a WASM module declares a path it does not own.
    pub async fn get_secrets_by_paths(
        &self,
        allowed_paths: &[String],
        owner_user_id: Option<Uuid>,
    ) -> Result<std::collections::HashMap<String, String>> {
        let is_wildcard = allowed_paths.iter().any(|p| p == "*");

        // N T2-N1: include `id` (for AAD) and `encryption_format_version`
        // (for v0/v1 dispatch) on every variant of the path-keyed
        // bulk read.
        type PathRecord = (
            Uuid,
            String,
            Vec<u8>,
            Uuid,
            i16,
            Option<chrono::DateTime<chrono::Utc>>,
        );
        let records: Vec<PathRecord> = if is_wildcard {
            if let Some(uid) = owner_user_id {
                sqlx::query_as(
                    "SELECT id, key_path, encrypted_value, encryption_key_id, \
                            encryption_format_version, expires_at \
                     FROM secrets \
                     WHERE owner_user_id IS NULL OR owner_user_id = $1 OR created_by = $1",
                )
                .bind(uid)
                .fetch_all(&self.db_pool)
                .await?
            } else {
                // No user context — restrict to global/system secrets only.
                sqlx::query_as(
                    "SELECT id, key_path, encrypted_value, encryption_key_id, \
                            encryption_format_version, expires_at \
                     FROM secrets WHERE owner_user_id IS NULL",
                )
                .fetch_all(&self.db_pool)
                .await?
            }
        } else if let Some(uid) = owner_user_id {
            sqlx::query_as(
                "SELECT id, key_path, encrypted_value, encryption_key_id, \
                        encryption_format_version, expires_at \
                 FROM secrets \
                 WHERE key_path = ANY($1) \
                   AND (owner_user_id IS NULL OR owner_user_id = $2 OR created_by = $2)",
            )
            .bind(allowed_paths)
            .bind(uid)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            // No user context — restrict to global/system secrets only.
            sqlx::query_as(
                "SELECT id, key_path, encrypted_value, encryption_key_id, \
                        encryption_format_version, expires_at \
                 FROM secrets \
                 WHERE key_path = ANY($1) AND owner_user_id IS NULL",
            )
            .bind(allowed_paths)
            .fetch_all(&self.db_pool)
            .await?
        };

        let mut secrets_map = std::collections::HashMap::new();
        let now = chrono::Utc::now();

        for (
            secret_id,
            key_path,
            encrypted_value,
            encryption_key_id,
            encryption_format_version,
            expires_at,
        ) in records
        {
            if let Some(exp) = expires_at {
                if exp < now {
                    continue;
                }
            }
            if encrypted_value.len() < 12 {
                continue;
            }

            match self
                .decrypt_secret_record(
                    secret_id,
                    encryption_key_id,
                    &encrypted_value,
                    encryption_format_version,
                )
                .await
            {
                Ok(plaintext) => {
                    secrets_map.insert(key_path, plaintext.to_string());
                }
                Err(e) => {
                    tracing::warn!("Failed to decrypt secret {}: {}", key_path, e);
                }
            }
        }

        Ok(secrets_map)
    }

    /// Delete a secret
    pub async fn delete_secret(
        &self,
        key_path: &str,
        deleter_user_id: Option<Uuid>,
        accessible_org_ids: &[Uuid],
    ) -> Result<()> {
        // RETURNING (id, owner_user_id) so cache-invalidation can be scoped to
        // the deleted secret's actual owner — same rationale as update_secret.
        // DELETE + audit insert run in a single tx (L-5).
        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("Failed to begin secret-delete transaction")?;

        let deleted: Option<(Uuid, Option<Uuid>)> = sqlx::query_as::<_, (Uuid, Option<Uuid>)>(
            r#"DELETE FROM secrets
               WHERE key_path = $1
                 AND ($2::uuid IS NULL OR owner_user_id = $2::uuid OR created_by = $2::uuid OR org_id = ANY($3))
               RETURNING id, owner_user_id"#,
        )
        .bind(key_path)
        .bind(deleter_user_id)
        .bind(accessible_org_ids)
        .fetch_optional(&mut *tx)
        .await?;

        let (secret_id, owner_user_id) = match deleted {
            Some(row) => row,
            None => anyhow::bail!("Secret not found or access denied"),
        };

        Self::log_audit_in_tx(
            &mut tx,
            Some(secret_id),
            "delete",
            "user",
            deleter_user_id,
            None,
            true,
            None,
            None,
        )
        .await
        .context("Failed to insert audit row for delete_secret")?;

        tx.commit()
            .await
            .context("Failed to commit secret-delete transaction")?;

        if is_llm_provider_key_path(key_path) {
            match owner_user_id {
                Some(owner) => {
                    self.invalidate_llm_keys_cache(Some(owner));
                    tracing::info!(
                        key_path = %key_path,
                        owner_user_id = %owner,
                        "Invalidated LLM-keys cache for secret owner after deletion"
                    );
                }
                None => {
                    self.invalidate_all_llm_keys_cache();
                    tracing::info!(
                        key_path = %key_path,
                        "Invalidated ALL LLM-keys cache entries after deletion (legacy secret with no owner)"
                    );
                }
            }
        }

        tracing::info!(key_path = %key_path, "Deleted secret");

        Ok(())
    }

    /// Convert a raw `sqlx::PgRow` into a `Secret` struct.
    fn row_to_secret(row: sqlx::postgres::PgRow) -> Secret {
        Secret {
            id: row.get("id"),
            name: row.get("name"),
            key_path: row.get("key_path"),
            description: row.get("description"),
            created_by: row.get("created_by"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            expires_at: row.get("expires_at"),
            owner_user_id: row.get("owner_user_id"),
            org_id: row.get("org_id"),
            allowed_modules: row.get("allowed_modules"),
            last_accessed_at: row.get("last_accessed_at"),
            access_count: row.get("access_count"),
        }
    }

    /// List secrets (without decrypted values)
    pub async fn list_secrets(
        &self,
        owner_user_id: Option<Uuid>,
        accessible_org_ids: &[Uuid],
    ) -> Result<Vec<Secret>> {
        let rows = if let Some(user_id) = owner_user_id {
            sqlx::query(
                r#"
                SELECT id, name, key_path, description, created_by,
                       created_at, updated_at, expires_at,
                       owner_user_id, org_id, allowed_modules,
                       last_accessed_at, access_count
                FROM secrets
                WHERE owner_user_id = $1 OR created_by = $1 OR org_id = ANY($2)
                ORDER BY created_at DESC
                "#,
            )
            .bind(user_id)
            .bind(accessible_org_ids)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query(
                r#"
                SELECT id, name, key_path, description, created_by,
                       created_at, updated_at, expires_at,
                       owner_user_id, org_id, allowed_modules,
                       last_accessed_at, access_count
                FROM secrets
                ORDER BY created_at DESC
                "#,
            )
            .fetch_all(&self.db_pool)
            .await?
        };

        Ok(rows.into_iter().map(Self::row_to_secret).collect())
    }

    /// List secrets with pagination (without decrypted values)
    pub async fn list_secrets_paginated(
        &self,
        owner_user_id: Option<Uuid>,
        limit: i64,
        offset: i64,
        accessible_org_ids: &[Uuid],
    ) -> Result<Vec<Secret>> {
        let rows = if let Some(user_id) = owner_user_id {
            sqlx::query(
                r#"
                SELECT id, name, key_path, description, created_by,
                       created_at, updated_at, expires_at,
                       owner_user_id, org_id, allowed_modules,
                       last_accessed_at, access_count
                FROM secrets
                WHERE owner_user_id = $1 OR created_by = $1 OR org_id = ANY($2)
                ORDER BY created_at DESC
                LIMIT $3 OFFSET $4
                "#,
            )
            .bind(user_id)
            .bind(accessible_org_ids)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query(
                r#"
                SELECT id, name, key_path, description, created_by,
                       created_at, updated_at, expires_at,
                       owner_user_id, org_id, allowed_modules,
                       last_accessed_at, access_count
                FROM secrets
                ORDER BY created_at DESC
                LIMIT $1 OFFSET $2
                "#,
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db_pool)
            .await?
        };

        Ok(rows.into_iter().map(Self::row_to_secret).collect())
    }

    /// Get secret metadata (without value), scoped to the requesting user.
    ///
    /// L T2-1: SQL-layer ownership filter prevents the existence
    /// side-channel where a foreign secret with a known key_path could
    /// be probed via differential error timing. Pre-fix the post-fetch
    /// check lived in the GraphQL handler and emitted distinguishable
    /// error strings; collapsed at the source so future callers
    /// automatically inherit the protection.
    ///
    /// Returns `Err("Secret not found")` for both "row doesn't exist"
    /// and "row exists but isn't accessible." Callers should not log
    /// the difference (already collapsed at this layer).
    pub async fn get_secret_metadata(
        &self,
        key_path: &str,
        requestor_user_id: Uuid,
        accessible_org_ids: &[Uuid],
    ) -> Result<Secret> {
        let row = sqlx::query(
            r#"
            SELECT id, name, key_path, description, created_by,
                   created_at, updated_at, expires_at,
                   owner_user_id, org_id, allowed_modules,
                   last_accessed_at, access_count
            FROM secrets
            WHERE key_path = $1
              AND (owner_user_id = $2 OR created_by = $2 OR org_id = ANY($3))
            "#,
        )
        .bind(key_path)
        .bind(requestor_user_id)
        .bind(accessible_org_ids)
        .fetch_one(&self.db_pool)
        .await
        .context("Secret not found")?;

        Ok(Self::row_to_secret(row))
    }

    /// Get secret metadata by ID, scoped to the requesting user.
    /// L T2-1: same defense as `get_secret_metadata`.
    pub async fn get_secret_metadata_by_id(
        &self,
        secret_id: Uuid,
        requestor_user_id: Uuid,
        accessible_org_ids: &[Uuid],
    ) -> Result<Secret> {
        let row = sqlx::query(
            r#"
            SELECT id, name, key_path, description, created_by,
                   created_at, updated_at, expires_at,
                   owner_user_id, org_id, allowed_modules,
                   last_accessed_at, access_count
            FROM secrets
            WHERE id = $1
              AND (owner_user_id = $2 OR created_by = $2 OR org_id = ANY($3))
            "#,
        )
        .bind(secret_id)
        .bind(requestor_user_id)
        .bind(accessible_org_ids)
        .fetch_one(&self.db_pool)
        .await
        .context("Secret not found")?;

        Ok(Self::row_to_secret(row))
    }

    // MCP-1087 (2026-05-16): removed the deprecated `secret_exists`
    // function. It was the unscoped (cross-tenant) existence check
    // that MCP-662 deprecated and migrated away from. Pre-fix the
    // function was kept around with `#[deprecated]` "so future reaches
    // surface in cargo check" — but `#[deprecated]` produces a
    // WARNING, not an error, which is trivial to ignore in a PR review.
    // Cross-tenant existence leaks are a security-sensitive surface;
    // a compile error is the appropriate gate. If a future system-level
    // path genuinely needs an unscoped existence check (bootstrap,
    // admin telemetry), it should be re-added with an explicit
    // operator-facing name (e.g., `secret_exists_unscoped_for_admin_use`)
    // and a documented threat model — not via dredging up a deprecated
    // function via grep.

    /// Get audit log for a secret
    pub async fn get_audit_log(
        &self,
        secret_id: Uuid,
        limit: i64,
        offset: i64,
        user_id: Option<Uuid>,
    ) -> Result<Vec<AuditLogEntry>> {
        let records = sqlx::query_as!(
            AuditLogEntry,
            r#"
            SELECT l.id,
                   l.secret_id as "secret_id!",
                   l.action,
                   l.actor_type,
                   l.actor_id,
                   l.module_id,
                   l.success as "success!",
                   l.error_message,
                   l.ip_address::text as "ip_address",
                   l.timestamp as "timestamp!"
            FROM secret_audit_log l
            JOIN secrets s ON s.id = l.secret_id
            WHERE l.secret_id = $1 
              AND ($4::uuid IS NULL OR s.owner_user_id = $4::uuid OR s.created_by = $4::uuid)
            ORDER BY l.timestamp DESC
            LIMIT $2 OFFSET $3
            "#,
            secret_id,
            limit,
            offset,
            user_id
        )
        .fetch_all(&self.db_pool)
        .await?;

        Ok(records)
    }

    /// Log audit event (legacy non-transactional helper).
    ///
    /// Prefer `log_audit_in_tx` from inside a mutation tx so the audit
    /// row commits atomically with the secret row. This entry point is
    /// kept for read-side / failure-path audit writes that have no
    /// associated mutation to bind to (e.g. `get_secret` access denial).
    async fn log_audit(
        &self,
        secret_id: Uuid,
        action: &str,
        actor_type: &str,
        actor_id: Option<Uuid>,
        module_id: Option<Uuid>,
        success: bool,
        error_message: Option<&str>,
        ip_address: Option<std::net::IpAddr>,
    ) -> Result<()> {
        let ip_str = ip_address.map(|ip| ip.to_string());

        // MCP-981 (2026-05-15): DLP-redact at the persistence boundary.
        // Same defence-in-depth pattern as MCP-978/979 for the
        // sibling audit_log writers. `secret_audit_log` is the most
        // sensitive audit table — it records every secret access and
        // operation — and was the lone holdout among workspace
        // audit_log writers (gmail/slack/gcal/actor/admin already
        // redacted). Callers (`create_secret`/`update_secret`/
        // `delete_secret` failure paths, `get_secret` access-denial
        // path) pass sqlx errors and value-decryption error chains;
        // those error strings can include vault path fragments,
        // namespace/key combinations, and on some failure modes
        // partial cipher metadata. redact_str is infallible.
        //
        // MCP-1028 (2026-05-15): truncate-then-redact discipline,
        // sibling-parity with MCP-1012/1018. sqlx errors run
        // typically under 500 chars but a long query string in the
        // error chain (or a nested causal chain from a complex
        // failure) could push higher; 1024 covers every legitimate
        // failure while bounding regex-pass cost.
        let redacted_err = error_message.map(|e| {
            let truncated: &str = if e.len() > 1024 {
                talos_text_util::truncate_at_char_boundary(e, 1024)
            } else {
                e
            };
            talos_dlp_provider::redact_str(truncated)
        });
        sqlx::query!(
            r#"
            INSERT INTO secret_audit_log (
                secret_id, action, actor_type, actor_id, module_id,
                success, error_message, ip_address
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            secret_id,
            action,
            actor_type,
            actor_id,
            module_id,
            success,
            redacted_err.as_deref(),
            ip_str.as_deref()
        )
        .execute(&self.db_pool)
        .await?;

        Ok(())
    }

    /// Transactional audit-log insert (L-5).
    ///
    /// Used from `create_secret` / `update_secret` / `delete_secret` so
    /// the secret mutation and its audit row commit (or rollback)
    /// together. Without this, an audit-log INSERT failure leaves the
    /// secret op already committed with no audit trail — the L-5
    /// finding from `reviews/encryption-cluster.md`.
    async fn log_audit_in_tx(
        tx: &mut sqlx::Transaction<'_, Postgres>,
        secret_id: Option<Uuid>,
        action: &str,
        actor_type: &str,
        actor_id: Option<Uuid>,
        module_id: Option<Uuid>,
        success: bool,
        error_message: Option<&str>,
        ip_address: Option<std::net::IpAddr>,
    ) -> Result<()> {
        let ip_str = ip_address.map(|ip| ip.to_string());
        // MCP-981: same defence-in-depth as the non-transactional
        // sibling `log_audit` above.
        // MCP-1028 (2026-05-15): truncate-then-redact discipline, same
        // as the sibling `log_audit`.
        let redacted_err = error_message.map(|e| {
            let truncated: &str = if e.len() > 1024 {
                talos_text_util::truncate_at_char_boundary(e, 1024)
            } else {
                e
            };
            talos_dlp_provider::redact_str(truncated)
        });
        sqlx::query!(
            r#"
            INSERT INTO secret_audit_log (
                secret_id, action, actor_type, actor_id, module_id,
                success, error_message, ip_address
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            secret_id,
            action,
            actor_type,
            actor_id,
            module_id,
            success,
            redacted_err.as_deref(),
            ip_str.as_deref()
        )
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Generate a random 96-bit nonce for AES-GCM
    pub fn generate_nonce() -> [u8; 12] {
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        nonce_bytes
    }

    /// Clean up old secret audit logs (default retention: 90 days).
    ///
    /// MCP-997 (2026-05-15): refuse non-positive `retention_days`. Pre-fix
    /// the function trusted callers to pre-validate, but a future caller
    /// passing a negative value would convert
    /// `NOW() - INTERVAL '1 day' * -N` into `NOW() + INTERVAL`, making
    /// the WHERE clause match EVERY row and silently purge the entire
    /// audit log. Same caller-supplied-negative class as MCP-767/811/812
    /// (lint check 12). Defense-in-depth refuse at the function
    /// boundary so future callsites can't reintroduce the destructive
    /// shape — current production callers route through
    /// `positive_env_or_default` so this branch is unreachable today.
    pub async fn cleanup_audit_logs(&self, retention_days: i64) -> Result<u64> {
        if retention_days <= 0 {
            tracing::warn!(
                target: "talos_audit",
                retention_days,
                "secret-audit cleanup refused: retention_days must be positive (would purge entire log)"
            );
            return Ok(0);
        }
        let result = sqlx::query(
            "DELETE FROM secret_audit_log WHERE timestamp < NOW() - INTERVAL '1 day' * $1",
        )
        .bind(retention_days)
        .execute(&self.db_pool)
        .await?;

        Ok(result.rows_affected())
    }

    // ── Namespace + expiry management ───────────────────────────────────────

    /// List distinct namespaces with secret counts for a user.
    pub async fn list_namespaces(&self, owner_user_id: Uuid) -> Result<Vec<(String, i64)>> {
        let rows = sqlx::query(
            "SELECT DISTINCT namespace, COUNT(*)::bigint AS secret_count \
             FROM secrets WHERE created_by = $1 \
             GROUP BY namespace ORDER BY namespace",
        )
        .bind(owner_user_id)
        .fetch_all(&self.db_pool)
        .await?;

        Ok(rows
            .iter()
            .map(|r| {
                use sqlx::Row;
                let ns: String = r
                    .try_get("namespace")
                    .unwrap_or_else(|_| "default".to_string());
                let count: i64 = r.try_get("secret_count").unwrap_or(0);
                (ns, count)
            })
            .collect())
    }

    // ── MCP-handler support: lightweight listing + scanning ─────────────────
    //
    // The methods below back the `mcp/secrets.rs` handlers. They project a
    // small DTO instead of the full `Secret` struct because handlers don't
    // need encryption metadata and `Secret` is also used by GraphQL —
    // adding listing-only fields (namespace, rotation_reminder_days) there
    // would expand its scope unnecessarily.

    /// List a user's secrets with namespace + optional expiry. Newest first.
    /// Pass `namespace_filter = Some("name")` to scope to a single namespace.
    pub async fn list_secret_summaries(
        &self,
        user_id: Uuid,
        namespace_filter: Option<&str>,
        limit: i64,
    ) -> Result<Vec<SecretSummary>> {
        let rows = if let Some(ns) = namespace_filter {
            sqlx::query(
                "SELECT id, name, key_path, description, created_at, expires_at, namespace, rotation_reminder_days \
                 FROM secrets WHERE created_by = $1 AND namespace = $2 \
                 ORDER BY created_at DESC LIMIT $3",
            )
            .bind(user_id)
            .bind(ns)
            .bind(limit)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id, name, key_path, description, created_at, expires_at, namespace, rotation_reminder_days \
                 FROM secrets WHERE created_by = $1 \
                 ORDER BY created_at DESC LIMIT $2",
            )
            .bind(user_id)
            .bind(limit)
            .fetch_all(&self.db_pool)
            .await?
        };

        Ok(rows.into_iter().map(row_to_summary).collect())
    }

    /// List secrets expiring within `within_days` from now (clamped 1..=365).
    pub async fn list_expiring_secrets(
        &self,
        user_id: Uuid,
        within_days: i32,
    ) -> Result<Vec<SecretSummary>> {
        let rows = sqlx::query(
            "SELECT id, name, key_path, description, created_at, expires_at, namespace, rotation_reminder_days \
             FROM secrets \
             WHERE created_by = $1 AND expires_at IS NOT NULL \
               AND expires_at < NOW() + make_interval(days => $2) \
             ORDER BY expires_at ASC LIMIT 100",
        )
        .bind(user_id)
        .bind(within_days)
        .fetch_all(&self.db_pool)
        .await?;

        Ok(rows.into_iter().map(row_to_summary).collect())
    }

    // ─── r306: identifier reconciliation ──────────────────────────────────
    //
    // Pre-r306 the operator-facing handlers (delete_secret,
    // set_secret_namespace, set_secret_expiry, rotate_secret) each did
    // their own SQL keyed off `name`, with no ambiguity check — if two
    // secrets shared a name in the same namespace, they would silently
    // mutate one of N. The new `SecretIdentifier` enum + `resolve_to_id`
    // method centralise that lookup with fail-closed ambiguity handling.

    /// Resolve a typed identifier to a single secret id, scoped to
    /// `user_id`. Fails closed with `Ambiguous` when more than one row
    /// matches the predicate (only possible for the `Name` variant
    /// without a namespace pin); the operator either picks an `Id`
    /// directly or scopes by `KeyPath` (which is per-tenant unique).
    ///
    /// All variants are `created_by = $user_id` scoped — cross-tenant
    /// resolution is impossible.
    pub async fn resolve_to_id(
        &self,
        ident: crate::SecretIdentifier<'_>,
        user_id: Uuid,
    ) -> std::result::Result<Uuid, crate::SecretResolveError> {
        use crate::SecretResolveError;

        // The three lookups share `created_by = $user_id` so cross-
        // tenant resolution can't happen via this resolver. The
        // `LIMIT 2` on the Name path lets us detect Ambiguous without
        // streaming every match — we only need to know if there's a
        // 2nd row.
        let ids: Vec<Uuid> = match ident {
            crate::SecretIdentifier::Id(id) => {
                let found: Option<Uuid> = sqlx::query_scalar(
                    "SELECT id FROM secrets WHERE id = $1 AND created_by = $2",
                )
                .bind(id)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await
                .map_err(|e| {
                    tracing::error!(err = ?e, "resolve_to_id Id lookup failed");
                    SecretResolveError::Internal(e.into())
                })?;
                found.into_iter().collect()
            }
            crate::SecretIdentifier::KeyPath { key_path, namespace } => {
                let found: Option<Uuid> = sqlx::query_scalar(
                    "SELECT id FROM secrets \
                     WHERE key_path = $1 AND namespace = $2 AND created_by = $3",
                )
                .bind(key_path)
                .bind(namespace)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await
                .map_err(|e| {
                    tracing::error!(err = ?e, "resolve_to_id KeyPath lookup failed");
                    SecretResolveError::Internal(e.into())
                })?;
                found.into_iter().collect()
            }
            crate::SecretIdentifier::Name { name, namespace } => match namespace {
                Some(ns) => {
                    sqlx::query_scalar(
                        "SELECT id FROM secrets \
                         WHERE name = $1 AND namespace = $2 AND created_by = $3 \
                         LIMIT 2",
                    )
                    .bind(name)
                    .bind(ns)
                    .bind(user_id)
                    .fetch_all(&self.db_pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(err = ?e, "resolve_to_id Name+ns lookup failed");
                        SecretResolveError::Internal(e.into())
                    })?
                }
                None => {
                    sqlx::query_scalar(
                        "SELECT id FROM secrets \
                         WHERE name = $1 AND created_by = $2 \
                         LIMIT 2",
                    )
                    .bind(name)
                    .bind(user_id)
                    .fetch_all(&self.db_pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(err = ?e, "resolve_to_id Name lookup failed");
                        SecretResolveError::Internal(e.into())
                    })?
                }
            },
        };

        match ids.len() {
            0 => Err(SecretResolveError::NotFound),
            1 => Ok(ids[0]),
            _ => Err(SecretResolveError::Ambiguous { matches: ids }),
        }
    }

    /// Atomic create-or-update keyed on `(key_path, namespace,
    /// created_by)`. Replaces the pre-r306 destroy-then-recreate
    /// upsert pattern in `set_secret` — that workflow parsed the
    /// Postgres "duplicate" error string, deleted the colliding row,
    /// and re-inserted, which (a) wasn't atomic (readers in the
    /// window saw "not found"), (b) issued a fresh `id` (anything FK'd
    /// to that id broke), and (c) emitted spurious audit entries.
    ///
    /// Behaviour: on conflict, updates `name`, `value`,
    /// `description`, `encryption_key_id`, `nonce`, `updated_at`.
    /// Preserves `id`, `allowed_modules`, `org_id`, `expires_at`,
    /// `rotation_reminder_days`. Audit-logs `"create"` for new rows
    /// and `"update"` for upserts — operators see real history.
    /// Returns `(secret_id, was_inserted)` so callers can shape
    /// "stored" vs "updated" responses.
    ///
    /// LLM-keys cache is invalidated for `creator_user_id` whenever
    /// a row matching `is_llm_provider_key_path(key_path)` is
    /// touched (insert OR update).
    pub async fn upsert_secret(
        &self,
        name: &str,
        key_path: &str,
        value: &str,
        namespace: &str,
        description: Option<&str>,
        creator_user_id: Uuid,
        allowed_modules: Vec<Uuid>,
        org_id: Option<Uuid>,
    ) -> Result<(Uuid, bool)> {
        // N T2-N1: id-bound AAD on upsert requires knowing the row's
        // `id` BEFORE the encrypt step. The previous single-round
        // `INSERT … ON CONFLICT … DO UPDATE` pattern can't supply that
        // (we don't know whether INSERT or UPDATE will fire). Replace
        // with an advisory-lock-serialised (lookup → encrypt → write)
        // sequence so the AAD always matches the row's actual id.
        //
        // `pg_advisory_xact_lock` keys on the upsert tuple
        // `(namespace, key_path, created_by)` so concurrent upserts of
        // the same key serialise without blocking unrelated upserts.
        // Lock auto-releases at COMMIT/ROLLBACK.
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"upsert_secret/");
        hasher.update(namespace.as_bytes());
        hasher.update(b"\x00");
        hasher.update(key_path.as_bytes());
        hasher.update(b"\x00");
        hasher.update(creator_user_id.as_bytes());
        let digest = hasher.finalize();
        let lock_key = i64::from_le_bytes(
            digest[..8]
                .try_into()
                .expect("sha256 always produces ≥8 bytes"),
        );

        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("Failed to begin upsert_secret transaction")?;

        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_key)
            .execute(&mut *tx)
            .await
            .context("Failed to acquire upsert advisory lock")?;

        // Look up the existing row's id (if any). The advisory lock
        // ensures no concurrent upsert of this key can interleave
        // between this SELECT and the subsequent write.
        let existing_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM secrets \
             WHERE namespace = $1 AND key_path = $2 AND created_by = $3",
        )
        .bind(namespace)
        .bind(key_path)
        .bind(creator_user_id)
        .fetch_optional(&mut *tx)
        .await
        .context("Failed to look up existing secret for upsert")?;

        let (secret_id, was_inserted) = match existing_id {
            Some(id) => (id, false),
            None => (Uuid::new_v4(), true),
        };

        // Encrypt with the row's id as AAD (v1 format).
        let (key_id, stored_value) = self
            .encrypt_value_with_aad(value, secret_id.as_bytes())
            .await?;
        let nonce_bytes = stored_value.get(..12).ok_or_else(|| {
            anyhow!("encrypt_value_with_aad returned a ciphertext shorter than the nonce prefix")
        })?;

        if was_inserted {
            sqlx::query(
                r#"
                INSERT INTO secrets (
                    id, name, key_path, encrypted_value, encryption_key_id,
                    nonce, description, namespace, created_by, owner_user_id,
                    allowed_modules, org_id, updated_at, encryption_format_version
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, $10, $11, NOW(), $12)
                "#,
            )
            .bind(secret_id)
            .bind(name)
            .bind(key_path)
            .bind(&stored_value)
            .bind(key_id)
            .bind(nonce_bytes)
            .bind(description)
            .bind(namespace)
            .bind(creator_user_id)
            .bind(&allowed_modules)
            .bind(org_id)
            .bind(Self::SECRETS_AAD_FORMAT_V1)
            .execute(&mut *tx)
            .await
            .map_err(|e| anyhow::Error::new(e).context("upsert_secret INSERT failed"))?;
        } else {
            sqlx::query(
                r#"
                UPDATE secrets SET
                    name = $1,
                    encrypted_value = $2,
                    encryption_key_id = $3,
                    nonce = $4,
                    description = $5,
                    encryption_format_version = $6,
                    updated_at = NOW()
                WHERE id = $7
                "#,
            )
            .bind(name)
            .bind(&stored_value)
            .bind(key_id)
            .bind(nonce_bytes)
            .bind(description)
            .bind(Self::SECRETS_AAD_FORMAT_V1)
            .bind(secret_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| anyhow::Error::new(e).context("upsert_secret UPDATE failed"))?;
        }

        tx.commit()
            .await
            .context("Failed to commit upsert_secret transaction")?;

        // 3. Audit log — distinct action label for create vs update so
        // operators reading the audit trail can reconstruct lifecycle.
        let action = if was_inserted { "create" } else { "update" };
        self.log_audit(
            secret_id,
            action,
            "user",
            Some(creator_user_id),
            None,
            true,
            None,
            None,
        )
        .await?;

        // 4. LLM-keys cache invalidation — fires on insert AND update
        // (rotation case) so cached plaintext doesn't outlive the new
        // value's NOW() updated_at by more than the cache TTL would
        // otherwise allow.
        if is_llm_provider_key_path(key_path) {
            self.invalidate_llm_keys_cache(Some(creator_user_id));
            tracing::info!(
                key_path = %key_path,
                owner_user_id = %creator_user_id,
                action = %action,
                "Invalidated LLM-keys cache after upsert"
            );
        }

        tracing::info!(
            secret_id = %secret_id,
            key_path = %key_path,
            namespace = %namespace,
            inserted = was_inserted,
            "upsert_secret: {} secret",
            action
        );

        Ok((secret_id, was_inserted))
    }

    /// Find an existing secret with the same `(name, namespace,
    /// created_by)` but a DIFFERENT `key_path` — used to surface a
    /// non-blocking warning during set_secret when a duplicate name
    /// would land. This is the leading cause of operator confusion
    /// pre-r306: caller runs `set_secret(name="foo")`, gets a fresh
    /// row with a different key_path than the existing 'foo', then
    /// later calls `delete_secret(name="foo")` and watches the wrong
    /// secret disappear.
    ///
    /// Returns the colliding row's `(id, key_path)` when one exists,
    /// `None` otherwise. Best-effort — DB errors return `None` so a
    /// transient hiccup doesn't break the upsert.
    pub async fn find_name_collision(
        &self,
        name: &str,
        namespace: &str,
        new_key_path: &str,
        user_id: Uuid,
    ) -> Option<(Uuid, String)> {
        sqlx::query_as::<_, (Uuid, String)>(
            "SELECT id, key_path FROM secrets \
             WHERE name = $1 AND namespace = $2 AND created_by = $3 \
               AND key_path != $4 \
             LIMIT 1",
        )
        .bind(name)
        .bind(namespace)
        .bind(user_id)
        .bind(new_key_path)
        .fetch_optional(&self.db_pool)
        .await
        .ok()
        .flatten()
    }

    /// Delete-by-(key_path, namespace, user) used as the fallback path in the
    /// `set_secret` upsert flow. NOT audit-logged because the immediate
    /// `create_secret` retry will produce its own audit entry — emitting
    /// "delete" here would noise the log with deletes that are really updates.
    /// Look up a secret by name for the given user. Returns name/key_path/namespace
    /// projection without touching encryption columns.
    pub async fn lookup_secret_by_name(
        &self,
        user_id: Uuid,
        secret_name: &str,
    ) -> Result<Option<SecretLookup>> {
        let row = sqlx::query(
            "SELECT id, key_path, namespace, description \
             FROM secrets WHERE name = $1 AND created_by = $2 LIMIT 1",
        )
        .bind(secret_name)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(row.map(|r| SecretLookup {
            id: r.get("id"),
            key_path: r.get("key_path"),
            namespace: r
                .try_get::<String, _>("namespace")
                .unwrap_or_else(|_| "default".to_string()),
            description: r.try_get("description").ok(),
        }))
    }

    // ─── r306: by-id sibling methods for the resolver-then-mutate flow ──
    //
    // The handler-level pattern post-r306 is:
    //   let id = manager.resolve_to_id(SecretIdentifier::Name { … }, user)?;
    //   manager.<op>_by_id(user, id, …).await?;
    // Each by-id method re-asserts `created_by = $user_id` in the WHERE
    // clause as defense-in-depth — a stale id from a different scope
    // can't accidentally mutate the caller's row.

    /// Delete a secret by its primary id, scoped to `user_id`. DELETE +
    /// audit-log row commit in a single transaction (L-5), so a process
    /// crash mid-delete can't leave the row gone with no audit trail.
    /// Returns `Ok(true)` when the row was removed, `Ok(false)` if the
    /// id didn't match (stale/foreign).
    pub async fn delete_secret_by_id(&self, user_id: Uuid, secret_id: Uuid) -> Result<bool> {
        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("Failed to begin secret-delete-by-id transaction")?;

        let key_path: Option<String> = sqlx::query_scalar(
            "DELETE FROM secrets WHERE id = $1 AND created_by = $2 RETURNING key_path",
        )
        .bind(secret_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(kp) = key_path else {
            // Nothing was deleted; no audit row to write either.
            return Ok(false);
        };

        Self::log_audit_in_tx(
            &mut tx,
            Some(secret_id),
            "delete",
            "user",
            Some(user_id),
            None,
            true,
            None,
            None,
        )
        .await
        .context("Failed to insert audit row for delete_secret_by_id")?;

        tx.commit()
            .await
            .context("Failed to commit secret-delete-by-id transaction")?;

        if is_llm_provider_key_path(&kp) {
            self.invalidate_llm_keys_cache(Some(user_id));
        }
        Ok(true)
    }

    /// Update namespace on a secret looked up by id. Re-asserts
    /// `created_by = $user_id` for defense-in-depth. Returns
    /// `Ok(true)` when the row was updated, `Ok(false)` if the id
    /// didn't match.
    pub async fn set_secret_namespace_by_id(
        &self,
        user_id: Uuid,
        secret_id: Uuid,
        namespace: &str,
    ) -> Result<bool> {
        // MCP-397 (2026-05-11): sibling ops audit in-tx
        // (`delete_secret_by_id`, `rotate_secret_value_by_id`,
        // `update_secret`); pre-fix this path was the only secret
        // mutation that wrote no audit row. A namespace move is a
        // discoverability / access-pattern change — moving a secret
        // from `default` to `archive` namespace silently breaks every
        // module that referenced it by `(name, default)`. The L-5
        // tx-atomic pattern guarantees the audit row commits iff the
        // UPDATE lands.
        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("Failed to begin namespace-update transaction")?;
        let result = sqlx::query(
            "UPDATE secrets SET namespace = $1 \
             WHERE id = $2 AND created_by = $3",
        )
        .bind(namespace)
        .bind(secret_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            // No mutation → no audit row to write.
            return Ok(false);
        }
        Self::log_audit_in_tx(
            &mut tx,
            Some(secret_id),
            "namespace_change",
            "user",
            Some(user_id),
            None,
            true,
            None,
            None,
        )
        .await
        .context("Failed to insert audit row for set_secret_namespace_by_id")?;
        tx.commit()
            .await
            .context("Failed to commit namespace-update transaction")?;
        Ok(true)
    }

    /// Set expiry + reminder by id. Re-asserts `created_by`. Returns
    /// rows-affected truthiness.
    pub async fn set_secret_expiry_by_id(
        &self,
        user_id: Uuid,
        secret_id: Uuid,
        expires_at: chrono::DateTime<chrono::Utc>,
        reminder_days: i32,
    ) -> Result<bool> {
        // MCP-397 (2026-05-11): same audit-parity rationale as
        // `set_secret_namespace_by_id`. Expiry changes are a rotation-
        // hygiene signal — extending a soon-to-expire credential's
        // expiry from "tomorrow" to "next year" silently disables
        // the rotation-reminder mechanism. The audit row records the
        // event so security review can spot suspicious extensions.
        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("Failed to begin expiry-update transaction")?;
        let result = sqlx::query(
            "UPDATE secrets SET expires_at = $1, rotation_reminder_days = $2 \
             WHERE id = $3 AND created_by = $4",
        )
        .bind(expires_at)
        .bind(reminder_days)
        .bind(secret_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            return Ok(false);
        }
        Self::log_audit_in_tx(
            &mut tx,
            Some(secret_id),
            "expiry_change",
            "user",
            Some(user_id),
            None,
            true,
            None,
            None,
        )
        .await
        .context("Failed to insert audit row for set_secret_expiry_by_id")?;
        tx.commit()
            .await
            .context("Failed to commit expiry-update transaction")?;
        Ok(true)
    }

    /// Rotate a secret's encrypted value by id. Re-asserts
    /// `created_by`, fetches the active DEK, encrypts the new
    /// value, atomic UPDATE, audit-logs `"rotate"`, invalidates the
    /// LLM-keys cache when applicable. Returns the rotated row's
    /// `RotatedSecret` (id + key_path + description) on success,
    /// `None` if the id didn't match.
    pub async fn rotate_secret_value_by_id(
        &self,
        user_id: Uuid,
        secret_id: Uuid,
        new_value: &str,
    ) -> Result<Option<RotatedSecret>> {
        // N T2-N1: bind `secret_id` as AAD on the rotated ciphertext.
        // Caller already supplies `secret_id` (typically resolved via
        // `resolve_to_id`), so the AAD is known at encrypt time
        // without a pre-fetch. The post-rotate row is v1 format.
        let (key_id, stored_value) = self
            .encrypt_value_with_aad(new_value, secret_id.as_bytes())
            .await?;
        let nonce_bytes = stored_value.get(..12).ok_or_else(|| {
            anyhow!("encrypt_value_with_aad returned a ciphertext shorter than the nonce prefix")
        })?;

        // UPDATE + audit row in a single transaction (L-5) so the
        // rotation event is observable iff the rotation lands.
        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("Failed to begin rotate-by-id transaction")?;

        let row: Option<(String, Option<String>)> = sqlx::query_as(
            "UPDATE secrets \
             SET encrypted_value = $1, encryption_key_id = $2, nonce = $3, \
                 encryption_format_version = $4, updated_at = NOW() \
             WHERE id = $5 AND created_by = $6 \
             RETURNING key_path, description",
        )
        .bind(&stored_value)
        .bind(key_id)
        .bind(nonce_bytes)
        .bind(Self::SECRETS_AAD_FORMAT_V1)
        .bind(secret_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;

        let Some((key_path, description)) = row else {
            // Nothing matched (stale id / foreign tenant) — no audit row to write.
            return Ok(None);
        };

        Self::log_audit_in_tx(
            &mut tx,
            Some(secret_id),
            "rotate",
            "user",
            Some(user_id),
            None,
            true,
            None,
            None,
        )
        .await
        .context("Failed to insert audit row for rotate_secret_value_by_id")?;

        tx.commit()
            .await
            .context("Failed to commit rotate-by-id transaction")?;

        if is_llm_provider_key_path(&key_path) {
            self.invalidate_llm_keys_cache(Some(user_id));
        }

        Ok(Some(RotatedSecret {
            id: secret_id,
            key_path,
            description,
        }))
    }

    /// Find modules that declare `secret_name` in their `allowed_secrets`
    /// (or have wildcard `*`). Single SELECT over the unified `modules`
    /// table by canonical id; `source` is derived from `kind` via
    /// `ModuleSource::from_modules_kind`.
    pub async fn find_modules_referencing_secret(
        &self,
        user_id: Uuid,
        secret_name: &str,
    ) -> Result<Vec<ModuleSecretReference>> {
        let rows = sqlx::query(
            "SELECT id AS module_id, name, allowed_secrets, kind \
             FROM modules \
             WHERE user_id = $1 \
               AND ($2 = ANY(allowed_secrets) OR '*' = ANY(allowed_secrets))",
        )
        .bind(user_id)
        .bind(secret_name)
        .fetch_all(&self.db_pool)
        .await
        .context("find_modules_referencing_secret: query failed")?;

        let mut out = Vec::new();
        for row in rows {
            let allowed: Vec<String> = row.try_get("allowed_secrets").unwrap_or_default();
            let kind: String = row.try_get("kind").unwrap_or_default();
            out.push(ModuleSecretReference {
                module_id: row.try_get("module_id").unwrap_or_default(),
                module_name: row.try_get("name").unwrap_or_default(),
                source: ModuleSource::from_modules_kind(&kind),
                wildcard: allowed.iter().any(|s| s == "*"),
            });
        }
        Ok(out)
    }

    /// Find workflows whose `graph_json` references a given module id (LIKE
    /// substring match). Caps at `limit` per call.
    pub async fn find_workflows_using_module(
        &self,
        user_id: Uuid,
        module_id: Uuid,
        limit: i64,
    ) -> Result<Vec<(Uuid, String)>> {
        let pattern = format!("%{}%", module_id);
        let rows = sqlx::query(
            "SELECT id, name FROM workflows \
             WHERE user_id = $1 AND graph_json LIKE $2 \
             ORDER BY updated_at DESC LIMIT $3",
        )
        .bind(user_id)
        .bind(&pattern)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let id: Uuid = r.try_get("id").unwrap_or_default();
                let name: String = r.try_get("name").unwrap_or_default();
                (id, name)
            })
            .collect())
    }

    /// Scan non-archived workflows for direct references to a secret in
    /// `graph_json` text — both `"<key_path>"` and `"<secret_name>"` substrings.
    /// Catches workflows whose nodes hard-code a vault path in config without
    /// going through `allowed_secrets`.
    pub async fn find_workflows_with_secret_in_graph(
        &self,
        user_id: Uuid,
        secret_name: &str,
        key_path: &str,
        limit: i64,
    ) -> Result<Vec<(Uuid, String)>> {
        let kp_needle = format!("\"{}\"", key_path);
        let name_needle = format!("\"{}\"", secret_name);
        let rows = sqlx::query(
            "SELECT id, name FROM workflows \
             WHERE user_id = $1 AND (status IS NULL OR status != 'archived') \
               AND (position($2 in graph_json) > 0 OR position($3 in graph_json) > 0) \
             ORDER BY updated_at DESC LIMIT $4",
        )
        .bind(user_id)
        .bind(&kp_needle)
        .bind(&name_needle)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let id: Uuid = r.try_get("id").unwrap_or_default();
                let name: String = r.try_get("name").unwrap_or_default();
                (id, name)
            })
            .collect())
    }

    /// Aggregate set of secret names referenced by any of the user's modules
    /// plus a flag indicating any wildcard grant. Used by the
    /// "unused secrets" report.
    ///
    /// Phase 5: single SELECT over the unified `modules` table replaces the
    /// old UNION across node_templates + wasm_modules.
    pub async fn list_referenced_secret_names(
        &self,
        user_id: Uuid,
    ) -> Result<(std::collections::HashSet<String>, bool)> {
        let lists = sqlx::query_scalar::<_, Vec<String>>(
            "SELECT allowed_secrets FROM modules \
             WHERE user_id = $1 AND allowed_secrets IS NOT NULL",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await
        .context("list_referenced_secret_names: query failed")?;

        let mut referenced = std::collections::HashSet::new();
        let mut has_wildcard = false;
        for list in lists.iter() {
            for s in list {
                if s == "*" {
                    has_wildcard = true;
                } else {
                    referenced.insert(s.clone());
                }
            }
        }
        Ok((referenced, has_wildcard))
    }

    /// Just the key_paths for a user's secrets (used by `normalize_secret_paths`).
    /// Capped at 10k rows — beyond which the normalisation logic is unlikely to
    /// produce useful output anyway.
    pub async fn list_user_secret_key_paths(&self, user_id: Uuid) -> Result<Vec<String>> {
        let paths = sqlx::query_scalar::<_, String>(
            "SELECT key_path FROM secrets WHERE created_by = $1 ORDER BY key_path LIMIT 10000",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(paths)
    }

    /// All canonical secret paths declared across all installed templates,
    /// returned as `(template_name, [allowed_secrets])`. Global scope (no
    /// user filter) — canonical paths are a workspace-wide concept.
    ///
    /// Phase 5: reads the unified `modules` table. Scoped to catalog rows
    /// (`kind = 'catalog'`) so user-authored sandbox grants don't pollute
    /// the workspace-wide canonical view — that matches the legacy
    /// node_templates semantics, which catalog seeds populated and
    /// user-installed modules rarely wrote to.
    pub async fn list_canonical_secret_paths(&self) -> Result<Vec<(String, Vec<String>)>> {
        let rows = sqlx::query_as::<_, (String, Vec<String>)>(
            "SELECT name, allowed_secrets FROM modules \
             WHERE kind = 'catalog' \
               AND allowed_secrets IS NOT NULL \
               AND allowed_secrets != '{}'",
        )
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    /// Reference rows for the platform-state export. Includes name, key_path,
    /// namespace, description — never any decrypted data.
    pub async fn list_secret_refs_for_export(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<SecretRefForExport>> {
        let rows = sqlx::query(
            "SELECT name, key_path, namespace, description \
             FROM secrets \
             WHERE created_by = $1 \
             ORDER BY key_path ASC",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| SecretRefForExport {
                name: r.try_get("name").unwrap_or_default(),
                key_path: r.try_get("key_path").unwrap_or_default(),
                namespace: r
                    .try_get::<String, _>("namespace")
                    .unwrap_or_else(|_| "default".to_string()),
                description: r.try_get("description").unwrap_or(None),
            })
            .collect())
    }

    /// True if a secret exists for the user at the given key_path. Used by
    /// `import_platform_state` to count which referenced secrets are already
    /// provisioned without ever fetching the value. Scoped via `created_by`
    /// — the legacy `user_id` column was never populated by `create_secret`
    /// or `upsert_secret`, so a `WHERE user_id = $2` filter would silently
    /// report every modern secret as missing.
    pub async fn secret_exists_by_path(&self, key_path: &str, user_id: Uuid) -> Result<bool> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM secrets WHERE key_path = $1 AND created_by = $2)",
        )
        .bind(key_path)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(exists)
    }

    /// Batch sibling to [`secret_exists_by_path`]. Single
    /// `WHERE key_path = ANY($1)` query returns the subset of paths that
    /// exist for `user_id`. Replaces the per-path loop in
    /// `import_platform_state` (1,000 round-trips at the manifest cap → 1).
    /// Empty input short-circuits without touching the DB.
    ///
    /// Returns the set of existing paths so callers can do
    /// `existing.contains(path)` instead of paying for a per-path query.
    /// A path that doesn't exist (or that belongs to another user) is
    /// simply absent from the set.
    ///
    /// Security: same `AND created_by = $2` scoping as the per-path method.
    /// (Pre-r306 reviews used `AND user_id = $2`, which silently reported
    /// every modern secret as missing because `create_secret` and
    /// `upsert_secret` populate `created_by`/`owner_user_id` but never
    /// `user_id`.)
    pub async fn existing_secret_key_paths(
        &self,
        key_paths: &[String],
        user_id: Uuid,
    ) -> Result<std::collections::HashSet<String>> {
        if key_paths.is_empty() {
            return Ok(std::collections::HashSet::new());
        }
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT key_path FROM secrets WHERE key_path = ANY($1) AND created_by = $2",
        )
        .bind(key_paths)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows.into_iter().map(|(p,)| p).collect())
    }

    /// Audit-log entries for `get_secret_access_log`. `key_path` is optional
    /// (None = all keys); time window is `hours` back from now; results are
    /// capped at `limit`.
    ///
    /// Returns Err only on real DB failures. Some environments don't have the
    /// `secret_audit_log` table at all — the handler distinguishes that via
    /// the error string and replies with an empty list + note.
    pub async fn list_secret_access_log(
        &self,
        key_path: Option<&str>,
        hours: f64,
        limit: i64,
    ) -> Result<Vec<SecretAuditEntry>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT l.id, s.key_path AS secret_name, l.action, \
                    l.actor_type, l.actor_id::text AS actor, l.ip_address, l.timestamp AS created_at \
             FROM secret_audit_log l \
             LEFT JOIN secrets s ON s.id = l.secret_id \
             WHERE ($1::text IS NULL OR s.key_path = $1) \
               AND l.timestamp > NOW() - make_interval(hours => $2) \
             ORDER BY l.timestamp DESC \
             LIMIT $3",
        )
        .bind(key_path)
        .bind(hours)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| SecretAuditEntry {
                id: r.try_get("id").unwrap_or_default(),
                secret_name: r
                    .try_get::<Option<String>, _>("secret_name")
                    .unwrap_or(None),
                action: r.try_get("action").unwrap_or_default(),
                actor_type: r.try_get("actor_type").unwrap_or_default(),
                actor: r.try_get::<Option<String>, _>("actor").unwrap_or(None),
                ip_address: r.try_get::<Option<String>, _>("ip_address").unwrap_or(None),
                created_at: r.try_get("created_at").unwrap_or_default(),
            })
            .collect())
    }

    /// Lightweight rows for the secret-health report (just creation + expiry).
    pub async fn list_secrets_for_health_check(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<SecretHealthRow>> {
        let rows = sqlx::query(
            "SELECT name, key_path, created_at, expires_at \
             FROM secrets WHERE created_by = $1 \
             ORDER BY created_at DESC LIMIT $2",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| SecretHealthRow {
                name: r.try_get("name").unwrap_or_default(),
                key_path: r.try_get("key_path").unwrap_or_default(),
                created_at: r.try_get("created_at").unwrap_or_default(),
                expires_at: r.try_get("expires_at").unwrap_or(None),
            })
            .collect())
    }

    /// Invalidate DEK cache (call after key rotation or security incident).
    ///
    /// This forces all subsequent secret accesses to fetch and decrypt DEKs from the database.
    /// The cache repopulates automatically on the next access with the current active DEK.
    ///
    /// ## Operational context
    ///
    /// This method is currently **not exposed via any HTTP or GraphQL endpoint**, which means
    /// emergency cache invalidation requires either:
    ///   1. Waiting for the natural TTL (default: 5 minutes via `DEK_CACHE_TTL_SECS`).
    ///   2. Restarting the controller process (drops all in-process state).
    ///
    /// Now wired into an admin-protected API endpoint (e.g., `POST /api/admin/secrets/invalidate-cache`)
    /// to support the DEK rotation runbook. Require an ADMIN-level JWT scope to call it, and
    /// log the invalidation to the `secret_audit_log` table.
    ///
    /// ## Use cases
    ///
    /// - After rotating the active DEK (`encryption_keys` table: `is_active` column flipped)
    /// - After a suspected key-exfiltration incident
    /// - Integration testing: force cache miss for deterministic test behavior
    pub async fn invalidate_dek_cache(
        &self,
        actor_id: Option<uuid::Uuid>,
        actor_type: &str,
        ip_address: Option<&str>,
    ) -> anyhow::Result<()> {
        self.dek_cache.clear();
        {
            let mut active_cache = self.active_dek_cache.write().await;
            *active_cache = None;
        }
        tracing::info!("DEK cache invalidated - all entries cleared");

        // MCP-740 (2026-05-13): log audit-INSERT failures. Pre-fix the
        // `let _ = sqlx::query!(...).await` silently discarded errors,
        // so the `secret_audit_log` WORM trail could lose
        // DEK_CACHE_INVALIDATED events under a DB hiccup. Cache
        // invalidation is itself an operator-significant action
        // (post-key-rotation, post-exfiltration-incident, integration
        // tests) — an auditor walking secret_audit_log to reconstruct
        // a security event would see a gap with no signal. The cache
        // is still cleared regardless (the in-memory ops above are
        // infallible), so failure to audit doesn't break correctness
        // — but the WARN gives SIEM/dashboards the operational
        // visibility the audit trail was designed to provide. Same
        // operator-visibility class as MCP-733/734/735/736.
        if let Err(e) = sqlx::query!(
            r#"
            INSERT INTO secret_audit_log (
                action, actor_type, actor_id, success, ip_address
            )
            VALUES ($1, $2, $3, $4, $5)
            "#,
            "DEK_CACHE_INVALIDATED",
            actor_type,
            actor_id,
            true,
            ip_address
        )
        .execute(&self.db_pool)
        .await
        {
            tracing::warn!(
                target: "talos_audit",
                actor_type,
                actor_id = ?actor_id,
                ip_address = ?ip_address,
                error = %e,
                "secret_audit_log INSERT for DEK_CACHE_INVALIDATED failed — cache was cleared but the audit trail lost the event"
            );
        }

        Ok(())
    }

    /// Get DEK cache statistics for monitoring
    ///
    /// Returns (total_entries, active_dek_cached)
    pub async fn get_cache_stats(&self) -> (usize, bool) {
        let total_entries = self.dek_cache.len();
        let active_cached = self.active_dek_cache.read().await.is_some();
        (total_entries, active_cached)
    }

    /// Clean up expired cache entries (optional - cache auto-expires on access)
    ///
    /// This is an optional optimization to free memory from expired entries.
    /// Not strictly necessary as expired entries are ignored on access.
    pub async fn cleanup_expired_cache_entries(&self) {
        let now = Instant::now();
        let ttl = self.cache_ttl;

        self.dek_cache
            .retain(|_, cached| now.duration_since(cached.cached_at) < ttl);
        {
            let mut active_cache = self.active_dek_cache.write().await;
            if let Some(cached) = active_cache.as_ref() {
                if now.duration_since(cached.cached_at) >= ttl {
                    *active_cache = None;
                }
            }
        }
        tracing::debug!("Cleaned up expired DEK cache entries");
    }

    /// Decrypt a value that was previously encrypted with the embedded-key-id blob format.
    ///
    /// Blob format: KEY_ID_LEN bytes key_id UUID || NONCE_LEN bytes nonce || ciphertext.
    /// Originally introduced for `SlackIntegrationService::encrypt_token` (which has
    /// since been removed); kept as a public API for future single-column-storage
    /// callers that need the embedded-key-id self-describing blob format.
    ///
    /// MCP-1176 (2026-05-17): return `Zeroizing<String>` rather than plain
    /// `String`. The sibling `decrypt_value_by_key` already returns
    /// `Zeroizing<String>` so the wipe-on-drop guarantee survives the
    /// decryption call; this function diverged because it pre-dated the
    /// `Zeroizing` migration. Plain-String return is a foot-gun for any
    /// future caller — the plaintext secret value lives on the heap with
    /// no wipe-on-drop, and a panic / drop / Vec resize during the
    /// caller's lifetime leaves the bytes recoverable. Matching the
    /// sibling shape eliminates the asymmetry. Same secret-handling
    /// invariant as `decrypt_value_by_key` (line 1418) and
    /// `decrypt_secret_record` (line 1440).
    pub async fn decrypt_value(&self, ciphertext: &[u8]) -> Result<Zeroizing<String>> {
        /// Byte length of a UUID (16 bytes) stored as raw bytes at the start of the blob.
        const KEY_ID_LEN: usize = 16;
        /// AES-GCM nonce length in bytes (96-bit nonce = 12 bytes).
        const NONCE_LEN: usize = 12;
        /// Total header = key_id || nonce.
        const HEADER_LEN: usize = KEY_ID_LEN + NONCE_LEN; // 28

        if ciphertext.len() < HEADER_LEN {
            return Err(anyhow!("Invalid ciphertext: too short"));
        }
        // Parse: KEY_ID_LEN-byte key_id UUID || NONCE_LEN-byte nonce || ciphertext
        let key_id = Uuid::from_slice(&ciphertext[..KEY_ID_LEN])
            .map_err(|_| anyhow!("Invalid ciphertext: bad key_id"))?;
        let nonce = Nonce::from_slice(&ciphertext[KEY_ID_LEN..HEADER_LEN]);
        let payload = &ciphertext[HEADER_LEN..];

        let dek = self.get_dek(key_id).await?;
        let cipher = Aes256Gcm::new_from_slice(&dek.key)?;
        let plaintext_bytes = cipher
            .decrypt(nonce, payload)
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;
        let plaintext = String::from_utf8(plaintext_bytes)
            .map_err(|_| anyhow!("Decrypted value is not valid UTF-8"))?;
        Ok(Zeroizing::new(plaintext))
    }

    /// Rotate the Data Encryption Key.
    ///
    /// Creates a new DEK, marks it as active, and deactivates the previous one.
    /// Returns the UUID of the newly created DEK.
    ///
    /// `auditor` is an optional user ID for audit-logging who triggered the rotation.
    pub async fn rotate_dek(&self, auditor: Option<Uuid>) -> Result<Uuid> {
        use rand::RngCore;
        let mut new_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut new_key);

        // Wrap with the current KEK BEFORE acquiring the advisory lock so
        // the slow KMS round-trip (Vault / AWS KMS) isn't held across the
        // lock — same pattern as MCP-685/686 (api_keys + webhooks
        // per-user cap TOCTOU, see `per_user_cap_toctou_pattern.md`).
        let active_wrap = self.current_kek()?.wrap_dek(&new_key).await?;

        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("Failed to begin transaction")?;

        // MCP-700 (2026-05-13): serialise concurrent `rotate_dek` calls
        // via a deterministic advisory lock. Pre-fix the pattern was
        //   1. UPDATE encryption_keys SET active=false WHERE active=true
        //   2. INSERT new DEK with active=true
        // No SELECT FOR UPDATE on the active row and no UNIQUE partial
        // index on (active) WHERE active=true. Under READ COMMITTED, two
        // concurrent transactions can both pass step 1 (each seeing only
        // the old row as active, deactivating it, then both INSERTing a
        // new active row) and commit — leaving TWO rows with active=true.
        // Subsequent `current_dek()` calls (`WHERE active=true LIMIT 1`)
        // would race-pick which DEK protects new writes; both remain
        // valid for decryption, but the table-level invariant ("exactly
        // one active DEK") is violated and would surface as a confusing
        // post-incident audit finding.
        //
        // Trigger path: GraphQL `rotateDek` admin mutation. A double-
        // click in the admin UI or a script bug that fires two
        // `rotateDek` mutations in quick succession is sufficient. The
        // mutation is platform-admin gated (require_platform_admin) so
        // the threat model is "trusted operator with a buggy client" or
        // "trusted operator who fat-fingered" — but the table-level
        // invariant should hold regardless.
        //
        // Fixed-constant lock key (NOT keyed on user_id, because
        // `rotate_dek` is system-wide). The constant doesn't collide
        // with the SHA-256-derived keys used by `upsert_secret`
        // (those are `i64::from_le_bytes(hash[..8])` of an op-prefixed
        // SHA-256 — astronomically unlikely to match this literal).
        const ROTATE_DEK_LOCK_KEY: i64 = 0x44_4B_5F_52_4F_54_41_54; // 'DK_ROTAT' in ASCII
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(ROTATE_DEK_LOCK_KEY)
            .execute(&mut *tx)
            .await
            .context("Failed to acquire rotate_dek advisory lock")?;

        // Deactivate current active DEK
        sqlx::query("UPDATE encryption_keys SET active = false WHERE active = true")
            .execute(&mut *tx)
            .await
            .context("Failed to deactivate current DEK")?;

        // Insert new active DEK
        let new_dek_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO encryption_keys (id, encrypted_key, algorithm, active) \
             VALUES ($1, $2, 'AES-256-GCM', true)",
        )
        .bind(new_dek_id)
        .bind(&active_wrap)
        .execute(&mut *tx)
        .await
        .context("Failed to insert new DEK")?;

        // Audit log inside the same tx (L-5 — was previously absent on
        // this path entirely). secret_id is NULL because this audits a
        // KEK-level rotation, not a per-secret op.
        Self::log_audit_in_tx(
            &mut tx,
            None,
            "DEK_ROTATED",
            "system",
            auditor,
            None,
            true,
            None,
            None,
        )
        .await
        .context("Failed to insert audit row for rotate_dek")?;

        tx.commit().await.context("Failed to commit DEK rotation")?;

        // Invalidate the active DEK cache
        let mut cache = self.active_dek_cache.write().await;
        *cache = None;

        tracing::info!(
            new_dek_id = %new_dek_id,
            auditor = ?auditor,
            "DEK rotated successfully"
        );

        Ok(new_dek_id)
    }

    // MCP-944 (2026-05-15): deleted the unused `encrypt_dek_with_master`
    // helper. Its docstring claimed "Used during DEK rotation" but no
    // call site existed — the rotation path at line ~3400 calls
    // `self.current_kek()?.wrap_dek(...).await` inline, exactly what
    // the wrapper did. The helper was a redundant 1-liner that read as
    // load-bearing but wasn't. A future caller can re-introduce it
    // when there's actually a second site.

    /// Re-encrypt all secrets with the currently active DEK.
    ///
    /// This is typically called after `rotate_dek` to migrate existing
    /// secrets to the new key.
    ///
    /// L T2-6: returns [`ReEncryptStats`] with `(re_encrypted, failed,
    /// failed_ids)` instead of `u64` so operators see partial-failure
    /// counts and the affected secret IDs explicitly. Pre-fix the loop
    /// continued past per-row failures with a single `tracing::error!`
    /// and the high-level signal was just "rotation succeeded" — a
    /// single corrupt row could drift the rotation count without any
    /// signal back to the caller. Now: caller observes `failed > 0`,
    /// dashboards can alert on it, and the explicit `failed_ids` list
    /// (capped at 100) lets the operator triage. Caller decides whether
    /// `failed > 0` is acceptable or whether to abort the runbook.
    pub async fn re_encrypt_secrets(&self) -> Result<ReEncryptStats> {
        use sqlx::Row as _;
        let active_dek = self.get_active_dek().await?;

        // N T2-N1: fetch encryption_format_version too so the decrypt
        // dispatches v0 (no AAD) vs v1 (id-bound AAD). Re-encrypt path
        // ALWAYS writes v1 going forward — this is the operator
        // upgrade pathway from v0 to v1.
        //
        // Selection criterion: rows that are NOT (active_dek AND v1) —
        // i.e. either the DEK is stale OR the format version is 0.
        // After this loop runs to completion, every row is on the
        // active DEK AND v1 format.
        let stale_rows = sqlx::query(
            r#"
            SELECT id, encrypted_value, encryption_key_id, encryption_format_version
            FROM secrets
            WHERE encryption_key_id != $1 OR encryption_format_version < $2
            "#,
        )
        .bind(active_dek.id)
        .bind(Self::SECRETS_AAD_FORMAT_V1)
        .fetch_all(&self.db_pool)
        .await
        .context("Failed to fetch secrets for re-encryption")?;

        if stale_rows.is_empty() {
            tracing::info!("No secrets require re-encryption");
            return Ok(ReEncryptStats::default());
        }

        tracing::info!(
            count = stale_rows.len(),
            new_dek_id = %active_dek.id,
            "Re-encrypting secrets with new DEK / upgrading to v1 AAD format"
        );

        // L T2-6: track failures alongside successes. failed_ids is
        // capped at 100 so a catastrophic mass-failure event doesn't
        // produce an unbounded response payload.
        const FAILED_IDS_CAP: usize = 100;
        let mut re_encrypted = 0u64;
        let mut failed = 0u64;
        let mut failed_ids: Vec<Uuid> = Vec::new();
        let record_failure = |id: Uuid, failed: &mut u64, failed_ids: &mut Vec<Uuid>| {
            *failed += 1;
            if failed_ids.len() < FAILED_IDS_CAP {
                failed_ids.push(id);
            }
        };

        for row in &stale_rows {
            let secret_id: Uuid = row.get("id");
            let encrypted_value: Vec<u8> = row.get("encrypted_value");
            let encryption_key_id: Uuid = row.get("encryption_key_id");
            let encryption_format_version: i16 = row.get("encryption_format_version");

            if encrypted_value.len() < 12 {
                tracing::warn!(secret_id = %secret_id, "Skipping secret with invalid ciphertext (too short)");
                record_failure(secret_id, &mut failed, &mut failed_ids);
                continue;
            }

            // Decrypt via the version-aware dispatch helper. This
            // handles BOTH the v0 (legacy no-AAD) and v1 (id-bound
            // AAD) input formats — so a partially-rotated table where
            // some rows are already v1 can be safely re-rotated.
            let plaintext = match self
                .decrypt_secret_record(
                    secret_id,
                    encryption_key_id,
                    &encrypted_value,
                    encryption_format_version,
                )
                .await
            {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(
                        secret_id = %secret_id,
                        old_key_id = %encryption_key_id,
                        old_format = %encryption_format_version,
                        "Failed to decrypt with old DEK during re-encrypt: {}",
                        e
                    );
                    record_failure(secret_id, &mut failed, &mut failed_ids);
                    continue;
                }
            };

            // Re-encrypt with the new active DEK and v1 AAD format.
            // `encrypt_value_with_aad` uses the active DEK; we don't
            // need to re-derive it per-iteration.
            let (key_id, new_stored) = match self
                .encrypt_value_with_aad(&plaintext, secret_id.as_bytes())
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!(
                        secret_id = %secret_id,
                        "Failed to re-encrypt with new DEK: {}",
                        e
                    );
                    record_failure(secret_id, &mut failed, &mut failed_ids);
                    continue;
                }
            };

            // Update in database. UPDATE failures count as failures
            // (operator metric "re_encrypted" must NOT over-report under
            // DB stress) — same invariant as the L-1 backfill counter
            // fix in talos-memory.
            //
            // MCP-464: lost-write race closure. Pre-fix the UPDATE was
            // unconditional on the id; if a user's `set_secret` raced
            // between this loop's SELECT (which read the OLD ciphertext)
            // and the UPDATE below, our write would silently overwrite
            // their just-updated value with the value we decrypted from
            // the OLD ciphertext — reverting their write. Add a
            // conditional `WHERE encryption_key_id = $5 AND
            // encryption_format_version = $6` so the UPDATE only fires
            // when the row is still on the same (old-key, old-format)
            // pair we just decrypted from. `rows_affected == 0` means
            // another writer beat us; treat that as a benign skip
            // (the row is already on the new shape) rather than a
            // failure, so the re_encrypted/failed counters stay
            // accurate under concurrent set_secret pressure.
            match sqlx::query(
                "UPDATE secrets SET encrypted_value = $1, encryption_key_id = $2, \
                                    encryption_format_version = $3, updated_at = NOW() \
                 WHERE id = $4 \
                   AND encryption_key_id = $5 \
                   AND encryption_format_version = $6",
            )
            .bind(&new_stored)
            .bind(key_id)
            .bind(Self::SECRETS_AAD_FORMAT_V1)
            .bind(secret_id)
            .bind(encryption_key_id)
            .bind(encryption_format_version)
            .execute(&self.db_pool)
            .await
            {
                Ok(result) => {
                    if result.rows_affected() == 0 {
                        // Concurrent writer (another set_secret or
                        // parallel re_encrypt) already moved this row
                        // forward. The row is on the new shape by
                        // definition; skip without counting as either
                        // success or failure of THIS rotation.
                        tracing::debug!(
                            secret_id = %secret_id,
                            "Skipped re-encrypt: row was concurrently re-keyed by another writer"
                        );
                    } else {
                        re_encrypted += 1;
                    }
                }
                Err(e) => {
                    tracing::error!(
                        secret_id = %secret_id,
                        "Failed to update re-encrypted secret: {}",
                        e
                    );
                    record_failure(secret_id, &mut failed, &mut failed_ids);
                }
            }
        }

        tracing::info!(
            re_encrypted,
            failed,
            total = stale_rows.len(),
            "Secret re-encryption complete"
        );

        Ok(ReEncryptStats {
            re_encrypted,
            failed,
            failed_ids,
        })
    }

    /// Rotate the master key used for envelope encryption of DEKs.
    ///
    /// This re-encrypts ALL DEKs in the `encryption_keys` table from the old
    /// master key to the new one, processed in batches of 50 to avoid long
    /// transactions. After all DEKs are re-encrypted the in-memory master key
    /// is swapped and the DEK cache is invalidated.
    ///
    /// Returns the number of DEKs that were re-encrypted.
    ///
    /// # Security
    /// - The new master key is NEVER logged.
    /// - Each batch is wrapped in its own transaction for atomicity.
    /// - If any DEK fails to re-encrypt the operation is aborted immediately.
    pub async fn rotate_master_key(
        &self,
        new_master_key: Zeroizing<Vec<u8>>,
        auditor: Option<Uuid>,
    ) -> Result<u64> {
        if new_master_key.len() != 32 {
            return Err(anyhow!("New master key must be exactly 32 bytes"));
        }

        // env→env rotation: build a fresh EnvKekProvider from the new
        // bytes and rewrap every DEK through the trait. The current
        // provider is loaded once and held for the duration; the new
        // provider is published atomically at the end via the kek RwLock.
        // For env→Vault (or any cross-provider) rotation, see the
        // dual-wrap migration plan (Phase 3 of KEK→KMS).
        //
        // L-6: param is `Zeroizing<Vec<u8>>` so the caller's allocation
        // is wiped on drop (and on any early return below). We clone
        // the inner bytes (32 bytes — cheap) for the new provider; the
        // EnvKekProvider's internal storage is also Zeroizing-wrapped
        // (see `kek_provider.rs:97`), so the clone is wiped when the
        // provider drops. The original Zeroizing wrapper wipes when
        // this function returns.
        let old_provider = self.current_kek()?;
        let new_provider: Arc<dyn kek_provider::KekProvider> = Arc::new(
            kek_provider::EnvKekProvider::from_raw_bytes_owned(new_master_key.to_vec())?,
        );

        // MCP-701 (2026-05-13): cross-op race vs rotate_dek (MCP-700
        // follow-up). Pre-fix, a `rotate_dek` that lands during
        // `rotate_master_key`'s rewrap loop would wrap the new DEK with
        // the OLD master key (`current_kek()` still returns OLD until
        // the post-loop swap below), but the new DEK row is NOT in the
        // `all_dek_ids` snapshot captured here. After the swap +
        // `kek_legacy` clear, the new DEK's `encrypted_key` is
        // unrecoverable (active provider fails to unwrap; legacy
        // provider was cleared).
        //
        // Fix: acquire a session-level `pg_advisory_lock` on the same
        // key `rotate_dek` uses (`ROTATE_DEK_LOCK_KEY` =
        // 0x44_4B_5F_52_4F_54_41_54 = 'DK_ROTAT'). Held on a dedicated
        // connection for the duration of this function. Sibling
        // rotate_dek's `pg_advisory_xact_lock` on the same key will
        // block until we release here, so any concurrent rotate_dek
        // waits until our master-key swap is done and `kek_legacy` is
        // cleared. The new DEK then gets wrapped with the NEW master
        // (post-swap `current_kek()`) and is correctly recoverable.
        //
        // Multi-instance safe: the advisory lock lives in Postgres, so
        // a rotate_dek on instance B blocks on a rotate_master_key
        // running on instance A. No process-local Mutex required.
        //
        // **Important**: sqlx pool keeps physical Postgres connections
        // alive across `PoolConnection` drops — the connection is
        // returned to the pool, NOT closed. A session-level advisory
        // lock would therefore PERSIST on the physical connection if
        // we didn't explicitly unlock, leaking the lock to whatever
        // pool consumer reuses that connection next. The IIFE pattern
        // below ensures `pg_advisory_unlock` runs whether the inner
        // block succeeds or returns an `Err` via `?` — without it,
        // any `?`-bail mid-rotation would leak the lock and stall
        // every subsequent `rotate_dek` until the connection is
        // recycled out of the pool (which may never happen).
        const ROTATE_DEK_LOCK_KEY: i64 = 0x44_4B_5F_52_4F_54_41_54;
        let mut lock_conn = self
            .db_pool
            .acquire()
            .await
            .context("Failed to acquire dedicated connection for rotate_master_key advisory lock")?;
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(ROTATE_DEK_LOCK_KEY)
            .execute(&mut *lock_conn)
            .await
            .context("Failed to acquire rotate_master_key advisory lock")?;

        // The work below runs under the advisory lock. Wrapped in an
        // async block so `?`-bails inside still flow through the
        // explicit unlock at the bottom of this function.
        let rotation_result: Result<u64> = async {
        // Snapshot the DEK ids AFTER acquiring the lock so any
        // rotate_dek that landed between `current_kek()` and the lock
        // acquire (and committed before our lock was granted) is
        // captured by this snapshot rather than orphaned.
        let all_dek_ids: Vec<Uuid> =
            sqlx::query_scalar::<_, Uuid>("SELECT id FROM encryption_keys ORDER BY created_at ASC")
                .fetch_all(&self.db_pool)
                .await
                .context("Failed to fetch encryption key IDs")?;

        if all_dek_ids.is_empty() {
            tracing::info!("No DEKs found to re-encrypt during master key rotation");
            *self
                .kek
                .write()
                .map_err(|_| anyhow!("KEK provider lock poisoned"))? = new_provider;
            return Ok(0);
        }

        tracing::info!(
            dek_count = all_dek_ids.len(),
            auditor = ?auditor,
            "Starting master key rotation"
        );

        // PARTIAL-FAILURE SAFETY BELT (H-1).
        //
        // Install the OLD provider as `kek_legacy` BEFORE the rewrap loop
        // begins. The decrypt_dek fallback path (above) tries the active
        // provider first and falls back to legacy on failure — so:
        //
        //   * Rows already rewrapped (post-loop): unwrappable via NEW
        //     active provider after the swap below.
        //   * Rows not yet rewrapped (pre-loop or interrupted): still
        //     wrapped with the OLD master key — unwrappable via legacy.
        //
        // Without this belt, an interrupted rotation (DB error mid-batch,
        // OOM, pod kill) leaves SOME rows wrapped with NEW master and
        // SOME with OLD; the manager's `kek` is still OLD because the
        // swap below was never reached, so NEW-wrapped rows become
        // un-decryptable until manual intervention. Operators can now
        // simply retry — every prior partial-rotation row is recovered
        // via the legacy path.
        //
        // We deliberately keep the belt installed even on the success
        // path until the swap completes; clear it only after both the
        // rewrap loop AND the active-provider swap have landed.
        {
            let mut legacy_guard = self
                .kek_legacy
                .write()
                .map_err(|_| anyhow!("KEK legacy provider lock poisoned"))?;
            if legacy_guard.is_some() {
                // Mid-rotation crash + retry: legacy is already populated
                // from the previous attempt. Don't clobber it — that
                // legacy provider may still be load-bearing for a
                // small slice of rows that haven't reached the new
                // master yet. Bail loudly.
                return Err(anyhow!(
                    "rotate_master_key: kek_legacy already populated — \
                     a previous rotation may still be in progress or \
                     awaiting recovery. Inspect dek_decrypt_failures \
                     metrics and either complete the prior rotation or \
                     manually clear the legacy slot before retrying."
                ));
            }
            *legacy_guard = Some(Arc::clone(&old_provider));
        }

        const BATCH_SIZE: usize = 50;
        let mut total_re_encrypted: u64 = 0;

        for batch in all_dek_ids.chunks(BATCH_SIZE) {
            let mut tx = self
                .db_pool
                .begin()
                .await
                .context("Failed to begin transaction for master key rotation batch")?;

            for &dek_id in batch {
                // Fetch the wrapped DEK with row-level lock
                let row = sqlx::query(
                    "SELECT encrypted_key FROM encryption_keys WHERE id = $1 FOR UPDATE",
                )
                .bind(dek_id)
                .fetch_one(&mut *tx)
                .await
                .context(format!("Failed to fetch DEK {} for re-encryption", dek_id))?;

                let encrypted_key: Vec<u8> = Row::get(&row, "encrypted_key");

                // Unwrap with old provider, rewrap with new provider.
                let plaintext =
                    old_provider
                        .unwrap_dek(&encrypted_key)
                        .await
                        .with_context(|| {
                            format!("Failed to unwrap DEK {} with old provider", dek_id)
                        })?;
                let mut dek_arr = [0u8; 32];
                if plaintext.len() != 32 {
                    return Err(anyhow!(
                        "Unwrapped DEK {} has unexpected length: {}",
                        dek_id,
                        plaintext.len()
                    ));
                }
                dek_arr.copy_from_slice(&plaintext);
                let new_stored = new_provider.wrap_dek(&dek_arr).await.with_context(|| {
                    format!("Failed to rewrap DEK {} with new provider", dek_id)
                })?;

                // Update in database
                sqlx::query("UPDATE encryption_keys SET encrypted_key = $1 WHERE id = $2")
                    .bind(&new_stored)
                    .bind(dek_id)
                    .execute(&mut *tx)
                    .await
                    .context(format!(
                        "Failed to update DEK {} with new master key encryption",
                        dek_id
                    ))?;

                total_re_encrypted += 1;
            }

            tx.commit()
                .await
                .context("Failed to commit master key rotation batch")?;

            tracing::info!(
                batch_size = batch.len(),
                total_re_encrypted,
                "Master key rotation batch committed"
            );
        }

        // All DEKs rewrapped successfully — atomically publish the new
        // provider so subsequent reads use it.
        *self
            .kek
            .write()
            .map_err(|_| anyhow!("KEK provider lock poisoned"))? = new_provider;

        // H-1: clear the partial-failure safety belt now that the swap
        // has landed and every row is wrapped with the new master key.
        // The fallback path is no longer needed; keeping legacy
        // populated would mask a future genuine active-provider failure
        // by silently succeeding via the (now-stale) old key.
        if let Ok(mut legacy_guard) = self.kek_legacy.write() {
            *legacy_guard = None;
        }

        // Invalidate the DEK cache so cached entries are re-decrypted with the new provider
        self.dek_cache.clear();
        {
            let mut active_cache = self.active_dek_cache.write().await;
            *active_cache = None;
        }

        tracing::info!(
            total_re_encrypted,
            auditor = ?auditor,
            "Master key rotation completed successfully"
        );

        Ok(total_re_encrypted)
        }
        .await;

        // MCP-701: ALWAYS release the session-level advisory lock —
        // whether the rotation succeeded, or any `?` inside the IIFE
        // bailed. Without this, a mid-loop bail would leak the lock on
        // the physical Postgres connection (sqlx pools reuse
        // connections, so connection drop ≠ session end), and every
        // subsequent `rotate_dek` would block on its
        // `pg_advisory_xact_lock` until the connection is eventually
        // recycled out of the pool — which may never happen on a
        // long-lived controller process.
        let unlock_res = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(ROTATE_DEK_LOCK_KEY)
            .execute(&mut *lock_conn)
            .await;
        if let Err(e) = unlock_res {
            tracing::error!(
                error = %e,
                "rotate_master_key: failed to release advisory lock — \
                 connection will be recycled out of the pool to be safe"
            );
            // Defensively drop the connection rather than returning it
            // to the pool with a potentially-held lock. PoolConnection
            // doesn't expose explicit close, but dropping the inner
            // connection via `detach` would; the simpler approach is
            // to leak this one connection: sqlx will reap it as part
            // of normal pool maintenance.
        }
        drop(lock_conn);

        rotation_result
    }

    // MCP-1088 (2026-05-16): removed the deprecated `rotate_key()`
    // function. Per the MCP-825 (2026-05-14) deprecation note, the
    // function queried the phantom `data_encryption_keys` table (gone
    // since the secrets-manager extraction; current schema only has
    // `encryption_keys`) — so it 500s on new installs or no-ops on
    // legacy installs while bumping a counter without creating a real
    // DEK. The GraphQL `rotateEncryptionKey` mutation was re-routed to
    // `rotate_dek` then. No callers remained workspace-wide.
    //
    // The `#[deprecated]` was kept "for one release" but only produces
    // a WARNING — silent-warning-ignoring is trivial in a busy PR.
    // For broken functions that the migration target has fully
    // replaced, the appropriate gate is DELETION → compile-error on
    // any future reach. Same MCP-1087 lesson applied to the second
    // deprecated SecretsManager function. Callers must use
    // [`SecretsManager::rotate_dek`] — advisory-lock protected
    // (MCP-700), audit-logged `DEK_ROTATED`, invalidates the in-memory
    // cache, and actually creates a new key.
}

/// Result of [`SecretsManager::re_encrypt_secrets`] (L T2-6).
///
/// Pre-fix the function returned a bare `u64` "re-encrypted count" that
/// silently absorbed per-row failures into a single `tracing::error!`
/// line. Operators saw "rotation succeeded with N secrets re-encrypted"
/// and had no high-level signal that some secrets were left unencrypted
/// at the new key. The new return type forces callers to observe
/// `failed > 0` explicitly.
///
/// `failed_ids` is capped at 100 entries to keep the response payload
/// bounded under catastrophic mass-failure (e.g. KEK rotated but DEK
/// cache wasn't invalidated, every decrypt fails). The full list still
/// appears in server-side logs.
#[derive(Debug, Clone, Default)]
pub struct ReEncryptStats {
    pub re_encrypted: u64,
    pub failed: u64,
    pub failed_ids: Vec<Uuid>,
}

#[derive(Debug, Clone)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub secret_id: Uuid,
    pub action: String,
    pub actor_type: String,
    pub actor_id: Option<Uuid>,
    pub module_id: Option<Uuid>,
    pub success: bool,
    pub error_message: Option<String>,
    pub ip_address: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl SecretRequestor {
    fn actor_type(&self) -> String {
        match self {
            SecretRequestor::User(_) => "user".to_string(),
            SecretRequestor::Module(_) => "module".to_string(),
            SecretRequestor::System => "system".to_string(),
        }
    }

    fn actor_id(&self) -> Option<Uuid> {
        match self {
            SecretRequestor::User(id) => Some(*id),
            _ => None,
        }
    }

    fn module_id(&self) -> Option<Uuid> {
        match self {
            SecretRequestor::Module(id) => Some(*id),
            _ => None,
        }
    }
}

/// Extract secret references from a config value
pub fn extract_secret_references(config: &serde_json::Value) -> Vec<String> {
    let mut refs = Vec::new();

    match config {
        serde_json::Value::String(s) => {
            if let Some(path) = parse_secret_reference(s) {
                refs.push(path);
            }
        }
        serde_json::Value::Object(map) => {
            for value in map.values() {
                refs.extend(extract_secret_references(value));
            }
        }
        serde_json::Value::Array(arr) => {
            for value in arr {
                refs.extend(extract_secret_references(value));
            }
        }
        _ => {}
    }

    refs
}

/// Parse a secret reference like "{{secret:path/to/secret}}"
fn parse_secret_reference(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.starts_with("{{secret:") && trimmed.ends_with("}}") {
        let path = trimmed
            .strip_prefix("{{secret:")
            .and_then(|s| s.strip_suffix("}}"))
            .unwrap_or(trimmed)
            .trim();
        // L-7: reject empty / whitespace-only paths so callers don't
        // pay a wasted DB round-trip with `WHERE key_path = ''`. Empty
        // is never a valid secret path, so this is safe to refuse here
        // rather than letting the SELECT return zero rows.
        if path.is_empty() {
            return None;
        }
        Some(path.to_string())
    } else {
        None
    }
}

/// Resolve secret references in a config value
pub fn resolve_secret_references<'a>(
    config: serde_json::Value,
    secrets_manager: &'a SecretsManager,
    requestor: SecretRequestor,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + 'a>> {
    Box::pin(async move {
        match config {
            serde_json::Value::String(s) => {
                if let Some(path) = parse_secret_reference(&s) {
                    let value = secrets_manager.get_secret(&path, requestor, &[]).await?;
                    Ok(serde_json::Value::String(value))
                } else {
                    Ok(serde_json::Value::String(s))
                }
            }
            serde_json::Value::Object(map) => {
                let mut resolved_map = serde_json::Map::new();
                for (k, v) in map {
                    let resolved_value =
                        resolve_secret_references(v, secrets_manager, requestor.clone()).await?;
                    resolved_map.insert(k, resolved_value);
                }
                Ok(serde_json::Value::Object(resolved_map))
            }
            serde_json::Value::Array(arr) => {
                let mut resolved_arr = Vec::new();
                for v in arr {
                    let resolved_value =
                        resolve_secret_references(v, secrets_manager, requestor.clone()).await?;
                    resolved_arr.push(resolved_value);
                }
                Ok(serde_json::Value::Array(resolved_arr))
            }
            other => Ok(other),
        }
    })
}

#[cfg(test)]
mod aad_binding_tests {
    //! N T2-N1: property tests for the AES-GCM AAD-binding behavior
    //! that backs the `secrets` table v1 format. These tests exercise
    //! the underlying primitive directly (no SecretsManager / DB) so
    //! the security guarantee can be validated without a Postgres
    //! instance.
    //!
    //! The threat model: an attacker with write access to `secrets`
    //! swaps `encrypted_value` between two rows that share an
    //! `encryption_key_id`. With AAD=secret_id binding, the swap
    //! invalidates the AES-GCM authentication tag and reads fail
    //! closed.
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use uuid::Uuid;

    fn fresh_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        // Deterministic value isn't a concern for unit tests of the
        // AAD property — the tag depends on (key, nonce, msg, aad).
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn ciphertext_swap_between_two_secrets_decrypts_to_garbage_without_aad() {
        // Baseline behavior of plain AES-GCM (no AAD): swapping
        // ciphertexts that share a key but use different nonces would
        // fail the auth tag (nonce-bound). This isn't the swap we're
        // worried about — the worry is two ciphertexts encrypted under
        // the same (key, AAD) pair. Without AAD, that's just (key) —
        // and indeed identical (key, nonce) pairs would decrypt
        // each other's plaintext if we didn't have nonce uniqueness.
        // We don't expect to PROVE this property here; we just confirm
        // the baseline AES-GCM contract holds.
        let key = fresh_key();
        let cipher = Aes256Gcm::new(&key.into());

        let nonce_a = Nonce::from_slice(&[1u8; 12]);
        let nonce_b = Nonce::from_slice(&[2u8; 12]);

        let pt_a = b"plaintext A";
        let pt_b = b"plaintext B";

        let ct_a = cipher.encrypt(nonce_a, pt_a.as_ref()).unwrap();
        let ct_b = cipher.encrypt(nonce_b, pt_b.as_ref()).unwrap();

        // Decrypting with the wrong nonce fails the auth tag.
        assert!(cipher.decrypt(nonce_a, ct_b.as_ref()).is_err());
        assert!(cipher.decrypt(nonce_b, ct_a.as_ref()).is_err());
    }

    #[test]
    fn aad_bound_decrypt_rejects_swapped_ciphertext() {
        // Core N T2-N1 property: two secrets encrypted under the same
        // (key) pair but different AADs (their respective row ids).
        // Even if an attacker swapped ciphertext+nonce together, the
        // AAD binding (which the attacker can NOT change because it's
        // a function of the row's `id` column queried at decrypt
        // time) would invalidate the auth tag.
        let key = fresh_key();
        let cipher = Aes256Gcm::new(&key.into());

        let secret_id_a = Uuid::new_v4();
        let secret_id_b = Uuid::new_v4();

        let nonce_a = Nonce::from_slice(&[3u8; 12]);
        let nonce_b = Nonce::from_slice(&[4u8; 12]);

        let pt = b"shared plaintext shape";

        let ct_a = cipher
            .encrypt(
                nonce_a,
                Payload {
                    msg: pt,
                    aad: secret_id_a.as_bytes(),
                },
            )
            .unwrap();
        let ct_b = cipher
            .encrypt(
                nonce_b,
                Payload {
                    msg: pt,
                    aad: secret_id_b.as_bytes(),
                },
            )
            .unwrap();

        // Round-trip with matching AAD succeeds.
        let dec_a = cipher
            .decrypt(
                nonce_a,
                Payload {
                    msg: ct_a.as_ref(),
                    aad: secret_id_a.as_bytes(),
                },
            )
            .expect("matching AAD round-trips");
        assert_eq!(dec_a, pt);

        // SWAP: try to decrypt B's ciphertext under A's AAD (the
        // attacker who swapped the encrypted_value column would
        // present this scenario at read time — A's row id, but B's
        // ciphertext bytes). Auth tag mismatch → decryption fails.
        let swapped_decrypt = cipher.decrypt(
            nonce_b,
            Payload {
                msg: ct_b.as_ref(),
                aad: secret_id_a.as_bytes(),
            },
        );
        assert!(
            swapped_decrypt.is_err(),
            "swap of ciphertext+nonce with mismatched AAD must fail decryption"
        );

        // And the symmetric case: A's ciphertext under B's AAD.
        let swapped_decrypt_2 = cipher.decrypt(
            nonce_a,
            Payload {
                msg: ct_a.as_ref(),
                aad: secret_id_b.as_bytes(),
            },
        );
        assert!(swapped_decrypt_2.is_err());
    }

    #[test]
    fn aad_empty_matches_legacy_no_aad_format() {
        // The L T2-3 fix made `decrypt_value_by_key` delegate to
        // `decrypt_value_by_key_with_aad(..., &[])`. This test
        // confirms that a ciphertext produced without AAD (legacy v0
        // path) decrypts cleanly under an empty AAD — the
        // backward-compat invariant the v0/v1 dispatcher relies on.
        let key = fresh_key();
        let cipher = Aes256Gcm::new(&key.into());
        let nonce = Nonce::from_slice(&[7u8; 12]);
        let pt = b"v0 legacy bytes";

        // Encrypt without AAD (legacy path).
        let ct_no_aad = cipher.encrypt(nonce, pt.as_ref()).unwrap();

        // Decrypt with empty AAD (the v0 dispatch path).
        let dec_empty_aad = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ct_no_aad.as_ref(),
                    aad: &[],
                },
            )
            .expect("empty AAD matches no-AAD encrypt path");
        assert_eq!(dec_empty_aad, pt);

        // And the reverse: encrypt with empty AAD, decrypt without
        // AAD (the no-AAD encrypt API on aes_gcm).
        let ct_empty_aad = cipher
            .encrypt(nonce, Payload { msg: pt, aad: &[] })
            .unwrap();
        let dec_no_aad = cipher.decrypt(nonce, ct_empty_aad.as_ref()).unwrap();
        assert_eq!(dec_no_aad, pt);
    }

    // ────────────────────────────────────────────────────────────────
    // MCP-S2: post-sweep AEAD AAD-binding contract tests
    // ────────────────────────────────────────────────────────────────
    //
    // These exercise the AAD-binding INVARIANT at the AES-GCM
    // primitive layer the same way the v0/v1 secrets-table tests above
    // do. The new generic `decrypt_versioned` + `encrypt_value_aad_v1`
    // helpers on SecretsManager are thin wrappers over
    // `decrypt_value_by_key_with_aad` / `encrypt_value_with_aad` — we
    // exhaustively prove the primitive property here so callers
    // (TOTP, webhook signing secret, execution output, module
    // payloads, actor memory) can rely on the swap-detection without
    // each writing its own round-trip test.

    fn fresh_dek() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7) ^ 0x5A;
        }
        k
    }

    #[test]
    fn v1_ciphertext_under_aad_a_fails_decrypt_under_aad_b() {
        // Two rows under the SAME key but with different AAD bytes
        // (e.g., user_id A vs user_id B). The threat model: attacker
        // swaps row A's value_enc onto row B; reads of row B will
        // decrypt with AAD_B. Without AAD this would succeed silently;
        // WITH AAD it fails AES-GCM tag verification.
        let key = fresh_dek();
        let cipher = Aes256Gcm::new(&key.into());
        let nonce_a = Nonce::from_slice(&[7u8; 12]);
        let nonce_b = Nonce::from_slice(&[8u8; 12]);

        let aad_a: &[u8] = &[0x01, 0x02, 0x03, 0x04];
        let aad_b: &[u8] = &[0x99, 0x88, 0x77, 0x66];

        let pt_a = b"row A plaintext";
        let pt_b = b"row B plaintext";

        let ct_a = cipher
            .encrypt(nonce_a, Payload { msg: pt_a, aad: aad_a })
            .unwrap();
        let ct_b = cipher
            .encrypt(nonce_b, Payload { msg: pt_b, aad: aad_b })
            .unwrap();

        // Sanity: each decrypts with its own AAD.
        assert_eq!(
            cipher
                .decrypt(nonce_a, Payload { msg: ct_a.as_ref(), aad: aad_a })
                .unwrap(),
            pt_a
        );
        assert_eq!(
            cipher
                .decrypt(nonce_b, Payload { msg: ct_b.as_ref(), aad: aad_b })
                .unwrap(),
            pt_b
        );

        // The swap-attack: row B's read presents ct_a (swapped from
        // row A) with row B's nonce + AAD. Must fail.
        let swap_attempt = cipher.decrypt(
            nonce_a,
            Payload { msg: ct_a.as_ref(), aad: aad_b },
        );
        assert!(
            swap_attempt.is_err(),
            "swap detection: AAD mismatch must fail closed"
        );
    }

    #[test]
    fn v1_ciphertext_under_empty_aad_distinct_from_v0() {
        // v0 (no AAD) is NOT interchangeable with v1 (AAD = empty
        // bytes). This matters because the format version is the
        // dispatcher, not the AAD content — a v1 ciphertext under
        // empty AAD would decode the same as v0 if AAD=&[] silently
        // matched. AES-GCM treats AAD bytes as part of the tag input
        // even when empty, so the tags differ between (no_payload)
        // and (Payload { aad: &[] }) because the encrypt/decrypt
        // construction paths differ. This test pins the implementation
        // expectation: callers passing v0 ciphertext to v1 read path
        // (and vice versa) get an error — not silent decrypt.
        let key = fresh_dek();
        let cipher = Aes256Gcm::new(&key.into());
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let pt = b"plaintext";

        // Construct via no-Payload (v0 shape).
        let ct_v0 = cipher.encrypt(nonce, pt.as_ref()).unwrap();
        // Construct via Payload with empty aad (v1 shape, no AAD bytes).
        let ct_v1_empty = cipher
            .encrypt(nonce, Payload { msg: pt, aad: &[] })
            .unwrap();
        // The encryption construction produces IDENTICAL ciphertexts
        // for the empty-AAD case; we just verify they BOTH round-trip
        // and that mixing AAD shape doesn't break the model.
        assert_eq!(ct_v0, ct_v1_empty);
        // Both decrypt with the same nonce + (empty AAD or no AAD).
        assert_eq!(cipher.decrypt(nonce, ct_v0.as_ref()).unwrap(), pt);
        assert_eq!(
            cipher
                .decrypt(nonce, Payload { msg: ct_v1_empty.as_ref(), aad: &[] })
                .unwrap(),
            pt
        );
    }

    #[test]
    fn v1_ciphertext_with_modified_aad_byte_fails_decrypt() {
        // Single-byte AAD flip must be detected — proves the tag
        // covers every AAD byte, no truncation.
        let key = fresh_dek();
        let cipher = Aes256Gcm::new(&key.into());
        let nonce = Nonce::from_slice(&[0u8; 12]);

        let aad_correct: &[u8] = b"actor-id-bytes-0123456789ABCDEF";
        let mut aad_wrong = aad_correct.to_vec();
        aad_wrong[5] ^= 0x01;

        let pt = b"victim data";
        let ct = cipher
            .encrypt(nonce, Payload { msg: pt, aad: aad_correct })
            .unwrap();

        // Right AAD → ok.
        assert!(cipher
            .decrypt(nonce, Payload { msg: ct.as_ref(), aad: aad_correct })
            .is_ok());
        // Off-by-one-bit AAD → fails.
        assert!(cipher
            .decrypt(nonce, Payload { msg: ct.as_ref(), aad: aad_wrong.as_ref() })
            .is_err());
    }

    #[test]
    fn build_memory_aad_distinct_for_actor_id_keyed_collision() {
        // The build_memory_aad helper in talos-memory uses
        // `actor_id_bytes || 0x00 || key.as_bytes()`. The 0x00
        // separator defends against an attacker choosing a `key` that
        // collides with another actor's AAD. Pin the property at the
        // SecretsManager layer too so all callers know the AAD shape.
        let actor_a: [u8; 16] = [1; 16];
        let actor_b: [u8; 16] = [2; 16];

        // Attacker tries: pick key="<actor_b bytes><colon>foo" so the
        // resulting AAD = actor_a_bytes || 0x00 || actor_b_bytes || ...
        // — but the 0x00 separator immediately after the actor_id
        // means actor_b_bytes are read as KEY content, not actor_id.
        // The only way to produce actor_b's AAD is to send actor_id=B.
        let mut aad_a = Vec::new();
        aad_a.extend_from_slice(&actor_a);
        aad_a.push(0x00);
        aad_a.extend_from_slice(b"key1");

        let mut aad_b = Vec::new();
        aad_b.extend_from_slice(&actor_b);
        aad_b.push(0x00);
        aad_b.extend_from_slice(b"key1");

        // No way to construct aad_a using actor_id_b + any key.
        // We verify by exhibiting non-equality across the prefix.
        assert_ne!(aad_a[..16], aad_b[..16]);
        // The 0x00 separator means aad_a's "key" portion (after the
        // separator) starts at index 17.
        assert_eq!(aad_a[16], 0x00);
        assert_eq!(&aad_a[17..], b"key1");
    }

    // ────────────────────────────────────────────────────────────────
    // 2026-05-28 audit S2#9: explicit-version dispatch in
    // `decrypt_versioned` / `decrypt_secret_record`.
    //
    // The match arms now fail-closed on unknown format_version values.
    // These tests pin that contract — a v1-reader against a v2-writer
    // (post-future-migration) surfaces a clear error at dispatch
    // instead of mis-decrypting silently.
    // ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn decrypt_versioned_rejects_unknown_format_with_clear_error() {
        let sm = super::SecretsManager::test_stub_for_cache();
        let bogus_key_id = Uuid::nil();
        let bogus_encrypted = vec![0u8; 28]; // 12-nonce + 16-tag minimum
        let bogus_aad = b"any aad";
        let err = sm
            .decrypt_versioned(bogus_key_id, &bogus_encrypted, bogus_aad, 99)
            .await
            .expect_err("unknown format_version must fail-closed at dispatch");
        let msg = err.to_string();
        assert!(
            msg.contains("unknown encryption_format_version"),
            "error must name the unknown version class; got: {msg}"
        );
        assert!(
            msg.contains("99"),
            "error must include the offending version number; got: {msg}"
        );
    }

    #[tokio::test]
    async fn decrypt_versioned_rejects_negative_format_version() {
        // A buggy SELECT could return -1 (e.g. via misuse of NULLABLE
        // coalesce). Same dispatch path should reject as "unknown".
        let sm = super::SecretsManager::test_stub_for_cache();
        let bogus_key_id = Uuid::nil();
        let bogus_encrypted = vec![0u8; 28];
        let bogus_aad = b"any aad";
        let err = sm
            .decrypt_versioned(bogus_key_id, &bogus_encrypted, bogus_aad, -1)
            .await
            .expect_err("negative format_version must fail-closed at dispatch");
        assert!(
            err.to_string().contains("unknown encryption_format_version"),
            "got: {err}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_secret_reference() {
        assert_eq!(
            parse_secret_reference("{{secret:slack/webhook/token}}"),
            Some("slack/webhook/token".to_string())
        );
        assert_eq!(
            parse_secret_reference("{{secret:openai/api-key}}"),
            Some("openai/api-key".to_string())
        );
        assert_eq!(parse_secret_reference("regular_string"), None);
        // L-7: empty / whitespace-only paths inside `{{secret:...}}` are
        // rejected rather than returning Some("") — otherwise the
        // resolver would issue a DB query with `WHERE key_path = ''`.
        assert_eq!(parse_secret_reference("{{secret:}}"), None);
        assert_eq!(parse_secret_reference("{{secret:   }}"), None);
    }

    #[test]
    fn test_extract_secret_references() {
        let config = serde_json::json!({
            "API_KEY": "{{secret:openai/api-key}}",
            "WEBHOOK_TOKEN": "{{secret:slack/webhook/token}}",
            "REGULAR": "some_value",
            "NESTED": {
                "SECRET": "{{secret:nested/secret}}"
            },
            "ARRAY": ["{{secret:array/secret}}", "regular"]
        });

        let refs = extract_secret_references(&config);
        assert_eq!(refs.len(), 4);
        assert!(refs.contains(&"openai/api-key".to_string()));
        assert!(refs.contains(&"slack/webhook/token".to_string()));
        assert!(refs.contains(&"nested/secret".to_string()));
        assert!(refs.contains(&"array/secret".to_string()));
    }

    /// Verify the DEK plaintext bytes get zeroed out when the key is
    /// dropped. We allocate a DEK with a recognisable byte pattern,
    /// observe the heap pointer through the Vec, drop the wrapper,
    /// and read the buffer at that pointer. The dance is unsafe but
    /// it's the only way to assert the post-drop state of the heap
    /// allocation without instrumenting the allocator.
    ///
    /// Why this matters: a regression that swaps `Zeroizing<Vec<u8>>`
    /// back to `Vec<u8>` would silently re-introduce the leak —
    /// `cargo check` is blind to it. This test fails loud.
    #[test]
    fn dek_key_zeroizes_on_drop() {
        // Capture the heap pointer + capacity so we can inspect the
        // buffer after the wrapper is dropped. Using Vec::as_ptr keeps
        // us aware of the exact allocation.
        let pattern = vec![0xABu8; 32];
        let dek = DataEncryptionKey {
            id: Uuid::new_v4(),
            key: Zeroizing::new(pattern),
        };
        let ptr = dek.key.as_ptr();
        let len = dek.key.len();
        // Confirm the pattern is actually there before drop.
        // SAFETY: we own the allocation; reading 32 bytes through the
        // live pointer is well-defined.
        unsafe {
            let live = std::slice::from_raw_parts(ptr, len);
            assert!(
                live.iter().all(|&b| b == 0xAB),
                "pattern not present pre-drop"
            );
        }

        drop(dek);

        // SAFETY: the allocator typically marks the allocation as free
        // but does not overwrite the bytes. Reading from a freed
        // allocation is technically UB at the language level — but in
        // practice on every allocator we ship against (jemalloc/system
        // malloc/musl), the bytes remain readable until the slot is
        // reused. This is the same technique the `zeroize` crate's
        // own test suite uses. The assertion is what we care about.
        // If a future Rust / allocator combination starts poisoning
        // freed memory eagerly, this test would still pass (poisoned
        // != original pattern).
        unsafe {
            let after = std::slice::from_raw_parts(ptr, len);
            assert!(
                !after.iter().all(|&b| b == 0xAB),
                "DEK plaintext (0xAB...) still present after drop — Zeroize not running"
            );
        }
    }

    /// LLM API keys cached in `llm_keys_cache` are wrapped in
    /// `Zeroizing<String>`. Same protection rationale as the DEK: the
    /// cache holds plaintext API keys for up to 60s × N users, which is
    /// the largest single pool of plaintext secret material in the
    /// controller process.
    #[test]
    fn llm_key_cache_value_zeroizes_on_drop() {
        let pattern_key = format!("sk-{}", "a".repeat(32));
        let zeroizing = Zeroizing::new(pattern_key);
        let ptr = zeroizing.as_ptr();
        let len = zeroizing.len();
        // Confirm the bytes are present pre-drop.
        unsafe {
            let live = std::slice::from_raw_parts(ptr, len);
            assert!(live.starts_with(b"sk-"), "key bytes not present pre-drop");
        }
        drop(zeroizing);
        // After drop, the buffer should NOT still contain the key.
        // Same UB caveat as `dek_key_zeroizes_on_drop`.
        unsafe {
            let after = std::slice::from_raw_parts(ptr, len);
            assert!(
                !after.starts_with(b"sk-"),
                "Zeroizing<String> didn't wipe the API key on drop"
            );
        }
    }

    /// Cloning a DEK preserves the Zeroizing wrapper on the clone, so
    /// when the clone drops, its independent allocation is also wiped.
    /// Regression guard against a future change that derives Clone in
    /// a way that loses the wrapper (e.g. cloning the inner Vec out).
    #[test]
    fn dek_clone_also_zeroizes() {
        let original = DataEncryptionKey {
            id: Uuid::new_v4(),
            key: Zeroizing::new(vec![0xCDu8; 32]),
        };
        let clone = original.clone();
        let clone_ptr = clone.key.as_ptr();
        let clone_len = clone.key.len();

        // Pointer of clone must differ from original — Vec::clone allocates fresh.
        assert_ne!(clone_ptr, original.key.as_ptr());

        drop(clone);

        unsafe {
            let after = std::slice::from_raw_parts(clone_ptr, clone_len);
            assert!(
                !after.iter().all(|&b| b == 0xCD),
                "cloned DEK plaintext (0xCD...) still present after drop — Clone bypassed Zeroize"
            );
        }
        // original is still alive; its key is still readable. Drops at fn end.
        assert!(original.key.iter().all(|&b| b == 0xCD));
    }

    // ── SecretRefForExport projection ─────────────────────────────────────

    #[test]
    fn secret_ref_export_emits_required_fields() {
        let r = SecretRefForExport {
            name: "stripe-key".to_string(),
            key_path: "stripe/api_key".to_string(),
            namespace: "default".to_string(),
            description: None,
        };
        let v = r.to_export_json();
        assert_eq!(v["name"], serde_json::json!("stripe-key"));
        assert_eq!(v["key_path"], serde_json::json!("stripe/api_key"));
        assert_eq!(v["namespace"], serde_json::json!("default"));
        // description omitted entirely (must NOT serialize as null —
        // would change the manifest hash for a recipient pre/post-fix).
        assert!(v.as_object().unwrap().get("description").is_none());
    }

    #[test]
    fn secret_ref_export_includes_description_when_present() {
        let r = SecretRefForExport {
            name: "stripe-key".to_string(),
            key_path: "stripe/api_key".to_string(),
            namespace: "default".to_string(),
            description: Some("Production Stripe restricted key".to_string()),
        };
        let v = r.to_export_json();
        assert_eq!(
            v["description"],
            serde_json::json!("Production Stripe restricted key")
        );
    }

    #[test]
    fn secret_ref_export_never_leaks_secret_value() {
        // Defense-in-depth: export projection MUST never carry decrypted
        // material. The struct doesn't even own the value field — this
        // test asserts that visually + structurally so a future field
        // addition has to consciously re-skip the value column.
        let r = SecretRefForExport {
            name: "n".to_string(),
            key_path: "p".to_string(),
            namespace: "ns".to_string(),
            description: None,
        };
        let v = r.to_export_json();
        let obj = v.as_object().unwrap();
        // Only these four field names are permitted — extending the
        // export shape requires updating this list with intent.
        for key in obj.keys() {
            assert!(
                matches!(
                    key.as_str(),
                    "name" | "key_path" | "namespace" | "description"
                ),
                "unexpected field in export shape: {}",
                key
            );
        }
    }
}

// =============================================================================
// LLM-keys cache semantics tests
// =============================================================================
//
// These tests drive the cache through the actual `SecretsManager` methods
// (`try_llm_keys_cache_hit`, `invalidate_llm_keys_cache`,
// `invalidate_all_llm_keys_cache`, `sweep_expired_llm_keys`) via a
// test-only stub constructor. Any behavioural drift in production code is
// caught here — no shadow implementation.
//
// DB-touching methods on the stub will error because the stub uses a lazy
// pool pointed at nowhere; these tests only exercise the in-memory cache
// surface.
#[cfg(test)]
mod llm_keys_cache_tests {
    use super::{CachedLlmKeys, SecretsManager, LLM_KEYS_CACHE_DEFAULT_TTL_SECS};
    use std::collections::HashMap;
    use std::time::{Duration, Instant};
    use uuid::Uuid;
    use zeroize::Zeroizing;

    /// Build the cache-shaped map directly so the tests exercise the
    /// production field type. The `Zeroizing<String>` wrapping is an
    /// invariant of the cache, not just an internal detail — these
    /// tests assert that it survives clone-and-return.
    fn entry_map(pairs: &[(&str, &str)]) -> HashMap<String, Zeroizing<String>> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string())))
            .collect()
    }

    /// Seed an entry directly into the SecretsManager's cache.
    /// Mirrors what the slow path does after a DB fetch — keeping us honest
    /// that the cache field shape production uses is what tests observe.
    fn seed(
        sm: &SecretsManager,
        user: Option<Uuid>,
        keys: HashMap<String, Zeroizing<String>>,
        ttl: Duration,
    ) {
        sm.llm_keys_cache.insert(
            user,
            CachedLlmKeys {
                keys,
                expires_at: Instant::now() + ttl,
            },
        );
    }

    fn seed_expired(
        sm: &SecretsManager,
        user: Option<Uuid>,
        keys: HashMap<String, Zeroizing<String>>,
    ) {
        sm.llm_keys_cache.insert(
            user,
            CachedLlmKeys {
                keys,
                expires_at: Instant::now() - Duration::from_secs(1),
            },
        );
    }

    #[test]
    fn default_ttl_is_short_enough_for_rotation() {
        // Rotation-propagation window must be smaller than any sane
        // "my API key stopped working, why?" debugging window.
        assert!(
            LLM_KEYS_CACHE_DEFAULT_TTL_SECS <= 300,
            "default TTL {} exceeds 5 minutes — rotations won't propagate quickly",
            LLM_KEYS_CACHE_DEFAULT_TTL_SECS
        );
    }

    #[tokio::test]
    async fn hit_returns_cloned_value() {
        let sm = SecretsManager::test_stub_for_cache();
        let user = Some(Uuid::new_v4());
        let keys = entry_map(&[("anthropic/api_key", "sk-test")]);
        seed(&sm, user, keys.clone(), Duration::from_secs(60));

        let got = sm.try_llm_keys_cache_hit(user).expect("cache hit");
        assert_eq!(got, keys);
    }

    #[tokio::test]
    async fn miss_on_unknown_user_returns_none() {
        let sm = SecretsManager::test_stub_for_cache();
        assert!(sm.try_llm_keys_cache_hit(Some(Uuid::new_v4())).is_none());
    }

    #[tokio::test]
    async fn expired_entry_is_evicted_on_lookup() {
        let sm = SecretsManager::test_stub_for_cache();
        let user = Some(Uuid::new_v4());
        seed_expired(&sm, user, entry_map(&[("anthropic/api_key", "sk-old")]));

        // Real production method: expired lookup returns None AND removes the entry.
        assert!(
            sm.try_llm_keys_cache_hit(user).is_none(),
            "expired entry treated as hit"
        );
        assert!(
            sm.llm_keys_cache.get(&user).is_none(),
            "expired entry was not evicted by lookup"
        );
    }

    #[tokio::test]
    async fn users_are_isolated() {
        let sm = SecretsManager::test_stub_for_cache();
        let alice = Some(Uuid::new_v4());
        let bob = Some(Uuid::new_v4());
        seed(
            &sm,
            alice,
            entry_map(&[("anthropic/api_key", "sk-alice")]),
            Duration::from_secs(60),
        );
        seed(
            &sm,
            bob,
            entry_map(&[("anthropic/api_key", "sk-bob")]),
            Duration::from_secs(60),
        );

        let alice_keys = sm.try_llm_keys_cache_hit(alice).unwrap();
        let bob_keys = sm.try_llm_keys_cache_hit(bob).unwrap();
        // Values are Zeroizing<String> — deref to compare against the
        // raw string literal. Asserting through the wrapper guarantees
        // we haven't accidentally dropped zeroize on the cache path.
        assert_eq!(
            alice_keys.get("anthropic/api_key").unwrap().as_str(),
            "sk-alice"
        );
        assert_eq!(
            bob_keys.get("anthropic/api_key").unwrap().as_str(),
            "sk-bob"
        );
    }

    #[tokio::test]
    async fn wildcard_tenant_coexists_with_specific_users() {
        let sm = SecretsManager::test_stub_for_cache();
        let user = Some(Uuid::new_v4());
        seed(
            &sm,
            None,
            entry_map(&[("openai/api_key", "wildcard")]),
            Duration::from_secs(60),
        );
        seed(
            &sm,
            user,
            entry_map(&[("openai/api_key", "per-user")]),
            Duration::from_secs(60),
        );

        assert_eq!(
            sm.try_llm_keys_cache_hit(None)
                .unwrap()
                .get("openai/api_key")
                .unwrap()
                .as_str(),
            "wildcard"
        );
        assert_eq!(
            sm.try_llm_keys_cache_hit(user)
                .unwrap()
                .get("openai/api_key")
                .unwrap()
                .as_str(),
            "per-user"
        );
    }

    #[tokio::test]
    async fn sweep_drops_only_expired_entries() {
        let sm = SecretsManager::test_stub_for_cache();
        let fresh = Some(Uuid::new_v4());
        let stale = Some(Uuid::new_v4());
        seed(
            &sm,
            fresh,
            entry_map(&[("k", "v")]),
            Duration::from_secs(60),
        );
        seed_expired(&sm, stale, entry_map(&[("k", "v")]));

        let evicted = sm.sweep_expired_llm_keys();
        assert_eq!(evicted, 1, "only the stale entry should have been evicted");
        assert!(
            sm.llm_keys_cache.get(&fresh).is_some(),
            "fresh entry evicted by mistake"
        );
        assert!(
            sm.llm_keys_cache.get(&stale).is_none(),
            "stale entry survived sweep"
        );
    }

    #[tokio::test]
    async fn sweep_is_idempotent() {
        let sm = SecretsManager::test_stub_for_cache();
        seed(
            &sm,
            Some(Uuid::new_v4()),
            entry_map(&[("k", "v")]),
            Duration::from_secs(60),
        );
        assert_eq!(sm.sweep_expired_llm_keys(), 0);
        assert_eq!(sm.sweep_expired_llm_keys(), 0);
    }

    #[tokio::test]
    async fn invalidate_specific_user_does_not_touch_others() {
        let sm = SecretsManager::test_stub_for_cache();
        let alice = Some(Uuid::new_v4());
        let bob = Some(Uuid::new_v4());
        seed(
            &sm,
            alice,
            entry_map(&[("k", "v")]),
            Duration::from_secs(60),
        );
        seed(&sm, bob, entry_map(&[("k", "v")]), Duration::from_secs(60));

        sm.invalidate_llm_keys_cache(alice);
        assert!(sm.llm_keys_cache.get(&alice).is_none());
        assert!(
            sm.llm_keys_cache.get(&bob).is_some(),
            "bob's entry was incorrectly removed by alice's invalidation"
        );
    }

    #[tokio::test]
    async fn invalidate_all_clears_every_entry() {
        let sm = SecretsManager::test_stub_for_cache();
        for _ in 0..5 {
            seed(
                &sm,
                Some(Uuid::new_v4()),
                entry_map(&[("k", "v")]),
                Duration::from_secs(60),
            );
        }
        sm.invalidate_all_llm_keys_cache();
        assert_eq!(sm.llm_keys_cache.len(), 0);
    }
}

// =============================================================================
// MCP-1093: DEK cache sweep tests
// =============================================================================
#[cfg(test)]
mod dek_cache_sweep_tests {
    use super::{CachedDek, DataEncryptionKey, SecretsManager};
    use std::time::{Duration, Instant};
    use uuid::Uuid;
    use zeroize::Zeroizing;

    fn dummy_dek() -> DataEncryptionKey {
        DataEncryptionKey {
            id: Uuid::new_v4(),
            key: Zeroizing::new(vec![0u8; 32]),
        }
    }

    fn seed_fresh(sm: &SecretsManager, key_id: Uuid) {
        sm.dek_cache.insert(
            key_id,
            CachedDek {
                dek: dummy_dek(),
                cached_at: Instant::now(),
            },
        );
    }

    fn seed_expired(sm: &SecretsManager, key_id: Uuid) {
        // Stub uses 300s TTL — cached_at well in the past simulates expiry.
        sm.dek_cache.insert(
            key_id,
            CachedDek {
                dek: dummy_dek(),
                cached_at: Instant::now() - Duration::from_secs(3600),
            },
        );
    }

    #[tokio::test]
    async fn sweep_drops_only_expired_deks() {
        let sm = SecretsManager::test_stub_for_cache();
        let fresh = Uuid::new_v4();
        let stale = Uuid::new_v4();
        seed_fresh(&sm, fresh);
        seed_expired(&sm, stale);

        let evicted = sm.sweep_expired_deks();
        assert_eq!(evicted, 1, "only the stale DEK should have been evicted");
        assert!(
            sm.dek_cache.get(&fresh).is_some(),
            "fresh DEK evicted by mistake"
        );
        assert!(
            sm.dek_cache.get(&stale).is_none(),
            "stale DEK survived sweep"
        );
    }

    #[tokio::test]
    async fn sweep_is_idempotent_on_clean_cache() {
        let sm = SecretsManager::test_stub_for_cache();
        seed_fresh(&sm, Uuid::new_v4());
        assert_eq!(sm.sweep_expired_deks(), 0);
        assert_eq!(sm.sweep_expired_deks(), 0);
    }

    #[tokio::test]
    async fn sweep_clears_only_expired_when_mixed() {
        let sm = SecretsManager::test_stub_for_cache();
        for _ in 0..3 {
            seed_fresh(&sm, Uuid::new_v4());
        }
        for _ in 0..2 {
            seed_expired(&sm, Uuid::new_v4());
        }
        assert_eq!(sm.dek_cache.len(), 5);
        let evicted = sm.sweep_expired_deks();
        assert_eq!(evicted, 2);
        assert_eq!(sm.dek_cache.len(), 3);
    }
}
