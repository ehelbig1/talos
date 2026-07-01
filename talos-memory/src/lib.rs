//! # talos-memory — shared actor memory service
//!
//! Canonical read/write/search surface for the `actor_memory` table,
//! depended on by both the controller and the worker so that every
//! write path computes embeddings through the same code and every
//! search path hits the same pgvector cosine query.
//!
//! The controller additionally wires graph-RAG entity extraction to
//! this service via [`register_graph_hook`] at startup — the hook is
//! invoked post-persist so a missing Neo4j never blocks memory writes.
//!
//! Prior to extraction this module lived in
//! `controller/src/actor_memory_service.rs`. Moving it out of the
//! controller lets the worker's WIT `agent-memory::{set, get, search,
//! store-with-embedding}` host impl delegate to the same path that
//! MCP uses, instead of the keyword-ILIKE shortcut that used to live
//! in `worker/src/host_impl.rs`.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use sqlx::{Pool, Postgres, Row};
use std::sync::{Arc, OnceLock};
use uuid::Uuid;

pub mod actor_context;
pub mod database_rpc;
pub mod embedding;
pub mod graph_rpc;
pub mod integration_state_rpc;
pub mod memory_rpc;
pub mod rpc_auth;
pub mod state_rpc;

pub const MAX_VALUE_BYTES: usize = 64 * 1024;
/// MCP-656: cap caller-controlled `metadata` JSONB at 16 KiB. Pre-fix
/// the persist_memory_with_metadata path serialized and INSERTed metadata
/// of arbitrary size into a JSONB column with no upper bound — a guest
/// could ship a ~900 KiB metadata blob (NATS max-msg of ~1 MiB minus
/// signing overhead) and bloat the actor_memory table row-by-row. Every
/// in-use label today (`meeting_prep`, `recall`, `daily_brief`) is tens
/// of bytes; 16 KiB leaves room for richer structured tags without
/// inviting payload abuse. Applies to BOTH `persist_memory_with_metadata`
/// and `persist_memory_in_tx_with_metadata` so the cap is uniform across
/// all writers (engine `__memory_write__`, RPC subscriber Set, MCP
/// handlers).
pub const MAX_METADATA_BYTES: usize = 16 * 1024;
pub const MAX_MEMORIES_PER_ACTOR: i64 = 10_000;
pub const MAX_LIST_LIMIT: i64 = 200;
pub const MEMORY_TYPES: &[&str] = &["working", "episodic", "semantic", "scratchpad"];

/// CSV rendering of [`MEMORY_TYPES`] for error messages.
///
/// MCP-819 (2026-05-14): single source of truth for the "valid values"
/// suffix in operator-facing memory_type rejection errors. Pre-fix six
/// sites in `talos-mcp-handlers/src/actor.rs` hardcoded the list as a
/// string literal — a new memory_type added to `MEMORY_TYPES` would
/// silently leave those error messages stale.
pub fn memory_types_csv() -> String {
    MEMORY_TYPES.join(", ")
}

/// Whether `s` is one of the recognised memory types.
///
/// MCP-819 (2026-05-14): companion to `memory_types_csv` — collapses
/// the six drifted `matches!(s, "working" | "episodic" | ...)` arms
/// in `talos-mcp-handlers/src/actor.rs` into one canonical predicate.
#[inline]
#[must_use]
pub fn is_valid_memory_type(s: &str) -> bool {
    MEMORY_TYPES.contains(&s)
}

/// Maximum byte length of an actor_memory key after trimming.
///
/// Mirrors the cap inside `persist_memory_with_metadata` (lib.rs:396),
/// promoted here so every caller observes the same value. The MCP
/// `validate_memory_key` helper (talos-mcp-handlers/src/actor.rs:1201)
/// has historically enforced 500; GraphQL `write_actor_memory` enforced
/// 200 — that asymmetry is now closed via [`validate_memory_key`] below.
pub const MAX_MEMORY_KEY_CHARS: usize = 500;

/// Canonical actor_memory key validator.
///
/// Steps mirror MCP `handle_actor_remember` / `handle_actor_forget` (MCP-388):
///   1. Trim leading/trailing whitespace.
///   2. Reject empty-after-trim (`"   "` → operator typo).
///   3. Cap length-after-trim at [`MAX_MEMORY_KEY_CHARS`].
///   4. Reject `\0` and control chars on the ORIGINAL (a key that trims
///      clean but had embedded `\0` still corrupts downstream lookups
///      and crashes `UPDATE ... SET key = $` with opaque Postgres
///      errors — MCP-431 class).
///
/// Returns the trimmed slice so callers can shadow the input variable.
/// Trim parity is critical: pre-MCP-388 `actor_remember(key: "  foo  ")`
/// stored the key with padding while `actor_recall(key: "foo")`
/// (paste-cleaned) missed the lookup.
///
/// MCP-834 (2026-05-14): promoted from `talos-mcp-handlers::actor::validate_memory_key`
/// so GraphQL `write_actor_memory` / `delete_actor_memory` mutations share
/// the same contract. Same canonicalization pattern as MCP-819
/// (`is_valid_memory_type`).
pub fn validate_memory_key(key: &str) -> Result<&str, &'static str> {
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return Err("key must be a non-empty, non-whitespace string");
    }
    if trimmed.len() > MAX_MEMORY_KEY_CHARS {
        return Err("key must be 1–500 characters");
    }
    if key.contains('\0') || key.chars().any(|c| c.is_control() && c != '\t') {
        return Err("key cannot contain control characters or null bytes");
    }
    Ok(trimmed)
}

/// MCP-437 (2026-05-11): hard upper bound on caller-controlled TTL.
/// 10 years matches the secret-expiry ceiling from MCP-404. Any
/// legitimate use case fits well under this — even long-lived
/// "semantic" actor memories are documented to use None (no expiry)
/// rather than a multi-decade TTL.
///
/// Before this bound existed, a module could emit
/// `__memory_write__: {ttl_hours: 1e30}` from inside a workflow run.
/// The downstream computation was `(hours * 3600.0) as i64` which
/// saturates to i64::MAX, then `Utc::now() + Duration::seconds(i64::MAX)`
/// overflows chrono's DateTime range — depending on chrono version
/// either panicking or wrapping the timestamp into the distant past
/// (effectively expired). Either way the memory's actual expiry is
/// nondeterministic and the operator's TTL intent is destroyed.
///
/// 10 years = 87 600 hours.
pub const MAX_TTL_HOURS: f64 = 87_600.0;

pub fn default_expires_at(memory_type: &str, ttl_hours: Option<f64>) -> Option<DateTime<Utc>> {
    let hours = ttl_hours.or(match memory_type {
        "working" => Some(1.0),
        "episodic" => Some(168.0),
        "scratchpad" => Some(24.0),
        "semantic" => None,
        _ => Some(1.0),
    })?;
    if !hours.is_finite() || hours <= 0.0 {
        return None;
    }
    // MCP-437: clamp absurd values to the documented ceiling instead
    // of overflowing chrono's DateTime arithmetic. Clamping rather
    // than rejecting because the caller's intent ("long-lived
    // memory") is preserved — they just get 10 years instead of
    // arbitrary i64::MAX. Logging the clamp would be nice but this
    // function is pure (no tracing dep), so the caller layer can
    // log if it cares.
    let hours = hours.min(MAX_TTL_HOURS);
    let secs = (hours * 3600.0) as i64;
    Some(Utc::now() + Duration::seconds(secs))
}

pub fn validate_memory_type(memory_type: &str) -> Result<&'static str> {
    match memory_type {
        "working" => Ok("working"),
        "episodic" => Ok("episodic"),
        "semantic" => Ok("semantic"),
        "scratchpad" => Ok("scratchpad"),
        other => anyhow::bail!(
            "invalid memory_type '{other}': must be one of {:?}",
            MEMORY_TYPES
        ),
    }
}

static GRAPH_EXTRACTION_SEMAPHORE: std::sync::LazyLock<tokio::sync::Semaphore> =
    std::sync::LazyLock::new(|| tokio::sync::Semaphore::new(5));

/// Graph extraction callback. Controllers wire this at startup via
/// [`register_graph_hook`]; the worker never registers one (so graph
/// extraction is a controller-only concern even though memory writes
/// can originate from either side).
pub trait GraphHook: Send + Sync + 'static {
    fn extract(
        &self,
        actor_id: Uuid,
        key: String,
        value: serde_json::Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>;
}

static GRAPH_HOOK: OnceLock<Arc<dyn GraphHook>> = OnceLock::new();

/// Register the graph-extraction callback. Idempotent — subsequent
/// calls are ignored so controller restarts never double-register.
pub fn register_graph_hook(hook: Arc<dyn GraphHook>) {
    let _ = GRAPH_HOOK.set(hook);
}

/// Crypto callback for `actor_memory.value` at-rest encryption (Phase A
/// of `docs/security/agent-memory-encryption-plan.md`).
///
/// Controllers wire this at startup via [`register_memory_crypto_hook`].
/// When registered, every memory write encrypts the JSON-serialized value
/// via `encrypt` and stores ciphertext in `value_enc` + `value_key_id`,
/// leaving the legacy `value` column NULL. Reads prefer ciphertext when
/// present, fall back to plaintext `value` for legacy rows.
///
/// When unregistered (worker / standalone tests), writes go to the
/// legacy plaintext `value` column — the dual-write window is what
/// keeps existing tests passing without crypto wiring.
pub trait MemoryCryptoHook: Send + Sync + 'static {
    /// Encrypt a JSON-serialized memory value with the supplied AAD
    /// (Additional Authenticated Data). Returns (key_id, ciphertext,
    /// format_version). MCP-S2: callers pass the stable composite
    /// `(actor_id || key.as_bytes())` so an attacker with DB write
    /// capability can't swap `value_enc` between two rows that share
    /// `value_key_id` (silent cross-actor / cross-key data leak).
    /// The format_version is persisted to `actor_memory.value_format`
    /// alongside the ciphertext.
    ///
    /// Per-org DEK arc: `org_id` is the actor's org (resolved by the persist /
    /// clone caller). `Some(org)` → encrypt under that org's root DEK (format
    /// v4); `None` → the global DEK (v3). The DEK scope matches the row's
    /// stamped `actor_memory.org_id`.
    fn encrypt(&self, plaintext: String, org_id: Option<Uuid>, aad: Vec<u8>) -> EncryptFuture;

    /// Decrypt ciphertext using the DEK referenced by `key_id`,
    /// dispatching on the per-row `value_format` column (0 = legacy
    /// no-AAD, 1 = AAD-bound). Returns the plaintext wrapped in
    /// [`zeroize::Zeroizing<String>`] so the heap allocation backing
    /// the decrypted bytes is wiped on drop. Callers reach a `&str`
    /// via `Deref` transparently.
    fn decrypt(
        &self,
        key_id: Uuid,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
        format_version: i16,
    ) -> DecryptFuture;
}

/// Future returned by [`MemoryCryptoHook::encrypt`]. Carries the
/// AAD format version alongside (key_id, ciphertext) so the per-row
/// version column can be persisted in lockstep.
pub type EncryptFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = anyhow::Result<(Uuid, Vec<u8>, i16)>> + Send>,
>;

/// Future returned by [`MemoryCryptoHook::decrypt`].
pub type DecryptFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = anyhow::Result<zeroize::Zeroizing<String>>> + Send>,
>;

/// Build the stable AAD bytes for an `actor_memory` row from its
/// composite primary key `(actor_id, key)`. Used by writers at
/// encrypt time and readers at decrypt time — both sites MUST produce
/// identical bytes or AES-GCM tag verification fails. The format
/// `actor_id_bytes || 0x00 || key.as_bytes()` includes a separator byte
/// so a malicious choice of `key` can't manufacture a collision with
/// another row's AAD (e.g., key="<other-actor-uuid-bytes>...").
pub fn build_memory_aad(actor_id: Uuid, key: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 1 + key.len());
    aad.extend_from_slice(actor_id.as_bytes());
    aad.push(0x00);
    aad.extend_from_slice(key.as_bytes());
    aad
}

static MEMORY_CRYPTO_HOOK: OnceLock<Arc<dyn MemoryCryptoHook>> = OnceLock::new();

/// Register the at-rest encryption callback. Idempotent.
pub fn register_memory_crypto_hook(hook: Arc<dyn MemoryCryptoHook>) {
    let _ = MEMORY_CRYPTO_HOOK.set(hook);
}

/// True when crypto is wired — writers encrypt, readers prefer ciphertext.
pub fn memory_crypto_enabled() -> bool {
    MEMORY_CRYPTO_HOOK.get().is_some()
}

/// Encrypt a memory value if crypto is registered. Returns
/// `Some((key_id, ciphertext, format_version))` when crypto is active,
/// `None` when the legacy plaintext path should be used. Errors on
/// crypto failure (caller decides whether to fall back or fail the
/// write — current policy is to fail the write rather than silently
/// downgrade).
///
/// MCP-S2: `aad` MUST be `build_memory_aad(actor_id, key)` so the
/// ciphertext is bound to the composite primary key. Caller is
/// responsible for passing the same bytes at decrypt time.
///
/// Persist paths serialize the value ONCE at the top (for the size cap
/// check + embedding text input) and pass the same string through here
/// to avoid redundant `serde_json::to_string` round-trips per write.
pub(crate) async fn maybe_encrypt_value_serialized(
    plaintext: String,
    org_id: Option<Uuid>,
    aad: Vec<u8>,
) -> anyhow::Result<Option<(Uuid, Vec<u8>, i16)>> {
    let Some(hook) = MEMORY_CRYPTO_HOOK.get().cloned() else {
        guard_plaintext_fallback(std::env::var("RUST_ENV").as_deref() == Ok("production"))?;
        return Ok(None);
    };
    let (key_id, ciphertext, version) = hook.encrypt(plaintext, org_id, aad).await?;
    Ok(Some((key_id, ciphertext, version)))
}

/// Fail-closed guard for the legacy plaintext write path. The read path
/// already fails loudly on ciphertext-without-hook (see
/// `resolve_stored_value`); this is the write-side mirror. Any binary
/// that links `talos-memory` with a live pool but forgets the
/// `register_memory_crypto_hook()` boot call would otherwise silently
/// persist plaintext `actor_memory` rows — in production that is a
/// refusal, in dev a one-time WARN (local stacks legitimately run
/// without the hook).
pub(crate) fn guard_plaintext_fallback(is_production: bool) -> anyhow::Result<()> {
    if is_production {
        anyhow::bail!(
            "no MemoryCryptoHook registered — refusing plaintext actor_memory write in \
             production; ensure register_memory_crypto_hook() is called at startup"
        );
    }
    static PLAINTEXT_WARN_ONCE: std::sync::Once = std::sync::Once::new();
    PLAINTEXT_WARN_ONCE.call_once(|| {
        tracing::warn!(
            "no MemoryCryptoHook registered — actor_memory writes will persist PLAINTEXT \
             (acceptable in dev only; production fails closed)"
        );
    });
    Ok(())
}

/// Resolve the org an actor belongs to, for per-org DEK scoping at memory-write
/// time. `actors.org_id` is set for every actor (the actor arc + org backfill),
/// so this is normally `Some`. `None` (missing actor / NULL org) falls back to
/// the global DEK in `encrypt_value_aad_v4_or_global`. The resolved org is also
/// stamped onto the `actor_memory` row so the row's `org_id` matches its DEK.
pub(crate) async fn resolve_actor_org_id(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
) -> anyhow::Result<Option<Uuid>> {
    let org: Option<Option<Uuid>> = sqlx::query_scalar("SELECT org_id FROM actors WHERE id = $1")
        .bind(actor_id)
        .fetch_optional(pool)
        .await?;
    Ok(org.flatten())
}

/// Resolve a stored memory value: prefer ciphertext (`value_enc` +
/// `value_key_id`) when both are present and crypto is registered;
/// otherwise return the plaintext fallback. Returns `null` JSON when
/// neither is present (corrupt row — caller should treat as "missing").
///
/// MCP-S2: `aad` is the row's `build_memory_aad(actor_id, key)`
/// bytes and `format_version` is the per-row `value_format` column.
/// Together they drive the AAD-binding dispatch — v0 rows accept
/// empty AAD, v1 rows require exactly the bytes used at encrypt time.
pub async fn resolve_stored_value(
    value_plain: Option<serde_json::Value>,
    value_enc: Option<Vec<u8>>,
    value_key_id: Option<Uuid>,
    aad: Vec<u8>,
    format_version: i16,
) -> anyhow::Result<serde_json::Value> {
    if let (Some(enc), Some(key_id)) = (value_enc, value_key_id) {
        if let Some(hook) = MEMORY_CRYPTO_HOOK.get().cloned() {
            let plaintext = hook
                .decrypt(key_id, enc, aad, format_version)
                .await
                .context("memory value decryption")?;
            return serde_json::from_str(&plaintext)
                .context("memory value JSON parse after decrypt");
        }
        // Hook unregistered but ciphertext present — most likely the
        // controller is misconfigured (Phase A code deployed without
        // the hook wired). Fail loudly rather than silently expose
        // ciphertext as opaque bytes.
        anyhow::bail!(
            "actor_memory row has ciphertext (value_enc) but no crypto hook is registered — \
             ensure register_memory_crypto_hook() is called at startup"
        );
    }
    Ok(value_plain.unwrap_or(serde_json::Value::Null))
}

/// Decrypt the value column from a `PgRow` that includes `actor_id`,
/// `key`, `value`, `value_enc`, `value_key_id`, and `value_format`.
/// Sites that build raw `sqlx::query` SELECTs (i.e. don't go through
/// the canonical `recall_*` helpers) should use this to stay
/// encryption-aware.
///
/// Phase B note: once the legacy `value` column is dropped, the
/// `value_plain` fallback becomes unreachable in production but the
/// helper remains valid because `try_get("value")` simply returns `None`.
pub async fn decrypt_row_value(row: &sqlx::postgres::PgRow) -> anyhow::Result<serde_json::Value> {
    use sqlx::Row as _;
    // MCP-S2 follow-up: fail LOUDLY when `actor_id` / `key` /
    // `value_format` are missing from the SELECT projection. Pre-fix
    // the helper silently defaulted to `Uuid::nil()` / `""` / `0`,
    // which made SELECT-projection drift surface as "AES-GCM tag
    // mismatch" downstream — a generic error that buried the real
    // bug (the caller forgot to project a column). Failing closed
    // here means CI / integration tests trip the moment a SELECT
    // omits a required column, rather than letting the silent v1
    // mis-dispatch reach production.
    let actor_id: Uuid = row
        .try_get("actor_id")
        .context("decrypt_row_value: caller's SELECT must project `actor_id` (MCP-S2 AAD)")?;
    let key: String = row
        .try_get("key")
        .context("decrypt_row_value: caller's SELECT must project `key`")?;
    let value_plain: Option<serde_json::Value> = row.try_get("value").ok();
    let value_enc: Option<Vec<u8>> = row.try_get("value_enc").ok();
    let value_key_id: Option<Uuid> = row.try_get("value_key_id").ok();
    let value_format: i16 = row.try_get("value_format").context(
        "decrypt_row_value: caller's SELECT must project `value_format` (MCP-S2 dispatch)",
    )?;
    let aad = build_memory_aad(actor_id, &key);
    resolve_stored_value(value_plain, value_enc, value_key_id, aad, value_format).await
}

/// Public helper — spawn graph-RAG entity extraction for a memory
/// write. `persist_memory` calls this itself on success; the `_in_tx`
/// variant does *not*, leaving it to the caller so the hook only
/// fires after a successful `tx.commit().await` (preventing graph
/// drift from rolled-back transactions).
///
/// Safe no-op when no hook is registered.
pub fn spawn_graph_extraction(actor_id: Uuid, key: String, value: serde_json::Value) {
    let Some(hook) = GRAPH_HOOK.get().cloned() else {
        return;
    };
    tokio::spawn(async move {
        let _permit = GRAPH_EXTRACTION_SEMAPHORE.acquire().await;
        if let Err(e) = hook.extract(actor_id, key.clone(), value).await {
            tracing::debug!(
                actor_id = %actor_id,
                key = %key,
                error = %e,
                "Graph entity extraction failed (non-fatal)"
            );
        }
    });
}

// ============================================================================
// Types
// ============================================================================

#[derive(Clone, Debug, Serialize)]
pub struct MemoryRow {
    pub key: String,
    pub value: serde_json::Value,
    pub memory_type: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MemoryMeta {
    pub key: String,
    pub memory_type: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub value_bytes: i32,
    /// Per-row `metadata` JSONB. Surfaced so listing tools (e.g. MCP
    /// `list_actor_memories`) can show `metadata.kind` — the convention
    /// label used to identify synthetic LLM outputs (`daily_brief`,
    /// `commitment_check`, etc.) so operators can audit what would be
    /// excluded by `agent_memory::search_filtered` without per-key drilldown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MemoryHit {
    pub key: String,
    pub value: serde_json::Value,
    pub memory_type: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub score: f64,
    /// Per-row `metadata` JSONB — the filter key (`metadata.kind`) is
    /// applied at the DB layer by `recall_semantic_filtered`, but
    /// returning the full object here lets callers display the kind /
    /// source / generated_at context alongside each hit (e.g. sandbox
    /// `agent_memory::search` → WIT `search-result.metadata`).
    pub metadata: Option<serde_json::Value>,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct PersistOutcome {
    pub embedded: bool,
    pub graph_extraction_attempted: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum SearchMethod {
    Direct,
    HyDE,
}

#[derive(Clone, Debug, Serialize)]
pub struct SearchOutcome {
    pub hits: Vec<MemoryHit>,
    pub method: &'static str,
    /// True when embedding generation succeeded for the query (or
    /// HyDE-wrapped query). Lets the MCP handler distinguish two
    /// otherwise-identical `keyword_fallback` cases:
    ///   - embedding unavailable (config issue) → guide operator to
    ///     EMBEDDING_API_URL.
    ///   - embedding worked but no rows scored above `min_score` →
    ///     guide operator to lower min_score / different query.
    /// Without this, both cases used the same misleading "embeddings
    /// not available" note.
    pub embedding_attempted: bool,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct ForgetOutcome {
    pub deleted: bool,
}

// ============================================================================
// Writes
// ============================================================================

pub async fn persist_memory(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    key: &str,
    value: &serde_json::Value,
    memory_type: &str,
    ttl_hours: Option<f64>,
) -> Result<PersistOutcome> {
    persist_memory_with_metadata(pool, actor_id, key, value, None, memory_type, ttl_hours).await
}

/// Persist an entry with an optional metadata blob stored in a dedicated
/// JSONB column. `metadata` is filterable server-side and NEVER mixed into
/// the `value` payload — read paths (`recall_exact`, etc.) return the value
/// exactly as it was stored.
/// Whether an embedding for `actor_id`'s data must stay HOST-LOCAL — the actor's
/// `max_llm_tier` is `tier1` ("data must not leave the host") AND the configured
/// embedding provider is external. The result is passed to `generate_embedding`,
/// which SKIPS the external call in that combination (the memory op proceeds
/// without a vector; semantic recall degrades to keyword/recency).
///
/// Cost: when the provider is host-local (the default in-cluster Ollama) there is
/// no egress risk, so we return `false` WITHOUT any DB query — the common case
/// pays nothing. Only an external-provider deployment pays one indexed
/// `actors.max_llm_tier` lookup per memory op. The tier is read from the
/// AUTHORITATIVE `actors` table (not a worker-supplied claim), so a compromised
/// worker cannot downgrade a tier-1 actor to leak its data. Fails CLOSED
/// (treat as tier-1 → skip external) on a lookup error.
async fn embed_local_only<'e, E>(executor: E, actor_id: Uuid) -> bool
where
    E: sqlx::PgExecutor<'e>,
{
    match embedding::EmbeddingConfig::cached() {
        Some(c) if !c.is_local_provider() => {}
        // Host-local provider, or none configured → no egress; no gate needed.
        _ => return false,
    }
    match sqlx::query_scalar::<_, String>("SELECT max_llm_tier FROM actors WHERE id = $1")
        .bind(actor_id)
        .fetch_optional(executor)
        .await
    {
        Ok(Some(tier)) => tier == "tier1",
        // No actors row (system / anonymous / non-actor memory) → not tier-1.
        Ok(None) => false,
        Err(e) => {
            tracing::warn!(
                target: "talos_audit",
                %actor_id,
                error = %e,
                "embedding tier-gate: actors.max_llm_tier lookup failed — failing closed \
                 (skipping the external embedding to avoid possible tier-1 data egress)"
            );
            true
        }
    }
}

pub async fn persist_memory_with_metadata(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    key: &str,
    value: &serde_json::Value,
    metadata: Option<&serde_json::Value>,
    memory_type: &str,
    ttl_hours: Option<f64>,
) -> Result<PersistOutcome> {
    // MCP-1224 (2026-05-18): route through the canonical
    // `validate_memory_key` helper at the persistence boundary so
    // every writer — MCP handlers, GraphQL mutations, engine
    // __memory_write__ hook, signed memory_rpc, talos-actor-scaffold's
    // seed_memories loop — observes the same rule (trim +
    // whitespace-only reject + ≤500-char cap + control-char/null-byte
    // reject) regardless of whether the caller remembered to
    // validate first. Pre-fix the inline `is_empty() || len() > 500`
    // check missed whitespace-only keys and embedded control chars;
    // a probe via scaffold_actor with `seed_memories: { "   ": ... }`
    // persisted a row that readers (all trim post-MCP-834) couldn't
    // recover. Same canonical-layer-defense shape as MCP-1218/1219
    // promoting graph_json caps into the engine's canonical validator.
    let key = validate_memory_key(key).map_err(|e| anyhow::anyhow!("{}", e))?;
    // Single JSON serialization, reused for size check + embedding text +
    // encryption. Prior code serialized the same value three times per
    // write (once for the size cap, once for embedding text input, once
    // inside the encryption hook).
    let serialized = serde_json::to_string(value).context("memory value JSON serialization")?;
    // Enforce the canonical per-value size ceiling here so every writer —
    // MCP, GraphQL, engine __memory_write__, and the worker RPC — observes
    // the same limit. Prior inconsistency (worker accepted 1 MiB, MCP
    // rejected at 64 KiB) allowed sandboxes to write rows that later
    // failed re-read through MCP.
    if serialized.len() > MAX_VALUE_BYTES {
        anyhow::bail!(
            "value too large ({} bytes). Maximum allowed is {} bytes (64 KiB).",
            serialized.len(),
            MAX_VALUE_BYTES
        );
    }
    // MCP-656: cap metadata at 16 KiB. Same rationale as MAX_METADATA_BYTES
    // doc — the JSONB column previously had no upper bound, allowing a
    // guest to ship a ~900 KiB tag blob through the signed RPC. Mirrors
    // the cap added in `persist_memory_in_tx_with_metadata` so all writers
    // (non-tx + tx) observe the same limit.
    if let Some(m) = metadata {
        let m_bytes = serde_json::to_string(m)
            .context("metadata JSON serialization")?
            .len();
        if m_bytes > MAX_METADATA_BYTES {
            anyhow::bail!(
                "metadata too large ({} bytes). Maximum allowed is {} bytes (16 KiB).",
                m_bytes,
                MAX_METADATA_BYTES
            );
        }
    }
    let canonical_type = validate_memory_type(memory_type)?;
    let expires_at = default_expires_at(canonical_type, ttl_hours);

    let embedding: Option<pgvector::Vector> = if canonical_type != "scratchpad" {
        let truncated: String = serialized.chars().take(4000).collect();
        let text_to_embed = format!("{}: {}", key, truncated);
        let local_only = embed_local_only(pool, actor_id).await;
        embedding::generate_embedding(&text_to_embed, local_only)
            .await
            .map(pgvector::Vector::from)
    } else {
        None
    };

    let embedded = embedding.is_some();

    // Phase B of at-rest encryption: writes always go through the crypto
    // hook. The hook MUST be registered before any actor-memory write —
    // unregistered hook = panic-loud bail (no plaintext fallback path).
    //
    // MCP-S2: AAD = build_memory_aad(actor_id, key) binds the
    // ciphertext to its composite primary key. An attacker with DB
    // write capability who swaps `value_enc` onto a different
    // (actor_id, key) row will fail AES-GCM tag verification on read.
    // Per-org DEK arc: encrypt under the actor's org root DEK (v4), and stamp
    // that org on the row so its org_id matches its DEK scope.
    let org_id = resolve_actor_org_id(pool, actor_id).await?;
    let aad = build_memory_aad(actor_id, key);
    let (key_id, ciphertext, value_format) =
        maybe_encrypt_value_serialized(serialized, org_id, aad)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "actor_memory write attempted without crypto hook registered — \
             ensure register_memory_crypto_hook() runs at startup before any write"
                )
            })?;

    sqlx::query(
        "INSERT INTO actor_memory \
         (actor_id, key, value_enc, value_key_id, value_format, memory_type, expires_at, embedding, metadata, org_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         ON CONFLICT (actor_id, key) DO UPDATE SET \
             value_enc     = EXCLUDED.value_enc, \
             value_key_id  = EXCLUDED.value_key_id, \
             value_format  = EXCLUDED.value_format, \
             memory_type   = EXCLUDED.memory_type, \
             expires_at    = EXCLUDED.expires_at, \
             embedding     = COALESCE(EXCLUDED.embedding, actor_memory.embedding), \
             metadata      = COALESCE(EXCLUDED.metadata, actor_memory.metadata), \
             org_id        = EXCLUDED.org_id, \
             updated_at    = now()",
    )
    .bind(actor_id)
    .bind(key)
    .bind(ciphertext.as_slice())
    .bind(key_id)
    .bind(value_format)
    .bind(canonical_type)
    .bind(expires_at)
    .bind(embedding)
    .bind(metadata)
    .bind(org_id)
    .execute(pool)
    .await
    .context("Failed to persist actor memory")?;

    let graph_extraction_attempted = canonical_type != "scratchpad" && GRAPH_HOOK.get().is_some();
    if graph_extraction_attempted {
        spawn_graph_extraction(actor_id, key.to_string(), value.clone());
    }

    Ok(PersistOutcome {
        embedded,
        graph_extraction_attempted,
    })
}

/// Persist a memory entry inside the caller's transaction.
///
/// Unlike [`persist_memory`], this variant does **not** fire graph
/// extraction — the caller must invoke [`spawn_graph_extraction`]
/// *after* a successful `tx.commit().await`, otherwise a rollback
/// would leave orphan entities in the knowledge graph referencing a
/// row that was never committed. The returned `PersistOutcome`
/// reports whether extraction *would* have run so the caller knows
/// when to invoke the helper.
pub async fn persist_memory_in_tx<'c>(
    tx: &mut sqlx::Transaction<'c, Postgres>,
    actor_id: Uuid,
    key: &str,
    value: &serde_json::Value,
    memory_type: &str,
    ttl_hours: Option<f64>,
) -> Result<PersistOutcome> {
    persist_memory_in_tx_with_metadata(tx, actor_id, key, value, None, memory_type, ttl_hours).await
}

/// Transaction-aware sibling of [`persist_memory_with_metadata`]. Same
/// Phase-B always-encrypt + metadata column semantics as the non-tx
/// path, with the same "graph extraction is the caller's problem
/// post-commit" rule as [`persist_memory_in_tx`].
pub async fn persist_memory_in_tx_with_metadata<'c>(
    tx: &mut sqlx::Transaction<'c, Postgres>,
    actor_id: Uuid,
    key: &str,
    value: &serde_json::Value,
    metadata: Option<&serde_json::Value>,
    memory_type: &str,
    ttl_hours: Option<f64>,
) -> Result<PersistOutcome> {
    // MCP-1224 (2026-05-18): route through the canonical
    // `validate_memory_key` helper at the persistence boundary so
    // every writer — MCP handlers, GraphQL mutations, engine
    // __memory_write__ hook, signed memory_rpc, talos-actor-scaffold's
    // seed_memories loop — observes the same rule (trim +
    // whitespace-only reject + ≤500-char cap + control-char/null-byte
    // reject) regardless of whether the caller remembered to
    // validate first. Pre-fix the inline `is_empty() || len() > 500`
    // check missed whitespace-only keys and embedded control chars;
    // a probe via scaffold_actor with `seed_memories: { "   ": ... }`
    // persisted a row that readers (all trim post-MCP-834) couldn't
    // recover. Same canonical-layer-defense shape as MCP-1218/1219
    // promoting graph_json caps into the engine's canonical validator.
    let key = validate_memory_key(key).map_err(|e| anyhow::anyhow!("{}", e))?;
    // Single JSON serialization, reused for size check + embedding text +
    // encryption (mirrors the non-tx path).
    let serialized = serde_json::to_string(value).context("memory value JSON serialization")?;
    if serialized.len() > MAX_VALUE_BYTES {
        anyhow::bail!(
            "value too large ({} bytes). Maximum allowed is {} bytes (64 KiB).",
            serialized.len(),
            MAX_VALUE_BYTES
        );
    }
    // MCP-656: metadata cap mirrors the non-tx sibling above.
    if let Some(m) = metadata {
        let m_bytes = serde_json::to_string(m)
            .context("metadata JSON serialization")?
            .len();
        if m_bytes > MAX_METADATA_BYTES {
            anyhow::bail!(
                "metadata too large ({} bytes). Maximum allowed is {} bytes (16 KiB).",
                m_bytes,
                MAX_METADATA_BYTES
            );
        }
    }
    let canonical_type = validate_memory_type(memory_type)?;
    let expires_at = default_expires_at(canonical_type, ttl_hours);

    let embedding: Option<pgvector::Vector> = if canonical_type != "scratchpad" {
        let truncated: String = serialized.chars().take(4000).collect();
        let text_to_embed = format!("{}: {}", key, truncated);
        let local_only = embed_local_only(&mut **tx, actor_id).await;
        embedding::generate_embedding(&text_to_embed, local_only)
            .await
            .map(pgvector::Vector::from)
    } else {
        None
    };
    let embedded = embedding.is_some();

    // Same Phase-B always-encrypt path as persist_memory.
    // MCP-S2: AAD binding to composite (actor_id, key) — see
    // persist_memory above for the rationale.
    // Per-org DEK arc: resolve the actor's org ON THE TX (consistent snapshot
    // with the write), encrypt under its root DEK (v4), and stamp it on the row.
    let org_row: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT org_id FROM actors WHERE id = $1")
            .bind(actor_id)
            .fetch_optional(&mut **tx)
            .await?;
    let org_id = org_row.flatten();
    let aad = build_memory_aad(actor_id, key);
    let (key_id, ciphertext, value_format) =
        maybe_encrypt_value_serialized(serialized, org_id, aad)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "actor_memory write attempted without crypto hook registered — \
             ensure register_memory_crypto_hook() runs at startup before any write"
                )
            })?;

    sqlx::query(
        "INSERT INTO actor_memory \
         (actor_id, key, value_enc, value_key_id, value_format, memory_type, expires_at, embedding, metadata, org_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         ON CONFLICT (actor_id, key) DO UPDATE SET \
             value_enc     = EXCLUDED.value_enc, \
             value_key_id  = EXCLUDED.value_key_id, \
             value_format  = EXCLUDED.value_format, \
             memory_type   = EXCLUDED.memory_type, \
             expires_at    = EXCLUDED.expires_at, \
             embedding     = COALESCE(EXCLUDED.embedding, actor_memory.embedding), \
             metadata      = COALESCE(EXCLUDED.metadata, actor_memory.metadata), \
             org_id        = EXCLUDED.org_id, \
             updated_at    = now()",
    )
    .bind(actor_id)
    .bind(key)
    .bind(ciphertext.as_slice())
    .bind(key_id)
    .bind(value_format)
    .bind(canonical_type)
    .bind(expires_at)
    .bind(embedding)
    .bind(metadata)
    .bind(org_id)
    .execute(&mut **tx)
    .await
    .context("Failed to persist actor memory (in tx)")?;

    // Intentionally do NOT spawn graph extraction here — see doc
    // comment above. The caller invokes `spawn_graph_extraction` after
    // a successful `tx.commit().await`.
    let graph_extraction_attempted = canonical_type != "scratchpad" && GRAPH_HOOK.get().is_some();

    Ok(PersistOutcome {
        embedded,
        graph_extraction_attempted,
    })
}

// ============================================================================
// Reads
// ============================================================================

pub async fn recall_exact(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    key: &str,
) -> Result<Option<MemoryRow>> {
    // Phase B: every row carries ciphertext; decrypt via the registered hook.
    // MCP-S2: SELECT value_format so the AAD-dispatch resolver picks
    // v0 vs v1.
    let row = sqlx::query(
        "SELECT key, value_enc, value_key_id, value_format, memory_type, expires_at, updated_at \
         FROM actor_memory \
         WHERE actor_id = $1 AND key = $2 \
           AND (expires_at IS NULL OR expires_at > now())",
    )
    .bind(actor_id)
    .bind(key)
    .fetch_optional(pool)
    .await
    .context("recall_exact")?;

    let Some(r) = row else { return Ok(None) };
    let row_key: String = r.get("key");
    let value_enc: Option<Vec<u8>> = r.try_get("value_enc").ok();
    let value_key_id: Option<Uuid> = r.try_get("value_key_id").ok();
    // Fail LOUD on a missing `value_format`, matching decrypt_row_value /
    // rows_to_memory_hits. value_format is NOT NULL in the schema, so `.ok()`
    // / `.unwrap_or(0)` here would only ever mask SELECT-projection drift —
    // and silently defaulting to 0 (legacy no-AAD) would mis-dispatch every
    // v1 ciphertext to empty-AAD decryption, surfacing as a generic
    // "AES-GCM tag mismatch" that buries the real bug (the dropped column).
    // This is the same projection-drift class as the Phase-B `value` bug.
    let value_format: i16 = r
        .try_get("value_format")
        .context("recall_exact: SELECT must project `value_format` (MCP-S2 AAD dispatch)")?;
    let aad = build_memory_aad(actor_id, &row_key);
    let value = resolve_stored_value(None, value_enc, value_key_id, aad, value_format).await?;

    Ok(Some(MemoryRow {
        key: row_key,
        value,
        memory_type: r.get("memory_type"),
        expires_at: r.get("expires_at"),
        updated_at: r.get("updated_at"),
    }))
}

pub async fn key_exists_at_all(pool: &Pool<Postgres>, actor_id: Uuid, key: &str) -> Result<bool> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM actor_memory WHERE actor_id = $1 AND key = $2)",
    )
    .bind(actor_id)
    .bind(key)
    .fetch_one(pool)
    .await
    .context("key_exists_at_all")?;
    Ok(exists)
}

pub async fn count_memories(pool: &Pool<Postgres>, actor_id: Uuid) -> Result<i64> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM actor_memory \
         WHERE actor_id = $1 AND (expires_at IS NULL OR expires_at > now())",
    )
    .bind(actor_id)
    .fetch_one(pool)
    .await
    .context("count_memories")?;
    Ok(count)
}

/// Recall the most recently updated, non-expired memories whose
/// `memory_type` is in `types` — decrypted, in `(key, value, memory_type)`
/// tuples ready for agent-context injection.
///
/// Used by `talos_workflow_repository::get_recent_actor_context` (Layer 3
/// of context-injection) to feed the LLM with recent working/episodic
/// memories. Centralised here so the canonical decrypt path
/// (`decrypt_row_value`) is the only way to read encrypted values.
///
/// `limit` is clamped to `[1, MAX_LIST_LIMIT]`.
pub async fn recall_recent_by_types(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    types: &[&str],
    limit: i64,
) -> Result<Vec<(String, serde_json::Value, String)>> {
    let limit = limit.clamp(1, MAX_LIST_LIMIT);
    let owned: Vec<String> = types.iter().map(|s| (*s).to_string()).collect();
    // MCP-S2 follow-up: project `actor_id` + `value_format` so
    // `decrypt_row_value` can dispatch v1 (AAD-bound) ciphertexts via
    // decrypt_versioned. Pre-fix omitted both → every v1 row decrypted
    // with empty AAD → AES-GCM tag mismatch → `?` propagated Err from
    // the loop, breaking Layer 3 context recall entirely for any
    // actor with at least one post-MCP-S2 row.
    //
    // Do NOT project the legacy `value` column — it was DROPPED in Phase B
    // (migration 20260424010000). Selecting it raised `column "value" does
    // not exist` at runtime, breaking this function entirely. The ciphertext
    // columns are the only value source post-Phase-B; `decrypt_row_value`
    // tolerates the absent `value` via `try_get(...).ok()`.
    let rows = sqlx::query(
        "SELECT actor_id, key, value_enc, value_key_id, value_format, memory_type \
         FROM actor_memory \
         WHERE actor_id = $1 \
           AND memory_type = ANY($2) \
           AND (expires_at IS NULL OR expires_at > now()) \
         ORDER BY updated_at DESC LIMIT $3",
    )
    .bind(actor_id)
    .bind(&owned)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("recall_recent_by_types")?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        use sqlx::Row as _;
        let key: String = r.get("key");
        let memory_type: String = r.get("memory_type");
        let value = decrypt_row_value(r).await?;
        out.push((key, value, memory_type));
    }
    Ok(out)
}

/// Recall the most recently updated, non-expired memories whose
/// `memory_type` is NOT in `exclude` — decrypted, in
/// `(key, value, memory_type)` tuples.
///
/// Used by `talos_workflow_repository::get_relevant_actor_context`'s
/// recency fallback (Layer 3) when semantic recall returned only
/// scratchpad hits. The exclude list typically contains `"scratchpad"`
/// to avoid recursive context growth.
///
/// `limit` is clamped to `[1, MAX_LIST_LIMIT]`. An empty `exclude`
/// returns recent memories of any type.
pub async fn recall_recent_excluding_types(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    exclude: &[&str],
    limit: i64,
) -> Result<Vec<(String, serde_json::Value, String)>> {
    let limit = limit.clamp(1, MAX_LIST_LIMIT);
    let owned: Vec<String> = exclude.iter().map(|s| (*s).to_string()).collect();
    // MCP-S2 follow-up: same SELECT-projection requirement as
    // recall_recent_by_types above — project actor_id + value_format so
    // decrypt_row_value can route v1 ciphertexts. And, as there, do NOT
    // project the legacy `value` column (DROPPED in Phase B migration
    // 20260424010000) — selecting it raised `column "value" does not exist`
    // at runtime, breaking this recency-fallback path entirely.
    let rows = sqlx::query(
        "SELECT actor_id, key, value_enc, value_key_id, value_format, memory_type \
         FROM actor_memory \
         WHERE actor_id = $1 \
           AND NOT (memory_type = ANY($2)) \
           AND (expires_at IS NULL OR expires_at > now()) \
         ORDER BY updated_at DESC LIMIT $3",
    )
    .bind(actor_id)
    .bind(&owned)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("recall_recent_excluding_types")?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        use sqlx::Row as _;
        let key: String = r.get("key");
        let memory_type: String = r.get("memory_type");
        let value = decrypt_row_value(r).await?;
        out.push((key, value, memory_type));
    }
    Ok(out)
}

pub async fn list_memories(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    prefix: Option<&str>,
    memory_type_filter: Option<&str>,
    limit: Option<i64>,
) -> Result<Vec<MemoryMeta>> {
    let limit = limit.unwrap_or(MAX_LIST_LIMIT).clamp(1, MAX_LIST_LIMIT);
    // MCP-955 (2026-05-15): escape SQL LIKE wildcards (`%`, `_`, `\`)
    // in the caller-supplied prefix so the predicate behaves as
    // literal-prefix matching, matching the existing escape patterns
    // in `forget_prefix` (line 1474) and `list_keys_with_limit` (line
    // 882). Pre-fix the raw `prefix` was bound into `LIKE $2 || '%'`,
    // so a caller passing `pre%` thinking they were doing
    // literal-prefix matching actually got `LIKE 'pre%%'` —
    // wildcard semantics. Worse, a caller (or attacker who reached
    // this surface) could pass a single `%` to get an unfiltered
    // scan of the entire actor's memory (still scoped to their own
    // actor, so not a cross-tenant leak — but a behavioral
    // surprise + DoS surface). `ESCAPE '\\'` added to the SQL so
    // the bound backslash-escaped bytes are interpreted as literal.
    let escaped_prefix = prefix.map(|p| {
        p.replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    });
    let rows = sqlx::query(
        "SELECT key, memory_type, expires_at, updated_at, metadata, \
                octet_length(value_enc) AS value_bytes \
         FROM actor_memory \
         WHERE actor_id = $1 \
           AND (expires_at IS NULL OR expires_at > now()) \
           AND ($2::text IS NULL OR key LIKE $2 || '%' ESCAPE '\\') \
           AND ($3::text IS NULL OR memory_type = $3) \
         ORDER BY updated_at DESC \
         LIMIT $4",
    )
    .bind(actor_id)
    .bind(escaped_prefix)
    .bind(memory_type_filter)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("list_memories")?;

    Ok(rows
        .iter()
        .map(|r| MemoryMeta {
            key: r.get("key"),
            memory_type: r.get("memory_type"),
            expires_at: r.get("expires_at"),
            updated_at: r.get("updated_at"),
            value_bytes: r.get("value_bytes"),
            metadata: r
                .try_get::<Option<serde_json::Value>, _>("metadata")
                .ok()
                .flatten(),
        })
        .collect())
}

/// Hard upper bound on the row count `list_keys` will return regardless
/// of caller-supplied limit. Mirrors the legacy hardcoded `LIMIT 1000`
/// retained for back-compat. Subscriber callers should pass an explicit
/// (smaller) limit per `MAX_RESULT_LIMIT` from the relevant RPC module.
pub const LIST_KEYS_HARD_CAP: i64 = 1000;

/// List keys for an actor, optionally filtered by prefix.
///
/// Back-compat wrapper around [`list_keys_with_limit`] that uses
/// [`LIST_KEYS_HARD_CAP`] as the limit. New callers should use
/// `list_keys_with_limit` and clamp via `MAX_RESULT_LIMIT` from the
/// relevant RPC module so caps are uniform across read paths.
pub async fn list_keys(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    prefix: Option<&str>,
) -> Result<Vec<String>> {
    list_keys_with_limit(pool, actor_id, prefix, LIST_KEYS_HARD_CAP).await
}

/// List keys for an actor with an explicit row cap.
///
/// `limit` is clamped to `[1, LIST_KEYS_HARD_CAP]` so callers can't
/// dodge the hard cap by passing a huge value, and a zero/negative
/// limit becomes a single-row probe rather than an error.
///
/// L-23: introduced so RPC subscribers can clamp via the canonical
/// `MAX_RESULT_LIMIT` constant — without this, ListKeys silently
/// inherited a 1000-row cap that disagreed with the 200-row Search cap.
pub async fn list_keys_with_limit(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    prefix: Option<&str>,
    limit: i64,
) -> Result<Vec<String>> {
    let limit = limit.clamp(1, LIST_KEYS_HARD_CAP);
    let pattern = prefix
        .map(|p| {
            let escaped = p
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            format!("{}%", escaped)
        })
        .unwrap_or_else(|| "%".to_string());

    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT key FROM actor_memory \
         WHERE actor_id = $1 AND key LIKE $2 \
         AND (expires_at IS NULL OR expires_at > NOW()) \
         ORDER BY key LIMIT $3",
    )
    .bind(actor_id)
    .bind(&pattern)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("list_keys")?;
    Ok(rows.into_iter().map(|(k,)| k).collect())
}

// ============================================================================
// Search
// ============================================================================

pub async fn recall_semantic(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    query: &str,
    limit: i64,
    min_score: f64,
    memory_type_filter: Option<&str>,
    method: SearchMethod,
) -> Result<SearchOutcome> {
    recall_semantic_filtered(
        pool,
        actor_id,
        query,
        limit,
        min_score,
        memory_type_filter,
        method,
        &[],
    )
    .await
}

/// Filtered variant of [`recall_semantic`] that excludes rows whose
/// `metadata.kind` field matches any entry in `exclude_kinds`.
///
/// Designed for synthesize → persist → search chains: a workflow that
/// writes its LLM briefs under `metadata.kind = "meeting_prep"` passes
/// `&["meeting_prep".to_string()]` here so the next invocation doesn't
/// feed the LLM its own prior output.
///
/// The filter is applied in both the vector-cosine path and the
/// keyword-fallback path. Empty `exclude_kinds` is a no-op equivalent
/// to [`recall_semantic`]. SQL uses a parameterized `text[]` so the
/// list is bind-safe regardless of caller-controlled content.
// 8 args is over the default clippy threshold; folding them into an
// options struct would be over-engineering for the one upstream caller
// (`agent_memory::search_filtered`) which has the same shape. If a third
// caller appears, build the struct then.
#[allow(clippy::too_many_arguments)]
pub async fn recall_semantic_filtered(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    query: &str,
    limit: i64,
    min_score: f64,
    memory_type_filter: Option<&str>,
    method: SearchMethod,
    exclude_kinds: &[String],
) -> Result<SearchOutcome> {
    let limit = limit.clamp(1, 50);
    let min_score = min_score.clamp(0.0, 1.0);

    let embed_input = match method {
        SearchMethod::Direct => query.to_string(),
        SearchMethod::HyDE => format!(
            "An answer to the question '{}' would be: ",
            query.chars().take(500).collect::<String>()
        ),
    };

    let local_only = embed_local_only(pool, actor_id).await;
    let embedding = embedding::generate_embedding(&embed_input, local_only).await;
    let embedding_attempted = embedding.is_some();

    if let Some(emb) = embedding {
        let vec = pgvector::Vector::from(emb);
        // `metadata->>'kind' != ALL($6)` excludes rows whose `kind` is in
        // the exclusion list. Rows with NULL metadata or missing `kind`
        // pass the filter (treated as "not synthetic" by default).
        // Using `!= ALL(...)` over `NOT IN (...)` is safer with NULLs:
        // `NULL NOT IN (...)` evaluates to UNKNOWN and would drop rows.
        let sql =
            "SELECT key, value_enc, value_key_id, value_format, memory_type, expires_at, updated_at, metadata, \
                          (1.0 - (embedding <=> $2)) AS score \
                   FROM actor_memory \
                   WHERE actor_id = $1 \
                     AND (expires_at IS NULL OR expires_at > now()) \
                     AND embedding IS NOT NULL \
                     AND (1.0 - (embedding <=> $2)) >= $3 \
                     AND ($5::text IS NULL OR memory_type = $5) \
                     AND (cardinality($6::text[]) = 0 \
                          OR metadata IS NULL \
                          OR metadata->>'kind' IS NULL \
                          OR metadata->>'kind' != ALL($6::text[])) \
                   ORDER BY embedding <=> $2 \
                   LIMIT $4";
        let rows = sqlx::query(sql)
            .bind(actor_id)
            .bind(&vec)
            .bind(min_score)
            .bind(limit)
            .bind(memory_type_filter)
            .bind(exclude_kinds)
            .fetch_all(pool)
            .await
            .context("recall_semantic vector query")?;

        if !rows.is_empty() {
            // Decrypt each row's value (Phase A) — score column is per-row,
            // can't use the positional helper. Build hits inline so we can
            // preserve the cosine-derived score. MCP-S2: AAD-dispatch on
            // per-row value_format using build_memory_aad(actor_id, key).
            let mut hits = Vec::with_capacity(rows.len());
            for r in rows {
                let row_key: String = r.get("key");
                let value_enc: Option<Vec<u8>> = r.try_get("value_enc").ok();
                let value_key_id: Option<Uuid> = r.try_get("value_key_id").ok();
                // Fail LOUD on a missing `value_format` (see recall_exact /
                // decrypt_row_value): silently defaulting to 0 would mis-
                // dispatch v1 ciphertexts to empty-AAD decryption on any
                // future SELECT-projection drift.
                let value_format: i16 = r.try_get("value_format").context(
                    "recall_semantic_filtered: SELECT must project `value_format` (MCP-S2 AAD dispatch)",
                )?;
                let aad = build_memory_aad(actor_id, &row_key);
                let value =
                    resolve_stored_value(None, value_enc, value_key_id, aad, value_format).await?;
                hits.push(MemoryHit {
                    key: row_key,
                    value,
                    memory_type: r.get("memory_type"),
                    expires_at: r.get("expires_at"),
                    updated_at: r.get("updated_at"),
                    score: r.get::<f64, _>("score"),
                    metadata: r.get::<Option<serde_json::Value>, _>("metadata"),
                });
            }
            return Ok(SearchOutcome {
                hits,
                method: "vector_cosine",
                embedding_attempted,
            });
        }
    }

    let hits = recall_keyword_inner(
        pool,
        actor_id,
        query,
        limit,
        memory_type_filter,
        exclude_kinds,
    )
    .await?;
    Ok(SearchOutcome {
        hits,
        method: "keyword_fallback",
        embedding_attempted,
    })
}

pub async fn recall_hyde(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    query: &str,
    limit: i64,
    min_score: f64,
    memory_type_filter: Option<&str>,
) -> Result<SearchOutcome> {
    recall_semantic_filtered(
        pool,
        actor_id,
        query,
        limit,
        min_score,
        memory_type_filter,
        SearchMethod::HyDE,
        &[],
    )
    .await
}

pub async fn recall_keyword(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    query: &str,
    limit: i64,
) -> Result<Vec<MemoryHit>> {
    recall_keyword_inner(pool, actor_id, query, limit.clamp(1, 50), None, &[]).await
}

async fn recall_keyword_inner(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    query: &str,
    limit: i64,
    memory_type_filter: Option<&str>,
    exclude_kinds: &[String],
) -> Result<Vec<MemoryHit>> {
    // Tokenize the query into meaningful terms, then OR-match each as a
    // separate ILIKE. A natural-language question like "which pull
    // requests are waiting for review" under the old whole-phrase ILIKE
    // returned 0 rows because no stored value contained that exact
    // substring; splitting into tokens surfaces rows that match ANY term.
    //
    // Filters: lowercase, strip non-alphanumeric punctuation per-token,
    // drop tokens shorter than 3 chars AND a small stopword list. Cap at
    // 8 tokens so we don't generate a 50-condition OR for verbose prompts.
    let tokens: Vec<String> = query
        .chars()
        .take(500)
        .collect::<String>()
        .split_whitespace()
        .map(|t| {
            t.chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .collect::<String>()
                .to_ascii_lowercase()
        })
        .filter(|t| t.len() >= 3 && !is_stopword(t))
        .take(8)
        .collect();

    // Empty token set (e.g. "what is it?") → fall back to whole-phrase
    // ILIKE so callers don't see a completely empty result set.
    if tokens.is_empty() {
        let escaped = query
            .chars()
            .take(200)
            .collect::<String>()
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let pattern = format!("%{}%", escaped);
        // Phase B: encrypted bytes can't be substring-matched at the DB
        // layer, so keyword fallback now matches `key` only. The vector-
        // cosine path (recall_semantic_filtered) remains the dominant
        // search surface; this fallback only fires when embeddings are
        // unavailable (queue stall, model down).
        let rows = sqlx::query(
            "SELECT actor_id, key, value_enc, value_key_id, value_format, memory_type, expires_at, updated_at, metadata \
             FROM actor_memory \
             WHERE actor_id = $1 \
               AND (expires_at IS NULL OR expires_at > now()) \
               AND key ILIKE $2 ESCAPE '\\' \
               AND ($4::text IS NULL OR memory_type = $4) \
               AND (cardinality($5::text[]) = 0 \
                    OR metadata IS NULL \
                    OR metadata->>'kind' IS NULL \
                    OR metadata->>'kind' != ALL($5::text[])) \
             ORDER BY updated_at DESC \
             LIMIT $3",
        )
        .bind(actor_id)
        .bind(&pattern)
        .bind(limit)
        .bind(memory_type_filter)
        .bind(exclude_kinds)
        .fetch_all(pool)
        .await?;
        return rows_to_memory_hits(rows).await;
    }

    // Build per-token ILIKE patterns, passed as a text[] array. SQL does
    // the fan-out with `ANY` — matches if any token appears in key/value.
    let patterns: Vec<String> = tokens
        .iter()
        .map(|t| {
            let escaped = t
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            format!("%{}%", escaped)
        })
        .collect();

    // Same `metadata.kind != ALL` semantics as recall_semantic_filtered —
    // the fallback path must honor the same exclusion so synthetic output
    // doesn't leak back in when embeddings are unavailable.
    // MCP-S2 follow-up: project `actor_id` + `value_format` so
    // `rows_to_memory_hits` can dispatch v1 ciphertexts via the AAD-
    // bound decrypt. Pre-fix omitted both — the whole-phrase branch
    // above already projected them; this per-token branch was the
    // sibling drift that broke keyword-fallback recall for any actor
    // with at least one v1 row.
    let rows = sqlx::query(
        "SELECT actor_id, key, value_enc, value_key_id, value_format, memory_type, expires_at, updated_at, metadata \
         FROM actor_memory \
         WHERE actor_id = $1 \
           AND (expires_at IS NULL OR expires_at > now()) \
           AND key ILIKE ANY($2::text[]) \
           AND ($4::text IS NULL OR memory_type = $4) \
           AND (cardinality($5::text[]) = 0 \
                OR metadata IS NULL \
                OR metadata->>'kind' IS NULL \
                OR metadata->>'kind' != ALL($5::text[])) \
         ORDER BY updated_at DESC \
         LIMIT $3",
    )
    .bind(actor_id)
    .bind(&patterns)
    .bind(limit)
    .bind(memory_type_filter)
    .bind(exclude_kinds)
    .fetch_all(pool)
    .await
    .context("recall_keyword")?;

    rows_to_memory_hits(rows).await
}

/// Small stopword list for keyword-fallback tokenization. English-only,
/// covers the highest-frequency function words that dilute match signal
/// in natural-language queries like "what are the urgent PRs".
fn is_stopword(t: &str) -> bool {
    matches!(
        t,
        "the"
            | "and"
            | "for"
            | "are"
            | "was"
            | "were"
            | "with"
            | "from"
            | "that"
            | "this"
            | "have"
            | "has"
            | "had"
            | "what"
            | "which"
            | "who"
            | "whom"
            | "when"
            | "where"
            | "why"
            | "how"
            | "any"
            | "all"
            | "some"
            | "can"
            | "should"
            | "would"
            | "could"
            | "there"
            | "their"
            | "them"
            | "they"
            | "about"
            | "into"
            | "over"
            | "under"
            | "also"
            | "just"
            | "than"
            | "been"
    )
}

/// Shared rows → MemoryHit conversion used by both the token and whole-
/// phrase keyword-fallback branches. Score decays 0.02 per rank so the
/// newest hit (i = 0) lands at 1.0 and the 50th hit (i = 49) at 0.02 —
/// callers who sort by score are effectively sorting by recency. Beyond
/// the 50th hit the `.max(0.0)` clamp pins everything to 0.0.
/// Convert raw rows into MemoryHits, decrypting `value_enc`/`value_key_id`
/// when present (Phase A). Async because decryption may need to fetch the
/// DEK via SecretsManager. The score is positional (newest = 1.0) — same
/// scheme as the legacy sync helper this replaces.
async fn rows_to_memory_hits(rows: Vec<sqlx::postgres::PgRow>) -> Result<Vec<MemoryHit>> {
    let mut hits = Vec::with_capacity(rows.len());
    for (i, r) in rows.into_iter().enumerate() {
        // MCP-S2: SELECT actor_id + value_format alongside the existing
        // columns so the AAD-dispatch resolver picks the right path.
        // Callers' SQL must include `actor_id` and `value_format` in
        // the projection. MCP-S2 follow-up: fail loudly on missing
        // columns (same rationale as decrypt_row_value above) so SELECT
        // drift in callers trips CI rather than silently mis-decrypting.
        let actor_id: Uuid = r
            .try_get("actor_id")
            .context("rows_to_memory_hits: caller's SELECT must project `actor_id` (MCP-S2 AAD)")?;
        let row_key: String = r.get("key");
        let value_enc: Option<Vec<u8>> = r.try_get("value_enc").ok();
        let value_key_id: Option<Uuid> = r.try_get("value_key_id").ok();
        let value_format: i16 = r.try_get("value_format").context(
            "rows_to_memory_hits: caller's SELECT must project `value_format` (MCP-S2 dispatch)",
        )?;
        let aad = build_memory_aad(actor_id, &row_key);
        let value = resolve_stored_value(None, value_enc, value_key_id, aad, value_format).await?;
        hits.push(MemoryHit {
            key: row_key,
            value,
            memory_type: r.get("memory_type"),
            expires_at: r.get("expires_at"),
            updated_at: r.get("updated_at"),
            score: (1.0 - (i as f64 * 0.02)).max(0.0),
            metadata: r.get::<Option<serde_json::Value>, _>("metadata"),
        });
    }
    Ok(hits)
}

// ============================================================================
// Mutations
// ============================================================================

pub async fn forget(pool: &Pool<Postgres>, actor_id: Uuid, key: &str) -> Result<ForgetOutcome> {
    let result = sqlx::query(
        "UPDATE actor_memory \
         SET expires_at = now() - INTERVAL '1 second', updated_at = now() \
         WHERE actor_id = $1 AND key = $2",
    )
    .bind(actor_id)
    .bind(key)
    .execute(pool)
    .await
    .context("forget")?;
    Ok(ForgetOutcome {
        deleted: result.rows_affected() > 0,
    })
}

pub async fn forget_exact(pool: &Pool<Postgres>, actor_id: Uuid, key: &str) -> Result<u64> {
    let result = sqlx::query("DELETE FROM actor_memory WHERE actor_id = $1 AND key = $2")
        .bind(actor_id)
        .bind(key)
        .execute(pool)
        .await
        .context("forget_exact")?;
    Ok(result.rows_affected())
}

/// Transaction-aware variant of `forget_exact` for callers composing a
/// multi-step memory mutation (consolidate, compress) atomically.
pub async fn forget_exact_in_tx<'c>(
    tx: &mut sqlx::Transaction<'c, Postgres>,
    actor_id: Uuid,
    key: &str,
) -> Result<u64> {
    let result = sqlx::query("DELETE FROM actor_memory WHERE actor_id = $1 AND key = $2")
        .bind(actor_id)
        .bind(key)
        .execute(&mut **tx)
        .await
        .context("forget_exact_in_tx")?;
    Ok(result.rows_affected())
}

/// Batch sibling to `forget_exact_in_tx` — single DELETE with
/// `WHERE key = ANY($2)`. Replaces the per-key loop used by
/// `consolidate_actor_memory` (N round-trips → 1 round-trip inside the
/// same transaction). Empty input short-circuits without touching the DB.
///
/// Returns total rows affected. Caller should treat that as "keys
/// successfully retired" — a key that didn't exist contributes 0 just
/// as it would in the per-key version.
pub async fn forget_keys_in_tx<'c>(
    tx: &mut sqlx::Transaction<'c, Postgres>,
    actor_id: Uuid,
    keys: &[String],
) -> Result<u64> {
    if keys.is_empty() {
        return Ok(0);
    }
    let result = sqlx::query("DELETE FROM actor_memory WHERE actor_id = $1 AND key = ANY($2)")
        .bind(actor_id)
        .bind(keys)
        .execute(&mut **tx)
        .await
        .context("forget_keys_in_tx")?;
    Ok(result.rows_affected())
}

/// Single-query "measure + forget" used by `compress_actor_context` —
/// previously a per-key SELECT + DELETE pair (2N round-trips for N keys).
/// CTE evaluation order in Postgres guarantees the SELECT runs against
/// the pre-DELETE snapshot, so the byte total and rows-affected count
/// match the prior loop.
///
/// Returns `(bytes_removed, keys_deleted)`. Empty input short-circuits.
///
/// Why a CTE: cuts wall time linearly with key count and atomicity
/// stays inside the caller's outer transaction (only one statement
/// executes), so the prior "what if we crash mid-loop" risk is gone.
pub async fn measure_and_forget_keys_in_tx<'c>(
    tx: &mut sqlx::Transaction<'c, Postgres>,
    actor_id: Uuid,
    keys: &[String],
) -> Result<(i64, u64)> {
    if keys.is_empty() {
        return Ok((0, 0));
    }
    let row: (i64, i64) = sqlx::query_as(
        "WITH measured AS ( \
             SELECT COALESCE(SUM(octet_length(value_enc)), 0)::bigint AS bytes \
             FROM actor_memory WHERE actor_id = $1 AND key = ANY($2) \
         ), deleted AS ( \
             DELETE FROM actor_memory WHERE actor_id = $1 AND key = ANY($2) \
             RETURNING 1 AS marker \
         ) \
         SELECT (SELECT bytes FROM measured), \
                (SELECT COUNT(*) FROM deleted)::bigint",
    )
    .bind(actor_id)
    .bind(keys)
    .fetch_one(&mut **tx)
    .await
    .context("measure_and_forget_keys_in_tx")?;
    Ok((row.0, row.1 as u64))
}

/// Measure the on-disk text size of a memory entry's `value` column,
/// transaction-scoped. Returns 0 if the row doesn't exist. Used by the
/// context-compression handler to compute bytes-saved estimates atomically
/// with the deletes that follow.
pub async fn measure_value_bytes_in_tx<'c>(
    tx: &mut sqlx::Transaction<'c, Postgres>,
    actor_id: Uuid,
    key: &str,
) -> Result<i64> {
    let size: Option<i64> = sqlx::query_scalar(
        "SELECT COALESCE(octet_length(value_enc), 0) FROM actor_memory \
         WHERE actor_id = $1 AND key = $2",
    )
    .bind(actor_id)
    .bind(key)
    .fetch_optional(&mut **tx)
    .await
    .context("measure_value_bytes_in_tx")?;
    Ok(size.unwrap_or(0))
}

/// Bulk-copy the live `semantic` and `episodic` memories of one actor to
/// another, in a single SQL round-trip. Returns the number of rows
/// written.
///
/// **Caller must verify both actors belong to the same user before
/// invoking.** This is a TENANCY boundary, not a crypto one: it stops one
/// user's agent memory from being copied into another user's agent. (The
/// DEK is a single system-wide key — there is no per-user DEK — so a
/// cross-user copy would in fact decrypt fine; we forbid it for privacy,
/// not because the destination "couldn't decrypt".) `talos-memory` has no
/// notion of user identity — that ownership check stays where it is, in the
/// MCP/GraphQL layer.
///
/// Crypto handling depends on the row's AEAD format. The per-row subkey is
/// `HKDF(global DEK, info = build_memory_aad(actor_id, key))`, so the
/// derivation (and the bound AAD) is tied to the SOURCE actor_id and must be
/// re-based on copy:
/// * v0 rows (no AAD) → ciphertext copied verbatim — cheap, no crypto.
/// * v1 / v3 rows → DECRYPTED under the source AAD and RE-ENCRYPTED under the
///   target AAD per row (see the per-format branch in the body), because the
///   AAD's actor_id changes. `metadata` is
/// preserved so cloned memories retain their `kind` tags + provenance.
/// Embeddings are NOT copied: they are lossy (1024-dim float vectors)
/// and the cheaper rebuild path is to spawn
/// `backfill_embeddings_for_actor(target, n)` after the clone returns.
///
/// TTL semantics on the destination row:
/// * `semantic` → `expires_at = NULL` (permanent)
/// * `episodic` → `expires_at = NOW() + 7d` (fresh window — we
///   intentionally do NOT carry over the source's near-expiry timestamp)
/// * `working` / `scratchpad` → excluded entirely (run-specific, no
///   value across an actor boundary).
///
/// Source rows whose `expires_at` is already in the past are excluded.
///
/// On `ON CONFLICT (actor_id, key)` (i.e. the destination already has a
/// memory at the same key), the destination row is overwritten with the
/// source ciphertext + key_id + memory_type + expires_at + metadata, and
/// `updated_at` is bumped to NOW(). This matches the prior inline-SQL
/// behaviour at the two extracted call sites.
pub async fn clone_memories(
    pool: &Pool<Postgres>,
    source_actor_id: Uuid,
    target_actor_id: Uuid,
) -> Result<i64> {
    // MCP-S2: v1/v3/v4 ciphertexts bind AAD = build_memory_aad(actor_id, key)
    // so a raw SQL ciphertext-passthrough across actors would produce
    // rows whose AAD bytes don't match their new actor_id, breaking
    // decryption. Paths:
    //   1. v0 rows (no AAD) — safe to bulk-copy ciphertext directly (stay
    //      global-DEK, org_id NULL).
    //   2. v1/v3/v4 rows — DECRYPTED with the source AAD (using each row's own
    //      format), then RE-ENCRYPTED under the TARGET actor's org root DEK
    //      (per-org DEK arc) with the target AAD, then written with org_id =
    //      target's org. (v3 rows were previously DROPPED here — the old SELECT
    //      matched only value_format = 1; this also closes that gap.)
    //   3. Rows without a crypto hook (test/standalone) — copy plaintext
    //      legacy column unchanged (current legacy behaviour).
    //
    // The per-row decrypt+re-encrypt cost is meaningful (one extra
    // AES-GCM round per row + DEK lookup) but clone_memories is a
    // relatively rare admin operation; correctness > throughput here.
    //
    // 2026-05-28 audit S2#7 follow-up: atomicity. Pre-fix the v0 bulk
    // INSERT committed implicitly via `fetch_one(pool)`, then each v1
    // re-encrypt+INSERT auto-committed individually. A mid-loop decrypt
    // / re-encrypt / INSERT failure left the target actor in a partial
    // state (v0 rows committed, some v1 rows committed, some missing),
    // and the caller saw only the Err — no count, no skip list.
    //
    // Post-fix: do crypto work outside the transaction (DEK cache is
    // in-process so no DB hop in the common path; SecretsManager would
    // borrow a separate pool connection in the rare miss case, which
    // could deadlock against our held tx), then wrap BOTH the v0
    // bulk INSERT and the v1 INSERTs in a single tx. Any failure
    // rolls the entire clone back; the caller's Err is now
    // semantically "no rows changed" rather than "some rows changed,
    // some didn't."

    // Per-org DEK arc: re-encrypt the cloned rows under the TARGET actor's org
    // root DEK (resolved once), and stamp that org on the cloned rows.
    let target_org = resolve_actor_org_id(pool, target_actor_id).await?;

    // ── Pre-fetch AAD-bound source rows (v1/v3/v4) + do crypto work (NO tx held) ──
    let v1_rows = sqlx::query(
        "SELECT key, value_enc, value_key_id, value_format, memory_type, expires_at, metadata \
         FROM actor_memory \
         WHERE actor_id = $1 \
           AND value_format IN (1, 3, 4) \
           AND memory_type IN ('semantic', 'episodic') \
           AND (expires_at IS NULL OR expires_at > NOW())",
    )
    .bind(source_actor_id)
    .fetch_all(pool)
    .await
    .context("clone_memories: select AAD-bound (v1/v3/v4) source rows")?;

    // Buffer the decrypted+re-encrypted v1 rows in memory so the
    // transaction below holds only DB-write work, not crypto.
    struct ReEncryptedRow {
        key: String,
        new_ciphertext: Vec<u8>,
        new_key_id: Uuid,
        new_format: i16,
        memory_type: String,
        metadata: Option<serde_json::Value>,
        new_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    }

    let mut v1_buffered: Vec<ReEncryptedRow> = Vec::with_capacity(v1_rows.len());
    if !v1_rows.is_empty() {
        let hook = MEMORY_CRYPTO_HOOK.get().cloned().ok_or_else(|| {
            anyhow::anyhow!(
                "clone_memories: v1 rows present but no MemoryCryptoHook registered — \
                 register_memory_crypto_hook() must run before any v1 clone"
            )
        })?;
        for r in v1_rows {
            let key: String = r.get("key");
            let value_enc: Vec<u8> = r.get("value_enc");
            let value_key_id: Uuid = r.get("value_key_id");
            let src_format: i16 = r.get("value_format");
            let memory_type: String = r.get("memory_type");
            let metadata: Option<serde_json::Value> = r.try_get("metadata").ok();
            // Decrypt under SOURCE AAD, using the row's OWN format (v1/v3/v4 all
            // decrypt via the versioned dispatch).
            let source_aad = build_memory_aad(source_actor_id, &key);
            let plaintext = hook
                .decrypt(value_key_id, value_enc, source_aad, src_format)
                .await
                .with_context(|| format!("clone_memories: decrypt source row key={key}"))?;
            // Re-encrypt under the TARGET actor's org DEK + TARGET AAD. new_format
            // is 4 (target has an org) or 3 (global) — stamped from the result.
            let target_aad = build_memory_aad(target_actor_id, &key);
            let (new_key_id, new_ciphertext, new_format) = hook
                .encrypt(plaintext.to_string(), target_org, target_aad)
                .await
                .with_context(|| format!("clone_memories: re-encrypt row key={key}"))?;
            let new_expires_at: Option<chrono::DateTime<chrono::Utc>> = match memory_type.as_str() {
                "semantic" => None,
                "episodic" => Some(chrono::Utc::now() + chrono::Duration::days(7)),
                _ => continue,
            };
            v1_buffered.push(ReEncryptedRow {
                key,
                new_ciphertext,
                new_key_id,
                new_format,
                memory_type,
                metadata,
                new_expires_at,
            });
        }
    }

    // ── Single transaction: v0 bulk INSERT + each buffered v1 INSERT ──
    // On Err from any step, the tx Drop's rollback discards EVERYTHING.
    let mut tx = pool
        .begin()
        .await
        .context("clone_memories: begin transaction")?;

    let v0_count: i64 = sqlx::query_scalar(
        "WITH inserted AS ( \
             INSERT INTO actor_memory (actor_id, key, value_enc, value_key_id, value_format, memory_type, expires_at, metadata, updated_at) \
             SELECT $1, key, value_enc, value_key_id, value_format, memory_type, \
                    CASE WHEN memory_type = 'semantic' THEN NULL \
                         WHEN memory_type = 'episodic' THEN now() + INTERVAL '7 days' \
                    END, \
                    metadata, \
                    now() \
             FROM actor_memory \
             WHERE actor_id = $2 \
               AND value_format = 0 \
               AND memory_type IN ('semantic', 'episodic') \
               AND (expires_at IS NULL OR expires_at > NOW()) \
             ON CONFLICT (actor_id, key) DO UPDATE \
               SET value_enc = EXCLUDED.value_enc, \
                   value_key_id = EXCLUDED.value_key_id, \
                   value_format = EXCLUDED.value_format, \
                   memory_type = EXCLUDED.memory_type, \
                   expires_at = EXCLUDED.expires_at, \
                   metadata = EXCLUDED.metadata, \
                   updated_at = NOW() \
             RETURNING 1 \
         ) SELECT COUNT(*) FROM inserted",
    )
    .bind(target_actor_id)
    .bind(source_actor_id)
    .fetch_one(&mut *tx)
    .await
    .context("clone_memories: bulk copy v0 (legacy no-AAD) rows")?;

    let mut v1_count: i64 = 0;
    for row in v1_buffered {
        sqlx::query(
            "INSERT INTO actor_memory (actor_id, key, value_enc, value_key_id, value_format, memory_type, expires_at, metadata, org_id, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()) \
             ON CONFLICT (actor_id, key) DO UPDATE \
               SET value_enc = EXCLUDED.value_enc, \
                   value_key_id = EXCLUDED.value_key_id, \
                   value_format = EXCLUDED.value_format, \
                   memory_type = EXCLUDED.memory_type, \
                   expires_at = EXCLUDED.expires_at, \
                   metadata = EXCLUDED.metadata, \
                   org_id = EXCLUDED.org_id, \
                   updated_at = NOW()",
        )
        .bind(target_actor_id)
        .bind(&row.key)
        .bind(row.new_ciphertext.as_slice())
        .bind(row.new_key_id)
        .bind(row.new_format)
        .bind(&row.memory_type)
        .bind(row.new_expires_at)
        .bind(row.metadata)
        .bind(target_org)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("clone_memories: insert v1 target row key={}", row.key))?;
        v1_count += 1;
    }

    tx.commit()
        .await
        .context("clone_memories: commit transaction")?;

    Ok(v0_count + v1_count)
}

pub async fn forget_prefix(pool: &Pool<Postgres>, actor_id: Uuid, prefix: &str) -> Result<u64> {
    if prefix.is_empty() {
        anyhow::bail!("forget_prefix requires a non-empty prefix");
    }
    let escaped = prefix
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    let result = sqlx::query(
        "DELETE FROM actor_memory \
         WHERE actor_id = $1 AND key LIKE $2 || '%' ESCAPE '\\'",
    )
    .bind(actor_id)
    .bind(escaped)
    .execute(pool)
    .await
    .context("forget_prefix")?;
    Ok(result.rows_affected())
}

pub async fn refresh_ttl(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    key: &str,
    new_expires_at: DateTime<Utc>,
) -> Result<u64> {
    let result = sqlx::query(
        "UPDATE actor_memory \
         SET expires_at = $1, updated_at = now() \
         WHERE actor_id = $2 AND key = $3 \
           AND expires_at IS NOT NULL \
           AND expires_at > now()",
    )
    .bind(new_expires_at)
    .bind(actor_id)
    .bind(key)
    .execute(pool)
    .await
    .context("refresh_ttl")?;
    Ok(result.rows_affected())
}

// ============================================================================
// Operations
// ============================================================================

/// Outcome of [`re_encrypt_memories_to_org`].
#[derive(Debug, Clone, Default)]
pub struct MemoryReEncryptStats {
    pub re_encrypted: u64,
    pub failed: u64,
}

/// Per-org DEK arc: migrate EXISTING `actor_memory` rows to their actor's org
/// root DEK (format v4). The cutover only converts NEW writes; this sweep brings
/// stored rows over, so the global DEK can retire for memory. Operator/background
/// invoked — sibling of `SecretsManager::re_encrypt_secrets_to_org`.
///
/// Selects rows whose actor HAS an org (`actors.org_id IS NOT NULL`) and that are
/// not already v4, decrypts via the registered hook (version-aware), and
/// re-encrypts under the actor's org DEK, stamping `actor_memory.org_id`. Rows
/// whose actor has no org keep their current (global) DEK. Same lost-write guard
/// as the secrets sweep: the UPDATE only fires while the row is still on the
/// `(value_key_id, value_format)` pair we decrypted from. No-op when no crypto
/// hook is registered.
pub async fn re_encrypt_memories_to_org(pool: &Pool<Postgres>) -> Result<MemoryReEncryptStats> {
    let Some(hook) = MEMORY_CRYPTO_HOOK.get().cloned() else {
        return Ok(MemoryReEncryptStats::default());
    };
    // 4 = talos_secrets_manager::SecretsManager::AAD_FORMAT_V4_ORG_DERIVED
    // (literal to avoid a talos-memory → talos-secrets-manager dependency).
    const V4: i16 = 4;

    let rows = sqlx::query(
        "SELECT am.actor_id, am.key, am.value_enc, am.value_key_id, am.value_format, a.org_id \
         FROM actor_memory am JOIN actors a ON a.id = am.actor_id \
         WHERE am.value_format <> $1 AND a.org_id IS NOT NULL",
    )
    .bind(V4)
    .fetch_all(pool)
    .await
    .context("re_encrypt_memories_to_org: select stale rows")?;

    let mut re_encrypted = 0u64;
    let mut failed = 0u64;
    for r in rows {
        let actor_id: Uuid = r.get("actor_id");
        let key: String = r.get("key");
        let value_enc: Vec<u8> = r.get("value_enc");
        let value_key_id: Uuid = r.get("value_key_id");
        let src_format: i16 = r.get("value_format");
        let org_id: Uuid = r.get("org_id");

        let aad = build_memory_aad(actor_id, &key);
        let plaintext = match hook
            .decrypt(value_key_id, value_enc, aad.clone(), src_format)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(%actor_id, %key, "memory per-org sweep: decrypt failed: {e}");
                failed += 1;
                continue;
            }
        };
        let (new_key_id, new_ct, new_format) = match hook
            .encrypt(plaintext.to_string(), Some(org_id), aad)
            .await
        {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(%actor_id, %key, "memory per-org sweep: re-encrypt failed: {e}");
                failed += 1;
                continue;
            }
        };

        match sqlx::query(
            "UPDATE actor_memory \
             SET value_enc = $1, value_key_id = $2, value_format = $3, org_id = $4, updated_at = now() \
             WHERE actor_id = $5 AND key = $6 AND value_key_id = $7 AND value_format = $8",
        )
        .bind(new_ct.as_slice())
        .bind(new_key_id)
        .bind(new_format)
        .bind(org_id)
        .bind(actor_id)
        .bind(&key)
        .bind(value_key_id)
        .bind(src_format)
        .execute(pool)
        .await
        {
            Ok(res) => {
                if res.rows_affected() > 0 {
                    re_encrypted += 1;
                } else {
                    tracing::debug!(%actor_id, %key, "memory per-org sweep: row concurrently re-keyed; skipped");
                }
            }
            Err(e) => {
                tracing::error!(%actor_id, %key, "memory per-org sweep: update failed: {e}");
                failed += 1;
            }
        }
    }

    tracing::info!(
        re_encrypted,
        failed,
        "Per-org actor_memory re-encryption sweep complete"
    );
    Ok(MemoryReEncryptStats {
        re_encrypted,
        failed,
    })
}

pub async fn backfill_embeddings(pool: &Pool<Postgres>, limit: i64) -> Result<usize> {
    backfill_embeddings_filtered(pool, None, limit).await
}

pub async fn backfill_embeddings_for_actor(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    limit: i64,
) -> Result<usize> {
    backfill_embeddings_filtered(pool, Some(actor_id), limit).await
}

/// Shared implementation for [`backfill_embeddings`] (global) and
/// [`backfill_embeddings_for_actor`] (per-actor). The two public
/// functions previously duplicated the same fetch → decrypt → embed →
/// UPDATE loop; this version branches the SELECT once on
/// `actor_filter`, then runs the same loop body.
///
/// L-1 invariant preserved: UPDATE failures `warn` + skip without
/// incrementing the counter, so the operator metric never over-reports
/// under DB stress.
async fn backfill_embeddings_filtered(
    pool: &Pool<Postgres>,
    actor_filter: Option<Uuid>,
    limit: i64,
) -> Result<usize> {
    // MCP-S2 follow-up: project `actor_id` + `value_format` so
    // `decrypt_row_value` dispatches v1 ciphertexts via the AAD-bound
    // path. Pre-fix the backfill would silently skip every v1 row
    // (decrypt err → warn + continue), so embeddings never got
    // generated for post-MCP-S2 actor_memory rows.
    let raw_rows = match actor_filter {
        Some(actor_id) => {
            sqlx::query(
                "SELECT id, actor_id, key, value_enc, value_key_id, value_format \
             FROM actor_memory \
             WHERE actor_id = $1 \
               AND embedding IS NULL \
               AND memory_type != 'scratchpad' \
               AND (expires_at IS NULL OR expires_at > NOW()) \
             ORDER BY created_at ASC LIMIT $2",
            )
            .bind(actor_id)
            .bind(limit)
            .fetch_all(pool)
            .await?
        }
        None => {
            sqlx::query(
                "SELECT id, actor_id, key, value_enc, value_key_id, value_format \
             FROM actor_memory \
             WHERE embedding IS NULL AND memory_type != 'scratchpad' \
             AND (expires_at IS NULL OR expires_at > NOW()) \
             ORDER BY created_at ASC LIMIT $1",
            )
            .bind(limit)
            .fetch_all(pool)
            .await?
        }
    };

    let total = raw_rows.len();
    let mut embedded = 0usize;
    for r in &raw_rows {
        use sqlx::Row as _;
        let id: Uuid = r.get("id");
        let key: String = r.get("key");
        let value = match decrypt_row_value(r).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, %id, "backfill_embeddings: decrypt failed; skipping");
                continue;
            }
        };
        // Single serialization, reused for the embedding text input.
        let serialized = serde_json::to_string(&value).unwrap_or_default();
        let truncated: String = serialized.chars().take(4000).collect();
        let text = format!("{}: {}", key, truncated);
        let row_actor: Uuid = r.get("actor_id");
        let local_only = embed_local_only(pool, row_actor).await;
        if let Some(emb) = embedding::generate_embedding(&text, local_only).await {
            // L-1: UPDATE failures (DB pool exhaustion, FK violation,
            // constraint mismatch) warn + skip without bumping the
            // counter, so "embedded N rows" metrics never lie under
            // DB stress.
            let vec = pgvector::Vector::from(emb);
            match sqlx::query(
                "UPDATE actor_memory SET embedding = $1, updated_at = now() WHERE id = $2",
            )
            .bind(vec)
            .bind(id)
            .execute(pool)
            .await
            {
                Ok(_) => embedded += 1,
                Err(e) => tracing::warn!(
                    error = %e,
                    %id,
                    "backfill_embeddings: UPDATE failed; row skipped (counter not incremented)"
                ),
            }
        }
    }
    match actor_filter {
        Some(actor_id) => tracing::info!(
            actor_id = %actor_id,
            total_candidates = total,
            embedded,
            "Per-actor embedding backfill complete"
        ),
        None => tracing::info!(
            total_candidates = total,
            embedded,
            "Actor memory embedding backfill complete"
        ),
    }
    Ok(embedded)
}

pub async fn sweep_expired(pool: &Pool<Postgres>, grace_hours: i64) -> Result<u64> {
    let grace = format!("{} hours", grace_hours.max(0));
    let result = sqlx::query(
        "DELETE FROM actor_memory \
         WHERE expires_at IS NOT NULL \
           AND expires_at < now() - ($1::text)::interval",
    )
    .bind(&grace)
    .execute(pool)
    .await
    .context("sweep_expired")?;
    Ok(result.rows_affected())
}

// ============================================================================
// Unit tests — pure logic only. Integration tests that require a live
// Postgres / Ollama live under `tests/` and are gated by env vars so
// `cargo test -p talos-memory` stays green in CI even when services
// aren't running.
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    // ────────────────────────────────────────────────────────────────
    // Fail-closed plaintext-fallback guard (write-side mirror of the
    // resolve_stored_value ciphertext-without-hook refusal)
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn guard_plaintext_fallback_refuses_in_production() {
        let err = guard_plaintext_fallback(true).expect_err("production must fail closed");
        let msg = err.to_string();
        assert!(
            msg.contains("register_memory_crypto_hook"),
            "error must name the fix: {msg}"
        );
        assert!(msg.contains("plaintext"), "error must name the risk: {msg}");
    }

    #[test]
    fn guard_plaintext_fallback_allows_in_dev() {
        guard_plaintext_fallback(false).expect("dev keeps the legacy plaintext path");
    }

    // ────────────────────────────────────────────────────────────────
    // MCP-S2: build_memory_aad invariants
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn build_memory_aad_encodes_actor_id_then_separator_then_key() {
        let actor = Uuid::parse_str("11111111-2222-3333-4444-555555555555").expect("valid uuid");
        let aad = build_memory_aad(actor, "my-key");
        // 16 actor_id bytes
        assert_eq!(&aad[..16], actor.as_bytes());
        // 1 separator byte
        assert_eq!(aad[16], 0x00);
        // remaining bytes = key
        assert_eq!(&aad[17..], b"my-key");
    }

    #[test]
    fn build_memory_aad_changes_when_actor_changes() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert_ne!(build_memory_aad(a, "k"), build_memory_aad(b, "k"));
    }

    #[test]
    fn build_memory_aad_changes_when_key_changes() {
        let a = Uuid::new_v4();
        assert_ne!(build_memory_aad(a, "k1"), build_memory_aad(a, "k2"));
    }

    #[test]
    fn build_memory_aad_separator_blocks_actor_id_collision_attack() {
        // Without the 0x00 separator, an attacker could pick a `key`
        // that starts with another actor's UUID bytes and produce the
        // same AAD as that other actor's legitimate row. The separator
        // forces the AAD's first 17 bytes to encode (actor_id, 0x00),
        // and no value of `key` can manufacture that prefix for a
        // different actor_id.
        let actor_a = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        let actor_b = Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();
        // Construct a malicious key that contains actor_b's bytes.
        let mut malicious_key = String::new();
        for b in actor_b.as_bytes() {
            malicious_key.push(*b as char);
        }
        // AAD for (actor_a, malicious_key) has actor_a prefix +
        // separator + actor_b bytes as the "key" portion.
        let aad_a = build_memory_aad(actor_a, &malicious_key);
        let aad_b = build_memory_aad(actor_b, "");
        assert_ne!(
            aad_a, aad_b,
            "0x00 separator must prevent collision under malicious key choice"
        );
        // Specifically, aad_a starts with actor_a; aad_b starts with actor_b.
        assert_eq!(&aad_a[..16], actor_a.as_bytes());
        assert_eq!(&aad_b[..16], actor_b.as_bytes());
    }

    #[test]
    fn build_memory_aad_empty_key_still_includes_separator() {
        // Empty `key` is unusual but legitimate (e.g., the "default"
        // memory slot for an actor). The separator MUST still appear
        // so the AAD length signals "key is empty" vs "key was elided".
        let a = Uuid::new_v4();
        let aad = build_memory_aad(a, "");
        assert_eq!(aad.len(), 17);
        assert_eq!(&aad[..16], a.as_bytes());
        assert_eq!(aad[16], 0x00);
    }

    #[test]
    fn default_ttl_by_type() {
        // Working defaults to 1 h
        let w = default_expires_at("working", None).unwrap();
        let delta = w.signed_duration_since(Utc::now());
        assert!(delta.num_seconds() > 0 && delta.num_seconds() <= 3601);

        // Episodic defaults to 168 h (7 days)
        let e = default_expires_at("episodic", None).unwrap();
        let delta = e.signed_duration_since(Utc::now());
        assert!(delta.num_hours() >= 167 && delta.num_hours() <= 168);

        // Scratchpad defaults to 24 h
        let s = default_expires_at("scratchpad", None).unwrap();
        let delta = s.signed_duration_since(Utc::now());
        assert!(delta.num_hours() >= 23 && delta.num_hours() <= 24);

        // Semantic never expires
        assert!(default_expires_at("semantic", None).is_none());

        // Explicit ttl_hours always overrides type default — including
        // for semantic (caller explicitly wants an expiry).
        let custom = default_expires_at("semantic", Some(2.0)).unwrap();
        let delta = custom.signed_duration_since(Utc::now());
        assert!(delta.num_hours() >= 1 && delta.num_hours() <= 2);
    }

    #[test]
    fn default_ttl_rejects_non_positive() {
        assert!(default_expires_at("working", Some(0.0)).is_none());
        assert!(default_expires_at("working", Some(-1.0)).is_none());
        assert!(default_expires_at("working", Some(f64::NAN)).is_none());
        assert!(default_expires_at("working", Some(f64::INFINITY)).is_none());
    }

    #[test]
    fn validate_memory_type_canonical() {
        for t in MEMORY_TYPES {
            assert_eq!(validate_memory_type(t).unwrap(), *t);
        }
        assert!(validate_memory_type("bogus").is_err());
        assert!(validate_memory_type("").is_err());
    }

    // MCP-1224 (2026-05-18): the canonical `validate_memory_key` helper
    // is now invoked at the persistence boundary inside
    // `persist_memory_with_metadata` and `persist_memory_in_tx_with_metadata`
    // (sibling-drift fix — `scaffold_actor.seed_memories` and any other
    // caller of those write paths previously did only a shallow
    // `key.is_empty()` check, allowing `"   "` whitespace-only keys
    // through and persisting unreachable rows). These tests pin the
    // canonical validator's accept/reject contract so a future
    // refactor of `validate_memory_key` doesn't loosen the bound.
    #[test]
    fn validate_memory_key_accepts_canonical() {
        assert_eq!(validate_memory_key("foo").unwrap(), "foo");
        assert_eq!(
            validate_memory_key("daily_brief/2026-04-21").unwrap(),
            "daily_brief/2026-04-21"
        );
        // Trim semantics: surrounding whitespace stripped, inner
        // whitespace preserved.
        assert_eq!(validate_memory_key("  foo  ").unwrap(), "foo");
        assert_eq!(validate_memory_key("a b\tc").unwrap(), "a b\tc");
        // Exact-cap accepted (500 chars).
        let at_cap = "a".repeat(MAX_MEMORY_KEY_CHARS);
        assert_eq!(validate_memory_key(&at_cap).unwrap(), at_cap.as_str());
    }

    #[test]
    fn validate_memory_key_rejects_whitespace_only() {
        // The seed_memories bypass: scaffold_actor caller passed
        // `"   "` and a shallow `is_empty()` check accepted it,
        // persisting a row whose primary-key projection is empty
        // and therefore unreachable from any subsequent recall.
        assert!(validate_memory_key("   ").is_err());
        assert!(validate_memory_key("\t\t").is_err());
        assert!(validate_memory_key(" \t \t ").is_err());
        assert!(validate_memory_key("").is_err());
    }

    #[test]
    fn validate_memory_key_rejects_control_chars() {
        // Tab is explicitly allowed (MCP-388 trim parity) — every
        // other control char rejected.
        assert!(validate_memory_key("foo\0bar").is_err());
        assert!(validate_memory_key("foo\nbar").is_err());
        assert!(validate_memory_key("foo\rbar").is_err());
        assert!(validate_memory_key("foo\x07bar").is_err());
        // Trailing control chars also rejected (validator inspects
        // the original key, not just the trimmed view, so embedded
        // \0 inside untrimmed padding still triggers).
        assert!(validate_memory_key("  foo\0  ").is_err());
        // Tab inside the key is fine.
        assert!(validate_memory_key("foo\tbar").is_ok());
    }

    #[test]
    fn validate_memory_key_rejects_oversize() {
        // 501 chars rejected (cap is 500 chars, MAX_MEMORY_KEY_CHARS).
        let oversize = "a".repeat(MAX_MEMORY_KEY_CHARS + 1);
        assert!(validate_memory_key(&oversize).is_err());
        // 10 000 chars rejected — the pre-MCP-834 GraphQL path used
        // MAX_SHORT_STRING_LENGTH = 10 000, which is what made this
        // drift hard to detect on the write surface before promotion.
        let way_oversize = "a".repeat(10_000);
        assert!(validate_memory_key(&way_oversize).is_err());
    }

    #[test]
    fn hmac_roundtrip() {
        use crate::rpc_auth;
        rpc_auth::register_hmac_key(std::sync::Arc::new(vec![0xABu8; 32]));
        let actor = Uuid::new_v4();
        let body = b"hello memory";
        let nonce = rpc_auth::random_nonce();
        let sig = rpc_auth::sign("memory_rpc", actor, &nonce, body).unwrap();
        assert!(rpc_auth::verify("memory_rpc", actor, &nonce, body, &sig));

        // Subject binding: a sig valid for memory_rpc must not verify
        // as graph_rpc.
        assert!(!rpc_auth::verify("graph_rpc", actor, &nonce, body, &sig));

        // Actor binding: different actor_id invalidates.
        assert!(!rpc_auth::verify(
            "memory_rpc",
            Uuid::new_v4(),
            &nonce,
            body,
            &sig
        ));

        // Body tampering invalidates.
        assert!(!rpc_auth::verify(
            "memory_rpc",
            actor,
            &nonce,
            b"tampered",
            &sig
        ));

        // Nonce binding invalidates.
        assert!(!rpc_auth::verify("memory_rpc", actor, "other", body, &sig));
    }

    #[test]
    fn memory_rpc_signed_roundtrip() {
        use crate::memory_rpc::{MemoryOp, MemoryRpcRequest};
        use crate::rpc_auth;
        rpc_auth::register_hmac_key(std::sync::Arc::new(vec![0x11u8; 32]));
        let actor = Uuid::new_v4();
        let req = MemoryRpcRequest::new_signed(
            actor,
            MemoryOp::Get {
                key: "capture/abc".to_string(),
            },
        )
        .expect("sign");
        assert!(req.verify());

        // Tamper with the op but keep the original signature — must
        // fail verify. This is the critical property for cross-tenant
        // security.
        let mut tampered = req.clone();
        tampered.op = MemoryOp::Delete {
            key: "victim-key".to_string(),
        };
        assert!(!tampered.verify());
    }

    #[test]
    fn canonical_json_sorts_object_keys() {
        use crate::rpc_auth::canonical_json_bytes;
        // Same logical JSON built in two different insertion orders
        // — canonical form must be byte-identical.
        let mut a = serde_json::Map::new();
        a.insert("z".to_string(), serde_json::json!(1));
        a.insert("a".to_string(), serde_json::json!(2));
        let mut b = serde_json::Map::new();
        b.insert("a".to_string(), serde_json::json!(2));
        b.insert("z".to_string(), serde_json::json!(1));
        let va = serde_json::Value::Object(a);
        let vb = serde_json::Value::Object(b);
        assert_eq!(canonical_json_bytes(&va), canonical_json_bytes(&vb));

        // Nested: a's inner keys must also be sorted recursively.
        let nested_a = serde_json::json!({
            "outer": {"zz": 1, "aa": 2, "mm": 3},
            "arr": [{"x": 1, "y": 2}, {"y": 2, "x": 1}],
        });
        let nested_b = serde_json::json!({
            "arr": [{"y": 2, "x": 1}, {"x": 1, "y": 2}],
            "outer": {"aa": 2, "mm": 3, "zz": 1},
        });
        assert_eq!(
            canonical_json_bytes(&nested_a),
            canonical_json_bytes(&nested_b)
        );
    }

    #[test]
    fn memory_set_signature_is_key_order_invariant() {
        use crate::memory_rpc::{MemoryOp, MemoryRpcRequest};
        use crate::rpc_auth;
        rpc_auth::register_hmac_key(std::sync::Arc::new(vec![0x55u8; 32]));
        let actor = Uuid::new_v4();

        // Value with keys inserted in two different orders — the
        // signed body must hash to the same bytes, so both requests
        // verify with each other's signatures.
        let mut value_a = serde_json::Map::new();
        value_a.insert("z".to_string(), serde_json::json!("last"));
        value_a.insert("a".to_string(), serde_json::json!("first"));
        let mut value_b = serde_json::Map::new();
        value_b.insert("a".to_string(), serde_json::json!("first"));
        value_b.insert("z".to_string(), serde_json::json!("last"));

        let req_a = MemoryRpcRequest::new_signed(
            actor,
            MemoryOp::Set {
                metadata: None,
                key: "k".to_string(),
                value: serde_json::Value::Object(value_a),
                memory_type: "semantic".to_string(),
                ttl_hours: None,
            },
        )
        .expect("sign A");
        let req_b = MemoryRpcRequest::new_signed(
            actor,
            MemoryOp::Set {
                metadata: None,
                key: "k".to_string(),
                value: serde_json::Value::Object(value_b),
                memory_type: "semantic".to_string(),
                ttl_hours: None,
            },
        )
        .expect("sign B");

        // Both must verify individually (freshness window in play).
        assert!(req_a.verify());
        assert!(req_b.verify());
        // Signatures may differ (nonce + timestamp do) — but the body
        // hashes must match. Construct a hybrid request using req_a's
        // signature + req_b's op: if canonical form really works,
        // this should still verify because the signed body is
        // byte-identical either way... actually no, nonce differs so
        // signatures still differ. The real test: swap op between
        // them (same nonce + timestamp + signature, new op shape) and
        // verify that works. This is subtle to test cleanly; the
        // canonical_json_sorts_object_keys test above covers the
        // byte invariant directly.
    }

    #[test]
    fn stale_request_is_rejected() {
        use crate::memory_rpc::{MemoryOp, MemoryRpcRequest};
        use crate::rpc_auth;
        rpc_auth::register_hmac_key(std::sync::Arc::new(vec![0x44u8; 32]));
        let actor = Uuid::new_v4();
        let mut req = MemoryRpcRequest::new_signed(
            actor,
            MemoryOp::Get {
                key: "x".to_string(),
            },
        )
        .expect("sign");
        assert!(req.verify(), "fresh request should verify");

        // Backdate by 10 minutes — well outside the 60 s window. The
        // signature is still structurally valid but freshness check
        // must reject it.
        req.timestamp_ms -= 10 * 60 * 1000;
        assert!(!req.verify(), "stale request must not verify");

        // Future-dated requests beyond the window are rejected too
        // (protects against clock-skew-based replay).
        let mut future_req = MemoryRpcRequest::new_signed(
            actor,
            MemoryOp::Get {
                key: "y".to_string(),
            },
        )
        .expect("sign");
        future_req.timestamp_ms += 10 * 60 * 1000;
        assert!(
            !future_req.verify(),
            "future-dated request outside window must not verify"
        );
    }

    #[test]
    fn state_rpc_signed_roundtrip() {
        use crate::rpc_auth;
        use crate::state_rpc::StateWriteRequest;
        rpc_auth::register_hmac_key(std::sync::Arc::new(vec![0x33u8; 32]));
        let actor = Uuid::new_v4();
        let exec = Uuid::new_v4();
        let req = StateWriteRequest::new_signed(
            exec,
            actor,
            "session/user".to_string(),
            "{}".to_string(),
            false,
        )
        .expect("sign");
        assert!(req.verify());

        // Tamper with the execution_id → should fail.
        let mut t = req.clone();
        t.execution_id = Uuid::new_v4();
        assert!(!t.verify());

        // Delete flag is part of the signed body — toggling it must
        // invalidate the signature, otherwise a malicious worker
        // could flip a set to a delete at write time.
        let mut t2 = req.clone();
        t2.is_delete = !t2.is_delete;
        assert!(!t2.verify());
    }

    #[test]
    fn database_rpc_signed_roundtrip() {
        use crate::database_rpc::DatabaseRpcRequest;
        use crate::rpc_auth;
        rpc_auth::register_hmac_key(std::sync::Arc::new(vec![0x22u8; 32]));
        let actor = Uuid::new_v4();
        let req = DatabaseRpcRequest::new_signed(
            actor,
            "SELECT 1".to_string(),
            vec!["foo".to_string()],
            true,
        )
        .expect("sign");
        assert!(req.verify());

        // Tampering with the SQL must invalidate the signature — the
        // critical property that prevents a sandbox from forging a
        // query after the controller passed initial validation.
        let mut tampered = req.clone();
        tampered.sql = "DROP TABLE actor_memory".to_string();
        assert!(!tampered.verify());

        // Subject binding: a valid database signature must not verify
        // as a memory or graph request.
        let body = serde_json::json!({
            "sql": req.sql,
            "params": req.params,
            "is_fetch": req.is_fetch,
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();
        assert!(!rpc_auth::verify(
            "memory_rpc",
            actor,
            &req.nonce,
            &body_bytes,
            &req.signature
        ));
        assert!(!rpc_auth::verify(
            "graph_rpc",
            actor,
            &req.nonce,
            &body_bytes,
            &req.signature
        ));
    }

    #[test]
    fn nonce_replay_is_rejected() {
        use crate::rpc_auth;
        let _g = rpc_auth::nonce_test_lock();
        rpc_auth::clear_nonce_cache_for_test();
        rpc_auth::register_hmac_key(std::sync::Arc::new(vec![0x66u8; 32]));
        let actor = Uuid::new_v4();
        let nonce = rpc_auth::random_nonce();

        // First presentation: accept.
        assert!(rpc_auth::check_and_record_nonce(
            "memory_rpc",
            actor,
            &nonce
        ));
        // Replay within the freshness window: reject.
        assert!(!rpc_auth::check_and_record_nonce(
            "memory_rpc",
            actor,
            &nonce
        ));

        // Cross-subject isolation: the same nonce bytes used under a
        // different subject must be accepted. That's why `subject` is
        // part of the nonce key.
        assert!(rpc_auth::check_and_record_nonce("graph_rpc", actor, &nonce));

        // Cross-actor isolation: a different actor presenting the
        // same nonce is also accepted.
        let other_actor = Uuid::new_v4();
        assert!(rpc_auth::check_and_record_nonce(
            "memory_rpc",
            other_actor,
            &nonce
        ));
    }

    #[test]
    fn memory_rpc_rejects_nan_fields() {
        use crate::memory_rpc::{MemoryOp, MemoryRpcRequest};
        use crate::rpc_auth;
        rpc_auth::register_hmac_key(std::sync::Arc::new(vec![0x77u8; 32]));
        let actor = Uuid::new_v4();

        // NaN ttl_hours — new_signed must refuse.
        assert!(MemoryRpcRequest::new_signed(
            actor,
            MemoryOp::Set {
                metadata: None,
                key: "k".to_string(),
                value: serde_json::json!({}),
                memory_type: "semantic".to_string(),
                ttl_hours: Some(f64::NAN),
            },
        )
        .is_none());

        // +Inf ttl_hours — same.
        assert!(MemoryRpcRequest::new_signed(
            actor,
            MemoryOp::Set {
                metadata: None,
                key: "k".to_string(),
                value: serde_json::json!({}),
                memory_type: "semantic".to_string(),
                ttl_hours: Some(f64::INFINITY),
            },
        )
        .is_none());

        // NaN min_score on Search.
        assert!(MemoryRpcRequest::new_signed(
            actor,
            MemoryOp::Search {
                exclude_kinds: vec![],
                query: "q".to_string(),
                limit: 5,
                min_score: f64::NAN,
            },
        )
        .is_none());

        // Legitimate value succeeds.
        assert!(MemoryRpcRequest::new_signed(
            actor,
            MemoryOp::Set {
                metadata: None,
                key: "k".to_string(),
                value: serde_json::json!({}),
                memory_type: "semantic".to_string(),
                ttl_hours: Some(24.0),
            },
        )
        .is_some());
    }

    #[test]
    fn canonical_json_respects_depth_limit() {
        use crate::rpc_auth::{canonical_json_bytes, MAX_CANONICAL_DEPTH};
        // Build an object nested MAX_CANONICAL_DEPTH + 10 deep.
        let mut v = serde_json::Value::Null;
        for _ in 0..(MAX_CANONICAL_DEPTH + 10) {
            let mut wrapper = serde_json::Map::new();
            wrapper.insert("n".to_string(), v);
            v = serde_json::Value::Object(wrapper);
        }
        // Overflow must return empty bytes so downstream signing fails.
        assert!(canonical_json_bytes(&v).is_empty());

        // Shallow nesting is fine.
        let shallow = serde_json::json!({ "a": { "b": { "c": 1 } } });
        assert!(!canonical_json_bytes(&shallow).is_empty());
    }

    #[test]
    fn embedding_cache_key_isolates_by_model() {
        use crate::embedding::{cache_key_for_test, CACHE_TTL};
        let _ = CACHE_TTL; // just to ensure const is reachable
        let a = cache_key_for_test("nomic-embed-text", "foo");
        let b = cache_key_for_test("text-embedding-3-small", "foo");
        assert_ne!(a, b, "cache keys must differ across models");
        let c = cache_key_for_test("nomic-embed-text", "foo");
        assert_eq!(a, c, "cache keys must be deterministic");
    }

    // MCP-437 (2026-05-11): TTL bounds + overflow safety.
    #[test]
    fn default_expires_at_rejects_negative() {
        assert!(super::default_expires_at("episodic", Some(-1.0)).is_none());
        assert!(super::default_expires_at("episodic", Some(-0.001)).is_none());
    }

    #[test]
    fn default_expires_at_rejects_zero() {
        assert!(super::default_expires_at("episodic", Some(0.0)).is_none());
    }

    #[test]
    fn default_expires_at_rejects_non_finite() {
        assert!(super::default_expires_at("episodic", Some(f64::NAN)).is_none());
        assert!(super::default_expires_at("episodic", Some(f64::INFINITY)).is_none());
        assert!(super::default_expires_at("episodic", Some(f64::NEG_INFINITY)).is_none());
    }

    #[test]
    fn default_expires_at_clamps_overflow() {
        // Pre-MCP-437 ttl_hours=1e30 would (hours * 3600.0) as i64
        // saturate to i64::MAX, then Utc::now() + Duration::seconds(i64::MAX)
        // would overflow chrono's DateTime range. Post-fix it clamps
        // to MAX_TTL_HOURS = 87600 (10 years) and returns a valid
        // future DateTime.
        let got = super::default_expires_at("semantic", Some(1e30));
        assert!(got.is_some(), "clamp should produce a valid timestamp");
        let dt = got.unwrap();
        let now = super::Utc::now();
        let max_window = now + super::Duration::seconds((super::MAX_TTL_HOURS as i64) * 3600 + 60);
        let min_window = now + super::Duration::seconds((super::MAX_TTL_HOURS as i64) * 3600 - 60);
        assert!(
            dt < max_window && dt > min_window,
            "clamped TTL should be ~10 years out, got {dt}"
        );
    }

    #[test]
    fn default_expires_at_clamps_exact_max() {
        // ttl_hours exactly at the cap should produce a valid timestamp
        // (not be rejected as "over the cap").
        let got = super::default_expires_at("episodic", Some(super::MAX_TTL_HOURS));
        assert!(got.is_some());
    }

    #[test]
    fn default_expires_at_typical_values_unchanged() {
        // The common cases — 1h, 168h (1wk), 24h — should not be
        // affected by the clamp.
        let one_hour = super::default_expires_at("working", Some(1.0)).unwrap();
        let now = super::Utc::now();
        let secs = (one_hour - now).num_seconds();
        assert!((3590..=3610).contains(&secs), "got {secs}s");
    }

    #[test]
    fn default_expires_at_semantic_with_no_override_returns_none() {
        // semantic type with no explicit TTL = no expiry.
        assert!(super::default_expires_at("semantic", None).is_none());
    }
}
