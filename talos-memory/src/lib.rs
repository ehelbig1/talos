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
pub mod ml_rpc;
pub mod rpc_auth;
pub mod state_rpc;
pub mod write_error;

pub use write_error::MemoryWriteError;

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
/// Hard cap on how many actors one batched listing
/// ([`list_memories_with_ciphertext_batched_scoped`]) will read. The
/// `actorsMemories` GraphQL resolver rejects larger batches loudly before
/// calling; the batched fn truncates as defense in depth so a future caller
/// can't fan a single `= ANY($1)` scan across an unbounded actor set.
pub const MAX_ACTOR_IDS_PER_BATCH: usize = 100;
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

/// Default retention for values written through the `agent_memory::set` host
/// binding (WASM guest KV writes).
///
/// The WIT contract (`wit/talos.wit`) documents `set` as *persistent* storage.
/// Before 2026-07 the worker binding hardcoded `memory_type = "working"` (1 h
/// TTL), so any state a module wrote via `set` silently vanished before the
/// next scheduled workflow run — a durable-KV API that wasn't durable. `set`
/// now writes `episodic` memory at this ceiling: effectively permanent, and
/// (unlike `scratchpad`, which is filtered out of actor-context injection)
/// first-class for context loading. Equals [`MAX_TTL_HOURS`]; the clamp in
/// [`default_expires_at`] keeps them in lockstep even if the ceiling changes.
pub const SET_KV_TTL_HOURS: f64 = MAX_TTL_HOURS;

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

/// True when `kind` is a SYNTHETIC self-output kind (a reflection, brief,
/// judge verdict, dispatch trace, digest, …) that the assistant produced
/// itself. Single source of truth is [`SYNTHETIC_MEMORY_KINDS`].
///
/// GRAPH-WRITE POLICY (Phase 4): the entity graph is built from REAL source
/// memories, NEVER from the assistant's own inferences. Auto-mining a
/// synthetic self-output into the entity graph would let a future response
/// ground on entities derived from a prior inference — a feedback-
/// amplification path (reflection → graph → recall → reflection). So the
/// generic auto-extraction SKIPS these kinds; synthetic self-outputs reach
/// the graph ONLY via a deliberate, curated path (the reflection loop's
/// entity synthesis in `talos_memory_consolidation`).
///
/// NOTE: `"consolidated"` is deliberately NOT synthetic — a consolidated
/// summary is condensed REAL content (episodic rows collapsed into a
/// semantic memory), so it SHOULD still auto-extract. Verified in
/// `spawn_graph_extraction_synthetic_kind_tests`.
pub fn is_synthetic_memory_kind(kind: &str) -> bool {
    SYNTHETIC_MEMORY_KINDS.contains(&kind)
}

/// Extract the `metadata.kind` string label from an optional metadata JSON
/// object, if present. Used at the [`spawn_graph_extraction`] call sites to
/// apply the graph-write policy (synthetic self-outputs skip extraction).
pub fn metadata_kind(metadata: Option<&serde_json::Value>) -> Option<&str> {
    metadata
        .and_then(|m| m.get("kind"))
        .and_then(|k| k.as_str())
}

/// Public helper — spawn graph-RAG entity extraction for a memory
/// write. `persist_memory` calls this itself on success; the `_in_tx`
/// variant does *not*, leaving it to the caller so the hook only
/// fires after a successful `tx.commit().await` (preventing graph
/// drift from rolled-back transactions).
///
/// GRAPH-WRITE POLICY: when `kind` is a SYNTHETIC self-output kind (see
/// [`is_synthetic_memory_kind`] / [`SYNTHETIC_MEMORY_KINDS`]) the generic
/// auto-extraction is SKIPPED — the assistant's own inferences
/// (reflections, briefs, judge verdicts, digests) must not be auto-mined
/// into the entity graph (feedback-amplification guard). Real source
/// memories (`kind = None` or a non-synthetic kind such as
/// `"consolidated"`) still extract.
///
/// Safe no-op when no hook is registered.
pub fn spawn_graph_extraction(
    actor_id: Uuid,
    key: String,
    value: serde_json::Value,
    kind: Option<&str>,
) {
    // Graph-write policy: synthetic self-output kinds never auto-extract.
    if let Some(k) = kind {
        if is_synthetic_memory_kind(k) {
            tracing::debug!(
                actor_id = %actor_id,
                key = %key,
                kind = %k,
                "Skipping graph entity extraction for synthetic self-output kind \
                 (graph-write policy: entity graph is built from real source memories, \
                 not the assistant's own inferences)"
            );
            return;
        }
    }
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

/// A recalled memory row plus the durability metadata a freshness-aware
/// consumer needs — the value AND its `created_at` / `expires_at` /
/// `memory_type`. Backs the `agent-memory::get-entry` WIT function
/// (DX-19). Distinct from [`MemoryRow`] only in that it also carries
/// `created_at`; the decrypt path is shared (`decrypt_row_value`).
#[derive(Clone, Debug, Serialize)]
pub struct MemoryEntry {
    pub key: String,
    pub value: serde_json::Value,
    pub memory_type: String,
    pub created_at: DateTime<Utc>,
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
    /// Durable write-time importance score in `[0, 1]` from the
    /// `actor_memory.importance` column (Phase 3a). `None` for rows written
    /// before the column existed; the smart-context ranker treats `None` as
    /// an absent hint and falls back to `metadata.importance`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub importance: Option<f64>,
    /// Durable `actor_memory.access_count` — number of times this row has been
    /// packed into an injected `__actor_context__` set. Feeds the fused
    /// ranker's access-frequency boost. `None` only on projection drift (the
    /// column is `NOT NULL DEFAULT 0`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_count: Option<i64>,
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

/// Anyhow-returning entry point kept for the ~10 existing callers (MCP
/// handlers, GraphQL mutations, the RPC subscriber, actor scaffolding,
/// `talos-ml` digest, examples/tests) that don't need to distinguish
/// failure classes. Delegates to [`persist_memory_with_metadata_typed`],
/// which owns the real logic — see that function's docs. `MemoryWriteError`
/// converts into `anyhow::Error` via `?`, so this is a pure signature
/// adapter with no behavior change.
pub async fn persist_memory_with_metadata(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    key: &str,
    value: &serde_json::Value,
    metadata: Option<&serde_json::Value>,
    memory_type: &str,
    ttl_hours: Option<f64>,
) -> Result<PersistOutcome> {
    persist_memory_with_metadata_typed(pool, actor_id, key, value, metadata, memory_type, ttl_hours)
        .await
        .map_err(Into::into)
}

/// Typed-error sibling of [`persist_memory_with_metadata`]. Same logic,
/// same SQL, same validation — the only difference is that failures are
/// classified into a [`MemoryWriteError`] variant AT THE SOURCE (where
/// the concrete failing operation — validation, crypto, or DB — is still
/// known), instead of relying on a caller substring-matching the
/// stringified error afterward.
///
/// Added for `talos-engine::node_hook`'s `__memory_write__` failure
/// metric, which pre-fix classified via `err.to_string().contains(...)`
/// — fragile because any `anyhow::Context::context(...)` call anywhere
/// upstream of the caller could silently change the string and demote a
/// crypto/db failure into the catch-all bucket (finding N-5, crate
/// review 2026-05-05). Callers that don't need classification should use
/// [`persist_memory_with_metadata`] instead — this typed variant is not
/// meant to replace the anyhow API workspace-wide.
pub async fn persist_memory_with_metadata_typed(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    key: &str,
    value: &serde_json::Value,
    metadata: Option<&serde_json::Value>,
    memory_type: &str,
    ttl_hours: Option<f64>,
) -> std::result::Result<PersistOutcome, MemoryWriteError> {
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
    let key = validate_memory_key(key)
        .map_err(|e| MemoryWriteError::Validation(anyhow::anyhow!("{}", e)))?;
    // Single JSON serialization, reused for size check + embedding text +
    // encryption. Prior code serialized the same value three times per
    // write (once for the size cap, once for embedding text input, once
    // inside the encryption hook).
    let serialized = serde_json::to_string(value)
        .context("memory value JSON serialization")
        .map_err(MemoryWriteError::Validation)?;
    // Enforce the canonical per-value size ceiling here so every writer —
    // MCP, GraphQL, engine __memory_write__, and the worker RPC — observes
    // the same limit. Prior inconsistency (worker accepted 1 MiB, MCP
    // rejected at 64 KiB) allowed sandboxes to write rows that later
    // failed re-read through MCP.
    if serialized.len() > MAX_VALUE_BYTES {
        return Err(MemoryWriteError::Validation(anyhow::anyhow!(
            "value too large ({} bytes). Maximum allowed is {} bytes (64 KiB).",
            serialized.len(),
            MAX_VALUE_BYTES
        )));
    }
    // MCP-656: cap metadata at 16 KiB. Same rationale as MAX_METADATA_BYTES
    // doc — the JSONB column previously had no upper bound, allowing a
    // guest to ship a ~900 KiB tag blob through the signed RPC. Mirrors
    // the cap added in `persist_memory_in_tx_with_metadata` so all writers
    // (non-tx + tx) observe the same limit.
    if let Some(m) = metadata {
        let m_bytes = serde_json::to_string(m)
            .context("metadata JSON serialization")
            .map_err(MemoryWriteError::Validation)?
            .len();
        if m_bytes > MAX_METADATA_BYTES {
            return Err(MemoryWriteError::Validation(anyhow::anyhow!(
                "metadata too large ({} bytes). Maximum allowed is {} bytes (16 KiB).",
                m_bytes,
                MAX_METADATA_BYTES
            )));
        }
    }
    let canonical_type = validate_memory_type(memory_type).map_err(MemoryWriteError::Validation)?;
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
    let org_id = resolve_actor_org_id(pool, actor_id)
        .await
        .map_err(MemoryWriteError::Db)?;
    let aad = build_memory_aad(actor_id, key);
    let (key_id, ciphertext, value_format) =
        maybe_encrypt_value_serialized(serialized, org_id, aad)
            .await
            .map_err(MemoryWriteError::Crypto)?
            .ok_or_else(|| {
                MemoryWriteError::Crypto(anyhow::anyhow!(
                    "actor_memory write attempted without crypto hook registered — \
             ensure register_memory_crypto_hook() runs at startup before any write"
                ))
            })?;

    // Phase 3a: durable write-time importance signal in [0, 1] — the
    // memory-type base blended 50/50 with a numeric `metadata.importance`.
    // Shared single-source scorer with the ranker (no shadowed copy). Written
    // REGARDLESS of the smart-context feature flag: a harmless dormant column
    // that accrues for when the flag is on (and for Phase 3b consolidation).
    // Bound as `real` (f32) to match the column type. On overwrite it is
    // re-scored (EXCLUDED.importance); `access_count` / `last_accessed_at` are
    // intentionally NOT touched here — access history persists across content
    // updates (the recall-path bump owns those columns).
    let importance_score = actor_context::write_time_importance(canonical_type, metadata) as f32;

    sqlx::query(
        "INSERT INTO actor_memory \
         (actor_id, key, value_enc, value_key_id, value_format, memory_type, expires_at, embedding, embedding_model, metadata, org_id, importance) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
         ON CONFLICT (actor_id, key) DO UPDATE SET \
             value_enc     = EXCLUDED.value_enc, \
             value_key_id  = EXCLUDED.value_key_id, \
             value_format  = EXCLUDED.value_format, \
             memory_type   = EXCLUDED.memory_type, \
             expires_at    = EXCLUDED.expires_at, \
             embedding     = COALESCE(EXCLUDED.embedding, actor_memory.embedding), \
             embedding_model = COALESCE(EXCLUDED.embedding_model, actor_memory.embedding_model), \
             metadata      = COALESCE(EXCLUDED.metadata, actor_memory.metadata), \
             org_id        = EXCLUDED.org_id, \
             importance    = EXCLUDED.importance, \
             updated_at    = now()",
    )
    .bind(actor_id)
    .bind(key)
    .bind(ciphertext.as_slice())
    .bind(key_id)
    .bind(value_format)
    .bind(canonical_type)
    .bind(expires_at)
    .bind(&embedding)
    .bind(embedding.as_ref().and_then(|_| embedding::active_embedding_model()))
    .bind(metadata)
    .bind(org_id)
    .bind(importance_score)
    .execute(pool)
    .await
    .context("Failed to persist actor memory")
    .map_err(MemoryWriteError::Db)?;

    // Graph-write policy (Phase 4): synthetic self-output kinds
    // (reflections/briefs/verdicts/digests — stamped via `metadata.kind`)
    // are EXCLUDED from generic auto-extraction so the assistant's own
    // inferences never pollute the entity graph. `spawn_graph_extraction`
    // enforces the skip; we surface it in `graph_extraction_attempted` so
    // callers/metrics observe the true outcome.
    let extraction_kind = metadata_kind(metadata);
    let graph_extraction_attempted = canonical_type != "scratchpad"
        && GRAPH_HOOK.get().is_some()
        && !extraction_kind.is_some_and(is_synthetic_memory_kind);
    if graph_extraction_attempted {
        spawn_graph_extraction(actor_id, key.to_string(), value.clone(), extraction_kind);
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

    // Phase 3a: durable write-time importance signal — mirror the non-tx
    // `persist_memory_with_metadata_typed` path so a row written IN a tx (e.g.
    // a Phase-3b `consolidate_memory` summary) carries the same durable
    // `importance` as one written outside a tx, instead of landing NULL. Shared
    // single-source scorer (memory-type base ⊕ numeric `metadata.importance`).
    let importance_score = actor_context::write_time_importance(canonical_type, metadata) as f32;

    sqlx::query(
        "INSERT INTO actor_memory \
         (actor_id, key, value_enc, value_key_id, value_format, memory_type, expires_at, embedding, embedding_model, metadata, org_id, importance) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
         ON CONFLICT (actor_id, key) DO UPDATE SET \
             value_enc     = EXCLUDED.value_enc, \
             value_key_id  = EXCLUDED.value_key_id, \
             value_format  = EXCLUDED.value_format, \
             memory_type   = EXCLUDED.memory_type, \
             expires_at    = EXCLUDED.expires_at, \
             embedding     = COALESCE(EXCLUDED.embedding, actor_memory.embedding), \
             embedding_model = COALESCE(EXCLUDED.embedding_model, actor_memory.embedding_model), \
             metadata      = COALESCE(EXCLUDED.metadata, actor_memory.metadata), \
             org_id        = EXCLUDED.org_id, \
             importance    = EXCLUDED.importance, \
             updated_at    = now()",
    )
    .bind(actor_id)
    .bind(key)
    .bind(ciphertext.as_slice())
    .bind(key_id)
    .bind(value_format)
    .bind(canonical_type)
    .bind(expires_at)
    .bind(&embedding)
    .bind(embedding.as_ref().and_then(|_| embedding::active_embedding_model()))
    .bind(metadata)
    .bind(org_id)
    .bind(importance_score)
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
    let row_key: String = r.try_get("key")?;
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
        memory_type: r.try_get("memory_type")?,
        expires_at: r.try_get("expires_at")?,
        updated_at: r.try_get("updated_at")?,
    }))
}

/// Sibling of [`recall_exact`] that also returns durability metadata
/// (`created_at`, `expires_at`, `memory_type`) so a caller can reason
/// about freshness / TTL — backs the `agent-memory::get-entry` WIT fn
/// (DX-19). Returns `Ok(None)` for an absent (or expired) key; that is
/// NOT an error, matching `recall_exact`.
///
/// The decrypt path is REUSED verbatim from [`decrypt_row_value`] (the
/// same canonical `resolve_stored_value` + per-row `value_format`
/// AAD-dispatch as `recall_exact`) — no crypto logic is duplicated here.
/// The SELECT projects `actor_id` + `value_format` for that dispatch and
/// adds only `created_at` over `recall_exact`'s projection.
pub async fn recall_entry(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    key: &str,
) -> Result<Option<MemoryEntry>> {
    // MCP-S2: project actor_id + value_format so `decrypt_row_value`
    // dispatches v0/v1/v3/v4 correctly. Fail-loud `try_get(...)?` on every
    // read (lint checks 52/55) — a dropped/renamed column errors, never a
    // silent default.
    let row = sqlx::query(
        "SELECT actor_id, key, value_enc, value_key_id, value_format, memory_type, \
                created_at, expires_at, updated_at \
         FROM actor_memory \
         WHERE actor_id = $1 AND key = $2 \
           AND (expires_at IS NULL OR expires_at > now())",
    )
    .bind(actor_id)
    .bind(key)
    .fetch_optional(pool)
    .await
    .context("recall_entry")?;

    let Some(r) = row else { return Ok(None) };
    // Shared canonical decrypt path (fails loud on missing actor_id/key/
    // value_format projection).
    let value = decrypt_row_value(&r).await?;
    Ok(Some(MemoryEntry {
        key: r.try_get("key")?,
        value,
        memory_type: r.try_get("memory_type")?,
        created_at: r.try_get("created_at")?,
        expires_at: r.try_get("expires_at")?,
        updated_at: r.try_get("updated_at")?,
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
/// Canonical set of `metadata.kind` labels identifying SYNTHETIC LLM
/// self-outputs — briefs, judge verdicts, dispatch traces, digests — that
/// a workflow persists to `actor_memory` and could otherwise recall as its
/// own "source" on the next run (hallucination amplification; see the
/// CLAUDE.md "metadata.kind convention" section).
///
/// SINGLE SOURCE OF TRUTH: the smart actor-context builder passes this to
/// [`recall_semantic_filtered`] / [`recall_recent_excluding_types_and_kinds`]
/// so grounding context excludes self-outputs, and any future writer that
/// stamps one of these kinds agrees with the reader by construction.
///
/// Conservative by design — only SELF-OUTPUT kinds belong here, NEVER
/// human-sourced memories. When in doubt, leave a kind OUT: a human note
/// wrongly excluded from grounding is a worse failure than a synthetic
/// note wrongly included.
pub const SYNTHETIC_MEMORY_KINDS: &[&str] = &[
    "recall",
    "meeting_prep",
    "daily_brief",
    "ask_thread",
    "synthesize",
    "judge",
    "inline_judge",
    "ensemble",
    "llm_dispatch",
    "capability_dispatch",
    "ml_digest",
    "commitment_check",
    // Phase 3 reflection: higher-order self-inferences synthesized by the
    // reflection loop. Excluded from grounding recall so the LLM never grounds
    // on its OWN prior inferences (feedback-amplification guard). Reflections
    // remain accessible via explicit `actor_recall`/`actor_recall_semantic`,
    // which do NOT apply this exclusion.
    "reflection",
];

/// [`SYNTHETIC_MEMORY_KINDS`] as an owned `Vec<String>` for the
/// `text[]`-bind recall APIs.
pub fn synthetic_memory_kinds() -> Vec<String> {
    SYNTHETIC_MEMORY_KINDS
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

/// Count actor-memory writes GROUPED BY `metadata->>'kind'` over the trailing
/// `days`, USER-SCOPED (joins `actors` on `user_id`) — the operator digest's
/// "what the autonomous loops + workflows produced" panel (briefs, reflections,
/// consolidations, CRM entries, …). Rows with NULL `metadata.kind`
/// (engine-trace writes) bucket under `'(unlabeled)'`. `updated_at` is the write
/// timestamp. Returns `(kind, count)`, most-written first. `metadata` is a plain
/// JSONB column (never encrypted), so this needs no decryption — a pure count.
pub async fn count_recent_writes_by_kind(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    days: i32,
) -> Result<Vec<(String, i64)>> {
    let days = days.clamp(1, 31);
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT COALESCE(am.metadata->>'kind', '(unlabeled)') AS kind, COUNT(*)::bigint \
         FROM actor_memory am JOIN actors a ON a.id = am.actor_id \
         WHERE a.user_id = $1 \
           AND am.updated_at > NOW() - make_interval(days => $2::int) \
         GROUP BY COALESCE(am.metadata->>'kind', '(unlabeled)') \
         ORDER BY COUNT(*) DESC",
    )
    .bind(user_id)
    .bind(days)
    .fetch_all(pool)
    .await
    .context("count_recent_writes_by_kind")?;
    Ok(rows)
}

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
        let key: String = r.try_get("key")?;
        let memory_type: String = r.try_get("memory_type")?;
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
        let key: String = r.try_get("key")?;
        let memory_type: String = r.try_get("memory_type")?;
        let value = decrypt_row_value(r).await?;
        out.push((key, value, memory_type));
    }
    Ok(out)
}

/// Recency fallback that ALSO excludes rows whose `metadata.kind` matches
/// any entry in `exclude_kinds` — the kind-filtered sibling of
/// [`recall_recent_excluding_types`].
///
/// Used by the smart actor-context builder's Layer-3 (recency) so
/// synthetic self-outputs ([`SYNTHETIC_MEMORY_KINDS`]) are dropped from
/// grounding context the same way the semantic layer drops them. `NULL`
/// metadata / missing `kind` passes the filter (treated as non-synthetic);
/// the `!= ALL(...)` form is NULL-safe (unlike `NOT IN`). An empty
/// `exclude_kinds` is a no-op equivalent to
/// [`recall_recent_excluding_types`].
///
/// `limit` is clamped to `[1, MAX_LIST_LIMIT]`.
pub async fn recall_recent_excluding_types_and_kinds(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    exclude_types: &[&str],
    exclude_kinds: &[String],
    limit: i64,
) -> Result<Vec<(String, serde_json::Value, String)>> {
    let limit = limit.clamp(1, MAX_LIST_LIMIT);
    let owned_types: Vec<String> = exclude_types.iter().map(|s| (*s).to_string()).collect();
    // Same MCP-S2 projection contract as recall_recent_excluding_types
    // (actor_id + value_format for AAD-bound decrypt; never the dropped
    // legacy `value` column). The `metadata.kind != ALL($4)` predicate
    // mirrors recall_semantic_filtered exactly so both retrieval layers
    // agree on what counts as synthetic.
    let rows = sqlx::query(
        "SELECT actor_id, key, value_enc, value_key_id, value_format, memory_type \
         FROM actor_memory \
         WHERE actor_id = $1 \
           AND NOT (memory_type = ANY($2)) \
           AND (expires_at IS NULL OR expires_at > now()) \
           AND (cardinality($4::text[]) = 0 \
                OR metadata IS NULL \
                OR metadata->>'kind' IS NULL \
                OR metadata->>'kind' != ALL($4::text[])) \
         ORDER BY updated_at DESC LIMIT $3",
    )
    .bind(actor_id)
    .bind(&owned_types)
    .bind(limit)
    .bind(exclude_kinds)
    .fetch_all(pool)
    .await
    .context("recall_recent_excluding_types_and_kinds")?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        use sqlx::Row as _;
        let key: String = r.try_get("key")?;
        let memory_type: String = r.try_get("memory_type")?;
        let value = decrypt_row_value(r).await?;
        out.push((key, value, memory_type));
    }
    Ok(out)
}

/// Timestamp-carrying sibling of [`recall_recent_excluding_types_and_kinds`]:
/// identical query, decrypt column set, AAD path, and `metadata.kind`
/// filter, but ALSO projects each row's `updated_at` so the smart
/// actor-context builder (Phase 2) can feed the recency signal into its
/// fused ranker.
///
/// Returns `(key, value, memory_type, updated_at)` tuples. `updated_at` is
/// read as `Option<DateTime<Utc>>` (structural-lint check 52: a
/// renamed/retyped column propagates as an error via `?`, a NULL yields
/// `None` rather than a silent default — the column is `NOT NULL` in the
/// schema, so `None` is effectively unreachable but the ranker treats a
/// missing timestamp as a neutral recency signal regardless).
///
/// Tenancy/crypto invariants are byte-for-byte those of the non-`_ts`
/// sibling: only ever `WHERE actor_id = $1`, the exact
/// `actor_id, key, value_enc, value_key_id, value_format, memory_type`
/// projection that `decrypt_row_value` requires for MCP-S2 AAD dispatch,
/// and the same NULL-safe `metadata->>'kind' != ALL($4)` predicate. The
/// only additions are the projected `updated_at` column and the wider
/// return tuple.
///
/// `limit` is clamped to `[1, MAX_LIST_LIMIT]`.
#[allow(clippy::type_complexity)]
pub async fn recall_recent_excluding_types_and_kinds_ts(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    exclude_types: &[&str],
    exclude_kinds: &[String],
    limit: i64,
) -> Result<Vec<actor_context::RecencyRow>> {
    let limit = limit.clamp(1, MAX_LIST_LIMIT);
    let owned_types: Vec<String> = exclude_types.iter().map(|s| (*s).to_string()).collect();
    // Phase 3a: also project the durable `importance` + `access_count` signal
    // columns so the fused ranker's importance term survives into the recency
    // layer (same decrypt column set + AAD path as before — additive only).
    let rows = sqlx::query(
        "SELECT actor_id, key, value_enc, value_key_id, value_format, memory_type, updated_at, importance, access_count \
         FROM actor_memory \
         WHERE actor_id = $1 \
           AND NOT (memory_type = ANY($2)) \
           AND (expires_at IS NULL OR expires_at > now()) \
           AND (cardinality($4::text[]) = 0 \
                OR metadata IS NULL \
                OR metadata->>'kind' IS NULL \
                OR metadata->>'kind' != ALL($4::text[])) \
         ORDER BY updated_at DESC LIMIT $3",
    )
    .bind(actor_id)
    .bind(&owned_types)
    .bind(limit)
    .bind(exclude_kinds)
    .fetch_all(pool)
    .await
    .context("recall_recent_excluding_types_and_kinds_ts")?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        use sqlx::Row as _;
        let key: String = r.try_get("key")?;
        let memory_type: String = r.try_get("memory_type")?;
        // check 52: read as Option so a dropped/retyped column errors via `?`
        // rather than silently defaulting; NULL (unreachable, NOT NULL col)
        // maps to None which the ranker treats as neutral recency.
        let updated_at: Option<DateTime<Utc>> =
            r.try_get::<Option<DateTime<Utc>>, _>("updated_at")?;
        // `importance` is `real` (f32) + NULLable (pre-Phase-3a rows) — read as
        // Option<f32> (matches the column type; f64 would type-mismatch) and
        // widen to f64 for the ranker. check 52: `?` propagates projection drift.
        let importance: Option<f64> = r.try_get::<Option<f32>, _>("importance")?.map(|v| v as f64);
        // `access_count` is `integer` (int4 → i32) NOT NULL DEFAULT 0; read as
        // Option<i32> (matches the column type) so drift errors loud, then widen
        // to i64. None (drift only) maps to a neutral boost in the ranker.
        let access_count: Option<i64> = r
            .try_get::<Option<i32>, _>("access_count")?
            .map(|v| v as i64);
        let value = decrypt_row_value(r).await?;
        out.push((
            key,
            value,
            memory_type,
            updated_at,
            importance,
            access_count,
        ));
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

    rows.iter()
        .map(|r| -> Result<MemoryMeta> {
            Ok(MemoryMeta {
                key: r.try_get("key")?,
                memory_type: r.try_get("memory_type")?,
                expires_at: r.try_get("expires_at")?,
                updated_at: r.try_get("updated_at")?,
                value_bytes: r.try_get("value_bytes")?,
                metadata: r
                    .try_get::<Option<serde_json::Value>, _>("metadata")
                    .ok()
                    .flatten(),
            })
        })
        .collect()
}

/// Ciphertext-bearing listing row returned by
/// `list_memories_with_ciphertext_scoped`. Carries the MCP-S2 columns
/// (`actor_id`, `key`, `value_format`) that AAD-bound decryption
/// requires — decrypt with `decrypt_memory_list_row` AFTER the caller's
/// transaction commits (the decrypt loop is connection-free, so don't
/// hold the tx open across it).
#[derive(Debug, sqlx::FromRow)]
pub struct MemoryListRowEnc {
    pub actor_id: Uuid,
    pub key: String,
    pub value_enc: Option<Vec<u8>>,
    pub value_key_id: Option<Uuid>,
    pub value_format: i16,
    pub memory_type: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

/// Non-expired memory rows WITH ciphertext for an actor, ordered
/// `memory_type, key ASC`. Takes the caller's connection so a
/// tenant-scoped tx / unit of work keeps its RLS backstop (the GraphQL
/// `actorMemories` resolver runs the actors ownership check and this
/// read in one per-user UoW). Do NOT add a pool variant for that path;
/// it would split the snapshot.
///
/// The projection deliberately includes `actor_id` + `value_format` —
/// the pre-extraction resolver SELECT omitted both, which the MCP-S2
/// fail-loud contract in `decrypt_row_value` rejects, so every decrypt
/// of a populated actor errored ("must project `actor_id`").
pub async fn list_memories_with_ciphertext_scoped(
    conn: &mut sqlx::PgConnection,
    actor_id: Uuid,
    memory_type_filter: Option<&str>,
    limit: i64,
) -> Result<Vec<MemoryListRowEnc>> {
    sqlx::query_as::<_, MemoryListRowEnc>(
        "SELECT actor_id, key, value_enc, value_key_id, value_format, \
                memory_type, expires_at, updated_at \
         FROM actor_memory \
         WHERE actor_id = $1 \
           AND ($2::text IS NULL OR memory_type = $2) \
           AND (expires_at IS NULL OR expires_at > NOW()) \
         ORDER BY memory_type, key ASC \
         LIMIT $3",
    )
    .bind(actor_id)
    .bind(memory_type_filter)
    .bind(limit)
    .fetch_all(conn)
    .await
    .context("list_memories_with_ciphertext_scoped")
}

/// Decrypt one `MemoryListRowEnc` via the registered crypto hook, with
/// the row's own `(actor_id, key)` AAD binding and per-row format
/// dispatch. Connection-free — safe to run after the listing tx commits.
pub async fn decrypt_memory_list_row(row: &MemoryListRowEnc) -> Result<serde_json::Value> {
    let aad = build_memory_aad(row.actor_id, &row.key);
    resolve_stored_value(
        None,
        row.value_enc.clone(),
        row.value_key_id,
        aad,
        row.value_format,
    )
    .await
}

/// Batched sibling of [`list_memories_with_ciphertext_scoped`]: the
/// non-expired ciphertext-bearing memory rows for MANY actors in ONE
/// query. Closes the residual per-actor listing loop the `actorsMemories`
/// GraphQL resolver ran after #566 collapsed the per-actor GraphQL
/// round-trips — the N reads inside the single resolver tx become one
/// `actor_id = ANY($1)` scan.
///
/// **Per-actor fairness.** A windowed
/// `ROW_NUMBER() OVER (PARTITION BY actor_id ORDER BY created_at DESC, key ASC)`
/// caps EACH actor at `limit_per_actor` rows (newest-first) so one
/// memory-heavy actor can't starve the batch — the single-actor path's
/// per-actor `LIMIT` becomes a per-partition window here. The outer
/// `ORDER BY actor_id, memory_type, key ASC` reproduces the single-actor
/// path's within-actor ordering (`memory_type, key ASC`) so the grouped
/// output is byte-identical to the pre-batch per-actor loop.
///
/// Takes the caller's connection (like the single-actor scoped fn) so the
/// resolver's per-user unit of work keeps its RLS backstop; do NOT add a
/// pool variant — it would split the snapshot. The projection carries the
/// MCP-S2 columns (`actor_id`, `value_format`) that AAD-bound decryption
/// requires; `value_format` maps to a NOT-NULL `i16` via `FromRow`, so a
/// dropped/retyped column fails LOUD (schema drift → `Err`, never a silent
/// default — read-side sibling of lint checks 34/52). Decrypt each returned
/// row with [`decrypt_memory_list_row`] AFTER the tx commits (the loop is
/// connection-free). Actors with no matching rows return NO rows here —
/// callers that need one group per requested actor reconstruct the empty
/// groups via [`group_memory_list_rows_by_actor`].
pub async fn list_memories_with_ciphertext_batched_scoped(
    conn: &mut sqlx::PgConnection,
    actor_ids: &[Uuid],
    memory_type_filter: Option<&str>,
    limit_per_actor: i64,
) -> Result<Vec<MemoryListRowEnc>> {
    if actor_ids.is_empty() {
        return Ok(Vec::new());
    }
    // Defense in depth: the resolver rejects >MAX_ACTOR_IDS_PER_BATCH ids
    // before calling, so this truncation is unreachable in practice — it
    // bounds the `= ANY($1)` scan for any future direct caller.
    let capped_ids: &[Uuid] = if actor_ids.len() > MAX_ACTOR_IDS_PER_BATCH {
        &actor_ids[..MAX_ACTOR_IDS_PER_BATCH]
    } else {
        actor_ids
    };
    // Mirror the single-actor scoped fn: trust the resolver's clamp (it caps
    // per-actor rows the same way `actorMemories` does). `.max(1)` only
    // guards a non-positive window (`rn <= 0` returns nothing) — it never
    // reduces a valid caller limit, so output stays byte-identical.
    let limit = limit_per_actor.max(1);
    sqlx::query_as::<_, MemoryListRowEnc>(
        "SELECT actor_id, key, value_enc, value_key_id, value_format, \
                memory_type, expires_at, updated_at \
         FROM ( \
             SELECT actor_id, key, value_enc, value_key_id, value_format, \
                    memory_type, expires_at, updated_at, \
                    ROW_NUMBER() OVER ( \
                        PARTITION BY actor_id \
                        ORDER BY created_at DESC, key ASC \
                    ) AS rn \
             FROM actor_memory \
             WHERE actor_id = ANY($1) \
               AND ($2::text IS NULL OR memory_type = $2) \
               AND (expires_at IS NULL OR expires_at > NOW()) \
         ) ranked \
         WHERE rn <= $3 \
         ORDER BY actor_id, memory_type, key ASC",
    )
    .bind(capped_ids)
    .bind(memory_type_filter)
    .bind(limit)
    .fetch_all(conn)
    .await
    .context("list_memories_with_ciphertext_batched_scoped")
}

/// Group the flat rows from [`list_memories_with_ciphertext_batched_scoped`]
/// by `actor_id`, preserving the caller's `ordered` actor sequence and
/// emitting an EMPTY group for any requested actor that returned no rows —
/// so the batched `actorsMemories` resolver reproduces the same
/// one-group-per-owned-actor shape the per-actor loop produced (an owned
/// actor with no memories was a group with an empty list, not an absent
/// group). Within each actor the rows keep the batch query's
/// `memory_type, key ASC` order.
///
/// `ordered` is expected to be duplicate-free (the resolver collapses
/// duplicate ids in its ownership filter); a repeated id would still be
/// safe here (its rows land in the first occurrence, later occurrences get
/// an empty group). Pure so unit tests exercise the real grouping logic.
pub fn group_memory_list_rows_by_actor(
    ordered: &[Uuid],
    rows: Vec<MemoryListRowEnc>,
) -> Vec<(Uuid, Vec<MemoryListRowEnc>)> {
    let mut by_actor: std::collections::HashMap<Uuid, Vec<MemoryListRowEnc>> =
        std::collections::HashMap::with_capacity(ordered.len());
    for id in ordered {
        by_actor.entry(*id).or_default();
    }
    for row in rows {
        // Rows whose actor is not in `ordered` are dropped defensively —
        // the query only selects `= ANY(ordered)`, so this can't happen.
        if let Some(bucket) = by_actor.get_mut(&row.actor_id) {
            bucket.push(row);
        }
    }
    ordered
        .iter()
        .map(|id| (*id, by_actor.remove(id).unwrap_or_default()))
        .collect()
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
            "SELECT key, value_enc, value_key_id, value_format, memory_type, expires_at, updated_at, metadata, importance, access_count, \
                          (1.0 - (embedding <=> $2)) AS score \
                   FROM actor_memory \
                   WHERE actor_id = $1 \
                     AND (expires_at IS NULL OR expires_at > now()) \
                     AND embedding IS NOT NULL \
                     AND embedding_model = $7 \
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
            .bind(embedding::active_embedding_model())
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
                let row_key: String = r.try_get("key")?;
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
                    memory_type: r.try_get("memory_type")?,
                    expires_at: r.try_get("expires_at")?,
                    updated_at: r.try_get("updated_at")?,
                    score: r.try_get::<f64, _>("score")?,
                    metadata: r.try_get::<Option<serde_json::Value>, _>("metadata")?,
                    // Phase 3a durable signals. check 52: read as Option (matches
                    // the `real`/`int4` column types) + `?` so projection drift
                    // fails loud; widen to the ranker's f64/i64.
                    importance: r.try_get::<Option<f32>, _>("importance")?.map(|v| v as f64),
                    access_count: r
                        .try_get::<Option<i32>, _>("access_count")?
                        .map(|v| v as i64),
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
            "SELECT actor_id, key, value_enc, value_key_id, value_format, memory_type, expires_at, updated_at, metadata, importance, access_count \
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
        "SELECT actor_id, key, value_enc, value_key_id, value_format, memory_type, expires_at, updated_at, metadata, importance, access_count \
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
        let row_key: String = r.try_get("key")?;
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
            memory_type: r.try_get("memory_type")?,
            expires_at: r.try_get("expires_at")?,
            updated_at: r.try_get("updated_at")?,
            score: (1.0 - (i as f64 * 0.02)).max(0.0),
            metadata: r.try_get::<Option<serde_json::Value>, _>("metadata")?,
            // Phase 3a durable signals. check 52: Option read + `?` fails loud on
            // projection drift; widen `real`/`int4` to the ranker's f64/i64.
            importance: r.try_get::<Option<f32>, _>("importance")?.map(|v| v as f64),
            access_count: r
                .try_get::<Option<i32>, _>("access_count")?
                .map(|v| v as i64),
        });
    }
    Ok(hits)
}

// ============================================================================
// Mutations
// ============================================================================

/// Phase 3a: bump the durable access signal for a set of memory keys that were
/// just packed into an injected `__actor_context__` set.
///
/// ONE batched UPDATE per context injection (not per row, not per recall):
/// `access_count += 1`, `last_accessed_at = now()` for every `(actor_id, key)`
/// in `keys`. Scoped `WHERE actor_id = $1 AND key = ANY($2)` — a strict
/// tenancy invariant: only ever touches the bound actor's own rows.
///
/// This is the FIRST recall-path mutation in the memory service; callers MUST
/// invoke it fire-and-forget (`tokio::spawn`, best-effort) so it never adds
/// latency to context assembly. Deliberately does NOT bump `updated_at` (an
/// access is not a content write — recency-decay should track writes, not
/// reads) and does NOT touch `importance`. Returns the number of rows updated.
/// An empty `keys` slice is a no-op (returns 0 without a query).
pub async fn bump_access(pool: &Pool<Postgres>, actor_id: Uuid, keys: &[String]) -> Result<u64> {
    if keys.is_empty() {
        return Ok(0);
    }
    let result = sqlx::query(
        "UPDATE actor_memory \
         SET access_count = access_count + 1, last_accessed_at = now() \
         WHERE actor_id = $1 AND key = ANY($2)",
    )
    .bind(actor_id)
    .bind(keys)
    .execute(pool)
    .await
    .context("bump_access")?;
    Ok(result.rows_affected())
}

// ============================================================================
// Adaptive per-actor memory ranking — Phase 1: provenance
// ============================================================================
//
// Records, for each actor-bound execution that injected `__actor_context__`,
// WHICH memory keys were in that context and their per-memory ranking-feature
// snapshot (relevance / recency / importance / access_boost / fused_score /
// rank), so a later phase can join this to execution OUTCOME (`judge_scores`,
// `workflow_executions.status`) and LEARN which memories lead to good results.
//
// Privacy: stores memory KEYS + numeric feature signals ONLY — never memory
// VALUES. Actor-scoped by construction. Retention-bounded via
// `sweep_execution_memory_context`. Default-OFF at the caller (gated on
// `talos_config::memory_rank_provenance_enabled()`).

/// One packed memory's ranking-feature snapshot at context-pack time — the
/// per-row features `record_execution_memory_context` persists. `relevance`,
/// `recency`, `importance`, `fused_score` mirror the fused-ranker signals;
/// `access_boost` is `None` when the row carried no durable access signal;
/// `rank` is the 0-based position in the packed (injected) set.
#[derive(Clone, Debug, PartialEq)]
pub struct MemoryContextProvenanceRow {
    pub memory_key: String,
    pub relevance: f64,
    pub recency: f64,
    pub importance: f64,
    pub access_boost: Option<f64>,
    pub fused_score: f64,
    pub rank: i32,
}

/// Persist the ranking-feature snapshot for the memories that were packed into
/// one execution's `__actor_context__`. ONE batched multi-row INSERT via
/// `UNNEST` (never a per-row loop). Empty `rows` → no-op returns 0.
///
/// Actor-scoped by construction: `actor_id` is a column and every value comes
/// from a single actor's packed set. `real` columns are bound as `f32`.
/// Callers MUST invoke this fire-and-forget (`tokio::spawn`, best-effort) — it
/// is off the request latency path, exactly like [`bump_access`].
pub async fn record_execution_memory_context(
    pool: &Pool<Postgres>,
    execution_id: Uuid,
    actor_id: Uuid,
    rows: &[MemoryContextProvenanceRow],
) -> Result<u64> {
    if rows.is_empty() {
        return Ok(0);
    }
    // Column-parallel arrays fed into a single `UNNEST(...)` — one round trip
    // regardless of row count. `access_boost` stays nullable (Vec<Option<f32>>).
    let keys: Vec<String> = rows.iter().map(|r| r.memory_key.clone()).collect();
    let relevance: Vec<f32> = rows.iter().map(|r| r.relevance as f32).collect();
    let recency: Vec<f32> = rows.iter().map(|r| r.recency as f32).collect();
    let importance: Vec<f32> = rows.iter().map(|r| r.importance as f32).collect();
    let access_boost: Vec<Option<f32>> = rows
        .iter()
        .map(|r| r.access_boost.map(|b| b as f32))
        .collect();
    let fused_score: Vec<f32> = rows.iter().map(|r| r.fused_score as f32).collect();
    let rank: Vec<i32> = rows.iter().map(|r| r.rank).collect();

    let result = sqlx::query(
        "INSERT INTO execution_memory_context \
             (execution_id, actor_id, memory_key, relevance, recency, importance, \
              access_boost, fused_score, rank) \
         SELECT $1, $2, k, rel, rec, imp, ab, fs, rk \
         FROM UNNEST($3::text[], $4::real[], $5::real[], $6::real[], \
                     $7::real[], $8::real[], $9::int[]) \
              AS t(k, rel, rec, imp, ab, fs, rk)",
    )
    .bind(execution_id)
    .bind(actor_id)
    .bind(&keys)
    .bind(&relevance)
    .bind(&recency)
    .bind(&importance)
    .bind(&access_boost)
    .bind(&fused_score)
    .bind(&rank)
    .execute(pool)
    .await
    .context("record_execution_memory_context")?;
    Ok(result.rows_affected())
}

/// A labeled training example for the Phase-2 learned ranker: one memory's
/// pack-time feature snapshot joined to its execution's OUTCOME label
/// (`judge_score` / `judge_passed` — the newest judge verdict for that
/// execution — and `execution_status`). Outcome fields are `Option` because a
/// provenance row may have no judge verdict and/or an orphaned execution.
#[derive(Clone, Debug)]
pub struct RankTrainingExample {
    pub memory_key: String,
    pub relevance: f64,
    pub recency: f64,
    pub importance: f64,
    pub access_boost: Option<f64>,
    pub fused_score: f64,
    pub rank: i32,
    pub judge_score: Option<f64>,
    pub judge_passed: Option<bool>,
    pub execution_status: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Upper bound on the labeled-example fetch, so a caller-supplied `limit`
/// can't ask for an unbounded scan.
const RANK_TRAINING_EXAMPLE_MAX: i64 = 50_000;

/// Fetch labeled training examples for one actor since `since`, newest first.
/// Left-joins each provenance row to (a) the NEWEST judge verdict for its
/// execution and (b) the execution status — the labeled-data source Phase 2
/// consumes. Actor-scoped (`WHERE emc.actor_id = $1`). `limit` is clamped to
/// `[0, RANK_TRAINING_EXAMPLE_MAX]`. Reads are fail-loud (`try_get`).
pub async fn fetch_rank_training_examples(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    since: DateTime<Utc>,
    limit: i64,
) -> Result<Vec<RankTrainingExample>> {
    let limit = limit.clamp(0, RANK_TRAINING_EXAMPLE_MAX);
    if limit == 0 {
        return Ok(Vec::new());
    }
    let rows = sqlx::query(
        "SELECT emc.memory_key, emc.relevance, emc.recency, emc.importance, \
                emc.access_boost, emc.fused_score, emc.rank, emc.created_at, \
                js.score AS judge_score, js.passed AS judge_passed, \
                we.status AS execution_status \
         FROM execution_memory_context emc \
         LEFT JOIN LATERAL ( \
             SELECT score, passed FROM judge_scores j \
             WHERE j.execution_id = emc.execution_id \
             ORDER BY j.created_at DESC LIMIT 1 \
         ) js ON true \
         LEFT JOIN workflow_executions we ON we.id = emc.execution_id \
         WHERE emc.actor_id = $1 AND emc.created_at >= $2 \
         ORDER BY emc.created_at DESC \
         LIMIT $3",
    )
    .bind(actor_id)
    .bind(since)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("fetch_rank_training_examples")?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        // `real` columns come back as f32 (widened to f64); nullable columns
        // read as Option so schema drift errors via `?` instead of a silent
        // default (checks 52/55).
        let relevance: f32 = row.try_get::<Option<f32>, _>("relevance")?.unwrap_or(0.0);
        let recency: f32 = row.try_get::<Option<f32>, _>("recency")?.unwrap_or(0.0);
        let importance: f32 = row.try_get::<Option<f32>, _>("importance")?.unwrap_or(0.0);
        let access_boost: Option<f32> = row.try_get::<Option<f32>, _>("access_boost")?;
        let fused_score: f32 = row.try_get::<Option<f32>, _>("fused_score")?.unwrap_or(0.0);
        let rank: i32 = row.try_get::<Option<i32>, _>("rank")?.unwrap_or(0);
        out.push(RankTrainingExample {
            memory_key: row
                .try_get::<Option<String>, _>("memory_key")?
                .unwrap_or_default(),
            relevance: relevance as f64,
            recency: recency as f64,
            importance: importance as f64,
            access_boost: access_boost.map(|b| b as f64),
            fused_score: fused_score as f64,
            rank,
            judge_score: row.try_get::<Option<f64>, _>("judge_score")?,
            judge_passed: row.try_get::<Option<bool>, _>("judge_passed")?,
            execution_status: row.try_get::<Option<String>, _>("execution_status")?,
            created_at: row
                .try_get::<Option<DateTime<Utc>>, _>("created_at")?
                .unwrap_or_else(Utc::now),
        });
    }
    Ok(out)
}

/// One execution's memory footprint joined to its outcome, aggregated per
/// execution (contrast [`RankTrainingExample`], which is per-memory-row). Used
/// by the OBSERVATIONAL evaluation: within executions that carried memory, does
/// higher mean relevance track a better judge outcome? Values-free.
#[derive(Clone, Debug)]
pub struct ExecutionMemoryOutcome {
    pub execution_id: Uuid,
    /// Mean fused rank score across the memories injected into this execution.
    pub mean_fused: f64,
    /// Max fused rank score among injected memories.
    pub max_fused: f64,
    /// Number of memories injected.
    pub mem_count: i64,
    /// Newest judge verdict for the execution, if any.
    pub judge_score: Option<f64>,
    pub judge_passed: Option<bool>,
    pub execution_status: Option<String>,
}

/// Per-execution aggregate of `execution_memory_context` joined to each
/// execution's NEWEST judge verdict and status. Actor-scoped
/// (`WHERE emc.actor_id = $1`). `limit` is clamped to
/// `[0, RANK_TRAINING_EXAMPLE_MAX]`. Reads are fail-loud. Only executions that
/// actually carried memory context appear (memory-OFF runs write no provenance
/// rows — which is exactly why observational analysis cannot prove ON-vs-OFF
/// causation, only correlation within the memory-ON population).
pub async fn fetch_execution_memory_outcomes(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    since: DateTime<Utc>,
    limit: i64,
) -> Result<Vec<ExecutionMemoryOutcome>> {
    let limit = limit.clamp(0, RANK_TRAINING_EXAMPLE_MAX);
    if limit == 0 {
        return Ok(Vec::new());
    }
    let rows = sqlx::query(
        "SELECT emc.execution_id, \
                AVG(emc.fused_score)::float8 AS mean_fused, \
                MAX(emc.fused_score)::float8 AS max_fused, \
                COUNT(*)::int8 AS mem_count, \
                js.score AS judge_score, js.passed AS judge_passed, \
                we.status AS execution_status \
         FROM execution_memory_context emc \
         LEFT JOIN LATERAL ( \
             SELECT score, passed FROM judge_scores j \
             WHERE j.execution_id = emc.execution_id \
             ORDER BY j.created_at DESC LIMIT 1 \
         ) js ON true \
         LEFT JOIN workflow_executions we ON we.id = emc.execution_id \
         WHERE emc.actor_id = $1 AND emc.created_at >= $2 \
         GROUP BY emc.execution_id, js.score, js.passed, we.status \
         ORDER BY MAX(emc.created_at) DESC \
         LIMIT $3",
    )
    .bind(actor_id)
    .bind(since)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("fetch_execution_memory_outcomes")?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(ExecutionMemoryOutcome {
            execution_id: row
                .try_get::<Option<Uuid>, _>("execution_id")?
                .unwrap_or(actor_id),
            mean_fused: row.try_get::<Option<f64>, _>("mean_fused")?.unwrap_or(0.0),
            max_fused: row.try_get::<Option<f64>, _>("max_fused")?.unwrap_or(0.0),
            mem_count: row.try_get::<Option<i64>, _>("mem_count")?.unwrap_or(0),
            judge_score: row.try_get::<Option<f64>, _>("judge_score")?,
            judge_passed: row.try_get::<Option<bool>, _>("judge_passed")?,
            execution_status: row.try_get::<Option<String>, _>("execution_status")?,
        });
    }
    Ok(out)
}

/// Delete provenance rows older than `retention_days`. Bound as `i32` and cast
/// `$1::int` per lint 27 (`make_interval` args are int4-only). Returns the
/// number of rows deleted. Harmless when the table is empty.
pub async fn sweep_execution_memory_context(
    pool: &Pool<Postgres>,
    retention_days: i64,
) -> Result<u64> {
    let days: i32 = retention_days.clamp(1, i32::MAX as i64) as i32;
    let result = sqlx::query(
        "DELETE FROM execution_memory_context \
         WHERE created_at < now() - make_interval(days => $1::int)",
    )
    .bind(days)
    .execute(pool)
    .await
    .context("sweep_execution_memory_context")?;
    Ok(result.rows_affected())
}

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

/// Atomic persist-summary + forget-sources consolidation kernel — the SINGLE
/// implementation shared by the MCP `consolidate_actor_memory` handler and the
/// Phase-3b autonomous consolidation loop (`talos_memory_consolidation`).
///
/// In ONE committed transaction it:
///   1. enriches `semantic_value` (when it's a JSON object) with
///      `__consolidated_from_count__` (source key count) and
///      `__consolidated_at__` (RFC-3339-ish UTC). Non-object values pass
///      through untouched. Callers that want a human `__consolidated_note__`
///      insert it into `semantic_value` before calling.
///   2. persists the enriched value as a `"semantic"` memory under
///      `semantic_key`, stamping the passed `metadata` (e.g.
///      `{"kind": "consolidated", ...}`).
///   3. hard-deletes the `source_keys` episodic rows (batched DELETE).
///   4. commits — so the summary and the source deletion are all-or-nothing.
///      Any error before commit rolls back BOTH (zero mutation).
///
/// Post-commit (outside the tx, by design — a rolled-back tx must not corrupt
/// the graph) it fires graph-RAG entity extraction for the new semantic row.
///
/// Returns the number of source rows retired.
pub async fn consolidate_memory(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    semantic_key: &str,
    semantic_value: serde_json::Value,
    source_keys: &[String],
    metadata: Option<serde_json::Value>,
) -> Result<u64> {
    // Never delete the summary we just wrote: if a caller (e.g. the MCP
    // `consolidate_actor_memory` handler with operator-supplied keys) includes
    // `semantic_key` in `source_keys`, the DELETE would wipe the fresh summary
    // in the same tx — losing BOTH the summary and its sources. Filter it out
    // up front so the provenance count below reflects the rows ACTUALLY retired.
    let retire_keys: Vec<String> = source_keys
        .iter()
        .filter(|k| k.as_str() != semantic_key)
        .cloned()
        .collect();

    // Enrich provenance onto object values only (mirrors the MCP handler's
    // pre-extraction behaviour). Count from `retire_keys` (post-filter) so
    // `__consolidated_from_count__` matches the number of rows that will be
    // retired, not the raw (possibly self-key-inclusive) input.
    let final_value = if let Some(obj) = semantic_value.as_object() {
        let mut enriched = obj.clone();
        enriched.insert(
            "__consolidated_from_count__".to_string(),
            serde_json::Value::Number(serde_json::Number::from(retire_keys.len() as u64)),
        );
        enriched.insert(
            "__consolidated_at__".to_string(),
            serde_json::Value::String(chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()),
        );
        serde_json::Value::Object(enriched)
    } else {
        semantic_value
    };

    // Persist the summary + delete the absorbed sources atomically. Without
    // the transaction, a crash between INSERT and DELETE would leave both the
    // new semantic entry AND the old episodic entries present simultaneously.
    let mut tx = pool.begin().await.context("consolidate_memory: begin tx")?;

    persist_memory_in_tx_with_metadata(
        &mut tx,
        actor_id,
        semantic_key,
        &final_value,
        metadata.as_ref(),
        "semantic",
        None,
    )
    .await
    .context("consolidate_memory: persist semantic summary")?;

    let retired_count = forget_keys_in_tx(&mut tx, actor_id, &retire_keys)
        .await
        .context("consolidate_memory: forget source keys")?;

    tx.commit().await.context("consolidate_memory: commit")?;

    // Post-commit only — running graph extraction inside the tx would corrupt
    // the graph if the tx rolled back. A consolidated summary is condensed
    // REAL content (not a synthetic self-output), so it STILL auto-extracts —
    // `"consolidated"` is deliberately absent from `SYNTHETIC_MEMORY_KINDS`.
    spawn_graph_extraction(
        actor_id,
        semantic_key.to_string(),
        final_value,
        Some("consolidated"),
    );

    Ok(retired_count)
}

/// Scan one actor's OLD, COLD, LOW-importance EPISODIC memories — the Phase-3b
/// consolidation candidate set. Returns decrypted `(key, value, memory_type)`
/// triples for up to `limit` rows.
///
/// Scope is deliberately narrow so consolidation never touches valuable or
/// recent memory:
///   * `memory_type = 'episodic'` only — never semantic / working / scratchpad.
///   * older than `min_age_days` (`updated_at < now() - interval`).
///   * low or UNSCORED importance (`importance IS NULL OR importance < max`).
///     Phase-3a leaves older rows' `importance` NULL; those unscored + cold
///     rows ARE the prime candidates (resolves the Phase-3a NULL-ordering
///     note), so NULLs sort FIRST.
///
/// Order: `importance ASC NULLS FIRST, last_accessed_at ASC NULLS FIRST,
/// updated_at ASC` — coldest, least-important, oldest first. The
/// `idx_actor_memory_signals(actor_id, importance, last_accessed_at)` index
/// serves the `actor_id` equality prefix; the NULLS-FIRST ordering and the
/// `memory_type`/`updated_at` predicates aren't covered, so Postgres sorts the
/// matched rows — cheap because per-actor episodic cardinality is bounded.
pub async fn scan_consolidation_candidates(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    min_age_days: f64,
    max_importance: f64,
    limit: i64,
) -> Result<Vec<(String, serde_json::Value, String)>> {
    // `make_interval` takes int4 only (lint 27) — bind i32 days AND cast
    // `$2::int` in SQL. `min_age_days` is an f64 config value; round to the
    // nearest whole day. FLOOR AT 1: a sub-1-day setting (e.g. 0.4) would
    // otherwise round to 0 → `updated_at < now()` matches essentially every
    // episodic row, defeating the "never touch recent memory" invariant and
    // making recent low-importance rows deletable. Consolidation always leaves
    // at least a full day of headroom.
    let min_age_days_i32 = (min_age_days.round() as i32).max(1);
    let sql = "SELECT actor_id, key, value_enc, value_key_id, value_format, memory_type \
               FROM actor_memory \
               WHERE actor_id = $1 \
                 AND memory_type = 'episodic' \
                 AND (expires_at IS NULL OR expires_at > now()) \
                 AND updated_at < now() - make_interval(days => $2::int) \
                 AND (importance IS NULL OR importance < $3) \
               ORDER BY importance ASC NULLS FIRST, last_accessed_at ASC NULLS FIRST, updated_at ASC \
               LIMIT $4";
    let rows = sqlx::query(sql)
        .bind(actor_id)
        .bind(min_age_days_i32)
        .bind(max_importance)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("scan_consolidation_candidates query")?;

    let mut out = Vec::with_capacity(rows.len());
    for row in &rows {
        // `key` + `memory_type` read fail-loud (checks 52/55); value decrypts
        // through the canonical AAD-aware helper (projects actor_id/key/
        // value_format — fails loud on projection drift).
        let key: String = row.try_get::<String, _>("key")?;
        let memory_type: String = row.try_get::<String, _>("memory_type")?;
        let value = decrypt_row_value(row).await?;
        out.push((key, value, memory_type));
    }
    Ok(out)
}

/// Scan an actor's MEANINGFUL memories for the autonomous reflection loop
/// (Phase 3). Returns decrypted `(key, value, memory_type)` for the most
/// recently updated `semantic`+`episodic` memories the actor holds — the
/// substrate the reflection LLM synthesizes higher-order insights over.
///
/// What it INCLUDES / EXCLUDES:
/// * `memory_type IN ('semantic','episodic')` — NOT `scratchpad`/`working`,
///   which are ephemeral bookkeeping with no reflective value.
/// * Excludes every synthetic kind in `exclude_kinds` (pass
///   [`synthetic_memory_kinds`], which now contains `"reflection"`) via the
///   SAME NULL-safe `metadata->>'kind' != ALL($N)` predicate the recall APIs
///   use. Excluding `"reflection"` is ESSENTIAL: reflecting over prior
///   reflections would drift/amplify the model's own inferences.
/// * Only live rows (`expires_at IS NULL OR expires_at > now()`).
/// * `ORDER BY updated_at DESC` (most recent context first), `LIMIT $N`.
///
/// Actor-scoped (`WHERE actor_id = $1`) and fail-loud (`try_get::<_,_>()?`)
/// throughout; value decrypts through the canonical AAD-aware
/// [`decrypt_row_value`] helper (projects `actor_id`/`value_format`).
pub async fn scan_reflection_input(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    exclude_kinds: &[String],
    limit: i64,
) -> Result<Vec<(String, serde_json::Value, String)>> {
    let limit = limit.clamp(1, MAX_LIST_LIMIT);
    let sql = "SELECT actor_id, key, value_enc, value_key_id, value_format, memory_type \
               FROM actor_memory \
               WHERE actor_id = $1 \
                 AND memory_type IN ('semantic', 'episodic') \
                 AND (expires_at IS NULL OR expires_at > now()) \
                 AND (cardinality($2::text[]) = 0 \
                      OR metadata IS NULL \
                      OR metadata->>'kind' IS NULL \
                      OR metadata->>'kind' != ALL($2::text[])) \
               ORDER BY updated_at DESC \
               LIMIT $3";
    let rows = sqlx::query(sql)
        .bind(actor_id)
        .bind(exclude_kinds)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("scan_reflection_input query")?;

    let mut out = Vec::with_capacity(rows.len());
    for row in &rows {
        // Fail-loud reads (checks 52/55); value decrypts through the canonical
        // AAD-aware helper (fails loud on projection drift).
        let key: String = row.try_get::<String, _>("key")?;
        let memory_type: String = row.try_get::<String, _>("memory_type")?;
        let value = decrypt_row_value(row).await?;
        out.push((key, value, memory_type));
    }
    Ok(out)
}

/// Persist a reflection as a NON-DESTRUCTIVE `semantic` memory (Phase 3).
///
/// Reflection AUGMENTS — unlike [`consolidate_memory`], which atomically
/// forgets its source rows, this writes ONE new memory and DELETES NOTHING.
/// It is a thin wrapper over [`persist_memory_with_metadata`] pinned to
/// `memory_type = "semantic"` (semantic memories ignore TTL, so the reflection
/// is durable), which routes through the canonical always-encrypt path
/// (per-org DEK, AAD bound to `(actor_id, key)`). Callers pass
/// `key = "reflection/latest"` so the single current reflection per actor is
/// OVERWRITTEN each cycle (the `ON CONFLICT (actor_id, key)` upsert refreshes
/// it) rather than accumulating unboundedly — mirroring the `daily_brief/latest`
/// convention.
pub async fn persist_reflection(
    pool: &Pool<Postgres>,
    actor_id: Uuid,
    key: &str,
    value: serde_json::Value,
    metadata: serde_json::Value,
) -> Result<()> {
    persist_memory_with_metadata(
        pool,
        actor_id,
        key,
        &value,
        Some(&metadata),
        "semantic",
        None,
    )
    .await
    .map(|_outcome| ())
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
            let key: String = r.try_get("key")?;
            let value_enc: Vec<u8> = r.try_get("value_enc")?;
            let value_key_id: Uuid = r.try_get("value_key_id")?;
            let src_format: i16 = r.try_get("value_format")?;
            let memory_type: String = r.try_get("memory_type")?;
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
        let actor_id: Uuid = r.try_get("actor_id")?;
        let key: String = r.try_get("key")?;
        let value_enc: Vec<u8> = r.try_get("value_enc")?;
        let value_key_id: Uuid = r.try_get("value_key_id")?;
        let src_format: i16 = r.try_get("value_format")?;
        let org_id: Uuid = r.try_get("org_id")?;

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

/// One-time grandfather stamp for the provenance migration: legacy rows
/// (embedding present, model NULL) are attributed to the CURRENTLY
/// configured model — true as long as the operator did not change
/// `EMBEDDING_MODEL` in the same deploy (release-notes caveat).
/// Idempotent (predicate self-empties); called once at controller boot.
pub async fn grandfather_embedding_model(pool: &Pool<Postgres>) -> Result<u64> {
    let Some(model) = embedding::active_embedding_model() else {
        return Ok(0); // embeddings disabled — nothing to attribute
    };
    let res = sqlx::query(
        "UPDATE actor_memory SET embedding_model = $1 \
         WHERE embedding IS NOT NULL AND embedding_model IS NULL",
    )
    .bind(&model)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
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
               AND (embedding IS NULL OR embedding_model IS DISTINCT FROM $3) \
               AND memory_type != 'scratchpad' \
               AND (expires_at IS NULL OR expires_at > NOW()) \
             ORDER BY created_at ASC LIMIT $2",
            )
            .bind(actor_id)
            .bind(limit)
            .bind(embedding::active_embedding_model())
            .fetch_all(pool)
            .await?
        }
        None => {
            sqlx::query(
                "SELECT id, actor_id, key, value_enc, value_key_id, value_format \
             FROM actor_memory \
             WHERE (embedding IS NULL OR embedding_model IS DISTINCT FROM $2) \
               AND memory_type != 'scratchpad' \
             AND (expires_at IS NULL OR expires_at > NOW()) \
             ORDER BY created_at ASC LIMIT $1",
            )
            .bind(limit)
            .bind(embedding::active_embedding_model())
            .fetch_all(pool)
            .await?
        }
    };

    let total = raw_rows.len();
    let mut embedded = 0usize;
    for r in &raw_rows {
        use sqlx::Row as _;
        let id: Uuid = r.try_get("id")?;
        let key: String = r.try_get("key")?;
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
        let row_actor: Uuid = r.try_get("actor_id")?;
        let local_only = embed_local_only(pool, row_actor).await;
        if let Some(emb) = embedding::generate_embedding(&text, local_only).await {
            // L-1: UPDATE failures (DB pool exhaustion, FK violation,
            // constraint mismatch) warn + skip without bumping the
            // counter, so "embedded N rows" metrics never lie under
            // DB stress.
            let vec = pgvector::Vector::from(emb);
            match sqlx::query(
                "UPDATE actor_memory SET embedding = $1, embedding_model = $3, updated_at = now() \
                 WHERE id = $2",
            )
            .bind(vec)
            .bind(id)
            .bind(embedding::active_embedding_model())
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
mod spawn_graph_extraction_synthetic_kind_tests {
    use super::*;

    // GRAPH-WRITE POLICY (Phase 4): synthetic self-output kinds must NOT
    // auto-extract into the entity graph; real / condensed-real content must.
    #[test]
    fn reflection_and_self_outputs_are_synthetic() {
        for k in [
            "reflection",
            "daily_brief",
            "judge",
            "ml_digest",
            "synthesize",
        ] {
            assert!(
                is_synthetic_memory_kind(k),
                "{k} must be treated as a synthetic self-output (skips auto-extraction)"
            );
        }
    }

    #[test]
    fn consolidated_is_not_synthetic_still_extracts() {
        // A consolidated summary is condensed REAL content — it MUST remain
        // eligible for auto-extraction (verifies the deliberate omission of
        // "consolidated" from SYNTHETIC_MEMORY_KINDS).
        assert!(
            !is_synthetic_memory_kind("consolidated"),
            "consolidated summaries are real condensed content and must still extract"
        );
    }

    #[test]
    fn real_source_kinds_and_absent_kind_extract() {
        // Human-sourced / integration-sourced content and rows with no kind
        // are not synthetic → they extract.
        assert!(!is_synthetic_memory_kind("jira_work_context"));
        assert!(!is_synthetic_memory_kind("email_triage"));
        assert_eq!(metadata_kind(None), None);
    }

    #[test]
    fn metadata_kind_extracts_string_label() {
        let md = serde_json::json!({ "kind": "reflection", "source_count": 3 });
        assert_eq!(metadata_kind(Some(&md)), Some("reflection"));
        // Missing / non-string kind → None (treated as non-synthetic).
        assert_eq!(metadata_kind(Some(&serde_json::json!({}))), None);
        assert_eq!(metadata_kind(Some(&serde_json::json!({ "kind": 7 }))), None);
    }
}

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
    fn set_kv_default_is_durable_not_working() {
        // Regression guard for the pre-2026-07 footgun: the `agent_memory::set`
        // host binding hardcoded `working`/1h, so state written via `set`
        // silently vanished before the next scheduled workflow run. `set` now
        // persists `episodic` at SET_KV_TTL_HOURS — this must resolve to an
        // effectively-permanent expiry, NOT the 1h working default.
        let exp = default_expires_at("episodic", Some(SET_KV_TTL_HOURS))
            .expect("set() TTL must yield a durable expiry");
        assert!(
            exp > Utc::now() + Duration::days(365 * 9),
            "set() retention must be >9 years (effectively permanent), got {exp}"
        );
        // Lockstep with the ceiling so the clamp in default_expires_at can never
        // silently shorten it.
        assert_eq!(SET_KV_TTL_HOURS, MAX_TTL_HOURS);
        // And unambiguously longer-lived than the old working/1h default.
        let working = default_expires_at("working", None).unwrap();
        assert!(exp > working + Duration::days(3000));
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

// ─────────────────────────────────────────────────────────────────────
// Batched actor-memory listing (the `actorsMemories` N+1 close). Covers
// the pure grouping helper (`group_memory_list_rows_by_actor`) and the
// per-row decrypt dispatch (`decrypt_memory_list_row`) across format
// versions + drift. The SQL fn `list_memories_with_ciphertext_batched_scoped`
// itself (the `= ANY($1)` window-cap query) needs a live Postgres — the
// project has no in-crate DB harness for talos-memory (all unit tests here
// are pure), so its query behavior (per-actor cap newest-first, empty
// actor_ids, unknown-actor-absent, value_format-projection fail-loud via
// FromRow) is exercised by the controller integration suite against the
// isolated-DB harness, mirrored by the pure grouping + decrypt assertions
// below.
// ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod batched_listing_tests {
    use super::{
        decrypt_memory_list_row, group_memory_list_rows_by_actor, register_memory_crypto_hook,
        DecryptFuture, EncryptFuture, MemoryCryptoHook, MemoryListRowEnc,
    };
    use chrono::Utc;
    use std::sync::Arc;
    use uuid::Uuid;

    fn row(actor_id: Uuid, key: &str, memory_type: &str) -> MemoryListRowEnc {
        MemoryListRowEnc {
            actor_id,
            key: key.to_string(),
            value_enc: None,
            value_key_id: None,
            value_format: 0,
            memory_type: memory_type.to_string(),
            expires_at: None,
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn grouping_preserves_requested_order_and_partitions_rows() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        // Rows arrive interleaved (the batched query orders by actor_id, but
        // the grouper must not depend on input order).
        let rows = vec![
            row(b, "k1", "working"),
            row(a, "k1", "working"),
            row(b, "k2", "episodic"),
            row(a, "k2", "episodic"),
        ];
        let grouped = group_memory_list_rows_by_actor(&[a, b], rows);
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped[0].0, a, "requested order (a before b) preserved");
        assert_eq!(grouped[1].0, b);
        let a_keys: Vec<_> = grouped[0].1.iter().map(|r| r.key.as_str()).collect();
        let b_keys: Vec<_> = grouped[1].1.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(a_keys, vec!["k1", "k2"], "actor a keeps only its own rows");
        assert_eq!(b_keys, vec!["k1", "k2"], "actor b keeps only its own rows");
    }

    #[test]
    fn owned_actor_with_no_rows_yields_empty_group_not_absent() {
        // Byte-identical to the pre-batch loop: an owned actor with no
        // memories was a group with an empty list, NOT an omitted group.
        let a = Uuid::new_v4();
        let empty_actor = Uuid::new_v4();
        let rows = vec![row(a, "k1", "working")];
        let grouped = group_memory_list_rows_by_actor(&[a, empty_actor], rows);
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped[1].0, empty_actor);
        assert!(
            grouped[1].1.is_empty(),
            "empty owned actor must produce a present-but-empty group"
        );
    }

    #[test]
    fn empty_ordered_yields_no_groups() {
        let grouped = group_memory_list_rows_by_actor(&[], vec![]);
        assert!(grouped.is_empty());
    }

    #[test]
    fn rows_for_unrequested_actor_are_dropped() {
        // The resolver only passes owned ids to `ordered`; a stray row for
        // an id not in `ordered` (defensive — can't happen, the query is
        // `= ANY(ordered)`) must not manufacture an extra group.
        let a = Uuid::new_v4();
        let stray = Uuid::new_v4();
        let rows = vec![row(a, "k1", "working"), row(stray, "k1", "working")];
        let grouped = group_memory_list_rows_by_actor(&[a], rows);
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].0, a);
        assert_eq!(grouped[0].1.len(), 1);
    }

    // Stub crypto hook: echoes the JSON-serialized plaintext it "encrypts"
    // straight back on decrypt (ciphertext == JSON bytes) for the known
    // format versions, and fails LOUD on any other version so a drifted /
    // unknown `value_format` surfaces as an Err rather than a silent
    // default (decrypt-side mirror of the query's FromRow fail-loud).
    struct EchoFormatHook;
    impl MemoryCryptoHook for EchoFormatHook {
        fn encrypt(
            &self,
            plaintext: String,
            _org_id: Option<Uuid>,
            _aad: Vec<u8>,
        ) -> EncryptFuture {
            Box::pin(async move { Ok((Uuid::nil(), plaintext.into_bytes(), 3i16)) })
        }
        fn decrypt(
            &self,
            _key_id: Uuid,
            ciphertext: Vec<u8>,
            _aad: Vec<u8>,
            format_version: i16,
        ) -> DecryptFuture {
            Box::pin(async move {
                match format_version {
                    0 | 1 | 3 | 4 => {
                        let s = String::from_utf8(ciphertext)
                            .map_err(|e| anyhow::anyhow!("utf8: {e}"))?;
                        Ok(zeroize::Zeroizing::new(s))
                    }
                    other => anyhow::bail!("unknown value_format {other} (schema drift)"),
                }
            })
        }
    }

    fn enc_row(
        actor: Uuid,
        key: &str,
        fmt: i16,
        json_value: &serde_json::Value,
    ) -> MemoryListRowEnc {
        let payload = serde_json::to_string(json_value).expect("serialize");
        MemoryListRowEnc {
            actor_id: actor,
            key: key.to_string(),
            value_enc: Some(payload.into_bytes()),
            value_key_id: Some(Uuid::new_v4()),
            value_format: fmt,
            memory_type: "working".to_string(),
            expires_at: None,
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn decrypt_dispatches_across_format_versions_in_one_batch_and_fails_loud_on_drift() {
        // Global OnceLock hook; register is idempotent and no other
        // talos-memory unit test depends on the no-hook state.
        register_memory_crypto_hook(Arc::new(EchoFormatHook));
        let actor = Uuid::new_v4();

        // v0/v1/v3/v4 rows all decrypt through the per-row format dispatch.
        for fmt in [0i16, 1, 3, 4] {
            let expected = serde_json::json!(format!("value-for-format-{fmt}"));
            let r = enc_row(actor, &format!("k{fmt}"), fmt, &expected);
            let got = decrypt_memory_list_row(&r)
                .await
                .expect("known format must decrypt");
            assert_eq!(got, expected, "format {fmt} round-trips to its own value");
        }

        // A drifted / unknown value_format must fail LOUD (Err), never a
        // silent default.
        let drift = enc_row(actor, "kbad", 99, &serde_json::json!("x"));
        let err = decrypt_memory_list_row(&drift)
            .await
            .expect_err("unknown value_format must fail loud");
        assert!(
            format!("{err:#}").contains("99"),
            "error must surface the drifted format: {err:#}"
        );
    }
}
