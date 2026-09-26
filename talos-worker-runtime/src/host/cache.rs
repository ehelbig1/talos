//! `cache` (Redis) host interface with per-user key namespacing.
//!
//! Every host function here takes its connection from
//! `TalosContext::redis_conn()` — ONE lazily-built `ConnectionManager` shared
//! across every job on the runtime (2026-09-10). Before that each of the nine
//! functions opened `get_multiplexed_async_connection()` per guest call, i.e. a
//! TCP (+TLS+AUTH) handshake per `cache::get`.

use super::*;

// ============================================================================
// Cache (Redis)
// ============================================================================

/// Build a namespace-prefixed cache key to isolate WASM module cache entries.
///
/// Format: `talos_cache:u={user_id}:{key}` (or `talos_cache:u=system:{key}`
/// when no user context is attached — system executions only).
///
/// **Cross-tenant isolation (2026-05-23, security review).** Pre-fix the
/// namespace was a single `talos_cache:{key}` shared across every tenant on
/// the cluster: any module holding the `Cache` capability — a routine grant
/// — could `get` / `set` / `delete` / `mget` / `exists` / `increment` any
/// other tenant's cache entries by name. PII, embeddings, OAuth-state
/// nonces, dedupe markers, computed weights — all of it was a `mget` of a
/// guessable key away from a hostile module. The doc-comment even called
/// this out as intentional. It is not — opt-out, not opt-in, is the
/// security-safe default for any tenant-aware platform.
///
/// **Why prefix per-user, not per-actor or per-module.** Cache values today
/// are scoped to the user (HTTP responses, computed embeddings, OAuth
/// state). Per-actor would over-isolate workflows-within-a-user that
/// genuinely share state; per-module would over-isolate two nodes in the
/// same workflow that compose a pipeline. Per-user matches the engine's
/// existing trust boundary (DEK lineage, integration-state) and keeps the
/// human-mental-model of "my data is mine, others can't see it" intact.
///
/// **Backward compatibility.** Existing `talos_cache:{key}` entries become
/// orphaned at deploy; the 24h Redis TTL on cache writes (`OCI_CACHE_TTL_SECS`
/// pattern) means they age out within a day. Any module relying on
/// cross-tenant cache reads was an unintended exploit path — losing those
/// reads is the fix, not a regression.
fn namespaced_cache_key(ctx: &TalosContext, key: &str) -> String {
    build_namespaced_cache_key(ctx.user_id, key)
}

/// Pure helper used by [`namespaced_cache_key`] so the namespacing rule can
/// be unit-tested without constructing a full [`TalosContext`].
///
/// The format is `talos_cache:u={user_id}:{key}` for user-scoped executions
/// and `talos_cache:u=system:{key}` for system executions. UUIDs render as
/// hex with hyphens — there is no representable user_id that collides with
/// the reserved `system` token, so the two namespaces are disjoint.
pub(crate) fn build_namespaced_cache_key(user_id: Option<uuid::Uuid>, key: &str) -> String {
    match user_id {
        Some(uid) => format!("talos_cache:u={}:{}", uid, key),
        None => format!("talos_cache:u=system:{}", key),
    }
}

/// MCP-754 (2026-05-13): per-key length cap shared across every
/// wit_cache::Host method. `set` (line ~3617) and `mset` (loop at
/// line ~3859) already enforced `key.len() <= 1024`; the read /
/// mutation siblings (`get`, `delete`, `exists`, `increment`,
/// `decrement`, `expire`, and `mget`'s per-entry check) had NO
/// per-key cap. A Cache-world guest could allocate a multi-megabyte
/// key string in WASM linear memory and pass it to any of those
/// methods — the host would format it into `talos_cache:<10MB>`,
/// allocate ~10MB on the host heap, then send the giant key to
/// Redis (Redis processes it but spends materially more CPU per
/// op than on a 1KB key). Loop the call → amplification DoS against
/// the shared Redis instance, with the audit ledger seeing only
/// "guest had Cache capability and made cache calls" — no signal
/// tying the spike to one module. Same sibling-defense drift class
/// as MCP-731 / MCP-732. Cap matches the established `set` /
/// `mset` limit.
const MAX_CACHE_KEY_BYTES: usize = 1024;

/// Per-execution cap on `cache` host calls (every method, reads included).
/// Same shape and value as `MAX_HTTP_CALLS_PER_EXECUTION`: the Redis behind
/// this interface also holds the platform's rate-limit, 2FA-lockout and
/// idempotency state, so an unbounded guest loop is a shared-service DoS.
pub(crate) const MAX_CACHE_CALLS_PER_EXECUTION: u64 = 1000;
/// Per-execution cap on bytes WRITTEN (keys + values, `set` and `mset`).
/// One maximal 10 MiB value fits; `mset`'s 1000 x 10 MiB (10 GB) does not.
pub(crate) const MAX_CACHE_WRITE_BYTES_PER_EXECUTION: u64 = 64 * 1024 * 1024;
/// TTL applied to a write that names none (or `0`): no immortal keys.
pub(crate) const DEFAULT_CACHE_TTL_SECS: u64 = 24 * 60 * 60;
/// Ceiling on any TTL a module may set (`set`, `mset`, `expire`, `increment`).
pub(crate) const MAX_CACHE_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// The TTL a write actually gets: `None`/`0` → default, else capped.
pub(crate) fn effective_cache_ttl(ttl: Option<u32>) -> u64 {
    match ttl {
        None | Some(0) => DEFAULT_CACHE_TTL_SECS,
        Some(secs) => u64::from(secs).min(MAX_CACHE_TTL_SECS),
    }
}

/// Atomically charge `n` bytes against a per-execution write budget; `false`
/// (nothing charged) once `cap` would be exceeded.
pub(crate) fn reserve_cache_bytes(used: &std::sync::atomic::AtomicU64, n: u64, cap: u64) -> bool {
    used.fetch_update(
        std::sync::atomic::Ordering::AcqRel,
        std::sync::atomic::Ordering::Acquire,
        |cur| cur.checked_add(n).filter(|next| *next <= cap),
    )
    .is_ok()
}

/// `INCRBY` that also gives a key WITHOUT a TTL the default one, atomically —
/// a bare `INCRBY` on a missing key creates an immortal counter.
const INCR_WITH_TTL_LUA: &str = "local v = redis.call('INCRBY', KEYS[1], ARGV[1]) \
     if redis.call('TTL', KEYS[1]) == -1 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end \
     return v";

impl TalosContext {
    /// Charge one cache call (and `write_bytes`) against this execution's
    /// budgets; audits and returns `true` when REFUSED.
    async fn cache_budget_refused(
        &mut self,
        op: &'static str,
        target: &str,
        write_bytes: u64,
    ) -> bool {
        let policy =
            if !self.check_rate_limit(&self.cache_call_count, MAX_CACHE_CALLS_PER_EXECUTION) {
                "cache-call-budget"
            } else if write_bytes > 0
                && !reserve_cache_bytes(
                    &self.cache_write_bytes,
                    write_bytes,
                    MAX_CACHE_WRITE_BYTES_PER_EXECUTION,
                )
            {
                "cache-write-byte-budget"
            } else {
                return false;
            };
        self.record_capability_denied(op, policy, target).await;
        tracing::warn!(module_id = ?self.module_id, op, policy, "cache call refused: per-execution budget spent");
        true
    }
}

impl wit_cache::Host for TalosContext {
    async fn get(&mut self, key: String) -> Result<String, wit_cache::Error> {
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __result = async move {
            use crate::wit_inspector::CapabilityWorld;
            if !matches!(
                self.capability_world,
                CapabilityWorld::Cache | CapabilityWorld::Trusted
            ) {
                // MCP-696 (2026-05-13): audit-ledger parity. Sibling
                // `exists` was closed in MCP-690; the other 8 wit_cache
                // methods silently denied without `record_capability_denied`,
                // so a Minimal-world module probing for cache access
                // surface left no audit trail. Same `tracing::warn!`-only
                // class as the original wit_state::exists / wit_files
                // gaps. Threat model identical to MCP-601 (Minimal world
                // poisoning the shared `talos_cache:` namespace).
                self.record_capability_denied("cache-get", "capability-world", &key)
                    .await;
                tracing::warn!("WASM module attempted cache access but lacks Cache capability");
                return Err(wit_cache::Error::Connectionfailed);
            }
            // MCP-754: per-key cap parity with `set`. See MAX_CACHE_KEY_BYTES doc.
            if key.is_empty() || key.len() > MAX_CACHE_KEY_BYTES {
                return Err(wit_cache::Error::Operationfailed);
            }

            if self.cache_budget_refused("cache-get", &key, 0).await {
                return Err(wit_cache::Error::Operationfailed);
            }
            let ns_key = namespaced_cache_key(self, &key);
            use redis::AsyncCommands;
            let mut conn = self
                .redis_conn()
                .await
                .map_err(|_| wit_cache::Error::Connectionfailed)?;
            conn.get::<_, String>(&ns_key)
                .await
                .map_err(|_| wit_cache::Error::Notfound)
        }
        .await;

        if let Some(ref m) = __metrics {
            m.record_host_function_call("cache::get", __start.elapsed().as_millis() as f64);
        }
        __result
    }

    async fn set(
        &mut self,
        key: String,
        value: String,
        ttl: Option<u32>,
    ) -> Result<(), wit_cache::Error> {
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __result: Result<(), wit_cache::Error> = async move {
            // MCP-601 (2026-05-12): every other wit_cache method gates on
            // CapabilityWorld::Cache | Trusted; `set` was missing the
            // check (copy-paste regression). Without this gate, a
            // Minimal-world module could write Redis keys in the shared
            // `talos_cache:` namespace, polluting/poisoning a cache that
            // Cache-world modules read from. Same gate used by get/
            // delete/exists/increment/decrement/mget/mset/expire (verified
            // by audit sweep of wit_cache::Host impl block).
            use crate::wit_inspector::CapabilityWorld;
            if !matches!(
                self.capability_world,
                CapabilityWorld::Cache | CapabilityWorld::Trusted
            ) {
                // MCP-696 (2026-05-13): audit-ledger parity — see cache::get above.
                self.record_capability_denied("cache-set", "capability-world", &key)
                    .await;
                tracing::warn!("WASM module attempted cache::set but lacks Cache capability");
                return Err(wit_cache::Error::Connectionfailed);
            }
            if key.is_empty() || key.len() > 1024 {
                return Err(wit_cache::Error::Operationfailed);
            }
            if value.len() > 10 * 1024 * 1024 {
                // 10MB limit
                tracing::warn!("Cache value exceeds 10MB limit");
                return Err(wit_cache::Error::Operationfailed);
            }

            let write_bytes = (key.len() + value.len()) as u64;
            if self
                .cache_budget_refused("cache-set", &key, write_bytes)
                .await
            {
                return Err(wit_cache::Error::Operationfailed);
            }
            let ns_key = namespaced_cache_key(self, &key);
            use redis::AsyncCommands;
            let mut conn = self
                .redis_conn()
                .await
                .map_err(|_| wit_cache::Error::Connectionfailed)?;
            // Always SET EX: a `None` TTL gets the default, never "forever".
            conn.set_ex::<_, _, ()>(&ns_key, &value, effective_cache_ttl(ttl))
                .await
                .map_err(|_| wit_cache::Error::Operationfailed)
        }
        .await;

        if let Some(ref m) = __metrics {
            m.record_host_function_call("cache::set", __start.elapsed().as_millis() as f64);
        }
        __result
    }

    async fn delete(&mut self, key: String) -> Result<(), wit_cache::Error> {
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __result: Result<(), wit_cache::Error> = async move {
            use crate::wit_inspector::CapabilityWorld;
            if !matches!(
                self.capability_world,
                CapabilityWorld::Cache | CapabilityWorld::Trusted
            ) {
                // MCP-696 (2026-05-13): audit-ledger parity — see cache::get above.
                self.record_capability_denied("cache-delete", "capability-world", &key)
                    .await;
                tracing::warn!("WASM module attempted cache access but lacks Cache capability");
                return Err(wit_cache::Error::Connectionfailed);
            }
            // MCP-754: per-key cap parity with `set`. See MAX_CACHE_KEY_BYTES doc.
            if key.is_empty() || key.len() > MAX_CACHE_KEY_BYTES {
                return Err(wit_cache::Error::Operationfailed);
            }

            if self.cache_budget_refused("cache-delete", &key, 0).await {
                return Err(wit_cache::Error::Operationfailed);
            }
            let ns_key = namespaced_cache_key(self, &key);
            use redis::AsyncCommands;
            let mut conn = self
                .redis_conn()
                .await
                .map_err(|_| wit_cache::Error::Connectionfailed)?;
            conn.del::<_, ()>(&ns_key)
                .await
                .map_err(|_| wit_cache::Error::Operationfailed)
        }
        .await;

        if let Some(ref m) = __metrics {
            m.record_host_function_call("cache::delete", __start.elapsed().as_millis() as f64);
        }
        __result
    }

    async fn exists(&mut self, key: String) -> bool {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Cache | CapabilityWorld::Trusted
        ) {
            // MCP-690 (2026-05-13): audit-ledger emission for
            // capability denial parity with the fallible siblings
            // (get/set/delete/increment etc.). Pre-fix this method
            // silently returned `false`, so a Minimal-world module
            // could probe arbitrary cache keys without leaving an
            // audit trail. Same `-> bool` silent-no-op class as
            // wit_state::exists, wit_state::list_keys, wit_files::exists.
            self.record_capability_denied("cache-exists", "capability-world", &key)
                .await;
            return false;
        }
        // MCP-754: per-key cap parity with `set`. See MAX_CACHE_KEY_BYTES doc.
        // `exists` returns `-> bool` so we silently no-op (return false) on
        // oversized keys, matching the existing silent-deny shape for missing
        // Redis client and connection errors below.
        if key.is_empty() || key.len() > MAX_CACHE_KEY_BYTES {
            return false;
        }
        if self.cache_budget_refused("cache-exists", &key, 0).await {
            return false;
        }
        let ns_key = namespaced_cache_key(self, &key);
        use redis::AsyncCommands;
        let Ok(mut conn) = self.redis_conn().await else {
            return false;
        };
        conn.exists::<_, bool>(&ns_key).await.unwrap_or(false)
    }

    async fn increment(&mut self, key: String, amount: i64) -> Result<i64, wit_cache::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Cache | CapabilityWorld::Trusted
        ) {
            // MCP-696 (2026-05-13): audit-ledger parity — see cache::get above.
            self.record_capability_denied("cache-increment", "capability-world", &key)
                .await;
            tracing::warn!("WASM module attempted cache access but lacks Cache capability");
            return Err(wit_cache::Error::Connectionfailed);
        }
        // MCP-754: per-key cap parity with `set`. See MAX_CACHE_KEY_BYTES doc.
        if key.is_empty() || key.len() > MAX_CACHE_KEY_BYTES {
            return Err(wit_cache::Error::Operationfailed);
        }

        // A new counter is a write of its key.
        if self
            .cache_budget_refused("cache-increment", &key, key.len() as u64)
            .await
        {
            return Err(wit_cache::Error::Operationfailed);
        }
        let ns_key = namespaced_cache_key(self, &key);
        let mut conn = self
            .redis_conn()
            .await
            .map_err(|_| wit_cache::Error::Connectionfailed)?;
        redis::Script::new(INCR_WITH_TTL_LUA)
            .key(&ns_key)
            .arg(amount)
            .arg(DEFAULT_CACHE_TTL_SECS)
            .invoke_async::<i64>(&mut conn)
            .await
            .map_err(|_| wit_cache::Error::Operationfailed)
    }

    async fn decrement(&mut self, key: String, amount: i64) -> Result<i64, wit_cache::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Cache | CapabilityWorld::Trusted
        ) {
            // MCP-696 (2026-05-13): audit-ledger parity — see cache::get above.
            self.record_capability_denied("cache-decrement", "capability-world", &key)
                .await;
            tracing::warn!("WASM module attempted cache access but lacks Cache capability");
            return Err(wit_cache::Error::Connectionfailed);
        }
        // MCP-754: per-key cap parity with `set`. Belt-and-suspenders:
        // `increment` (delegated below) also enforces, but this catch
        // saves the negation arithmetic + the second capability check.
        if key.is_empty() || key.len() > MAX_CACHE_KEY_BYTES {
            return Err(wit_cache::Error::Operationfailed);
        }

        // MCP-1007 (2026-05-15): guard the i64 negation against
        // `amount = i64::MIN`. Pre-fix `-amount` panicked in debug
        // builds (Rust's `Neg` trait for i64 overflows on `i64::MIN`,
        // since `-i64::MIN = i64::MAX + 1` doesn't fit in i64) and
        // wrapped to `i64::MIN` in release builds — so
        // `decrement(key, i64::MIN)` silently collapsed to
        // `increment(key, i64::MIN)`, producing the wrong cache value
        // instead of the operation-not-representable error the caller
        // expected. Redis would then catch the resulting overflow at
        // the INCRBY level and return generic `Operationfailed`,
        // hiding the real cause from operators reading worker logs.
        // Same defense-in-depth class as the integer-cast wraparound
        // sweep (MCP-960 / MCP-961 / MCP-962). Fail-closed at the
        // boundary with `checked_neg`; the caller sees
        // `Operationfailed` immediately rather than reaching Redis.
        let neg_amount = match amount.checked_neg() {
            Some(n) => n,
            None => {
                tracing::warn!(
                    module_id = ?self.module_id,
                    "cache::decrement received i64::MIN — negation would overflow; rejecting"
                );
                return Err(wit_cache::Error::Operationfailed);
            }
        };

        self.increment(key, neg_amount).await
    }

    async fn mget(&mut self, keys: Vec<String>) -> Result<Vec<Option<String>>, wit_cache::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Cache | CapabilityWorld::Trusted
        ) {
            // MCP-696 (2026-05-13): audit-ledger parity — see cache::get above.
            // Multi-key surface, so target encodes the batch size rather
            // than a key literal (avoids cardinality blow-up + key-bag PII).
            let target = format!("<batch:{}>", keys.len());
            self.record_capability_denied("cache-mget", "capability-world", &target)
                .await;
            tracing::warn!(
                module_id = ?self.module_id,
                "WASM module attempted cache mget but lacks Cache capability"
            );
            return Err(wit_cache::Error::Connectionfailed);
        }

        // MCP-732 (2026-05-13): batch-size cap, sibling-defense parity
        // with the single-key path. Pre-fix a Cache-world guest could
        // pass an unbounded `keys: Vec<String>` and the host would
        // forward all of them to Redis in one MGET — enumeration-DoS
        // against the shared `talos_cache:` namespace AND a memory
        // bomb for the host (the reply Vec<Option<String>> mirrors
        // the input cardinality). Sibling drift class to MCP-731
        // (wit_messaging::request missed siblings).
        const MAX_CACHE_BATCH_KEYS: usize = 1000;
        if keys.len() > MAX_CACHE_BATCH_KEYS {
            tracing::warn!(
                module_id = ?self.module_id,
                batch_size = keys.len(),
                "cache::mget batch size exceeds {} keys; rejecting",
                MAX_CACHE_BATCH_KEYS
            );
            return Err(wit_cache::Error::Operationfailed);
        }
        // MCP-754: per-key length cap, sibling-parity with `mset`'s
        // per-entry loop check (lines below). Pre-fix `mget` only
        // capped batch size — a 1000-key batch where each key was 10 MB
        // long was a 10 GB host allocation in `ns_keys` + a 10 GB
        // payload to Redis. See MAX_CACHE_KEY_BYTES doc.
        for (i, k) in keys.iter().enumerate() {
            if k.is_empty() || k.len() > MAX_CACHE_KEY_BYTES {
                tracing::warn!(
                    module_id = ?self.module_id,
                    index = i,
                    key_len = k.len(),
                    "cache::mget key exceeds {} bytes (or empty); rejecting batch",
                    MAX_CACHE_KEY_BYTES
                );
                return Err(wit_cache::Error::Operationfailed);
            }
        }

        let target = format!("<batch:{}>", keys.len());
        if self.cache_budget_refused("cache-mget", &target, 0).await {
            return Err(wit_cache::Error::Operationfailed);
        }
        let ns_keys: Vec<String> = keys.iter().map(|k| namespaced_cache_key(self, k)).collect();
        use redis::AsyncCommands;
        let mut conn = self
            .redis_conn()
            .await
            .map_err(|_| wit_cache::Error::Connectionfailed)?;
        conn.mget::<_, Vec<Option<String>>>(ns_keys)
            .await
            .map_err(|_| wit_cache::Error::Operationfailed)
    }

    async fn mset(&mut self, pairs: Vec<(String, String)>) -> Result<(), wit_cache::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Cache | CapabilityWorld::Trusted
        ) {
            // MCP-696 (2026-05-13): audit-ledger parity — see cache::get above.
            // Multi-key surface — encode batch size only (same reasoning as mget).
            let target = format!("<batch:{}>", pairs.len());
            self.record_capability_denied("cache-mset", "capability-world", &target)
                .await;
            tracing::warn!("WASM module attempted cache access but lacks Cache capability");
            return Err(wit_cache::Error::Connectionfailed);
        }

        // MCP-732 (2026-05-13): batch-size + per-key/per-value caps,
        // sibling-defense parity with the single-key `set` path. Pre-fix
        // `mset` had zero size checks while `set` enforces
        // `key.len() <= 1024` AND `value.len() <= 10 MiB`. A Cache-world
        // guest could write GBs into Redis in a single call (memory-
        // exhaust the shared `talos_cache:` namespace), or use
        // pathological key lengths to overflow Redis's per-key limit.
        // Same drift class as MCP-731. Caps match the single-key path.
        const MAX_CACHE_BATCH_KEYS: usize = 1000;
        const MAX_KEY_BYTES: usize = 1024;
        const MAX_VALUE_BYTES: usize = 10 * 1024 * 1024;
        if pairs.len() > MAX_CACHE_BATCH_KEYS {
            tracing::warn!(
                module_id = ?self.module_id,
                batch_size = pairs.len(),
                "cache::mset batch size exceeds {} pairs; rejecting",
                MAX_CACHE_BATCH_KEYS
            );
            return Err(wit_cache::Error::Operationfailed);
        }
        for (k, v) in &pairs {
            if k.is_empty() || k.len() > MAX_KEY_BYTES {
                tracing::warn!(
                    module_id = ?self.module_id,
                    key_len = k.len(),
                    "cache::mset key exceeds {} bytes (or empty); rejecting batch",
                    MAX_KEY_BYTES
                );
                return Err(wit_cache::Error::Operationfailed);
            }
            if v.len() > MAX_VALUE_BYTES {
                tracing::warn!(
                    module_id = ?self.module_id,
                    value_len = v.len(),
                    "cache::mset value exceeds {} bytes; rejecting batch",
                    MAX_VALUE_BYTES
                );
                return Err(wit_cache::Error::Operationfailed);
            }
        }

        let write_bytes: u64 = pairs.iter().map(|(k, v)| (k.len() + v.len()) as u64).sum();
        let target = format!("<batch:{}>", pairs.len());
        if self
            .cache_budget_refused("cache-mset", &target, write_bytes)
            .await
        {
            return Err(wit_cache::Error::Operationfailed);
        }
        let ns_pairs: Vec<(String, String)> = pairs
            .into_iter()
            .map(|(k, v)| (namespaced_cache_key(self, &k), v))
            .collect();
        let mut conn = self
            .redis_conn()
            .await
            .map_err(|_| wit_cache::Error::Connectionfailed)?;
        // MSET cannot carry a TTL, so write every pair as SET EX in one
        // atomic pipeline: no immortal keys, same all-or-nothing shape.
        let ttl = effective_cache_ttl(None);
        let mut pipe = redis::pipe();
        pipe.atomic();
        for (k, v) in &ns_pairs {
            pipe.set_ex(k, v, ttl).ignore();
        }
        pipe.query_async::<()>(&mut conn)
            .await
            .map_err(|_| wit_cache::Error::Operationfailed)
    }

    async fn expire(&mut self, key: String, ttl: u32) -> Result<(), wit_cache::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Cache | CapabilityWorld::Trusted
        ) {
            // MCP-696 (2026-05-13): audit-ledger parity — see cache::get above.
            self.record_capability_denied("cache-expire", "capability-world", &key)
                .await;
            tracing::warn!("WASM module attempted cache access but lacks Cache capability");
            return Err(wit_cache::Error::Connectionfailed);
        }
        // MCP-754: per-key cap parity with `set`. See MAX_CACHE_KEY_BYTES doc.
        if key.is_empty() || key.len() > MAX_CACHE_KEY_BYTES {
            return Err(wit_cache::Error::Operationfailed);
        }

        if self.cache_budget_refused("cache-expire", &key, 0).await {
            return Err(wit_cache::Error::Operationfailed);
        }
        let ns_key = namespaced_cache_key(self, &key);
        use redis::AsyncCommands;
        let mut conn = self
            .redis_conn()
            .await
            .map_err(|_| wit_cache::Error::Connectionfailed)?;
        // `0` keeps Redis's meaning (expire now); anything else is capped.
        let secs = u64::from(ttl).min(MAX_CACHE_TTL_SECS);
        conn.expire::<_, ()>(&ns_key, secs as i64)
            .await
            .map_err(|_| wit_cache::Error::Operationfailed)
    }
}

#[cfg(test)]
mod namespaced_cache_key_tests {
    use super::build_namespaced_cache_key;
    use uuid::Uuid;

    #[test]
    fn user_scoped_key_has_user_id_prefix() {
        let uid = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
        let got = build_namespaced_cache_key(Some(uid), "foo");
        assert_eq!(
            got,
            "talos_cache:u=00000000-0000-4000-8000-000000000001:foo"
        );
    }

    #[test]
    fn no_user_id_routes_to_system_bucket() {
        // System executions (scheduler, internal) get their own bucket so
        // a malicious guest can never probe internal cache entries by
        // omitting their own user_id.
        assert_eq!(
            build_namespaced_cache_key(None, "foo"),
            "talos_cache:u=system:foo",
        );
    }

    #[test]
    fn distinct_users_get_distinct_namespaces() {
        // Cross-tenant isolation invariant: two users with the same key
        // string must produce different Redis keys.
        let a = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
        let b = Uuid::parse_str("00000000-0000-4000-8000-000000000002").unwrap();
        assert_ne!(
            build_namespaced_cache_key(Some(a), "shared-key"),
            build_namespaced_cache_key(Some(b), "shared-key"),
        );
    }

    #[test]
    fn user_id_cannot_collide_with_system_token() {
        // UUIDs always contain hyphens; the literal `system` token does not
        // parse as a Uuid. No user_id can collide with the system bucket.
        assert!(Uuid::parse_str("system").is_err());
    }

    #[test]
    fn keys_containing_namespace_separator_do_not_break_isolation() {
        // A guest who tries to escape its own namespace by embedding
        // `:u=` in the key cannot probe another user's bucket — the
        // prefix is BEFORE the key, so the resulting Redis key still
        // starts with the right user namespace.
        let uid = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
        let injected = "extra:u=00000000-0000-4000-8000-000000000002:victim";
        let got = build_namespaced_cache_key(Some(uid), injected);
        assert!(got.starts_with("talos_cache:u=00000000-0000-4000-8000-000000000001:"));
        // The injected suffix is present but inert — Redis treats the
        // whole string as one opaque key.
        assert!(got.ends_with(injected));
    }
}

#[cfg(test)]
mod cache_budget_tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    #[test]
    fn no_write_is_immortal_and_ttls_are_capped() {
        assert_eq!(effective_cache_ttl(None), DEFAULT_CACHE_TTL_SECS);
        assert_eq!(effective_cache_ttl(Some(0)), DEFAULT_CACHE_TTL_SECS);
        assert_eq!(effective_cache_ttl(Some(60)), 60);
        assert_eq!(effective_cache_ttl(Some(u32::MAX)), MAX_CACHE_TTL_SECS);
    }

    #[test]
    fn write_budget_refuses_past_the_cap_and_charges_nothing() {
        let used = AtomicU64::new(0);
        assert!(reserve_cache_bytes(
            &used,
            10 * 1024 * 1024,
            MAX_CACHE_WRITE_BYTES_PER_EXECUTION
        ));
        // mset's worst case (1000 x 10 MiB) is refused outright.
        assert!(!reserve_cache_bytes(
            &used,
            1000 * 10 * 1024 * 1024,
            MAX_CACHE_WRITE_BYTES_PER_EXECUTION
        ));
        assert_eq!(
            used.load(std::sync::atomic::Ordering::Relaxed),
            10 * 1024 * 1024
        );
        assert!(!reserve_cache_bytes(
            &used,
            u64::MAX,
            MAX_CACHE_WRITE_BYTES_PER_EXECUTION
        ));
    }

    /// TEXTUAL pin: every method charges the budget, and no write path
    /// can create a key without a TTL.
    #[test]
    fn source_pin_every_method_charges_the_budget() {
        let src = include_str!("cache.rs");
        let start = src.find("impl wit_cache::Host for TalosContext").unwrap();
        // Production region only: this test's own needles must not match.
        let end = src
            .find("#[cfg(test)]\nmod namespaced_cache_key_tests")
            .unwrap();
        let body = &src[start..end];
        for op in [
            "\"cache-get\", &key, 0",
            "\"cache-set\", &key, write_bytes",
            "\"cache-delete\", &key, 0",
            "\"cache-exists\", &key, 0",
            "\"cache-increment\", &key",
            "\"cache-mget\", &target, 0",
            "\"cache-mset\", &target, write_bytes",
            "\"cache-expire\", &key, 0",
        ] {
            assert!(
                body.contains(&format!("cache_budget_refused({op}")),
                "{op} must charge the per-execution cache budget"
            );
        }
        assert!(
            !body.contains("conn.set::<"),
            "a TTL-less SET is an immortal key"
        );
        assert!(!body.contains("conn.mset::<"), "MSET carries no TTL");
    }

    /// Behavioural: the budget is charged BEFORE any Redis connection, so a
    /// spent budget refuses with no Redis configured at all.
    #[tokio::test]
    async fn a_spent_call_budget_refuses_before_redis() {
        use wit_cache::Host;
        let mut ctx = TalosContext::new(
            crate::wit_inspector::CapabilityWorld::Cache,
            vec![],
            vec![],
            128,
            std::collections::HashMap::new(),
            None,
            None,
            false,
            None,
            std::sync::Arc::new(crate::expose_fallback::ExposeFallback::new()),
            talos_workflow_job_protocol::LlmTier::Tier2,
            None,
        )
        .expect("context builds");
        ctx.cache_call_count.store(
            MAX_CACHE_CALLS_PER_EXECUTION,
            std::sync::atomic::Ordering::Relaxed,
        );
        assert!(matches!(
            ctx.get("k".into()).await,
            Err(wit_cache::Error::Operationfailed)
        ));
        assert!(!ctx.exists("k".into()).await);
        assert!(matches!(
            ctx.set("k".into(), "v".into(), None).await,
            Err(wit_cache::Error::Operationfailed)
        ));
    }
}
