pub mod api;
pub mod module_fetcher;
pub mod module_visibility;
pub mod reconcile;
pub mod sync;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::{Pool, Postgres};
use talos_capability_world::CapabilityWorld;
// L-27: canonical user-scoped WASM cache-key + dispatch-URI format, shared
// with `talos-workflow-engine` (the engine emits the URI; the registry writes
// the key) so the two can never drift. Both crates depend on this one.
use talos_workflow_engine_core::{scoped_wasm_cache_key, scoped_wasm_redis_uri};
use uuid::Uuid;

const MAX_ALLOWED_HOSTS: usize = 50;
/// MCP-1123 (2026-05-16): per-host length cap for `allowed_hosts`
/// entries. DNS RFC 1035 §2.3.4 caps a full domain name at 253 ASCII
/// chars (255 minus the trailing null + length-prefix byte). Anything
/// longer cannot be a valid hostname; rejecting it at the validator
/// boundary prevents persisted garbage (operator typo, malformed
/// upstream registry payload, attacker-supplied multi-MB string) from
/// living in `wasm_modules.allowed_hosts` and consuming RAM on every
/// outbound check.
const MAX_HOST_LENGTH: usize = 253;

/// Map a `wasm_modules.capability_world` or `node_templates.capability_world`
/// string (stored as a label like `"network-node"` or `"trusted"`) to the
/// typed [`talos_capability_world::CapabilityWorld`] the dispatcher understands.
///
/// Unknown labels map to [`CapabilityWorld::Unknown`] and the dispatcher
/// treats them as the most-restrictive world — fails closed.
///
/// MCP-815 (2026-05-14): delegates to the canonical
/// `<CapabilityWorld as FromStr>::from_str` impl in `talos-capability-world`
/// instead of duplicating its match arms. Pre-fix this was a hand-copied
/// match (identical to the canonical version's body) that worked TODAY but
/// would silently drift the next time a world was added — same crate-pair
/// reimplementation class as MCP-814 (retry-policy cap drift). The
/// canonical impl is a total parser returning `Ok(Unknown)` on miss; the
/// wrapper preserves the historical infallible signature so call sites
/// don't need a `.expect()`.
fn parse_capability_world(label: &str) -> CapabilityWorld {
    use std::str::FromStr;
    // The canonical impl is total — `Err` is unreachable, but unwrap_or
    // makes the fall-closed semantic explicit at the call site.
    CapabilityWorld::from_str(label).unwrap_or(CapabilityWorld::Unknown)
}

/// Clamp a stored `max_fuel` value to the dispatcher's hard ceiling and
/// fall back to the 1M default when the DB value is zero or negative.
///
/// The 50M cap matches the cap applied to node-config `max_fuel` overrides
/// elsewhere in the dispatcher; the two ceilings are kept numerically
/// identical so an operator can't raise one without raising the other.
fn clamp_execution_fuel(db_max_fuel: i64) -> i64 {
    if db_max_fuel > 0 {
        db_max_fuel.min(50_000_000)
    } else {
        1_000_000
    }
}

/// Inline-dispatch byte ceiling — modules larger than this are dispatched
/// by `redis:wasm:{user_id}:{id}` URI rather than embedded in the
/// `DispatchJob`, so their bytes MUST be resident in Redis before the
/// worker fetches them.
///
/// Kept in lockstep with the engine's authoritative copy
/// (`talos_workflow_engine::dispatch_bytes::inline_wasm_cap_bytes`) via the
/// SAME env var + default — the registry can't depend on the engine crate
/// (that would invert the layering), so the value is mirrored here and the
/// two are aligned by reading identical config. If they ever diverge the
/// failure is safe-but-suboptimal (a module between the two thresholds gets
/// a synchronous pre-warm it didn't strictly need), never a miss.
fn inline_wasm_cap_bytes() -> usize {
    static CAP: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CAP.get_or_init(|| {
        std::env::var("TALOS_INLINE_WASM_MAX_BYTES")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(4 * 1024 * 1024)
    })
}

/// MCP-548: decode `allowed_secrets TEXT[]` from a Postgres row, logging
/// loudly when the decode fails. The column is `NOT NULL DEFAULT '{}'` per
/// the migration, so a decode error indicates a real anomaly: a schema-type
/// drift (TEXT[] → JSONB etc.), a SQLx type-mapping regression, or a
/// projection that lost the column. The fail-closed Vec::new() return
/// preserves the security invariant (empty allowed_secrets denies every
/// vault path per `vault_path_permitted`) but the prior silent
/// `unwrap_or_default()` made the symptom indistinguishable from a module
/// the operator legitimately installed with no secret grants. Surfacing
/// the underlying sqlx error lets operators tell schema drift apart from
/// a deliberately empty grant.
fn decode_allowed_secrets(row: &sqlx::postgres::PgRow, module_id: Uuid) -> Vec<String> {
    use sqlx::Row;
    match row.try_get::<Vec<String>, _>("allowed_secrets") {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                target: "talos_registry",
                event_kind = "allowed_secrets_decode_failed",
                module_id = %module_id,
                error = %e,
                "MCP-548: allowed_secrets column decode failed — falling back to empty (deny-all). \
                 Every vault path will be denied for this module until schema parity is restored. \
                 Check recent migrations for a TEXT[] → JSONB / projection-loss regression."
            );
            Vec::new()
        }
    }
}

/// Validate an `allowed_hosts` list.
/// Each entry must be either `"*"` (wildcard) or a bare hostname (no scheme, no path).
/// Returns `Ok(())` or an error message string suitable for any caller (Axum, GraphQL, etc.).
///
/// MCP-1123 (2026-05-16): tightened to reject malformed entries that
/// previously passed the validator but silently failed at runtime:
///
///  * Per-entry length cap of 253 chars (DNS RFC 1035 §2.3.4). Pre-fix
///    a multi-MB host string (operator typo / malformed upstream
///    registry payload / attacker-controlled upload) persisted to
///    `wasm_modules.allowed_hosts` and the worker's
///    `allowed_hosts.iter().any(|p| p == host)` exact-match loop ran
///    against it on every outbound HTTP / GraphQL / webhook call —
///    wasted CPU + RAM proportional to the bad entry size on every
///    outbound check from the affected module.
///
///  * Port-specifier (`host:port`) rejection. The worker's match is
///    against `url::Url::host_str()` which returns the host portion
///    WITHOUT the port, so entries like `"api.github.com:8443"`
///    silently never matched any outbound URL (operator thought they
///    were allow-listing the service; the worker denied every
///    request). Rejecting at validator time surfaces the
///    misconfiguration loudly.
///
///  * Charset restriction to ASCII alphanumeric + `-`, `.`, `*`
///    (wildcard prefix used by some allowlist conventions). Rejects
///    control chars, whitespace, newlines, non-ASCII. Same defense-in-
///    depth class as MCP-1003 (key_path canonical charset) — gates
///    bad data at the trust boundary rather than relying on every
///    downstream consumer to handle it correctly.
pub fn validate_allowed_hosts(hosts: &[String]) -> std::result::Result<(), String> {
    if hosts.len() > MAX_ALLOWED_HOSTS {
        return Err(format!(
            "allowed_hosts exceeds maximum of {} entries",
            MAX_ALLOWED_HOSTS
        ));
    }
    for host in hosts {
        if host == "*" {
            continue;
        }
        if host.is_empty() {
            return Err("allowed_hosts entry must not be empty".to_string());
        }
        if host.len() > MAX_HOST_LENGTH {
            return Err(format!(
                "Invalid allowed_hosts entry: hostname exceeds {} chars (DNS RFC 1035 cap). Got {} chars.",
                MAX_HOST_LENGTH,
                host.len()
            ));
        }
        if host.contains("://") || host.contains('/') {
            return Err(format!(
                "Invalid allowed_hosts entry '{}'. Use a bare hostname (e.g. 'api.github.com'), not a URL.",
                talos_text_util::bounded_preview(host, 64)
            ));
        }
        if host.contains(':') {
            return Err(format!(
                "Invalid allowed_hosts entry '{}'. Port specifiers are not supported — outbound URL matching ignores port. Use just the hostname (e.g. 'api.github.com').",
                talos_text_util::bounded_preview(host, 64)
            ));
        }
        // Charset: ASCII alphanumeric + `-`, `.`, `*` (for wildcard-prefix
        // conventions like `*.example.com` that some allowlist consumers
        // accept). Rejects control chars, whitespace, newlines, non-ASCII.
        if !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '*')
        {
            return Err(format!(
                "Invalid allowed_hosts entry '{}'. Hostname must be ASCII alphanumeric plus '-', '.', or '*'.",
                talos_text_util::bounded_preview(host, 64)
            ));
        }
    }
    Ok(())
}

/// MCP-1124 (2026-05-16): per-entry caps for `allowed_secrets`.
/// Vault-path allowlist entries — must match the `vault_path_permitted`
/// matcher's pattern grammar.
const MAX_ALLOWED_SECRETS: usize = 50;
const MAX_SECRET_PATH_LENGTH: usize = 200;

/// Validate an `allowed_secrets` list.
///
/// MCP-1124 (2026-05-16): sibling sweep of MCP-1123. The OCI catalog
/// sync (`sync.rs`) and the operator publish endpoint (`api.rs`)
/// both persisted `allowed_secrets` to the unified `modules` table
/// with no validation. `allowed_hosts` was validated since MCP-468
/// but `allowed_secrets` slipped through — same trust-boundary
/// (untrusted upstream OCI manifest / operator publish input),
/// same threat (operator typo, malformed upstream registry payload,
/// signing-key compromise on the publisher side).
///
/// Each entry must match the patterns the
/// `talos_workflow_job_protocol::vault_path_permitted` matcher
/// understands:
///   * `*` — full wildcard (matches every vault path)
///   * `path/segment` — exact match (e.g. `anthropic/api_key`)
///   * `path/prefix/*` — trailing-`/*` prefix pattern
///
/// Path portion (without trailing `/*`) must be 1-200 chars,
/// lowercase ASCII alphanumeric + `-`, `_`, `/`. No leading/trailing
/// `/`, no consecutive `//`. Mirrors `talos_api::validation::
/// validate_vault_key_path` (MCP-1003) plus the prefix-pattern
/// grammar.
pub fn validate_allowed_secrets(secrets: &[String]) -> std::result::Result<(), String> {
    if secrets.len() > MAX_ALLOWED_SECRETS {
        return Err(format!(
            "allowed_secrets exceeds maximum of {} entries",
            MAX_ALLOWED_SECRETS
        ));
    }
    for entry in secrets {
        if entry == "*" {
            continue;
        }
        if entry.is_empty() {
            return Err("allowed_secrets entry must not be empty".to_string());
        }
        if entry.len() > MAX_SECRET_PATH_LENGTH {
            return Err(format!(
                "Invalid allowed_secrets entry: path exceeds {} chars. Got {} chars.",
                MAX_SECRET_PATH_LENGTH,
                entry.len()
            ));
        }
        // Strip optional trailing `/*` prefix-pattern marker so we
        // validate just the path portion.
        let path = entry.strip_suffix("/*").unwrap_or(entry);
        if path.is_empty() {
            return Err(format!(
                "Invalid allowed_secrets entry '{}'. Path portion before '/*' must not be empty.",
                talos_text_util::bounded_preview(entry, 64)
            ));
        }
        if !path.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '/'
        }) {
            return Err(format!(
                "Invalid allowed_secrets entry '{}'. Path must be lowercase ASCII alphanumeric + '-', '_', '/' (optional trailing '/*' for prefix matching).",
                talos_text_util::bounded_preview(entry, 64)
            ));
        }
        if path.starts_with('/') || path.ends_with('/') || path.contains("//") {
            return Err(format!(
                "Invalid allowed_secrets entry '{}'. Path must not start/end with '/' or contain consecutive slashes.",
                talos_text_util::bounded_preview(entry, 64)
            ));
        }
    }
    Ok(())
}

/// Phase 2 read-path counters. Each `get_module` call increments exactly
/// one of these. Surfaced via [`ModuleRegistry::read_path_counters`] for
/// the `get_module_unification_status` MCP operator tool, which uses them
/// to compute the Phase 3 readiness gate (sustained <0.01% miss_new for
/// 24h). Counters reset on controller restart — operators looking at
/// long-term trends should rely on the structured tracing metric instead.
#[derive(Debug, Default)]
pub struct ReadPathCounters {
    pub hit_new: std::sync::atomic::AtomicU64,
    pub hit_legacy: std::sync::atomic::AtomicU64,
    pub miss_new: std::sync::atomic::AtomicU64,
}

/// A module whose compiled bytes were NULLed by the WASM cache sweep
/// (`modules.wasm_evicted_at IS NOT NULL`). The row, its `source_code` and its
/// execution history are intact; only the artifact is gone, and
/// `hot_update_module` restores it. Typed (rather than a bare `anyhow!`) so
/// `get_module_for_execution` can tell it apart from "not found" and refuse to
/// fall through to the stale-name lookup, which would otherwise report a module
/// that exists as missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleBytesEvicted {
    pub module_id: Uuid,
    pub name: String,
    pub evicted_at: chrono::DateTime<chrono::Utc>,
}

impl std::fmt::Display for ModuleBytesEvicted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Module '{}' ({}) has no compiled WASM: its bytes were evicted from the \
             WASM cache at {} (idle past WASM_CACHE_RETENTION_DAYS). The source is \
             retained — recompile with hot_update_module to restore it.",
            self.name,
            self.module_id,
            self.evicted_at.to_rfc3339()
        )
    }
}

impl std::error::Error for ModuleBytesEvicted {}

/// The ONE reading of a `modules` row whose `wasm_bytes` is NULL/empty, shared
/// by `get_module` and the bytes-only reads. Three states, three sentences:
/// OCI-served (fine — the worker pulls), EVICTED (typed, actionable),
/// NEVER COMPILED (the metadata-only catalog shape from the 2026-07-21 defect).
/// Callers pass `oci_url` so an OCI row is never reported as anything else.
fn classify_absent_wasm_bytes(
    module_id: Uuid,
    name: &str,
    evicted_at: Option<chrono::DateTime<chrono::Utc>>,
    oci_url: Option<&str>,
) -> anyhow::Error {
    if oci_url.is_some_and(|u| !u.is_empty()) {
        // Not reachable from `get_module` (it returns before asking), kept so
        // the bytes-only reads cannot misreport an OCI row.
        return anyhow::anyhow!(
            "Module '{}' ({}) is served from its OCI registry and holds no inline bytes",
            name,
            module_id
        );
    }
    match evicted_at {
        Some(evicted_at) => anyhow::Error::new(ModuleBytesEvicted {
            module_id,
            name: name.to_string(),
            evicted_at,
        }),
        None => anyhow::anyhow!(
            "Module '{}' has no compiled WASM yet (metadata-only catalog row). \
             Run install_module_from_catalog to compile it before use.",
            name
        ),
    }
}

/// The dispatch-side recency stamp — see [`ModuleRegistry::touch_last_used`].
///
/// The `AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '1 hour')`
/// clause is the THROTTLE: without it this is one row write per dispatch,
/// contending on a single tuple per module (35,793 executions in the 2026-08
/// corpus). With it, the PK probe finds the row and the predicate declines it
/// for the rest of the hour — an index-only no-op. Pinned by
/// `wasm_cache_sweep_sql_tests::touch_sql_is_throttled_and_keyed_on_pk`.
pub const LAST_USED_TOUCH_SQL: &str = "UPDATE modules \
     SET last_used_at = NOW(), usage_count = usage_count + 1 \
     WHERE id = $1 \
       AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '1 hour')";

pub struct ModuleRegistry {
    pub db_pool: Pool<Postgres>,
    pub redis_client: Option<std::sync::Arc<redis::Client>>,
    /// ONE lazily-built, auto-reconnecting multiplexed Redis connection shared
    /// by every cache read/write in this registry (the `wasm:{user}:{module}`
    /// SETEX / GET / EXISTS sites). Until 2026-09-10 each of those five sites
    /// called `client.get_multiplexed_async_connection()` per call — a fresh
    /// TCP (+TLS) handshake on every dispatch-time cache fill. Same shape as
    /// `talos-node-cache` / `talos-idempotency`; `Arc` so the fire-and-forget
    /// fill task (`cache_wasm_bytes_under`) can share it without borrowing
    /// `self`. `get_or_try_init` does not cache a failed init, so a Redis
    /// outage at first use is retried on the next call.
    redis_conn: std::sync::Arc<tokio::sync::OnceCell<redis::aio::ConnectionManager>>,
    /// Phase 2 fall-through counters (see ReadPathCounters docs).
    pub(crate) read_path_counters: std::sync::Arc<ReadPathCounters>,
    /// Process-start instant — operator tool reports "uptime" alongside
    /// the counter values so an unusually low total doesn't get mistaken
    /// for a sudden traffic drop.
    pub(crate) started_at: std::time::Instant,
}

#[allow(dead_code)]
pub struct ModuleExecutionInfo {
    pub module_uri: String,
    /// SHA-256 hex digest of the WASM binary, recorded at compile/registration time.
    /// Propagated into `JobRequest::expected_wasm_hash` so the worker can verify
    /// the content it loads from the registry matches what the controller compiled.
    pub content_hash: String,
    pub config: Option<JsonValue>,
    pub allowed_hosts: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_secrets: Vec<String>,
    pub requires_approval_for: Vec<String>,
    /// Per-module fuel budget from `wasm_modules.max_fuel`. Used as the
    /// dispatch-time fallback when a node config has no `max_fuel` override.
    /// Without this, template-dispatched pipeline paths hardcoded 1M and
    /// silently ignored any DB bump.
    pub max_fuel: u64,
    /// Integration this module belongs to, if any. Propagated into
    /// JobRequest / PipelineStep so the worker scopes integration_state
    /// host fns correctly.
    pub integration_name: Option<String>,
}

/// Free-function twin of [`ModuleRegistry::redis_conn`] for tasks that hold an
/// `Arc` to the cell rather than `&self` (the spawned cache fill).
async fn redis_conn_from(
    cell: &tokio::sync::OnceCell<redis::aio::ConnectionManager>,
    client: &redis::Client,
) -> Result<redis::aio::ConnectionManager, redis::RedisError> {
    let mgr = cell
        .get_or_try_init(|| async { redis::aio::ConnectionManager::new(client.clone()).await })
        .await?;
    Ok(mgr.clone())
}

impl ModuleRegistry {
    /// Snapshot the Phase 2 read-path counters. Returns
    /// (hit_new, hit_legacy, miss_new, uptime_secs).
    pub fn read_path_counters(&self) -> (u64, u64, u64, u64) {
        use std::sync::atomic::Ordering;
        (
            self.read_path_counters.hit_new.load(Ordering::Relaxed),
            self.read_path_counters.hit_legacy.load(Ordering::Relaxed),
            self.read_path_counters.miss_new.load(Ordering::Relaxed),
            self.started_at.elapsed().as_secs(),
        )
    }

    pub fn new(
        db_pool: Pool<Postgres>,
        redis_client: Option<std::sync::Arc<redis::Client>>,
    ) -> Self {
        Self {
            db_pool,
            redis_client,
            redis_conn: std::sync::Arc::new(tokio::sync::OnceCell::new()),
            read_path_counters: std::sync::Arc::new(ReadPathCounters::default()),
            started_at: std::time::Instant::now(),
        }
    }

    /// A clone of the shared [`redis::aio::ConnectionManager`], building it
    /// on first use. `None` when no Redis is configured; `Err` when Redis is
    /// configured but unreachable right now (the cell stays empty so the
    /// next call retries).
    async fn redis_conn(&self) -> Option<Result<redis::aio::ConnectionManager, redis::RedisError>> {
        let client = self.redis_client.as_ref()?;
        Some(redis_conn_from(&self.redis_conn, client).await)
    }

    /// List all templates, optionally filtered by category.
    ///
    /// **UNSCOPED and BLOB-HEAVY — internal callers only.** This reads EVERY
    /// row of `modules` regardless of `user_id` (every tenant's private
    /// modules alongside the shared catalog) and projects `source_code` AND
    /// `wasm_bytes` for each, so one call loads every compiled binary on the
    /// deployment into memory. No caller-facing surface may use it: a
    /// per-user listing is `list_template_metadata_for_user`, which carries
    /// the tenancy predicate and no blobs. (2026-09-10: `list_templates`,
    /// `tools/list` and `get_platform_info` all called this, i.e. any
    /// authenticated MCP agent enumerated every other tenant's module names,
    /// descriptions, config schemas, allowed hosts and secret paths.)
    ///
    /// Phase 5: reads from the unified `modules` table. The legacy
    /// `node_templates.icon` column has no equivalent on `modules` and is
    /// surfaced as `None`; `code_template` maps to `modules.source_code`;
    /// `precompiled_wasm` maps to `modules.wasm_bytes`.
    pub async fn list_templates(&self, category: Option<&str>) -> Result<Vec<NodeTemplate>> {
        let templates = if let Some(cat) = category {
            sqlx::query_as::<_, NodeTemplateRow>(
                "SELECT id, name, COALESCE(category, kind) AS category, description, config_schema, \
                        COALESCE(source_code, '') AS code_template, wasm_bytes AS precompiled_wasm, \
                        NULL::TEXT AS icon, oci_url, allowed_hosts, allowed_methods, allowed_secrets, \
                        requires_approval_for, max_retries, retry_backoff_ms, capability_world, dependencies \
                 FROM modules WHERE COALESCE(category, kind) = $1"
            )
            .bind(cat)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query_as::<_, NodeTemplateRow>(
                "SELECT id, name, COALESCE(category, kind) AS category, description, config_schema, \
                        COALESCE(source_code, '') AS code_template, wasm_bytes AS precompiled_wasm, \
                        NULL::TEXT AS icon, oci_url, allowed_hosts, allowed_methods, allowed_secrets, \
                        requires_approval_for, max_retries, retry_backoff_ms, capability_world, dependencies \
                 FROM modules"
            )
            .fetch_all(&self.db_pool)
            .await?
        };

        Ok(templates.into_iter().map(|row| row.into()).collect())
    }

    /// Tenant-scoped, metadata-only template listing (2026-09-10).
    ///
    /// Rows visible to `user_id` are the shared catalog (`user_id IS NULL`)
    /// plus the caller's own — the same predicate `get_template_for_user` /
    /// `list_templates_paginated_for_user` use (there is no org-share arm on
    /// `modules` in those readers, so none is added here). `Uuid::nil()` is
    /// the documented spelling for an agent with no user scope and yields the
    /// catalog alone.
    ///
    /// The projection carries NO `wasm_bytes` and NO `source_code`; whether a
    /// compiled binary exists is answered by `is_compiled`
    /// (`wasm_bytes IS NOT NULL AND octet_length(wasm_bytes) > 0`), computed
    /// server-side so the blob never crosses the wire. This is the listing
    /// every caller-facing surface must use; `list_templates` is unscoped and
    /// loads every binary.
    pub async fn list_template_metadata_for_user(
        &self,
        user_id: Uuid,
        category: Option<&str>,
    ) -> Result<Vec<NodeTemplateMetadata>> {
        // Two static literals rather than one `format!`-assembled statement,
        // so check 88 can PREPARE both against the real schema.
        let rows = if let Some(cat) = category {
            sqlx::query_as::<_, NodeTemplateMetadata>(
                "SELECT id, name, COALESCE(category, kind) AS category, description, \
                        config_schema, allowed_hosts, allowed_methods, allowed_secrets, \
                        requires_approval_for, capability_world, \
                        (wasm_bytes IS NOT NULL AND octet_length(wasm_bytes) > 0) AS is_compiled \
                 FROM modules \
                 WHERE COALESCE(category, kind) = $1 AND (user_id IS NULL OR user_id = $2) \
                 ORDER BY name ASC, id ASC",
            )
            .bind(cat)
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query_as::<_, NodeTemplateMetadata>(
                "SELECT id, name, COALESCE(category, kind) AS category, description, \
                        config_schema, allowed_hosts, allowed_methods, allowed_secrets, \
                        requires_approval_for, capability_world, \
                        (wasm_bytes IS NOT NULL AND octet_length(wasm_bytes) > 0) AS is_compiled \
                 FROM modules \
                 WHERE user_id IS NULL OR user_id = $1 \
                 ORDER BY name ASC, id ASC",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await?
        };
        Ok(rows)
    }

    /// List templates with pagination, optionally filtered by category.
    ///
    /// Phase 5: reads from `modules` (see `list_templates` for the column
    /// mapping notes).
    pub async fn list_templates_paginated(
        &self,
        category: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<NodeTemplate>> {
        let templates = if let Some(cat) = category {
            sqlx::query_as::<_, NodeTemplateRow>(
                "SELECT id, name, COALESCE(category, kind) AS category, description, config_schema, \
                        COALESCE(source_code, '') AS code_template, wasm_bytes AS precompiled_wasm, \
                        NULL::TEXT AS icon, oci_url, allowed_hosts, allowed_methods, allowed_secrets, \
                        requires_approval_for, max_retries, retry_backoff_ms, capability_world, dependencies \
                 FROM modules WHERE COALESCE(category, kind) = $1 ORDER BY name ASC, id ASC LIMIT $2 OFFSET $3"
            )
            .bind(cat)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query_as::<_, NodeTemplateRow>(
                "SELECT id, name, COALESCE(category, kind) AS category, description, config_schema, \
                        COALESCE(source_code, '') AS code_template, wasm_bytes AS precompiled_wasm, \
                        NULL::TEXT AS icon, oci_url, allowed_hosts, allowed_methods, allowed_secrets, \
                        requires_approval_for, max_retries, retry_backoff_ms, capability_world, dependencies \
                 FROM modules ORDER BY name ASC, id ASC LIMIT $1 OFFSET $2"
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db_pool)
            .await?
        };

        Ok(templates.into_iter().map(|row| row.into()).collect())
    }

    /// User-scoped paginated template listing — returns catalog templates
    /// (`user_id IS NULL`) plus templates owned by `user_id`. Prevents the
    /// MCP-794 IDOR where the GraphQL `node_templates` query previously
    /// returned every user's private template metadata (name, description,
    /// config_schema, allowed_hosts) to any authenticated caller.
    ///
    /// Same predicate as `get_template_for_user` (MCP-793) extended over a
    /// paginated set. Catalog templates remain accessible to everyone;
    /// private templates resolve only for their owner.
    pub async fn list_templates_paginated_for_user(
        &self,
        category: Option<&str>,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<NodeTemplate>> {
        let templates = if let Some(cat) = category {
            sqlx::query_as::<_, NodeTemplateRow>(
                "SELECT id, name, COALESCE(category, kind) AS category, description, config_schema, \
                        COALESCE(source_code, '') AS code_template, wasm_bytes AS precompiled_wasm, \
                        NULL::TEXT AS icon, oci_url, allowed_hosts, allowed_methods, allowed_secrets, \
                        requires_approval_for, max_retries, retry_backoff_ms, capability_world, dependencies \
                 FROM modules \
                 WHERE COALESCE(category, kind) = $1 \
                   AND (user_id IS NULL OR user_id = $2) \
                 ORDER BY name ASC, id ASC LIMIT $3 OFFSET $4"
            )
            .bind(cat)
            .bind(user_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query_as::<_, NodeTemplateRow>(
                "SELECT id, name, COALESCE(category, kind) AS category, description, config_schema, \
                        COALESCE(source_code, '') AS code_template, wasm_bytes AS precompiled_wasm, \
                        NULL::TEXT AS icon, oci_url, allowed_hosts, allowed_methods, allowed_secrets, \
                        requires_approval_for, max_retries, retry_backoff_ms, capability_world, dependencies \
                 FROM modules \
                 WHERE user_id IS NULL OR user_id = $1 \
                 ORDER BY name ASC, id ASC LIMIT $2 OFFSET $3"
            )
            .bind(user_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db_pool)
            .await?
        };

        Ok(templates.into_iter().map(|row| row.into()).collect())
    }

    /// Get single template by ID. Phase 5.1: reads from `modules` by canonical id.
    pub async fn get_template(&self, id: Uuid) -> Result<NodeTemplate> {
        let row = sqlx::query_as::<_, NodeTemplateRow>(
            "SELECT id, name, COALESCE(category, kind) AS category, description, config_schema, \
                    COALESCE(source_code, '') AS code_template, wasm_bytes AS precompiled_wasm, \
                    NULL::TEXT AS icon, oci_url, allowed_hosts, allowed_methods, allowed_secrets, \
                    requires_approval_for, max_retries, retry_backoff_ms, capability_world, dependencies \
             FROM modules \
             WHERE id = $1 \
             LIMIT 1"
        )
        .bind(id)
        .fetch_one(&self.db_pool)
        .await
        .context("Template not found")?;

        Ok(row.into())
    }

    /// User-scoped template lookup: returns catalog templates (user_id IS NULL) and
    /// templates owned by `user_id`. Prevents IDOR — callers cannot access templates
    /// owned by other users. Use this for MCP / API endpoints.
    ///
    /// Phase 5.1: reads from `modules` by canonical id.
    pub async fn get_template_for_user(&self, id: Uuid, user_id: Uuid) -> Result<NodeTemplate> {
        let row = sqlx::query_as::<_, NodeTemplateRow>(
            "SELECT id, name, COALESCE(category, kind) AS category, description, config_schema, \
                    COALESCE(source_code, '') AS code_template, wasm_bytes AS precompiled_wasm, \
                    NULL::TEXT AS icon, oci_url, allowed_hosts, allowed_methods, allowed_secrets, \
                    requires_approval_for, max_retries, retry_backoff_ms, capability_world, dependencies \
             FROM modules \
             WHERE id = $1 \
               AND (user_id IS NULL OR user_id = $2) \
             LIMIT 1"
        )
        .bind(id)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await
        .context("Template not found or access denied")?;

        Ok(row.into())
    }

    /// Store compiled WASM module.
    ///
    /// Phase 5: writes the unified `modules` table (kind = `"sandbox"` for
    /// user-owned compiles, `"catalog"` for system-owned). Content-hash
    /// dedup short-circuits repeat writes of the same binary. The upsert
    /// key is `(user_id, name)` (partial unique index on modules) so
    /// recompiles of the same-named module preserve the row's id — the
    /// same behavioural contract the legacy `(user_id, template_id)` upsert
    /// provided, but keyed on the identifier every caller already has in
    /// hand.
    pub async fn store_module(&self, module: WasmModule) -> Result<Uuid> {
        // Content-hash dedup: if the exact binary already exists in
        // `modules`, return that id instead of inserting a duplicate.
        // Bounded to the caller's ownership scope to avoid cross-tenant
        // reuse of a user-compiled module.
        let existing_same_hash = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM modules WHERE content_hash = $1 \
               AND (user_id = $2 OR (user_id IS NULL AND $2 IS NULL)) \
             LIMIT 1",
        )
        .bind(&module.content_hash)
        .bind(module.user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("Failed to check modules content_hash")?;
        if let Some(id) = existing_same_hash {
            return Ok(id);
        }

        // Long-form capability world to match the `modules.capability_world`
        // convention (see mirror_module_write — stored as `"secrets-node"`,
        // not `"secrets"`, for parity with the worker-side parser).
        let cw_short = module.capability_world.to_string();
        let cw_long = if cw_short == "trusted" {
            "automation-node".to_string()
        } else if cw_short.ends_with("-node") {
            cw_short.clone()
        } else {
            format!("{}-node", cw_short)
        };
        // `kind` = sandbox when a user owns the row; catalog when
        // `user_id IS NULL` (the latter is rare on this path — catalog
        // seeds go through publish_template / sync_repo_tag).
        let kind = if module.user_id.is_some() {
            "sandbox"
        } else {
            "catalog"
        };

        let id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO modules ( \
                user_id, name, kind, capability_world, \
                allowed_hosts, allowed_methods, allowed_secrets, requires_approval_for, \
                source_code, wasm_bytes, content_hash, size_bytes, max_fuel, max_memory_mb, \
                imported_interfaces, dependencies, config, \
                oci_url, language, \
                created_at, compiled_at, updated_at \
             ) VALUES ( \
                $1, $2, $3, $4, \
                $5, $6, $7, $8, \
                $9, $10, $11, $12, $13, $14, \
                $15, $16, $17, \
                $18, $19, \
                NOW(), NOW(), NOW() \
             ) \
             ON CONFLICT (user_id, name) WHERE user_id IS NOT NULL DO UPDATE SET \
                capability_world      = EXCLUDED.capability_world, \
                allowed_hosts         = EXCLUDED.allowed_hosts, \
                allowed_methods       = EXCLUDED.allowed_methods, \
                allowed_secrets       = EXCLUDED.allowed_secrets, \
                requires_approval_for = EXCLUDED.requires_approval_for, \
                source_code           = EXCLUDED.source_code, \
                wasm_bytes            = EXCLUDED.wasm_bytes, \
                content_hash          = EXCLUDED.content_hash, \
                size_bytes            = EXCLUDED.size_bytes, \
                max_fuel              = EXCLUDED.max_fuel, \
                max_memory_mb         = EXCLUDED.max_memory_mb, \
                imported_interfaces   = EXCLUDED.imported_interfaces, \
                dependencies          = EXCLUDED.dependencies, \
                config                = EXCLUDED.config, \
                oci_url               = EXCLUDED.oci_url, \
                language              = EXCLUDED.language, \
                compiled_at           = NOW() \
             /* updated_at deliberately NOT set: the BEFORE UPDATE trigger stamps \
                it only when a non-maintenance column really changed. An explicit \
                NOW() overrides that verdict and re-dates every catalog row at \
                every boot — the defect migration 20260905120000 measured at 75 of \
                112 module rows sharing one boot second. */ \
             RETURNING id",
        )
        .bind(module.user_id)
        .bind(&module.name)
        .bind(kind)
        .bind(&cw_long)
        .bind(&module.allowed_hosts)
        .bind(&module.allowed_methods)
        .bind(&module.allowed_secrets)
        .bind(&module.requires_approval_for)
        .bind(&module.source_code)
        .bind(&module.wasm_bytes)
        .bind(&module.content_hash)
        .bind(module.size_bytes)
        .bind(module.max_fuel)
        .bind(module.max_memory_mb)
        .bind(&module.imported_interfaces)
        .bind(&module.dependencies)
        .bind(&module.config)
        .bind(&module.oci_url)
        .bind(&module.language)
        .fetch_one(&self.db_pool)
        .await
        .context("Failed to insert module")?;

        // L-27: no store-time Redis seed. The old seed wrote a non-scoped
        // `wasm:{id}` key, which is exactly the cross-tenant-readable shadow
        // key this fix removes. Scoping it under the module owner would be
        // dead weight: the read path is user-scoped and the dispatch-prep
        // pre-warm (`get_module` -> `cache_wasm_bytes_under` /
        // `ensure_wasm_bytes_cached`, both keyed on the EXECUTING user) fires
        // before every dispatch and provably covers the redis-routed path.
        // For catalog modules (`user_id IS NULL`) there is no single owner to
        // scope to anyway. So the seed is dropped entirely; the first
        // execution's pre-warm populates the correct user-scoped key.

        Ok(id)
    }

    /// Like `store_module` but always inserts a fresh row with a new UUID.
    /// Used by `compile_template` where each invocation must produce a distinct
    /// module_id — the `(user_id, name)` upsert in `store_module` would otherwise
    /// return the existing row's id, silently discarding the newly-compiled binary.
    ///
    /// Phase 5: name-collision avoidance now lives on the caller side — the
    /// MCP `compile_template` path already forces distinct display names per
    /// invocation. On this path we intentionally do NOT upsert: if a
    /// same-named row already exists for this user, the partial unique index
    /// on `(user_id, name)` surfaces the collision as a SQL error so the
    /// caller can pick a unique name rather than silently shadowing the
    /// existing module.
    pub async fn store_module_fresh(&self, module: WasmModule) -> Result<Uuid> {
        let cw_short = module.capability_world.to_string();
        let cw_long = if cw_short == "trusted" {
            "automation-node".to_string()
        } else if cw_short.ends_with("-node") {
            cw_short.clone()
        } else {
            format!("{}-node", cw_short)
        };
        let kind = if module.user_id.is_some() {
            "sandbox"
        } else {
            "catalog"
        };

        let id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO modules ( \
                user_id, name, kind, capability_world, \
                allowed_hosts, allowed_methods, allowed_secrets, requires_approval_for, \
                source_code, wasm_bytes, content_hash, size_bytes, max_fuel, max_memory_mb, \
                imported_interfaces, dependencies, config, \
                oci_url, language, \
                created_at, compiled_at, updated_at \
             ) VALUES ( \
                $1, $2, $3, $4, \
                $5, $6, $7, $8, \
                $9, $10, $11, $12, $13, $14, \
                $15, $16, $17, \
                $18, $19, \
                NOW(), NOW(), NOW() \
             ) \
             RETURNING id",
        )
        .bind(module.user_id)
        .bind(&module.name)
        .bind(kind)
        .bind(&cw_long)
        .bind(&module.allowed_hosts)
        .bind(&module.allowed_methods)
        .bind(&module.allowed_secrets)
        .bind(&module.requires_approval_for)
        .bind(&module.source_code)
        .bind(&module.wasm_bytes)
        .bind(&module.content_hash)
        .bind(module.size_bytes)
        .bind(module.max_fuel)
        .bind(module.max_memory_mb)
        .bind(&module.imported_interfaces)
        .bind(&module.dependencies)
        .bind(&module.config)
        .bind(&module.oci_url)
        .bind(&module.language)
        .fetch_one(&self.db_pool)
        .await
        .context("Failed to insert fresh module")?;

        // L-27: no store-time Redis seed (same rationale as store_module) —
        // the old seed wrote the cross-tenant-readable non-scoped `wasm:{id}`
        // shadow key. The dispatch-prep pre-warm populates the correct
        // user-scoped key before the first execution.

        Ok(id)
    }

    /// Phase 5: dead code. All live update paths route through
    /// `ModuleRepository::mirror_module_write` / hot_update_module.
    /// Retained as a no-op stub so any cold caller fails loudly rather
    /// than writing to a legacy table that will be dropped in the
    /// schema finalisation step.
    pub async fn update_module(&self, id: Uuid, _module: WasmModule) -> Result<Uuid> {
        anyhow::bail!(
            "registry::update_module is no longer supported — modules are written via \
             ModuleRepository::mirror_module_write (programmatic) or the hot_update_module \
             MCP tool (operator). Requested id: {}",
            id
        )
    }

    pub async fn get_module(&self, module_id: Uuid, user_id: Uuid) -> Result<WasmModule> {
        use sqlx::Row;

        // Phase 3.1 of module entity unification (docs/module-entity-consolidation.md):
        // the `modules` table is now the SINGLE source of truth for module
        // reads. The legacy fallback (wasm_modules + node_templates JOIN)
        // was removed after Phase 2 metrics confirmed sustained 0.0000%
        // miss_new across all observed reads.
        //
        // Phase 5.1: canonical id lookup only. `template_id` projects
        // `modules.id` so the WasmModule struct's legacy field stays
        // populated for downstream consumers that still inspect it.
        //
        // Error handling: a DB error (connection drop, query timeout)
        // bubbles up via `?` so the dispatcher retries the JobRequest
        // rather than reporting "module not found". A genuinely missing
        // row returns the typed "Module not found or access denied" error.
        let row = sqlx::query(
            r#"
            SELECT id, name, content_hash, wasm_bytes, source_code,
                   id AS template_id, config, size_bytes, max_fuel,
                   max_memory_mb, allowed_hosts, allowed_methods, allowed_secrets,
                   requires_approval_for, user_id, capability_world,
                   imported_interfaces, dependencies, oci_url, language, integration_name,
                   wasm_evicted_at
            FROM modules
            WHERE id = $1
              AND (user_id = $2 OR user_id IS NULL)
            ORDER BY compiled_at DESC NULLS LAST
            LIMIT 1
            "#,
        )
        .bind(module_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("Failed to query modules table")?
        .ok_or_else(|| anyhow::anyhow!("Module not found or access denied"))?;

        self.read_path_counters
            .hit_new
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // DEBUG level post-cutover — every dispatch hits this path; logging
        // each one at INFO would flood operator dashboards with a constant
        // baseline that carries no signal. Bump back to INFO temporarily
        // if rollback is being investigated.
        tracing::debug!(
            target: "talos_engine",
            event_kind = "modules_read_path",
            outcome = "hit_new",
            %module_id,
            "served get_module from modules table"
        );

        // MCP-636 (2026-05-12): closes N-3 (talos-registry get_module
        // unwrap_or_default for 10+ fields). Pre-fix every column was
        // read via `try_get(col).unwrap_or_default()`, so a schema
        // drift that dropped or renamed a column silently produced a
        // `WasmModule` with default-valued fields (empty allowed_hosts,
        // empty allowed_methods, default fuel, etc.). The dispatcher
        // would then deny-all and the operator saw a confusing
        // "module call failed" rather than the actual root cause.
        // Propagate try_get errors via `?` so column-rename / type-
        // change failures surface as a descriptive sqlx error. Nullable
        // columns keep `Option<T>` semantics (NULL → None is correct).
        //
        // `allowed_secrets` keeps its dedicated helper because it has
        // a JSON-encoded encrypted-or-plaintext envelope format that
        // doesn't fit a simple type bind. The helper is unchanged.
        let cap_str: String = row
            .try_get("capability_world")
            .context("modules.capability_world: try_get failed (schema drift?)")?;
        let capability_world = parse_capability_world(&cap_str);
        // `wasm_bytes` is NULLABLE — and since 2026-09-10 a NULL has TWO
        // meanings, which is why it is read as `Option` and classified below
        // rather than decoded straight into `Vec<u8>` (a NULL there is a
        // decode error that reads as "not found").
        let wasm_bytes: Vec<u8> = row
            .try_get::<Option<Vec<u8>>, _>("wasm_bytes")
            .context("modules.wasm_bytes: try_get failed (schema drift?)")?
            .unwrap_or_default();

        // 2026-07-21 defect: a catalog registration path could leave a
        // metadata-only row (NULL wasm_bytes, no oci_url) — advertised as a
        // template but non-executable, surfacing at dispatch as a confusing
        // "Module not found". Fail loud with an actionable message so the
        // caller (or the resolve-fallback chain) reports what to do rather
        // than shipping an empty binary to the worker. A row with an
        // `oci_url` is fine — the worker fetches its bytes from the registry.
        //
        // 2026-09-10: the SECOND way to have NULL bytes — the WASM cache sweep
        // evicted them (`wasm_evicted_at IS NOT NULL`; row, source and history
        // kept). That one is a typed `ModuleBytesEvicted` so the dispatch
        // resolver does not fall through to "not found" — see
        // `classify_absent_wasm_bytes`.
        let oci_url: Option<String> = row
            .try_get("oci_url")
            .context("modules.oci_url: try_get failed (schema drift?)")?;
        let oci_url_present = oci_url.as_deref().is_some_and(|u| !u.is_empty());
        if wasm_bytes.is_empty() && !oci_url_present {
            let module_name: String = row
                .try_get("name")
                .context("modules.name: try_get failed (schema drift?)")?;
            let evicted_at: Option<chrono::DateTime<chrono::Utc>> = row
                .try_get("wasm_evicted_at")
                .context("modules.wasm_evicted_at: try_get failed (schema drift?)")?;
            return Err(classify_absent_wasm_bytes(
                module_id,
                &module_name,
                evicted_at,
                None,
            ));
        }

        if !wasm_bytes.is_empty() {
            // Oversized (redis-routed) modules must be resident BEFORE this
            // fetch returns — the worker fetches by `redis:wasm:` URI and
            // would race a fire-and-forget fill. Small (inlined) modules
            // keep the async fill. See `ensure_wasm_bytes_cached`.
            // L-27: pre-warm under the CALLER's `user_id` — the exact id the
            // engine will emit in the dispatch URI for this fetch.
            if wasm_bytes.len() > inline_wasm_cap_bytes() {
                self.ensure_wasm_bytes_cached(user_id, module_id, &wasm_bytes)
                    .await;
            } else {
                self.cache_wasm_bytes_under(user_id, module_id, &wasm_bytes);
            }
        }

        Ok(WasmModule {
            name: row
                .try_get("name")
                .context("modules.name: try_get failed (schema drift?)")?,
            content_hash: row
                .try_get("content_hash")
                .context("modules.content_hash: try_get failed (schema drift?)")?,
            wasm_bytes,
            source_code: row
                .try_get("source_code")
                .context("modules.source_code: try_get failed (schema drift?)")?,
            template_id: row
                .try_get("template_id")
                .context("modules.template_id: try_get failed (schema drift?)")?,
            config: row
                .try_get("config")
                .context("modules.config: try_get failed (schema drift?)")?,
            size_bytes: row
                .try_get("size_bytes")
                .context("modules.size_bytes: try_get failed (schema drift?)")?,
            max_fuel: row
                .try_get("max_fuel")
                .context("modules.max_fuel: try_get failed (schema drift?)")?,
            max_memory_mb: row
                .try_get("max_memory_mb")
                .context("modules.max_memory_mb: try_get failed (schema drift?)")?,
            allowed_hosts: row
                .try_get("allowed_hosts")
                .context("modules.allowed_hosts: try_get failed (schema drift?)")?,
            allowed_methods: row
                .try_get("allowed_methods")
                .context("modules.allowed_methods: try_get failed (schema drift?)")?,
            allowed_secrets: decode_allowed_secrets(&row, module_id),
            requires_approval_for: row
                .try_get("requires_approval_for")
                .context("modules.requires_approval_for: try_get failed (schema drift?)")?,
            user_id: row
                .try_get("user_id")
                .context("modules.user_id: try_get failed (schema drift?)")?,
            capability_world,
            imported_interfaces: row
                .try_get("imported_interfaces")
                .context("modules.imported_interfaces: try_get failed (schema drift?)")?,
            dependencies: row
                .try_get("dependencies")
                .context("modules.dependencies: try_get failed (schema drift?)")?,
            oci_url: row
                .try_get("oci_url")
                .context("modules.oci_url: try_get failed (schema drift?)")?,
            language: row
                .try_get::<Option<String>, _>("language")
                .context("modules.language: try_get failed (schema drift?)")?
                .unwrap_or_else(|| "rust".to_string()),
            integration_name: row
                .try_get::<Option<String>, _>("integration_name")
                .context("modules.integration_name: try_get failed (schema drift?)")?,
        })
    }

    /// Fetch a wasm module for workflow dispatch, honoring all the fallback
    /// paths a live execution may need.
    ///
    /// Four resolution levels are tried in order:
    ///
    /// 1. **Primary**: [`get_module`](Self::get_module) — by `id` or `template_id`
    ///    scoped to `user_id`.
    /// 2. **Stale ref by name**: when `module_id` no longer exists (e.g. the
    ///    user rebuilt their module, producing a new row with a new id), look
    ///    up the old row's `name` from either `wasm_modules` or
    ///    `node_templates`, then find the latest `wasm_modules` row with that
    ///    name owned by `user_id`. Lets in-flight executions of a workflow
    ///    keep resolving against their workflow's graph even after the
    ///    module is rebuilt.
    /// 3. **Template fallback**: look for any compiled `wasm_modules` row whose
    ///    `template_id = module_id`. Covers the case where the workflow graph
    ///    references a `node_templates.id` directly; any user's compile of that
    ///    template resolves. `max_fuel` comes from the DB row (not hardcoded)
    ///    so per-module fuel overrides propagate through template dispatch.
    /// 4. **Precompiled legacy**: `node_templates.precompiled_wasm`. Pre-dates
    ///    the `wasm_modules` write; safety net for modules installed before
    ///    that write existed.
    ///
    /// On levels 2-4, the resolved `wasm_bytes` are written back to Redis at
    /// the `wasm:<module_id>` key (if a Redis client is configured) so the
    /// worker's bytecode-load path can find the module by the original id
    /// without re-running the fallback pipeline.
    ///
    /// Returns a descriptive error on total miss that points operators at the
    /// install/compile tools.
    pub async fn get_module_for_execution(
        &self,
        module_id: Uuid,
        user_id: Uuid,
    ) -> Result<WasmModule> {
        use sqlx::Row;

        // Phase 3.2 of module entity unification (docs/module-entity-consolidation.md):
        // collapsed from 4 fallback levels to 2 now that the unified `modules`
        // table handles every reference shape.
        //
        // Level 1: canonical get_module — matches modules.id,
        //          modules.legacy_template_id, OR modules.legacy_wasm_module_id
        //          AND scopes by user_id (with NULL-allowed for catalog).
        //          This subsumes the old Level 3 (wasm_modules WHERE template_id)
        //          via the legacy_template_id forwarding alias, AND the old
        //          Level 4 (node_templates.precompiled_wasm) via the
        //          modules.wasm_bytes column populated by the Phase 1.1 backfill.
        // Level 2: stale-name fallback — when a user rebuilt their module
        //          (new modules.id, same name), in-flight executions may
        //          carry the OLD id in their workflow's graph_json. Resolve
        //          via name + user_id to find the latest row by that name.
        match self.get_module(module_id, user_id).await {
            Ok(m) => {
                // The graph-dispatch read: stamp recency here (throttled, off
                // the critical path). `get_execution_info` is the module-bound
                // twin. These two are the ONLY writers of `last_used_at`.
                self.spawn_touch_last_used(module_id);
                return Ok(m);
            }
            // An EVICTED module exists — its bytes were NULLed by the cache
            // sweep and its source is intact. Falling through to the
            // stale-name lookup would find no row with bytes under that name
            // and report "Module not found", which is false on both clauses.
            // Surface the actionable error instead.
            Err(e) if e.downcast_ref::<ModuleBytesEvicted>().is_some() => return Err(e),
            Err(_) => {}
        }

        // Level 2: stale module ref by name. Look up the OLD module's name
        // in the modules table (which has the row even if it was renamed
        // or rebuilt under a new id), then find the latest row by that
        // name owned by the user. Two queries, scoped by user_id at every
        // step to prevent cross-user resolution.
        let old_name: Option<String> = sqlx::query_scalar(
            "SELECT name FROM modules \
             WHERE id = $1 \
             LIMIT 1",
        )
        .bind(module_id)
        .fetch_optional(&self.db_pool)
        .await
        .ok()
        .flatten();

        if let Some(name) = old_name {
            let successor = sqlx::query(
                "SELECT id, wasm_bytes, name, content_hash, COALESCE(size_bytes, 0) AS size_bytes, \
                        allowed_hosts, allowed_methods, allowed_secrets, requires_approval_for, \
                        capability_world, COALESCE(max_fuel, 2000000) AS max_fuel, integration_name \
                 FROM modules \
                 WHERE name = $1 AND (user_id = $2 OR user_id IS NULL) \
                   AND wasm_bytes IS NOT NULL \
                 ORDER BY compiled_at DESC NULLS LAST LIMIT 1",
            )
            .bind(&name)
            .bind(user_id)
            .fetch_optional(&self.db_pool)
            .await
            .ok()
            .flatten();

            if let Some(row) = successor {
                let new_id: Uuid = row.try_get::<Option<_>, _>("id")?.unwrap_or(module_id);
                let wasm_bytes: Vec<u8> = row
                    .try_get::<Option<_>, _>("wasm_bytes")?
                    .unwrap_or_default();
                let cap_str: String = row
                    .try_get::<Option<_>, _>("capability_world")?
                    .unwrap_or_default();
                tracing::info!(
                    old_module_id = %module_id,
                    new_module_id = %new_id,
                    module_name = %name,
                    "stale-name fallback: original module id was renamed/superseded; resolved a fresh module by name",
                );
                let m = WasmModule {
                    name: row.try_get::<Option<_>, _>("name")?.unwrap_or(name),
                    content_hash: row
                        .try_get::<Option<_>, _>("content_hash")?
                        .unwrap_or_default(),
                    wasm_bytes,
                    source_code: None,
                    template_id: Some(new_id),
                    config: None,
                    size_bytes: row.try_get::<Option<_>, _>("size_bytes")?.unwrap_or(0),
                    max_fuel: clamp_execution_fuel(
                        row.try_get::<Option<_>, _>("max_fuel")?.unwrap_or(0),
                    ),
                    max_memory_mb: 128,
                    allowed_hosts: row
                        .try_get::<Option<_>, _>("allowed_hosts")?
                        .unwrap_or_default(),
                    allowed_methods: row
                        .try_get::<Option<_>, _>("allowed_methods")?
                        .unwrap_or_default(),
                    allowed_secrets: decode_allowed_secrets(&row, module_id),
                    requires_approval_for: row
                        .try_get::<Option<_>, _>("requires_approval_for")?
                        .unwrap_or_default(),
                    user_id: None,
                    capability_world: parse_capability_world(&cap_str),
                    imported_interfaces: vec![],
                    dependencies: None,
                    oci_url: None,
                    language: "rust".to_string(),
                    integration_name: row.try_get::<Option<String>, _>("integration_name")?,
                };
                // Oversized (redis-routed) modules must be resident before
                // returning — see the twin call in `get_module`. L-27: cache
                // under the requested `module_id` (the id the engine emits)
                // and the caller's `user_id`, NOT the successor `new_id`.
                if m.wasm_bytes.len() > inline_wasm_cap_bytes() {
                    self.ensure_wasm_bytes_cached(user_id, module_id, &m.wasm_bytes)
                        .await;
                } else {
                    self.cache_wasm_bytes_under(user_id, module_id, &m.wasm_bytes);
                }
                // The row that will actually run is the SUCCESSOR — stamp it,
                // not the stale id the graph still carries.
                self.spawn_touch_last_used(new_id);
                return Ok(m);
            }
        }

        anyhow::bail!(
            "Module {} not found. Re-install with install_module_from_catalog \
             or compile_custom_sandbox to bake permissions into the compiled artifact.",
            module_id
        )
    }

    /// Best-effort Redis cache fill for `wasm:{user_id}:{module_id}` so the
    /// worker bytecode-load path can find the resolved module after a
    /// fallback resolution. Silently ignored when no Redis is configured or
    /// the connection is unavailable — the worker falls through to its own
    /// module-load path on miss.
    ///
    /// L-27: the key is USER-SCOPED. `user_id` MUST be the executing user —
    /// the same id the engine then emits in the `redis:wasm:{user_id}:{id}`
    /// dispatch URI (see `get_module` / `get_module_for_execution`, both of
    /// which thread the caller's `user_id` through). A non-scoped
    /// `wasm:{module_id}` key was cross-tenant readable.
    ///
    /// **Fire-and-forget**: returns immediately and does the SET on a
    /// background tokio task. `get_module()` is on the dispatch hot path —
    /// every workflow node-execution pays this — and a blocking
    /// implementation would add a Redis round-trip per fetch. The fire-and-
    /// forget pattern keeps cache-warming asynchronous while preserving
    /// the cache's purpose (subsequent dispatches resolve from Redis).
    ///
    /// SETEX with a 24h TTL bounds stale-after-rotation exposure for
    /// callers that don't explicitly DEL the key (matches the TTL on
    /// `get_module_bytes::SETEX`).
    fn cache_wasm_bytes_under(&self, user_id: Uuid, module_id: Uuid, wasm_bytes: &[u8]) {
        let Some(ref redis_client) = self.redis_client else {
            return;
        };
        // Clone the shared connection cell + client + bytes for the background
        // task. Small modules (~80 KB typical Rust component) ride INLINE in
        // the dispatch and never need this key on the worker's read path, so
        // a lost race is harmless — the fire-and-forget keeps the dispatch hot
        // path free of a Redis round-trip. Oversized components DON'T take
        // this path (they go through `ensure_wasm_bytes_cached` — see the
        // call sites), so the async fill is only ever used where a miss is
        // recoverable.
        let client = redis_client.clone();
        let cell = self.redis_conn.clone();
        let bytes = wasm_bytes.to_vec();
        tokio::spawn(async move {
            match redis_conn_from(&cell, &client).await {
                Ok(conn) => Self::set_wasm_key(conn, user_id, module_id, &bytes).await,
                Err(e) => tracing::debug!(
                    user_id = %user_id, module_id = %module_id, error = %e,
                    "Redis connect failed during cache fill — read path will fall back"
                ),
            }
        });
    }

    /// **Synchronous** Redis pre-warm for `wasm:{user_id}:{module_id}` —
    /// awaits the SETEX before returning so the key is guaranteed resident.
    ///
    /// Required for OVERSIZED components (interpreter toolchains:
    /// componentize-py ~18 MB, jco ~13 MB). Those exceed the inline cap,
    /// so the engine dispatches them by `redis:wasm:{user_id}:{id}` URI
    /// instead of embedding the bytes (`dispatch_bytes::embeds_inline`). If
    /// the pre-warm were fire-and-forget (as for small modules), the worker
    /// could issue its `GET wasm:{user_id}:{id}` before the background SETEX
    /// landed and fail the job with "wasm module not found" — a
    /// non-deterministic race that gets WORSE with size (a 13 MB SETEX
    /// easily loses to a fast local dispatch → NATS → worker GET). Awaiting
    /// closes it: the key exists before `fetch` returns to the engine, so
    /// it exists before the JobRequest is even built.
    async fn ensure_wasm_bytes_cached(&self, user_id: Uuid, module_id: Uuid, wasm_bytes: &[u8]) {
        match self.redis_conn().await {
            None => {}
            Some(Ok(conn)) => Self::set_wasm_key(conn, user_id, module_id, wasm_bytes).await,
            Some(Err(e)) => tracing::debug!(
                user_id = %user_id, module_id = %module_id, error = %e,
                "Redis connect failed during cache fill — read path will fall back"
            ),
        }
    }

    /// Shared SETEX body for both the fire-and-forget (`cache_wasm_bytes_under`)
    /// and awaited (`ensure_wasm_bytes_cached`) pre-warm paths. Writes the
    /// canonical user-scoped key so it can never drift from the URI the
    /// engine emits — both derive from `talos_workflow_engine_core`.
    async fn set_wasm_key(
        mut conn: redis::aio::ConnectionManager,
        user_id: Uuid,
        module_id: Uuid,
        bytes: &[u8],
    ) {
        let key = scoped_wasm_cache_key(user_id, module_id);
        // SETEX (vs SET): bound stale exposure if a downstream rotation
        // path forgets to DEL. 24h matches `get_module_bytes`.
        if let Err(e) = redis::cmd("SETEX")
            .arg(&key)
            .arg(86400)
            .arg(bytes)
            .query_async::<()>(&mut conn)
            .await
        {
            tracing::debug!(user_id = %user_id, module_id = %module_id, error = %e, "Redis SET failed during cache fill");
        }
    }

    /// The Postgres half of every bytes-only read (`get_module_bytes`,
    /// `fetch_and_cache_scoped`): ONE statement, and a THREE-way answer rather
    /// than the `query_scalar::<Vec<u8>>` + `fetch_one` it replaced. That
    /// shape decoded a NULL `wasm_bytes` as a sqlx decode ERROR and then
    /// labelled it "Module not found or access denied" — which, once the
    /// cache sweep started NULLing bytes on evicted rows (2026-09-10), would
    /// have told the caller their module does not exist when it plainly does.
    ///
    /// * row absent → not found / access denied
    /// * bytes NULL, `wasm_evicted_at` set → [`ModuleBytesEvicted`]
    /// * bytes NULL, not evicted → never compiled (the metadata-only shape)
    /// * bytes present → `Ok(bytes)`
    async fn fetch_wasm_bytes_from_db(&self, module_id: Uuid, user_id: Uuid) -> Result<Vec<u8>> {
        use sqlx::Row;
        let row = sqlx::query(
            "SELECT name, wasm_bytes, wasm_evicted_at, oci_url FROM modules \
             WHERE id = $1 \
               AND (user_id = $2 OR user_id IS NULL) \
             ORDER BY compiled_at DESC NULLS LAST \
             LIMIT 1",
        )
        .bind(module_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("Failed to query modules table")?
        .ok_or_else(|| anyhow::anyhow!("Module not found or access denied"))?;
        let bytes: Option<Vec<u8>> = row.try_get("wasm_bytes")?;
        let name: String = row.try_get("name")?;
        let evicted_at: Option<chrono::DateTime<chrono::Utc>> = row.try_get("wasm_evicted_at")?;
        let oci_url: Option<String> = row.try_get("oci_url")?;
        match bytes {
            Some(b) if !b.is_empty() => Ok(b),
            _ => Err(classify_absent_wasm_bytes(
                module_id,
                &name,
                evicted_at,
                oci_url.as_deref(),
            )),
        }
    }

    pub async fn get_module_bytes(&self, module_id: Uuid, user_id: Uuid) -> Result<Vec<u8>> {
        // SECURITY: Use user-scoped cache key to prevent cross-tenant cache leakage
        let cache_key = scoped_wasm_cache_key(user_id, module_id);

        // 1. Try to fetch from Redis cache (over the shared connection manager)
        let mut redis = match self.redis_conn().await {
            None => None,
            Some(Ok(conn)) => Some(conn),
            Some(Err(e)) => {
                tracing::warn!("Redis connection error: {}", e);
                None
            }
        };
        if let Some(conn) = redis.as_mut() {
            match redis::cmd("GET")
                .arg(&cache_key)
                .query_async::<Option<Vec<u8>>>(conn)
                .await
            {
                Ok(Some(bytes)) if !bytes.is_empty() => {
                    tracing::debug!("Cache hit for module {}/{}", user_id, module_id);
                    return Ok(bytes);
                }
                Ok(_) => tracing::debug!("Cache miss for module {}/{}", user_id, module_id),
                Err(e) => tracing::warn!("Redis GET error for module {}: {}", module_id, e),
            }
        }

        // 2. Fetch from Postgres (enforces authorization).
        //    Phase 5.1: reads from the unified `modules` table by canonical id.
        //    Catalog rows (user_id IS NULL) are accessible to every
        //    authenticated user; sandbox rows are scoped to the owning user.
        let bytes = self.fetch_wasm_bytes_from_db(module_id, user_id).await?;

        // 3. Populate Redis cache with user-scoped key
        if let Some(conn) = redis.as_mut() {
            // Set with 24-hour expiration
            // MCP-745 (2026-05-13): see store_module for rationale.
            // Cache-fill failure on the GET path means every
            // subsequent dispatch round-trips to the DB — silent
            // capacity hit until operator notices DB load.
            if let Err(e) = redis::cmd("SETEX")
                .arg(&cache_key)
                .arg(86400)
                .arg(&bytes)
                .query_async::<()>(conn)
                .await
            {
                tracing::warn!(
                    target: "talos_rpc",
                    module_id = %module_id,
                    user_id = %user_id,
                    error = %e,
                    "Redis SETEX failed in get_module_bytes cache-fill — subsequent reads will miss cache",
                );
            }
        }

        Ok(bytes)
    }

    /// Prepares a module for execution and returns the necessary information.
    /// If the module is not an OCI image, it ensures the module is loaded into the Redis cache.
    ///
    /// FUEL CONTRACT: the `max_fuel` returned here is the module-row default
    /// (`wasm_modules.max_fuel`) with NO graph-JSON `data.max_fuel` override
    /// applied — deliberately. This path backs the module-bound direct-fire
    /// family (gmail / gcp / google_calendar / webhook push dispatch), which
    /// fires a single module in response to an inbound event with NO owning
    /// workflow node, hence no node config to override from. The override
    /// precedence (`node data.max_fuel` > module default > adaptive floor)
    /// lives in `ParallelWorkflowEngine::resolve_node_max_fuel` and only applies
    /// on the graph-execution paths (single-node / pipeline / loop body), where
    /// a node actually exists. Operators needing a non-default fuel ceiling for
    /// inbound-event processing wrap the module in a workflow node (which then
    /// carries `data.max_fuel`) — the module row is the correct, only source of
    /// truth for a bare module fire.
    ///
    /// This is the module-bound DISPATCH read, so it stamps `last_used_at`
    /// (throttled, off the critical path — see [`Self::spawn_touch_last_used`]);
    /// its graph-dispatch twin is `get_module_for_execution`.
    pub async fn get_execution_info(
        &self,
        module_id: Uuid,
        user_id: Uuid,
    ) -> Result<ModuleExecutionInfo> {
        let module = self.get_module(module_id, user_id).await?;
        self.spawn_touch_last_used(module.template_id.unwrap_or(module_id));

        let module_uri = if let Some(ref url) = module.oci_url {
            url.clone()
        } else {
            if !module.wasm_bytes.is_empty() {
                if let Err(e) = self.ensure_module_in_cache(module_id, user_id).await {
                    tracing::warn!(
                        "Failed to cache module {} before execution: {}",
                        module_id,
                        e
                    );
                }
            }
            // CRITICAL: match the user-scoped cache key written by
            // `ensure_module_in_cache` / `get_module_bytes`, which SET at
            // `wasm:{user_id}:{module_id}` for cross-tenant isolation. The
            // engine's dispatch sites emit the identical URI (L-27), both
            // via `talos_workflow_engine_core::scoped_wasm_redis_uri`.
            scoped_wasm_redis_uri(user_id, module_id)
        };

        Ok(ModuleExecutionInfo {
            module_uri,
            content_hash: module.content_hash,
            config: module.config,
            allowed_hosts: module.allowed_hosts,
            allowed_methods: module.allowed_methods,
            allowed_secrets: module.allowed_secrets,
            requires_approval_for: module.requires_approval_for,
            // wasm_modules.max_fuel is stored as BIGINT (i64); clamp at zero
            // before casting so a negative DB value becomes 0 (triggering the
            // dispatcher's default fallback) instead of wrapping to a huge u64.
            max_fuel: module.max_fuel.max(0) as u64,
            integration_name: module.integration_name,
        })
    }

    /// Ensures the module is loaded into the Redis cache without downloading it into memory if it already exists.
    /// SECURITY: Uses user-scoped cache key to prevent cross-tenant access.
    pub async fn ensure_module_in_cache(&self, module_id: Uuid, user_id: Uuid) -> Result<()> {
        if let Some(Ok(mut conn)) = self.redis_conn().await {
            // SECURITY (L-27): user-scoped cache key prevents cross-tenant
            // leakage. This is the only key shape the worker resolves now —
            // the engine emits `redis:wasm:{user_id}:{module_id}` for every
            // dispatch shape (single / pipeline-step / loop-body).
            let user_key = scoped_wasm_cache_key(user_id, module_id);
            let user_exists: bool = redis::cmd("EXISTS")
                .arg(&user_key)
                .query_async(&mut conn)
                .await
                .unwrap_or(false);
            if user_exists {
                return Ok(());
            }
        }

        // Fetch from Postgres (auth-enforced) and populate the user-scoped
        // key so the engine's `redis:wasm:{user_id}:{module_id}` URI resolves
        // on the worker.
        self.fetch_and_cache_scoped(module_id, user_id).await?;
        Ok(())
    }

    /// Fetch module bytes from Postgres and write them to the user-scoped
    /// Redis key `wasm:{user_id}:{module_id}` — the one key shape the worker
    /// resolves (L-27). The engine emits the matching
    /// `redis:wasm:{user_id}:{module_id}` URI for every dispatch shape.
    async fn fetch_and_cache_scoped(&self, module_id: Uuid, user_id: Uuid) -> Result<Vec<u8>> {
        // Phase 5.1: reads from `modules` by canonical id. See
        // `get_module_bytes` for the ownership-scope rationale.
        let bytes = self.fetch_wasm_bytes_from_db(module_id, user_id).await?;

        if let Some(Ok(mut conn)) = self.redis_conn().await {
            let user_key = scoped_wasm_cache_key(user_id, module_id);
            // 24h TTL — matches existing get_module_bytes behaviour.
            // MCP-745 (2026-05-13): log SETEX failures. ensure_module_in_cache
            // is the prefetch path called before dispatch — silent failure
            // here means the subsequent execution incurs the DB-read
            // fallback even though the operator believed the cache was warm.
            if let Err(e) = redis::cmd("SETEX")
                .arg(&user_key)
                .arg(86400)
                .arg(&bytes)
                .query_async::<()>(&mut conn)
                .await
            {
                tracing::warn!(
                    target: "talos_rpc",
                    module_id = %module_id,
                    user_id = %user_id,
                    error = %e,
                    "Redis SETEX failed in ensure_module_in_cache — prefetch incomplete",
                );
            }
        }
        Ok(bytes)
    }

    /// Stamp `modules.last_used_at` / `usage_count` for a module that is about
    /// to be DISPATCHED — the one implementation (it replaced `increment_usage`,
    /// which wrote unconditionally and had zero callers, so the column was
    /// never written and `WASM_CACHE_RETENTION_DAYS` was inert; see
    /// `docs/engineering-log/2026-09-10-whole-codebase-review.md`).
    ///
    /// THROTTLED by [`LAST_USED_TOUCH_SQL`]'s predicate: the row is written at
    /// most once per hour, so on a module dispatched every minute this is one
    /// PK-indexed UPDATE in sixty and fifty-nine index probes that match no
    /// row. `usage_count` therefore counts HOURS-WITH-A-DISPATCH, not
    /// dispatches — `module_executions` is the dispatch count.
    ///
    /// Returns whether the row was actually stamped (false = throttled or no
    /// such row), so a test can pin the throttle without inspecting the table.
    pub async fn touch_last_used(&self, module_id: Uuid) -> Result<bool> {
        let result = sqlx::query(LAST_USED_TOUCH_SQL)
            .bind(module_id)
            .execute(&self.db_pool)
            .await
            .context("modules.last_used_at touch failed")?;
        Ok(result.rows_affected() > 0)
    }

    /// Fire-and-forget-but-COUNTED wrapper around [`Self::touch_last_used`]
    /// for the dispatch hot path: never awaited by the caller (a workflow node
    /// must not wait on usage telemetry), never `let _ =` either — a failure
    /// is logged at WARN with the module id so an unreadable `modules` table
    /// does not silently make every module look idle to the cache sweep.
    pub fn spawn_touch_last_used(&self, module_id: Uuid) {
        let pool = self.db_pool.clone();
        tokio::spawn(async move {
            if let Err(e) = sqlx::query(LAST_USED_TOUCH_SQL)
                .bind(module_id)
                .execute(&pool)
                .await
            {
                tracing::warn!(
                    target: "talos_rpc",
                    module_id = %module_id,
                    error = %e,
                    "modules.last_used_at touch failed — this module will look \
                     idle to the WASM cache sweep until a later dispatch succeeds"
                );
            }
        });
    }

    /// Get module configuration (enforces ownership via user_id).
    ///
    /// Phase 5: reads from the unified `modules` table. Catalog rows
    /// (user_id IS NULL) are accessible to every authenticated user.
    /// `config_schema` is intentionally NOT returned here — it's the UI
    /// metadata, not runtime config (see BUG-10).
    pub async fn get_module_config(
        &self,
        module_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<JsonValue>> {
        let row = sqlx::query_as::<_, (Option<JsonValue>,)>(
            "SELECT config FROM modules \
             WHERE id = $1 \
               AND (user_id = $2 OR user_id IS NULL) \
             ORDER BY compiled_at DESC NULLS LAST \
             LIMIT 1",
        )
        .bind(module_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("Failed to query module config")?;

        match row {
            // Row found with a non-NULL config — return it as-is.
            Some((Some(cfg),)) => Ok(Some(cfg)),
            // Row found but config IS NULL — catalog rows and
            // freshly-installed sandbox rows behave this way. Return
            // an empty object so callers that unwrap_or(json!({}))
            // still get the "template exists, no stored config" signal.
            Some((None,)) => Ok(Some(serde_json::json!({}))),
            None => Ok(None),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeTemplate {
    pub id: Uuid,
    pub name: String,
    pub category: String,
    pub description: Option<String>,
    pub config_schema: JsonValue,
    pub code_template: String,
    pub precompiled_wasm: Option<Vec<u8>>,
    pub icon: Option<String>,
    pub oci_url: Option<String>,
    pub allowed_hosts: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_secrets: Vec<String>,
    pub requires_approval_for: Vec<String>,
    pub max_retries: i32,
    pub retry_backoff_ms: i64,
    /// WIT capability world stored at compile time (e.g. "automation-node", "minimal-node").
    /// Used by Tier-3 module resolution to supply the correct hint to the worker,
    /// bypassing binary re-inspection which fails for Wizer-snapshotted binaries.
    pub capability_world: String,
    /// Third-party crate dependencies used when compiling this template.
    /// Stored as a JSON object mapping crate names to version strings,
    /// e.g. `{"base64": "0.21"}`.
    ///
    /// This used to say "`None` for catalog templates", and it was true —
    /// every one of the 75 catalog rows had the column NULL, because no
    /// catalog path ever wrote it. That is exactly the defect fixed on
    /// 2026-08-11: the disk seeder now writes `talos.json`'s `dependencies`
    /// through `talos_compilation::CatalogTemplate`, so a catalog row's value
    /// is `Some(..)` whenever its manifest declares a crate. Any consumer
    /// that reads this field must forward it — a hardcoded `None` no longer
    /// coincides with the data (structural lint check 68 leg (d)).
    pub dependencies: Option<JsonValue>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct NodeTemplateRow {
    id: Uuid,
    name: String,
    category: String,
    description: Option<String>,
    config_schema: JsonValue,
    code_template: String,
    precompiled_wasm: Option<Vec<u8>>,
    icon: Option<String>,
    oci_url: Option<String>,
    allowed_hosts: Vec<String>,
    allowed_methods: Vec<String>,
    allowed_secrets: Vec<String>,
    requires_approval_for: Vec<String>,
    max_retries: i32,
    retry_backoff_ms: i64,
    capability_world: String,
    dependencies: Option<JsonValue>,
}

impl From<NodeTemplateRow> for NodeTemplate {
    fn from(row: NodeTemplateRow) -> Self {
        NodeTemplate {
            id: row.id,
            name: row.name,
            category: row.category,
            description: row.description,
            config_schema: row.config_schema,
            code_template: row.code_template,
            precompiled_wasm: row.precompiled_wasm,
            icon: row.icon,
            oci_url: row.oci_url,
            allowed_hosts: row.allowed_hosts,
            allowed_methods: row.allowed_methods,
            allowed_secrets: row.allowed_secrets,
            requires_approval_for: row.requires_approval_for,
            max_retries: row.max_retries,
            retry_backoff_ms: row.retry_backoff_ms,
            capability_world: row.capability_world,
            dependencies: row.dependencies,
        }
    }
}

/// Metadata-only template row returned by
/// [`ModuleRegistry::list_template_metadata_for_user`] — every field a
/// listing surface renders, and neither blob (`wasm_bytes`, `source_code`).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct NodeTemplateMetadata {
    pub id: Uuid,
    pub name: String,
    pub category: String,
    pub description: Option<String>,
    pub config_schema: JsonValue,
    pub allowed_hosts: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_secrets: Vec<String>,
    pub requires_approval_for: Vec<String>,
    pub capability_world: String,
    /// `wasm_bytes IS NOT NULL AND octet_length(wasm_bytes) > 0`, computed in
    /// SQL so a listing never loads the binary to ask whether it exists.
    pub is_compiled: bool,
}

/// SQL fragment: the rows this cache sweep is permitted to EVICT (NULL the
/// bytes of — never delete; see [`EVICT_BYTES_RETURNING`]).
///
/// `modules` is a module REGISTRY that a cache sweep happens to run over, not a
/// cache. Every row carries `source_code`, and rows with `user_id IS NULL` are
/// the shared catalog every tenant installs from. A sweep driven by AGGREGATE
/// footprint — pressure that ANY tenant can create — must never touch a row
/// that no tenant owns.
///
/// `kind = 'catalog'` rows that DO carry a `user_id` are excluded for a second
/// reason: they are a user's INSTALL of a shared template, and re-installing
/// mints a NEW id while workflows bind modules by raw UUID inside `graph_json`
/// with no foreign key. They are definitions, not artifacts.
///
/// **Measured on the live deployment 2026-08-26:** 112 of 112 cached rows carry
/// `source_code`; **0 of 112 carry an `oci_url`**; 29 are evictable under this
/// predicate alone (before [`module_eviction_exemptions!`] is applied).
/// Re-measure `count(*) FILTER (WHERE oci_url IS NOT NULL)` before assuming it
/// is still 0 — the predicate this one replaced (`wasm_bytes IS NOT NULL`, on
/// the reasoning that catalog rows are OCI-served and hold no bytes) was true
/// when written and excluded nothing by the time it mattered.
macro_rules! evictable_module_predicate {
    () => {
        "m.wasm_bytes IS NOT NULL AND m.user_id IS NOT NULL AND m.kind <> 'catalog'"
    };
}

/// SQL fragment: the recency key of a candidate row — the LATEST of the
/// dispatch-side stamp (`m.last_used_at`, written throttled by
/// [`ModuleRegistry::touch_last_used`] and backfilled once from
/// `module_executions` by migration `20260910140000`) and the newest surviving
/// `module_executions.started_at` (`e.last_exec`, the LATERAL below), falling
/// back to `m.created_at` when neither exists.
///
/// **`COALESCE(…, m.created_at)`, not `NULLS FIRST`.** Absence of evidence is
/// not evidence of coldness: a just-compiled module has no execution rows yet
/// and no stamp, and `module_executions` has no retention policy *today* — if
/// one is added, a hot module could present as never-used. Falling back to
/// `created_at` keeps such a row in its creation position instead of sending
/// it to the front of the eviction queue.
///
/// `GREATEST` ignores NULLs in Postgres, so a row with a stamp and no
/// execution rows (or the reverse) resolves to the one it has.
macro_rules! module_recency_key {
    () => {
        "COALESCE(GREATEST(m.last_used_at, e.last_exec), m.created_at)"
    };
}

/// SQL fragment: the EXEMPTIONS — rows that pass [`evictable_module_predicate!`]
/// and must still not be evicted. Written ONCE and consumed by BOTH sweep
/// paths ([`CLEANUP_OLD_MODULES_SQL`] and the two cap statements), which is
/// what `wasm_cache_sweep_sql_tests::both_sweep_paths_share_one_exemption_fragment`
/// pins: before 2026-09-10 the two paths had DIFFERENT predicates and neither
/// asked whether anything still referenced the module.
///
/// `$window` is the placeholder (`"$1"`) for the idle window in DAYS. A module
/// is exempt when ANY of:
///
/// 1. A workflow references it through the `workflow_module_refs` junction
///    (indexed on `module_id`; one probe per candidate). This is the HOT path.
/// 2. Its id appears in ANY workflow's `graph_json` text. The junction is
///    maintained only by the GraphQL save hook (`sync_workflow_module_refs`)
///    — the MCP graph mutations do not write it — so it CAN lag, and this leg
///    is the safety net. Cost: `candidates × workflows` substring scans of
///    graph text (~30 × ~40 × ~20 kB ≈ 25 MB of text on the reference fleet)
///    on a six-hourly sweep. Deliberately NOT filtered on `workflows.status`:
///    archiving is reversible, and un-archiving must not find its module's
///    bytes gone. (Static text also keeps this statement inside lint check 88's
///    PREPARE coverage.)
/// 3. A `webhook_triggers.module_id` names it (indexed).
/// 4. An ACTIVE `google_calendar_watch_channels.module_id` names it (the
///    index is partial on `is_active`, hence the predicate). Gmail and GCP
///    push bindings are NOT covered here: they live inside
///    `integration_state.value` (`GmailWatchRow.module_id`, the GCP push
///    subscription row), which is JSON that may be ENCRYPTED (`value_enc`),
///    so SQL cannot see the binding — stated as a limit rather than
///    approximated. A module bound only to a gmail/gcp push channel is
///    protected by leg 5 for as long as it keeps firing.
/// 5. It was used within the window — [`module_recency_key!`] is newer than
///    `NOW() - $window days`. This is the leg that makes `WASM_CACHE_RETENTION_DAYS`
///    mean what it says on BOTH paths.
///
/// `workflow_nodes.module_id` is NOT consulted: that table has no INSERT
/// writer anywhere in the workspace.
macro_rules! module_eviction_exemptions {
    ($window:literal) => {
        concat!(
            " AND NOT EXISTS (SELECT 1 FROM workflow_module_refs r WHERE r.module_id = m.id) \
              AND NOT EXISTS (SELECT 1 FROM workflows w \
                              WHERE w.graph_json LIKE '%' || m.id::text || '%') \
              AND NOT EXISTS (SELECT 1 FROM webhook_triggers t WHERE t.module_id = m.id) \
              AND NOT EXISTS (SELECT 1 FROM google_calendar_watch_channels c \
                              WHERE c.module_id = m.id AND c.is_active = true) \
              AND ",
            module_recency_key!(),
            " < NOW() - INTERVAL '1 day' * ",
            $window
        )
    };
}

/// SQL fragment: the evictable candidate relation, carrying a REAL recency key.
///
/// **Shape matters more than the usual "no correlated subquery" rule.** Measured
/// on the live DB with `EXPLAIN (ANALYZE, BUFFERS)` (2026-08-26, 29 candidates):
///
/// | shape | time | buffers | scaling |
/// |---|---|---|---|
/// | `GROUP BY module_id` derived table | 8.04 ms | 2,751 | Seq Scan, grows forever |
/// | same + `module_id IN (candidates)` | 134.58 ms | 5,116 | reads all matching entries |
/// | this LATERAL | **0.25 ms** | **146** | 29 index-only probes, O(log n) each |
///
/// The LATERAL *is* a correlated subquery, and it is the shape that satisfies
/// the constraint's substance: cost bounded by the CANDIDATE count, never by the
/// history table. `module_executions` grows ~730 rows/day with no retention, so
/// the `GROUP BY` form degrades without bound while this one does not.
///
/// `e` exposes only `last_exec`, so every column in the predicate is
/// `m.`-qualified and unambiguous.
macro_rules! evictable_candidates {
    ($window:literal) => {
        concat!(
            "FROM modules m \
             LEFT JOIN LATERAL ( \
               SELECT x.started_at AS last_exec FROM module_executions x \
               WHERE x.module_id = m.id ORDER BY x.started_at DESC LIMIT 1 \
             ) e ON true \
             WHERE ",
            evictable_module_predicate!(),
            module_eviction_exemptions!($window)
        )
    };
}

/// SQL fragment: a TOTAL eviction order over [`evictable_candidates!`] —
/// coldest first by [`module_recency_key!`], then `m.created_at, m.id` so both
/// `LIMIT` (count cap) and `ROWS UNBOUNDED PRECEDING` (size cap) are
/// reproducible.
///
/// What this replaced was worse than a neutral tiebreaker. Over the live
/// evictable set, `created_at ASC` is close to an ANTI-LRU — the modules built
/// earliest are the ones longest in production — and its first five deletions
/// were modules last executed the same day with 101, 767 and 819 executions,
/// against a true-recency order whose first five were last used five weeks ago.
macro_rules! eviction_order {
    () => {
        concat!(
            "ORDER BY ",
            module_recency_key!(),
            " ASC, m.created_at ASC, m.id ASC"
        )
    };
}

/// SQL statement head/tail: the ONE mutation the sweep performs. It NULLs the
/// compiled bytes and stamps `wasm_evicted_at`; the row, `source_code`,
/// `content_hash`, `size_bytes` (so an operator can still see how large the
/// artifact was) and every FK child stay. Until 2026-09-10 this was
/// `DELETE FROM modules`, and `module_executions.module_id` is
/// `ON DELETE CASCADE` — the module's whole execution history and its
/// `module_execution_logs` went with it, `workflow_nodes.module_id` was SET
/// NULL, and `source_code` was lost. A reader that meets the NULL bytes gets
/// [`ModuleBytesEvicted`] and recompiles with `hot_update_module`; migration
/// `20260910140000`'s trigger clears the marker when bytes land again.
macro_rules! evict_bytes_where_id_in {
    ($select:expr) => {
        concat!(
            "UPDATE modules SET wasm_bytes = NULL, wasm_evicted_at = NOW() \
             WHERE id IN ( ",
            $select,
            " ) RETURNING COALESCE(size_bytes, 0)"
        )
    };
}

/// The candidate relation with the idle window bound at `$1` — exposed so the
/// SQL tests can assert every sweep statement embeds this exact text.
pub const EVICTION_CANDIDATES_SQL: &str = evictable_candidates!("$1");

/// Retention sweep: evict the bytes of EVERY candidate idle past `$1` days.
pub const CLEANUP_OLD_MODULES_SQL: &str =
    evict_bytes_where_id_in!(concat!("SELECT m.id ", evictable_candidates!("$1")));

/// Count-cap sweep: evict the `$2` coldest candidates idle past `$1` days.
pub const ENFORCE_COUNT_CAP_SQL: &str = evict_bytes_where_id_in!(concat!(
    "SELECT m.id ",
    evictable_candidates!("$1"),
    " ",
    eviction_order!(),
    " LIMIT $2"
));

/// Size-cap sweep: evict the smallest coldest-first prefix of candidates idle
/// past `$1` days whose bytes COVER an excess of `$2` bytes.
///
/// Two corrections carried over from the DELETE form this replaced:
///  * `ROWS UNBOUNDED PRECEDING` — the default `RANGE` frame gives every row
///    that TIES on the ordering key the sum of the whole peer group, not a
///    prefix sum; with every `last_used_at` NULL (the pre-2026-09-10 state)
///    ALL rows tied and the size cap shed nothing at all.
///  * `running_total - size_bytes < $2` selects the SMALLEST prefix that
///    COVERS the excess; `running_total <= excess` selected the largest prefix
///    that fits WITHIN it and freed nothing whenever the excess was smaller
///    than the first candidate row.
pub const ENFORCE_SIZE_CAP_SQL: &str = concat!(
    "WITH candidates AS ( \
       SELECT m.id, \
              COALESCE(m.size_bytes, 0) AS size_bytes, \
              SUM(COALESCE(m.size_bytes, 0)) OVER ( ",
    eviction_order!(),
    " ROWS UNBOUNDED PRECEDING ) AS running_total ",
    evictable_candidates!("$1"),
    " ) ",
    evict_bytes_where_id_in!("SELECT id FROM candidates WHERE running_total - size_bytes < $2")
);

/// Outcome of one cache sweep (either path).
///
/// `unevictable_*_overage` is the part of the cap that could NOT be met without
/// evicting rows this sweep is not allowed to touch — the shared catalog, or,
/// since 2026-09-10, any module that is referenced or was used inside the idle
/// window. It is a returned value rather than only a log line so it is
/// unit-testable: a registry whose excess is entirely in-use must SURFACE
/// that, not silently do nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheEvictionOutcome {
    /// Rows whose bytes were evicted (rows themselves are KEPT).
    pub modules_evicted: u64,
    /// Bytes actually reclaimed — real `size_bytes`, not a row count.
    pub bytes_freed: i64,
    /// Rows still over the count cap that this sweep is not allowed to evict.
    pub unevictable_count_overage: i64,
    /// Bytes still over the size cap that this sweep is not allowed to evict.
    pub unevictable_size_overage_bytes: i64,
}

impl ModuleRegistry {
    /// Retention sweep: evict the compiled bytes of every candidate module idle
    /// for more than `retention_days` (`WASM_CACHE_RETENTION_DAYS`, default 30).
    ///
    /// "Idle" is [`module_recency_key!`] — the newer of the dispatch-side
    /// `last_used_at` stamp and the latest surviving `module_executions` row,
    /// falling back to `created_at`. Referenced modules (workflow junction,
    /// graph text, webhook, active gcal channel) are exempt whatever their age
    /// — see [`module_eviction_exemptions!`]. Rows are never deleted; see
    /// [`evict_bytes_where_id_in!`].
    ///
    /// History, so the knob's past is not re-discovered: until 2026-09-10 this
    /// was `DELETE … WHERE last_used_at < NOW() - N days`, and `last_used_at`
    /// had no live writer, so it matched nothing — the knob was inert. It is
    /// now written (throttled) on every dispatch read and was backfilled once
    /// from `module_executions` by migration `20260910140000`.
    pub async fn cleanup_old_modules(
        &self,
        retention_days: i64,
    ) -> anyhow::Result<CacheEvictionOutcome> {
        // MCP-997 (2026-05-15): refuse non-positive `retention_days`.
        // Sibling caller-supplied-negative class as MCP-767/811/812 —
        // a negative value would convert
        // `NOW() - INTERVAL '1 day' * -N` into `NOW() + INTERVAL`,
        // matching every unreferenced row and evicting the entire cache.
        // Recoverable (recompile) but operationally costly. Defense-in-depth
        // refuse at the function boundary.
        if retention_days <= 0 {
            tracing::warn!(
                target: "talos_audit",
                retention_days,
                "wasm-cache cleanup refused: retention_days must be positive (would evict entire cache)"
            );
            return Ok(CacheEvictionOutcome::default());
        }
        let freed = sqlx::query_as::<_, (i32,)>(CLEANUP_OLD_MODULES_SQL)
            .bind(retention_days)
            .fetch_all(&self.db_pool)
            .await
            .context("wasm-cache retention sweep failed")?;

        Ok(CacheEvictionOutcome {
            modules_evicted: freed.len() as u64,
            bytes_freed: freed.iter().map(|r| i64::from(r.0)).sum::<i64>(),
            unevictable_count_overage: 0,
            unevictable_size_overage_bytes: 0,
        })
    }

    /// Enforce the cache caps by evicting the bytes of the least recently used
    /// **evictable** modules — those that pass [`evictable_module_predicate!`]
    /// AND every exemption in [`module_eviction_exemptions!`], including
    /// "not used within `idle_window_days`".
    ///
    /// Stats are taken over the FULL cached set, because the caps are about real
    /// footprint; only the UPDATEs are restricted. Restricting the STATS instead
    /// would be the silent failure — an over-cap registry whose excess is all
    /// catalog or all in-use would simply report itself as under cap. Whatever
    /// overage cannot be met is returned in [`CacheEvictionOutcome`] for the
    /// caller to surface.
    ///
    /// **Consequence an operator must know:** the caps can no longer evict a
    /// module that is referenced or was used inside the window. When the
    /// in-use set alone exceeds `WASM_CACHE_MAX_MODULES` / `_MAX_SIZE_MB`, the
    /// sweep REPORTS the overage (`unevictable_*`) and evicts nothing — the
    /// cap is a signal to raise, not a promise to hold, because the only way
    /// to hold it would be to break a workflow that runs.
    pub async fn enforce_cache_limits(
        &self,
        max_modules: i64,
        max_size_mb: i64,
        idle_window_days: i64,
    ) -> anyhow::Result<CacheEvictionOutcome> {
        // Defense-in-depth at the function boundary, mirroring
        // `cleanup_old_modules` (MCP-643): a non-positive cap makes
        // `current > max` trivially true with an unbounded `to_delete`, evicting
        // every evictable row; a non-positive window would exempt nothing on
        // recency. No caller can reach this today — the sweep reads all three
        // through `talos_config::positive_env_or_default` — but this is a `pub`
        // API and the sibling guards the identical shape.
        if max_modules <= 0 || max_size_mb <= 0 || idle_window_days <= 0 {
            tracing::warn!(
                target: "talos_audit",
                max_modules,
                max_size_mb,
                idle_window_days,
                "wasm-cache eviction refused: caps and idle window must be positive (would evict every evictable row)"
            );
            return Ok(CacheEvictionOutcome::default());
        }
        let max_size_bytes = max_size_mb.saturating_mul(1_048_576);

        let (current_count, current_size) = sqlx::query_as::<_, (i64, i64)>(
            "SELECT COUNT(*), COALESCE(SUM(size_bytes), 0)::bigint \
             FROM modules WHERE wasm_bytes IS NOT NULL",
        )
        .fetch_one(&self.db_pool)
        .await
        .context("wasm-cache footprint read failed")?;

        let mut outcome = CacheEvictionOutcome::default();

        // ── Pass 1: count cap ────────────────────────────────────────────
        if current_count > max_modules {
            let wanted = current_count - max_modules;
            // RETURNING the real sizes: pass 2 needs to know what this pass
            // actually freed (see below), and the caller needs bytes rather
            // than a row count mislabelled as bytes.
            let freed = sqlx::query_as::<_, (i32,)>(ENFORCE_COUNT_CAP_SQL)
                .bind(idle_window_days)
                .bind(wanted)
                .fetch_all(&self.db_pool)
                .await
                .context("wasm-cache count-cap sweep failed")?;

            let evicted = freed.len() as i64;
            outcome.modules_evicted += evicted as u64;
            outcome.bytes_freed += freed.iter().map(|r| i64::from(r.0)).sum::<i64>();
            outcome.unevictable_count_overage = wanted - evicted;
        }

        // ── Pass 2: size cap ─────────────────────────────────────────────
        // `current_size` was read BEFORE pass 1 ran, and pass 1 mutates the very
        // set this pass measures — so reusing it over-states the live footprint
        // by whatever pass 1 freed and over-evicts by that amount. This needs
        // no concurrent writer to go wrong. Subtract what was actually freed.
        // (A concurrent writer can still move the set between the stats read and
        // either UPDATE; that residual window is narrowed, not closed.)
        let live_size = current_size - outcome.bytes_freed;
        if live_size > max_size_bytes {
            let excess = live_size - max_size_bytes;
            let freed = sqlx::query_as::<_, (i32,)>(ENFORCE_SIZE_CAP_SQL)
                .bind(idle_window_days)
                .bind(excess)
                .fetch_all(&self.db_pool)
                .await
                .context("wasm-cache size-cap sweep failed")?;

            let bytes = freed.iter().map(|r| i64::from(r.0)).sum::<i64>();
            outcome.modules_evicted += freed.len() as u64;
            outcome.bytes_freed += bytes;
            outcome.unevictable_size_overage_bytes = (excess - bytes).max(0);
        }

        Ok(outcome)
    }

    /// Get cache statistics.
    ///
    /// Phase 5: aggregates over `modules` instead of the legacy
    /// `wasm_modules` table. Only rows with compiled bytes contribute so
    /// the reported footprint matches what the workers actually serve.
    pub async fn get_cache_stats(&self) -> anyhow::Result<CacheStats> {
        // Cast SUMs to bigint: `modules.size_bytes` is int4 so
        // `SUM` → bigint; `modules.usage_count` is bigint so `SUM` →
        // numeric, which sqlx won't auto-coerce to i64. Explicit cast
        // keeps both in int8.
        let stats = sqlx::query_as::<_, (i64, i64, i64)>(
            r#"
            SELECT
                COUNT(*) as module_count,
                COALESCE(SUM(size_bytes), 0)::bigint as total_size_bytes,
                COALESCE(SUM(usage_count), 0)::bigint as total_usage_count
            FROM modules
            WHERE wasm_bytes IS NOT NULL
            "#,
        )
        .fetch_one(&self.db_pool)
        .await?;

        Ok(CacheStats {
            module_count: stats.0,
            total_size_bytes: stats.1,
            total_size_mb: (stats.1 as f64 / 1_048_576.0),
            total_usage_count: stats.2,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub module_count: i64,
    pub total_size_bytes: i64,
    pub total_size_mb: f64,
    pub total_usage_count: i64,
}

#[derive(Debug, Clone)]
pub struct WasmModule {
    pub name: String,
    pub content_hash: String,
    pub wasm_bytes: Vec<u8>,
    pub source_code: Option<String>,
    pub template_id: Option<Uuid>,
    pub config: Option<JsonValue>,
    pub size_bytes: i32,
    pub max_fuel: i64,
    pub max_memory_mb: i32,
    pub allowed_hosts: Vec<String>,
    /// HTTP method allowlist. Empty = allow all methods. Non-empty = only those methods.
    pub allowed_methods: Vec<String>,
    /// Secret allowlist. Empty = deny all. `["*"]` = allow all. Otherwise explicit names.
    pub allowed_secrets: Vec<String>,
    /// Operation types that require human approval before execution.
    pub requires_approval_for: Vec<String>,
    pub user_id: Option<Uuid>,
    /// WIT capability world detected at compile time.
    pub capability_world: CapabilityWorld,
    /// WIT interface names imported by the component (e.g. ["talos:core/http"]).
    pub imported_interfaces: Vec<String>,
    pub dependencies: Option<JsonValue>,
    pub oci_url: Option<String>,
    /// Source language: "rust", "javascript", or "typescript". Defaults to "rust".
    pub language: String,
    /// Integration this module belongs to, if any. Scopes the module's
    /// access to the `integration_state` table to this namespace.
    /// `None` means the module is not an integration (cannot call
    /// `integration-state::*` host fns).
    pub integration_name: Option<String>,
}

impl ModuleRegistry {
    /// Store an AOT-precompiled WASM blob for a module.
    ///
    /// Phase 5: writes only the unified `modules.wasm_bytes` column. The
    /// legacy `node_templates.precompiled_wasm` write was dropped when
    /// Phase 3.2 ratified `modules` as the single source of truth.
    /// 3-shape id match preserves callers that still hold a legacy id.
    pub async fn store_precompiled_template(
        &self,
        template_id: uuid::Uuid,
        precompiled: Vec<u8>,
    ) -> anyhow::Result<()> {
        sqlx::query(
            // Compile outputs only — `compiled_at` already dates the artifact.
            // Stamping `updated_at` would date the module as edited by an AOT
            // precompile that changed nothing the operator authored.
            // `wasm_evicted_at = NULL` is also what migration 20260910140000's
            // trigger does on any write landing non-NULL bytes; stated here so
            // the one writer in this crate reads correctly without the schema.
            "UPDATE modules \
             SET wasm_bytes = $1, \
                 size_bytes = LENGTH($1)::INTEGER, \
                 compiled_at = NOW(), \
                 wasm_evicted_at = NULL \
             WHERE id = $2",
        )
        .bind(&precompiled)
        .bind(template_id)
        .execute(&self.db_pool)
        .await
        .context("Failed to store precompiled AOT blob on unified modules table")?;
        Ok(())
    }
}

#[cfg(test)]
mod wasm_cache_key_tests {
    use super::*;

    // L-27: the key the registry writes (`set_wasm_key` / `get_module_bytes`
    // / `ensure_module_in_cache`, all via `scoped_wasm_cache_key`) MUST equal
    // the key the worker derives by stripping `redis:` from the URI the engine
    // emits (`scoped_wasm_redis_uri`). Both come from the shared
    // `talos_workflow_engine_core` helper, so this pins the contract on the
    // registry side — if someone reverts the registry to a bespoke literal,
    // this test catches the drift.
    #[test]
    fn registry_key_matches_engine_uri_after_redis_strip() {
        let user = Uuid::new_v4();
        let module = Uuid::new_v4();
        let key = scoped_wasm_cache_key(user, module);
        let uri = scoped_wasm_redis_uri(user, module);
        assert_eq!(uri.strip_prefix("redis:"), Some(key.as_str()));
        // And the concrete shape the worker's `get_execution_info` test pins.
        assert_eq!(key, format!("wasm:{}:{}", user, module));
    }
}

#[cfg(test)]
mod validate_allowed_hosts_tests {
    use super::*;

    #[test]
    fn accepts_wildcard() {
        assert!(validate_allowed_hosts(&["*".into()]).is_ok());
    }

    #[test]
    fn accepts_bare_hostname() {
        assert!(validate_allowed_hosts(&["api.github.com".into()]).is_ok());
    }

    #[test]
    fn accepts_wildcard_subdomain() {
        assert!(validate_allowed_hosts(&["*.example.com".into()]).is_ok());
    }

    #[test]
    fn rejects_empty_entry() {
        assert!(validate_allowed_hosts(&["".into()]).is_err());
    }

    #[test]
    fn rejects_url_with_scheme() {
        assert!(validate_allowed_hosts(&["https://api.github.com".into()]).is_err());
    }

    #[test]
    fn rejects_url_with_path() {
        assert!(validate_allowed_hosts(&["api.github.com/repos".into()]).is_err());
    }

    #[test]
    fn rejects_port_specifier() {
        let err = validate_allowed_hosts(&["api.github.com:8443".into()]).unwrap_err();
        assert!(err.contains("Port specifiers"), "got: {}", err);
    }

    #[test]
    fn rejects_oversized_hostname() {
        let huge = "a".repeat(MAX_HOST_LENGTH + 1);
        let err = validate_allowed_hosts(&[huge]).unwrap_err();
        assert!(err.contains("exceeds"), "got: {}", err);
    }

    #[test]
    fn accepts_at_cap_hostname() {
        // 253 chars, valid DNS shape (alternating dots every ~10 chars)
        let mut h = String::new();
        while h.len() + 11 <= MAX_HOST_LENGTH {
            if !h.is_empty() {
                h.push('.');
            }
            h.push_str("abcdefghij");
        }
        assert!(h.len() <= MAX_HOST_LENGTH);
        assert!(validate_allowed_hosts(&[h]).is_ok());
    }

    #[test]
    fn rejects_control_chars() {
        assert!(validate_allowed_hosts(&["api.github.com\n127.0.0.1".into()]).is_err());
        assert!(validate_allowed_hosts(&["api.github.com\0".into()]).is_err());
    }

    #[test]
    fn rejects_whitespace() {
        assert!(validate_allowed_hosts(&["api github com".into()]).is_err());
        assert!(validate_allowed_hosts(&[" ".into()]).is_err());
    }

    #[test]
    fn rejects_non_ascii() {
        assert!(validate_allowed_hosts(&["münchen.example".into()]).is_err());
    }

    #[test]
    fn rejects_too_many_entries() {
        let hosts: Vec<String> = (0..=MAX_ALLOWED_HOSTS)
            .map(|i| format!("host{}.example.com", i))
            .collect();
        assert!(validate_allowed_hosts(&hosts).is_err());
    }
}

/// Every shipped module template must pass the controller's seed-time
/// validation. The seeding loop (controller main.rs) SKIPS a template —
/// with only a boot-log WARN — when its `requires_secrets` or
/// `allowed_hosts` fail validation, so a drifted talos.json silently
/// vanishes from every fresh deploy's catalog. That happened to three
/// OAuth templates (Jira/Gmail/Calendar, fixed 2026-07-06): they carried
/// `vault://oauth/<provider>/*/access_token` grants — a convention the
/// canonical `job_protocol::vault_path_permitted` matcher NEVER
/// understood (no scheme prefix, no mid-path `*`), so they were both
/// unseedable AND would have been dead grants at runtime. This test
/// makes that drift a CI failure instead of a silent catalog gap.
#[cfg(test)]
mod shipped_template_manifests_pass_seed_validation {
    use super::*;

    fn str_array(manifest: &serde_json::Value, key: &str) -> Vec<String> {
        manifest
            .get(key)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn every_template_talos_json_validates() {
        // CARGO_MANIFEST_DIR-relative; fail LOUDLY if the layout moves
        // (cargo_manifest_dir_relocation_class, PR #190) rather than
        // silently validating zero files.
        let templates_dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../module-templates");
        let entries: Vec<_> = std::fs::read_dir(&templates_dir)
            .unwrap_or_else(|e| {
                panic!(
                    "module-templates dir not found at {} ({e}) — if the layout moved, update this test",
                    templates_dir.display()
                )
            })
            .filter_map(|e| e.ok())
            .filter(|e| e.path().join("talos.json").is_file())
            .collect();
        assert!(
            entries.len() > 10,
            "expected a full template catalog, found {} — wrong directory?",
            entries.len()
        );

        let mut failures = Vec::new();
        for entry in entries {
            let name = entry.file_name().to_string_lossy().to_string();
            let manifest_path = entry.path().join("talos.json");
            let manifest: serde_json::Value = match serde_json::from_str(
                &std::fs::read_to_string(&manifest_path).expect("readable talos.json"),
            ) {
                Ok(m) => m,
                Err(e) => {
                    failures.push(format!("{name}: talos.json is not valid JSON: {e}"));
                    continue;
                }
            };
            if let Err(msg) = validate_allowed_secrets(&str_array(&manifest, "requires_secrets")) {
                failures.push(format!("{name}: requires_secrets: {msg}"));
            }
            if let Err(msg) = validate_allowed_hosts(&str_array(&manifest, "allowed_hosts")) {
                failures.push(format!("{name}: allowed_hosts: {msg}"));
            }
            // `allowed_methods` is fail-OPEN at seed time on purpose: an
            // unrecognised verb is dropped rather than skipping the template
            // (see `reconcile::parse_manifest_allowed_methods`). That is the
            // right RUNTIME behaviour and the wrong BUILD behaviour — a typo'd
            // verb silently yields a NARROWER list than the author wrote, and a
            // too-narrow list is a runtime denial at the worker's enforcement
            // point, not a permissive no-op. So assert here that nothing a
            // SHIPPED manifest declares gets dropped: kept count == declared
            // count. The message names the dropped entries so the failure says
            // what to fix, not merely that something is wrong.
            let declared = str_array(&manifest, "allowed_methods");
            if !declared.is_empty() {
                let kept = crate::reconcile::parse_manifest_allowed_methods(&manifest);
                if kept.len() != declared.len() {
                    failures.push(format!(
                        "{name}: allowed_methods: {} of {} entries are not recognised HTTP \
                         verbs and would be silently dropped, NARROWING the enforced \
                         allowlist (declared: {declared:?}, kept: {kept:?})",
                        declared.len() - kept.len(),
                        declared.len()
                    ));
                }
            }
            // capability_world must be a REAL compile target, i.e. one the
            // dispatcher's `CapabilityWorld` parser recognises. `llm-node` is
            // the trap: it exists as a WIT world AND as an actor-ceiling rank
            // label, but the wit-inspector classifies every LLM import as the
            // `secrets` tier ("LLM API keys are host-managed"), so a module
            // declaring `world = "llm-node"` while importing llm bindings
            // fails compilation with a world-mismatch — uninstallable via
            // createModuleFromTemplate (llm-inference + constitutional-
            // refinement shipped this way, 2026-07-06; the fix is
            // `secrets-node`, matching anthropic-claude). from_str maps
            // llm-node → Unknown, which is exactly the signal. Check 48
            // verifies talos.json ↔ macro consistency but not that either is
            // a compilable world, so it passed both-wrong.
            if let Some(world) = manifest.get("capability_world").and_then(|v| v.as_str()) {
                use std::str::FromStr;
                // `from_str` is TOTAL — unrecognised strings map to
                // `Unknown` (Ok), never Err — so check the variant.
                if talos_capability_world::CapabilityWorld::from_str(world)
                    == Ok(talos_capability_world::CapabilityWorld::Unknown)
                {
                    failures.push(format!(
                        "{name}: capability_world '{world}' is not a compilable WIT world \
                         (llm-node is an actor-ceiling rank only — LLM modules must declare \
                         'secrets-node')"
                    ));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} template(s) would be SKIPPED at seed time or fail to install:\n  {}",
            failures.len(),
            failures.join("\n  ")
        );
    }
}

#[cfg(test)]
mod validate_allowed_secrets_tests {
    use super::*;

    #[test]
    fn accepts_wildcard() {
        assert!(validate_allowed_secrets(&["*".into()]).is_ok());
    }

    #[test]
    fn accepts_exact_path() {
        assert!(validate_allowed_secrets(&["anthropic/api_key".into()]).is_ok());
    }

    #[test]
    fn accepts_prefix_pattern() {
        assert!(validate_allowed_secrets(&["oauth/gmail/*".into()]).is_ok());
    }

    #[test]
    fn accepts_single_segment() {
        assert!(validate_allowed_secrets(&["github-token".into()]).is_ok());
    }

    #[test]
    fn rejects_empty_entry() {
        assert!(validate_allowed_secrets(&["".into()]).is_err());
    }

    #[test]
    fn rejects_only_prefix_marker() {
        // "/*" → path portion is empty
        assert!(validate_allowed_secrets(&["/*".into()]).is_err());
    }

    #[test]
    fn rejects_uppercase() {
        assert!(validate_allowed_secrets(&["Anthropic/API_KEY".into()]).is_err());
    }

    #[test]
    fn rejects_leading_slash() {
        assert!(validate_allowed_secrets(&["/anthropic/api_key".into()]).is_err());
    }

    #[test]
    fn rejects_trailing_slash() {
        assert!(validate_allowed_secrets(&["anthropic/".into()]).is_err());
    }

    #[test]
    fn rejects_consecutive_slashes() {
        assert!(validate_allowed_secrets(&["anthropic//api_key".into()]).is_err());
    }

    #[test]
    fn rejects_control_chars() {
        assert!(validate_allowed_secrets(&["anthropic/\nbad".into()]).is_err());
        assert!(validate_allowed_secrets(&["anthropic/\0bad".into()]).is_err());
    }

    #[test]
    fn rejects_special_chars() {
        // Spaces, ?, =, & — characters that would carry semantic
        // weight in some allowlist consumers.
        assert!(validate_allowed_secrets(&["anthropic api_key".into()]).is_err());
        assert!(validate_allowed_secrets(&["anthropic/key?ver=1".into()]).is_err());
    }

    #[test]
    fn rejects_oversized_path() {
        let huge = "a".repeat(MAX_SECRET_PATH_LENGTH + 1);
        assert!(validate_allowed_secrets(&[huge]).is_err());
    }

    #[test]
    fn accepts_at_cap_path() {
        let path = "a".repeat(MAX_SECRET_PATH_LENGTH);
        assert!(validate_allowed_secrets(&[path]).is_ok());
    }

    #[test]
    fn rejects_too_many_entries() {
        let secrets: Vec<String> = (0..=MAX_ALLOWED_SECRETS)
            .map(|i| format!("vault/key{}", i))
            .collect();
        assert!(validate_allowed_secrets(&secrets).is_err());
    }

    #[test]
    fn accepts_non_ascii_rejected() {
        assert!(validate_allowed_secrets(&["anthropic/münchen".into()]).is_err());
    }
}

#[cfg(test)]
mod wasm_cache_sweep_sql_tests {
    //! Pins on the RENDERED sweep SQL. These are text assertions on purpose:
    //! the two sweep paths (`cleanup_old_modules`, `enforce_cache_limits`) had
    //! DIFFERENT predicates until 2026-09-10 and neither asked whether anything
    //! still referenced the module; the guard against that drifting back is
    //! that every statement embeds ONE candidate fragment verbatim.
    use super::*;

    const ALL_SWEEP_STATEMENTS: [(&str, &str); 3] = [
        ("cleanup_old_modules", CLEANUP_OLD_MODULES_SQL),
        ("enforce_cache_limits/count", ENFORCE_COUNT_CAP_SQL),
        ("enforce_cache_limits/size", ENFORCE_SIZE_CAP_SQL),
    ];

    #[test]
    fn both_sweep_paths_share_one_exemption_fragment() {
        for (name, sql) in ALL_SWEEP_STATEMENTS {
            assert!(
                sql.contains(EVICTION_CANDIDATES_SQL),
                "{name} does not embed the shared candidate relation verbatim:\n{sql}"
            );
        }
    }

    #[test]
    fn exemptions_name_every_reference_surface_and_the_window() {
        for needle in [
            "NOT EXISTS (SELECT 1 FROM workflow_module_refs r WHERE r.module_id = m.id)",
            "FROM workflows w",
            "w.graph_json LIKE '%' || m.id::text || '%'",
            "NOT EXISTS (SELECT 1 FROM webhook_triggers t WHERE t.module_id = m.id)",
            "FROM google_calendar_watch_channels c",
            "c.module_id = m.id AND c.is_active = true",
            "COALESCE(GREATEST(m.last_used_at, e.last_exec), m.created_at) < NOW() - INTERVAL '1 day' * $1",
        ] {
            assert!(
                EVICTION_CANDIDATES_SQL.contains(needle),
                "exemption fragment lost `{needle}`:\n{EVICTION_CANDIDATES_SQL}"
            );
        }
        // Base predicate still present: never the catalog, never an unowned row.
        assert!(EVICTION_CANDIDATES_SQL.contains(
            "m.wasm_bytes IS NOT NULL AND m.user_id IS NOT NULL AND m.kind <> 'catalog'"
        ));
        // The graph-text leg is deliberately NOT status-filtered (archiving is
        // reversible) — a `status` predicate appearing here is a regression.
        assert!(
            !EVICTION_CANDIDATES_SQL.contains("status"),
            "graph-text exemption must protect archived workflows' modules too"
        );
    }

    #[test]
    fn the_sweep_evicts_bytes_and_never_deletes_rows() {
        for (name, sql) in ALL_SWEEP_STATEMENTS {
            assert!(
                !sql.contains("DELETE"),
                "{name} deletes rows — the sweep must NULL bytes only:\n{sql}"
            );
            assert!(
                sql.contains("UPDATE modules SET wasm_bytes = NULL, wasm_evicted_at = NOW()"),
                "{name} is not the byte-eviction UPDATE:\n{sql}"
            );
            assert!(sql.contains("RETURNING COALESCE(size_bytes, 0)"), "{name}");
        }
    }

    #[test]
    fn statements_bind_the_window_first_and_the_cap_second() {
        // Binding order is what the Rust callers rely on; a reordered
        // placeholder would bind the cap as the window (days) silently.
        assert!(CLEANUP_OLD_MODULES_SQL.contains("$1"));
        assert!(!CLEANUP_OLD_MODULES_SQL.contains("$2"));
        assert!(ENFORCE_COUNT_CAP_SQL.contains(" LIMIT $2"));
        assert!(ENFORCE_SIZE_CAP_SQL.contains("running_total - size_bytes < $2"));
        assert!(ENFORCE_SIZE_CAP_SQL.contains("ROWS UNBOUNDED PRECEDING"));
    }

    #[test]
    fn touch_sql_is_throttled_and_keyed_on_pk() {
        assert!(LAST_USED_TOUCH_SQL.starts_with("UPDATE modules"));
        assert!(LAST_USED_TOUCH_SQL.contains("WHERE id = $1"));
        assert!(
            LAST_USED_TOUCH_SQL
                .contains("(last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '1 hour')"),
            "throttle predicate missing — this would be one row write per dispatch"
        );
        assert!(LAST_USED_TOUCH_SQL.contains("last_used_at = NOW()"));
        assert!(LAST_USED_TOUCH_SQL.contains("usage_count = usage_count + 1"));
        assert!(!LAST_USED_TOUCH_SQL.contains("updated_at"));
    }

    #[test]
    fn evicted_error_is_typed_and_actionable() {
        let id = Uuid::new_v4();
        let at = chrono::Utc::now();
        let err = classify_absent_wasm_bytes(id, "csv-parser", Some(at), None);
        let typed = err
            .downcast_ref::<ModuleBytesEvicted>()
            .expect("evicted rows must produce the typed error");
        assert_eq!(typed.module_id, id);
        assert_eq!(typed.name, "csv-parser");
        let msg = err.to_string();
        assert!(msg.contains("evicted"), "{msg}");
        assert!(msg.contains("hot_update_module"), "{msg}");
        assert!(!msg.contains("not found"), "{msg}");
    }

    #[test]
    fn never_compiled_is_not_reported_as_evicted() {
        let err = classify_absent_wasm_bytes(Uuid::new_v4(), "x", None, None);
        assert!(err.downcast_ref::<ModuleBytesEvicted>().is_none());
        assert!(err.to_string().contains("install_module_from_catalog"));
    }

    #[test]
    fn oci_rows_are_never_reported_as_evicted_or_uncompiled() {
        let at = chrono::Utc::now();
        let err = classify_absent_wasm_bytes(Uuid::new_v4(), "x", Some(at), Some("oci://r/x:1"));
        assert!(err.downcast_ref::<ModuleBytesEvicted>().is_none());
        assert!(err.to_string().contains("OCI"));
        // Empty oci_url is "no oci_url".
        let err = classify_absent_wasm_bytes(Uuid::new_v4(), "x", Some(at), Some(""));
        assert!(err.downcast_ref::<ModuleBytesEvicted>().is_some());
    }
}
