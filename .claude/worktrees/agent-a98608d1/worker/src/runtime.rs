use anyhow::Result;
use lru::LruCache;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{
    Caller, Config, Engine, InstanceAllocationStrategy, PoolingAllocationConfig, Store,
};

use crate::context::TalosContext;
use crate::wit_inspector::CapabilityWorld;
// ---------------------------------------------------------------------
// AOT versioning
// ---------------------------------------------------------------------
/// Header prefixed to every AOT‑compiled blob. Guarantees that the binary was
/// produced by the same Talos version and Wasmtime configuration.
pub const AOT_VERSION_HDR: &[u8] = b"TALOSV1";
/// Number of bytes occupied by the HMAC-SHA256 integrity tag that immediately
/// follows the version header in every AOT blob.
const AOT_HMAC_LEN: usize = 32;

/// Load (or derive) the HMAC key used to sign/verify AOT blobs.
///
/// Precedence:
///   1. `TALOS_AOT_HMAC_KEY` env var (raw hex or UTF-8 secret).
///   2. `TALOS_MASTER_KEY` env var (same key used for secret envelope encryption).
///   3. Warn and fall back to a hard-coded sentinel — AOT verification will still
///      work within the same process, but blobs signed by another instance will
///      fail.  Set `TALOS_AOT_HMAC_KEY` in production!
fn aot_hmac_key() -> Vec<u8> {
    if let Ok(k) = std::env::var("TALOS_AOT_HMAC_KEY") {
        return k.into_bytes();
    }
    if let Ok(k) = std::env::var("TALOS_MASTER_KEY") {
        tracing::debug!("TALOS_AOT_HMAC_KEY not set; deriving AOT HMAC key from TALOS_MASTER_KEY");
        return k.into_bytes();
    }

    if std::env::var("RUST_ENV").unwrap_or_default() == "production" {
        panic!("CRITICAL SECURITY ERROR: TALOS_AOT_HMAC_KEY or TALOS_MASTER_KEY must be set in production to secure AOT binaries.");
    }

    tracing::warn!(
        "Neither TALOS_AOT_HMAC_KEY nor TALOS_MASTER_KEY is set. \
         AOT HMAC will use an insecure fallback key — set TALOS_AOT_HMAC_KEY in production."
    );
    b"talos-aot-default-insecure-key".to_vec()
}
// Suppress dead‑code warnings for fields and methods that are part of the public API
#[allow(dead_code)]
/// Retry policy for WASM execution
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts (0 = no retries)
    pub max_attempts: u32,
    /// Initial backoff duration
    pub initial_backoff: Duration,
    /// Maximum backoff duration
    pub max_backoff: Duration,
    /// Backoff multiplier (exponential backoff)
    pub backoff_multiplier: f32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        // The default retry policy now provides a modest number of attempts to
        // improve resiliency for transient failures while still protecting
        // against duplicate side‑effects. Modules that cannot tolerate retries
        // should explicitly set `max_attempts = 0`.
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(10),
            backoff_multiplier: 2.0,
        }
    }
}

#[allow(dead_code)]
impl RetryPolicy {
    /// No retries
    pub fn none() -> Self {
        Self {
            max_attempts: 0,
            ..Default::default()
        }
    }

    /// Calculate backoff duration for attempt number
    pub fn backoff_for_attempt(&self, attempt: u32) -> Duration {
        let backoff_ms =
            self.initial_backoff.as_millis() as f32 * self.backoff_multiplier.powi(attempt as i32);
        let backoff = Duration::from_millis(backoff_ms as u64);
        backoff.min(self.max_backoff)
    }
}

/// Performance metrics for WASM execution
#[derive(Debug, Clone, Default)]
pub struct PerformanceMetrics {
    /// Time spent compiling WASM module (0 if cache hit)
    pub compilation_ms: u64,
    /// Time spent executing WASM module
    pub execution_ms: u64,
    /// Whether component was loaded from cache
    pub cache_hit: bool,
    /// Whether result was loaded from cache
    pub result_cache_hit: bool,
    /// Total number of retry attempts (0 if succeeded first try)
    pub retry_attempts: u32,
}

/// Helper to read a UTF-8 string from Wasm memory.
#[allow(dead_code)]
fn read_string_from_memory(
    caller: &mut Caller<'_, TalosContext>,
    memory: &wasmtime::Memory,
    ptr: i32,
    len: i32,
) -> Result<String> {
    let data = memory
        .data(&caller)
        .get(ptr as usize..(ptr + len) as usize)
        .ok_or_else(|| anyhow::anyhow!("invalid memory range"))?;
    Ok(std::str::from_utf8(data)?.to_string())
}

/// Determine if an error is transient and should be retried
fn is_transient_error(error: &anyhow::Error) -> bool {
    let error_str = error.to_string().to_lowercase();

    // Network-related errors (transient)
    if error_str.contains("connection refused")
        || error_str.contains("connection reset")
        || error_str.contains("timeout")
        || error_str.contains("temporary failure")
        || error_str.contains("try again")
        || error_str.contains("unavailable")
    {
        return true;
    }

    // HTTP errors (transient)
    if error_str.contains("429") // Rate limited
        || error_str.contains("503") // Service unavailable
        || error_str.contains("504") // Gateway timeout
        || error_str.contains("502")
    // Bad gateway
    {
        return true;
    }

    // Database errors (transient)
    if error_str.contains("deadlock")
        || error_str.contains("lock timeout")
        || error_str.contains("connection pool")
    {
        return true;
    }

    // Permanent errors (do NOT retry)
    // - Authentication errors (401, 403)
    // - Not found (404)
    // - Invalid input (400)
    // - Out of fuel (resource limit)
    // - Trap (security violation)
    // - Module errors (business logic)

    false
}

// ============================================================================
// PIPELINE TYPES
// ============================================================================

/// Runtime-internal representation of a single pipeline step.
/// Pre-decrypted secrets are passed directly from the caller.
pub struct PipelineStepSpec {
    pub module_id: String,
    pub wasm_bytes: Vec<u8>,
    pub config: JsonValue,
    pub allowed_hosts: Vec<String>,
    pub allowed_methods: Vec<String>,
    /// Pre-decrypted secret values for this step.
    pub secrets: HashMap<String, String>,
    /// Maximum fuel (WASM instructions) for this step.
    pub max_fuel: u64,
    pub max_memory_mb: usize,
    pub timeout: Duration,
}

/// Result of executing a pipeline.
pub struct PipelineResult {
    /// Per-step output values (in execution order).
    pub step_outputs: Vec<JsonValue>,
    /// Output of the last step.
    pub final_output: JsonValue,
    /// Elapsed time for each step in milliseconds.
    pub step_times_ms: Vec<u64>,
}

// ============================================================================
// RUNTIME
// ============================================================================

/// The core runtime that compiles and executes Wasm components with security policies.
#[allow(dead_code)]
pub struct TalosRuntime {
    engine: Engine,

    // ── Tiered linkers ───────────────────────────────────────────────────────
    // Each linker only registers the host functions allowed for its world.
    // A component that claims to be `secrets-node` but secretly imports
    // `talos:core/files` will fail to link against `secrets_linker` at
    // runtime — defence-in-depth on top of upload-time validation.
    /// Minimal-tier linker: logging, json, datetime, crypto, env only.
    minimal_linker: Linker<TalosContext>,
    /// Network-tier linker: adds http, webhook, graphql, email, state,
    /// data-transform, and templates on top of the minimal set.
    network_linker: Linker<TalosContext>,
    /// Secrets-tier linker: network + secrets vault.
    secrets_linker: Linker<TalosContext>,
    /// Filesystem-tier linker: network + sandboxed file I/O.
    filesystem_linker: Linker<TalosContext>,
    /// Messaging-tier linker: network + NATS pub/sub.
    messaging_linker: Linker<TalosContext>,
    /// Cache-tier linker: network + Redis distributed cache.
    cache_node_linker: Linker<TalosContext>,
    /// Database-tier linker: network + secrets + PostgreSQL.
    database_linker: Linker<TalosContext>,
    governance_linker: Linker<TalosContext>,
    /// Trusted-tier linker: full world — all interfaces.
    trusted_linker: Linker<TalosContext>,

    // ── InstancePre caches ───────────────────────────────────────────────────
    // Caching InstancePre instead of Component saves the link step on every
    // call.  Each world has its own partition so a burst of trusted jobs does
    // not evict minimal/network entries.
    //
    // Size distribution (500 total):
    //   minimal: 125 | network: 125 | secrets: 75 | filesystem: 25
    //   messaging: 50 | cache_node: 50 | database: 25 | trusted: 25
    /// Pre-instantiation cache for minimal-tier components.
    minimal_cache: Arc<RwLock<LruCache<[u8; 32], wasmtime::component::InstancePre<TalosContext>>>>,
    /// Pre-instantiation cache for network-tier components.
    network_cache: Arc<RwLock<LruCache<[u8; 32], wasmtime::component::InstancePre<TalosContext>>>>,
    /// Pre-instantiation cache for secrets-tier components.
    secrets_cache: Arc<RwLock<LruCache<[u8; 32], wasmtime::component::InstancePre<TalosContext>>>>,
    /// Pre-instantiation cache for filesystem-tier components.
    filesystem_cache:
        Arc<RwLock<LruCache<[u8; 32], wasmtime::component::InstancePre<TalosContext>>>>,
    /// Pre-instantiation cache for messaging-tier components.
    messaging_cache:
        Arc<RwLock<LruCache<[u8; 32], wasmtime::component::InstancePre<TalosContext>>>>,
    /// Pre-instantiation cache for cache-tier (Redis) components.
    cache_node_cache:
        Arc<RwLock<LruCache<[u8; 32], wasmtime::component::InstancePre<TalosContext>>>>,
    /// Pre-instantiation cache for database-tier components.
    database_cache: Arc<RwLock<LruCache<[u8; 32], wasmtime::component::InstancePre<TalosContext>>>>,
    governance_cache:
        Arc<RwLock<LruCache<[u8; 32], wasmtime::component::InstancePre<TalosContext>>>>,
    /// Pre-instantiation cache for trusted-tier (automation-node) components.
    trusted_cache: Arc<RwLock<LruCache<[u8; 32], wasmtime::component::InstancePre<TalosContext>>>>,

    /// Redis client for distributed caching (optional)
    redis_client: Option<Arc<redis::Client>>,
    /// In‑process result cache (fast path before Redis). Size 256 entries.
    in_memory_result_cache: Arc<RwLock<LruCache<String, JsonValue>>>,
    /// NATS client for message queue (optional)
    nats_client: Option<Arc<async_nats::Client>>,
    /// Postgres connection pool for database queries (optional)
    db_pool: Option<sqlx::PgPool>,
    /// Sandboxed file system directory (optional)
    fs_dir: Option<Arc<cap_std::fs::Dir>>,
    /// Runtime metrics for health checks and observability
    active_executions: Arc<AtomicU32>,
    total_executions: Arc<AtomicU64>,
    /// Fuel limit for each execution (instructions). Default 1_000_000.
    fuel_limit: u64,
    /// Maximum JSON output size (bytes) enforced after module execution.
    max_output_bytes: usize,
    /// Maximum JSON input size (bytes) enforced before execution.
    max_input_bytes: usize,
    start_time: std::time::Instant,
    /// OpenTelemetry metrics for production observability
    metrics: Option<Arc<crate::metrics::RuntimeMetrics>>,
    /// Default TTL (seconds) for result caching when callers do not specify one.
    /// Populated from the `WASM_RESULT_CACHE_TTL_SECS` env var at runtime
    /// construction to avoid repeated lookups.
    default_result_cache_ttl_secs: Option<u64>,
}

// ── Linker builders ──────────────────────────────────────────────────────────

/// Build the minimal-tier linker: WASI + logging + json + datetime + crypto + env.
fn build_minimal_linker(engine: &Engine) -> Result<Linker<TalosContext>> {
    let mut l = Linker::new(engine);

    wasmtime_wasi::p2::add_to_linker_async(&mut l)?;
    wasmtime_wasi_http::add_only_http_to_linker_async(&mut l)?;
    crate::bindings::talos::core::logging::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    crate::bindings::talos::core::json::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    crate::bindings::talos::core::datetime::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    crate::bindings::talos::core::crypto::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    crate::bindings::talos::core::env::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    Ok(l)
}

/// Build the network-tier linker: minimal interfaces + http, webhook, graphql,
/// email, state, data-transform, and templates.
fn build_network_linker(engine: &Engine) -> Result<Linker<TalosContext>> {
    let mut l = Linker::new(engine);

    wasmtime_wasi::p2::add_to_linker_async(&mut l)?;
    wasmtime_wasi_http::add_only_http_to_linker_async(&mut l)?;
    // Minimal interfaces
    crate::bindings::talos::core::logging::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    crate::bindings::talos::core::json::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    crate::bindings::talos::core::datetime::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    crate::bindings::talos::core::crypto::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    crate::bindings::talos::core::env::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    // Network interfaces
    crate::bindings::talos::core::http::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    crate::bindings::talos::core::webhook::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    crate::bindings::talos::core::graphql::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    crate::bindings::talos::core::email::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    crate::bindings::talos::core::state::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    crate::bindings::talos::core::data_transform::add_to_linker::<
        TalosContext,
        HasSelf<TalosContext>,
    >(&mut l, |c| c)?;
    crate::bindings::talos::core::templates::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    Ok(l)
}

/// Build the governance-tier linker: network interfaces + human approvals.
fn build_governance_linker(engine: &Engine) -> Result<Linker<TalosContext>> {
    let mut l = build_network_linker(engine)?;
    crate::bindings::talos::core::governance::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    Ok(l)
}

fn build_trusted_linker(engine: &Engine) -> Result<Linker<TalosContext>> {
    let mut l = Linker::new(engine);

    wasmtime_wasi::p2::add_to_linker_async(&mut l)?;
    wasmtime_wasi_http::add_only_http_to_linker_async(&mut l)?;
    crate::bindings::AutomationNode::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |ctx| ctx,
    )?;

    Ok(l)
}

/// Build the secrets-tier linker: network interfaces + secrets vault.
fn build_secrets_linker(engine: &Engine) -> Result<Linker<TalosContext>> {
    let mut l = build_network_linker(engine)?;
    crate::bindings::talos::core::secrets::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    Ok(l)
}

/// Build the filesystem-tier linker: network interfaces + sandboxed file I/O.
fn build_filesystem_linker(engine: &Engine) -> Result<Linker<TalosContext>> {
    let mut l = build_network_linker(engine)?;
    crate::bindings::talos::core::files::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    Ok(l)
}

/// Build the messaging-tier linker: network interfaces + NATS pub/sub.
fn build_messaging_linker(engine: &Engine) -> Result<Linker<TalosContext>> {
    let mut l = build_network_linker(engine)?;
    crate::bindings::talos::core::messaging::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    Ok(l)
}

/// Build the cache-tier linker: network interfaces + Redis distributed cache.
fn build_cache_node_linker(engine: &Engine) -> Result<Linker<TalosContext>> {
    let mut l = build_network_linker(engine)?;
    crate::bindings::talos::core::cache::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    Ok(l)
}

/// Build the database-tier linker: network interfaces + secrets + PostgreSQL.
/// Secrets are bundled because database connections always require credentials.
fn build_database_linker(engine: &Engine) -> Result<Linker<TalosContext>> {
    let mut l = build_network_linker(engine)?;
    crate::bindings::talos::core::secrets::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    crate::bindings::talos::core::database::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    Ok(l)
}

#[allow(dead_code)]
impl TalosRuntime {
    /// Generate cache key for result caching
    /// Format: "wasm:result:{module_hash}:{input_hash}"
    fn result_cache_key(module_hash: &str, input: &JsonValue) -> String {
        let input_str = input.to_string();
        let mut hasher = Sha256::new();
        hasher.update(input_str.as_bytes());
        let input_hash = hex::encode(hasher.finalize().as_slice());
        format!("wasm:result:{}:{}", module_hash, input_hash)
    }

    /// Try to get cached result from Redis
    async fn get_cached_result(&self, cache_key: &str) -> Option<JsonValue> {
        // First check fast in‑process cache.
        if let Ok(mut c) = self.in_memory_result_cache.write() {
            if let Some(v) = c.get(cache_key) {
                return Some(v.clone());
            }
        }
        // Fall back to Redis if configured.
        if let Some(redis) = &self.redis_client {
            if let Ok(mut conn) = redis.get_multiplexed_async_connection().await {
                use redis::AsyncCommands;
                if let Ok(cached_str) = conn.get::<_, String>(cache_key).await {
                    if let Ok(cached_json) = serde_json::from_str::<JsonValue>(&cached_str) {
                        // Populate in‑process cache for future fast reads.
                        let _ = self.in_memory_result_cache.write().map(|mut c| {
                            c.put(cache_key.to_string(), cached_json.clone());
                        });
                        return Some(cached_json);
                    }
                }
            }
        }
        None
    }

    /// Store result in Redis cache with TTL
    async fn cache_result(&self, cache_key: &str, result: &JsonValue, ttl_secs: u64) {
        // Update in‑process cache (ignore poisoning errors).
        let _ = self.in_memory_result_cache.write().map(|mut c| {
            c.put(cache_key.to_string(), result.clone());
        });
        // Also push to Redis if available.
        if let Some(redis) = &self.redis_client {
            if let Ok(mut conn) = redis.get_multiplexed_async_connection().await {
                use redis::AsyncCommands;
                if let Ok(result_str) = serde_json::to_string(result) {
                    let _ = conn
                        .set_ex::<_, _, ()>(cache_key, result_str, ttl_secs)
                        .await;
                }
            }
        }
    }

    /// Select the linker and InstancePre cache for a given capability world.
    #[allow(clippy::type_complexity)]
    fn select_tier(
        &self,
        cap: &CapabilityWorld,
    ) -> Result<(
        &Linker<TalosContext>,
        &Arc<RwLock<LruCache<[u8; 32], wasmtime::component::InstancePre<TalosContext>>>>,
    )> {
        match *cap {
            CapabilityWorld::Minimal => Ok((&self.minimal_linker, &self.minimal_cache)),
            CapabilityWorld::Http => Ok((&self.network_linker, &self.network_cache)), // Map Http to Network linker/cache
            CapabilityWorld::Network => Ok((&self.network_linker, &self.network_cache)),
            CapabilityWorld::Secrets => Ok((&self.secrets_linker, &self.secrets_cache)),
            CapabilityWorld::Filesystem => Ok((&self.filesystem_linker, &self.filesystem_cache)),
            CapabilityWorld::Messaging => Ok((&self.messaging_linker, &self.messaging_cache)),
            CapabilityWorld::Cache => Ok((&self.cache_node_linker, &self.cache_node_cache)),
            CapabilityWorld::Database => Ok((&self.database_linker, &self.database_cache)),
            CapabilityWorld::Governance => Ok((&self.governance_linker, &self.governance_cache)),
            CapabilityWorld::Trusted => Ok((&self.trusted_linker, &self.trusted_cache)),
            CapabilityWorld::Unknown => {
                anyhow::bail!("Cannot execute component with unknown capabilities")
            }
        }
    }
}

impl TalosRuntime {
    /// Construct a new runtime with fuel consumption and component-model enabled.
    pub fn redis_client(&self) -> Option<Arc<redis::Client>> {
        self.redis_client.clone()
    }

    pub fn new() -> Result<Self> {
        Self::with_resources(None, None, None, None)
    }

    /// Construct a new runtime with optional external resources.
    /// This enables advanced capabilities for WASM modules:
    /// - Redis client for distributed caching
    /// - NATS client for message queues
    /// - Sandboxed directory for file I/O
    pub fn with_resources(
        redis_client: Option<Arc<redis::Client>>,
        nats_client: Option<Arc<async_nats::Client>>,
        db_pool: Option<sqlx::PgPool>,
        fs_dir: Option<Arc<cap_std::fs::Dir>>,
    ) -> Result<Self> {
        let mut config = Config::new();
        config.async_support(true);
        config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Enable);
        config.debug_info(true);
        config.consume_fuel(true);
        config.wasm_component_model(true);

        // Enhance developer experience by increasing Wasm stack size limits
        // Default is usually around 512KB which easily overflows on nested JSON parsing.
        // We set max Wasm stack size to 4MB.
        config.max_wasm_stack(4 * 1024 * 1024);
        // Sync execution mode: host functions use block_in_place for I/O.
        // async_support is NOT enabled — AutomationNode::instantiate (sync) requires it off.
        // Fuel limits (1M instructions) guard against runaway modules.

        // ========================================================================
        // SECURITY: WASM Security Hardening
        // ========================================================================

        // Stack height limit: Prevent stack overflow attacks (512KB max stack depth)
        config.max_wasm_stack(512 * 1024);

        // Disable backtraces for production (prevents information disclosure)
        config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Disable);

        // ========================================================================
        // PERFORMANCE: Instance Pooling (10-100x faster instantiation)
        // ========================================================================

        let mut pooling_config = PoolingAllocationConfig::default();

        pooling_config
            .total_component_instances(1000)
            .max_component_instance_size(10 * 1024 * 1024)
            .max_core_instances_per_component(10)
            .max_memories_per_component(1)
            .max_tables_per_component(10)
            .linear_memory_keep_resident(8 * 1024 * 1024)
            .table_keep_resident(10_000);

        config.allocation_strategy(InstanceAllocationStrategy::Pooling(pooling_config));

        // Parallel compilation and speed optimization
        config.parallel_compilation(true);
        config.cranelift_opt_level(wasmtime::OptLevel::Speed);

        let engine = Engine::new(&config)?;

        // Build eight tiered linkers — each exposes only the interfaces its tier allows.
        // A component compiled against secrets-node that secretly imports `files` will
        // fail to link against secrets_linker at runtime (defence-in-depth on top of
        // the upload-time validate_capability_level() check).
        let minimal_linker = build_minimal_linker(&engine)?;
        let network_linker = build_network_linker(&engine)?;
        let secrets_linker = build_secrets_linker(&engine)?;
        let filesystem_linker = build_filesystem_linker(&engine)?;
        let messaging_linker = build_messaging_linker(&engine)?;
        let cache_node_linker = build_cache_node_linker(&engine)?;
        let database_linker = build_database_linker(&engine)?;
        let governance_linker = build_governance_linker(&engine)?;
        let trusted_linker = build_trusted_linker(&engine)?;

        // Eight InstancePre caches — 500 total entries, partitioned by tier so a burst
        // of trusted jobs cannot evict minimal/network entries.
        //   minimal: 125 | network: 125 | secrets: 75  | filesystem: 25
        //   messaging: 50 | cache_node: 50 | database: 25 | trusted: 25
        let total_cache_size = std::env::var("WASM_COMPONENT_CACHE_SIZE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(500);

        let c_min = std::cmp::max(total_cache_size * 125 / 500, 1);
        let c_net = std::cmp::max(total_cache_size * 125 / 500, 1);
        let c_sec = std::cmp::max(total_cache_size * 75 / 500, 1);
        let c_fs = std::cmp::max(total_cache_size * 25 / 500, 1);
        let c_msg = std::cmp::max(total_cache_size * 50 / 500, 1);
        let c_cache = std::cmp::max(total_cache_size * 50 / 500, 1);
        let c_db = std::cmp::max(total_cache_size * 25 / 500, 1);
        let c_gov = std::cmp::max(total_cache_size * 25 / 500, 1);
        let c_trust = std::cmp::max(total_cache_size * 25 / 500, 1);

        let minimal_cache = Arc::new(RwLock::new(LruCache::new(
            NonZeroUsize::new(c_min).expect("Valid NonZeroUsize"),
        )));
        let network_cache = Arc::new(RwLock::new(LruCache::new(
            NonZeroUsize::new(c_net).expect("Valid NonZeroUsize"),
        )));
        let secrets_cache = Arc::new(RwLock::new(LruCache::new(
            NonZeroUsize::new(c_sec).expect("Valid NonZeroUsize"),
        )));
        let filesystem_cache = Arc::new(RwLock::new(LruCache::new(
            NonZeroUsize::new(c_fs).expect("Valid NonZeroUsize"),
        )));
        let messaging_cache = Arc::new(RwLock::new(LruCache::new(
            NonZeroUsize::new(c_msg).expect("Valid NonZeroUsize"),
        )));
        let cache_node_cache = Arc::new(RwLock::new(LruCache::new(
            NonZeroUsize::new(c_cache).expect("Valid NonZeroUsize"),
        )));
        let database_cache = Arc::new(RwLock::new(LruCache::new(
            NonZeroUsize::new(c_db).expect("Valid NonZeroUsize"),
        )));
        let governance_cache = Arc::new(RwLock::new(LruCache::new(
            NonZeroUsize::new(c_gov).expect("Valid NonZeroUsize"),
        )));
        let trusted_cache = Arc::new(RwLock::new(LruCache::new(
            NonZeroUsize::new(c_trust).expect("Valid NonZeroUsize"),
        )));

        // Initialize OpenTelemetry metrics (optional)
        let metrics = if std::env::var("OTEL_METRICS_ENABLED").unwrap_or_default() == "true" {
            Some(Arc::new(crate::metrics::RuntimeMetrics::new()))
        } else {
            None
        };

        // -----------------------
        // Runtime Config (env‑vars)
        // -----------------------
        // Fuel limit – guards against runaway loops. Override with WASM_FUEL_LIMIT.
        let fuel_limit: u64 = std::env::var("WASM_FUEL_LIMIT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1_000_000);

        // Result‑cache in‑process size – configurable via WASM_RESULT_CACHE_CAPACITY.
        let result_cache_cap: usize = std::env::var("WASM_RESULT_CACHE_CAPACITY")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(256); // default 256 entries

        // -----------------------------------------------------------------
        // Security limits – configurable via env vars for flexibility.
        // -----------------------------------------------------------------
        // Maximum size of JSON output returned to the caller (bytes).
        // Prevents accidental OOM when a malicious module returns a huge blob.
        let max_output_bytes: usize = std::env::var("WASM_MAX_OUTPUT_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1_000_000); // 1 MiB default

        // Maximum size of JSON input accepted (bytes). Large inputs can cause
        // excessive parsing cost or memory pressure.
        let max_input_bytes: usize = std::env::var("WASM_MAX_INPUT_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1_000_000);

        Ok(Self {
            engine,
            minimal_linker,
            network_linker,
            secrets_linker,
            filesystem_linker,
            messaging_linker,
            cache_node_linker,
            database_linker,
            governance_linker,
            trusted_linker,
            minimal_cache,
            network_cache,
            secrets_cache,
            filesystem_cache,
            messaging_cache,
            cache_node_cache,
            database_cache,
            governance_cache,
            trusted_cache,
            redis_client,
            nats_client,
            db_pool,
            fs_dir,
            in_memory_result_cache: Arc::new(RwLock::new(LruCache::new(
                NonZeroUsize::new(result_cache_cap).expect("Valid NonZeroUsize"),
            ))),
            active_executions: Arc::new(AtomicU32::new(0)),
            total_executions: Arc::new(AtomicU64::new(0)),
            fuel_limit,
            max_output_bytes,
            max_input_bytes,
            start_time: std::time::Instant::now(),
            metrics,
            // Default TTL for cached results (seconds). If the env var is not set,
            // we fall back to a 5‑minute TTL (300 s) in the execution path.
            default_result_cache_ttl_secs: std::env::var("WASM_RESULT_CACHE_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok()),
        })
    }

    /// Execute a Wasm component bytecode with the given JSON input.
    /// Returns the JSON output produced by the component.
    pub async fn execute_job(
        &self,
        wasm_bytes: &[u8],
        allowed_hosts: Vec<String>,
        allowed_methods: Vec<String>,
        max_memory_mb: usize,
        input: JsonValue,
    ) -> Result<JsonValue> {
        self.execute_job_with_sandbox(
            wasm_bytes,
            allowed_hosts,
            allowed_methods,
            max_memory_mb,
            input,
            None,
        )
        .await
    }

    /// Execute a WASM module with optional per-execution file sandbox.
    pub async fn execute_job_with_sandbox(
        &self,
        wasm_bytes: &[u8],
        allowed_hosts: Vec<String>,
        allowed_methods: Vec<String>,
        max_memory_mb: usize,
        input: JsonValue,
        _execution_fs_dir: Option<Arc<cap_std::fs::Dir>>,
    ) -> Result<JsonValue> {
        self.execute_job_with_context(
            wasm_bytes,
            allowed_hosts,
            allowed_methods,
            max_memory_mb,
            input,
            _execution_fs_dir,
            None,           // No execution context
            HashMap::new(), // No secrets
        )
        .await
    }

    /// Execute a WASM module with full execution context and secrets.
    ///
    /// When `execution_context` is provided, all logs are automatically persisted
    /// to the database via NATS. `secrets` are pre-fetched, decrypted values made
    /// available to the module via the `secrets::get-secret` host function.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_job_with_context(
        &self,
        wasm_bytes: &[u8],
        allowed_hosts: Vec<String>,
        allowed_methods: Vec<String>,
        max_memory_mb: usize,
        input: JsonValue,
        _execution_fs_dir: Option<Arc<cap_std::fs::Dir>>,
        execution_context: Option<(String, String, String)>, // (workflow_id, execution_id, module_id)
        secrets: HashMap<String, String>,
    ) -> Result<JsonValue> {
        self.execute_job_with_full_features(
            wasm_bytes,
            allowed_hosts,
            allowed_methods,
            max_memory_mb,
            input,
            _execution_fs_dir,
            execution_context,
            secrets,
            None,                    // token_sender
            Duration::from_secs(30), // Default 30-second timeout
            RetryPolicy::default(),  // Default retry policy (3 attempts)
            Some(300),               // Result cache TTL: 5 minutes
        )
        .await
    }

    /// Execute WASM with all runtime-enforced safety and performance features.
    ///
    /// - Automatic logging (START/END with metrics)
    /// - Automatic timeout (prevents infinite loops)
    /// - Automatic retry (handles transient failures)
    /// - Performance monitoring (compilation, execution, cache metrics)
    /// - Result caching (Redis-backed, configurable TTL)
    /// - Error classification (timeout, out_of_fuel, trap, etc.)
    /// - Resource limits (fuel + memory)
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_job_with_full_features(
        &self,
        wasm_bytes: &[u8],
        allowed_hosts: Vec<String>,
        allowed_methods: Vec<String>,
        max_memory_mb: usize,
        input: JsonValue,
        _execution_fs_dir: Option<Arc<cap_std::fs::Dir>>,
        execution_context: Option<(String, String, String)>, // (workflow_id, execution_id, module_id)
        secrets: HashMap<String, String>,
        token_sender: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
        timeout: Duration,
        retry_policy: RetryPolicy,
        result_cache_ttl_secs: Option<u64>, // None = no caching
    ) -> Result<JsonValue> {
        // Apply default result‑cache TTL from env (cached on runtime creation) if not supplied
        let result_cache_ttl_secs = result_cache_ttl_secs.or(self.default_result_cache_ttl_secs);

        // -----------------------------------------------------------------
        // Input size validation (prevent OOM / abuse)
        // -----------------------------------------------------------------
        let input_len = serde_json::to_vec(&input)
            .map_err(|e| anyhow::anyhow!("Failed to serialize input JSON: {}", e))?
            .len();
        if input_len > self.max_input_bytes {
            anyhow::bail!(
                "Input JSON size {} exceeds allowed maximum of {} bytes",
                input_len,
                self.max_input_bytes
            );
        }

        // TRACKING: Increment active executions counter for health checks
        self.active_executions.fetch_add(1, Ordering::SeqCst);
        self.total_executions.fetch_add(1, Ordering::SeqCst);

        // Track metrics (if enabled)
        if let Some(ref metrics) = self.metrics {
            metrics.increment_active();
            metrics.total_executions.add(1, &[]);
        }

        // Ensure we decrement on exit (even if error occurs)
        struct ExecutionGuard {
            counter: Arc<AtomicU32>,
            metrics: Option<Arc<crate::metrics::RuntimeMetrics>>,
        }
        impl Drop for ExecutionGuard {
            fn drop(&mut self) {
                self.counter.fetch_sub(1, Ordering::SeqCst);
                if let Some(ref metrics) = self.metrics {
                    metrics.decrement_active();
                }
            }
        }
        let _guard = ExecutionGuard {
            counter: self.active_executions.clone(),
            metrics: self.metrics.clone(),
        };

        let mut metrics = PerformanceMetrics::default();
        let overall_start = std::time::Instant::now();

        // Compute module SHA256 ONCE — reused for result cache key, logging, and component cache.
        let module_hash_bytes: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(wasm_bytes);
            hasher.finalize().into()
        };
        let module_hash_str = hex::encode(module_hash_bytes);

        // Inspect capability world to see if caching should be disabled
        let cap = crate::wit_inspector::inspect_component(wasm_bytes).capability_world;
        let mut result_cache_ttl_secs = result_cache_ttl_secs;
        if matches!(cap, crate::wit_inspector::CapabilityWorld::Governance) {
            // Governance nodes must not be cached because they require human interaction
            result_cache_ttl_secs = None;
        }

        // PHASE 2: RESULT CACHING — check before doing any compilation work
        if result_cache_ttl_secs.is_some() {
            let cache_key = Self::result_cache_key(&module_hash_str, &input);
            if let Some(cached_result) = self.get_cached_result(&cache_key).await {
                metrics.result_cache_hit = true;
                metrics.execution_ms = overall_start.elapsed().as_millis() as u64;

                // Log cache hit
                if let Some((_, exec_id, _)) = &execution_context {
                    if let Some(nats) = &self.nats_client {
                        let cache_log = serde_json::json!({
                            "execution_id": exec_id,
                            "level": "info",
                            "message": "Result cache hit - returning cached result",
                            "timestamp": chrono::Utc::now().to_rfc3339(),
                            "source": "runtime",
                            "metadata": {
                                "cache_key": cache_key,
                                "duration_ms": metrics.execution_ms,
                                "result_cache_hit": true,
                            }
                        });
                        if let Ok(payload) = serde_json::to_vec(&cache_log) {
                            let _ = nats
                                .publish(format!("wasm.log.{}", exec_id), payload.into())
                                .await;
                        }
                    }
                }

                return Ok(cached_result);
            }
        }

        // PHASE 2: AUTOMATIC RETRY LOGIC — retry on transient failures with exponential backoff
        let max_attempts = retry_policy.max_attempts + 1; // +1 for initial attempt
        let mut last_error = None;

        for attempt in 0..max_attempts {
            metrics.retry_attempts = attempt;

            // Log retry attempt if this isn't the first try
            if attempt > 0 {
                let backoff = retry_policy.backoff_for_attempt(attempt - 1);

                if let Some((_, exec_id, _)) = &execution_context {
                    if let Some(nats) = &self.nats_client {
                        let retry_log = serde_json::json!({
                            "execution_id": exec_id,
                            "level": "warn",
                            "message": format!("Retrying WASM execution (attempt {}/{})", attempt + 1, max_attempts),
                            "timestamp": chrono::Utc::now().to_rfc3339(),
                            "source": "runtime",
                            "metadata": {
                                "retry_attempt": attempt,
                                "backoff_ms": backoff.as_millis() as u64,
                                "previous_error": last_error.as_ref().map(|e: &anyhow::Error| e.to_string()),
                            }
                        });
                        if let Ok(payload) = serde_json::to_vec(&retry_log) {
                            let _ = nats
                                .publish(format!("wasm.log.{}", exec_id), payload.into())
                                .await;
                        }
                    }
                }

                tokio::time::sleep(backoff).await;
            }

            match self
                .execute_job_with_context_and_timeout_internal(
                    wasm_bytes,
                    allowed_hosts.clone(),
                    allowed_methods.clone(),
                    max_memory_mb,
                    input.clone(),
                    execution_context.clone(),
                    secrets.clone(),
                    token_sender.clone(),
                    module_hash_bytes,
                    timeout,
                    &mut metrics,
                )
                .await
            {
                Ok(result) => {
                    // Cache the result if caching is enabled
                    if let Some(ttl_secs) = result_cache_ttl_secs {
                        let cache_key = Self::result_cache_key(&module_hash_str, &input);
                        self.cache_result(&cache_key, &result, ttl_secs).await;
                    }

                    // Log performance metrics
                    if let Some((_, exec_id, _)) = &execution_context {
                        if let Some(nats) = &self.nats_client {
                            let perf_log = serde_json::json!({
                                "execution_id": exec_id,
                                "level": "info",
                                "message": "WASM execution performance metrics",
                                "timestamp": chrono::Utc::now().to_rfc3339(),
                                "source": "runtime",
                                "metadata": {
                                    "compilation_ms": metrics.compilation_ms,
                                    "execution_ms": metrics.execution_ms,
                                    "total_ms": overall_start.elapsed().as_millis() as u64,
                                    "cache_hit": metrics.cache_hit,
                                    "result_cache_hit": metrics.result_cache_hit,
                                    "retry_attempts": metrics.retry_attempts,
                                }
                            });
                            if let Ok(payload) = serde_json::to_vec(&perf_log) {
                                let _ = nats
                                    .publish(format!("wasm.log.{}", exec_id), payload.into())
                                    .await;
                            }
                        }
                    }

                    // Record OpenTelemetry metrics (if enabled)
                    if let Some(ref otel_metrics) = self.metrics {
                        let total_duration = overall_start.elapsed().as_millis() as f64;
                        otel_metrics.record_execution(total_duration, "success");
                        otel_metrics
                            .record_compilation(metrics.compilation_ms as f64, metrics.cache_hit);

                        if metrics.retry_attempts > 0 {
                            for _ in 0..metrics.retry_attempts {
                                otel_metrics.record_retry("transient_error");
                            }
                        }
                    }

                    return Ok(result);
                }
                Err(e) => {
                    if attempt < retry_policy.max_attempts && is_transient_error(&e) {
                        last_error = Some(e);
                        continue; // Retry
                    } else {
                        // Record failure metrics (if enabled)
                        if let Some(ref otel_metrics) = self.metrics {
                            let total_duration = overall_start.elapsed().as_millis() as f64;
                            otel_metrics.record_execution(total_duration, "error");

                            let error_str = e.to_string();
                            let (error_type, friendly_msg) = if error_str.contains("timeout") {
                                ("timeout", "WASM execution timed out")
                            } else if error_str.contains("out of fuel") {
                                (
                                    "out_of_fuel",
                                    "WASM execution exhausted fuel – likely runaway loop",
                                )
                            } else if error_str.contains("trap") {
                                (
                                    "trap",
                                    "WASM trap encountered – possible security violation",
                                )
                            } else if error_str.contains("memory") {
                                ("memory_limit", "WASM memory limit exceeded")
                            } else {
                                ("runtime_error", "WASM execution failed")
                            };
                            otel_metrics.record_error(error_type);
                            // Return a sanitized, user‑friendly error without leaking internals.
                            return Err(anyhow::anyhow!(friendly_msg));
                        }

                        return Err(e);
                    }
                }
            }
        }

        // All retries exhausted
        let error = last_error
            .unwrap_or_else(|| anyhow::anyhow!("Execution failed after {} attempts", max_attempts));

        if let Some(ref otel_metrics) = self.metrics {
            let total_duration = overall_start.elapsed().as_millis() as f64;
            otel_metrics.record_execution(total_duration, "retry_exhausted");
            otel_metrics.record_error("retries_exhausted");
        }

        Err(error)
    }

    /// Internal execution method with performance metrics tracking.
    /// Called by execute_job_with_full_features for each retry attempt.
    #[allow(clippy::too_many_arguments)]
    async fn execute_job_with_context_and_timeout_internal(
        &self,
        wasm_bytes: &[u8],
        allowed_hosts: Vec<String>,
        allowed_methods: Vec<String>,
        max_memory_mb: usize,
        input: JsonValue,
        execution_context: Option<(String, String, String)>, // (workflow_id, execution_id, module_id)
        secrets: HashMap<String, String>,
        token_sender: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
        // Pre-computed SHA256 hash — avoids triple-computing it per attempt.
        module_hash_bytes: [u8; 32],
        timeout: Duration,
        metrics: &mut PerformanceMetrics,
    ) -> Result<JsonValue> {
        // DISTRIBUTED TRACING: Create execution span
        let execution_id = execution_context
            .as_ref()
            .map(|(_, exec_id, _)| exec_id.clone())
            .unwrap_or_else(|| format!("exec-{}", uuid::Uuid::new_v4()));

        let mut span = crate::tracing::ExecutionSpan::new("wasm-execution", &execution_id);

        if let Some((workflow_id, _, module_id)) = &execution_context {
            span.set_attribute("workflow.id", workflow_id);
            span.set_attribute("module.id", module_id);
        }
        span.set_attribute_int("memory_limit_mb", max_memory_mb as i64);
        span.set_attribute_int("timeout_ms", timeout.as_millis() as i64);
        span.set_attribute_int("wasm_size_bytes", wasm_bytes.len() as i64);

        // Inspect capability world to select the appropriate tiered linker.
        let cap = crate::wit_inspector::inspect_component(wasm_bytes).capability_world;
        // Only specific worlds are granted raw WASI network access (TCP/UDP sockets).
        let allow_wasi_network = matches!(
            cap,
            CapabilityWorld::Network | CapabilityWorld::Database | CapabilityWorld::Trusted
        );

        // Select the correct linker + cache for this tier.
        let (linker, cache) = self.select_tier(&cap)?;

        // Build a secured store with execution context and pre-fetched secrets.
        let mut context = TalosContext::new(
            cap.clone(),
            allowed_hosts.clone(),
            allowed_methods,
            max_memory_mb,
            secrets,
            self.redis_client.clone(),
            self.nats_client.clone(),
            self.db_pool.clone(),
            allow_wasi_network,
            token_sender,
        )?;

        // Set execution context for automatic logging
        if let Some((workflow_id, exec_id, module_id)) = execution_context {
            context.set_workflow_context(workflow_id.clone(), exec_id.clone(), module_id.clone());
            // Correlate logs across controller and worker using the workflow ID.
            context.set_request_id(workflow_id.clone());

            // Initialize cryptographic ledger for WORM logging
            let ledger = std::sync::Arc::new(tokio::sync::Mutex::new(
                crate::audit::ExecutionLedger::new(&workflow_id, &exec_id),
            ));
            context.set_audit_ledger(ledger);
        }

        let mut store = Store::new(&self.engine, context);
        let exec_id_for_log = store.data().execution_id.clone();

        // SECURITY: Apply Resource Limits — enforced by TalosContext::ResourceLimiter impl
        store.limiter(|ctx| ctx as &mut dyn wasmtime::ResourceLimiter);

        // Derive string hash from pre-computed bytes (avoids recomputing)
        let module_hash_str = hex::encode(module_hash_bytes);
        let start_time = std::time::Instant::now();

        // AUTOMATIC START LOG (Runtime-Enforced — Cannot be skipped)
        if let Some(exec_id) = &exec_id_for_log {
            if let Some(nats) = &self.nats_client {
                let start_log = serde_json::json!({
                    "execution_id": exec_id,
                    "level": "info",
                    "message": "WASM module execution started",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "source": "runtime",
                    "metadata": {
                        "module_hash": module_hash_str,
                        "max_memory_mb": max_memory_mb,
                        "allowed_hosts": allowed_hosts,
                        "capability_tier": cap.to_string(),
                        "has_sandbox": true,
                    }
                });

                if let Ok(payload) = serde_json::to_vec(&start_log) {
                    let _ = nats
                        .publish(format!("wasm.log.{}", exec_id), payload.into())
                        .await;
                }
            }
        }

        // Provide fuel to cap CPU usage (1M instructions)
        store.set_fuel(self.fuel_limit)?;

        // ── InstancePre cache lookup ─────────────────────────────────────────
        // On cache hit:  zero compilation, zero linking — just instantiate.
        // On cache miss: compile → link → pre-instantiate → cache.
        let instance_pre = {
            let mut c = cache
                .write()
                .map_err(|e| anyhow::anyhow!("InstancePre cache lock poisoned: {}", e))?;
            if let Some(pre) = c.get(&module_hash_bytes) {
                metrics.cache_hit = true;
                metrics.compilation_ms = 0;
                span.add_event("cache_hit");
                span.set_attribute_bool("cache_hit", true);
                pre.clone()
            } else {
                metrics.cache_hit = false;
                span.add_event("compilation_started");
                span.set_attribute_bool("cache_hit", false);
                let compilation_start = std::time::Instant::now();
                let component = if wasm_bytes.starts_with(AOT_VERSION_HDR) {
                    self.load_precompiled(wasm_bytes)?
                } else {
                    Component::new(&self.engine, wasm_bytes)?
                };
                let pre = linker.instantiate_pre(&component)?;
                metrics.compilation_ms = compilation_start.elapsed().as_millis() as u64;
                span.add_event("compilation_completed");
                span.set_attribute_int("compilation_ms", metrics.compilation_ms as i64);
                c.put(module_hash_bytes, pre.clone());
                pre
            }
        };

        // Instantiate from the pre-linked component (fast path with pooling).
        let automation_pre = crate::bindings::AutomationNodePre::new(instance_pre)?;
        let instance = automation_pre.instantiate_async(&mut store).await?;

        // Call the exported `run` function with automatic timeout enforcement.
        let input_str = input.to_string();
        println!("--> PASSING TO WASM NODE: {}", input_str);

        // If the module can use Governance (human-in-the-loop), it might park for days.
        let actual_timeout =
            if matches!(cap, CapabilityWorld::Governance | CapabilityWorld::Trusted) {
                std::time::Duration::from_secs(86400 * 7) // 7 days
            } else {
                timeout
            };

        let execution_start = std::time::Instant::now();
        let call_result = tokio::time::timeout(actual_timeout, async move {
            instance.call_run(&mut store, &input_str).await
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "WASM execution timed out after {:?}. The module took too long to execute.\
                    \nThis may indicate an infinite loop or excessive computation.",
                actual_timeout
            )
        })?;

        metrics.execution_ms = execution_start.elapsed().as_millis() as u64;

        let _duration_ms = start_time.elapsed().as_millis() as u64;

        // Handle runtime error (outer Result)
        let output_result = call_result?;

        // Handle component error (inner Result<String, String>)
        let output_str: String = match output_result {
            Ok(s) => s,
            Err(e) => {
                span.end_error(&format!("Component error: {}", e));
                return Err(anyhow::anyhow!("Component returned error: {}", e));
            }
        };

        println!("--> WASM NODE RETURNED: {:?}", output_str);
        tracing::debug!("WASM module returned output_str: {:?}", output_str);

        // Parse the JSON output, fallback to wrapping it in a String value if parsing fails
        let out_json: JsonValue = match serde_json::from_str(&output_str) {
            Ok(json) => json,
            Err(_) => {
                tracing::debug!(
                    "Output is not valid JSON, treating as raw string: {:?}",
                    output_str
                );
                serde_json::Value::String(output_str.clone())
            }
        };

        span.set_attribute_int("output_size_bytes", output_str.len() as i64);
        span.set_attribute_bool("cache_hit", metrics.cache_hit);
        span.add_event("execution_completed");
        span.end_success();

        // Enforce output size limit to avoid huge payloads.
        let output_len = serde_json::to_vec(&out_json)
            .map_err(|e| anyhow::anyhow!("Failed to serialize output JSON: {}", e))?
            .len();
        if output_len > self.max_output_bytes {
            anyhow::bail!(
                "Output JSON size {} exceeds allowed maximum of {} bytes",
                output_len,
                self.max_output_bytes,
            );
        }
        Ok(out_json)
    }

    /// Execute a WASM module with a string input and timeout.
    ///
    /// This is the async version. Prefer calling it directly from async contexts
    /// rather than using a blocking wrapper.
    pub async fn execute_module_with_timeout(
        &self,
        wasm_bytes: &[u8],
        input: &str,
        timeout: std::time::Duration,
    ) -> Result<String> {
        tokio::time::timeout(timeout, self.execute_module_string(wasm_bytes, input))
            .await
            .map_err(|_| anyhow::anyhow!("WASM execution timed out after {:?}", timeout))?
    }

    /// Execute a WASM module with string input/output (no JSON parsing)
    pub async fn execute_module_string(&self, wasm_bytes: &[u8], input: &str) -> Result<String> {
        self.execute_module_string_with_context(wasm_bytes, input, None)
            .await
    }

    /// Execute a WASM module with string input/output and execution context.
    pub async fn execute_module_string_with_context(
        &self,
        wasm_bytes: &[u8],
        input: &str,
        execution_context: Option<(String, String, String)>, // (workflow_id, execution_id, module_id)
    ) -> Result<String> {
        self.execute_module_string_with_context_and_timeout(
            wasm_bytes,
            input,
            execution_context,
            std::time::Duration::from_secs(30),
            HashMap::new(),
            None,
        )
        .await
    }

    /// Execute a WASM module with string input/output, execution context, custom timeout, and secrets.
    pub async fn execute_module_string_with_context_and_timeout(
        &self,
        wasm_bytes: &[u8],
        input: &str,
        execution_context: Option<(String, String, String)>, // (workflow_id, execution_id, module_id)
        timeout: std::time::Duration,
        secrets: HashMap<String, String>,
        stdout_sender: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    ) -> Result<String> {
        // Inspect capability world so we use the correct tiered linker + cache.
        let cap = crate::wit_inspector::inspect_component(wasm_bytes).capability_world;
        // Only specific worlds are granted raw WASI network access (TCP/UDP sockets).
        let allow_wasi_network = matches!(
            cap,
            CapabilityWorld::Network | CapabilityWorld::Database | CapabilityWorld::Trusted
        );
        let (linker, cache) = self.select_tier(&cap)?;

        let mut context = TalosContext::new(
            cap.clone(),
            vec![], // allowed_hosts: deny all
            vec![], // allowed_methods
            128,
            secrets,
            self.redis_client.clone(),
            self.nats_client.clone(),
            self.db_pool.clone(),
            allow_wasi_network,
            stdout_sender,
        )?;

        if let Some((workflow_id, execution_id, module_id)) = execution_context {
            context.set_workflow_context(
                workflow_id.clone(),
                execution_id.clone(),
                module_id.clone(),
            );
            context.set_request_id(workflow_id.clone());
        }

        let mut store = Store::new(&self.engine, context);

        // SECURITY: Apply Resource Limits
        store.limiter(|ctx| ctx as &mut dyn wasmtime::ResourceLimiter);

        // Provide fuel to cap CPU usage
        store.set_fuel(self.fuel_limit)?;

        // Get or compile InstancePre with caching
        let mut hasher = Sha256::new();
        hasher.update(wasm_bytes);
        let cache_key: [u8; 32] = hasher.finalize().into();

        let instance_pre = {
            let mut c = cache
                .write()
                .map_err(|e| anyhow::anyhow!("InstancePre cache lock poisoned: {}", e))?;
            if let Some(pre) = c.get(&cache_key) {
                pre.clone()
            } else {
                let component = if wasm_bytes.starts_with(AOT_VERSION_HDR) {
                    self.load_precompiled(wasm_bytes)?
                } else {
                    Component::new(&self.engine, wasm_bytes)?
                };
                let pre = linker.instantiate_pre(&component)?;
                c.put(cache_key, pre.clone());
                pre
            }
        };

        let automation_pre = crate::bindings::AutomationNodePre::new(instance_pre)?;
        let instance = automation_pre.instantiate_async(&mut store).await?;

        let input_str = input.to_string();

        let call_result = tokio::time::timeout(timeout, async move {
            instance.call_run(&mut store, &input_str).await
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "WASM execution timed out after {:?}. The module took too long to execute.",
                timeout
            )
        })?;

        let output_result = call_result?;

        let output_str: String = match output_result {
            Ok(s) => s,
            Err(e) => return Err(anyhow::anyhow!("Component returned error: {}", e)),
        };

        Ok(output_str)
    }

    // ========================================================================
    // PIPELINE EXECUTION (Superpower 2)
    // ========================================================================

    /// Execute a sequence of WASM steps as a single in-process pipeline.
    ///
    /// Outputs from each step are passed as `input` to the next step, wrapped
    /// alongside that step's `config`:
    ///
    /// ```json
    /// { "config": <step.config>, "input": <previous_output> }
    /// ```
    ///
    /// # Shared state
    /// All steps share one `state_store` so they can exchange values via the
    /// `state::set` / `state::get` host functions without NATS round-trips.
    ///
    /// # Shared sandbox (`share_sandbox = true`)
    /// All steps see the same ephemeral directory through the `files` host
    /// interface — a step can write a file and the next step can read it.
    /// WASI-level file I/O is still per-step (separate WASI context).
    ///
    /// # Security
    /// - Each step gets its **own** `Store` (WASM linear memory is not shared).
    /// - Each step is linked against its **tiered linker** (capability enforcement).
    /// - Each step's fuel is independently capped by `step.max_fuel`.
    /// - `overall_timeout` caps the entire pipeline; per-step timeouts add a
    ///   finer-grained guard.
    pub async fn execute_pipeline(
        &self,
        workflow_execution_id: &str,
        steps: Vec<PipelineStepSpec>,
        overall_timeout: Duration,
        share_sandbox: bool,
    ) -> Result<PipelineResult> {
        if steps.is_empty() {
            anyhow::bail!("pipeline must have at least one step");
        }

        let overall_start = std::time::Instant::now();
        let deadline = overall_start + overall_timeout;

        // One state store shared across all steps.
        let shared_state: Arc<std::sync::Mutex<HashMap<String, String>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        // Optional shared sandbox directory (lifetime spans the entire pipeline).
        let shared_sandbox_dir = if share_sandbox {
            Some(tempfile::tempdir()?)
        } else {
            None
        };

        let mut previous_output: JsonValue = JsonValue::Null;
        let mut step_outputs: Vec<JsonValue> = Vec::with_capacity(steps.len());
        let mut step_times_ms: Vec<u64> = Vec::with_capacity(steps.len());

        for step in &steps {
            // Enforce the overall deadline.
            let now = std::time::Instant::now();
            if now >= deadline {
                anyhow::bail!(
                    "pipeline overall timeout ({:?}) exceeded before step '{}' could run",
                    overall_timeout,
                    step.module_id,
                );
            }
            let remaining = deadline - now;
            let step_timeout = step.timeout.min(remaining);

            let step_start = std::time::Instant::now();

            // Compute module SHA256 for cache lookup.
            let module_hash_bytes: [u8; 32] = {
                let mut hasher = Sha256::new();
                hasher.update(&step.wasm_bytes);
                hasher.finalize().into()
            };

            // Inspect capability world → tiered linker + cache.
            let cap = crate::wit_inspector::inspect_component(&step.wasm_bytes).capability_world;
            // All worlds except Minimal and Unknown allow outbound network access.
            let allow_wasi_network =
                !matches!(cap, CapabilityWorld::Minimal | CapabilityWorld::Unknown);
            let (linker, cache) = self.select_tier(&cap)?;

            // Get or compile InstancePre.
            let instance_pre = {
                let mut c = cache
                    .write()
                    .map_err(|e| anyhow::anyhow!("InstancePre cache poisoned: {}", e))?;
                if let Some(pre) = c.get(&module_hash_bytes) {
                    pre.clone()
                } else {
                    let component = if step.wasm_bytes.starts_with(AOT_VERSION_HDR) {
                        self.load_precompiled(&step.wasm_bytes)?
                    } else {
                        wasmtime::component::Component::new(&self.engine, &step.wasm_bytes)?
                    };
                    let pre = linker.instantiate_pre(&component)?;
                    c.put(module_hash_bytes, pre.clone());
                    pre
                }
            };

            // Build step input: previous output + this step's config.
            let step_input = serde_json::json!({
                "config": step.config,
                "input": previous_output,
            });

            // Create a TalosContext for this step (fresh WASM memory / WASI sandbox).
            let mut context = TalosContext::new(
                cap.clone(),
                step.allowed_hosts.clone(),
                step.allowed_methods.clone(),
                step.max_memory_mb,
                step.secrets.clone(),
                self.redis_client.clone(),
                self.nats_client.clone(),
                self.db_pool.clone(),
                allow_wasi_network,
                None,
            )?;
            // Correlate step execution logs with the module ID.
            context.set_request_id(step.module_id.clone());

            // Share the pipeline-scoped state store across steps.
            context.state_store = shared_state.clone();

            // Share the sandbox directory through the `files` host interface.
            if let Some(ref sandbox_dir) = shared_sandbox_dir {
                context.fs_dir = cap_std::fs::Dir::open_ambient_dir(
                    sandbox_dir.path(),
                    cap_std::ambient_authority(),
                )?;
            }

            // Tag the execution context for tracing / logging.
            context.set_workflow_context(
                workflow_execution_id.to_string(),
                format!("pipeline-{}:{}", workflow_execution_id, step.module_id),
                step.module_id.clone(),
            );

            let mut store = Store::new(&self.engine, context);
            store.limiter(|ctx| ctx as &mut dyn wasmtime::ResourceLimiter);
            store.set_fuel(step.max_fuel)?;

            // Instantiate from the cached InstancePre.
            let automation_pre = crate::bindings::AutomationNodePre::new(instance_pre)?;
            let instance = automation_pre.instantiate_async(&mut store).await?;

            let input_str = step_input.to_string();

            // Execute with the per-step timeout (bounded by overall deadline).
            let call_result = tokio::time::timeout(step_timeout, async move {
                instance.call_run(&mut store, &input_str).await
            })
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "Pipeline step '{}' timed out after {:?}",
                    step.module_id,
                    step_timeout
                )
            })?;

            let output_result = call_result?;

            let output_str = match output_result {
                Ok(s) => s,
                Err(e) => {
                    anyhow::bail!("Pipeline step '{}' returned error: {}", step.module_id, e);
                }
            };

            let step_output: JsonValue = serde_json::from_str(&output_str).map_err(|e| {
                anyhow::anyhow!(
                    "Pipeline step '{}' produced invalid JSON: {}",
                    step.module_id,
                    e
                )
            })?;

            let step_time_ms = step_start.elapsed().as_millis() as u64;
            step_outputs.push(step_output.clone());
            step_times_ms.push(step_time_ms);
            previous_output = step_output;
        }

        Ok(PipelineResult {
            step_outputs,
            final_output: previous_output,
            step_times_ms,
        })
    }

    // ========================================================================
    // HEALTH CHECKS & OBSERVABILITY
    // ========================================================================

    /// Get current runtime health status
    pub fn get_health_status(&self) -> RuntimeHealthStatus {
        // Sum InstancePre cache sizes across all 8 tiers.
        let total_cache_size = [
            &self.minimal_cache,
            &self.network_cache,
            &self.secrets_cache,
            &self.filesystem_cache,
            &self.messaging_cache,
            &self.cache_node_cache,
            &self.database_cache,
            &self.trusted_cache,
        ]
        .iter()
        .map(|cache| {
            cache.read().map(|c| c.len()).unwrap_or_else(|e| {
                eprintln!("Warning: cache lock poisoned: {}", e);
                0
            })
        })
        .sum();

        RuntimeHealthStatus {
            uptime_seconds: self.start_time.elapsed().as_secs(),
            active_executions: self.active_executions.load(Ordering::SeqCst),
            total_executions: self.total_executions.load(Ordering::SeqCst),
            component_cache_size: total_cache_size,
            has_redis: self.redis_client.is_some(),
            has_nats: self.nats_client.is_some(),
            has_fs: self.fs_dir.is_some(),
        }
    }

    /// Get uptime in seconds
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Get number of active executions
    pub fn active_executions(&self) -> u32 {
        self.active_executions.load(Ordering::SeqCst)
    }

    /// Get total number of executions since startup
    pub fn total_executions(&self) -> u64 {
        self.total_executions.load(Ordering::SeqCst)
    }

    /// Get total InstancePre cache entries across all 8 tiers.
    pub fn cache_size(&self) -> usize {
        [
            &self.minimal_cache,
            &self.network_cache,
            &self.secrets_cache,
            &self.filesystem_cache,
            &self.messaging_cache,
            &self.cache_node_cache,
            &self.database_cache,
            &self.trusted_cache,
        ]
        .iter()
        .map(|c| c.read().map(|g| g.len()).unwrap_or(0))
        .sum()
    }

    /// Warm the cache by pre-loading frequently used WASM modules.
    /// This eliminates cold start latency for common workflows.
    pub async fn warm_cache(&self, frequent_modules: Vec<(&str, Vec<u8>)>) -> Result<usize> {
        let mut cached_count = 0;

        for (module_id, wasm_bytes) in frequent_modules {
            let cap = crate::wit_inspector::inspect_component(&wasm_bytes).capability_world;
            let (linker, cache) = match self.select_tier(&cap) {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(
                        module_id,
                        error = %e,
                        "cache warming: skipping module with unknown capability world"
                    );
                    continue;
                }
            };

            let component_result = if wasm_bytes.starts_with(AOT_VERSION_HDR) {
                self.load_precompiled(&wasm_bytes)
            } else {
                Component::new(&self.engine, &wasm_bytes)
            };

            match component_result {
                Ok(component) => match linker.instantiate_pre(&component) {
                    Ok(pre) => {
                        let mut hasher = Sha256::new();
                        hasher.update(&wasm_bytes);
                        let cache_key: [u8; 32] = hasher.finalize().into();

                        match cache.write() {
                            Ok(mut c) => {
                                c.put(cache_key, pre);
                                cached_count += 1;
                                tracing::info!(
                                    module_id,
                                    bytes = wasm_bytes.len(),
                                    tier = %cap,
                                    "cache warming: cached module"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    module_id,
                                    error = %e,
                                    "cache warming: failed to acquire cache lock, skipping"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            module_id,
                            error = %e,
                            "cache warming: failed to pre-instantiate module"
                        );
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        module_id,
                        error = %e,
                        "cache warming: failed to compile module"
                    );
                }
            }
        }

        Ok(cached_count)
    }

    /// Gracefully shutdown the runtime.
    /// Waits for active executions to complete (up to timeout).
    pub async fn shutdown_gracefully(&self, timeout: Duration) -> Result<u32> {
        tracing::info!("Graceful shutdown initiated, waiting for active executions");

        let deadline = std::time::Instant::now() + timeout;

        while self.active_executions.load(Ordering::SeqCst) > 0 {
            if std::time::Instant::now() > deadline {
                let remaining = self.active_executions.load(Ordering::SeqCst);
                tracing::warn!(
                    "Shutdown timeout reached, {} executions still active",
                    remaining
                );
                return Ok(remaining);
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        tracing::info!("All executions completed, shutdown clean");
        Ok(0)
    }

    // ========================================================================
    // AOT (AHEAD-OF-TIME) COMPILATION
    // ========================================================================

    /// Pre‑compile a WASM module to native code (AOT compilation).
    /// Generates a serialized, pre‑compiled module that loads 10‑100× faster.
    ///
    /// Blob format: `[TALOSV1 (7 bytes)] [HMAC-SHA256 (32 bytes)] [serialized component]`
    ///
    /// The HMAC prevents tampered blobs from reaching `unsafe Component::deserialize`.
    pub fn precompile_module(&self, wasm_bytes: &[u8]) -> Result<Vec<u8>> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        // Structured logging replaces raw stdout prints for observability.
        tracing::info!(bytes = wasm_bytes.len(), "AOT pre‑compiling WASM module");

        let compile_start = std::time::Instant::now();
        let serialized = self.engine.precompile_component(wasm_bytes)?;
        let compile_time = compile_start.elapsed();

        // Compute HMAC-SHA256 over the serialized blob to protect integrity.
        let key = aot_hmac_key();
        let mut mac = Hmac::<Sha256>::new_from_slice(&key)
            .map_err(|e| anyhow::anyhow!("Failed to create AOT HMAC: {}", e))?;
        mac.update(&serialized);
        let tag: [u8; AOT_HMAC_LEN] = mac.finalize().into_bytes().into();

        // Layout: VERSION_HDR | HMAC_TAG | serialized_component
        let mut out = Vec::with_capacity(AOT_VERSION_HDR.len() + AOT_HMAC_LEN + serialized.len());
        out.extend_from_slice(AOT_VERSION_HDR);
        out.extend_from_slice(&tag);
        out.extend_from_slice(&serialized);

        tracing::info!(
            duration_ms = compile_time.as_millis(),
            input_bytes = wasm_bytes.len(),
            output_bytes = out.len(),
            speedup = out.len() as f64 / wasm_bytes.len() as f64,
            "AOT pre‑compilation complete"
        );

        Ok(out)
    }

    /// Load a pre-compiled WASM module (AOT deserialization).
    ///
    /// Verifies the HMAC-SHA256 integrity tag before calling the unsafe
    /// `Component::deserialize` API.  A tampered or truncated blob will be
    /// rejected with an error before any unsafe code is reached.
    ///
    /// # Safety
    /// Pre-compiled modules MUST be compiled with the EXACT SAME version of Wasmtime
    /// and the EXACT SAME engine configuration. Always verify compatibility before loading.
    pub fn load_precompiled(&self, precompiled_bytes: &[u8]) -> Result<Component> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        use subtle::ConstantTimeEq;

        let deserialize_start = std::time::Instant::now();

        // ── Step 1: verify version header ────────────────────────────────────
        const VERSION_HDR: &[u8] = AOT_VERSION_HDR;
        let min_len = VERSION_HDR.len() + AOT_HMAC_LEN;
        if precompiled_bytes.len() < VERSION_HDR.len() {
            anyhow::bail!("Precompiled blob too short to contain version header");
        }
        let (hdr, after_hdr) = precompiled_bytes.split_at(VERSION_HDR.len());
        if hdr != VERSION_HDR {
            anyhow::bail!("Precompiled WASM version mismatch – expected TALOSV1");
        }

        // Guard against legacy blobs that pre-date HMAC signing (they have the
        // version header but no HMAC tag).  Rather than silently deserializing
        // untrusted bytes, reject them so the caller knows to recompile.
        if precompiled_bytes.len() < min_len {
            anyhow::bail!(
                "Precompiled blob missing HMAC integrity tag (legacy format). \
                 Recompile the module to get a signed blob."
            );
        }

        // ── Step 2: verify HMAC-SHA256 integrity tag ─────────────────────────
        let (stored_tag, serialized) = after_hdr.split_at(AOT_HMAC_LEN);
        let key = aot_hmac_key();
        let mut mac = Hmac::<Sha256>::new_from_slice(&key)
            .map_err(|e| anyhow::anyhow!("Failed to create AOT HMAC: {}", e))?;
        mac.update(serialized);
        let expected_tag = mac.finalize().into_bytes();

        // Constant-time comparison to prevent timing side-channels.
        if stored_tag.ct_eq(expected_tag.as_slice()).unwrap_u8() != 1 {
            anyhow::bail!(
                "AOT blob HMAC verification failed — blob may have been tampered with or \
                 compiled by a different instance. Recompile the module."
            );
        }

        // ── Step 3: deserialize ───────────────────────────────────────────────
        // SAFETY: The binary blob has just been cryptographically verified using HMAC-SHA256
        // under the trusted master key, ensuring the serialized bytes were produced locally
        // and are un-tampered.
        let component = unsafe { Component::deserialize(&self.engine, serialized)? };

        tracing::info!(
            duration_ms = deserialize_start.elapsed().as_millis(),
            payload_bytes = serialized.len(),
            "AOT deserialization complete"
        );

        Ok(component)
    }

    /// Execute a pre-compiled WASM module (AOT mode).
    ///
    /// Uses the trusted linker because the original WASM bytes are unavailable
    /// for capability inspection.  AOT components must have been validated at
    /// upload time.
    pub async fn execute_precompiled(
        &self,
        precompiled_bytes: &[u8],
        cap: crate::wit_inspector::CapabilityWorld,
        allowed_hosts: Vec<String>,
        allowed_methods: Vec<String>,
        max_memory_mb: usize,
        input: JsonValue,
    ) -> Result<JsonValue> {
        let component = self.load_precompiled(precompiled_bytes)?;

        self.execute_component_internal(
            component,
            cap,
            allowed_hosts,
            allowed_methods,
            max_memory_mb,
            input,
            None,
            None,
            HashMap::new(),
            Duration::from_secs(30),
            false,
        )
        .await
    }

    /// Internal execution method for pre-loaded components.
    /// Used by both JIT and AOT execution paths.
    ///
    /// Uses the trusted linker — callers are responsible for ensuring the component
    /// was pre-validated against the correct capability level.
    #[allow(clippy::too_many_arguments)]
    async fn execute_component_internal(
        &self,
        component: Component,
        cap: crate::wit_inspector::CapabilityWorld,
        allowed_hosts: Vec<String>,
        allowed_methods: Vec<String>,
        max_memory_mb: usize,
        input: JsonValue,
        _execution_fs_dir: Option<Arc<cap_std::fs::Dir>>,
        execution_context: Option<(String, String, String)>,
        secrets: HashMap<String, String>,
        timeout: Duration,
        allow_wasi_network: bool,
    ) -> Result<JsonValue> {
        let mut context = TalosContext::new(
            cap.clone(),
            allowed_hosts,
            allowed_methods,
            max_memory_mb,
            secrets,
            self.redis_client.clone(),
            self.nats_client.clone(),
            self.db_pool.clone(),
            allow_wasi_network,
            None,
        )?;

        if let Some((workflow_id, execution_id, module_id)) = execution_context {
            context.set_workflow_context(
                workflow_id.clone(),
                execution_id.clone(),
                module_id.clone(),
            );
            context.set_request_id(workflow_id.clone());
        }

        let mut store = Store::new(&self.engine, context);

        store.limiter(|ctx| ctx as &mut dyn wasmtime::ResourceLimiter);
        store.set_fuel(self.fuel_limit)?;

        // Use the trusted linker for AOT/pre-loaded components.
        let pre = self.trusted_linker.instantiate_pre(&component)?;
        let automation_pre = crate::bindings::AutomationNodePre::new(pre)?;
        let bindings = automation_pre.instantiate_async(&mut store).await?;

        let input_str = serde_json::to_string(&input)?;

        let call_result = tokio::time::timeout(timeout, async move {
            bindings.call_run(&mut store, &input_str).await
        })
        .await??;

        let output_str: String = match call_result {
            Ok(s) => s,
            Err(e) => return Err(anyhow::anyhow!("Component returned error: {}", e)),
        };

        let output: JsonValue = serde_json::from_str(&output_str)?;
        Ok(output)
    }

    /// Hybrid execution mode: Try AOT first, fallback to JIT.
    pub async fn execute_hybrid(
        &self,
        wasm_bytes: &[u8],
        precompiled_bytes: Option<&[u8]>,
        allowed_hosts: Vec<String>,
        allowed_methods: Vec<String>,
        max_memory_mb: usize,
        input: JsonValue,
    ) -> Result<JsonValue> {
        if let Some(precompiled) = precompiled_bytes {
            match self.load_precompiled(precompiled) {
                Ok(component) => {
                    tracing::info!("AOT: Using pre-compiled module");
                    // Inspect the original WASM bytes (not precompiled) to determine
                    // the capability tier.  This is the correct source of truth.
                    let cap = crate::wit_inspector::inspect_component(wasm_bytes).capability_world;
                    // All worlds except Minimal and Unknown allow outbound network access.
                    let allow_wasi_network =
                        !matches!(cap, CapabilityWorld::Minimal | CapabilityWorld::Unknown);
                    return self
                        .execute_component_internal(
                            component,
                            cap.clone(),
                            allowed_hosts,
                            allowed_methods,
                            max_memory_mb,
                            input,
                            None,
                            None,
                            HashMap::new(),
                            Duration::from_secs(30),
                            allow_wasi_network,
                        )
                        .await;
                }
                Err(e) => {
                    tracing::warn!("AOT load failed, falling back to JIT: {}", e);
                }
            }
        }

        // Fallback to JIT compilation
        tracing::info!("JIT: Using JIT compilation");
        self.execute_job(
            wasm_bytes,
            allowed_hosts,
            allowed_methods,
            max_memory_mb,
            input,
        )
        .await
    }

    /// Execute a WASM module with a mock input, capturing stdout for testing.
    pub async fn execute_test_module_string(
        &self,
        wasm_bytes: &[u8],
        input: &str,
    ) -> (Result<String, String>, Vec<String>) {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);

        let log_collector = tokio::spawn(async move {
            let mut logs = Vec::new();
            let mut total_bytes = 0;
            const MAX_LOG_BYTES: usize = 100 * 1024; // 100 KB limit
            const MAX_LOG_LINES: usize = 1000;

            loop {
                match tokio::time::timeout(std::time::Duration::from_secs(60), rx.recv()).await {
                    Ok(Some(bytes)) => {
                        if total_bytes + bytes.len() > MAX_LOG_BYTES || logs.len() >= MAX_LOG_LINES {
                            if logs.last().map(|s: &String| s.as_str())
                                != Some("... [Logs truncated due to size limits] ...")
                            {
                                logs.push("... [Logs truncated due to size limits] ...".to_string());
                            }
                            continue; // Drain channel but don't store
                        }

                        total_bytes += bytes.len();
                        if let Ok(s) = String::from_utf8(bytes) {
                            let trimmed = s.trim();
                            if !trimmed.is_empty() {
                                logs.push(trimmed.to_string());
                            }
                        }
                    }
                    Ok(None) => break, // Channel closed
                    Err(_) => {
                        tracing::warn!("Log collector timed out waiting for messages");
                        break;
                    }
                }
            }
            logs
        });

        let result = self
            .execute_module_string_with_context_and_timeout(
                wasm_bytes,
                input,
                None,
                std::time::Duration::from_secs(10),
                std::collections::HashMap::new(),
                Some(tx.clone()),
            )
            .await
            .map_err(|e| format!("Execution failed: {}", e));

        drop(tx);
        let logs = log_collector.await.unwrap_or_default();

        (result, logs)
    }
}

/// Runtime health status for monitoring
#[derive(Debug, Clone, serde::Serialize)]
pub struct RuntimeHealthStatus {
    /// Uptime in seconds
    pub uptime_seconds: u64,
    /// Number of currently active executions
    pub active_executions: u32,
    /// Total executions since startup
    pub total_executions: u64,
    /// Total InstancePre entries across all tiers
    pub component_cache_size: usize,
    /// Whether Redis is configured
    pub has_redis: bool,
    /// Whether NATS is configured
    pub has_nats: bool,
    /// Whether filesystem is configured
    pub has_fs: bool,
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_status_initial_values() {
        let rt = TalosRuntime::new().expect("runtime creation");
        let status = rt.get_health_status();
        assert_eq!(status.active_executions, 0);
        assert_eq!(status.total_executions, 0);
        assert_eq!(status.component_cache_size, 0);
        assert!(!status.has_redis);
        assert!(!status.has_nats);
    }
}
