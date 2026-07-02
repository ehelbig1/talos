use cap_std::fs::Dir;
use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tempfile::TempDir;
use wasmtime::component::ResourceTable;
use wasmtime::ResourceLimiter;
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

/// The execution context for a single Wasm job.
///
/// Holds WASI state, resource limits, pre-fetched secrets, workflow metadata,
/// and optional handles to Redis / NATS / sandboxed file-system.
pub struct TalosContext {
    /// WASI state (file descriptors, env vars, etc.)
    wasi: WasiCtx,
    /// Resource table needed for the component model.
    table: ResourceTable,
    http_ctx: wasmtime_wasi_http::WasiHttpCtx,

    /// Allowed outbound hosts for the `http::fetch` host function.
    /// An empty list means "deny all" (safe default; use `["*"]` to allow any host).
    pub allowed_hosts: Vec<String>,

    /// Allowed HTTP methods for outbound requests (`http::fetch` and `graphql::execute`).
    /// Empty = allow all methods. Non-empty = only those methods permitted.
    /// Checked after the host allowlist so both restrictions must pass.
    pub allowed_methods: Vec<String>,

    /// Allowed SQL statement types for the `database::execute_query` host function.
    /// Empty = allow all statements (backwards-compatible). Non-empty = only those
    /// statement types permitted (e.g., `["SELECT", "INSERT"]`).
    /// `SELECT` is always allowed regardless. DDL statements (CREATE, DROP, ALTER,
    /// TRUNCATE) are always blocked regardless.
    pub allowed_sql_operations: Vec<String>,

    /// Per-module secret allowlist.  When non-empty, only secrets whose key
    /// matches an entry in this list (or the wildcard `"*"`) are served by
    /// `secrets::get-secret`.  An empty list means the module has no secret
    /// allowlist configured and ALL available secrets are accessible
    /// (backwards-compatible default).
    pub allowed_secrets: Vec<String>,

    /// Workflow-scoped environment variables surfaced via the `env` interface.
    pub env_vars: HashMap<String, String>,
    pub capability_world: crate::wit_inspector::CapabilityWorld,

    /// Integration this module belongs to, if any. `None` means the module
    /// is not an integration and `integration-state::*` host functions
    /// return `unauthorized`. The worker NEVER reads this value from
    /// guest args — it comes from the JobRequest populated by the engine
    /// from `wasm_modules.integration_name`, which is set at compile
    /// time via `compile_custom_sandbox(integration_name: "...")`.
    /// Scopes every integration_state RPC the module makes.
    pub integration_name: Option<String>,

    /// Pluggable secret provider — the single source of truth for all secret resolution.
    ///
    /// Backs three-tier secret access:
    ///   Tier 1: host-side ops (fetch-with-bearer, fetch-with-header, hmac-sign) — no plaintext to guest
    ///   Tier 2: expose-secret(handle, reason) — explicit, audited, rate-limited plaintext crossing
    ///   Tier 3: vault:// config injection in HTTP headers — unchanged
    ///
    /// SlotHandle values are host-internal (u64) — the WASM guest holds only the integer.
    pub provider: std::sync::Arc<dyn talos_secrets::SecretProvider>,

    /// Rate-limit counter for Tier-2 `expose-secret` calls.
    /// Capped at MAX_EXPOSE_CALLS (10) per execution.
    pub(crate) expose_call_count: std::sync::atomic::AtomicU64,

    /// Set to true when any Tier-2 `expose-secret` call succeeds.
    /// The execution trace is marked to indicate explicit secret exposure occurred.
    pub(crate) secret_tier2_exposed: std::sync::atomic::AtomicBool,

    /// When false, `expose_secret` returns Unauthorized before any plaintext
    /// crosses the WASM boundary. Default: false (Tier-1-only). Modules must
    /// opt in via `allow_tier2_exposure: true` in their metadata to receive
    /// raw secret values.
    pub allow_tier2_exposure: bool,

    /// Per-user in-memory fallback counter for the Tier-2 `expose_secret`
    /// daily cap, used when Redis is unavailable or unconfigured.
    ///
    /// M-2 (2026-05-22): the prior `Arc<AtomicU64>` was process-wide, so
    /// one tenant exhausting the counter starved every other tenant on
    /// that worker until the pod restarted. The current shape isolates
    /// per `(user_id, date)` and self-resets at the day rollover. Shared
    /// across all executions via `Arc<ExposeFallback>`.
    pub global_expose_fallback: std::sync::Arc<crate::expose_fallback::ExposeFallback>,

    /// Workflow ID for tracing / logging.
    pub workflow_id: Option<String>,
    /// Execution ID for tracing / logging (also used as NATS log topic suffix).
    pub execution_id: Option<String>,
    /// Module ID for permissions and logging.
    pub module_id: Option<String>,
    /// User ID for global rate limiting and audit logging.
    pub user_id: Option<uuid::Uuid>,
    /// Optional request identifier that ties together controller, worker and logs.
    pub request_id: Option<String>,

    /// Cancellation token for cooperative cancellation.  When set, host functions
    /// check this token periodically and abort if revoked.
    pub cancellation_token: Option<String>,

    /// Whether this execution has been cancelled.  Set to true when the
    /// cancellation token is detected as revoked.  Checked by host functions.
    ///
    /// Wrapped in [`Arc`] so spawned background tasks (e.g. the SSE stream
    /// reader at `host_impl::wit_http_stream::connect`) can hold a clone
    /// and bail out promptly when the execution is cancelled —
    /// `AtomicBool` itself is `!Clone`, so without the `Arc` the only
    /// way a spawned task could observe cancellation was via mpsc
    /// receiver-drop, which doesn't fire while the task is blocked
    /// waiting on slow upstream bytes.
    pub cancelled: Arc<std::sync::atomic::AtomicBool>,

    /// In-memory key-value store scoped to this workflow execution.
    pub state_store: Arc<std::sync::Mutex<HashMap<String, String>>>,

    /// Optional Redis client for the `cache` interface.
    pub redis_client: Option<Arc<redis::Client>>,
    /// Optional NATS client for the `messaging` and `logging` interfaces.
    pub nats_client: Option<Arc<async_nats::Client>>,

    /// The WORM cryptographic ledger for verifiable audit trails.
    pub audit_ledger: Option<Arc<tokio::sync::Mutex<crate::audit::ExecutionLedger>>>,

    /// Ephemeral sandbox directory for the `files` interface.
    ///
    /// Every execution gets a fresh, empty temporary directory that is:
    ///   - Mounted at `/` in the WASI preopened-dirs table so WASM nodes can use
    ///     standard Rust file I/O (`std::fs`, `std::io`) transparently.
    ///   - Exposed here as a `cap_std::fs::Dir` for the `talos:core/files` host
    ///     functions, which enforce additional path‑sanitisation.
    ///   - Automatically shredded when this `TalosContext` is dropped (panic,
    ///     timeout, or normal completion), providing strong isolation between jobs.
    pub fs_dir: Dir,

    // `db_pool` removed Phase 2.10 — the worker has been credential-
    // free since the database WIT was routed through NATS-RPC
    // (Phase 2.3). The field was always None at runtime; deleting
    // it makes "no Postgres credentials in this binary" structural.
    /// Stores the human-readable detail of the last database error.
    /// Populated by execute_query (now via NATS-RPC reply), read by get_last_error.
    pub last_db_error: String,

    /// Human-readable OOM error message set when memory growth is denied.
    /// Checked after `call_run` failures to provide a clear diagnostic instead
    /// of a generic trap message.
    pub oom_error_message: Option<String>,

    /// Actor ID for persistent memory + state operations. All
    /// durable data flows through NATS-RPC to the controller; the
    /// worker no longer holds a DB pool directly. Anonymous
    /// executions (run_sandbox / test harness) leave this as `None`
    /// and every write-through path short-circuits to a no-op.
    pub actor_id: Option<uuid::Uuid>,

    /// LLM data-egress tier ceiling. `Tier1` refuses resolution of
    /// Anthropic / OpenAI / Gemini vault keys and fails closed with
    /// a clear error. Default `Tier2` for jobs without actor context
    /// or from pre-tier workers.
    pub max_llm_tier: talos_workflow_job_protocol::LlmTier,

    /// Keeps the ephemeral `TempDir` alive until this context is dropped.
    /// Dropping `_ephemeral_dir` removes the directory from the file system.
    _ephemeral_dir: TempDir,

    /// Maximum memory allowed for this execution (bytes).
    pub max_memory_bytes: usize,

    /// Remaining crypto compute budget in microseconds.
    /// Shared across all `hash()` and `hmac()` calls in this execution.
    /// Default: 5 seconds (5_000_000 us). When exhausted, crypto calls return empty.
    pub(crate) crypto_budget_us: AtomicU64,

    /// In-memory quota tracking for this execution.
    /// Each entry maps a metric name to (used, limit).
    pub(crate) quota_usage: std::sync::Mutex<HashMap<String, (u64, u64)>>,

    // ── Field-grouping status (B1, 2026-07) ──────────────────────────────
    // The active-stream receivers were grouped into `StreamRegistry`
    // (`self.streams`), and every host-internal per-execution counter /
    // budget below was narrowed `pub` → `pub(crate)` (the WASM guest never
    // touches them — it drives everything through WIT host functions).
    //
    // DEFERRED (left flat, on purpose): the per-execution rate-limit
    // counters were NOT collapsed into a single `RateLimitCounters`
    // sub-struct because each is a distinct budget passed by-reference into
    // `check_rate_limit(&self.<counter>, MAX_*)` from a different host
    // file, and re-nesting them buys little while touching ~13 sites across
    // ~10 files. The `ExecutionIdentity` cluster (`actor_id` /
    // `execution_id` / `max_llm_tier`, ~60 call sites, `max_llm_tier` read
    // by integration tests) was also left flat — regrouping it is a large,
    // higher-risk mechanical churn out of scope for a behaviour-preserving
    // pass. Both remain clean single-field accesses; group them later only
    // if a new consumer makes it worthwhile.
    /// Per-execution call counters for rate-limited host functions.
    /// Each counter tracks calls within the current execution.
    pub(crate) http_call_count: AtomicU64,
    /// M-6: per-host HTTP counter. The global `http_call_count` caps
    /// total fetches at `MAX_HTTP_CALLS_PER_EXECUTION` (1000); without
    /// a per-host cap, a single guest can issue all 1000 calls to one
    /// upstream and turn the worker into a third-party DoS
    /// amplification primitive. The per-host limit
    /// (`MAX_HTTP_CALLS_PER_HOST_PER_EXECUTION` in host_impl.rs)
    /// stacks on top of the global cap. Host strings are lowercased
    /// at insertion so `Example.com` and `example.com` share a slot.
    /// `DashMap` chosen for lock-free updates on the hot path —
    /// `Mutex<HashMap>` would serialize every HTTP call.
    pub(crate) http_calls_per_host: dashmap::DashMap<String, u64>,
    pub(crate) db_query_count: AtomicU64,
    pub(crate) messaging_publish_count: AtomicU64,
    /// MCP-523: per-execution email-send count. Pre-fix `wit_email::send`
    /// had no rate limit — see `MAX_EMAIL_SENDS_PER_EXECUTION` in
    /// `host_impl.rs`.
    pub(crate) email_send_count: AtomicU64,
    /// MCP-537: per-execution webhook-send count. Pre-fix `wit_webhook::send`
    /// had no rate limit — a WASM module could fire arbitrarily many
    /// outbound POSTs (each up to 1 + max_retries actual requests).
    /// See `MAX_WEBHOOK_SENDS_PER_EXECUTION` in `host_impl.rs`.
    pub(crate) webhook_send_count: AtomicU64,
    /// MCP-537: per-execution GraphQL-query count. Same gap as
    /// `wit_webhook::send` — `wit_graphql::execute` and
    /// `execute_with_retry` had no per-execution cap.
    pub(crate) graphql_query_count: AtomicU64,
    /// MCP-588: per-execution `wit_secrets::get_secret` count. Pre-fix
    /// guest-initiated secret access had no rate limit — a module could
    /// loop `get_secret` thousands of times within its fuel budget,
    /// each call appending to the local audit ledger AND publishing to
    /// `talos.audit.ledger` over NATS. The audit-pipeline DoS is the
    /// concern (one execution flooding many MB of audit traffic), not
    /// the secret values themselves (host-side allowlist is intact).
    /// Host-initiated resolutions (`resolve_vault_header` from http /
    /// graphql / webhook headers) are bounded by their parent surface's
    /// per-execution cap, but the direct `get_secret` path was the
    /// straggler.
    pub(crate) secret_access_count: AtomicU64,

    /// Cumulative bytes written to the sandbox filesystem in this execution.
    pub(crate) fs_bytes_written: AtomicU64,

    /// Number of log messages emitted in this execution.
    pub(crate) log_message_count: AtomicU64,

    /// Per-execution event emission counter for the events interface.
    pub(crate) event_emit_count: AtomicU64,

    /// Host-internal registry of active LLM / SSE stream receivers for
    /// this execution. Grouped (was two loose `llm_streams` /
    /// `sse_streams` fields) — the guest only ever holds an opaque
    /// `stream_id` string, so this is `pub(crate)`.
    pub(crate) streams: StreamRegistry,

    /// L-finding-7 (2026-05-23): per-host CUMULATIVE SSE connect
    /// counter — sibling to `http_calls_per_host` (M-6). The global
    /// `MAX_SSE_STREAMS_PER_EXECUTION` (5) caps total concurrent
    /// streams per execution, but pre-fix all 5 could be opened
    /// against ONE upstream, turning the worker into a small-but-real
    /// amplification primitive (each stream stays open for the
    /// execution timeout and the worker holds a connection slot
    /// against the target). Tracking CUMULATIVE connects (not
    /// "currently open") matches the existing http_calls_per_host
    /// semantics: a guest that opens/closes/reopens a stream against
    /// the same host still consumes the budget. The host key is
    /// `host:port` lowercased — same normalisation as
    /// `http_calls_per_host` so the matcher (`per_host_check_and_bump`)
    /// stays shared. Cap value lives in `host_impl.rs` as
    /// `MAX_SSE_CONNECTS_PER_HOST_PER_EXECUTION`.
    pub(crate) sse_connects_per_host: dashmap::DashMap<String, u64>,

    /// Shared HTTP client for all outbound requests in this execution.
    ///
    /// Built once per execution with security defaults (no redirects, user-agent).
    /// Reused across `fetch`, `fetch_all`, `graphql`, `webhook`, `email`, `llm`,
    /// and `object_storage` calls to enable TCP/TLS connection reuse via the
    /// internal connection pool. Per-call timeouts are set on the request builder,
    /// not the client.
    pub http_client: reqwest::Client,

    /// S3-compatible endpoint URL (e.g., "http://minio:9000" or "https://s3.amazonaws.com").
    /// Configured via S3_ENDPOINT env var or secrets.
    pub s3_endpoint: Option<String>,
    /// S3 access key ID.
    pub s3_access_key: Option<String>,
    /// S3 secret access key.
    pub s3_secret_key: Option<String>,
    /// S3 region (default: "us-east-1").
    pub s3_region: Option<String>,

    /// Optional OpenTelemetry runtime metrics handle.
    /// Set from the runtime after construction so host functions can record
    /// rate-limit, approval, LLM, cancellation, and quota metrics.
    pub metrics: Option<Arc<crate::metrics::RuntimeMetrics>>,

    /// Captures bytes written to WASI stderr during execution (panic messages, etc.).
    /// Shared with the WasiCtx via a clone; readable from outside the Store after execution.
    pub stderr_capture: Arc<std::sync::Mutex<Vec<u8>>>,

    /// When true, non-GET HTTP requests, webhook sends, and messaging publishes
    /// are mocked with success responses instead of executing real network calls.
    /// GET requests still execute normally for data fetching.
    pub dry_run: bool,
}

impl WasiView for TalosContext {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncWrite;
use wasmtime_wasi::cli::{IsTerminal, StdoutStream};

struct MpscWriter {
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl AsyncWrite for MpscWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let _ = self.sender.try_send(buf.to_vec());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone)]
struct ChannelStdout {
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl IsTerminal for ChannelStdout {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for ChannelStdout {
    fn async_stream(&self) -> Box<dyn AsyncWrite + Send + Sync> {
        Box::new(MpscWriter {
            sender: self.sender.clone(),
        })
    }
}

/// L-5 (2026-05-22): null sink for WASI stdout when no `token_sender`
/// channel is wired. Pre-fix the worker called `builder.inherit_stdout()`,
/// which routed guest stdout to the worker process's own stdout. A
/// per-Store dropped after execution bounds the cross-job confidentiality
/// risk, but inherited stdout mingled guest output with worker logs and
/// could fill operator log volumes from a chatty (or hostile) module.
/// The null sink discards all writes — the WASI guest sees a successful
/// write so it doesn't burn fuel on retry. Pair with an explicit
/// `token_sender` channel if the operator wants stdout captured.
#[derive(Clone, Copy, Default)]
struct NullStdout;

impl IsTerminal for NullStdout {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for NullStdout {
    fn async_stream(&self) -> Box<dyn AsyncWrite + Send + Sync> {
        Box::new(NullWriter)
    }
}

struct NullWriter;

impl AsyncWrite for NullWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Captures WASI stderr writes (e.g. panic messages) into an in-process buffer.
/// The Arc<Mutex<Vec<u8>>> is shared between the WasiCtx and the outer runtime
/// so that panic text can be read after the Store is consumed.
struct BufferWriter {
    buffer: Arc<std::sync::Mutex<Vec<u8>>>,
}

/// MCP-593: per-execution cap on WASI stderr capture. Pre-fix the
/// BufferWriter's `extend_from_slice` was unbounded — a malicious or
/// buggy WASM module writing multi-GB to stderr (WASI stderr flows
/// to the host buffer, NOT the WASM-bounded heap) would OOM the
/// worker. The only legitimate consumer of this buffer is
/// `extract_panic_message_from_stderr` (runtime.rs:163), which
/// reads the first ~hundred bytes of a Rust panic header. 64 KiB
/// is generous (covers verbose panics with backtraces) and bounds
/// the host-side allocation cost per execution.
const MAX_STDERR_CAPTURE_BYTES: usize = 64 * 1024;

impl AsyncWrite for BufferWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Marker stamped into the buffer the first time we drop tail
        // bytes, so an operator reading the captured stderr can tell
        // truncation apart from genuine module output ending. Without
        // this, a malicious module could fill the buffer with forged
        // "verified by" lines to displace real diagnostic output and
        // the silent truncation would leave no trace.
        const TRUNCATION_MARKER: &[u8] =
            b"\n[stderr truncated by host at MAX_STDERR_CAPTURE_BYTES]\n";
        if let Ok(mut guard) = self.buffer.lock() {
            // MCP-593: cap host-side allocation. Returning `buf.len()`
            // even when we silently drop the tail keeps the WASM guest
            // believing the write succeeded (so it doesn't get stuck
            // looping retries on a "short write" — that would just
            // burn fuel without making progress); the panic-extraction
            // path only needs the first few hundred bytes anyway.
            let remaining = MAX_STDERR_CAPTURE_BYTES.saturating_sub(guard.len());
            if remaining > 0 {
                let take = buf.len().min(remaining);
                guard.extend_from_slice(&buf[..take]);
                // If this write filled the buffer AND there were more
                // bytes the guest tried to emit, append the truncation
                // marker once (overwriting the last bytes if needed so
                // total length stays at MAX_STDERR_CAPTURE_BYTES + marker).
                if take < buf.len() {
                    // Reserve marker space at the tail by trimming if
                    // necessary. This ensures the marker is always at
                    // the END so it's easy to grep for.
                    let target_len =
                        MAX_STDERR_CAPTURE_BYTES.saturating_sub(TRUNCATION_MARKER.len());
                    if guard.len() > target_len {
                        guard.truncate(target_len);
                    }
                    guard.extend_from_slice(TRUNCATION_MARKER);
                }
            }
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone)]
struct BufferCapture {
    buffer: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl IsTerminal for BufferCapture {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for BufferCapture {
    fn async_stream(&self) -> Box<dyn AsyncWrite + Send + Sync> {
        Box::new(BufferWriter {
            buffer: self.buffer.clone(),
        })
    }
}

/// Parsed SSE event for the http-stream interface.
pub struct SseEventInternal {
    pub event_type: Option<String>,
    pub data: String,
    pub id: Option<String>,
}

/// Host-internal registry of active streaming receivers for one execution.
///
/// Groups the two per-execution stream maps that were previously loose
/// `TalosContext` fields. Both are host-side plumbing — the WASM guest
/// only ever holds an opaque string `stream_id` and drives the streams
/// through the `llm-streaming` / `http-stream` WIT host functions, so
/// these are `pub(crate)` (the guest never accesses them directly).
///
/// Behaviour is unchanged from the flat fields: each map is an
/// independent `Mutex<HashMap<..>>` keyed by stream id, and the two
/// budgets (`MAX_LLM_STREAMS_PER_EXECUTION` /
/// `MAX_SSE_STREAMS_PER_EXECUTION`) stay separate. The per-host
/// CUMULATIVE connect budget (`sse_connects_per_host`) is intentionally
/// NOT here — it pairs with `http_calls_per_host` as a rate-limit
/// counter, not with the active-stream registry.
pub struct StreamRegistry {
    /// Active LLM streams indexed by stream ID. Each holds a receiver
    /// channel for SSE events stored as JSON values.
    pub(crate) llm:
        std::sync::Mutex<HashMap<String, tokio::sync::mpsc::Receiver<serde_json::Value>>>,
    /// Active HTTP SSE streams indexed by stream ID. Each holds a
    /// receiver for parsed SSE events (`None` = stream ended).
    pub(crate) sse:
        std::sync::Mutex<HashMap<String, tokio::sync::mpsc::Receiver<SseEventInternal>>>,
}

impl StreamRegistry {
    fn new() -> Self {
        Self {
            llm: std::sync::Mutex::new(HashMap::new()),
            sse: std::sync::Mutex::new(HashMap::new()),
        }
    }
}

/// Per-execution hardened reqwest client.
///
/// Pulled into a free helper (rather than left inline in
/// `TalosContext::new`) so the `SsrfFilteringResolver` can borrow
/// `allowed_hosts` before the latter is moved into the struct, and so
/// the security-critical client posture (no redirects, 5s handshake
/// budget, SSRF-aware DNS) is grep-able in one place.
///
/// Security posture summary:
///   * No automatic redirect-following — a 30x to a private IP would
///     bypass the per-call DNS validation that operates on the
///     original URL only.
///   * 5s connect timeout — bounds TLS-handshake stalls so a SSRF
///     target hardened against TLS probes can't consume the full
///     per-call timeout on the handshake alone (MCP-1058).
///   * Per-host idle-pool cap (10) — limits resource churn while
///     keeping a useful connection-reuse path open.
///   * SSRF-aware DNS resolver scoped to this execution's allowed
///     hosts — every address the OS resolver returns is re-classified
///     via `classify_private_ip` BEFORE reqwest connects, closing the
///     TOCTOU window between the per-call check and the connect step.
///   * Tier-1 (`local_egress_only`) INVERTS the resolver's default
///     public-allow posture: any resolved address that is NOT
///     loopback/private/link-local is denied, enforcing the documented
///     "data must NOT leave host" contract at the connect point (S3,
///     2026-06-23). This defeats the DNS hole the name-based
///     `tier1_egress_deny_reason` gate cannot close.
fn build_per_execution_http_client(
    allowed_hosts: &[String],
    local_egress_only: bool,
) -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent("Talos-Worker/1.0")
        .connect_timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(10)
        .dns_resolver(std::sync::Arc::new(
            crate::ssrf_resolver::SsrfFilteringResolver::for_allowed_hosts(
                allowed_hosts,
                local_egress_only,
            ),
        ))
        .build()
        .expect("worker: failed to build hardened reqwest client with no-redirect policy")
}

/// Filesystem-preopen policy for a capability world.
///
/// Returns `true` ONLY for the two worlds that get a full read/write WASI
/// preopen AND the policy-enforcing `talos:core/files` host interface
/// (Filesystem, Trusted). Every other world — including Database and Agent —
/// gets NO WASI preopen, so a guest's only filesystem surface is a raw WASI
/// syscall that errors at the capability boundary.
///
/// Exhaustive match on purpose: a NEW `CapabilityWorld` variant is a compile
/// error here, forcing an explicit fs-preopen decision rather than silently
/// inheriting a (potentially wrong) default. See the call site in
/// `TalosContext::new` for why Database/Agent are no-preopen (the read-only
/// preopen they used to get was an empty, unpopulated dir whose only guard was
/// WASI `FilePerms` — the surface RUSTSEC-2026-0149 bypassed).
pub(crate) fn capability_world_has_fs_preopen(
    world: &crate::wit_inspector::CapabilityWorld,
) -> bool {
    use crate::wit_inspector::CapabilityWorld;
    match world {
        CapabilityWorld::Filesystem | CapabilityWorld::Trusted => true,
        CapabilityWorld::Database
        | CapabilityWorld::Agent
        | CapabilityWorld::Minimal
        | CapabilityWorld::Http
        | CapabilityWorld::Network
        | CapabilityWorld::Secrets
        | CapabilityWorld::Messaging
        | CapabilityWorld::Cache
        | CapabilityWorld::Governance
        | CapabilityWorld::Unknown => false,
    }
}

impl TalosContext {
    /// Create a new execution context with an ephemeral file-system sandbox.
    ///
    /// A fresh temporary directory is created for each call and mounted at `/`
    /// in the WASI preopened-dirs table.  The directory is removed from disk
    /// when the returned `TalosContext` is dropped.
    ///
    /// * `allowed_hosts` – hostname allowlist for outbound HTTP (empty = deny all; use `["*"]` to allow any host).
    /// * `allowed_methods` – HTTP method allowlist (empty = allow all; `["GET"]` = read-only).
    /// * `max_memory_mb` – memory cap in megabytes.
    /// * `secrets` – pre-fetched, decrypted secret values consumed by the `TalosVaultProvider`.
    ///   After construction the map is owned by the provider; no plaintext copy remains in the context.
    /// * `redis_client` – optional Redis connection.
    /// * `nats_client` – optional NATS connection.
    /// * `allow_wasi_network` – if `true`, grant `wasi:sockets` access so the
    ///   component can use `std::net::TcpStream` (WASIP2).
    ///   Only set this for `network-node` or `automation-node`
    ///   components; `minimal-node` components never need it.
    /// * `max_llm_tier` – the actor's data-egress ceiling. `Tier1`
    ///   (local-Ollama-only) wires the per-execution SSRF resolver into
    ///   `local_egress_only` mode, denying any resolved address that is
    ///   not loopback/private/link-local (S3, 2026-06-23). The field is
    ///   also stored on the context so the host-fn tier gates read it.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        capability_world: crate::wit_inspector::CapabilityWorld,
        allowed_hosts: Vec<String>,
        allowed_methods: Vec<String>,
        max_memory_mb: usize,
        secrets: HashMap<String, String>,
        redis_client: Option<Arc<redis::Client>>,
        nats_client: Option<Arc<async_nats::Client>>,
        allow_wasi_network: bool,
        token_sender: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
        global_expose_fallback: Arc<crate::expose_fallback::ExposeFallback>,
        max_llm_tier: talos_workflow_job_protocol::LlmTier,
    ) -> anyhow::Result<Self> {
        // ── Ephemeral sandbox ────────────────────────────────────────────────
        // Create the per-execution temporary directory.  It is automatically
        // removed from disk (including all contents) when `_ephemeral_dir` is
        // dropped — which happens as soon as the Store is deallocated after
        // execution, timeout, or panic.
        let ephemeral_dir = tempfile::tempdir()?;

        // Open a cap_std::fs::Dir handle for the `talos:core/files` host functions.
        // These host functions enforce additional path sanitisation on top of
        // the capability-based boundary already provided by cap-std.
        let fs_dir =
            cap_std::fs::Dir::open_ambient_dir(ephemeral_dir.path(), cap_std::ambient_authority())?;

        // ── WASI context ─────────────────────────────────────────────────────
        // Mount the sandbox at `/` using its host path.  WasiCtxBuilder opens
        // the directory internally and registers it as a WASI preopened dir so
        // that WASM nodes can use standard Rust file I/O (std::fs, std::io)
        // transparently.  The DirPerms / FilePerms restrict what the WASM guest
        // can do within the sandbox.
        // Ensure a sensible memory limit is supplied (must be > 0).
        if max_memory_mb == 0 {
            anyhow::bail!("max_memory_mb must be > 0");
        }
        let mut builder = WasiCtxBuilder::new();

        if let Some(tx) = token_sender {
            builder.stdout(ChannelStdout { sender: tx });
        } else {
            // L-5: discard guest stdout when no capture channel is
            // wired. Inheriting the worker process's stdout would
            // commingle untrusted guest output with operator logs and
            // let a chatty module bloat log volumes — even though each
            // Store is dropped per-job so confidentiality across jobs
            // is bounded.
            builder.stdout(NullStdout);
        }

        // Capture WASI stderr into an in-process buffer instead of inheriting the
        // worker's process stderr.  Panic messages (written to WASI stderr by the
        // wasm32-wasip2 runtime) are preserved here and surfaced in trap errors.
        let stderr_capture = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        builder.stderr(BufferCapture {
            buffer: stderr_capture.clone(),
        });

        // L1 (2026-05-22): gate the filesystem preopen by capability world.
        //
        // Pre-fix: every WASM execution got a preopened `/` with
        // DirPerms::all() + FilePerms::all(), regardless of whether the
        // module's declared capability world actually included
        // filesystem access. The blast radius was bounded to the
        // ephemeral per-instance tempdir, but defense-in-depth says
        // worlds without filesystem capability should not have ANY
        // file handle available — the WASI preopen surface is itself
        // attack surface (path-resolution bugs, symlink-following
        // tricks against cap-std, etc.).
        //
        // TWO tiers of preopen:
        //   * Filesystem / Trusted (Automation) — full read/write. These
        //     worlds also have the `talos:core/files` host interface linked
        //     (build_filesystem_linker / build_trusted_linker), so the WASI
        //     preopen and the policy-enforcing custom interface back the same
        //     per-execution dir; a module legitimately needs scratch I/O.
        //   * EVERYTHING ELSE — NO preopen. Guest `std::fs::*` fails at the
        //     capability boundary ("Capability denied").
        //
        // 2026-06-02 architectural change: Database / Agent previously got a
        // READ-ONLY preopen (DirPerms::READ / FilePerms::READ), justified as
        // "read operator-mounted lookup tables." That mount was never wired —
        // the dir is a FRESH EMPTY `tempfile::tempdir()` (line above), the
        // `execution_fs_dir` staging param is unused, and the `files`
        // interface (the only thing that writes the dir) is NOT linked for
        // these worlds. So the read-only preopen was an EMPTY, unpopulated,
        // functionally-inert dir — pure attack surface with no benefit.
        //
        // Worse, its read-only enforcement rode entirely on WASI `FilePerms`,
        // which is exactly what RUSTSEC-2026-0149 (wasmtime-wasi
        // `path_open(TRUNCATE)`) bypassed. Patched in wasmtime 44 (PR #121),
        // but the architectural lesson stands: a world WITHOUT the custom
        // `files` interface should not have a raw WASI preopen whose only
        // guard is the host's permission model. Collapsing Database / Agent
        // into the no-preopen tier removes the surface entirely and makes the
        // FilePerms-bypass class structurally unreachable for them. If these
        // worlds ever genuinely need to read staged files, route it through a
        // READ-ONLY `files` host interface (policy-enforcing), not a preopen.
        //
        // Defense-in-depth fact-check: the `files` host functions
        // (read/write/delete/list_dir) are linked ONLY in the Filesystem and
        // Trusted tiers, so a non-fs world that somehow imports
        // `talos:core/files` already fails to link. This closes the lower
        // raw-WASI-syscall surface to match.
        // Single, named, exhaustive policy (see `capability_world_has_fs_preopen`).
        if capability_world_has_fs_preopen(&capability_world) {
            builder.preopened_dir(ephemeral_dir.path(), "/", DirPerms::all(), FilePerms::all())?;
        }

        // Network access for wasi:sockets (WASIP2) — only granted when the
        // component's capability world includes outbound network I/O.
        // `inherit_network()` lets the guest use std::net::TcpStream et al.
        // The Talos `allowed_hosts` list still governs the HTTP host function;
        // raw TCP is gated here at the WasiCtx level.
        if allow_wasi_network {
            builder.inherit_network();
            builder.allow_ip_name_lookup(true);

            // SECURITY: Disable raw UDP sockets.  Talos HTTP is TCP-only;
            // UDP would allow DNS exfiltration and QUIC bypass of HTTP controls.
            builder.allow_udp(false);

            // SECURITY: Prevent Server-Side Request Forgery (SSRF)
            // Even though `talos:core/http::fetch` respects the `allowed_hosts` list,
            // raw WASI sockets bypass it entirely because they resolve directly to IPs.
            // To ensure the WASM sandbox cannot be used to scan internal network infrastructure,
            // we actively block connections to private, loopback, and link-local IP addresses.
            builder.socket_addr_check(|addr, _use| {
                Box::pin(async move {
                    // Route raw WASI sockets through the SAME shared SSRF
                    // classifier the WIT-http literal-IP gate and the controller
                    // pre-validation use (`talos_ssrf_classify::classify_private_ip`),
                    // so all three egress surfaces agree BY CONSTRUCTION. This
                    // replaces ~90 lines of hand-maintained range checks that the
                    // MCP-1067..1070 comments had to keep "byte-for-byte" in sync
                    // — exactly the drift hazard the literal-IP chokepoint (PR #116)
                    // removed on the http side.
                    //
                    // Two behaviour deltas vs. the old inline copy, both correct:
                    //   * It now blocks EVERY IPv4-in-IPv6 transition form
                    //     (IPv4-mapped AND IPv4-compat / NAT64 / 6to4) — the old
                    //     copy canonicalized only IPv4-mapped, so `::169.254.169.254`
                    //     (compat), 6to4, and NAT64 spellings of an internal target
                    //     were a latent socket-SSRF bypass. Now closed.
                    //   * It no longer special-cases RFC-5737 documentation ranges
                    //     (192.0.2/24, …). Those are reserved-unassigned, not
                    //     internal, and the other two surfaces already treat them
                    //     as public (see talos_http_utils::ssrf). Aligning removes
                    //     the lone divergence.
                    let ip = addr.ip();
                    if let Some(policy) = talos_ssrf_classify::classify_private_ip(ip) {
                        tracing::warn!(
                            %ip,
                            policy,
                            "SECURITY: blocked WASI socket connection to a non-public IP"
                        );
                        return false; // deny
                    }
                    // Public destination — allowed (the http host fn's
                    // `allowed_hosts` list still governs `talos:core/http`).
                    true
                })
            });
        }

        let wasi = builder.build();

        let table = ResourceTable::new();
        let max_memory_bytes = max_memory_mb * 1024 * 1024;
        let http_ctx = wasmtime_wasi_http::WasiHttpCtx::new();

        // Consume the pre-fetched secrets map into the SecretProvider.
        // No plaintext copy of the map is retained in TalosContext — all secret
        // access goes through the provider, which adds slot-based tracking and
        // audit logging via AuditingProvider.
        let provider: std::sync::Arc<dyn talos_secrets::SecretProvider> = {
            let p = talos_secrets::config::build_provider(
                &talos_secrets::config::ProviderConfig::TalosVault,
                secrets, // consumed — no clone
                true,    // enable AuditingProvider wrapper
            );
            std::sync::Arc::from(p)
        };

        // Build the per-execution reqwest client BEFORE moving
        // `allowed_hosts` into the struct so the SSRF resolver can be
        // scoped to this execution's explicit hostnames. See the
        // resolver doc-comment for the per-host bypass rationale.
        //
        // S3 (2026-06-23): a Tier-1 actor is "local-Ollama-only — data
        // must NOT leave host". Wire `local_egress_only` so the resolver
        // denies every public (globally-routable) resolved address,
        // regardless of hostname, closing the DNS hole the name-based
        // `tier1_egress_deny_reason` fast-fail gate cannot.
        let local_egress_only = matches!(max_llm_tier, talos_workflow_job_protocol::LlmTier::Tier1);
        let http_client = build_per_execution_http_client(&allowed_hosts, local_egress_only);

        Ok(Self {
            wasi,
            table,
            http_ctx,
            allowed_hosts,
            allowed_methods,
            allowed_sql_operations: vec![],
            allowed_secrets: vec![],
            env_vars: HashMap::new(),
            capability_world,
            // Populated downstream from the JobRequest; construct-time
            // default is None so non-integration modules fall through to
            // the `unauthorized` path in integration_state host fns.
            integration_name: None,
            provider,
            expose_call_count: std::sync::atomic::AtomicU64::new(0),
            secret_tier2_exposed: std::sync::atomic::AtomicBool::new(false),
            allow_tier2_exposure: false,
            global_expose_fallback,
            workflow_id: None,
            execution_id: None,
            module_id: None,
            user_id: None,
            state_store: Arc::new(std::sync::Mutex::new(HashMap::new())),
            redis_client,
            nats_client,
            audit_ledger: None,
            last_db_error: String::new(),
            oom_error_message: None,
            fs_dir,
            _ephemeral_dir: ephemeral_dir,
            max_memory_bytes,
            crypto_budget_us: AtomicU64::new(5_000_000), // 5 seconds default
            request_id: None,
            cancellation_token: None,
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            quota_usage: std::sync::Mutex::new(HashMap::new()),
            http_call_count: AtomicU64::new(0),
            http_calls_per_host: dashmap::DashMap::new(),
            db_query_count: AtomicU64::new(0),
            messaging_publish_count: AtomicU64::new(0),
            email_send_count: AtomicU64::new(0),
            webhook_send_count: AtomicU64::new(0),
            graphql_query_count: AtomicU64::new(0),
            secret_access_count: AtomicU64::new(0),
            fs_bytes_written: AtomicU64::new(0),
            log_message_count: AtomicU64::new(0),
            event_emit_count: AtomicU64::new(0),
            streams: StreamRegistry::new(),
            sse_connects_per_host: dashmap::DashMap::new(),
            // MCP-471: tighten the SSRF-redirect fallback. The
            // `redirect(Policy::none())` above closes the redirect-
            // pivot bypass for the worker's outbound HTTP / webhook /
            // GraphQL / http-stream surfaces. The previous fallback
            // `Client::new()` (no `.redirect()`) would silently
            // re-enable the default `Policy::limited(10)` redirect
            // following — exactly the gap we're trying to prevent.
            // `.build()` rarely fails (TLS init only); `Client::new()`
            // would panic on the same condition anyway, so the
            // fallback was effectively dead AND would have reopened
            // the SSRF gap if reached. `.expect()` surfaces a
            // deployment failure loudly at worker context creation
            // instead of silently degrading security posture.
            // MCP-1058 (2026-05-15): defense-in-depth `.connect_timeout()`
            // on the WIT host HTTP client. Per-call `wit_http::fetch` /
            // `wit_http::fetch_all` / `wit_webhook::send` set the
            // request-level `.timeout()` per invocation, but no
            // client-level cap on TCP+TLS handshake. A WASM module
            // calling out to a remote that accepts TCP but stalls TLS
            // (e.g. SSRF target hardened against TLS probes, or a
            // black-holed host) would otherwise consume the full
            // per-call timeout on the handshake alone. 5s matches the
            // workspace-canonical handshake budget.
            http_client,
            // MCP-937 (2026-05-15): filter empty-string env values so a
            // Helm-placeholder `S3_ENDPOINT=""` (or any of the three S3
            // creds) doesn't propagate `Some("")` into the
            // wit_object_storage host functions. Downstream consumers
            // use `.as_ref().ok_or(NotConfigured)` which succeeds on
            // `Some(&"")`, then `format!("{}/{}/{}", "", bucket, key)`
            // produces a relative URL → parse fails → operator sees a
            // confusing "Invalid S3 URL" log instead of the clean
            // "NotConfigured" surface the absent-config case was
            // designed to produce.
            //
            // s3_region also needs the filter — its `.or_else(|| Some(
            // "us-east-1"))` fallback was shadowed by `Some("")` (the
            // same chain class as MCP-934). With the filter, empty
            // S3_REGION falls through to the us-east-1 default.
            //
            // Same empty-env-var-bypass class as MCP-590..631 /
            // MCP-934 / MCP-935 / MCP-936.
            s3_endpoint: std::env::var("S3_ENDPOINT").ok().filter(|v| !v.is_empty()),
            s3_access_key: std::env::var("S3_ACCESS_KEY_ID")
                .ok()
                .filter(|v| !v.is_empty()),
            s3_secret_key: std::env::var("S3_SECRET_ACCESS_KEY")
                .ok()
                .filter(|v| !v.is_empty()),
            s3_region: std::env::var("S3_REGION")
                .ok()
                .filter(|v| !v.is_empty())
                .or_else(|| Some("us-east-1".to_string())),
            metrics: None,
            stderr_capture,
            dry_run: false,
            actor_id: None,
            // Stamped from the constructor arg so the SSRF resolver's
            // `local_egress_only` decision (built above) and the host-fn
            // tier gates agree on the same value from construction. Live
            // execution paths still re-assign `context.max_llm_tier` after
            // `new()` (a no-op since they pass the same value); legacy /
            // test paths that pass `LlmTier::default()` keep Tier-2.
            max_llm_tier,
        })
    }

    /// Read the bytes written to WASI stderr during this execution.
    /// Returns an empty string if nothing was captured (normal case).
    /// Non-UTF8 bytes are replaced with the Unicode replacement character.
    pub fn take_stderr_output(&self) -> String {
        let guard = self
            .stderr_capture
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        String::from_utf8_lossy(&guard).into_owned()
    }

    /// Set workflow context metadata for tracing and automatic logging.
    pub fn set_workflow_context(
        &mut self,
        workflow_id: String,
        execution_id: String,
        module_id: String,
    ) {
        self.workflow_id = Some(workflow_id);
        self.execution_id = Some(execution_id);
        self.module_id = Some(module_id);
    }

    /// Set an optional request identifier for end‑to‑end correlation.
    pub fn set_request_id(&mut self, request_id: String) {
        self.request_id = Some(request_id);
    }

    /// Set the user ID for global rate limiting and audit logging.
    pub fn set_user_id(&mut self, user_id: uuid::Uuid) {
        self.user_id = Some(user_id);
    }

    /// Override environment variables (from workflow / module configuration).
    pub fn set_env_vars(&mut self, vars: HashMap<String, String>) {
        self.env_vars = vars;
    }

    /// Build the module-scoped prefix for agent memory keys.
    /// Format: `mem:{module_id}:` — distinct from state keys (`{module_id}:`).
    pub fn memory_key_prefix(&self) -> String {
        match &self.module_id {
            Some(mid) => format!("mem:{}:", mid),
            None => "mem:_:".to_string(),
        }
    }

    /// Build a module-scoped agent memory key.
    pub fn scoped_memory_key(&self, key: &str) -> String {
        format!("{}{}", self.memory_key_prefix(), key)
    }

    /// Set per-module secret allowlist.  When non-empty, only secrets whose
    /// key matches an entry (or `"*"`) are served by `secrets::get-secret`.
    pub fn set_allowed_secrets(&mut self, allowed: Vec<String>) {
        self.allowed_secrets = allowed;
    }

    /// Allow or deny Tier-2 secret exposure for this module.
    pub fn set_allow_tier2_exposure(&mut self, allow: bool) {
        self.allow_tier2_exposure = allow;
    }

    /// Set per-module SQL operation allowlist.
    pub fn set_allowed_sql_operations(&mut self, allowed: Vec<String>) {
        self.allowed_sql_operations = allowed;
    }

    /// Enable dry-run mode: non-GET HTTP requests, webhook sends, and messaging
    /// publishes are mocked. GET requests still execute normally for data fetching.
    pub fn set_dry_run(&mut self, dry_run: bool) {
        self.dry_run = dry_run;
    }

    /// Attach OpenTelemetry runtime metrics so host functions can record
    /// rate-limit, approval, LLM, cancellation, and quota events.
    pub fn set_metrics(&mut self, metrics: Arc<crate::metrics::RuntimeMetrics>) {
        self.metrics = Some(metrics);
    }
}

// ============================================================================
// SAFETY NOTE
// ============================================================================
// `WasiCtx` and `ResourceTable` contain interior-mutability structures that
// are not `Sync`.  Talos guarantees each `TalosContext` is only ever accessed
// from a single thread at any point in time (one store per job execution).
// This impl must be revisited if concurrent access is ever introduced.
// unsafe impl Sync for TalosContext {}

// ============================================================================
// Resource limiter – enforced by Wasmtime to prevent exhaustion attacks
// ============================================================================
impl ResourceLimiter for TalosContext {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> std::result::Result<bool, wasmtime::Error> {
        tracing::debug!(
            current_kb = current / 1024,
            desired_kb = desired / 1024,
            limit_mb = self.max_memory_bytes / 1024 / 1024,
            "WASM memory growth requested"
        );
        if desired > self.max_memory_bytes {
            tracing::warn!(
                current_mb = current / 1024 / 1024,
                desired_mb = desired / 1024 / 1024,
                limit_mb = self.max_memory_bytes / 1024 / 1024,
                "WASM memory limit exceeded — denying allocation"
            );
            self.oom_error_message = Some(format!(
                "WASM module exceeded its {}MB memory limit (tried to allocate {}MB). Reduce result size or use pagination.",
                self.max_memory_bytes / 1024 / 1024,
                desired / 1024 / 1024
            ));
            return Ok(false);
        }
        Ok(true)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> std::result::Result<bool, wasmtime::Error> {
        const MAX_TABLE_SIZE: usize = 10_000;
        if desired > MAX_TABLE_SIZE {
            tracing::warn!(
                current,
                desired,
                MAX_TABLE_SIZE,
                "WASM table limit exceeded — denying allocation"
            );
            // Reuse the `oom_error_message` path so the trap-handling site in
            // `runtime.rs` surfaces an operator-actionable message instead of
            // a generic trap. Without this the guest aborts with no signal
            // about which resource limit was hit.
            self.oom_error_message = Some(format!(
                "WASM module exceeded its table-entry limit of {} (tried to grow to {}). \
                 This typically indicates an unbounded indirect-call or function-pointer \
                 table; refactor to reduce dispatch fan-out.",
                MAX_TABLE_SIZE, desired
            ));
            return Ok(false);
        }
        Ok(true)
    }
}

// Allow the context to be used as wasmtime component store data.
impl wasmtime::component::HasData for TalosContext {
    type Data<'a> = TalosContext;
}

impl wasmtime_wasi_http::p2::WasiHttpView for TalosContext {
    fn http(&mut self) -> wasmtime_wasi_http::p2::WasiHttpCtxView<'_> {
        wasmtime_wasi_http::p2::WasiHttpCtxView {
            ctx: &mut self.http_ctx,
            table: &mut self.table,
            // SECURITY (H2): default_hooks() is the UNFILTERED built-in
            // send_request (raw hyper/tokio, no SSRF/allowlist/tier-1 gate). It
            // is only ever reachable from a world that links
            // wasi:http/outgoing-handler, and as of the 2026-05-28 review that
            // is EXCLUSIVELY the trusted/automation linker (build_trusted_linker)
            // — non-trusted worlds (minimal/network/governance/secrets/cache/…)
            // register wasi:http/types ONLY via add_wasi_http_types_only, so the
            // handler is unavailable there (a component importing it fails to
            // link). Talos WASM nodes use talos:core/http for controlled HTTP
            // (host allowlist, rate limits, SSRF protection); trusted modules are
            // operator-authored and allowed unrestricted egress by design.
            hooks: wasmtime_wasi_http::p2::default_hooks(),
        }
    }
}

impl TalosContext {
    pub fn set_audit_ledger(
        &mut self,
        ledger: std::sync::Arc<tokio::sync::Mutex<crate::audit::ExecutionLedger>>,
    ) {
        self.audit_ledger = Some(ledger);
    }

    /// Records a capability denial to the cryptographic audit ledger and
    /// publishes it to the WORM stream (`talos.audit.ledger`).
    ///
    /// Every policy-driven refusal in the worker — HTTP host allowlist,
    /// HTTP method allowlist, Tier-1 LLM egress, secret allowlist,
    /// private-IP SSRF guard — calls this BEFORE returning the deny error
    /// to the guest. The append is hash-chained (SHA-256 over the previous
    /// row's hash plus length-prefixed fields) and HMAC-signed if
    /// `TALOS_AUDIT_SIGNING_KEY` is configured. The downstream subscriber
    /// in the controller persists the row to Postgres (append-only via
    /// `prevent_audit_modification` trigger) and to S3 / MinIO (optionally
    /// Object-Lock-Compliance gated by `TALOS_AUDIT_S3_OBJECT_LOCK`).
    ///
    /// Best-effort: a NATS publish failure does NOT change the deny
    /// outcome and the security event remains visible via tracing and the
    /// in-memory ledger row. The deny path itself is unconditional.
    ///
    /// SECURITY: never pass plaintext secret values, full vault paths, or
    /// URLs containing tokens through `target`. Hash secret-derived values
    /// first and pass only the host / path / hash.
    ///
    /// * `capability` — kebab-case kind: `http-fetch`, `http-method`,
    ///   `tier1-llm-egress`, `secret-access`, `vault-header`, `graphql`,
    ///   `webhook`, etc. Stable across releases — operator dashboards key
    ///   on this.
    /// * `policy` — which named policy fired: `allowed-hosts`,
    ///   `external-llm-hosts`, `private-ip`, `method-allowlist`,
    ///   `secret-allowlist`, etc. Pairs with `capability` to make the
    ///   reason machine-grep'able.
    /// * `target` — the attempted target as a non-secret string (host,
    ///   key-path SHA-256, sanitized URL).
    ///
    /// Takes `&mut self` (not `&self`) so the future is `Send` without
    /// requiring `TalosContext: Sync` — `WasiCtx` contains
    /// `dyn RngCore + Send` which is not `Sync`. Matches the existing
    /// inline-audit pattern at `host_impl.rs::secrets::get_secret`.
    pub async fn record_capability_denied(&mut self, capability: &str, policy: &str, target: &str) {
        let Some(ledger_mutex) = &self.audit_ledger else {
            return;
        };

        let payload = serde_json::json!({
            "capability": capability,
            "policy": policy,
            "target": target,
            "actor_id": self.actor_id.map(|u| u.to_string()),
            "module_id": self.module_id.as_deref(),
        })
        .to_string();

        let event = {
            let mut ledger = ledger_mutex.lock().await;
            ledger.append("worker", "wasi:capability_denied", &payload)
        };

        if let Some(n) = &self.nats_client {
            let nats = n.clone();
            // MCP-735 (2026-05-13): log NATS publish failures on the
            // audit-ledger replication path. Local `ledger.append`
            // above is the WORM source-of-truth (file-level
            // append-only), so a publish failure doesn't lose the
            // event — but SIEM/dashboard consumers watching the NATS
            // stream would silently see zero capability-deny events
            // during a NATS outage and conclude (incorrectly) that no
            // probes are happening. Same operational-visibility class
            // as MCP-733 (state-write SQL) and MCP-734 (state-write-
            // through publish) — fire-and-forget for the guest, but
            // operators need WARN-level visibility on systemic
            // failures.
            let capability_label = capability.to_string();
            tokio::spawn(async move {
                let hash = event.calculate_hash();
                let msg = serde_json::json!({
                    "event": event,
                    "hash": hash,
                });
                match serde_json::to_vec(&msg) {
                    Ok(bytes) => {
                        if let Err(e) = nats
                            .publish("talos.audit.ledger".to_string(), bytes.into())
                            .await
                        {
                            tracing::warn!(
                                target: "talos_rpc",
                                capability = %capability_label,
                                error = %e,
                                "audit-ledger NATS replication failed (capability_denied) — local ledger unaffected, SIEM stream will miss this event"
                            );
                        }
                    }
                    Err(e) => tracing::error!(
                        error = %e,
                        "Failed to serialize capability_denied audit event"
                    ),
                }
            });
        }
    }

    /// Build a module-scoped state key to isolate per-module state within a
    /// shared pipeline execution.  Format: `{module_id}:{key}`.
    pub fn scoped_state_key(&self, key: &str) -> String {
        match &self.module_id {
            Some(mid) => format!("{}:{}", mid, key),
            None => key.to_string(), // fallback for tests/unknown
        }
    }

    /// Check if this execution has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::Relaxed)
    }

    // ========================================================================
    // UNIFIED RESOURCE VALIDATION HELPERS
    // ========================================================================

    /// Validates that a JSON payload does not exceed the configured size limit.
    ///
    /// This is a unified helper used by all JSON-handling host functions to ensure
    /// consistent enforcement of payload size limits and prevent OOM attacks.
    ///
    /// # Arguments
    /// * `payload` - The JSON string to validate
    /// * `operation` - Name of the operation for logging (e.g., "json::parse")
    ///
    /// # Returns
    /// * `Ok(())` if the payload is within limits
    /// * `Err(limit)` where limit is the max size if exceeded
    pub fn validate_json_size(&self, payload: &str, operation: &str) -> Result<(), usize> {
        const DEFAULT_MAX_JSON: usize = 1024 * 1024; // 1 MiB default
                                                     // MCP-495: cache the env-driven cap on first use. Every JSON
                                                     // parse/serialize ran `std::env::var("WASM_MAX_JSON_SIZE")` —
                                                     // a Mutex<HashMap> lookup inside libstd — and re-parsed the
                                                     // string on every call. WASM_MAX_JSON_SIZE is set at process
                                                     // start and doesn't change at runtime; OnceLock locks it in.
                                                     //
                                                     // MCP-772 (2026-05-13): route through `nonzero_env_or_default`
                                                     // (sibling to MCP-639 which fixed the WASM_MAX_OUTPUT_BYTES /
                                                     // WASM_MAX_INPUT_BYTES variants). `WASM_MAX_JSON_SIZE=0`
                                                     // previously parsed as a valid value and produced
                                                     // `payload.len() > 0 → true` for any non-empty JSON, rejecting
                                                     // every parse/serialize at the boundary. Helper substitutes
                                                     // the default + emits a structured WARN at first use.
        use std::sync::OnceLock;
        static MAX_JSON: OnceLock<usize> = OnceLock::new();
        let max_json = *MAX_JSON.get_or_init(|| {
            crate::runtime::nonzero_env_or_default("WASM_MAX_JSON_SIZE", DEFAULT_MAX_JSON)
        });

        if payload.len() > max_json {
            tracing::warn!(
                operation = operation,
                size = payload.len(),
                limit = max_json,
                "JSON payload exceeds size limit"
            );
            return Err(max_json);
        }
        Ok(())
    }

    /// Consumes fuel to account for async host function execution time.
    ///
    /// This provides "async-aware" fuel consumption. While WASM fuel counts
    /// instructions executed inside the guest, async host functions (like HTTP
    /// requests) can run for a long time without executing guest instructions.
    ///
    /// This method converts elapsed wall time into an approximate fuel cost
    /// based on the assumption that ~1ms of wall time ≈ 10,000 instructions
    /// on a typical host. This prevents modules from making indefinite async
    /// calls to bypass fuel limits.
    ///
    /// # Arguments
    /// * `elapsed` - The elapsed wall time
    /// * `operation` - Name of the operation for logging
    ///
    /// # Returns
    /// The fuel cost computed from `elapsed`. Currently always succeeds —
    /// fuel-budget enforcement happens in the per-host-fn caller, this
    /// helper just standardizes the wall-time → fuel conversion.
    pub fn consume_async_fuel(&mut self, elapsed: std::time::Duration, operation: &str) -> u64 {
        // Approximate conversion: 1ms wall time ≈ 10,000 WASM instructions
        // This is a conservative estimate that prevents abuse while allowing
        // legitimate async operations.
        const FUEL_PER_MS: u64 = 10_000;
        let fuel_cost = (elapsed.as_millis() as u64).saturating_mul(FUEL_PER_MS);

        // Return the cost so the caller can account for it
        tracing::debug!(
            operation = operation,
            elapsed_ms = elapsed.as_millis(),
            fuel_cost = fuel_cost,
            "Consumed async fuel"
        );

        fuel_cost
    }

    /// Atomically check and consume crypto budget.
    ///
    /// This is an optimized variant of `deduct_crypto_budget` that checks if
    /// sufficient budget exists before deducting, preventing overdraft.
    ///
    /// # Arguments
    /// * `microseconds` - The amount of budget to consume
    ///
    /// # Returns
    /// * `true` if the budget was successfully deducted
    /// * `false` if insufficient budget exists
    pub fn try_deduct_crypto_budget(&self, microseconds: u64) -> bool {
        use std::sync::atomic::Ordering;
        loop {
            let current = self.crypto_budget_us.load(Ordering::Relaxed);
            if current < microseconds {
                return false;
            }
            let new_val = current - microseconds;
            match self.crypto_budget_us.compare_exchange(
                current,
                new_val,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(_) => continue, // CAS failed, retry
            }
        }
    }

    /// Mark this execution as cancelled.
    pub fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Check if a rate limit has been exceeded. Returns true if OK, false if exceeded.
    /// `limit` of 0 means unlimited.
    ///
    /// MCP-495: previously `fetch_add(1)` unconditionally — even when
    /// the call was already over-budget. A module hammering an
    /// exhausted limit pushed the counter arbitrarily high; consumers
    /// reading the counter for metrics / reporting saw inflated
    /// "attempts" instead of the actual call count. The CAS pattern
    /// here matches `try_deduct_crypto_budget` / `deduct_crypto_budget`
    /// in this same file: load → check → CAS-increment, retry on
    /// contention. The counter only advances when the call IS
    /// admitted, so its value is a faithful "calls allowed" tally.
    /// The batch-HTTP path at `host_impl.rs::fetch_all` had to roll
    /// back manually for the same reason — this helper now does
    /// the right thing inline.
    pub fn check_rate_limit(&self, counter: &AtomicU64, limit: u64) -> bool {
        if limit == 0 {
            return true;
        }
        use std::sync::atomic::Ordering;
        loop {
            let current = counter.load(Ordering::Relaxed);
            if current >= limit {
                return false;
            }
            match counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }

    /// M-6: atomic check-and-bump of the per-host HTTP counter.
    /// Returns `true` if the per-host budget for `host` still has
    /// headroom and the counter was incremented; `false` if the host
    /// is at `limit`.
    ///
    /// Hosts are lowercased at entry so `Example.com` and
    /// `example.com` share a slot. The `DashMap` entry API is
    /// linearizable per-key, so concurrent admissions from the same
    /// execution serialize correctly without an outer lock.
    pub fn check_per_host_rate_limit(&self, host: &str, limit: u64) -> bool {
        per_host_check_and_bump(&self.http_calls_per_host, host, limit)
    }

    /// L-finding-7: per-host CUMULATIVE SSE-connect check. Sibling to
    /// `check_per_host_rate_limit` but routes through the separate
    /// `sse_connects_per_host` map so the HTTP and SSE budgets do not
    /// share a counter (a chatty webhook poller shouldn't drain the
    /// SSE budget and vice versa). Same lower-cased `host:port` key
    /// normalisation, same lock-free DashMap update pattern.
    pub fn check_sse_per_host_rate_limit(&self, host: &str, limit: u64) -> bool {
        per_host_check_and_bump(&self.sse_connects_per_host, host, limit)
    }

    /// Atomically deduct `microseconds` from the crypto time budget.
    /// Returns `true` if budget remains, `false` if exhausted.
    pub fn deduct_crypto_budget(&self, microseconds: u64) -> bool {
        use std::sync::atomic::Ordering;
        loop {
            let current = self.crypto_budget_us.load(Ordering::Relaxed);
            if current == 0 {
                return false;
            }
            let new_val = current.saturating_sub(microseconds);
            match self.crypto_budget_us.compare_exchange(
                current,
                new_val,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return new_val > 0,
                Err(_) => continue, // CAS failed, retry
            }
        }
    }

    // Bulk state flush / load were part of the pre-Phase-2.3 durable-
    // state design (used `state_db_pool` directly from the worker).
    // With state writes now brokered through NATS via
    // `spawn_state_write_through`, there is no in-process DB pool on
    // the worker to flush to. Removed 2026-04-14.
}

// `flush_state_impl` and `load_state_impl` lived here pre-Phase-2.3
// to push state into `execution_state` from the worker directly.
// That path no longer exists — writes go through NATS-RPC
// (`spawn_state_write_through`) and reads are in-memory only during
// an execution. Deleted 2026-04-14.

/// Pure-function core of `TalosContext::check_per_host_rate_limit`,
/// extracted so the per-host rate-limit algorithm is unit-testable
/// without constructing a full TalosContext. Lowercases the host
/// (so case variants share a slot), short-circuits when limit == 0,
/// and uses the DashMap entry API for linearizable per-key updates.
pub(crate) fn per_host_check_and_bump(
    counts: &dashmap::DashMap<String, u64>,
    host: &str,
    limit: u64,
) -> bool {
    if limit == 0 {
        return true;
    }
    let key = host.to_ascii_lowercase();
    let mut entry = counts.entry(key).or_insert(0);
    if *entry >= limit {
        return false;
    }
    *entry += 1;
    true
}

#[cfg(test)]
mod fs_preopen_policy_tests {
    use super::capability_world_has_fs_preopen;
    use crate::wit_inspector::CapabilityWorld;

    #[test]
    fn only_filesystem_and_trusted_get_a_preopen() {
        assert!(capability_world_has_fs_preopen(
            &CapabilityWorld::Filesystem
        ));
        assert!(capability_world_has_fs_preopen(&CapabilityWorld::Trusted));
    }

    #[test]
    fn database_and_agent_get_no_preopen() {
        // The architectural change: Database/Agent no longer get a raw WASI
        // preopen (the read-only one was empty/unpopulated and its only guard
        // was bypassable WASI FilePerms — RUSTSEC-2026-0149). A regression
        // re-granting them a preopen must fail here.
        assert!(!capability_world_has_fs_preopen(&CapabilityWorld::Database));
        assert!(!capability_world_has_fs_preopen(&CapabilityWorld::Agent));
    }

    #[test]
    fn non_filesystem_worlds_get_no_preopen() {
        for w in [
            CapabilityWorld::Minimal,
            CapabilityWorld::Http,
            CapabilityWorld::Network,
            CapabilityWorld::Secrets,
            CapabilityWorld::Messaging,
            CapabilityWorld::Cache,
            CapabilityWorld::Governance,
            CapabilityWorld::Unknown,
        ] {
            assert!(
                !capability_world_has_fs_preopen(&w),
                "{w:?} must not get a filesystem preopen"
            );
        }
    }
}

#[cfg(test)]
mod per_host_rate_limit_tests {
    use super::per_host_check_and_bump;

    #[test]
    fn limit_zero_is_unlimited() {
        // limit == 0 means "no per-host cap" — match the global
        // check_rate_limit convention so 0-via-env or unset behaves
        // identically. The counter is NOT incremented in this path.
        let counts = dashmap::DashMap::new();
        for _ in 0..10_000 {
            assert!(per_host_check_and_bump(&counts, "example.com:443", 0));
        }
        assert!(
            counts.is_empty(),
            "counter must not be touched when limit=0"
        );
    }

    #[test]
    fn admits_up_to_limit_then_rejects() {
        let counts = dashmap::DashMap::new();
        for _ in 0..5 {
            assert!(per_host_check_and_bump(&counts, "a.example.com:443", 5));
        }
        // The 6th call must be rejected.
        assert!(!per_host_check_and_bump(&counts, "a.example.com:443", 5));
        // Counter does NOT advance past the limit.
        assert_eq!(*counts.get("a.example.com:443").unwrap(), 5);
    }

    #[test]
    fn different_hosts_have_independent_budgets() {
        let counts = dashmap::DashMap::new();
        for _ in 0..3 {
            assert!(per_host_check_and_bump(&counts, "a.com:443", 3));
        }
        // a.com is full but b.com still has its full budget.
        assert!(!per_host_check_and_bump(&counts, "a.com:443", 3));
        for _ in 0..3 {
            assert!(per_host_check_and_bump(&counts, "b.com:443", 3));
        }
        assert!(!per_host_check_and_bump(&counts, "b.com:443", 3));
    }

    #[test]
    fn case_insensitive_host_collision() {
        // Example.com and example.com share a budget — otherwise an
        // attacker could double their effective per-host budget by
        // alternating case.
        let counts = dashmap::DashMap::new();
        for _ in 0..2 {
            assert!(per_host_check_and_bump(&counts, "Example.com:443", 2));
        }
        // Third request — different case, same logical host.
        assert!(!per_host_check_and_bump(&counts, "example.com:443", 2));
        assert!(!per_host_check_and_bump(&counts, "EXAMPLE.COM:443", 2));
    }

    #[test]
    fn rejected_attempts_do_not_advance_counter() {
        // Once we're at the cap, subsequent rejected attempts must
        // not silently push the counter higher (would matter if we
        // ever exposed the counter for diagnostic purposes).
        let counts = dashmap::DashMap::new();
        for _ in 0..2 {
            assert!(per_host_check_and_bump(&counts, "a:80", 2));
        }
        for _ in 0..5 {
            assert!(!per_host_check_and_bump(&counts, "a:80", 2));
        }
        assert_eq!(*counts.get("a:80").unwrap(), 2);
    }
}
