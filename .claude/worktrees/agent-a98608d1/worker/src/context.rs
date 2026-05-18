#![allow(dead_code)]
use cap_std::fs::Dir;
use std::collections::HashMap;
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

    /// Workflow-scoped environment variables surfaced via the `env` interface.
    pub env_vars: HashMap<String, String>,
    pub capability_world: crate::wit_inspector::CapabilityWorld,

    /// Pre-fetched, decrypted secrets.  Populated from the encrypted `JobRequest`
    /// field or directly by the controller for in-process executions.
    /// The `secrets::get-secret` host function reads from this map.
    pub secrets: HashMap<String, String>,

    /// Workflow ID for tracing / logging.
    pub workflow_id: Option<String>,
    /// Execution ID for tracing / logging (also used as NATS log topic suffix).
    pub execution_id: Option<String>,
    /// Module ID for permissions and logging.
    pub module_id: Option<String>,
    /// Optional request identifier that ties together controller, worker and logs.
    pub request_id: Option<String>,

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

    /// Optional PostgreSQL connection pool for the `database` interface.
    pub db_pool: Option<sqlx::PgPool>,

    /// Keeps the ephemeral `TempDir` alive until this context is dropped.
    /// Dropping `_ephemeral_dir` removes the directory from the file system.
    _ephemeral_dir: TempDir,

    /// Maximum memory allowed for this execution (bytes).
    pub max_memory_bytes: usize,
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
    /// * `secrets` – pre-fetched, decrypted secret values.
    /// * `redis_client` – optional Redis connection.
    /// * `nats_client` – optional NATS connection.
    /// * `allow_wasi_network` – if `true`, grant `wasi:sockets` access so the
    ///   component can use `std::net::TcpStream` (WASIP2).
    ///   Only set this for `network-node` or `automation-node`
    ///   components; `minimal-node` components never need it.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        capability_world: crate::wit_inspector::CapabilityWorld,
        allowed_hosts: Vec<String>,
        allowed_methods: Vec<String>,
        max_memory_mb: usize,
        secrets: HashMap<String, String>,
        redis_client: Option<Arc<redis::Client>>,
        nats_client: Option<Arc<async_nats::Client>>,
        db_pool: Option<sqlx::PgPool>,
        allow_wasi_network: bool,
        token_sender: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
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
            builder.inherit_stdout();
        }
        builder.inherit_stderr();

        builder.preopened_dir(ephemeral_dir.path(), "/", DirPerms::all(), FilePerms::all())?;

        // Network access for wasi:sockets (WASIP2) — only granted when the
        // component's capability world includes outbound network I/O.
        // `inherit_network()` lets the guest use std::net::TcpStream et al.
        // The Talos `allowed_hosts` list still governs the HTTP host function;
        // raw TCP is gated here at the WasiCtx level.
        if allow_wasi_network {
            builder.inherit_network();
            builder.allow_ip_name_lookup(true);

            // SECURITY: Prevent Server-Side Request Forgery (SSRF)
            // Even though `talos:core/http::fetch` respects the `allowed_hosts` list,
            // raw WASI sockets bypass it entirely because they resolve directly to IPs.
            // To ensure the WASM sandbox cannot be used to scan internal network infrastructure,
            // we actively block connections to private, loopback, and link-local IP addresses.
            builder.socket_addr_check(|addr, _use| {
                Box::pin(async move {
                    let ip = addr.ip();

                    // Block loopback (127.0.0.0/8), unspecified (0.0.0.0), and multicast
                    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
                        tracing::warn!("SECURITY: Blocked WASI socket connection to loopback/multicast IP: {}", ip);
                        return false;
                    }

                    match ip {
                        std::net::IpAddr::V4(ipv4) => {
                            // Block RFC 1918 private networks (10.x, 172.16.x, 192.168.x)
                            // and RFC 3927 link-local networks (169.254.x.x - AWS Metadata)
                            if ipv4.is_private() || ipv4.is_link_local() || ipv4.is_broadcast() || ipv4.is_documentation() {
                                tracing::warn!("SECURITY: Blocked WASI socket connection to private/internal IP: {}", ipv4);
                                return false;
                            }
                        }
                        std::net::IpAddr::V6(ipv6) => {
                            // Block Unique Local Addresses (fc00::/7) which are the IPv6 equivalent of RFC 1918
                            if (ipv6.segments()[0] & 0xfe00) == 0xfc00 {
                                tracing::warn!("SECURITY: Blocked WASI socket connection to private IPv6: {}", ipv6);
                                return false;
                            }
                        }
                    }

                    // Allow public external internet connections
                    true
                })
            });
        }

        let wasi = builder.build();

        let table = ResourceTable::new();
        let max_memory_bytes = max_memory_mb * 1024 * 1024;
        let http_ctx = wasmtime_wasi_http::WasiHttpCtx::new();

        Ok(Self {
            wasi,
            table,
            http_ctx,
            allowed_hosts,
            allowed_methods,
            env_vars: HashMap::new(),
            capability_world,
            secrets,
            workflow_id: None,
            execution_id: None,
            module_id: None,
            state_store: Arc::new(std::sync::Mutex::new(HashMap::new())),
            redis_client,
            nats_client,
            audit_ledger: None,
            db_pool,
            fs_dir,
            _ephemeral_dir: ephemeral_dir,
            max_memory_bytes,
            request_id: None,
        })
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

    /// Override environment variables (from workflow / module configuration).
    pub fn set_env_vars(&mut self, vars: HashMap<String, String>) {
        self.env_vars = vars;
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
        if desired > self.max_memory_bytes {
            tracing::warn!(
                current_mb = current / 1024 / 1024,
                desired_mb = desired / 1024 / 1024,
                limit_mb = self.max_memory_bytes / 1024 / 1024,
                "WASM memory limit exceeded — denying allocation"
            );
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
            return Ok(false);
        }
        Ok(true)
    }
}

// Allow the context to be used as wasmtime component store data.
impl wasmtime::component::HasData for TalosContext {
    type Data<'a> = TalosContext;
}

impl wasmtime_wasi_http::WasiHttpView for TalosContext {
    fn ctx(&mut self) -> &mut wasmtime_wasi_http::WasiHttpCtx {
        &mut self.http_ctx
    }
    fn table(&mut self) -> &mut wasmtime::component::ResourceTable {
        &mut self.table
    }
}

impl TalosContext {
    pub fn set_audit_ledger(
        &mut self,
        ledger: std::sync::Arc<tokio::sync::Mutex<crate::audit::ExecutionLedger>>,
    ) {
        self.audit_ledger = Some(ledger);
    }
}
