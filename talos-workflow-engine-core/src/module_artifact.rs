//! Executor-facing shape of a compiled workflow module.
//!
//! [`WasmModuleArtifact`] is the minimal dispatch-ready view an engine needs
//! to ship a node to a worker: the wasm binary (or its URI), the
//! capability grants the worker must enforce, budgets, and integration
//! scope. It is deliberately **lean** — no compile-time metadata
//! (source language, imported WIT interfaces, size, name) and no
//! ownership bookkeeping (`user_id`, `template_id`) — because nothing in
//! the dispatch loop reads those. Consumer impls of [`ModuleFetcher`]
//! own that richer shape and project down to this type.
//!
//! # Why a crate-level type, not a re-export
//!
//! The engine trait boundary must not pull controller-specific types
//! (for example, a controller-side `WasmModule` might carry a
//! `worker::CapabilityWorld` enum from its runtime). Adapters flatten
//! those into the `String` fields here.

use serde_json::Value as JsonValue;
use uuid::Uuid;

/// Everything the executor needs to dispatch one module on one worker.
///
/// Fields are intentionally flat primitives + `Vec`s — no enums, no
/// `Arc<Box<dyn ...>>` — so adapters targeting any backing store (OCI,
/// filesystem, test map, Postgres-backed registry) can populate it
/// trivially.
///
/// # Debug
///
/// A manual [`std::fmt::Debug`] impl elides `wasm_bytes` (reports length
/// only) so tracing the artifact at dispatch sites is safe; inlined wasm
/// blobs are multi-MB and not useful in log output.
#[derive(Clone)]
pub struct WasmModuleArtifact {
    /// Fetcher-assigned module identity. The adapter and the engine
    /// cache key off this — a stable id across fetches of the same
    /// module means the engine's prefetch cache hits the next time
    /// the same node dispatches.
    pub module_id: Uuid,
    /// SHA-256 hex digest of `wasm_bytes`. The worker verifies a
    /// URI-fetched binary matches this digest before executing; skip
    /// when `wasm_bytes` is inline (HMAC on the job envelope already
    /// covers the bytes).
    pub content_hash: String,
    /// The wasm binary the worker runs. May be empty when the module
    /// is resolved via `oci_url` at dispatch time; the engine treats
    /// an empty vec as "fetch via URI" and populates
    /// [`DispatchJob::wasm_bytes`] accordingly.
    ///
    /// [`DispatchJob::wasm_bytes`]: crate::DispatchJob::wasm_bytes
    pub wasm_bytes: Vec<u8>,
    /// Optional URI the worker may fetch the binary from when
    /// `wasm_bytes` is empty (e.g. `oci://...` or a Redis blob key).
    pub oci_url: Option<String>,
    /// Wasmtime fuel budget for this module's dispatch. The engine
    /// may cap or override this per-node based on node-level config;
    /// this is the module-level default.
    pub max_fuel: u64,
    /// Opaque capability-world identifier (e.g. `"network-node"`,
    /// `"memory-node"`). The worker's linker decodes it; the engine
    /// just forwards. Flattened to a `String` here so adapters whose
    /// backing store uses a typed enum don't leak that type into the
    /// trait API.
    pub capability_world: String,
    /// Hostnames the worker permits outbound HTTP to.
    pub allowed_hosts: Vec<String>,
    /// HTTP methods the worker permits. Empty means allow all.
    pub allowed_methods: Vec<String>,
    /// Secret path allowlist. Empty = deny all; `["*"]` = allow all.
    pub allowed_secrets: Vec<String>,
    /// Operation types that require human approval before execution
    /// (e.g. `"send_email"`). The engine pauses the workflow when a
    /// dispatched module declares approvals still pending.
    pub requires_approval_for: Vec<String>,
    /// Integration this module is scoped to, if any. Forwarded in the
    /// dispatch so the worker signs `integration_state` RPCs with it.
    pub integration_name: Option<String>,
    /// Optional compile-time config blob. Some backing stores carry
    /// per-module defaults here; the engine merges with node-level
    /// config at dispatch time. Populating it is optional —
    /// `None` means "module declares no defaults".
    pub config: Option<JsonValue>,
}

impl std::fmt::Debug for WasmModuleArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmModuleArtifact")
            .field("module_id", &self.module_id)
            .field("content_hash", &self.content_hash)
            .field(
                "wasm_bytes",
                &format_args!("<{} bytes>", self.wasm_bytes.len()),
            )
            .field("oci_url", &self.oci_url)
            .field("max_fuel", &self.max_fuel)
            .field("capability_world", &self.capability_world)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("allowed_methods", &self.allowed_methods)
            .field("allowed_secrets", &self.allowed_secrets)
            .field("requires_approval_for", &self.requires_approval_for)
            .field("integration_name", &self.integration_name)
            .field("config", &self.config)
            .finish()
    }
}
