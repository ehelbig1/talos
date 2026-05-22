use anyhow::Result;
use dashmap::DashMap;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{
    Caller, Config, Engine, InstanceAllocationStrategy, PoolingAllocationConfig, Store,
};

use crate::context::TalosContext;
use crate::wit_inspector::CapabilityWorld;

/// M1 (2026-05-22): epoch-interruption ticker cadence. The background
/// task calls `engine.increment_epoch()` once per interval; per-Store
/// `set_epoch_deadline(N)` then trips after `N` ticks (so deadline_ms
/// granularity = `EPOCH_TICK_INTERVAL_MS`).
///
/// Trade-off: shorter interval = finer-grained interruption (catches
/// runaway sooner) but more atomic increments on the ticker thread.
/// 100 ms is the canonical wasmtime example for epoch interruption
/// and matches the wall-clock-timeout granularity operators expect.
pub const EPOCH_TICK_INTERVAL_MS: u64 = 100;

/// Convert a wall-clock duration into the equivalent number of epoch
/// ticks (rounded UP so we never trip the interrupt before the
/// wall-clock timeout would have fired). Returns at least 1 — a
/// deadline of 0 trips at the first WASM yield point, which would
/// match the pre-M1 disabled-epoch behaviour and defeat the gate.
///
/// Pure function so the rounding policy is unit-testable.
pub(crate) fn epoch_ticks_for_timeout(timeout: Duration) -> u64 {
    let ms = timeout.as_millis() as u64;
    let ticks = ms.div_ceil(EPOCH_TICK_INTERVAL_MS);
    ticks.max(1)
}

/// Spawn a background tokio task that increments the engine's epoch
/// counter every `EPOCH_TICK_INTERVAL_MS`. Returns a `JoinHandle` the
/// caller can keep (or drop — the task lives for the lifetime of the
/// process, but cancellation drops cleanly).
///
/// `Engine` clones are cheap (internal `Arc`) so the closure owns its
/// own handle without sharing with the runtime's primary engine.
pub fn spawn_epoch_ticker(engine: Engine) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(EPOCH_TICK_INTERVAL_MS));
        // Skip the first immediate tick so the engine epoch doesn't
        // tick at process startup before any deadlines are set.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            engine.increment_epoch();
        }
    })
}

#[cfg(test)]
mod epoch_helper_tests {
    use super::*;

    #[test]
    fn ticks_round_up_so_we_never_trip_early() {
        // 1 ms → 1 tick (round up from 0.01)
        assert_eq!(epoch_ticks_for_timeout(Duration::from_millis(1)), 1);
        // 100 ms → 1 tick exact
        assert_eq!(epoch_ticks_for_timeout(Duration::from_millis(100)), 1);
        // 101 ms → 2 ticks (round up)
        assert_eq!(epoch_ticks_for_timeout(Duration::from_millis(101)), 2);
        // 1 s → 10 ticks
        assert_eq!(epoch_ticks_for_timeout(Duration::from_secs(1)), 10);
        // 30 s → 300 ticks (default execution timeout)
        assert_eq!(epoch_ticks_for_timeout(Duration::from_secs(30)), 300);
        // 7 day Trusted/Governance ceiling → ~6M ticks, well within u64.
        let week = Duration::from_secs(7 * 24 * 60 * 60);
        assert_eq!(epoch_ticks_for_timeout(week), 6_048_000);
    }

    #[test]
    fn zero_timeout_clamps_to_one_tick() {
        // Defensive: a zero-duration timeout would otherwise produce a
        // deadline of 0 = current epoch, which trips at the first
        // yield point — exactly the pre-M1 behaviour we're closing.
        assert_eq!(epoch_ticks_for_timeout(Duration::ZERO), 1);
    }
}

/// Per-execution security policy carried from the controller.
/// Threaded through the runtime call chain and applied to `TalosContext`.
#[derive(Clone, Debug, Default)]
pub struct SecurityPolicy {
    /// Secret key allowlist.  Non-empty = only listed keys (or `"*"`) served.
    pub allowed_secrets: Vec<String>,
    /// SQL statement allowlist.  Non-empty = only listed types allowed.
    pub allowed_sql_operations: Vec<String>,
    /// When false (the default), the Tier-2 `expose_secret` host function
    /// returns `Unauthorized` without crossing any plaintext into WASM
    /// memory. Modules must opt in explicitly to receive raw secret
    /// values. This enforces the Tier-1-only guarantee for the vast
    /// majority of modules that only need vault:// header resolution
    /// or slot-based `fetch_with_header`.
    pub allow_tier2_exposure: bool,
    /// Integration this module belongs to, if any. Threaded through to
    /// TalosContext so the integration_state host functions know which
    /// namespace to scope writes to. None = the module is not an
    /// integration; integration_state calls return `unauthorized`.
    pub integration_name: Option<String>,
}
// ---------------------------------------------------------------------
// AOT versioning
// ---------------------------------------------------------------------
/// Header prefixed to every AOT‑compiled blob. Guarantees that the binary was
/// produced by the same Talos version and Wasmtime configuration.
///
/// IMPORTANT: Bump this any time the Engine configuration changes in a way that
/// makes serialized components incompatible (wasmtime major version, fuel cost
/// table, compilation flags, etc.).  Old blobs will be cleanly rejected with a
/// "version mismatch" error rather than a cryptic deserialize failure.
///
/// History:
///   TALOSV1 — wasmtime 41.0.3, uniform fuel cost
///   TALOSV2 — wasmtime 43.0.1, per-operator fuel costs, concurrency_support
///   TALOSV3 — M1 (2026-05-22): epoch_interruption enabled. AOT
///             artifacts encode the epoch-check instruction sequence,
///             so a TALOSV2 blob (compiled without epoch_interruption)
///             would skip the per-yield-point check at runtime and
///             defeat the gate. Bump rejects old blobs cleanly.
pub const AOT_VERSION_HDR: &[u8] = b"TALOSV3";
/// Number of bytes occupied by the HMAC-SHA256 integrity tag that immediately
/// follows the version header in every AOT blob.
const AOT_HMAC_LEN: usize = 32;

/// Holds signing and verification keys for AOT blob integrity.
///
/// Supports graceful key rotation: new blobs are signed with `signing_key`,
/// but verification accepts any key in `verification_keys` (which includes
/// the signing key and optionally previous keys).
///
/// ## Rotation Workflow
///
/// 1. Set `TALOS_AOT_HMAC_KEY=<new_key>` and `TALOS_AOT_HMAC_KEY_PREVIOUS=<old_key>`.
/// 2. Deploy. New blobs are signed with `new_key`. Old blobs verify via `old_key`.
/// 3. Over time, modules are recompiled, replacing old blobs.
/// 4. Once all old blobs are gone, remove `TALOS_AOT_HMAC_KEY_PREVIOUS`.
struct AotKeyRing {
    /// Current key used for signing new AOT blobs.
    signing_key: Vec<u8>,
    /// All keys that can verify blobs (signing_key is always first).
    verification_keys: Vec<Vec<u8>>,
}

/// Cached key ring to avoid re-reading env vars on each AOT operation.
static AOT_KEY_RING: std::sync::OnceLock<AotKeyRing> = std::sync::OnceLock::new();

/// Load the AOT key ring from environment variables.
///
/// Precedence:
///   1. `TALOS_AOT_HMAC_KEY` — the current signing key (required in production).
///   2. `TALOS_AOT_HMAC_KEY_PREVIOUS` — comma-separated list of previous keys
///      that are accepted for verification only (optional, for key rotation).
///   3. In dev/test: a cryptographically random ephemeral key per startup.
fn aot_key_ring() -> &'static AotKeyRing {
    AOT_KEY_RING.get_or_init(|| {
        // MCP-671: empty-string-safe production gate. Pre-fix
        // `RUST_ENV=""` made `is_prod = false`, so the panic-on-missing
        // / panic-on-short-key checks silently devolved to "use an
        // ephemeral random key" — the worker would start cleanly in
        // what the operator believes is production. AOT cache then
        // invalidates on every restart (different ephemeral key per
        // pod), masking the misconfig as a vague performance issue.
        let is_prod = talos_config::is_production();

        let signing_key = if let Ok(k) = std::env::var("TALOS_AOT_HMAC_KEY") {
            let key_bytes = k.into_bytes();
            if is_prod && key_bytes.len() < 32 {
                panic!(
                    "CRITICAL: TALOS_AOT_HMAC_KEY is only {} bytes — \
                     production requires at least 32 bytes for HMAC-SHA256 security.",
                    key_bytes.len()
                );
            }
            key_bytes
        } else if is_prod {
            panic!("CRITICAL: TALOS_AOT_HMAC_KEY must be set in production.");
        } else {
            use rand::RngCore;
            let mut key = vec![0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut key);
            tracing::warn!(
                "TALOS_AOT_HMAC_KEY is not set — using an ephemeral random key. \
                 Set TALOS_AOT_HMAC_KEY for stable AOT caching across restarts."
            );
            key
        };

        // Build verification key list: current key + any previous keys
        let mut verification_keys = vec![signing_key.clone()];

        if let Ok(prev) = std::env::var("TALOS_AOT_HMAC_KEY_PREVIOUS") {
            let prev_keys: Vec<Vec<u8>> = prev
                .split(',')
                .map(|k| k.trim().to_string().into_bytes())
                .filter(|k| !k.is_empty())
                .collect();
            let count = prev_keys.len();
            if count > 0 {
                tracing::info!(
                    previous_key_count = count,
                    "AOT key rotation active — accepting {} previous key(s) for verification",
                    count
                );
            }
            verification_keys.extend(prev_keys);
        }

        // L-5: structured fingerprint log of the AOT signing key (and
        // each verification key) at startup so an operator can grep
        // both worker logs across a fleet and confirm they agree.
        // Compromise of this key allows an attacker to forge
        // pre-deserialize blobs — i.e. arbitrary native code
        // execution via `Component::deserialize`. The 32-bit (8 hex
        // char) prefix is enough to detect drift; the full key
        // never leaves the process.
        {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            let mut mac = Hmac::<Sha256>::new_from_slice(&signing_key)
                .expect("HMAC-SHA256 accepts any key length");
            mac.update(b"talos-aot-key-fingerprint-v1");
            let tag = mac.finalize().into_bytes();
            let fp_short = hex::encode(&tag[..4]);
            tracing::info!(
                aot_signing_key_fp = %fp_short,
                verification_key_count = verification_keys.len(),
                "AOT HMAC key loaded; compare fingerprint across worker fleet for drift detection"
            );
        }

        AotKeyRing {
            signing_key,
            verification_keys,
        }
    })
}
/// Extract a clean panic message from WASI stderr output produced when a WASM module panics.
///
/// Handles both Rust panic message formats:
///
/// **Pre-1.73** (single-line, message in quotes):
/// ```text
/// thread '<unnamed>' panicked at 'explicit panic', src/lib.rs:10:5
/// ```
///
/// **1.73+** (two-line, location then message):
/// ```text
/// thread '<unnamed>' panicked at src/lib.rs:10:5:
/// explicit panic
/// ```
///
/// Returns `None` when the stderr doesn't contain either format (e.g. pure WASM
/// `unreachable` trap with no Rust panic overhead).  In that case callers fall
/// back to the raw trap error.
///
/// This is the **fallback** path used for traps that bypass `catch_unwind` (stack
/// overflow, `unreachable`, pre-compiled modules built with `panic = "abort"`).
/// Modules compiled with `panic = "unwind"` (the default for freshly compiled
/// sandbox modules) have their panics caught by the macro-injected `catch_unwind`
/// before they ever reach this code path.
fn extract_panic_message_from_stderr(stderr: &str) -> Option<String> {
    // Pre-1.73: panicked at 'MESSAGE', FILE:LINE:COL
    // Detect by the opening single-quote immediately after "panicked at ".
    if let Some(start) = stderr.find("panicked at '") {
        let after = &stderr[start + "panicked at '".len()..];
        // Closing delimiter is "', " — last single-quote before a comma.
        if let Some(end) = after.find("',") {
            let msg = after[..end].trim();
            if !msg.is_empty() {
                return Some(msg.to_string());
            }
        }
    }

    // 1.73+: panicked at FILE:LINE:COL:\nMESSAGE
    // "panicked at " is NOT followed by a single-quote.
    if let Some(start) = stderr.find("panicked at ") {
        let after = &stderr[start + "panicked at ".len()..];
        // Skip if this is actually the old format (starts with quote).
        if !after.starts_with('\'') {
            if let Some(newline) = after.find('\n') {
                // Collect message lines until the first note:/backtrace: annotation.
                let msg = after[newline + 1..]
                    .lines()
                    .take_while(|l| {
                        let t = l.trim_start();
                        !t.starts_with("note:") && !t.starts_with("stack backtrace:")
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                let msg = msg.trim();
                if !msg.is_empty() {
                    return Some(msg.to_string());
                }
            }
        }
    }

    None
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

    /// Calculate backoff duration for attempt number with jitter.
    ///
    /// Jitter adds randomness (±25%) to the backoff to prevent thundering herd
    /// problems when multiple modules retry simultaneously after a transient failure.
    /// The formula is: base_backoff * (0.75 + random(0..0.5))
    pub fn backoff_for_attempt(&self, attempt: u32) -> Duration {
        // Cap exponent to prevent f32 overflow on high attempt counts.
        let capped_attempt = attempt.min(20) as i32;
        let backoff_ms =
            self.initial_backoff.as_millis() as f32 * self.backoff_multiplier.powi(capped_attempt);
        let backoff = Duration::from_millis(backoff_ms as u64);
        let base_backoff = backoff.min(self.max_backoff);

        // Add jitter: ±25% of the calculated backoff
        let jitter_factor = 0.75 + rand::random::<f32>() * 0.5;
        let jittered_ms = (base_backoff.as_millis() as f32 * jitter_factor) as u64;

        Duration::from_millis(jittered_ms.min(self.max_backoff.as_millis() as u64))
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

/// Build a short, control-character-safe preview of a module's stdout
/// for inclusion in error messages. Empty bodies render as `<empty>` so
/// the "LLM returned nothing" case is distinguishable from "returned
/// non-JSON". Long bodies are head/tail-clipped to keep the message
/// under ~500 chars even when stdout is megabytes.
fn preview_for_error(s: &str) -> String {
    if s.is_empty() {
        return "<empty>".to_string();
    }
    const HEAD: usize = 200;
    const TAIL: usize = 80;
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                '·'
            } else {
                c
            }
        })
        .collect();
    let raw = if cleaned.chars().count() <= HEAD + TAIL + 16 {
        cleaned
    } else {
        let head: String = cleaned.chars().take(HEAD).collect();
        let tail: String = cleaned
            .chars()
            .rev()
            .take(TAIL)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        format!("{}…[{} chars]…{}", head, s.len() - HEAD - TAIL, tail)
    };
    format!("{:?}", raw)
}

/// Build a user-actionable breakdown of an oversized job input.
///
/// Called from the input size cap check to point operators at the *upstream
/// node* whose output blew the budget — without this, the error names the
/// consuming node and operators reach for the wrong knob (real symptom hit
/// during watch-ghas validation 2026-04-30: a 530KB HTML body JSON-encoded
/// to 1.1MB and the error blamed `extract_text` when the fix was
/// `MAX_RESPONSE_BYTES` on the producing `fetch` node).
///
/// Reports key NAMES + serialized SIZES only — never values — so a payload
/// containing decrypted secrets (post-resolve `vault://` headers, etc.)
/// can't leak through a public-facing error path. Pure function for unit
/// testing; runs only on the failure path so the per-key serialize cost
/// is acceptable.
fn describe_oversized_input(input: &JsonValue) -> String {
    const TOP_N: usize = 5;
    const REMEDIATION_HINT_THRESHOLD: usize = 100_000;

    let Some(obj) = input.as_object() else {
        return "(input is not a JSON object — no per-key breakdown available)".to_string();
    };

    // Engine wraps multi-parent inputs as `__accumulated__.<source_id>.<...>`.
    // When present, that's where the size almost always lives — surface it
    // first so the operator sees per-upstream attribution at a glance.
    if let Some(JsonValue::Object(acc)) = obj.get("__accumulated__") {
        let mut sources: Vec<(String, usize)> = acc
            .iter()
            .map(|(k, v)| {
                let size = serde_json::to_vec(v).map(|b| b.len()).unwrap_or(0);
                (k.clone(), size)
            })
            .collect();
        sources.sort_by_key(|(_, size)| std::cmp::Reverse(*size));

        let mut lines = Vec::with_capacity(sources.len().min(TOP_N) + 3);
        lines.push("Upstream node outputs (largest first):".to_string());
        for (name, size) in sources.iter().take(TOP_N) {
            lines.push(format!("  - {}: {} bytes", name, size));
        }
        if let Some((top_name, top_size)) = sources.first() {
            if *top_size > REMEDIATION_HINT_THRESHOLD {
                lines.push(format!(
                    "Reduce '{}' output. For HTTP fetches, set MAX_RESPONSE_BYTES on the producing \
                     node (HTML→JSON inflates ~2× — try ~450000 for typical HTML pages, ~700000 \
                     for JSON-heavy responses).",
                    top_name
                ));
            }
        }
        return lines.join("\n");
    }

    // Fallback: no accumulated wrapper (e.g. trigger-only or single-parent
    // direct input). Surface top-level key sizes instead.
    let mut keys: Vec<(String, usize)> = obj
        .iter()
        .map(|(k, v)| {
            let size = serde_json::to_vec(v).map(|b| b.len()).unwrap_or(0);
            (k.clone(), size)
        })
        .collect();
    keys.sort_by_key(|(_, size)| std::cmp::Reverse(*size));

    let mut lines = Vec::with_capacity(keys.len().min(TOP_N) + 1);
    lines.push("Input top-level keys (largest first):".to_string());
    for (name, size) in keys.iter().take(TOP_N) {
        lines.push(format!("  - {}: {} bytes", name, size));
    }
    lines.join("\n")
}

/// MCP-639 (2026-05-13): read a numeric env var, treating both
/// missing and `=0` as "use default". Many of the worker's runtime
/// caps (fuel limit, max input/output bytes) have a fail-mode where
/// `=0` produces a tokio semaphore / byte cap that rejects everything,
/// silently breaking all WASM execution. Operators typically intend
/// `=0` to mean "unlimited" (common UNIX convention) but the worker's
/// downstream semantics give the opposite. Substituting the default +
/// WARN makes the misconfiguration visible while keeping the system
/// operational. Sibling to MCP-638 (semaphore clamp).
///
/// Generic over `T: FromStr + PartialOrd + Display + Copy`. Current
/// callers are all unsigned (`u64`, `usize`); MCP-698 (2026-05-13)
/// widened the bound from `PartialEq` to `PartialOrd` and replaced
/// `== T::default()` with `<= T::default()` so any future signed-type
/// caller (`i32`, `i64`) gets the negative-value substitute-and-WARN
/// behaviour, mirroring `talos_config::positive_env_or_default`.
/// Without this, `WASM_FUEL_LIMIT=-1` (parsed as i64) would slip
/// through the `!= 0` check and produce destructive negative downstream
/// arithmetic on the first caller that wires a signed type.
pub(crate) fn nonzero_env_or_default<T>(var: &str, default: T) -> T
where
    T: std::str::FromStr + std::fmt::Display + Default + PartialOrd + Copy,
{
    let parsed = std::env::var(var).ok().and_then(|v| v.parse::<T>().ok());
    match parsed {
        Some(n) if n <= T::default() => {
            tracing::warn!(
                target: "talos_runtime",
                event_kind = "wasm_env_nonpositive_substituted",
                var = var,
                configured = %n,
                default = %default,
                "{var}={n} is a misconfiguration (would block every WASM execution); using default {default}"
            );
            default
        }
        Some(n) => n,
        None => default,
    }
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
    /// Per-module security policy for this pipeline step.
    pub security_policy: SecurityPolicy,
    /// User ID for global rate limiting and audit logging.
    pub user_id: Option<uuid::Uuid>,
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
    /// Agent-tier linker: secrets + LLM + agent-memory + governance + agent-orchestration.
    agent_linker: Linker<TalosContext>,
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

    /// Uses DashMap for lock-free concurrent access.
    minimal_cache: Arc<DashMap<[u8; 32], wasmtime::component::InstancePre<TalosContext>>>,
    /// Pre-instantiation cache for network-tier components.

    /// Uses DashMap for lock-free concurrent access.
    network_cache: Arc<DashMap<[u8; 32], wasmtime::component::InstancePre<TalosContext>>>,
    /// Pre-instantiation cache for secrets-tier components.

    /// Uses DashMap for lock-free concurrent access.
    secrets_cache: Arc<DashMap<[u8; 32], wasmtime::component::InstancePre<TalosContext>>>,
    /// Pre-instantiation cache for filesystem-tier components.

    /// Uses DashMap for lock-free concurrent access.
    filesystem_cache: Arc<DashMap<[u8; 32], wasmtime::component::InstancePre<TalosContext>>>,
    /// Pre-instantiation cache for messaging-tier components.

    /// Uses DashMap for lock-free concurrent access.
    messaging_cache: Arc<DashMap<[u8; 32], wasmtime::component::InstancePre<TalosContext>>>,
    /// Pre-instantiation cache for cache-tier (Redis) components.

    /// Uses DashMap for lock-free concurrent access.
    cache_node_cache: Arc<DashMap<[u8; 32], wasmtime::component::InstancePre<TalosContext>>>,
    /// Pre-instantiation cache for database-tier components.

    /// Uses DashMap for lock-free concurrent access.
    database_cache: Arc<DashMap<[u8; 32], wasmtime::component::InstancePre<TalosContext>>>,
    /// Pre-instantiation cache for governance-tier components.
    /// Uses DashMap for lock-free concurrent access.
    governance_cache: Arc<DashMap<[u8; 32], wasmtime::component::InstancePre<TalosContext>>>,
    /// Pre-instantiation cache for agent-tier components.
    /// Uses DashMap for lock-free concurrent access.
    agent_cache: Arc<DashMap<[u8; 32], wasmtime::component::InstancePre<TalosContext>>>,
    /// Pre-instantiation cache for trusted-tier (automation-node) components.

    /// Uses DashMap for lock-free concurrent access.
    trusted_cache: Arc<DashMap<[u8; 32], wasmtime::component::InstancePre<TalosContext>>>,

    /// Redis client for distributed caching (optional)
    redis_client: Option<Arc<redis::Client>>,
    /// In‑process result cache (fast path before Redis).
    ///
    /// Uses `DashMap` for lock-free concurrent reads (no write lock needed).
    /// Each entry stores `(value, expires_at)` so reads can fail-stale and
    /// fall through to Redis (MCP-1092). Capacity eviction picks the entry
    /// closest to expiring. Capacity is configurable via
    /// `WASM_RESULT_CACHE_CAPACITY` (default 256).
    in_memory_result_cache: Arc<DashMap<String, (JsonValue, std::time::Instant)>>,
    /// Maximum number of entries in the in-process result cache.
    result_cache_capacity: usize,
    /// NATS client for message queue (optional)
    nats_client: Option<Arc<async_nats::Client>>,
    /// Sandboxed file system directory (optional)
    fs_dir: Option<Arc<cap_std::fs::Dir>>,
    /// Runtime metrics for health checks and observability
    active_executions: Arc<AtomicU32>,
    total_executions: Arc<AtomicU64>,
    /// Fuel limit for each execution (instructions). Default 10_000_000.
    fuel_limit: u64,
    /// Maximum entries per tier in the InstancePre cache.  When a tier exceeds
    /// this limit, the oldest entries are evicted on insert.
    /// Configurable via WASM_INSTANCE_CACHE_MAX_PER_TIER (default 256).
    instance_cache_max_per_tier: usize,
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
    /// Per-user in-memory fallback for the Tier-2 `expose_secret` daily
    /// cap. Shared across ALL executions in this worker process via
    /// `Arc<ExposeFallback>` — see [`crate::expose_fallback`] for the
    /// M-2 tenant-isolation rationale.
    global_expose_fallback: Arc<crate::expose_fallback::ExposeFallback>,
}

// ── Linker builders ──────────────────────────────────────────────────────────

/// Build the minimal-tier linker: WASI + logging + json + datetime + crypto + env.
fn build_minimal_linker(engine: &Engine) -> Result<Linker<TalosContext>> {
    let mut l = Linker::new(engine);

    wasmtime_wasi::p2::add_to_linker_async(&mut l)?;
    wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut l)?;
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
    wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut l)?;
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
    // Events + HTTP streaming available from http-node upward.
    crate::bindings::talos::core::events::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    crate::bindings::talos::core::http_stream::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
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
    wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut l)?;
    crate::bindings::AutomationNode::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |ctx| ctx,
    )?;

    Ok(l)
}

/// Build the secrets-tier linker: network interfaces + secrets vault + LLM APIs.
fn build_secrets_linker(engine: &Engine) -> Result<Linker<TalosContext>> {
    let mut l = build_network_linker(engine)?;
    crate::bindings::talos::core::secrets::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    // LLM interfaces (part of secrets-node world in WIT)
    crate::bindings::talos::core::llm::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    crate::bindings::talos::core::llm_tools::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    crate::bindings::talos::core::llm_streaming::add_to_linker::<
        TalosContext,
        HasSelf<TalosContext>,
    >(&mut l, |c| c)?;
    crate::bindings::talos::core::context_window::add_to_linker::<
        TalosContext,
        HasSelf<TalosContext>,
    >(&mut l, |c| c)?;
    crate::bindings::talos::core::resource_quotas::add_to_linker::<
        TalosContext,
        HasSelf<TalosContext>,
    >(&mut l, |c| c)?;
    // Embedding (uses OpenAI API key — same secrets tier as LLM)
    crate::bindings::talos::core::embedding::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
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
    // Database tier extends secrets tier (includes LLM)
    let mut l = build_secrets_linker(engine)?;
    crate::bindings::talos::core::database::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    Ok(l)
}

/// Build the agent-tier linker: secrets + LLM + agent-memory + governance + agent-orchestration.
///
/// This provides the agentic workflow capability set without database, filesystem, cache,
/// messaging, or object-storage access — the least-privilege world for autonomous agents.
fn build_agent_linker(engine: &Engine) -> Result<Linker<TalosContext>> {
    let mut l = build_secrets_linker(engine)?;
    crate::bindings::talos::core::agent_memory::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    crate::bindings::talos::core::graph_memory::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    crate::bindings::talos::core::integration_state::add_to_linker::<
        TalosContext,
        HasSelf<TalosContext>,
    >(&mut l, |c| c)?;
    crate::bindings::talos::core::governance::add_to_linker::<TalosContext, HasSelf<TalosContext>>(
        &mut l,
        |c| c,
    )?;
    crate::bindings::talos::core::agent_orchestration::add_to_linker::<
        TalosContext,
        HasSelf<TalosContext>,
    >(&mut l, |c| c)?;
    Ok(l)
}

#[allow(dead_code)]
impl TalosRuntime {
    /// Generate cache key for result caching.
    ///
    /// Format: `wasm:result:{module_hash}:{context_hash}`
    ///
    /// The context hash covers input JSON + execution context (workflow_id,
    /// execution_id, module_id) to prevent multi-tenant cache leakage.
    /// Different users running the same module with the same input but different
    /// secrets or actor contexts will get different cache keys because
    /// execution_context differs per-invocation.
    fn result_cache_key(
        module_hash: &str,
        input: &JsonValue,
        execution_context: Option<&(String, String, String)>,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.to_string().as_bytes());
        // Include execution context in cache key for tenant isolation.
        // execution_context contains (workflow_id, execution_id, module_id),
        // which ties the cache entry to a specific workflow invocation.
        if let Some((wf_id, _exec_id, mod_id)) = execution_context {
            hasher.update(wf_id.as_bytes());
            hasher.update(mod_id.as_bytes());
            // Intentionally omit execution_id — it changes every run and would
            // defeat caching entirely. workflow_id + module_id provides the
            // tenant isolation needed.
        }
        let context_hash = hex::encode(hasher.finalize().as_slice());
        format!("wasm:result:{}:{}", module_hash, context_hash)
    }

    /// Try to get cached result from in-process cache, then Redis.
    ///
    /// The in-process cache uses `DashMap` for lock-free reads — no write lock
    /// contention even under high concurrency (unlike `RwLock<LruCache>` which
    /// requires a write lock on every `.get()` to update LRU ordering).
    ///
    /// MCP-1092 (2026-05-16): in-memory entries store `expires_at`; a stale
    /// hit returns None (and is lazily evicted) so the caller falls through
    /// to Redis. Pre-fix the second tuple field was `insert_time` used only
    /// for capacity eviction, so the in-memory layer happily served entries
    /// long past their declared `ttl_secs` — a module configured for 60-s
    /// caching got the same answer for hours until capacity-eviction kicked
    /// in. Redis already enforced TTL via SETEX, but the in-memory layer
    /// is checked first, so it "wins" over the expiring Redis entry.
    async fn get_cached_result(&self, cache_key: &str) -> Option<JsonValue> {
        // Fast in-process lookup (lock-free via DashMap).
        if let Some(entry) = self.in_memory_result_cache.get(cache_key) {
            let (value, expires_at) = entry.value();
            if std::time::Instant::now() < *expires_at {
                return Some(value.clone());
            }
            // Drop the read guard before the write-side remove to avoid
            // self-deadlock on the same shard.
            drop(entry);
            self.in_memory_result_cache.remove(cache_key);
        }
        // Fall back to Redis if configured.
        if let Some(redis) = &self.redis_client {
            if let Ok(mut conn) = redis.get_multiplexed_async_connection().await {
                use redis::AsyncCommands;
                if let Ok(cached_str) = conn.get::<_, String>(cache_key).await {
                    if let Ok(cached_json) = serde_json::from_str::<JsonValue>(&cached_str) {
                        // Populate in-process cache for future fast reads.
                        // Pull the remaining Redis TTL so the in-memory entry
                        // can't outlive the canonical Redis copy. Fall back to
                        // a conservative 60-s window if TTL lookup fails.
                        let ttl_secs = conn
                            .ttl::<_, i64>(cache_key)
                            .await
                            .ok()
                            .filter(|t| *t > 0)
                            .map(|t| t as u64)
                            .unwrap_or(60);
                        self.insert_to_cache(cache_key.to_string(), cached_json.clone(), ttl_secs);
                        return Some(cached_json);
                    }
                }
            }
        }
        None
    }

    /// Insert a result into the in-process cache with capacity-based eviction.
    ///
    /// MCP-1092: the second tuple field is now `expires_at` (insert_time +
    /// `ttl_secs`). Reads check freshness; capacity eviction picks the entry
    /// closest to expiring (which approximates the prior oldest-insert-first
    /// policy when TTLs are similar, while avoiding the worse outcome of
    /// evicting a fresher entry to retain a stale one).
    fn insert_to_cache(&self, key: String, value: JsonValue, ttl_secs: u64) {
        let expires_at = std::time::Instant::now() + std::time::Duration::from_secs(ttl_secs);
        self.in_memory_result_cache.insert(key, (value, expires_at));

        // Evict entries closest to expiry first if over capacity.
        while self.in_memory_result_cache.len() > self.result_cache_capacity {
            let earliest_key = self
                .in_memory_result_cache
                .iter()
                .min_by_key(|entry| entry.value().1)
                .map(|entry| entry.key().clone());
            if let Some(k) = earliest_key {
                self.in_memory_result_cache.remove(&k);
            } else {
                break;
            }
        }
    }

    /// Store result in both in-process cache and Redis (with TTL).
    async fn cache_result(&self, cache_key: &str, result: &JsonValue, ttl_secs: u64) {
        self.insert_to_cache(cache_key.to_string(), result.clone(), ttl_secs);
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

    /// Insert an InstancePre into a tier cache with bounded eviction.
    ///
    /// When the cache exceeds `instance_cache_max_per_tier`, ~25% of entries
    /// are removed (random eviction via DashMap iteration order).  This amortizes
    /// eviction cost: one O(n) scan per 25% growth instead of one per insert.
    fn cache_insert_instance_pre(
        &self,
        cache: &DashMap<[u8; 32], wasmtime::component::InstancePre<TalosContext>>,
        key: [u8; 32],
        value: wasmtime::component::InstancePre<TalosContext>,
    ) {
        cache.insert(key, value);

        if cache.len() > self.instance_cache_max_per_tier {
            let evict_count = self.instance_cache_max_per_tier / 4;
            let keys_to_evict: Vec<[u8; 32]> = cache
                .iter()
                .take(evict_count)
                .map(|entry| *entry.key())
                .collect();
            for k in keys_to_evict {
                cache.remove(&k);
            }
            tracing::info!(
                cache_size = cache.len(),
                evicted = evict_count,
                max = self.instance_cache_max_per_tier,
                "InstancePre cache eviction"
            );
        }
    }

    /// Select the linker and InstancePre cache for a given capability world.
    #[allow(clippy::type_complexity)]
    fn select_tier(
        &self,
        cap: &CapabilityWorld,
    ) -> Result<(
        &Linker<TalosContext>,
        &Arc<DashMap<[u8; 32], wasmtime::component::InstancePre<TalosContext>>>,
    )> {
        match *cap {
            CapabilityWorld::Minimal => Ok((&self.minimal_linker, &self.minimal_cache)),
            // Http and Network share the same linker because wasmtime_wasi::p2 doesn't
            // support granular per-interface linking. WASI socket access is instead gated
            // at the context level: allow_wasi_network=false for Http, true for Network.
            // This is defense-in-depth: the WIT inspector rejects Http modules that import
            // wasi:sockets, and even if they somehow linked, the context blocks connections.
            CapabilityWorld::Http => Ok((&self.network_linker, &self.network_cache)),
            CapabilityWorld::Network => Ok((&self.network_linker, &self.network_cache)),
            CapabilityWorld::Secrets => Ok((&self.secrets_linker, &self.secrets_cache)),
            CapabilityWorld::Filesystem => Ok((&self.filesystem_linker, &self.filesystem_cache)),
            CapabilityWorld::Messaging => Ok((&self.messaging_linker, &self.messaging_cache)),
            CapabilityWorld::Cache => Ok((&self.cache_node_linker, &self.cache_node_cache)),
            CapabilityWorld::Database => Ok((&self.database_linker, &self.database_cache)),
            CapabilityWorld::Governance => Ok((&self.governance_linker, &self.governance_cache)),
            CapabilityWorld::Agent => Ok((&self.agent_linker, &self.agent_cache)),
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

    /// M1 (2026-05-22): expose the engine handle so callers (worker
    /// `main`) can start the background epoch-ticker via
    /// `spawn_epoch_ticker`. `Engine` is cheap to clone (internal
    /// `Arc`); cloning gives the ticker an independent handle without
    /// borrowing through the runtime.
    pub fn engine_handle(&self) -> Engine {
        self.engine.clone()
    }

    pub fn new() -> Result<Self> {
        Self::with_resources(None, None, None)
    }

    /// Construct a new runtime with optional external resources.
    /// This enables advanced capabilities for WASM modules:
    /// - Redis client for distributed caching
    /// - NATS client for message queues
    /// - Sandboxed directory for file I/O
    pub fn with_resources(
        redis_client: Option<Arc<redis::Client>>,
        nats_client: Option<Arc<async_nats::Client>>,
        fs_dir: Option<Arc<cap_std::fs::Dir>>,
    ) -> Result<Self> {
        let mut config = Config::new();

        // ── Async / Concurrency ─────────────────────────────────────────────
        // In wasmtime ≥42 `Config::async_support` was removed.
        // `concurrency_support(true)` enables fiber stacks for call_async /
        // instantiate_async (same runtime semantics as the old async_support).
        config.concurrency_support(true);

        // ── Debug / Backtrace ───────────────────────────────────────────────
        // In dev/test: enable full backtrace details and DWARF debug info so trap
        // diagnostics (function names, source locations) are available in logs.
        // In production: disable both — DWARF debug info costs ~2-3x JIT memory per
        // function and backtrace details add overhead on every trap path.
        // MCP-671: empty-string-safe production gate (wasmtime debug-info
        // memory-overhead reduction in real production).
        let is_production = talos_config::is_production();
        config.wasm_backtrace_details(if is_production {
            wasmtime::WasmBacktraceDetails::Disable
        } else {
            wasmtime::WasmBacktraceDetails::Enable
        });
        config.debug_info(!is_production);

        // Limit backtrace depth in production to avoid unbounded diagnostic overhead
        // on deeply nested trap paths.  In dev we capture all frames.
        if is_production {
            config.wasm_backtrace_max_frames(Some(std::num::NonZeroUsize::new(16).unwrap()));
        }

        // ── Fuel (instruction-level metering) ───────────────────────────────
        config.consume_fuel(true);

        // Per-operator fuel costs (wasmtime ≥43).
        // Default is 1 fuel per operator.  Charge more for memory-heavy ops so the
        // 10M fuel budget better reflects real resource consumption.
        // OperatorCost fields are u8 (0–255); default is 1 for most ops.
        let op_cost = wasmtime::OperatorCost {
            MemoryGrow: 255, // 64 KiB page alloc — most expensive
            TableGrow: 128,  // funcref table growth
            MemoryFill: 5,   // bulk memory fill
            MemoryCopy: 5,   // bulk memory copy
            ..wasmtime::OperatorCost::default()
        };
        config.operator_cost(op_cost);

        config.wasm_component_model(true);

        // ── WASM proposal lockdown (H2) ──────────────────────────────────────
        // Explicit opt-out of every WASM proposal Talos's component-model
        // workload doesn't need. Each enabled proposal is additional
        // attack surface in the codegen pipeline (Cranelift); historical
        // wasmtime CVEs have repeatedly landed in SIMD lowering, GC, and
        // the bulk-memory codegen. Keep ONLY what the component model
        // strictly requires:
        //   - bulk_memory: required by component-model lowering (memory.copy/fill)
        //   - reference_types: required by component-model lowering (externref/funcref)
        // Everything else is explicitly disabled. If a future Talos
        // module legitimately needs SIMD or threads, flip the relevant
        // line WITH a justification comment — the default must stay off.
        //
        // Pinning these makes the policy explicit regardless of upstream
        // default changes between wasmtime point releases.
        config.wasm_threads(false);
        config.wasm_simd(false);
        config.wasm_relaxed_simd(false);
        config.wasm_multi_memory(false);
        config.wasm_memory64(false);
        config.wasm_gc(false);
        config.wasm_function_references(false);
        config.wasm_tail_call(false);
        config.wasm_bulk_memory(true);
        config.wasm_reference_types(true);

        // M1 (2026-05-22): epoch interruption enabled as a third
        // independent kill switch alongside fuel + wall-clock timeout.
        //
        // How the three interlock:
        //   1. consume_fuel        — bounds total CPU work (per-op
        //                            cost × ops). Trips on tight
        //                            in-WASM loops.
        //   2. tokio::time::timeout — wraps `call_async`. Trips on
        //                            wall-clock regardless of what
        //                            the guest is doing — but ONLY at
        //                            an async yield point. A guest
        //                            stuck in pure synchronous WASM
        //                            won't yield.
        //   3. epoch interruption  — wasmtime polls a deadline at
        //                            every loop backedge + function
        //                            entry; trips on either deadline
        //                            exceeded OR explicit interrupt.
        //                            Closes the gap between (1) and
        //                            (2) — guest stuck in sync WASM
        //                            with cheap operators (fuel
        //                            cost = 1 per op) still trips
        //                            this within one
        //                            EPOCH_TICK_INTERVAL.
        //
        // The matching call sites for each Store:
        //   * `Store::set_epoch_deadline(ticks_ahead)` — the deadline
        //     is set in `select_tier` callers BEFORE `call_async`.
        //     The deadline is denominated in epoch ticks (one per
        //     `EPOCH_TICK_INTERVAL`); we set it from the per-job
        //     `timeout` so it matches the wall-clock budget.
        //   * Background ticker — `TalosRuntime::spawn_epoch_ticker`
        //     calls `engine.increment_epoch()` once per
        //     EPOCH_TICK_INTERVAL on a dedicated tokio task.
        //
        // Cost: one atomic increment per tick on the ticker thread
        // + a relaxed load at every loop backedge / function entry
        // in the guest. Negligible compared to the security value
        // of having a third independent kill switch.
        config.epoch_interruption(true);

        // ========================================================================
        // WASM Stack Size
        // ========================================================================
        // With async_support(true), wasmtime uses fiber stacks. The total fiber
        // stack is async_stack_size, split between WASM (max_wasm_stack) and the
        // host (the remainder). We need:
        //   async_stack_size > max_wasm_stack
        // so the host has room for its own frames during host calls.
        //
        // 2MB WASM stack allows serde_json to parse large results (~10K rows).
        // 4MB async stack gives the host 2MB for its own call frames.
        config.async_stack_size(4 * 1024 * 1024);
        config.max_wasm_stack(2 * 1024 * 1024);

        // Backtraces enabled for diagnostics — the error is returned as an opaque
        // string to the MCP caller and never exposed to end-users via the API.

        // ========================================================================
        // ALLOCATOR STRATEGY
        // ========================================================================
        // TALOS_DISABLE_POOLING=true  → on-demand allocator (safe, slightly slower).
        //   Use this when the pooling slab causes mmap/mprotect failures in the
        //   host environment (Docker Desktop VM memory overcommit limits, etc.).
        //
        // Default (TALOS_DISABLE_POOLING unset / "false") → pooling allocator
        //   with a 128 MiB per-slot reservation so the slab fits in Docker Desktop.
        //
        // In both cases, cap memory_reservation to 128 MiB so wasmtime emits
        // explicit Cranelift bounds checks rather than relying on hardware guard
        // pages that require a 4 GiB PROT_NONE reservation per memory slot.
        const MEMORY_SLOT_BYTES: u64 = 128 * 1024 * 1024; // 128 MiB
        config.memory_reservation(MEMORY_SLOT_BYTES);

        let disable_pooling = std::env::var("TALOS_DISABLE_POOLING")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        if !disable_pooling {
            let mut pooling_config = PoolingAllocationConfig::default();
            pooling_config
                .total_component_instances(500)
                .max_component_instance_size(10 * 1024 * 1024)
                .max_core_instances_per_component(20)
                .max_memories_per_component(20)
                .total_memories(2000)
                // Must be ≤ memory_reservation set above.
                .max_memory_size(MEMORY_SLOT_BYTES as usize)
                .max_tables_per_component(20)
                .total_tables(2000)
                .total_stacks(500)
                .linear_memory_keep_resident(8 * 1024 * 1024)
                .table_keep_resident(20_000)
                // ── Performance tuning (wasmtime ≥42) ────────────────────────
                // Batch 8 slot decommits per syscall instead of 1.  Reduces
                // mmap/mprotect overhead in high-throughput execution.
                .decommit_batch_size(8)
                // Retain up to 50 warm slots with committed memory.  Re-using a
                // warm slot avoids page faults on the first access.
                .max_unused_warm_slots(50);

            // ── Memory Protection Keys (Linux x86-64 only) ──────────────────
            // MPK striping dramatically reduces virtual address space consumption
            // by the pooling allocator — multiple instances share the same VA
            // range, switching protection via WRPKRU instead of mmap.
            // MpkEnabled::Auto detects hardware support at runtime.
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            {
                pooling_config.memory_protection_keys(wasmtime::Enabled::Auto);
            }

            config.allocation_strategy(InstanceAllocationStrategy::Pooling(pooling_config));
        }

        config.parallel_compilation(true);
        config.cranelift_opt_level(wasmtime::OptLevel::Speed);

        let engine = Engine::new(&config)?;
        tracing::info!(
            // Keep this in sync with worker/Cargo.toml's wasmtime dep
            // when bumping the version. wasmtime doesn't expose a
            // runtime VERSION constant, so the value is a literal here.
            wasmtime_version = "43.0.2",
            allocator = if disable_pooling {
                "on-demand (TALOS_DISABLE_POOLING=true)"
            } else {
                "pooling (500 instances, 2000 memories, batch_decommit=8, warm_slots=50)"
            },
            memory_reservation_mb = 128,
            fuel_custom_costs = true,
            "Engine created"
        );

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
        let agent_linker = build_agent_linker(&engine)?;
        let trusted_linker = build_trusted_linker(&engine)?;

        // Ten InstancePre caches using DashMap for lock-free concurrent access.
        // Each tier is independently bounded by instance_cache_max_per_tier
        // (default 256, configurable via WASM_INSTANCE_CACHE_MAX_PER_TIER).
        // On insert, if over capacity, ~25% of entries are evicted.
        let minimal_cache = Arc::new(DashMap::new());
        let network_cache = Arc::new(DashMap::new());
        let secrets_cache = Arc::new(DashMap::new());
        let filesystem_cache = Arc::new(DashMap::new());
        let messaging_cache = Arc::new(DashMap::new());
        let cache_node_cache = Arc::new(DashMap::new());
        let database_cache = Arc::new(DashMap::new());
        let governance_cache = Arc::new(DashMap::new());
        let agent_cache = Arc::new(DashMap::new());
        let trusted_cache = Arc::new(DashMap::new());

        // Initialize OpenTelemetry metrics (optional).
        // MCP-1073 (2026-05-16): canonical bool-env helper. Pre-fix
        // `== "true"` case-sensitive exact-match — operator setting
        // `OTEL_METRICS_ENABLED=1` got no metrics silently. Sibling
        // drift class to MCP-1060/1064/1065/1066/1072.
        let metrics = if talos_config::bool_env_or_default("OTEL_METRICS_ENABLED", false) {
            Some(Arc::new(crate::metrics::RuntimeMetrics::new()))
        } else {
            None
        };

        // -----------------------
        // Runtime Config (env‑vars)
        // -----------------------
        // Fuel limit – guards against runaway loops. Override with WASM_FUEL_LIMIT.
        // MCP-639 (2026-05-13): treat `WASM_FUEL_LIMIT=0` as
        // misconfiguration. Wasmtime's fuel semantic is "zero fuel
        // budget → trap on first instruction", so a literal 0 makes
        // EVERY WASM call fuel-exhaust before doing any work. Operators
        // setting `=0` usually intend "no limit" (common UNIX
        // convention) — but wasmtime gives them the opposite. Substitute
        // the default + WARN so the misconfiguration is visible.
        // Sibling to MCP-638 (semaphore 0-clamp).
        let fuel_limit: u64 = nonzero_env_or_default("WASM_FUEL_LIMIT", 10_000_000);

        // Result‑cache in‑process size – configurable via WASM_RESULT_CACHE_CAPACITY.
        // Minimum 1 to prevent NonZeroUsize panic; setting to 0 silently clamps to 1.
        let result_cache_cap: usize = std::env::var("WASM_RESULT_CACHE_CAPACITY")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(256) // default 256 entries
            .max(1);

        // -----------------------------------------------------------------
        // Security limits – configurable via env vars for flexibility.
        // -----------------------------------------------------------------
        // Maximum size of JSON output returned to the caller (bytes).
        // Prevents accidental OOM when a malicious module returns a huge blob.
        // MCP-639: `WASM_MAX_OUTPUT_BYTES=0` would reject every output
        // (even empty JSON `null` exceeds 0). Substitute default + WARN.
        let max_output_bytes: usize = nonzero_env_or_default("WASM_MAX_OUTPUT_BYTES", 1_000_000);

        // Maximum size of JSON input accepted (bytes). Large inputs can cause
        // excessive parsing cost or memory pressure.
        // MCP-639: same 0-clamp — `=0` rejects every input at the boundary.
        let max_input_bytes: usize = nonzero_env_or_default("WASM_MAX_INPUT_BYTES", 1_000_000);

        // InstancePre cache capacity per tier.  Each of the 10 tier caches is
        // independently bounded.  When a tier exceeds this limit, ~25% of
        // entries are evicted on the next insert to amortize cleanup cost.
        let instance_cache_max_per_tier: usize = std::env::var("WASM_INSTANCE_CACHE_MAX_PER_TIER")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(256)
            .max(8); // minimum 8 to avoid degenerate thrashing

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
            agent_linker,
            trusted_linker,
            minimal_cache,
            network_cache,
            secrets_cache,
            filesystem_cache,
            messaging_cache,
            cache_node_cache,
            database_cache,
            governance_cache,
            agent_cache,
            trusted_cache,
            redis_client,
            nats_client,
            fs_dir,
            in_memory_result_cache: Arc::new(DashMap::with_capacity(result_cache_cap)),
            result_cache_capacity: result_cache_cap,
            active_executions: Arc::new(AtomicU32::new(0)),
            total_executions: Arc::new(AtomicU64::new(0)),
            fuel_limit,
            instance_cache_max_per_tier,
            max_output_bytes,
            max_input_bytes,
            start_time: std::time::Instant::now(),
            metrics,
            // Default TTL for cached results (seconds). If the env var is not set,
            // we fall back to a 5‑minute TTL (300 s) in the execution path.
            //
            // MCP-772 (2026-05-13): treat `=0` as unset (None → no caching).
            // Pre-fix `WASM_RESULT_CACHE_TTL_SECS=0` produced `Some(0)`
            // which `is_some()` reads as "caching enabled" — but the
            // Redis path's `SETEX cache_key 0` is rejected as `ERR
            // invalid expire time`. The `.filter(|n| *n > 0)` collapses
            // Some(0) → None so "disable caching" actually disables it.
            // MCP-1092 (2026-05-16) closed the related in-memory TTL
            // gap: `insert_to_cache` now stores `expires_at` and reads
            // fall-stale, so even with a non-zero TTL the in-memory
            // layer no longer serves entries past their declared TTL.
            default_result_cache_ttl_secs: std::env::var("WASM_RESULT_CACHE_TTL_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|n| *n > 0),
            global_expose_fallback: Arc::new(crate::expose_fallback::ExposeFallback::new()),
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
            SecurityPolicy::default(),
            None,                                            // capability_world_hint
            None,              // max_fuel_override — use runtime default
            false,             // dry_run
            None,              // actor_id
            uuid::Uuid::nil(), // user_id — legacy helper has no user context
            talos_workflow_job_protocol::LlmTier::default(), // tier2 for legacy helper
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
        security_policy: SecurityPolicy,
        // Capability world hint from the controller (bypasses binary re-inspection).
        // Critical for sandbox modules whose Wizer-snapshotted binary may have lost
        // embedded WIT world-name strings that `inspect_component` relies on.
        capability_world_hint: Option<CapabilityWorld>,
        // Per-job fuel override from the controller (read from node config `max_fuel`).
        // When non-zero, overrides the runtime's global `fuel_limit`.
        max_fuel_override: Option<u64>,
        // When true, non-GET HTTP requests are mocked with success responses.
        dry_run: bool,
        // Actor ID for persistent agent-memory WIT interface operations.
        actor_id: Option<uuid::Uuid>,
        // User ID — owner of the execution. Used by integration_state host
        // fns to scope writes to (integration_name, user_id). Nil UUID
        // means 'no user context' — integration_state calls fail closed.
        user_id: uuid::Uuid,
        // LLM data-egress ceiling for this job. `Tier1` refuses to
        // resolve external-provider keys (Anthropic / OpenAI / Gemini).
        max_llm_tier: talos_workflow_job_protocol::LlmTier,
    ) -> Result<JsonValue> {
        // Per-job fuel override: use the controller-supplied value when non-zero,
        // otherwise fall back to the runtime's global fuel_limit.
        let effective_fuel_limit = match max_fuel_override {
            Some(f) if f > 0 => f,
            _ => self.fuel_limit,
        };

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
                "Input JSON size {} exceeds allowed maximum of {} bytes.\n{}",
                input_len,
                self.max_input_bytes,
                describe_oversized_input(&input),
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

        // Resolve capability world: prefer the hint from the controller (avoids re-inspecting
        // a Wizer-snapshotted binary that may have lost embedded WIT world-name strings),
        // then fall back to binary inspection only when no usable hint is provided.
        let cap = match capability_world_hint {
            Some(hint) if !matches!(hint, CapabilityWorld::Unknown) => hint,
            _ => crate::wit_inspector::inspect_component(wasm_bytes).capability_world,
        };
        let mut result_cache_ttl_secs = result_cache_ttl_secs;
        if matches!(cap, crate::wit_inspector::CapabilityWorld::Governance) {
            // Governance nodes must not be cached because they require human interaction
            result_cache_ttl_secs = None;
        }

        // PHASE 2: RESULT CACHING — check before doing any compilation work
        if result_cache_ttl_secs.is_some() {
            let cache_key =
                Self::result_cache_key(&module_hash_str, &input, execution_context.as_ref());
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
                    &security_policy,
                    cap.clone(),
                    effective_fuel_limit,
                    dry_run,
                    actor_id,
                    user_id,
                    max_llm_tier,
                )
                .await
            {
                Ok(result) => {
                    // Cache the result if caching is enabled
                    if let Some(ttl_secs) = result_cache_ttl_secs {
                        let cache_key = Self::result_cache_key(
                            &module_hash_str,
                            &input,
                            execution_context.as_ref(),
                        );
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
                        // Record failure metrics (if enabled).
                        // The error in `e` has already been formatted by the inner execution
                        // function into a user-facing message:
                        //   "Component returned error: ..."  — WIT Err(String) return
                        //   "PANIC: ..."                     — panic via WASI stderr capture
                        //   "WASM fuel exhausted after ..."  — fuel budget exhausted
                        //   "WASM execution timed out ..."   — wall-clock timeout
                        //   "WASM trap encountered"          — unexpected trap (sanitized above)
                        // Do NOT replace e with a generic string — that would destroy the
                        // specific, actionable message the inner function produced.
                        if let Some(ref otel_metrics) = self.metrics {
                            let total_duration = overall_start.elapsed().as_millis() as f64;
                            otel_metrics.record_execution(total_duration, "error");
                            let error_str = e.to_string();
                            let error_type = if error_str.contains("timeout") {
                                "timeout"
                            } else if error_str.contains("fuel") {
                                "out_of_fuel"
                            } else if error_str.contains("trap") {
                                "trap"
                            } else if error_str.contains("PANIC") {
                                "panic"
                            } else if error_str.contains("Component returned error") {
                                "component_error"
                            } else if error_str.contains("memory") {
                                "memory_limit"
                            } else {
                                "runtime_error"
                            };
                            otel_metrics.record_error(error_type);
                        }

                        // Pass the already-formatted error through to the caller unchanged.
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
        security_policy: &SecurityPolicy,
        // Pre-resolved capability world — avoids re-inspecting the binary (which can fail for
        // Wizer-snapshotted sandbox modules that lose embedded WIT world-name strings).
        capability_world: CapabilityWorld,
        // Per-job fuel limit (overrides self.fuel_limit when > 0).
        effective_fuel_limit: u64,
        // When true, non-GET HTTP requests are mocked with success responses.
        dry_run: bool,
        // Actor ID for persistent agent-memory WIT interface operations.
        actor_id: Option<uuid::Uuid>,
        // User ID — owner of the execution. Used by integration_state host
        // fns to scope writes to (integration_name, user_id). Nil UUID
        // means 'no user context' — integration_state calls fail closed.
        user_id: uuid::Uuid,
        // LLM data-egress ceiling for this job. `Tier1` refuses to
        // resolve external-provider keys (Anthropic / OpenAI / Gemini).
        max_llm_tier: talos_workflow_job_protocol::LlmTier,
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

        // Use the pre-resolved capability world (passed from execute_job_with_full_features)
        // to select the appropriate tiered linker.  Re-inspecting the binary here would fail
        // for Wizer-snapshotted sandbox modules that have lost embedded WIT world-name strings.
        let cap = capability_world;
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
            allow_wasi_network,
            token_sender,
            self.global_expose_fallback.clone(),
        )?;

        // Attach OpenTelemetry metrics so host functions can record events.
        if let Some(ref m) = self.metrics {
            context.set_metrics(m.clone());
        }

        // Apply per-module security policy from the controller.
        context.set_allowed_secrets(security_policy.allowed_secrets.clone());
        context.set_allowed_sql_operations(security_policy.allowed_sql_operations.clone());
        context.set_allow_tier2_exposure(security_policy.allow_tier2_exposure);
        // Integration scoping for `integration-state` host fns. None means
        // the module is not an integration; those host fns return
        // `unauthorized` without any DB round-trip.
        context.integration_name = security_policy.integration_name.clone();

        // Enable dry-run mode if requested (mocks non-GET HTTP, webhook, messaging calls).
        if dry_run {
            context.set_dry_run(true);
        }

        // Wire actor_id for persistent agent-memory operations.
        if let Some(aid) = actor_id {
            context.actor_id = Some(aid);
        }
        // Wire LLM tier ceiling. `get_llm_api_key` refuses to resolve
        // external-provider keys when this is Tier1.
        context.max_llm_tier = max_llm_tier;
        // Wire user_id for integration_state scoping + per-user rate limiting.
        // Uuid::nil() means the controller didn't supply one (system
        // execution); integration_state host fns treat that as "not
        // available" and reject before any NATS round-trip.
        if !user_id.is_nil() {
            context.set_user_id(user_id);
        }

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

        // Durable state load-on-resume was previously read from the
        // `execution_state` table via the worker's db_pool. Post-
        // Phase-2.3 the worker is credential-free and the state
        // interface is in-memory-only per execution — if we need
        // cross-worker resumption, the controller must push the
        // snapshot into the initial input envelope before dispatch.

        // OOM-safe store creation (wasmtime ≥42): returns Result instead of
        // panicking when the allocator cannot reserve memory for the Store.
        let mut store = Store::try_new(&self.engine, context)?;
        let exec_id_for_log = store.data().execution_id.clone();

        // SECURITY: Apply Resource Limits — enforced by TalosContext::ResourceLimiter impl
        store.limiter(|ctx| ctx as &mut dyn wasmtime::ResourceLimiter);

        // M1 (2026-05-22): set the epoch interruption deadline. The
        // ticker in `spawn_epoch_ticker` increments the engine epoch
        // every `EPOCH_TICK_INTERVAL_MS`; this Store traps when the
        // engine reaches `current_epoch + deadline_ticks`. Closes the
        // gap where fuel and wall-clock timeout could both miss a
        // tight sync-WASM loop with cheap operators that never yields
        // to the tokio runtime.
        store.set_epoch_deadline(epoch_ticks_for_timeout(timeout));

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

        // Provide fuel to cap CPU usage (per-job override or global limit)
        store.set_fuel(effective_fuel_limit)?;

        // ── InstancePre cache lookup ─────────────────────────────────────────
        // On cache hit:  zero compilation, zero linking — just instantiate.
        // On cache miss: compile → link → pre-instantiate → cache.
        let instance_pre = {
            if let Some(entry) = cache.get(&module_hash_bytes) {
                metrics.cache_hit = true;
                metrics.compilation_ms = 0;
                span.add_event("cache_hit");
                span.set_attribute_bool("cache_hit", true);
                entry.clone()
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
                self.cache_insert_instance_pre(cache, module_hash_bytes, pre.clone());
                pre
            }
        };

        // Instantiate directly from the pre-linked component.
        //
        // We do NOT use AutomationNodePre::new() here because that typed wrapper is
        // generated specifically for the `automation-node` WIT world and fails with
        // "no export 'run' found" for components compiled against other worlds
        // (minimal-node, secrets-node, http-node, etc.) or with wit-bindgen 0.26.x.
        //
        // All Talos WIT worlds export the identical bare function:
        //   run: func(input: string) -> result<string, string>
        // so we can find it by name after instantiation without world-level type
        // validation. The linker already enforced import correctness via select_tier().
        let instance = instance_pre.instantiate_async(&mut store).await?;
        let run_func = instance.get_func(&mut store, "run").ok_or_else(|| {
            anyhow::anyhow!(
                "WASM component does not export 'run'. \
                 Ensure your module is annotated with #[talos_module] or #[talos_node] \
                 and exports: run: func(input: string) -> result<string, string>"
            )
        })?;
        let typed_run = run_func
            .typed::<(String,), (Result<String, String>,)>(&store)
            .map_err(|e| {
                anyhow::anyhow!(
                    "WASM 'run' export has an unexpected type signature: {}. \
                 Expected: func(input: string) -> result<string, string>",
                    e
                )
            })?;

        // Clone the stderr capture Arc before the store is moved into the timeout closure.
        // After the closure completes (or times out), we read any panic message written to
        // WASI stderr and attach it to trap errors for actionable diagnostics.
        let stderr_arc = store.data().stderr_capture.clone();

        // Call the exported `run` function with automatic timeout enforcement.
        let input_str = input.to_string();
        tracing::debug!(
            input = {
                let end = input_str.len().min(1000);
                // Find a char boundary at or before the target offset to avoid
                // panicking on multi-byte UTF-8 sequences (e.g. emoji).
                let safe_end = input_str.floor_char_boundary(end);
                &input_str[..safe_end]
            },
            "--> PASSING TO WASM NODE"
        );

        // If the module can use Governance (human-in-the-loop), it might park for days.
        let actual_timeout =
            if matches!(cap, CapabilityWorld::Governance | CapabilityWorld::Trusted) {
                std::time::Duration::from_secs(86400 * 7) // 7 days
            } else {
                timeout
            };

        let execution_start = std::time::Instant::now();
        let fuel_limit_for_calc = effective_fuel_limit;
        let call_result = tokio::time::timeout(actual_timeout, async move {
            let res = typed_run
                .call_async(&mut store, (input_str,))
                .await
                .map(|(r,)| r);
            let oom_msg = store.data().oom_error_message.clone();
            let remaining_fuel = store.get_fuel().ok();
            (res, oom_msg, remaining_fuel)
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

        let (call_result, oom_msg, remaining_fuel) = call_result;
        let fuel_consumed = remaining_fuel.map(|r| fuel_limit_for_calc.saturating_sub(r));

        // Read any bytes written to WASI stderr during execution (e.g. panic messages).
        // The WASM runtime writes "thread '...' panicked at '...'" to WASI stderr on panic.
        let captured_stderr = {
            let guard = stderr_arc.lock().unwrap_or_else(|e| e.into_inner());
            String::from_utf8_lossy(&guard).into_owned()
        };

        // Handle runtime error (outer Result) — check for OOM before generic trap
        let output_result = match call_result {
            Err(e) => {
                if let Some(oom_msg) = oom_msg {
                    return Err(anyhow::anyhow!("{}", oom_msg));
                }
                // Check both Display and Debug formats — wasmtime may put
                // "all fuel consumed" in the error chain, not the top-level message
                let err_str = format!("{}", e);
                let err_debug = format!("{:?}", e);
                if err_str.contains("fuel")
                    || err_str.contains("all fuel consumed")
                    || err_debug.contains("fuel")
                    || err_debug.contains("OutOfFuel")
                {
                    return Err(anyhow::anyhow!(
                        "WASM fuel exhausted after {} instructions. Your module ran out of computation budget. \
                         Split into smaller modules or reduce payload size. \
                         Current fuel limit: {} (configurable via WASM_FUEL_LIMIT or per-node max_fuel config).",
                        effective_fuel_limit, effective_fuel_limit
                    ));
                }
                // Fallback: when a trap carries WASI stderr output, try to extract a
                // clean panic message.  This path fires for:
                //   • Modules compiled with panic="abort" (old binaries / OCI modules)
                //   • Stack-overflow and other traps that bypass catch_unwind
                // Modules compiled with panic="unwind" (all fresh sandbox compilations)
                // have their panics caught by the macro-injected catch_unwind before
                // reaching here, so this is truly a last-resort fallback.
                let stderr_trimmed = captured_stderr.trim();
                if !stderr_trimmed.is_empty()
                    && (err_str.contains("trap") || err_debug.contains("trap"))
                {
                    // Try to extract a clean "PANIC: message" from the stderr dump.
                    // If parseable, present identically to catch_unwind output so
                    // callers see a consistent format regardless of panic strategy.
                    if let Some(panic_msg) = extract_panic_message_from_stderr(stderr_trimmed) {
                        return Err(anyhow::anyhow!("PANIC: {}", panic_msg));
                    }
                    // Unknown trap with stderr — include both for diagnostics.
                    return Err(anyhow::anyhow!(
                        "WASM trap: {}\nPanic output:\n{}",
                        e,
                        stderr_trimmed
                    ));
                }
                // Log full trap details (Display + Debug) to help identify root cause.
                // Debug format includes the backtrace when wasm_backtrace_details is Enable.
                // The raw wasmtime error (which may contain WASM backtrace addresses) is
                // logged here and must NOT propagate to callers — return a sanitized message.
                tracing::error!(
                    err_display = %e,
                    err_debug = ?e,
                    stderr = %captured_stderr.trim(),
                    "WASM trap (no stderr / no fuel): full diagnostics"
                );
                return Err(anyhow::anyhow!("WASM trap encountered"));
            }
            Ok(v) => v,
        };

        // Handle component error (inner Result<String, String>)
        let output_str: String = match output_result {
            Ok(s) => s,
            Err(e) => {
                span.end_error(&format!("Component error: {}", e));
                return Err(anyhow::anyhow!("Component returned error: {}", e));
            }
        };

        // MCP-854 (2026-05-14): the bounded debug below (1000-byte
        // char-boundary-safe truncation) is the operator-friendly
        // tracing surface for WASM-node output. Pre-fix two more
        // `tracing::debug!("...: {:?}", output_str)` calls dumped the
        // ENTIRE output_str (potentially many MB) via Debug format —
        // unbounded payload + no truncation + no DLP, redundant with
        // the bounded debug above (which any operator who needs
        // output content has already seen). The unbounded variant is
        // a debug-log antipattern: at TRACE/DEBUG it's gated behind
        // RUST_LOG=debug but if an operator flips it on to investigate
        // an issue, they'd accidentally tail-log secrets, tokens, or
        // PII the module emitted. Drop both unbounded sites; keep the
        // bounded one. The not-valid-JSON branch shouldn't need a
        // dedicated log either — `out_json` is built right below;
        // operators can see the raw value through the bounded log
        // above. Same class as MCP-852/853 (Debug-format leaks).
        tracing::debug!(
            output = {
                let end = output_str.len().min(1000);
                let safe_end = output_str.floor_char_boundary(end);
                &output_str[..safe_end]
            },
            "--> WASM NODE RETURNED"
        );

        // Parse the JSON output, fallback to wrapping it in a String value if parsing fails
        let out_json: JsonValue = match serde_json::from_str(&output_str) {
            Ok(json) => json,
            Err(_) => serde_json::Value::String(output_str.clone()),
        };

        // Inject fuel consumption metadata into the output JSON.
        let mut out_json = out_json;
        if let Some(consumed) = fuel_consumed {
            if let Some(obj) = out_json.as_object_mut() {
                obj.insert("__fuel_consumed__".to_string(), serde_json::json!(consumed));
            }
        }

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
            allow_wasi_network,
            stdout_sender,
            self.global_expose_fallback.clone(),
        )?;

        // Attach OpenTelemetry metrics so host functions can record events.
        if let Some(ref m) = self.metrics {
            context.set_metrics(m.clone());
        }

        if let Some((workflow_id, execution_id, module_id)) = execution_context {
            context.set_workflow_context(
                workflow_id.clone(),
                execution_id.clone(),
                module_id.clone(),
            );
            context.set_request_id(workflow_id.clone());
        }

        let mut store = Store::try_new(&self.engine, context)?;

        // SECURITY: Apply Resource Limits
        store.limiter(|ctx| ctx as &mut dyn wasmtime::ResourceLimiter);

        // M1: epoch interruption deadline — see top of file.
        store.set_epoch_deadline(epoch_ticks_for_timeout(timeout));

        // Provide fuel to cap CPU usage
        store.set_fuel(self.fuel_limit)?;

        // Get or compile InstancePre with caching
        let mut hasher = Sha256::new();
        hasher.update(wasm_bytes);
        let cache_key: [u8; 32] = hasher.finalize().into();

        let instance_pre = {
            if let Some(entry) = cache.get(&cache_key) {
                entry.clone()
            } else {
                let component = if wasm_bytes.starts_with(AOT_VERSION_HDR) {
                    self.load_precompiled(wasm_bytes)?
                } else {
                    Component::new(&self.engine, wasm_bytes)?
                };
                let pre = linker.instantiate_pre(&component)?;
                self.cache_insert_instance_pre(cache, cache_key, pre.clone());
                pre
            }
        };

        let instance = instance_pre.instantiate_async(&mut store).await?;
        let run_func = instance.get_func(&mut store, "run").ok_or_else(|| {
            anyhow::anyhow!(
                "WASM component does not export 'run'. \
                 Expected: run: func(input: string) -> result<string, string>"
            )
        })?;
        let typed_run = run_func
            .typed::<(String,), (Result<String, String>,)>(&store)
            .map_err(|e| anyhow::anyhow!("WASM 'run' export has wrong type: {}", e))?;

        let input_str = input.to_string();

        let fuel_limit_for_calc = self.fuel_limit;
        let call_result = tokio::time::timeout(timeout, async move {
            let res = typed_run
                .call_async(&mut store, (input_str,))
                .await
                .map(|(r,)| r);
            let oom_msg = store.data().oom_error_message.clone();
            let remaining_fuel = store.get_fuel().ok();
            (res, oom_msg, remaining_fuel)
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "WASM execution timed out after {:?}. The module took too long to execute.",
                timeout
            )
        })?;

        let (call_result, oom_msg, remaining_fuel) = call_result;
        let fuel_consumed = remaining_fuel.map(|r| fuel_limit_for_calc.saturating_sub(r));

        let output_result = match call_result {
            Err(e) => {
                if let Some(oom_msg) = oom_msg {
                    return Err(anyhow::anyhow!("{}", oom_msg));
                }
                // Check both Display and Debug formats — wasmtime may put
                // "all fuel consumed" in the error chain, not the top-level message
                let err_str = format!("{}", e);
                let err_debug = format!("{:?}", e);
                if err_str.contains("fuel")
                    || err_str.contains("all fuel consumed")
                    || err_debug.contains("fuel")
                    || err_debug.contains("OutOfFuel")
                {
                    return Err(anyhow::anyhow!(
                        "WASM fuel exhausted after {} instructions. Your module ran out of computation budget. \
                         Split into smaller modules or reduce payload size. \
                         Current fuel limit: {} (configurable via WASM_FUEL_LIMIT).",
                        self.fuel_limit, self.fuel_limit
                    ));
                }
                return Err(e.into());
            }
            Ok(v) => v,
        };

        let output_str: String = match output_result {
            Ok(s) => s,
            Err(e) => return Err(anyhow::anyhow!("Component returned error: {}", e)),
        };

        // Inject fuel consumption into string output if it's valid JSON
        if let Some(consumed) = fuel_consumed {
            if let Ok(mut json_val) = serde_json::from_str::<JsonValue>(&output_str) {
                if let Some(obj) = json_val.as_object_mut() {
                    obj.insert("__fuel_consumed__".to_string(), serde_json::json!(consumed));
                    if let Ok(s) = serde_json::to_string(&json_val) {
                        return Ok(s);
                    }
                }
            }
        }

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
        // LLM tier ceiling stamped on every step's TalosContext so pipeline
        // steps enforce the same tier gate as single-node JobRequest dispatch.
        max_llm_tier: talos_workflow_job_protocol::LlmTier,
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
                if let Some(entry) = cache.get(&module_hash_bytes) {
                    entry.clone()
                } else {
                    let component = if step.wasm_bytes.starts_with(AOT_VERSION_HDR) {
                        self.load_precompiled(&step.wasm_bytes)?
                    } else {
                        wasmtime::component::Component::new(&self.engine, &step.wasm_bytes)?
                    };
                    let pre = linker.instantiate_pre(&component)?;
                    self.cache_insert_instance_pre(cache, module_hash_bytes, pre.clone());
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
                allow_wasi_network,
                None,
                self.global_expose_fallback.clone(),
            )?;
            // Attach OpenTelemetry metrics so host functions can record events.
            if let Some(ref m) = self.metrics {
                context.set_metrics(m.clone());
            }
            // Apply per-step security policy.
            context.set_allowed_secrets(step.security_policy.allowed_secrets.clone());
            context.set_allowed_sql_operations(step.security_policy.allowed_sql_operations.clone());
            context.set_allow_tier2_exposure(step.security_policy.allow_tier2_exposure);
            context.integration_name = step.security_policy.integration_name.clone();
            // Stamp the pipeline-wide LLM tier ceiling so every step's
            // host-fn gates (llm::*, wit_http, graphql, webhook, http_stream)
            // enforce the same contract as a single-node JobRequest.
            context.max_llm_tier = max_llm_tier;

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

            let mut store = Store::try_new(&self.engine, context)?;
            store.limiter(|ctx| ctx as &mut dyn wasmtime::ResourceLimiter);
            // M1: epoch interruption deadline — per-step.
            store.set_epoch_deadline(epoch_ticks_for_timeout(step_timeout));
            store.set_fuel(step.max_fuel)?;

            // Instantiate from the cached InstancePre.
            let instance = instance_pre.instantiate_async(&mut store).await?;
            let run_func = instance.get_func(&mut store, "run").ok_or_else(|| {
                anyhow::anyhow!(
                    "WASM component does not export 'run'. \
                     Expected: run: func(input: string) -> result<string, string>"
                )
            })?;
            let typed_run = run_func
                .typed::<(String,), (Result<String, String>,)>(&store)
                .map_err(|e| anyhow::anyhow!("WASM 'run' export has wrong type: {}", e))?;

            let input_str = step_input.to_string();

            // Execute with the per-step timeout (bounded by overall deadline).
            let step_max_fuel = step.max_fuel;
            let call_result = tokio::time::timeout(step_timeout, async move {
                let res = typed_run
                    .call_async(&mut store, (input_str,))
                    .await
                    .map(|(r,)| r);
                let oom_msg = store.data().oom_error_message.clone();
                let remaining_fuel = store.get_fuel().ok();
                (res, oom_msg, remaining_fuel)
            })
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "Pipeline step '{}' timed out after {:?}",
                    step.module_id,
                    step_timeout
                )
            })?;

            let (call_result, oom_msg, remaining_fuel) = call_result;
            let fuel_consumed = remaining_fuel.map(|r| step_max_fuel.saturating_sub(r));

            let output_result = match call_result {
                Err(e) => {
                    if let Some(oom_msg) = oom_msg {
                        anyhow::bail!("{}", oom_msg);
                    }
                    let err_str = format!("{}", e);
                    if err_str.contains("fuel") || err_str.contains("all fuel consumed") {
                        anyhow::bail!(
                            "WASM fuel exhausted in pipeline step '{}' after {} instructions. \
                             Your module ran out of computation budget. \
                             Split into smaller modules or reduce payload size. \
                             Current fuel limit: {} (configurable via WASM_FUEL_LIMIT).",
                            step.module_id,
                            self.fuel_limit,
                            self.fuel_limit
                        );
                    }
                    return Err(e.into());
                }
                Ok(v) => v,
            };

            let output_str = match output_result {
                Ok(s) => s,
                Err(e) => {
                    anyhow::bail!("Pipeline step '{}' returned error: {}", step.module_id, e);
                }
            };

            let mut step_output: JsonValue = serde_json::from_str(&output_str).map_err(|e| {
                // Bare serde errors like "expected value at line 1 column 1"
                // are unhelpful: the operator can't tell whether the module
                // returned an empty body, a truncated LLM response, or HTML.
                // Attach the body length plus a head/tail preview so the cause
                // is diagnosable from error_message alone (preview is safe —
                // pipeline-step output is module return data, not secrets).
                anyhow::anyhow!(
                    "Pipeline step '{}' produced invalid JSON: {} (output_len={}, preview={})",
                    step.module_id,
                    e,
                    output_str.len(),
                    preview_for_error(&output_str)
                )
            })?;

            // Inject fuel consumption metadata into the step output.
            if let Some(consumed) = fuel_consumed {
                if let Some(obj) = step_output.as_object_mut() {
                    obj.insert("__fuel_consumed__".to_string(), serde_json::json!(consumed));
                }
            }

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
        // Sum InstancePre cache sizes across all tiers.
        let total_cache_size = [
            &self.minimal_cache,
            &self.network_cache,
            &self.secrets_cache,
            &self.filesystem_cache,
            &self.messaging_cache,
            &self.cache_node_cache,
            &self.database_cache,
            &self.governance_cache,
            &self.agent_cache,
            &self.trusted_cache,
        ]
        .iter()
        .map(|cache| cache.len())
        .sum();

        RuntimeHealthStatus {
            build: "2026-03-13-r16".to_string(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            active_executions: self.active_executions.load(Ordering::SeqCst),
            total_executions: self.total_executions.load(Ordering::SeqCst),
            component_cache_size: total_cache_size,
            has_redis: self.redis_client.is_some(),
            has_nats: self.nats_client.is_some(),
            has_db: false, // worker is credential-free since Phase 2.3 — DB access is via NATS-RPC
            has_fs: self.fs_dir.is_some(),
            nonce_cache_size: talos_workflow_job_protocol::job_nonce_cache_size(),
            nonce_cache_capacity: talos_workflow_job_protocol::JOB_NONCE_CACHE_CAPACITY,
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
    /// DashMap provides lock-free concurrent access, so we can call .len() directly.
    pub fn cache_size(&self) -> usize {
        [
            &self.minimal_cache,
            &self.network_cache,
            &self.secrets_cache,
            &self.filesystem_cache,
            &self.messaging_cache,
            &self.cache_node_cache,
            &self.database_cache,
            &self.governance_cache,
            &self.agent_cache,
            &self.trusted_cache,
        ]
        .iter()
        .map(|c| c.len())
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

            let component_result: anyhow::Result<Component> =
                if wasm_bytes.starts_with(AOT_VERSION_HDR) {
                    self.load_precompiled(&wasm_bytes)
                } else {
                    Component::new(&self.engine, &wasm_bytes).map_err(Into::into)
                };

            match component_result {
                Ok(component) => match linker.instantiate_pre(&component) {
                    Ok(pre) => {
                        let mut hasher = Sha256::new();
                        hasher.update(&wasm_bytes);
                        let cache_key: [u8; 32] = hasher.finalize().into();

                        self.cache_insert_instance_pre(cache, cache_key, pre);
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
    /// Blob format: `[TALOSV2 (7 bytes)] [HMAC-SHA256 (32 bytes)] [serialized component]`
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
        // Always sign with the current key from the key ring.
        let key_ring = aot_key_ring();
        let mut mac = Hmac::<Sha256>::new_from_slice(&key_ring.signing_key)
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
            anyhow::bail!(
                "Precompiled WASM version mismatch – expected TALOSV2 (wasmtime 43). \
                 This blob was compiled with an older Talos version. Recompile the module."
            );
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
        // Try each key in the key ring (current key first, then previous keys).
        // This enables graceful key rotation without invalidating cached blobs.
        let (stored_tag, serialized) = after_hdr.split_at(AOT_HMAC_LEN);
        let key_ring = aot_key_ring();
        let mut verified = false;
        let mut matched_key_index = 0usize;

        for (idx, key) in key_ring.verification_keys.iter().enumerate() {
            let mut mac = Hmac::<Sha256>::new_from_slice(key)
                .map_err(|e| anyhow::anyhow!("Failed to create AOT HMAC: {}", e))?;
            mac.update(serialized);
            let expected_tag = mac.finalize().into_bytes();

            // Constant-time comparison to prevent timing side-channels.
            if stored_tag.ct_eq(expected_tag.as_slice()).unwrap_u8() == 1 {
                verified = true;
                matched_key_index = idx;
                break;
            }
        }

        if !verified {
            anyhow::bail!(
                "AOT blob HMAC verification failed — blob may have been tampered with or \
                 compiled by a different instance. Recompile the module."
            );
        }

        // Log when a blob was verified with a previous (non-current) key for
        // operational visibility during key rotation.
        if matched_key_index > 0 {
            tracing::info!(
                key_index = matched_key_index,
                "AOT blob verified with previous key (index {}) — consider recompiling to use current key",
                matched_key_index
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
    /// Linker tier is selected from the supplied `cap`, matching the JIT path
    /// at `Self::execute()`. AOT artefacts that import host functions outside
    /// their declared capability world will fail to instantiate against the
    /// chosen linker — the same fail-closed posture as fresh compilation.
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
    /// Linker tier is selected from the supplied `cap` via `select_tier`;
    /// `CapabilityWorld::Unknown` fails closed.
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
            allow_wasi_network,
            None,
            self.global_expose_fallback.clone(),
        )?;

        // Attach OpenTelemetry metrics so host functions can record events.
        if let Some(ref m) = self.metrics {
            context.set_metrics(m.clone());
        }

        if let Some((workflow_id, execution_id, module_id)) = execution_context {
            context.set_workflow_context(
                workflow_id.clone(),
                execution_id.clone(),
                module_id.clone(),
            );
            context.set_request_id(workflow_id.clone());
        }

        let mut store = Store::try_new(&self.engine, context)?;

        store.limiter(|ctx| ctx as &mut dyn wasmtime::ResourceLimiter);
        // M1: epoch interruption deadline.
        store.set_epoch_deadline(epoch_ticks_for_timeout(timeout));
        store.set_fuel(self.fuel_limit)?;

        // Defense-in-depth: pick the linker for the DECLARED capability world
        // rather than always using the trusted (automation-node) surface.
        // A component whose imports exceed `cap`'s linker tier will fail to
        // instantiate here, which is the desired fail-closed behaviour and
        // matches the JIT path. `Unknown` cap fails closed via `select_tier`.
        let (linker, _instance_cache) = self.select_tier(&cap)?;
        let pre = linker.instantiate_pre(&component)?;
        let instance = pre.instantiate_async(&mut store).await?;
        let run_func = instance.get_func(&mut store, "run").ok_or_else(|| {
            anyhow::anyhow!(
                "WASM component does not export 'run'. \
                 Expected: run: func(input: string) -> result<string, string>"
            )
        })?;
        let typed_run = run_func
            .typed::<(String,), (Result<String, String>,)>(&store)
            .map_err(|e| anyhow::anyhow!("WASM 'run' export has wrong type: {}", e))?;

        let input_str = serde_json::to_string(&input)?;

        let call_result = tokio::time::timeout(timeout, async move {
            let res = typed_run
                .call_async(&mut store, (input_str,))
                .await
                .map(|(r,)| r);
            let oom_msg = store.data().oom_error_message.clone();
            (res, oom_msg)
        })
        .await
        .map_err(|_| anyhow::anyhow!("WASM execution timed out after {:?}", timeout))?;

        let (call_result, oom_msg) = call_result;

        let call_result = match call_result {
            Err(e) => {
                if let Some(oom_msg) = oom_msg {
                    return Err(anyhow::anyhow!("{}", oom_msg));
                }
                // Check both Display and Debug formats — wasmtime may put
                // "all fuel consumed" in the error chain, not the top-level message
                let err_str = format!("{}", e);
                let err_debug = format!("{:?}", e);
                if err_str.contains("fuel")
                    || err_str.contains("all fuel consumed")
                    || err_debug.contains("fuel")
                    || err_debug.contains("OutOfFuel")
                {
                    return Err(anyhow::anyhow!(
                        "WASM fuel exhausted after {} instructions. Your module ran out of computation budget. \
                         Split into smaller modules or reduce payload size. \
                         Current fuel limit: {} (configurable via WASM_FUEL_LIMIT).",
                        self.fuel_limit, self.fuel_limit
                    ));
                }
                return Err(e.into());
            }
            Ok(v) => v,
        };

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
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(10_000);

        let log_collector = tokio::spawn(async move {
            let mut logs = Vec::new();
            let mut total_bytes = 0;
            const MAX_LOG_BYTES: usize = 100 * 1024; // 100 KB limit
            const MAX_LOG_LINES: usize = 1000;

            loop {
                match tokio::time::timeout(std::time::Duration::from_secs(60), rx.recv()).await {
                    Ok(Some(bytes)) => {
                        if total_bytes + bytes.len() > MAX_LOG_BYTES || logs.len() >= MAX_LOG_LINES
                        {
                            if logs.last().map(|s: &String| s.as_str())
                                != Some("... [Logs truncated due to size limits] ...")
                            {
                                logs.push(
                                    "... [Logs truncated due to size limits] ...".to_string(),
                                );
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
    /// Build identifier for verifying deployed version
    pub build: String,
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
    /// Whether PostgreSQL is configured
    pub has_db: bool,
    /// Whether NATS is configured
    pub has_nats: bool,
    /// Whether filesystem is configured
    pub has_fs: bool,
    /// Process-local job-nonce replay cache: current entry count.
    /// Surfaced so operators can correlate "approaching capacity"
    /// with upstream traffic rate and tune the cap / intake gate.
    pub nonce_cache_size: usize,
    /// Hard cap of the replay cache. `nonce_cache_size /
    /// nonce_cache_capacity` is the headroom; sustained values close
    /// to 1.0 indicate either legitimate high throughput or a replay
    /// flood.
    pub nonce_cache_capacity: usize,
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

    // -----------------------------------------------------------------------
    // extract_panic_message_from_stderr — unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn extract_panic_pre_173_simple_message() {
        let stderr = "thread '<unnamed>' panicked at 'explicit panic', src/lib.rs:10:5\n\
                      note: run with `RUST_BACKTRACE=1` to see a backtrace\n";
        assert_eq!(
            extract_panic_message_from_stderr(stderr),
            Some("explicit panic".to_string())
        );
    }

    #[test]
    fn extract_panic_pre_173_assert_eq() {
        let stderr = "thread '<unnamed>' panicked at 'assertion failed: left == right\n  left: 1\n right: 2', src/lib.rs:5:5\n";
        let msg = extract_panic_message_from_stderr(stderr).expect("should extract");
        assert!(msg.contains("assertion failed"), "got: {msg}");
    }

    #[test]
    fn extract_panic_new_format_173() {
        // Rust 1.73+ format: location on first line, message on second.
        let stderr = "thread '<unnamed>' panicked at src/lib.rs:10:5:\nexplicit panic\n\
                      note: run with `RUST_BACKTRACE=1` to see a backtrace\n";
        assert_eq!(
            extract_panic_message_from_stderr(stderr),
            Some("explicit panic".to_string())
        );
    }

    #[test]
    fn extract_panic_new_format_multiline_message() {
        let stderr = "thread '<unnamed>' panicked at src/lib.rs:3:5:\nassertion `left == right` failed\n  left: 1\n right: 2\nnote: run with `RUST_BACKTRACE=1`\n";
        let msg = extract_panic_message_from_stderr(stderr).expect("should extract");
        assert!(msg.starts_with("assertion"), "got: {msg}");
    }

    #[test]
    fn extract_panic_returns_none_for_non_panic_trap() {
        // Pure WASM unreachable — no "panicked at" in stderr.
        let stderr = "Error: memory access out of bounds";
        assert_eq!(extract_panic_message_from_stderr(stderr), None);
    }

    #[test]
    fn extract_panic_returns_none_for_empty_stderr() {
        assert_eq!(extract_panic_message_from_stderr(""), None);
    }

    #[test]
    fn extract_panic_stack_overflow_not_falsely_extracted() {
        // Stack overflow panic message — should still parse, not return None.
        let stderr = "thread '<unnamed>' panicked at 'stack overflow', src/lib.rs:0:0\n";
        let msg = extract_panic_message_from_stderr(stderr).expect("should extract");
        assert_eq!(msg, "stack overflow");
    }

    // -----------------------------------------------------------------------
    // preview_for_error — pipeline-step JSON-parse diagnostics
    // -----------------------------------------------------------------------

    #[test]
    fn preview_empty_body_distinguishable() {
        // The whole point: empty body must not collapse to `""` — that's
        // indistinguishable from a body containing two literal quotes.
        assert_eq!(preview_for_error(""), "<empty>");
    }

    #[test]
    fn preview_short_body_returned_verbatim() {
        let preview = preview_for_error("not json");
        assert!(preview.contains("not json"), "got: {preview}");
    }

    #[test]
    fn preview_long_body_head_tail_clipped() {
        let body: String = "a".repeat(800) + &"z".repeat(80);
        let preview = preview_for_error(&body);
        assert!(preview.contains("aaa"), "head missing: {preview}");
        assert!(preview.contains("zzz"), "tail missing: {preview}");
        assert!(preview.contains("chars"), "elision missing: {preview}");
        assert!(preview.len() < 600, "preview too long: {}", preview.len());
    }

    #[test]
    fn preview_strips_control_chars_keeps_newlines() {
        // Common case: WASM module wrote a NUL byte by accident.
        let body = "a\0b\nc\td";
        let preview = preview_for_error(body);
        // NUL replaced with the placeholder; \n and \t preserved (they show
        // up escaped through Debug, but the chars themselves aren't dropped).
        assert!(preview.contains('·'), "NUL not redacted: {preview}");
    }

    // -----------------------------------------------------------------------
    // describe_oversized_input — unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn describe_oversized_input_attributes_to_largest_upstream() {
        // Mirror the engine wrapping shape: __accumulated__.<source_id>.<...>.
        let big = "x".repeat(150_000);
        let small = "y".repeat(100);
        let input = serde_json::json!({
            "__accumulated__": {
                "fetch": { "body": big },
                "context": { "today": small },
            }
        });
        let report = describe_oversized_input(&input);
        // Per-upstream attribution present and ordered largest-first.
        let fetch_idx = report.find("fetch:").expect("fetch line present");
        let context_idx = report.find("context:").expect("context line present");
        assert!(
            fetch_idx < context_idx,
            "largest upstream should come first: {report}"
        );
        // Remediation hint fires for the >100KB top source.
        assert!(
            report.contains("MAX_RESPONSE_BYTES"),
            "remediation hint missing: {report}"
        );
    }

    #[test]
    fn describe_oversized_input_redacts_values() {
        // Defense in depth: payload values must NOT appear in the breakdown.
        // If a vault://-resolved secret ever lands in an upstream output,
        // the error path can't be the leak.
        let input = serde_json::json!({
            "__accumulated__": {
                "fetch": { "secret": "sk-live-leakedsecret123" }
            }
        });
        let report = describe_oversized_input(&input);
        assert!(
            !report.contains("sk-live-leakedsecret123"),
            "secret value leaked into error: {report}"
        );
        assert!(report.contains("fetch:"), "key name missing: {report}");
    }

    #[test]
    fn describe_oversized_input_falls_back_to_top_level_keys() {
        // No __accumulated__ wrapper (e.g. trigger-only input). Fall back
        // to top-level key sizes so the operator still sees attribution.
        let input = serde_json::json!({
            "config": { "URL": "https://example.com" },
            "input": { "huge_field": "x".repeat(50_000) },
        });
        let report = describe_oversized_input(&input);
        assert!(
            report.contains("Input top-level keys"),
            "fallback path not engaged: {report}"
        );
        assert!(report.contains("input:"), "input key missing: {report}");
        assert!(report.contains("config:"), "config key missing: {report}");
    }

    #[test]
    fn describe_oversized_input_handles_non_object_input() {
        // Defensive: don't panic on a non-object input (string, number, null).
        let input = serde_json::json!("a string at the root");
        let report = describe_oversized_input(&input);
        assert!(
            report.contains("not a JSON object"),
            "non-object fallback missing: {report}"
        );
    }

    #[test]
    fn describe_oversized_input_no_remediation_hint_for_small_top() {
        // When the largest upstream is below the hint threshold (100KB),
        // skip the MAX_RESPONSE_BYTES suggestion — at that scale the
        // problem is usually fanning-in too many small inputs, not one
        // oversized HTTP body.
        let input = serde_json::json!({
            "__accumulated__": {
                "a": { "v": "x".repeat(50) },
                "b": { "v": "x".repeat(50) },
            }
        });
        let report = describe_oversized_input(&input);
        assert!(
            !report.contains("MAX_RESPONSE_BYTES"),
            "remediation hint should not fire below threshold: {report}"
        );
    }
}
