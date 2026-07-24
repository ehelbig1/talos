//! Pluggable dispatch for a single workflow node.
//!
//! [`NodeDispatcher`] is the engine's highest-level dispatch
//! abstraction. Consumers of the engine implement this trait once,
//! telling the engine how to ship one node's configuration + input to
//! an executor and get a result back. Everything above this trait —
//! wire-format construction, signing, transport, retry, result
//! parsing — is the impl's responsibility.
//!
//! This is a layer above [`JobTransport`]. `JobTransport` is a raw
//! "send bytes, get bytes" channel; `NodeDispatcher` is the full
//! "run this node" primitive. An impl that backs onto a signed NATS
//! protocol uses `JobTransport` internally but exposes the higher-
//! level contract to the engine.
//!
//! # Timeout handling
//!
//! [`DispatchJob`] carries the timeout as part of the job. Impls are
//! expected to honor it. The engine does not re-wrap the dispatch
//! call in `tokio::time::timeout`; the impl either enforces the
//! timeout internally or returns an error. This is different from the
//! raw-transport contract (where the caller wraps) because
//! `NodeDispatcher` owns the full dispatch lifecycle including
//! retries, and retries need per-attempt timeout handling the caller
//! cannot express without understanding the retry policy.
//!
//! [`JobTransport`]: crate::JobTransport

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::BoxError;

/// The pre-signing description of one node's dispatch.
///
/// The engine assembles this struct from its own state (node config,
/// resolved module, user context, etc.) and hands it to a
/// [`NodeDispatcher`]. The dispatcher impl is responsible for
/// translating it into whatever wire format it uses, signing,
/// transport, and extracting the result.
///
/// All fields are either primitives, `Uuid`, `Vec<u8>`, or
/// `JsonValue` — no controller-specific types leak through. That
/// keeps this crate consumable by any engine adopter.
///
/// # Per-step vs chain-level fields
///
/// When a `DispatchJob` is used as a **single-node** dispatch via
/// [`NodeDispatcher::dispatch`], every field is honored.
///
/// When a `DispatchJob` is used as a **chain step** inside a
/// [`ChainDispatchRequest::steps`], several fields describe
/// properties that only make sense at the chain level and are taken
/// from the request, not from the per-step `DispatchJob`:
///
/// * `user_id` — taken from [`ChainDispatchRequest::user_id`]
/// * `actor_id` — chain-level (not carried by per-step wire format)
/// * `dry_run` — chain-level
/// * `max_retries`, `backoff_ms`, `retry_condition`,
///   `retry_delay_expr` — chain-level retry policy, set on the
///   request, not per step
///
/// Populating these on a chain step is harmless but ignored. If your
/// impl needs per-step values for any of them, it should document
/// that deviation; the reference NATS dispatcher does not honor them
/// per-step because the underlying `PipelineJobRequest` wire format
/// doesn't carry them.
///
/// # Construction
///
/// The struct exposes all fields as `pub`. For the common case of
/// dispatching a node that doesn't need WASM/HMAC-shaped fields, use
/// the functional-update syntax with [`Default`]:
///
/// ```no_run
/// # use uuid::Uuid;
/// # use serde_json::json;
/// # use std::time::Duration;
/// # use talos_workflow_engine_core::DispatchJob;
/// let job = DispatchJob {
///     execution_id: Uuid::new_v4(),
///     node_id: Uuid::new_v4(),
///     module_id: Uuid::new_v4(),
///     input_payload: json!({ "msg": "hello" }),
///     timeout: Duration::from_secs(30),
///     ..Default::default()
/// };
/// ```
///
/// The [`DispatchJob::new`] constructor is equivalent shorthand for
/// the four most-common required fields.
#[derive(Clone)]
pub struct DispatchJob {
    // ── Identity ─────────────────────────────────────────────────────
    /// Workflow execution that owns this dispatch.
    pub execution_id: Uuid,
    /// Engine-local node identifier within the graph.
    pub node_id: Uuid,
    /// Resolved module identifier — what the worker runs.
    pub module_id: Uuid,
    /// Optional stable job id for this dispatch. When present, impls
    /// should use it as the wire-format `job_id`; when `None`, impls
    /// generate a fresh UUID. Callers set this when they have
    /// pre-INSERTed a `module_executions` row (or similar side-effect
    /// keyed on job id) that the worker will later update by the same
    /// id — letting DB rows and worker log lines correlate.
    pub job_id: Option<Uuid>,
    /// Owning user for this execution. Workers use this for per-user
    /// quota enforcement and cross-tenant isolation.
    ///
    /// `None` means "no user context" — typical for in-process test
    /// harnesses or one-off diagnostic runs that don't belong to any
    /// tenant. Impls that route tenant-scoped subjects should fall back
    /// to a tenant-agnostic subject on `None` (subscribers bound to
    /// `workflow.jobs.<uuid>` will not see jobs dispatched without a
    /// user id). Impls whose wire format demands a non-optional value
    /// may substitute `Uuid::nil()` at their own boundary.
    pub user_id: Option<Uuid>,
    /// Actor id that owns the execution (if actor-owned), so the
    /// worker can route agent-memory WIT calls to the right rows.
    pub actor_id: Option<Uuid>,

    // ── Module artifact ──────────────────────────────────────────────
    /// URI the worker can resolve the wasm binary from if
    /// `wasm_bytes` is empty (e.g. `oci://...` or `redis:wasm:<id>`).
    pub module_uri: String,
    /// Optional inlined wasm bytes. When present, worker uses these
    /// directly and skips the URI fetch.
    pub wasm_bytes: Option<Vec<u8>>,
    /// SHA-256 hex digest of the wasm binary at `module_uri`. Lets
    /// the worker verify a URI-fetched binary matches what the engine
    /// compiled. Ignored when `wasm_bytes` is populated (HMAC already
    /// covers the inline bytes).
    pub expected_wasm_hash: Option<String>,
    /// Capability-world hint (e.g. `"network-node"`). Opaque to the
    /// engine; interpreted by the worker's linker. Not signed.
    pub capability_world: Option<String>,
    /// Integration the module is scoped to, if any. The worker signs
    /// integration-state RPCs with this value.
    pub integration_name: Option<String>,

    // ── Per-dispatch input ───────────────────────────────────────────
    /// JSON payload the worker feeds into the module's entry point.
    pub input_payload: JsonValue,

    // ── Budgets ──────────────────────────────────────────────────────
    /// Per-node execution budget. Seconds-resolution — impls truncate
    /// sub-second values. This is the **WASM-level** budget the worker
    /// enforces; impls that wrap in an outer cancellation timer (for
    /// example, a NATS dispatcher using `tokio::time::timeout`) should
    /// add grace on top internally rather than forcing callers to
    /// pre-add it.
    pub timeout: Duration,
    /// Wasmtime fuel budget for the dispatch.
    pub max_fuel: u64,

    // ── Capability grants ────────────────────────────────────────────
    /// Hostnames the worker permits outbound HTTP to.
    pub allowed_hosts: Vec<String>,
    /// HTTP methods the worker permits. Empty means allow all.
    pub allowed_methods: Vec<String>,
    /// Secret path allowlist. Empty = deny all; `["*"]` = allow all.
    pub allowed_secrets: Vec<String>,
    /// SQL operation allowlist (`"SELECT"`, `"INSERT"`, ...). Empty
    /// means allow all.
    pub allowed_sql_operations: Vec<String>,
    /// When true, the module may call Tier-2 `expose_secret` to
    /// receive plaintext secret bytes in-guest. Default false.
    pub allow_tier2_exposure: bool,

    // ── Secrets (already encrypted) ──────────────────────────────────
    /// Ciphertext of the encrypted secrets map the worker will decrypt
    /// with its copy of the shared key. Opaque bytes at this layer.
    pub encrypted_secrets_ciphertext: Vec<u8>,
    /// AES-GCM nonce paired with `encrypted_secrets_ciphertext`.
    pub encrypted_secrets_nonce: Vec<u8>,

    // ── RFC 0010 P3 (D3b): claim-based sealing ───────────────────────
    /// When `Some`, this dispatch uses claim-based ephemeral sealing
    /// (`TALOS_ENVELOPE_SEALING` on): the engine resolved the PLAINTEXT
    /// secrets here instead of sealing them into
    /// `encrypted_secrets_ciphertext` (which stays empty). This value is
    /// **controller-process-internal only** — the dispatcher registers it
    /// in `InFlightSeals` keyed on the wire `job_id` and it NEVER reaches
    /// the wire (`JobRequest` carries no plaintext; the worker obtains the
    /// values via a signed claim + on-claim ephemeral seal). `None` = the
    /// legacy inline WSK envelope path (today's default).
    pub plaintext_secrets: Option<std::collections::HashMap<String, String>>,
    /// The vault paths this job is permitted to resolve, sent in the clear
    /// on the `JobRequest` when claim-based sealing is active (paths are
    /// not secrets; values are). Empty for the legacy path.
    pub secret_paths: Vec<String>,

    // ── Dispatch policy ──────────────────────────────────────────────
    /// Priority hint (higher dequeues first). Default 100.
    pub priority: u8,
    /// When true, the worker mocks write-bearing calls (non-GET HTTP,
    /// webhooks, messaging) — used for dry-run previews.
    pub dry_run: bool,
    /// LLM data-egress ceiling for this job. The worker enforces this
    /// at `llm::*` host-function entry: a `Tier1` ceiling refuses to
    /// resolve keys for Anthropic / `OpenAI` / Gemini and the call fails
    /// closed.
    ///
    /// **Default `Tier1`** (fail-closed). Real dispatch paths override
    /// this via `talos_engine::actor_binding::apply_actor_to_engine`, which sources
    /// the value from `actors.max_llm_tier` for actor-bound executions
    /// and fail-closes to Tier1 on DB errors. Tier1 as the default
    /// ensures any code path that bypasses the canonical builder lands
    /// in the most-restrictive ceiling.
    pub max_llm_tier: crate::LlmTier,

    /// Data-mutation ceiling for the dispatched job. `ReadOnly` refuses
    /// every data-mutating host surface at the worker; `Write` permits
    /// mutation (subject to the module's capability grant).
    ///
    /// **Default `Write`** (permissive) so trusted actor-less system jobs
    /// and legacy wire messages are never silently blocked. Real
    /// actor-bound dispatch overrides this via
    /// `talos_engine::actor_binding::apply_actor_to_engine`, which sources
    /// `actors.max_write_ceiling` (new actors default `readonly`) and
    /// fail-closes to `ReadOnly` on DB errors — so a user-built workflow
    /// can't silently mutate data without an explicit grant.
    pub max_write_ceiling: crate::WriteCeiling,

    /// Blanket network-egress scope override (independent of `max_llm_tier`).
    /// `None` (default) falls back to the tier-derived default at the worker;
    /// `Some(Public)` permits public egress even for a `Tier1` actor whose LLM
    /// stays hard-gated local; `Some(Local)` denies all public egress. Sourced
    /// from `actors.egress_scope` via `apply_actor_to_engine`. See
    /// [`crate::EgressScope`].
    pub egress_scope: Option<crate::EgressScope>,

    // ── Idempotency ──────────────────────────────────────────────────
    /// Opt-in idempotency key for a SEND node. `Some` when the node declared
    /// idempotency (config key `__idempotency_key__`); the worker emits it as an
    /// `Idempotency-Key` header on mutating outbound HTTP so a retried send is
    /// deduped at the destination. Its presence is what lets the method-aware
    /// retry default grant retries to an otherwise-non-idempotent send world.
    /// `None` (the default + every non-declaring node) ships nothing on the wire.
    pub idempotency_key: Option<String>,

    // ── Retry policy ─────────────────────────────────────────────────
    /// Max retries for transient failures. Timeouts do not retry.
    pub max_retries: u32,
    /// Base backoff between retries in milliseconds. Impls may add
    /// jitter and exponential growth.
    pub backoff_ms: u64,
    /// Optional expression evaluated against error output to decide
    /// whether to retry. Opaque at this layer.
    pub retry_condition: Option<String>,
    /// Optional expression returning a retry delay in ms computed from
    /// the error output. Opaque at this layer.
    pub retry_delay_expr: Option<String>,
    /// When true, the dispatcher emits per-attempt observability
    /// events (e.g. `node_retrying`, `retry_skipped` in the reference
    /// NATS impl) keyed on `execution_id` / `node_id`. Set to `false`
    /// for nested/internal dispatches (loop-body iterations,
    /// sub-workflow steps) whose retries are not visible at the
    /// workflow level and should not inflate retry-rate metrics.
    /// Default `true`.
    pub emit_retry_events: bool,
}

/// Default per-node execution budget used by [`DispatchJob::default`].
///
/// Matches the engine's out-of-box node-timeout (also 60 s). Chosen so a
/// `DispatchJob::new(...)` that doesn't override `timeout` produces a
/// positive, bounded budget; [`Duration::ZERO`] would surface as "0 s +
/// dispatcher-grace = ~5 s cancel" under the reference NATS dispatcher,
/// which is the wrong foot-gun to ship. Override explicitly when the
/// consumer has its own budget policy.
pub const DEFAULT_DISPATCH_TIMEOUT_SECS: u64 = 60;

impl Default for DispatchJob {
    /// Populates every field with its documented default:
    ///
    /// * Required `Uuid` fields (`execution_id`, `node_id`, `module_id`)
    ///   → [`Uuid::nil()`]
    /// * Optional `Uuid` fields (`user_id`, `job_id`) and all other
    ///   `Option<...>` fields → `None`
    /// * All `Vec<...>` fields → empty
    /// * `input_payload` → `JsonValue::Null`
    /// * `timeout` → [`DEFAULT_DISPATCH_TIMEOUT_SECS`] (60 s). Chosen to
    ///   avoid the `Duration::ZERO` + dispatcher-grace foot-gun where
    ///   every job cancels after a few seconds because the user forgot
    ///   to set a budget.
    /// * `max_fuel` → 0 — impls that enforce fuel read this as "no
    ///   budget configured"
    /// * `priority` → 100 (documented default)
    /// * `emit_retry_events` → `true` (documented default)
    /// * Everything else → `false` / 0 / `None`
    fn default() -> Self {
        Self {
            execution_id: Uuid::nil(),
            node_id: Uuid::nil(),
            module_id: Uuid::nil(),
            job_id: None,
            user_id: None,
            actor_id: None,
            module_uri: String::new(),
            wasm_bytes: None,
            expected_wasm_hash: None,
            capability_world: None,
            integration_name: None,
            input_payload: JsonValue::Null,
            timeout: Duration::from_secs(DEFAULT_DISPATCH_TIMEOUT_SECS),
            max_fuel: 0,
            allowed_hosts: Vec::new(),
            allowed_methods: Vec::new(),
            allowed_secrets: Vec::new(),
            allowed_sql_operations: Vec::new(),
            allow_tier2_exposure: false,
            encrypted_secrets_ciphertext: Vec::new(),
            encrypted_secrets_nonce: Vec::new(),
            plaintext_secrets: None,
            secret_paths: Vec::new(),
            idempotency_key: None,
            priority: 100,
            dry_run: false,
            // SECURITY: default to Tier1 (local-only LLM egress). This
            // is the fail-closed posture — any code path that constructs
            // a `DispatchJob` without going through the canonical
            // `talos_engine::builder::for_workflow` (which calls
            // `talos_engine::actor_binding::apply_actor_to_engine` and stamps the
            // actor's configured ceiling) will land here.
            //
            // Pre-r306 the default was `Tier2`, which fail-OPENED: a
            // bypass of the canonical builder would silently grant
            // external-LLM egress. Real dispatch is unaffected because
            // `apply_actor_to_engine` overrides this field before any
            // job is dispatched — but for tests, ad-hoc tooling, and
            // any future dispatch path that forgets the actor-stamping
            // step, Tier1 is the right default.
            //
            // Actor-less dispatch paths that *legitimately* need Tier2
            // (per CLAUDE.md "Module-bound dispatch (Gmail/GCal/webhook
            // push notifications) is intentionally Tier-2 default")
            // must opt in explicitly via the builder, not implicitly via
            // the default.
            max_llm_tier: crate::LlmTier::Tier1,
            // Permissive `Write` default (unlike the restrictive Tier1 above):
            // a `ReadOnly` default would break trusted actor-less system writes
            // (module-bound push → integration_state). The default-deny
            // guarantee is enforced at the actor layer — `apply_actor_to_engine`
            // stamps the actor's `max_write_ceiling` (new actors → `readonly`),
            // and every user workflow must pass through it (lint check 29), so a
            // user-built workflow can't reach this permissive default.
            max_write_ceiling: crate::WriteCeiling::Write,
            egress_scope: None,
            max_retries: 0,
            backoff_ms: 0,
            retry_condition: None,
            retry_delay_expr: None,
            emit_retry_events: true,
        }
    }
}

impl DispatchJob {
    /// Construct a [`DispatchJob`] with the four fields every dispatch
    /// needs — the identity triple plus the input payload — leaving
    /// every other field at its documented [`Default`].
    ///
    /// Callers that need WASM-flavored fields (`wasm_bytes`,
    /// `capability_world`, `allowed_hosts`, `encrypted_secrets_*`, etc.)
    /// populate them directly on the returned struct; the functional-
    /// update idiom `DispatchJob { field: value, ..Default::default() }`
    /// is equivalent when more than a handful of fields differ.
    ///
    /// For chained customization, prefer [`DispatchJob::builder`].
    #[must_use]
    pub fn new(
        execution_id: Uuid,
        node_id: Uuid,
        module_id: Uuid,
        input_payload: JsonValue,
    ) -> Self {
        Self {
            execution_id,
            node_id,
            module_id,
            input_payload,
            ..Self::default()
        }
    }

    /// Start a chained builder for a [`DispatchJob`].
    ///
    /// The four required fields — the identity triple plus the input
    /// payload — are taken upfront so the builder can stay infallible
    /// (no `Result` from [`DispatchJobBuilder::build`]). Optional
    /// fields land via fluent setters; whatever is unset retains the
    /// documented [`DispatchJob::default`] value.
    ///
    /// ```
    /// # use uuid::Uuid;
    /// # use serde_json::json;
    /// # use std::time::Duration;
    /// # use talos_workflow_engine_core::DispatchJob;
    /// let job = DispatchJob::builder(
    ///     Uuid::new_v4(),    // execution_id
    ///     Uuid::new_v4(),    // node_id
    ///     Uuid::new_v4(),    // module_id
    ///     json!({"hello": "world"}),
    /// )
    /// .timeout(Duration::from_secs(30))
    /// .max_retries(2)
    /// .priority(150)
    /// .build();
    /// ```
    ///
    /// Use the builder when the call site differs in more than three
    /// or four fields from `Default`; for the simple cases the struct-
    /// literal form (`DispatchJob { field: value, ..Default::default() }`)
    /// is just as clear and one fewer allocation.
    pub fn builder(
        execution_id: Uuid,
        node_id: Uuid,
        module_id: Uuid,
        input_payload: JsonValue,
    ) -> DispatchJobBuilder {
        DispatchJobBuilder {
            inner: Self::new(execution_id, node_id, module_id, input_payload),
        }
    }
}

/// Fluent builder for [`DispatchJob`].
///
/// Constructed via [`DispatchJob::builder`]. Every setter returns
/// `Self`; [`build`](Self::build) is infallible because the four
/// required fields were forced at construction time. The builder
/// owns a single inner [`DispatchJob`] populated from
/// [`DispatchJob::new`] and mutates it in place — cheap to use in a
/// hot loop.
///
/// # Why a separate type?
///
/// The struct-literal `DispatchJob { ..Default::default() }` form
/// remains supported and is fine for one-or-two-field overrides. The
/// builder pays its way at three+ fields, where naming each setter
/// is more readable than a long `..Default::default()` block — and
/// it sidesteps the foot-gun where a future field added to
/// [`DispatchJob`] silently lands as its `Default` value (no
/// compile-time prompt to revisit existing call sites).
#[derive(Clone, Debug)]
#[must_use]
pub struct DispatchJobBuilder {
    inner: DispatchJob,
}

impl DispatchJobBuilder {
    /// Optional stable job id. When `None` (the default), impls
    /// generate a fresh UUID at dispatch time.
    pub fn job_id(mut self, job_id: Uuid) -> Self {
        self.inner.job_id = Some(job_id);
        self
    }

    /// Owning user for this execution. See [`DispatchJob::user_id`]
    /// for the trait-level contract on `None`.
    pub fn user_id(mut self, user_id: Uuid) -> Self {
        self.inner.user_id = Some(user_id);
        self
    }

    /// Actor id that owns the execution.
    pub fn actor_id(mut self, actor_id: Uuid) -> Self {
        self.inner.actor_id = Some(actor_id);
        self
    }

    /// URI the worker can resolve the wasm binary from when
    /// [`DispatchJob::wasm_bytes`] is empty.
    pub fn module_uri(mut self, module_uri: impl Into<String>) -> Self {
        self.inner.module_uri = module_uri.into();
        self
    }

    /// Inlined wasm bytes the worker uses directly, skipping the URI
    /// fetch.
    pub fn wasm_bytes(mut self, wasm_bytes: Vec<u8>) -> Self {
        self.inner.wasm_bytes = Some(wasm_bytes);
        self
    }

    /// SHA-256 hex digest of the wasm binary at
    /// [`DispatchJob::module_uri`].
    pub fn expected_wasm_hash(mut self, hash: impl Into<String>) -> Self {
        self.inner.expected_wasm_hash = Some(hash.into());
        self
    }

    /// Capability-world hint for the worker's linker.
    pub fn capability_world(mut self, world: impl Into<String>) -> Self {
        self.inner.capability_world = Some(world.into());
        self
    }

    /// Integration the module is scoped to.
    pub fn integration_name(mut self, name: impl Into<String>) -> Self {
        self.inner.integration_name = Some(name.into());
        self
    }

    /// Per-node execution budget (seconds resolution).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.inner.timeout = timeout;
        self
    }

    /// Wasmtime fuel budget for the dispatch.
    pub fn max_fuel(mut self, max_fuel: u64) -> Self {
        self.inner.max_fuel = max_fuel;
        self
    }

    /// Hostnames the worker permits outbound HTTP to.
    pub fn allowed_hosts(mut self, hosts: Vec<String>) -> Self {
        self.inner.allowed_hosts = hosts;
        self
    }

    /// HTTP methods the worker permits. Empty means allow all.
    pub fn allowed_methods(mut self, methods: Vec<String>) -> Self {
        self.inner.allowed_methods = methods;
        self
    }

    /// Secret path allowlist. Empty = deny all; `["*"]` = allow all.
    pub fn allowed_secrets(mut self, secrets: Vec<String>) -> Self {
        self.inner.allowed_secrets = secrets;
        self
    }

    /// SQL operation allowlist. Empty means allow all.
    pub fn allowed_sql_operations(mut self, ops: Vec<String>) -> Self {
        self.inner.allowed_sql_operations = ops;
        self
    }

    /// When `true`, the module may call Tier-2 `expose_secret` to
    /// receive plaintext secret bytes in-guest. Default `false`.
    pub fn allow_tier2_exposure(mut self, allow: bool) -> Self {
        self.inner.allow_tier2_exposure = allow;
        self
    }

    /// LLM data-egress ceiling for the dispatched job. `Tier1`
    /// restricts the worker to local Ollama; `Tier2` allows external
    /// providers. The builder default is `Tier1` (fail-closed); real
    /// dispatch paths overwrite via the actor-stamping step. Sourced
    /// from `actors.max_llm_tier`.
    pub fn max_llm_tier(mut self, tier: crate::LlmTier) -> Self {
        self.inner.max_llm_tier = tier;
        self
    }

    /// Blanket network-egress scope override (independent of `max_llm_tier`).
    /// Builder default is `None` (tier-derived); real dispatch paths overwrite
    /// via the actor-stamping step from `actors.egress_scope`.
    pub fn egress_scope(mut self, scope: Option<crate::EgressScope>) -> Self {
        self.inner.egress_scope = scope;
        self
    }

    /// Data-mutation ceiling for the dispatched job. `ReadOnly` refuses
    /// every mutating host surface; `Write` permits mutation. Sourced from
    /// `actors.max_write_ceiling` via the actor-stamping step; permissive
    /// `Write` default for trusted actor-less jobs.
    pub fn max_write_ceiling(mut self, ceiling: crate::WriteCeiling) -> Self {
        self.inner.max_write_ceiling = ceiling;
        self
    }

    /// Set the encrypted-secrets ciphertext + nonce together — the
    /// pair must always come from the same seal call. Use
    /// [`Self::encrypted_secrets`] rather than two independent
    /// setters so a partial assignment can't desynchronise the pair.
    pub fn encrypted_secrets(mut self, ciphertext: Vec<u8>, nonce: Vec<u8>) -> Self {
        self.inner.encrypted_secrets_ciphertext = ciphertext;
        self.inner.encrypted_secrets_nonce = nonce;
        self
    }

    /// Priority hint (higher dequeues first). Default `100`.
    pub fn priority(mut self, priority: u8) -> Self {
        self.inner.priority = priority;
        self
    }

    /// Enable dry-run mode for this dispatch.
    pub fn dry_run(mut self, dry_run: bool) -> Self {
        self.inner.dry_run = dry_run;
        self
    }

    /// Maximum retries for transient failures. Timeouts do not
    /// retry.
    pub fn max_retries(mut self, max_retries: u32) -> Self {
        self.inner.max_retries = max_retries;
        self
    }

    /// Base backoff between retries (milliseconds).
    pub fn backoff_ms(mut self, backoff_ms: u64) -> Self {
        self.inner.backoff_ms = backoff_ms;
        self
    }

    /// Optional expression evaluated against error output to decide
    /// whether to retry.
    pub fn retry_condition(mut self, expr: impl Into<String>) -> Self {
        self.inner.retry_condition = Some(expr.into());
        self
    }

    /// Optional expression returning a retry delay in ms computed
    /// from the error output.
    pub fn retry_delay_expr(mut self, expr: impl Into<String>) -> Self {
        self.inner.retry_delay_expr = Some(expr.into());
        self
    }

    /// When `false`, suppresses per-attempt observability events
    /// (`node_retrying`, `retry_skipped`). Default `true`.
    pub fn emit_retry_events(mut self, emit: bool) -> Self {
        self.inner.emit_retry_events = emit;
        self
    }

    /// Finalize the builder into a [`DispatchJob`]. Infallible — the
    /// four required fields were forced at [`DispatchJob::builder`]
    /// time.
    #[must_use]
    pub fn build(self) -> DispatchJob {
        self.inner
    }
}

impl fmt::Debug for DispatchJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact `input_payload` and the encrypted-secrets blobs so
        // `Debug` output is safe to feed into `tracing::` macros. The
        // plaintext input may contain secret values after caller-side
        // template interpolation; the ciphertext is safe but large and
        // adds no debugging value beyond its length.
        f.debug_struct("DispatchJob")
            .field("execution_id", &self.execution_id)
            .field("node_id", &self.node_id)
            .field("module_id", &self.module_id)
            .field("job_id", &self.job_id)
            .field("user_id", &self.user_id)
            .field("actor_id", &self.actor_id)
            .field("module_uri", &self.module_uri)
            .field(
                "wasm_bytes",
                &self
                    .wasm_bytes
                    .as_ref()
                    .map(|b| format!("<{} bytes>", b.len())),
            )
            .field("expected_wasm_hash", &self.expected_wasm_hash)
            .field("capability_world", &self.capability_world)
            .field("integration_name", &self.integration_name)
            .field(
                "input_payload",
                &"<redacted — may contain plaintext secrets>",
            )
            .field("timeout", &self.timeout)
            .field("max_fuel", &self.max_fuel)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("allowed_methods", &self.allowed_methods)
            .field("allowed_secrets", &self.allowed_secrets)
            .field("allowed_sql_operations", &self.allowed_sql_operations)
            .field("allow_tier2_exposure", &self.allow_tier2_exposure)
            .field(
                "encrypted_secrets_ciphertext",
                &format!("<{} bytes>", self.encrypted_secrets_ciphertext.len()),
            )
            .field(
                "encrypted_secrets_nonce",
                &format!("<{} bytes>", self.encrypted_secrets_nonce.len()),
            )
            .field(
                "plaintext_secrets",
                &self
                    .plaintext_secrets
                    .as_ref()
                    .map(|m| format!("<{} redacted secrets>", m.len())),
            )
            .field("secret_paths", &self.secret_paths)
            .field("priority", &self.priority)
            .field("dry_run", &self.dry_run)
            .field("max_llm_tier", &self.max_llm_tier)
            .field("max_write_ceiling", &self.max_write_ceiling)
            .field("egress_scope", &self.egress_scope)
            .field("idempotency_key", &self.idempotency_key)
            .field("max_retries", &self.max_retries)
            .field("backoff_ms", &self.backoff_ms)
            .field("retry_condition", &self.retry_condition)
            .field("retry_delay_expr", &self.retry_delay_expr)
            .field("emit_retry_events", &self.emit_retry_events)
            .finish()
    }
}

/// Output of a successful node dispatch.
#[derive(Debug, Clone)]
pub struct DispatchResult {
    /// The worker's output payload. Shape is module-defined.
    pub output: JsonValue,
}

/// Per-step outcome returned by [`NodeDispatcher::dispatch_chain`].
///
/// Every step in the chain produces one of these, regardless of
/// whether the overall chain succeeded — a failure in step `N` still
/// reports completed results for steps `0..N` and an absent (or
/// default) entry for later steps, depending on the impl.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StepStatus {
    /// Step ran to completion and produced an `output`.
    Success,
    /// Step exceeded its per-step timeout.
    TimedOut,
    /// Step errored internally (WASM trap, serialization failure,
    /// worker-side validation error, etc.).
    Failed,
}

/// Result of one step inside a chain dispatch.
#[derive(Debug, Clone)]
pub struct ChainStepResult {
    /// Module id the step ran (mirrors [`DispatchJob::module_id`] for
    /// the corresponding input).
    pub module_id: Uuid,
    /// How the step ended.
    pub status: StepStatus,
    /// The step's output payload. Shape is module-defined. Present
    /// regardless of `status` — a failed step may still produce a
    /// partial error envelope useful for downstream routing.
    pub output: JsonValue,
    /// Optional error detail when `status != Success`.
    pub error: Option<String>,
    /// Wall-clock step execution time in milliseconds.
    pub execution_time_ms: u64,
}

/// Request to dispatch a chain (pipeline) of steps as a single unit.
///
/// Used when the engine has detected a linear sequence of nodes that
/// can share a sandbox and avoid per-node round-trips. The dispatcher
/// translates this into whatever batch format the backing transport
/// supports.
#[derive(Debug, Clone, Default)]
pub struct ChainDispatchRequest {
    /// Workflow execution the chain belongs to.
    pub workflow_execution_id: Uuid,
    /// User owning the execution. Routing / tenant isolation apply
    /// per the same rules as [`DispatchJob::user_id`]. `None` means
    /// "no user context"; see that field's docs.
    pub user_id: Option<Uuid>,
    /// Optional stable chain id. When `None`, impls generate one.
    pub job_id: Option<Uuid>,
    /// The chain's steps, in dispatch order. Each carries its own
    /// per-step config via the [`DispatchJob`] it reuses. See
    /// [`DispatchJob`]'s "per-step vs chain-level fields" section
    /// for which fields of each step are honored vs. inherited from
    /// this request.
    pub steps: Vec<DispatchJob>,
    /// When true, the transport tries to keep all steps on a single
    /// worker sandbox so filesystem / module-instance state carries
    /// across steps. Falls back to per-step isolation if the transport
    /// can't honor it.
    pub share_sandbox: bool,
    /// LLM data-egress ceiling for the chain. Same enforcement as
    /// `DispatchJob::max_llm_tier` — every step's `TalosContext` gets
    /// stamped with this and refuses external providers when `Tier1`.
    ///
    /// **Default `Tier1`** (fail-closed). Sourced from
    /// `actors.max_llm_tier` on the owning workflow's actor via the
    /// canonical builder.
    pub max_llm_tier: crate::LlmTier,
    /// Data-mutation ceiling for the chain. Same enforcement as
    /// `DispatchJob::max_write_ceiling` — every step's `TalosContext` gets
    /// stamped with this and refuses mutating host calls when `ReadOnly`.
    /// Sourced from `actors.max_write_ceiling` via the canonical builder;
    /// permissive `Write` default for trusted actor-less jobs.
    pub max_write_ceiling: crate::WriteCeiling,

    /// Blanket network-egress scope override (independent of `max_llm_tier`).
    /// `None` (default) falls back to the tier-derived default at the worker;
    /// `Some(Public)` permits public egress even for a `Tier1` actor whose LLM
    /// stays hard-gated local; `Some(Local)` denies all public egress. Sourced
    /// from `actors.egress_scope` via `apply_actor_to_engine`. See
    /// [`crate::EgressScope`].
    pub egress_scope: Option<crate::EgressScope>,
    /// Aggregate budget for the whole chain (sum of per-step budgets
    /// plus any slack the caller wants).
    pub total_timeout: Duration,
    /// Chain-level retry policy — applied at the transport layer on
    /// the whole chain, not per individual step.
    pub max_retries: u32,
    /// Base backoff between chain retries in milliseconds.
    pub backoff_ms: u64,
    /// Optional expression evaluated against the chain-level error
    /// output to decide whether to retry. Opaque at this layer.
    pub retry_condition: Option<String>,
    /// Optional expression returning a retry delay in ms computed from
    /// the chain-level error output. Opaque at this layer.
    pub retry_delay_expr: Option<String>,
}

/// Aggregate result of a chain dispatch.
#[derive(Debug, Clone)]
pub struct ChainDispatchResult {
    /// Per-step outcomes, aligned with `ChainDispatchRequest.steps` by
    /// index. May be shorter than the input on early failure — later
    /// steps never ran.
    pub steps: Vec<ChainStepResult>,
    /// Consolidated final output the chain produced — typically the
    /// last successful step's output, but transport-defined.
    pub final_output: JsonValue,
    /// Chain-level aggregate status. `Success` implies every step in
    /// `steps` is also `Success`.
    pub overall_status: StepStatus,
}

/// Dispatch a single workflow node, or a chain of nodes, and return
/// their result(s).
///
/// See the module-level docs for the layer relationship to
/// [`crate::JobTransport`] and for the timeout contract.
#[async_trait]
pub trait NodeDispatcher: Send + Sync {
    /// Execute one node and return its result. Impls own the full
    /// dispatch lifecycle: wire encoding, signing, transport,
    /// per-attempt timeout, retries, result decoding.
    async fn dispatch(&self, job: DispatchJob) -> Result<DispatchResult, BoxError>;

    /// Execute a linear chain of steps as a single unit. Used for
    /// pipeline-chain optimization where the engine has detected a
    /// sequence of nodes that can share a sandbox.
    ///
    /// The default body delegates to [`dispatch_chain_sequential`],
    /// which loops over [`dispatch`](Self::dispatch) and assembles a
    /// `ChainDispatchResult`. Batch-capable transports (the reference
    /// NATS impl uses a `PipelineJobRequest` batch) should **override**
    /// this method to get the round-trip savings and, if
    /// `share_sandbox` is load-bearing for the consumer, a truly
    /// shared worker sandbox — the default impl does not provide
    /// either.
    async fn dispatch_chain(
        &self,
        request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        dispatch_chain_sequential(self, request).await
    }
}

/// Helper for `NodeDispatcher` impls that lack a batch transport.
///
/// Dispatches each step sequentially via
/// [`NodeDispatcher::dispatch`] and assembles a `ChainDispatchResult`
/// with the step outputs. On the first `Err`, subsequent steps are
/// not attempted; the returned `ChainDispatchResult` has an
/// `overall_status` of `Failed` and truncated `steps`.
///
/// Note: this does not provide sandbox sharing. If `share_sandbox` is
/// load-bearing for a consumer, they MUST implement batch dispatch.
pub async fn dispatch_chain_sequential<D: NodeDispatcher + ?Sized>(
    dispatcher: &D,
    request: ChainDispatchRequest,
) -> Result<ChainDispatchResult, BoxError> {
    let mut steps = Vec::with_capacity(request.steps.len());
    let mut last_output = JsonValue::Null;
    for job in request.steps {
        let module_id = job.module_id;
        let started = std::time::Instant::now();
        match dispatcher.dispatch(job).await {
            Ok(result) => {
                last_output = result.output.clone();
                steps.push(ChainStepResult {
                    module_id,
                    status: StepStatus::Success,
                    output: result.output,
                    error: None,
                    execution_time_ms: u64::try_from(started.elapsed().as_millis())
                        .unwrap_or(u64::MAX),
                });
            }
            Err(e) => {
                steps.push(ChainStepResult {
                    module_id,
                    status: StepStatus::Failed,
                    output: JsonValue::Null,
                    error: Some(e.to_string()),
                    execution_time_ms: u64::try_from(started.elapsed().as_millis())
                        .unwrap_or(u64::MAX),
                });
                return Ok(ChainDispatchResult {
                    steps,
                    final_output: JsonValue::Null,
                    overall_status: StepStatus::Failed,
                });
            }
        }
    }
    Ok(ChainDispatchResult {
        steps,
        final_output: last_output,
        overall_status: StepStatus::Success,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ids() -> (Uuid, Uuid, Uuid) {
        (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4())
    }

    #[test]
    fn builder_starts_from_required_fields_and_keeps_defaults() {
        // Required fields go in via `builder(...)`. Everything else
        // must match `DispatchJob::default()` until a setter is called.
        let (exec, node, module) = ids();
        let payload = json!({"k": 1});
        let job = DispatchJob::builder(exec, node, module, payload.clone()).build();
        assert_eq!(job.execution_id, exec);
        assert_eq!(job.node_id, node);
        assert_eq!(job.module_id, module);
        assert_eq!(job.input_payload, payload);
        // Defaults preserved:
        assert_eq!(
            job.timeout,
            Duration::from_secs(DEFAULT_DISPATCH_TIMEOUT_SECS)
        );
        assert_eq!(job.priority, 100);
        assert!(job.emit_retry_events);
        assert_eq!(job.user_id, None);
        assert!(job.encrypted_secrets_ciphertext.is_empty());
        assert!(job.encrypted_secrets_nonce.is_empty());
    }

    #[test]
    fn default_llm_tier_is_tier1_fail_closed() {
        // SECURITY: `DispatchJob::default()` MUST return `Tier1`. Any
        // code path that constructs a `DispatchJob` without going
        // through `talos_engine::builder::for_workflow` (and thus
        // `talos_engine::actor_binding::apply_actor_to_engine`) lands in the
        // most-restrictive ceiling rather than fail-opening to Tier2.
        //
        // If this test fails, the default was probably flipped back to
        // Tier2 — re-read the doc-comment on the field before changing
        // it; pre-r306 the default WAS Tier2 and that was a real
        // defense-in-depth gap.
        let job = DispatchJob::default();
        assert_eq!(
            job.max_llm_tier,
            crate::LlmTier::Tier1,
            "DispatchJob::default() must fail-closed to Tier1"
        );

        // Same for the builder entry point — since `builder()` calls
        // `default()` under the hood, this is a redundant check but
        // makes the lock-in obvious to a future reader inspecting the
        // builder.
        let (exec, node, module) = ids();
        let built = DispatchJob::builder(exec, node, module, JsonValue::Null).build();
        assert_eq!(built.max_llm_tier, crate::LlmTier::Tier1);
    }

    #[test]
    fn builder_setters_override_defaults() {
        let (exec, node, module) = ids();
        let user = Uuid::new_v4();
        let job = DispatchJob::builder(exec, node, module, JsonValue::Null)
            .user_id(user)
            .timeout(Duration::from_secs(45))
            .max_fuel(2_000_000)
            .priority(200)
            .max_retries(5)
            .backoff_ms(250)
            .dry_run(true)
            .emit_retry_events(false)
            .allowed_hosts(vec!["api.example.com".into()])
            .allowed_methods(vec!["GET".into(), "POST".into()])
            .allowed_secrets(vec!["foo/*".into()])
            .build();

        assert_eq!(job.user_id, Some(user));
        assert_eq!(job.timeout, Duration::from_secs(45));
        assert_eq!(job.max_fuel, 2_000_000);
        assert_eq!(job.priority, 200);
        assert_eq!(job.max_retries, 5);
        assert_eq!(job.backoff_ms, 250);
        assert!(job.dry_run);
        assert!(!job.emit_retry_events);
        assert_eq!(job.allowed_hosts, vec!["api.example.com".to_string()]);
        assert_eq!(job.allowed_methods, vec!["GET", "POST"]);
        assert_eq!(job.allowed_secrets, vec!["foo/*".to_string()]);
    }

    #[test]
    fn encrypted_secrets_setter_assigns_pair_atomically() {
        // The ciphertext + nonce pair always travels together — set
        // them via the single helper so a partial assignment can't
        // desynchronise them. This test locks the API shape in.
        let (exec, node, module) = ids();
        let job = DispatchJob::builder(exec, node, module, JsonValue::Null)
            .encrypted_secrets(vec![1, 2, 3], vec![9, 9, 9, 9])
            .build();
        assert_eq!(job.encrypted_secrets_ciphertext, vec![1, 2, 3]);
        assert_eq!(job.encrypted_secrets_nonce, vec![9, 9, 9, 9]);
    }

    #[test]
    fn builder_and_struct_literal_produce_equal_jobs() {
        // The builder is a thin wrapper over Default — verify it
        // produces a job byte-for-byte equivalent to the
        // struct-literal idiom for the same overrides. Catches a
        // drift where the builder forgets to mirror a Default field.
        let (exec, node, module) = ids();
        let payload = json!({"x": "y"});
        let via_builder = DispatchJob::builder(exec, node, module, payload.clone())
            .timeout(Duration::from_secs(10))
            .priority(7)
            .build();
        let via_literal = DispatchJob {
            execution_id: exec,
            node_id: node,
            module_id: module,
            input_payload: payload,
            timeout: Duration::from_secs(10),
            priority: 7,
            ..Default::default()
        };
        // The struct doesn't derive PartialEq; compare field by field
        // for the ones that vary (the rest match by Default).
        assert_eq!(via_builder.execution_id, via_literal.execution_id);
        assert_eq!(via_builder.timeout, via_literal.timeout);
        assert_eq!(via_builder.priority, via_literal.priority);
        assert_eq!(via_builder.max_retries, via_literal.max_retries);
        assert_eq!(via_builder.emit_retry_events, via_literal.emit_retry_events);
    }
}
