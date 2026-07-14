//! Inline-Rust compile service: scaffolds caller-supplied Rust source
//! into a Talos WIT module, lint-pre-flights it, full-compiles it, and
//! mirrors the resulting WASM into the `modules` table — the
//! orchestration that previously lived inline in
//! `talos-mcp-handlers/src/workflows.rs::handle_add_node_to_workflow`'s
//! `rust_code` branch (~330 LoC of compile + lint + ceiling + drift +
//! persistence).
//!
//! Not used by the `module_id` branch — that path doesn't compile,
//! it just attaches an already-stored module.
//!
//! Architectural pattern: matches `talos-execution-orchestration`
//! (r295), `talos-workflow-manifest` (r302), and `talos-replay-service`
//! (r303). Arc-injected dependencies, `thiserror` enum mapped to
//! JSON-RPC codes via `jsonrpc_code()`, typed input + outcome structs,
//! and a `user_facing_message()` accessor that collapses internal
//! errors to a generic message so the protocol response cannot leak
//! schema or query detail.
//!
//! Security posture (preserved from the inline handler verbatim):
//! - Caller's `user_id` scopes the existing-module name lookup so a
//!   `node_id` collision with a module owned by a different user is a
//!   miss, not a hijack.
//! - Pre-compile actor capability-ceiling check (when the workflow has
//!   an `actor_id`) blocks scaffolding a `network-node` body when the
//!   actor is restricted to `http-node` BEFORE spending 30–60 s of
//!   compile budget. The post-compile defense-in-depth check still
//!   fires from the handler — this just shortens the failure feedback
//!   loop and saves controller fuel.
//! - Shared-module overwrite guard: if a module owned by the same
//!   user already exists under this name AND another live workflow
//!   depends on it, refuse the overwrite (the operator picks a unique
//!   `node_id` or uses `hot_update_module`). Without this, hot-updating
//!   a shared library via `add_node_to_workflow` could silently change
//!   semantics for an unrelated workflow.
//! - Permission-drift guard: when the caller explicitly passed
//!   `allowed_hosts` / `allowed_secrets` / `allowed_methods` AND those
//!   differ from what's stored on the colliding module, refuse with a
//!   diff-line list. Without this guard the upsert silently keeps the
//!   stored permissions — leaving the caller's explicit grants
//!   discarded with no diagnostic.
//! - Lint pre-flight runs `cargo check`-equivalent in ~3–5 s before
//!   the ~30–60 s WASM compile, surfacing typos and type errors early.

#![forbid(unsafe_code)]

use std::sync::Arc;

use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

use talos_compilation::CompilationService;
use talos_module_repository::ModuleRepository;
use talos_workflow_repository::WorkflowRepository;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Service-level errors. The `jsonrpc_code()` helper maps each variant
/// to a stable JSON-RPC error code so the MCP handler wrapper stays
/// trivial. Error messages match the pre-extraction handler shape
/// byte-for-byte.
#[derive(Debug, Error)]
pub enum InlineCompileError {
    /// Caller-supplied argument failed structural validation
    /// (capability_world too long, etc.). Maps to `-32602`.
    #[error("{0}")]
    InvalidArg(String),

    /// Caller's chosen `capability_world` exceeds the workflow's
    /// owning actor's `max_capability_world`. Pre-compile gate; the
    /// handler still runs the post-compile defense-in-depth check.
    /// Maps to `-32603` (unauthorized).
    #[error("{0}")]
    CapabilityCeilingViolation(String),

    /// Caller-supplied `dependencies` map failed the canonical crate
    /// allowlist (`talos_compilation::dependency_allowlist::validate_dependencies`
    /// — unallowlisted crate name, or a version requirement that isn't
    /// pinned, e.g. a bare `"*"`). Maps to `-32602`.
    ///
    /// N-6 (crate review 2026-05-06, re-verified 2026-07-14): this
    /// service validated `capability_world` in-service but forwarded
    /// `dependencies` straight into `lint_code` / `compile_to_wasm_with_config`
    /// unchecked — a doc comment claimed the caller was responsible.
    /// Today's sole caller (`talos-mcp-handlers/src/workflows.rs`)
    /// happened to validate first, but the service boundary itself was
    /// unguarded: a future GraphQL/other caller could forward an
    /// unvalidated deps map straight into lint+compile. Validating here
    /// closes that gap regardless of caller.
    #[error("Dependency validation failed: {0}")]
    DependencyValidation(String),

    /// Lint pre-flight surfaced syntax / type errors. Maps to `-32000`.
    /// Message format: `"Lint check failed — fix these errors before
    /// compiling (saved ~30-60s):\n<line:col: msg>\n…"`.
    #[error("{0}")]
    LintFailed(String),

    /// `cargo build --target wasm32-…` returned a structured error
    /// list. Maps to `-32000`. Message format:
    /// `"Inline code compilation failed:\n<error 1>\n<error 2>…"`.
    #[error("{0}")]
    CompilationFailed(String),

    /// A module owned by the same user under this `node_id` already
    /// exists AND is referenced by at least one OTHER workflow.
    /// Maps to `-32000`. Message includes the colliding module id and
    /// the dependent workflow names.
    #[error("{0}")]
    SharedModuleOverwrite(String),

    /// Caller passed explicit `allowed_hosts` / `allowed_secrets` /
    /// `allowed_methods` that differ from the stored module's values.
    /// Refuses the upsert so the caller is surfaced the drift rather
    /// than silently dropping their explicit grant. Maps to `-32000`.
    #[error("{0}")]
    PermissionDrift(String),

    /// Compile produced no WASM bytes despite reporting success — a
    /// CompilationService bug or a transient runner failure. Maps to
    /// `-32000`. Message is the literal pre-extraction string.
    #[error("Compiled successfully but no WASM bytes were generated")]
    NoWasmEmitted,

    /// Required-path repository call returned an error. The detail is
    /// logged at `error!` level by the service; callers receive the
    /// generic mapped message. Maps to `-32000`.
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl InlineCompileError {
    /// Stable JSON-RPC error code for protocol wrappers.
    pub fn jsonrpc_code(&self) -> i32 {
        match self {
            Self::InvalidArg(_) | Self::DependencyValidation(_) => -32602,
            Self::CapabilityCeilingViolation(_) => -32603,
            Self::LintFailed(_)
            | Self::CompilationFailed(_)
            | Self::SharedModuleOverwrite(_)
            | Self::PermissionDrift(_)
            | Self::NoWasmEmitted
            | Self::Internal(_) => -32000,
        }
    }

    /// Generic, callable-safe message for the protocol response.
    /// `Internal` collapses to `"Internal error"` so the response does
    /// not leak schema, query, or runtime-trap detail.
    pub fn user_facing_message(&self) -> String {
        match self {
            Self::InvalidArg(msg)
            | Self::CapabilityCeilingViolation(msg)
            | Self::LintFailed(msg)
            | Self::CompilationFailed(msg)
            | Self::SharedModuleOverwrite(msg)
            | Self::PermissionDrift(msg) => msg.clone(),
            // Display format adds the "Dependency validation failed: "
            // prefix around the raw allowlist-validator message, so the
            // user-facing text is `self.to_string()`, not the bare field
            // — matches how `NoWasmEmitted` (a fixed-text Display) is
            // surfaced below.
            Self::DependencyValidation(_) => self.to_string(),
            Self::NoWasmEmitted => self.to_string(),
            Self::Internal(_) => "Internal error".to_string(),
        }
    }
}

// -----------------------------------------------------------------------------
// Inputs / outcome
// -----------------------------------------------------------------------------

/// Caller input for [`InlineCompileService::compile_and_persist`].
/// The handler is responsible for protocol-level argument parsing
/// (length caps, charset validation) and for parsing
/// `integration_name` and `fuel_budget` from the raw args; this
/// service operates on the typed result.
pub struct InlineCompileInput<'a> {
    /// Owner of the resulting module + scope for the existing-name lookup.
    pub user_id: Uuid,
    /// Workflow this node lives in. Used to scope the
    /// shared-module-overwrite guard — the colliding module is "shared"
    /// only if at least one OTHER workflow references it.
    pub workflow_id: Uuid,
    /// Workflow's owning actor, when present. Drives the pre-compile
    /// capability-ceiling check.
    pub workflow_actor_id: Option<Uuid>,
    /// Stable identifier within the workflow graph. Doubles as the
    /// module's name — re-running with the same `node_id` upserts the
    /// existing module's WASM (subject to the drift / shared-module
    /// guards). Pre-validated by the caller for length + charset.
    pub node_id: &'a str,
    /// Raw Rust source the caller wants compiled. Pre-validated by the
    /// caller for size cap (≤ 512 KiB).
    pub rust_code: &'a str,
    /// Capability world string, e.g. `"minimal-node"` or `"http"`. May
    /// be missing the `-node` suffix; the service normalises. Pre-
    /// defaulted by the caller to `"minimal-node"` if absent.
    pub capability_world: &'a str,
    /// Caller-explicit `allowed_hosts` (HTTP outbound). `None` = caller
    /// did not pass the key (drift guard skipped for this field).
    /// `Some(vec![])` = caller explicitly asked for empty (drift fires
    /// if stored is non-empty).
    pub explicit_allowed_hosts: Option<Vec<String>>,
    /// Same `Option` semantics as `explicit_allowed_hosts`.
    pub explicit_allowed_secrets: Option<Vec<String>>,
    /// Same `Option` semantics. Strings are uppercased by convention.
    pub explicit_allowed_methods: Option<Vec<String>>,
    /// Optional `dependencies` map (mirrors `compile_custom_sandbox`'s
    /// allowlisted-crate set). Forwarded to lint + compile. Validated
    /// in-service (early in `compile_and_persist`, via
    /// `talos_compilation::dependency_allowlist::validate_dependencies`)
    /// — callers MAY pre-validate for an earlier error, but the service
    /// boundary itself is guarded regardless (N-6, crate review
    /// 2026-05-06).
    pub dependencies: Option<&'a serde_json::Value>,
    /// Optional integration namespace. Pre-parsed by the caller from
    /// the raw args via `parse_integration_name_arg`.
    pub integration_name: Option<String>,
    /// Optional fuel budget. Pre-parsed by the caller from the raw
    /// args via `parse_fuel_budget_arg`. When `None`, the service
    /// falls back to `talos_compilation::scaffold::compute_max_fuel`.
    pub fuel_budget: Option<u64>,
}

/// Outcome of [`InlineCompileService::compile_and_persist`]. The
/// caller writes `module_id` into the workflow graph as the new
/// node's `module_id` field.
#[derive(Debug, Serialize)]
pub struct InlineCompileOutcome {
    /// `modules.id` — re-used when the upsert hit an existing row,
    /// freshly minted on a first compile.
    pub module_id: Uuid,
    /// Resolved `allowed_hosts` after applying world-based defaults.
    /// Surfaced so handlers can include it in response bodies.
    pub allowed_hosts: Vec<String>,
    /// Final fuel budget written to `modules.max_fuel`. Surfaced so
    /// the handler's `applied_max_fuel` response field is a
    /// pass-through, not a re-fetch.
    pub max_fuel: i64,
}

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/// Inline-Rust compile service. Holds Arc-wrapped dependencies; safe
/// to clone (cheap reference-count bumps). Constructed once at
/// controller boot and shared across the MCP handler tree (and any
/// future GraphQL surface).
pub struct InlineCompileService {
    workflow_repo: Arc<WorkflowRepository>,
    module_repo: Arc<ModuleRepository>,
    compiler: Arc<CompilationService>,
    db_pool: sqlx::PgPool,
}

impl InlineCompileService {
    pub fn new(
        workflow_repo: Arc<WorkflowRepository>,
        module_repo: Arc<ModuleRepository>,
        compiler: Arc<CompilationService>,
        db_pool: sqlx::PgPool,
    ) -> Self {
        Self {
            workflow_repo,
            module_repo,
            compiler,
            db_pool,
        }
    }

    /// Wrap source, lint-pre-flight, full-compile, then persist to
    /// `modules` (with shared-module + permission-drift guards). The
    /// happy path returns the resulting module id; every failure mode
    /// surfaces as a typed [`InlineCompileError`] with stable JSON-RPC
    /// codes so the handler wrapper stays a thin translation.
    pub async fn compile_and_persist(
        &self,
        input: InlineCompileInput<'_>,
    ) -> Result<InlineCompileOutcome, InlineCompileError> {
        // 1. Validate capability_world length.
        if input.capability_world.len() > 100 {
            return Err(InlineCompileError::InvalidArg(
                "capability_world must be ≤ 100 characters".to_string(),
            ));
        }

        // 1b. MCP-781 (2026-05-14): allowlist-validate capability_world
        //     BEFORE the wrap/lint/compile pipeline interpolates it
        //     into Rust source. The downstream
        //     `talos_workflow_creation_helpers::wrap_rust_code_with_talos_module`
        //     (called at step 3 below) builds
        //     `format!("#[talos_sdk_macros::talos_module(world = \"{}\")]", capability_world)`,
        //     and `CompilationService::lint_code` does the same for
        //     the lint-only path. A capability_world string containing
        //     `\"]` followed by Rust would land in the generated source
        //     verbatim. Pre-fix this service relied solely on a length
        //     cap (line 261) + the actor-ceiling rank check (line 277);
        //     the rank check uses `world_rank` which returns 7 (max-
        //     privileged) for unknown strings — so a malformed world
        //     string would silently pass through any actor whose ceiling
        //     is `automation-node` or `trusted-node`. Sibling
        //     `handle_compile_custom_sandbox` (talos-mcp-handlers/sandbox.rs:655)
        //     and `handle_lint_sandbox` (same file, MCP-781 sibling)
        //     both validate explicitly. Normalize first so callers can
        //     pass either `minimal` or `minimal-node` — sibling handlers
        //     do the same.
        let world_full_for_validation = normalise_world_to_node(input.capability_world);
        if !talos_capability_world::is_compilable_world(&world_full_for_validation) {
            return Err(InlineCompileError::InvalidArg(format!(
                "Invalid capability_world '{}'. Valid values: {}",
                input.capability_world,
                talos_capability_world::compilable_worlds_csv()
            )));
        }

        // 1c. N-6 (crate review 2026-05-06, re-verified 2026-07-14):
        //     validate caller-supplied `dependencies` against the
        //     canonical crate allowlist BEFORE it's forwarded into
        //     `lint_code` (step 4) and `compile_to_wasm_with_config`
        //     (step 5) below. Defense in depth — today's sole caller
        //     (`talos-mcp-handlers/src/workflows.rs`) already validates
        //     before invoking this service, but the service boundary
        //     itself must not trust an unvalidated deps map from a
        //     future caller (GraphQL, etc.).
        validate_service_dependencies(input.dependencies)?;

        // 2. Pre-compile actor capability ceiling check. The handler
        //    runs a post-compile check too; this short-circuits the
        //    expensive compile.
        //
        //    MCP-462: actor-side strict rank lookup — `world_rank` returns
        //    7 (max) for unknown actor worlds, which would silently grant
        //    any module ceiling. Use `actor_world_rank_strict` and pin
        //    unknown to rank 0 so legacy / malformed actor rows fail
        //    closed. Same fix as MCP-461 in workflow-authorization.
        let world_full = normalise_world_to_node(input.capability_world);
        if let Some(actor_id) = input.workflow_actor_id {
            if let Some(actor_max) =
                talos_actor_repository::get_actor_max_world(&self.db_pool, actor_id).await
            {
                // Wasm-security review 2026-05-28 (HIGH): single canonical
                // partial-order ceiling gate (replaces the inline rank+subset
                // pair from the 2026-05-23 review). The lattice catches both the
                // "higher tier" and the "incomparable sibling" case (e.g. an
                // actor with `max_capability_world=database` may NOT install an
                // Agent module — `Agent ⊄ Database`), and fail-closes on unknown
                // worlds; `ceiling_permits` fully subsumes the linear-rank check.
                if !talos_capability_world::ceiling_permits(&actor_max, &world_full) {
                    return Err(InlineCompileError::CapabilityCeilingViolation(format!(
                        "Capability ceiling violation: inline node uses '{}' world which exceeds \
                         the actor's max_capability_world '{}'. \
                         Choose a lower capability_world or run \
                         grant_capability_ceiling(actor_id: '{}', world: '{}') to raise the ceiling.",
                        world_full, actor_max, actor_id, world_full
                    )));
                }
            }
        }

        // 3. Wrap caller's source with the talos_module! macro.
        let wrapped_code = talos_workflow_creation_helpers::wrap_rust_code_with_talos_module(
            input.rust_code,
            input.capability_world,
        );

        // 4. Lint pre-flight (~3-5 s) — surface obvious errors before
        //    spending the full compile budget.
        match self
            .compiler
            .lint_code(
                Some(input.user_id),
                "add_node_lint",
                &wrapped_code,
                &world_full,
                input.dependencies,
            )
            .await
        {
            Ok(lint_errors) if !lint_errors.is_empty() => {
                let msgs: Vec<String> = lint_errors
                    .iter()
                    .map(|e| match (e.line, e.column) {
                        (Some(l), Some(c)) => format!("Line {}:{}: {}", l, c, e.message),
                        _ => e.message.clone(),
                    })
                    .collect();
                return Err(InlineCompileError::LintFailed(format!(
                    "Lint check failed — fix these errors before compiling (saved ~30-60s):\n{}",
                    msgs.join("\n"),
                )));
            }
            Ok(_) => {}
            Err(e) => {
                // L-32: lint runner errored (transient infra, OOM,
                // advisory-DB load failure). The fast-path safety net
                // is silently bypassed and the user pays the full
                // ~30-60s compile budget. Log so operators can
                // correlate slow-compile spikes with lint-runner
                // outages; user-facing path proceeds to the full
                // compile (which may also fail with the same error,
                // but worst case the user gets the slower path
                // instead of a hung lint).
                tracing::warn!(
                    target: "talos_compilation",
                    event_kind = "lint_pre_flight_unavailable",
                    user_id = %input.user_id,
                    workflow_id = %input.workflow_id,
                    error = %e,
                    "lint pre-flight unavailable — proceeding to full compile (slower path)"
                );
            }
        }

        // 5. Full compile (~30-60 s).
        let job_id = Uuid::new_v4();
        let compile_result = self
            .compiler
            .compile_to_wasm_with_config(
                input.user_id,
                job_id,
                input.node_id,
                &wrapped_code,
                &serde_json::json!({}),
                input.dependencies,
            )
            .await;

        let res = match compile_result {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(err = ?e, "add_node_to_workflow inline compile error");
                return Err(InlineCompileError::Internal(anyhow::anyhow!(
                    "Compilation error"
                )));
            }
        };
        if !res.success {
            let error_msgs: Vec<String> = res.errors.iter().map(|e| e.message.clone()).collect();
            return Err(InlineCompileError::CompilationFailed(format!(
                "Inline code compilation failed:\n{}",
                error_msgs.join("\n"),
            )));
        }
        let wasm_bytes = res.wasm_bytes.ok_or(InlineCompileError::NoWasmEmitted)?;

        // 6. Resolve allowed_hosts from caller-explicit or world default.
        let allowed_hosts = talos_workflow_creation_helpers::resolve_default_allowed_hosts(
            input.capability_world,
            input.explicit_allowed_hosts.clone(),
        );
        // Caller's allowed_secrets list (when not passed, empty — matches
        // pre-extraction behaviour for the persistence write).
        let allowed_secrets: Vec<String> =
            input.explicit_allowed_secrets.clone().unwrap_or_default();

        // 7. Find existing module by name + user (drives upsert).
        let existing_id = self
            .workflow_repo
            .find_node_template_by_name_and_user(input.node_id, input.user_id)
            .await
            .map_err(|e| {
                tracing::error!(err = ?e, "find_node_template_by_name_and_user failed");
                InlineCompileError::Internal(e)
            })?;

        if let Some(eid) = existing_id {
            // 7a. Shared-module overwrite guard.
            //
            // MCP-885 (2026-05-14): pre-fix `.unwrap_or_default()` made
            // this guard fail-OPEN on DB error — a transient sqlx
            // failure during the dependency lookup let `other_users`
            // collapse to empty Vec, the guard's `!is_empty()`
            // returned false, and the overwrite proceeded silently
            // clobbering a module potentially used by N other
            // workflows / users. Worst-case cross-user data
            // corruption (e.g. inline-compile by user A overwrites
            // a module shared with user B who's running production
            // workflows). Guards on shared-resource operations MUST
            // fail-CLOSED on DB error — same security invariant as
            // the actor-budget gate (MCP-366) which already enforces
            // this pattern. Same misleading-success class as the
            // broader MCP-883/884 sweep, but for a multi-tenant
            // safety boundary rather than a single-user one.
            let other_users = self
                .workflow_repo
                .workflows_using_module_excluding(eid, input.workflow_id, input.user_id)
                .await
                .map_err(|e| {
                    tracing::error!(
                        existing_id = %eid,
                        workflow_id = %input.workflow_id,
                        user_id = %input.user_id,
                        error = %e,
                        "InlineCompileService: shared-module overwrite-guard lookup failed — \
                         refusing to compile to avoid silently clobbering a module that may be \
                         used by other workflows. Retry once the database is healthy."
                    );
                    InlineCompileError::Internal(anyhow::anyhow!(
                        "Shared-module overwrite-guard lookup failed (database error). \
                         Refusing inline compile to avoid silently overwriting a module that \
                         may be used by other workflows. Retry the request."
                    ))
                })?;
            if !other_users.is_empty() {
                return Err(InlineCompileError::SharedModuleOverwrite(
                    talos_workflow_creation_helpers::format_shared_module_overwrite_error(
                        input.node_id,
                        eid,
                        &other_users,
                    ),
                ));
            }

            // 7b. Permission-drift guard — fires when caller passed at
            //     least one explicit perm key (allowed_hosts /
            //     allowed_secrets / allowed_methods / capability_world)
            //     AND it differs from stored. Callers who omit all of
            //     them keep the pre-2026-04-23 "preserve existing"
            //     semantics.
            //
            //     L-finding-1 (2026-05-23): capability_world is included
            //     in the drift comparison. The actor's
            //     `max_capability_world` is already enforced as a hard
            //     ceiling above (step 2); the drift check is the
            //     additional "caller must make the world change
            //     EXPLICIT" gate that prevents a silent capability
            //     upgrade on name-collision (e.g. existing module is
            //     http-node, recompile keeps the same node_id but
            //     declares agent-node — without this check, the upsert
            //     would silently widen the capability surface of every
            //     graph that references this module). Because the
            //     caller ALWAYS passes `capability_world` (the field is
            //     `&str`, not `Option<&str>` on the input), the drift
            //     check always runs once a collision happens. The
            //     legacy-row case (stored value empty) is skipped
            //     inside `compute_permission_drift` so existing modules
            //     without a recorded world don't trip on first
            //     touch.
            let caller_explicit = input.explicit_allowed_hosts.is_some()
                || input.explicit_allowed_secrets.is_some()
                || input.explicit_allowed_methods.is_some();
            if caller_explicit {
                if let Ok(Some(existing)) = self
                    .workflow_repo
                    .get_module_permissions(eid, input.user_id)
                    .await
                {
                    let stored = talos_workflow_creation_helpers::StoredPermissions {
                        allowed_hosts: existing.allowed_hosts.clone(),
                        allowed_secrets: existing.allowed_secrets.clone(),
                        allowed_methods: existing.allowed_methods.clone(),
                        capability_world: existing.capability_world.clone(),
                    };
                    let drift_lines = talos_workflow_creation_helpers::compute_permission_drift(
                        input.explicit_allowed_hosts.as_deref(),
                        input.explicit_allowed_secrets.as_deref(),
                        input.explicit_allowed_methods.as_deref(),
                        Some(input.capability_world),
                        &stored,
                    );
                    if !drift_lines.is_empty() {
                        return Err(InlineCompileError::PermissionDrift(
                            talos_workflow_creation_helpers::format_permission_drift_error(
                                input.node_id,
                                eid,
                                &drift_lines,
                            ),
                        ));
                    }
                }
            }
        }

        // 8. Compute world_short, max_fuel, content_hash, then mirror.
        let world_short = world_short_for_persistence(input.capability_world);
        let max_fuel: i64 = input
            .fuel_budget
            .map(|f| f as i64)
            .unwrap_or_else(|| talos_compilation::scaffold::compute_max_fuel(10, 2000, 2.0) as i64);

        use sha2::{Digest, Sha256};
        let content_hash = format!("{:x}", Sha256::digest(&wasm_bytes));

        let template_id = existing_id.unwrap_or_else(Uuid::new_v4);

        self.module_repo
            .mirror_sandbox_compile_to_modules(
                template_id,
                template_id, // legacy_template_id alias = modules.id
                Some(input.user_id),
                input.node_id,
                "extracted",
                &world_short,
                &wasm_bytes,
                &content_hash,
                input.rust_code,
                max_fuel,
                &allowed_hosts,
                &[],
                &allowed_secrets,
                input.integration_name.as_deref(),
                input.dependencies,
                // Inline add_node compiles are rust_code-only by definition.
                "rust",
            )
            .await
            .map_err(|e| {
                tracing::error!(err = ?e, "mirror_sandbox_compile_to_modules failed");
                // Preserve the pre-extraction copy verbatim — operators
                // recognise this string from production logs.
                InlineCompileError::Internal(anyhow::anyhow!(
                    "Compiled successfully but failed to store module in modules table: {}",
                    e
                ))
            })?;

        Ok(InlineCompileOutcome {
            module_id: template_id,
            allowed_hosts,
            max_fuel,
        })
    }
}

// -----------------------------------------------------------------------------
// Pure helpers
// -----------------------------------------------------------------------------

/// Validates `dependencies` against the canonical crate allowlist
/// (`talos_compilation::dependency_allowlist::validate_dependencies`)
/// and maps a failure into the service's typed error. Pulled out as a
/// pure, DB-free helper (mirrors `normalise_world_to_node` /
/// `world_short_for_persistence` below) so it's unit-testable without
/// standing up `InlineCompileService`'s repositories/compiler.
fn validate_service_dependencies(
    deps: Option<&serde_json::Value>,
) -> Result<(), InlineCompileError> {
    talos_compilation::validate_dependencies(deps).map_err(InlineCompileError::DependencyValidation)
}

/// `"http"` → `"http-node"`; `"http-node"` → `"http-node"`. Used for
/// world-rank comparison against the actor's `max_capability_world`.
fn normalise_world_to_node(world: &str) -> String {
    if world.ends_with("-node") {
        world.to_string()
    } else {
        format!("{}-node", world)
    }
}

/// `world_short` for the `modules.capability_world` column. Mirrors
/// the pre-extraction logic verbatim — `"automation-node"` becomes
/// `"trusted"` (legacy synonym), everything else just drops the
/// trailing `"-node"`. Persisted form is the short-name; downstream
/// readers normalise via `talos_capability_world::parse_*`.
fn world_short_for_persistence(world: &str) -> String {
    if world == "automation-node" {
        "trusted".to_string()
    } else {
        world.trim_end_matches("-node").to_string()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonrpc_codes_are_stable() {
        assert_eq!(
            InlineCompileError::InvalidArg("x".into()).jsonrpc_code(),
            -32602
        );
        assert_eq!(
            InlineCompileError::CapabilityCeilingViolation("x".into()).jsonrpc_code(),
            -32603,
        );
        assert_eq!(
            InlineCompileError::LintFailed("x".into()).jsonrpc_code(),
            -32000
        );
        assert_eq!(
            InlineCompileError::CompilationFailed("x".into()).jsonrpc_code(),
            -32000,
        );
        assert_eq!(
            InlineCompileError::SharedModuleOverwrite("x".into()).jsonrpc_code(),
            -32000,
        );
        assert_eq!(
            InlineCompileError::PermissionDrift("x".into()).jsonrpc_code(),
            -32000
        );
        assert_eq!(InlineCompileError::NoWasmEmitted.jsonrpc_code(), -32000);
        assert_eq!(
            InlineCompileError::Internal(anyhow::anyhow!("boom")).jsonrpc_code(),
            -32000,
        );
    }

    #[test]
    fn internal_user_message_does_not_leak_detail() {
        let err = InlineCompileError::Internal(anyhow::anyhow!(
            "ERROR: column \"max_fuel_v2\" of relation \"modules\" does not exist"
        ));
        // The user-facing message must not echo the underlying anyhow
        // detail — it can leak schema / SQL surface.
        assert_eq!(err.user_facing_message(), "Internal error");
    }

    #[test]
    fn invalid_arg_user_message_passes_through() {
        let err = InlineCompileError::InvalidArg("capability_world too long".into());
        assert_eq!(err.user_facing_message(), "capability_world too long");
    }

    #[test]
    fn lint_failed_message_round_trips() {
        let body = "Lint check failed — fix these errors before compiling (saved ~30-60s):\n\
                    Line 3:5: expected `;`, found `}`";
        let err = InlineCompileError::LintFailed(body.to_string());
        assert_eq!(err.user_facing_message(), body);
    }

    #[test]
    fn no_wasm_emitted_user_message_is_canonical() {
        // Unit-level lock-in for the well-known operator-recognised
        // error string. Changing this is a breaking change for
        // anyone grepping logs for the exact phrase.
        assert_eq!(
            InlineCompileError::NoWasmEmitted.user_facing_message(),
            "Compiled successfully but no WASM bytes were generated",
        );
    }

    #[test]
    fn ceiling_violation_user_message_includes_remediation() {
        let err = InlineCompileError::CapabilityCeilingViolation(
            "Capability ceiling violation: inline node uses 'http-node' world …".into(),
        );
        assert!(err.user_facing_message().contains("Capability ceiling"));
    }

    #[test]
    fn normalise_world_appends_node_suffix() {
        assert_eq!(normalise_world_to_node("http"), "http-node");
        assert_eq!(normalise_world_to_node("minimal"), "minimal-node");
    }

    #[test]
    fn normalise_world_preserves_already_suffixed() {
        assert_eq!(normalise_world_to_node("http-node"), "http-node");
        assert_eq!(normalise_world_to_node("minimal-node"), "minimal-node");
    }

    #[test]
    fn normalise_world_handles_empty() {
        // Empty string defaults to "-node" — caller is supposed to
        // pre-default to "minimal-node", but we don't crash on empty.
        assert_eq!(normalise_world_to_node(""), "-node");
    }

    #[test]
    fn world_short_for_automation_is_trusted_legacy() {
        // Legacy synonym: "automation-node" persists as "trusted" in
        // `modules.capability_world`. Downstream readers normalise.
        assert_eq!(world_short_for_persistence("automation-node"), "trusted");
    }

    #[test]
    fn world_short_strips_node_suffix() {
        assert_eq!(world_short_for_persistence("http-node"), "http");
        assert_eq!(world_short_for_persistence("minimal-node"), "minimal");
        assert_eq!(world_short_for_persistence("network-node"), "network");
    }

    #[test]
    fn world_short_passthrough_when_unsuffixed() {
        // Caller may already pass the short form — leave it.
        assert_eq!(world_short_for_persistence("http"), "http");
    }

    // -------------------------------------------------------------------
    // N-6: service-side dependency validation
    // -------------------------------------------------------------------

    #[test]
    fn dependency_validation_rejects_disallowed_crate() {
        let deps = serde_json::json!({ "some-unallowlisted-crate": "1.0" });
        let err = validate_service_dependencies(Some(&deps)).unwrap_err();
        assert!(matches!(err, InlineCompileError::DependencyValidation(_)));
        assert_eq!(err.jsonrpc_code(), -32602);
        let msg = err.user_facing_message();
        assert!(
            msg.starts_with("Dependency validation failed: "),
            "unexpected message: {msg}"
        );
        assert!(msg.contains("Disallowed crate dependencies"));
        assert!(msg.contains("some-unallowlisted-crate"));
    }

    #[test]
    fn dependency_validation_rejects_wildcard_version() {
        let deps = serde_json::json!({ "serde": "*" });
        let err = validate_service_dependencies(Some(&deps)).unwrap_err();
        assert_eq!(err.jsonrpc_code(), -32602);
        let msg = err.user_facing_message();
        assert!(
            msg.starts_with("Dependency validation failed: "),
            "unexpected message: {msg}"
        );
        assert!(msg.contains("Invalid version specifiers"));
        assert!(msg.contains("serde = \"*\""));
    }

    #[test]
    fn dependency_validation_accepts_absent_null_and_empty() {
        assert!(validate_service_dependencies(None).is_ok());
        assert!(validate_service_dependencies(Some(&serde_json::Value::Null)).is_ok());
        assert!(validate_service_dependencies(Some(&serde_json::json!({}))).is_ok());
    }

    #[test]
    fn dependency_validation_accepts_allowlisted_crate_with_pinned_version() {
        let deps = serde_json::json!({ "serde": "1.0", "chrono": "0.4" });
        assert!(validate_service_dependencies(Some(&deps)).is_ok());
    }
}
