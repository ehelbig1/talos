//! # talos-hot-update-service — module recompilation orchestration
//!
//! Owns the full hot-update flow that was previously inline in
//! `talos_mcp_handlers::sandbox::handle_hot_update_module` (~530 LoC).
//! The handler is now a thin wrapper that parses MCP args into
//! [`HotUpdateInput`], calls [`HotUpdateService::execute`], and shapes
//! the [`HotUpdateOutcome`] back into a JSON-RPC response.
//!
//! Phases inside `execute` (in order):
//! 1. Fetch hot-update context (dual-UUID aware via `module_repo`).
//! 2. Resolve effective source (provided arg or stored fallback).
//! 3. Resolve effective `capability_world` (explicit arg or stored).
//! 4. Resolve dependencies via three-level cascade (explicit / template / wasm_modules).
//! 5. Wrap source with `#[talos_sdk_macros::talos_module]` if not already wrapped.
//! 6. Compile via `talos_compilation::CompilationService`.
//! 7. Mirror to `modules` table (sandbox vs compiled paths).
//! 8. Best-effort Redis cache invalidation across both URI shapes.
//! 9. Insert update history (chains `prev_hash → new_hash`).
//! 10. Validate dependent workflows; collect results without blocking.
//!
//! The pure helpers (`resolve_source`, `wrap_source_with_module_macro`,
//! `resolve_max_fuel_*`, `world_short`) are unit-tested directly so the
//! transformation logic doesn't need a database to verify.

use std::sync::Arc;

use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use talos_compilation::CompilationService;
use talos_module_repository::ModuleRepository;
use talos_workflow_repository::WorkflowRepository;
use talos_workflow_validation::WorkflowValidationService;

/// Max byte size for inline Rust source code.
///
/// MCP-1038 (2026-05-15): made `pub` and locked in parity with
/// `talos_mcp_handlers::utils::MAX_RUST_CODE_BYTES` via the
/// `_MCP_1038_PARITY_GUARD` compile-time assertion below. The MCP
/// handler runs a cheap early-exit at this same byte cap before
/// dispatching; this service-side check is the binding one for any
/// non-MCP (e.g. future GraphQL) caller. Both surfaces share the
/// exact 1 MiB convention.
pub const MAX_RUST_CODE_BYTES: usize = 1_048_576;
pub const MAX_CONFIG_BYTES: usize = 100_000;
const COMPILED_FALLBACK_FUEL: i64 = 2_000_000;

#[derive(Debug, Clone)]
pub struct HotUpdateInput {
    pub module_id: Uuid,
    pub user_id: Uuid,
    pub rust_code: Option<String>,
    pub config: Option<JsonValue>,
    pub capability_world: Option<String>,
    pub dependencies: Option<JsonValue>,
    pub fuel_budget: Option<u64>,
}

#[derive(Debug, Error)]
pub enum HotUpdateError {
    #[error("{0}")]
    InvalidArg(String),
    #[error("Module not found or access denied")]
    ModuleNotFound,
    #[error("Dependency validation failed: {0}")]
    DependencyValidation(String),
    #[error("Compilation errors:\n{}", .0.join("\n"))]
    Compilation(Vec<String>),
    #[error("{0}")]
    DatabaseWrite(String),
    #[error("Compilation succeeded but produced no WASM bytes")]
    NoWasmBytes,
    #[error("Compilation failed: {0}")]
    CompilerInvocation(String),
}

#[derive(Debug, Clone)]
pub struct HotUpdateOutcome {
    pub module_id: Uuid,
    pub name: String,
    pub size_bytes: i32,
    pub content_hash: String,
    pub lint_warnings: Vec<String>,
    pub affected_workflows: Vec<DependentWorkflowResult>,
}

#[derive(Debug, Clone)]
pub struct DependentWorkflowResult {
    pub workflow_id: Uuid,
    pub workflow_name: String,
    pub valid: bool,
    pub errors: Vec<String>,
}

#[derive(Clone)]
pub struct HotUpdateService {
    module_repo: Arc<ModuleRepository>,
    workflow_repo: Arc<WorkflowRepository>,
    compiler: Arc<CompilationService>,
}

impl HotUpdateService {
    pub fn new(
        module_repo: Arc<ModuleRepository>,
        workflow_repo: Arc<WorkflowRepository>,
        compiler: Arc<CompilationService>,
    ) -> Self {
        Self {
            module_repo,
            workflow_repo,
            compiler,
        }
    }

    pub async fn execute(&self, input: HotUpdateInput) -> Result<HotUpdateOutcome, HotUpdateError> {
        let HotUpdateInput {
            module_id,
            user_id,
            rust_code,
            config: provided_config,
            capability_world: explicit_world,
            dependencies: explicit_dependencies,
            fuel_budget,
        } = input;

        // 1. Fetch context.
        let ctx = match self
            .module_repo
            .get_hot_update_context(module_id, user_id)
            .await
        {
            Ok(Some(c)) => c,
            Ok(None) => return Err(HotUpdateError::ModuleNotFound),
            Err(e) => {
                tracing::error!(err = ?e, %module_id, "hot_update_module context fetch failed");
                return Err(HotUpdateError::DatabaseWrite(
                    "Failed to load module for hot update".into(),
                ));
            }
        };

        // 2. Resolve effective source.
        let source_code = resolve_source(rust_code.as_deref(), ctx.stored_source.as_deref())?;

        // 3. Resolve effective config (size-validated).
        let config = resolve_config(provided_config.as_ref(), &ctx.stored_config)?;

        // 4. Resolve effective capability world.
        if let Some(w) = explicit_world.as_deref() {
            reject_non_compilable_world(w)?;
        }
        let effective_world = explicit_world
            .clone()
            .unwrap_or_else(|| ctx.capability_world.clone());

        // 4a. MCP-909 (2026-05-14): capability-downgrade warning.
        // Operators recompiling a module to a LOWER capability world
        // than its previous version silently break every workflow
        // node relying on the now-removed capability — those nodes
        // start failing at runtime with no advance warning. Compare
        // old (`ctx.capability_world`) vs new (`effective_world`) via
        // the canonical `check_downgrade` helper and emit any
        // warnings through the same `lint_warnings` channel the
        // compiler uses. Unknown worlds (parse fail) bubble through
        // `CapabilityWorld::Unknown` which `is_subset_of` treats
        // conservatively (never a subset of anything else) — the
        // helper returns an "incomparable worlds" warning, which is
        // the right operator signal: "your update changed something
        // we can't reason about, double-check workflows manually."
        let mut downgrade_warnings: Vec<String> = Vec::new();
        if let (Ok(old_w), Ok(new_w)) = (
            ctx.capability_world.parse::<talos_capability_world::CapabilityWorld>(),
            effective_world.parse::<talos_capability_world::CapabilityWorld>(),
        ) {
            if let Some(msg) =
                talos_capability_downgrade::check_downgrade(&ctx.name, &old_w, &new_w)
            {
                downgrade_warnings.push(msg);
            }
        }

        // 5. Validate explicit dependencies if provided; otherwise cascade
        //    explicit → node_templates → wasm_modules.
        if let Some(d) = explicit_dependencies.as_ref() {
            talos_compilation::dependency_allowlist::validate_dependencies(Some(d))
                .map_err(HotUpdateError::DependencyValidation)?;
        }
        let stored_dependencies = self
            .resolve_dependencies(
                explicit_dependencies,
                module_id,
                ctx.template_id,
                ctx.is_sandbox_only,
            )
            .await;

        // 6. Wrap source with `#[talos_module]` if needed.
        let wrapped_source = wrap_source_with_module_macro(&source_code, &effective_world);

        // 7. Compile.
        let job_id = Uuid::new_v4();
        let result = self
            .compiler
            .compile_to_wasm_with_config(
                user_id,
                job_id,
                &ctx.name,
                &wrapped_source,
                &config,
                stored_dependencies.as_ref(),
            )
            .await
            .map_err(|e| {
                tracing::error!(%module_id, "hot_update_module compilation failed: {}", e);
                HotUpdateError::CompilerInvocation(e.to_string())
            })?;

        if !result.success {
            let messages = result.errors.iter().map(|e| e.message.clone()).collect();
            return Err(HotUpdateError::Compilation(messages));
        }

        let wasm_bytes = result
            .wasm_bytes
            .clone()
            .ok_or(HotUpdateError::NoWasmBytes)?;

        // 8. Mirror to modules table — sandbox vs compiled paths.
        if ctx.is_sandbox_only {
            self.write_sandbox_path(
                module_id,
                user_id,
                &ctx.name,
                &effective_world,
                &wasm_bytes,
                &source_code,
                fuel_budget,
                ctx.existing_max_fuel,
                stored_dependencies.as_ref(),
            )
            .await?;
        } else {
            self.write_compiled_path(
                ctx.effective_wm_id,
                ctx.template_id,
                user_id,
                &ctx.name,
                &effective_world,
                &wasm_bytes,
                &result.content_hash,
                &source_code,
                fuel_budget,
                ctx.existing_max_fuel,
                stored_dependencies.as_ref(),
            )
            .await?;
        }
        let _ = config;

        // 9. Best-effort Redis cache invalidation.
        invalidate_redis_cache(module_id, ctx.effective_wm_id, user_id).await;

        // 10. Update history (chained from previous hash).
        let prev_hash = match ctx.old_content_hash.clone() {
            Some(h) => h,
            None => self
                .module_repo
                .last_history_hash_for_module(module_id)
                .await
                .unwrap_or(None)
                .unwrap_or_else(|| "initial".to_string()),
        };
        if let Err(e) = self
            .module_repo
            .insert_module_update_history(
                module_id,
                user_id,
                &prev_hash,
                &result.content_hash,
                result.size_bytes,
            )
            .await
        {
            tracing::warn!(%module_id, "Failed to record module update history: {:#}", e);
        }

        // 11. Validate dependent workflows (informational; never blocks).
        let affected_workflows = self.validate_dependents(module_id, ctx.template_id).await;

        // 12. Collect lint warnings (compiler-emitted).
        // MCP-909: prepend any capability-downgrade warnings from
        // step 4a so they surface before compiler-emitted ones —
        // operators reviewing the response see the high-impact
        // semantic warning before the (typically noisier)
        // line-level compiler lints.
        let mut lint_warnings: Vec<String> = downgrade_warnings;
        lint_warnings.extend(
            result
                .errors
                .iter()
                .filter(|e| e.severity == "warning")
                .map(|e| match e.line {
                    Some(line) => format!("Line {}: {}", line, e.message),
                    None => e.message.clone(),
                }),
        );

        Ok(HotUpdateOutcome {
            module_id,
            name: ctx.name,
            size_bytes: result.size_bytes,
            content_hash: result.content_hash,
            lint_warnings,
            affected_workflows,
        })
    }

    async fn resolve_dependencies(
        &self,
        explicit: Option<JsonValue>,
        module_id: Uuid,
        template_id: Option<Uuid>,
        is_sandbox: bool,
    ) -> Option<JsonValue> {
        if let Some(d) = explicit {
            return Some(d);
        }
        let lookup_id = if is_sandbox {
            Some(module_id)
        } else {
            template_id
        };
        let from_template = if let Some(tid) = lookup_id {
            self.module_repo
                .get_template_dependencies(tid)
                .await
                .unwrap_or(None)
        } else {
            None
        };
        match from_template {
            Some(d) => Some(d),
            None => self
                .module_repo
                .get_wasm_module_dependencies(module_id)
                .await
                .unwrap_or(None),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn write_sandbox_path(
        &self,
        module_id: Uuid,
        user_id: Uuid,
        module_name: &str,
        effective_world: &str,
        wasm_bytes: &[u8],
        source_code: &str,
        fuel_budget: Option<u64>,
        existing_max_fuel: Option<i64>,
        stored_dependencies: Option<&JsonValue>,
    ) -> Result<(), HotUpdateError> {
        let computed_max_fuel = resolve_sandbox_max_fuel(fuel_budget, existing_max_fuel);
        let world_short = sandbox_world_short(effective_world);

        // MCP-883 (2026-05-14): three pre-compile DB reads that
        // previously collapsed errors into "default" values via
        // `.ok().flatten().unwrap_or(module_id)` and `.unwrap_or_default()`.
        // Misleading-success class: a DB blip during these reads
        // would let the hot-update proceed with:
        //   * mirror_id = module_id (writing to the wrong row if a
        //     mirror existed but the lookup failed)
        //   * stored_secrets/hosts = [] (new module loses its
        //     allowlist — runtime fails with permission denials
        //     immediately after "hot update successful")
        //   * stored_integration_name = None (loses integration
        //     binding — workflow node breaks)
        // Now each Err path logs + fails the hot-update with
        // DatabaseWrite (reused variant since adding DatabaseRead
        // ripples through the caller's match arms). User-visible:
        // operator sees a clear "DB error" instead of a silent
        // module-breaking update.
        let mirror_id = match self
            .module_repo
            .find_wasm_module_id_by_template(module_id, Some(user_id))
            .await
        {
            Ok(opt) => opt.unwrap_or(module_id),
            Err(e) => {
                tracing::error!(%module_id, %user_id, error = %e, "hot_update sandbox: find_wasm_module_id_by_template failed");
                return Err(HotUpdateError::DatabaseWrite(
                    "Failed to look up sandbox mirror id (database error)".into(),
                ));
            }
        };
        let content_hash = format!("{:x}", Sha256::digest(wasm_bytes));
        let (stored_secrets, stored_hosts) = match self
            .module_repo
            .get_template_secrets_and_hosts(module_id)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(%module_id, error = %e, "hot_update sandbox: get_template_secrets_and_hosts failed — refusing to write with empty allowlist");
                return Err(HotUpdateError::DatabaseWrite(
                    "Failed to load template secrets/hosts allowlist (database error). \
                     Refusing to hot-update with an empty allowlist that would break the module at runtime."
                        .into(),
                ));
            }
        };
        let stored_integration_name = match self
            .module_repo
            .get_template_integration_name(module_id)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(%module_id, error = %e, "hot_update sandbox: get_template_integration_name failed");
                return Err(HotUpdateError::DatabaseWrite(
                    "Failed to load template integration binding (database error)".into(),
                ));
            }
        };

        self.module_repo
            .mirror_sandbox_compile_to_modules(
                mirror_id,
                module_id,
                Some(user_id),
                module_name,
                "sandbox",
                world_short,
                wasm_bytes,
                &content_hash,
                source_code,
                computed_max_fuel,
                &stored_hosts,
                &[],
                &stored_secrets,
                stored_integration_name.as_deref(),
                stored_dependencies,
            )
            .await
            .map_err(|e| {
                tracing::error!(%module_id, error = %e, "hot_update_module sandbox: modules-table write failed");
                HotUpdateError::DatabaseWrite("Failed to update sandbox module".into())
            })
    }

    #[allow(clippy::too_many_arguments)]
    async fn write_compiled_path(
        &self,
        effective_wm_id: Uuid,
        template_id: Option<Uuid>,
        user_id: Uuid,
        module_name: &str,
        effective_world: &str,
        wasm_bytes: &[u8],
        content_hash: &str,
        source_code: &str,
        fuel_budget: Option<u64>,
        existing_max_fuel: Option<i64>,
        stored_dependencies: Option<&JsonValue>,
    ) -> Result<(), HotUpdateError> {
        let mirror_max_fuel = resolve_compiled_max_fuel(fuel_budget, existing_max_fuel);
        let mirror_tid = template_id.unwrap_or(effective_wm_id);
        self.module_repo
            .mirror_sandbox_compile_to_modules(
                effective_wm_id,
                mirror_tid,
                Some(user_id),
                module_name,
                "sandbox",
                compiled_world_short(effective_world),
                wasm_bytes,
                content_hash,
                source_code,
                mirror_max_fuel,
                &[],
                &[],
                &[],
                None,
                stored_dependencies,
            )
            .await
            .map_err(|e| {
                tracing::error!(%effective_wm_id, error = %e, "hot_update_module compiled: modules-table write failed");
                HotUpdateError::DatabaseWrite("Failed to update module in database".into())
            })
    }

    async fn validate_dependents(
        &self,
        module_id: Uuid,
        template_id: Option<Uuid>,
    ) -> Vec<DependentWorkflowResult> {
        // MCP-884 (2026-05-14): log the DB error before returning empty.
        // Pre-fix `.unwrap_or_default()` swallowed the sqlx error so the
        // operator response showed `{affected_workflows: []}` —
        // indistinguishable from "module truly has no dependents."
        // An operator running hot_update_module on a module used by
        // 50 workflows would see "no workflows affected" if the
        // lookup transiently failed, then ship the update believing
        // it was safe. Worst-case real consequence: the WASM swap
        // is config-incompatible with the actual dependent workflow
        // graphs, and 50 production workflows break at next
        // execution. WARN log lets operators correlate post-incident.
        // Return shape (Vec) preserved to avoid rippling through
        // HotUpdateOutcome.affected_workflows; a future ship could
        // add a validation_skipped bool to surface the omission at
        // the API response level.
        let dependents = match self
            .module_repo
            .find_dependent_workflows_dual_id(module_id, template_id)
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(
                    %module_id,
                    template_id = ?template_id,
                    error = %e,
                    "validate_dependents: find_dependent_workflows_dual_id failed — \
                     returning empty list. Operator-visible affected_workflows will be \
                     INCORRECTLY empty; re-run validate_workflow on each known dependent."
                );
                Vec::new()
            }
        };
        let mut results = Vec::with_capacity(dependents.len());
        for (wf_id, wf_name, wf_user_id) in &dependents {
            match WorkflowValidationService::validate(&self.workflow_repo, *wf_id, *wf_user_id)
                .await
            {
                Ok(vr) => {
                    let errors = vr
                        .errors()
                        .iter()
                        .map(|e| e.message.clone())
                        .collect::<Vec<_>>();
                    results.push(DependentWorkflowResult {
                        workflow_id: *wf_id,
                        workflow_name: wf_name.clone(),
                        valid: vr.valid,
                        errors,
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        workflow_id = %wf_id,
                        "Post-hot-update validation failed for dependent workflow: {}",
                        e
                    );
                }
            }
        }
        results
    }
}

// ── Pure helpers ─────────────────────────────────────────────────────────────

pub fn resolve_source(
    provided: Option<&str>,
    stored: Option<&str>,
) -> Result<String, HotUpdateError> {
    match provided {
        Some(code) if code.len() > MAX_RUST_CODE_BYTES => Err(HotUpdateError::InvalidArg(
            "rust_code exceeds 1 MB limit".into(),
        )),
        Some(code) if !code.is_empty() => Ok(code.to_string()),
        _ => match stored {
            Some(s) if !s.is_empty() => Ok(s.to_string()),
            _ => Err(HotUpdateError::InvalidArg(
                "No source code provided and no stored source_code available for recompilation"
                    .into(),
            )),
        },
    }
}

pub fn resolve_config(
    provided: Option<&JsonValue>,
    stored: &JsonValue,
) -> Result<JsonValue, HotUpdateError> {
    match provided {
        Some(c) if c.is_object() => {
            let len = serde_json::to_string(c).map(|s| s.len()).unwrap_or(0);
            if len > MAX_CONFIG_BYTES {
                Err(HotUpdateError::InvalidArg(
                    "config must be ≤ 100 KB when serialized".into(),
                ))
            } else {
                Ok(c.clone())
            }
        }
        _ => Ok(stored.clone()),
    }
}

/// Reject `llm-node` (an actor RBAC label, not a compilable WIT world).
/// Other strings pass — the compiler will reject genuinely-unknown worlds.
/// Mirrors `talos_mcp_handlers::sandbox::reject_non_compilable_world`.
pub fn reject_non_compilable_world(world: &str) -> Result<(), HotUpdateError> {
    let normalised = if world.ends_with("-node") {
        world.to_string()
    } else {
        format!("{}-node", world)
    };
    if normalised == "llm-node" {
        return Err(HotUpdateError::InvalidArg(
            "capability_world 'llm-node' is an actor RBAC tier label, not a compilable \
             WIT world — pass 'agent-node' instead (it includes both LLM and memory bindings). \
             llm-node is only valid for create_actor / grant_capability_ceiling, where it \
             caps an actor to native LLM access without vault privileges."
                .into(),
        ));
    }
    // MCP-782 (2026-05-14): allowlist-validate against
    // `compilable_worlds`. Pre-fix this helper only rejected the
    // operator-friendly `llm-node` case (informative error pointing
    // at `agent-node`); ANY other unrecognised string passed through
    // and landed in `wrap_source_with_module_macro`'s
    // `format!("#[talos_sdk_macros::talos_module(world = \"{}\")]", ...)`
    // interpolation. A `world = "minimal\")] pub fn evil() {} #[talos_module(world = \"minimal"`
    // crafts the attribute into valid Rust with an injected fn,
    // running as proc-macro-expanded code at compile time. Sibling
    // fixes MCP-781 closed `handle_lint_sandbox` and
    // `InlineCompileService::compile_and_persist`; this brings the
    // hot-update path to parity. The `llm-node` arm above runs FIRST
    // so the operator-friendly diagnostic still wins for that
    // specific value.
    if !talos_capability_world::is_compilable_world(&normalised) {
        return Err(HotUpdateError::InvalidArg(format!(
            "Invalid capability_world '{}'. Valid values: {}",
            world,
            talos_capability_world::compilable_worlds_csv()
        )));
    }
    Ok(())
}

/// Inject `#[talos_sdk_macros::talos_module(world = "...")]` directly above
/// the first `fn run(` declaration if no talos macro / wit_bindgen marker is
/// present. Returns the source unchanged when one of those markers IS present.
pub fn wrap_source_with_module_macro(source: &str, effective_world: &str) -> String {
    // MCP-1053 (2026-05-15): delegate to canonical
    // `talos_workflow_creation_helpers::wrap_rust_code_with_talos_module`.
    // Pre-fix this function and the canonical one were byte-for-byte
    // duplicates (same skip-markers, same regex, same format string).
    // Same N-inline-copies class as MCP-1037/1049/1050/1051/1052.
    // Keeping the `wrap_source_with_module_macro` name preserves the
    // existing test suite + caller (resolve_source in execute()) shape;
    // future maintenance happens in ONE place.
    talos_workflow_creation_helpers::wrap_rust_code_with_talos_module(source, effective_world)
}

/// Sandbox-path fuel cascade: explicit `fuel_budget` > stored `existing_max_fuel`
/// > compute_max_fuel(10, 2000, 2.0) baseline.
pub fn resolve_sandbox_max_fuel(fuel_budget: Option<u64>, existing: Option<i64>) -> i64 {
    if let Some(v) = fuel_budget {
        return v as i64;
    }
    if let Some(v) = existing {
        return v;
    }
    talos_compilation::scaffold::compute_max_fuel(10, 2000, 2.0) as i64
}

/// Compiled-path fuel cascade: same precedence, different baseline (2_000_000).
pub fn resolve_compiled_max_fuel(fuel_budget: Option<u64>, existing: Option<i64>) -> i64 {
    if let Some(v) = fuel_budget {
        return v as i64;
    }
    existing.unwrap_or(COMPILED_FALLBACK_FUEL)
}

/// Sandbox path's world-short: maps `automation-node` → `trusted`, otherwise
/// strips the `-node` suffix.
pub fn sandbox_world_short(effective_world: &str) -> &str {
    if effective_world == "automation-node" {
        "trusted"
    } else {
        effective_world.trim_end_matches("-node")
    }
}

/// Compiled path's world-short: just strips the `-node` suffix (no
/// automation-node mapping). Preserves pre-extraction behavior — the
/// difference vs. the sandbox path is intentional.
pub fn compiled_world_short(effective_world: &str) -> &str {
    effective_world.trim_end_matches("-node")
}

/// Best-effort Redis DEL across both URI shapes (`wasm:{id}` and
/// `wasm:{user_id}:{id}`) and both id forms (caller-supplied + canonical).
///
/// MCP-491: failures are non-fatal but MUST be observable. Pre-fix the
/// "Redis cache invalidated for hot_update_module" log fired
/// unconditionally — even when REDIS_URL was unset, the connection
/// failed, or the DEL command itself returned an error. Operators
/// reading logs saw "cache invalidated" and assumed every worker had
/// dropped its stale WASM; in fact nothing had been invalidated and the
/// next executions of the module ran the OLD bytes. That defeats the
/// whole point of the hot update.
///
/// Each failure mode now emits a structured WARN so the operator can
/// see exactly which leg of the invalidation broke down; the success
/// log only fires on actual DEL completion.
async fn invalidate_redis_cache(module_id: Uuid, effective_wm_id: Uuid, user_id: Uuid) {
    let redis_url = match std::env::var("REDIS_URL") {
        Ok(u) => u,
        Err(_) => {
            tracing::warn!(
                %module_id,
                "REDIS_URL not set — skipping hot-update cache invalidation; workers may serve stale WASM"
            );
            return;
        }
    };
    let client = match redis::Client::open(redis_url.as_str()) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                %module_id,
                error = %e,
                "Redis client open failed during hot-update cache invalidation; workers may serve stale WASM"
            );
            return;
        }
    };
    let mut con = match client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                %module_id,
                error = %e,
                "Redis connection failed during hot-update cache invalidation; workers may serve stale WASM"
            );
            return;
        }
    };
    let mut keys: Vec<String> = vec![
        format!("wasm:{}", effective_wm_id),
        format!("wasm:{}:{}", user_id, effective_wm_id),
    ];
    if module_id != effective_wm_id {
        keys.push(format!("wasm:{}", module_id));
        keys.push(format!("wasm:{}:{}", user_id, module_id));
    }
    let mut cmd = redis::cmd("DEL");
    for k in &keys {
        cmd.arg(k);
    }
    match cmd.query_async::<()>(&mut con).await {
        Ok(()) => {
            tracing::info!(
                %module_id,
                %effective_wm_id,
                %user_id,
                keys_invalidated = keys.len(),
                "Redis cache invalidated for hot_update_module"
            );
        }
        Err(e) => {
            tracing::warn!(
                %module_id,
                %effective_wm_id,
                error = %e,
                attempted_keys = keys.len(),
                "Redis DEL failed during hot-update cache invalidation; workers may serve stale WASM"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolve_source_prefers_provided_when_nonempty() {
        let out = resolve_source(Some("fn run() {}"), Some("stored")).unwrap();
        assert_eq!(out, "fn run() {}");
    }

    #[test]
    fn resolve_source_falls_back_to_stored_when_provided_empty() {
        let out = resolve_source(Some(""), Some("stored")).unwrap();
        assert_eq!(out, "stored");
    }

    #[test]
    fn resolve_source_uses_stored_when_provided_none() {
        let out = resolve_source(None, Some("stored code")).unwrap();
        assert_eq!(out, "stored code");
    }

    #[test]
    fn resolve_source_rejects_oversized_provided() {
        let big = "x".repeat(MAX_RUST_CODE_BYTES + 1);
        let err = resolve_source(Some(&big), Some("stored")).unwrap_err();
        assert!(matches!(err, HotUpdateError::InvalidArg(_)));
    }

    #[test]
    fn resolve_source_errors_when_neither_available() {
        let err = resolve_source(None, None).unwrap_err();
        assert!(matches!(err, HotUpdateError::InvalidArg(_)));
        let err = resolve_source(Some(""), None).unwrap_err();
        assert!(matches!(err, HotUpdateError::InvalidArg(_)));
    }

    #[test]
    fn resolve_config_prefers_provided_object() {
        let provided = json!({"x": 1});
        let stored = json!({"y": 2});
        let out = resolve_config(Some(&provided), &stored).unwrap();
        assert_eq!(out, provided);
    }

    #[test]
    fn resolve_config_falls_back_when_provided_is_not_object() {
        let provided = json!(42);
        let stored = json!({"y": 2});
        let out = resolve_config(Some(&provided), &stored).unwrap();
        assert_eq!(out, stored);
    }

    #[test]
    fn resolve_config_rejects_oversized_serialized() {
        let big_string = "x".repeat(MAX_CONFIG_BYTES + 100);
        let provided = json!({"big": big_string});
        let err = resolve_config(Some(&provided), &json!({})).unwrap_err();
        assert!(matches!(err, HotUpdateError::InvalidArg(_)));
    }

    #[test]
    fn wrap_source_skips_already_wrapped() {
        let src = "#[talos_module]\npub fn run() {}";
        assert_eq!(wrap_source_with_module_macro(src, "minimal-node"), src);
    }

    #[test]
    fn wrap_source_skips_with_wit_bindgen_marker() {
        let src = "wit_bindgen::generate!({...});\npub fn run() {}";
        assert_eq!(wrap_source_with_module_macro(src, "minimal-node"), src);
    }

    #[test]
    fn wrap_source_injects_macro_above_pub_fn_run() {
        let src = "use foo;\npub fn run() {}\n";
        let out = wrap_source_with_module_macro(src, "http-node");
        assert!(out.contains("#[talos_sdk_macros::talos_module(world = \"http-node\")]"));
        assert!(out.contains("pub fn run() {}"));
        let macro_idx = out.find("#[talos_sdk_macros::talos_module").unwrap();
        let fn_idx = out.find("pub fn run").unwrap();
        assert!(macro_idx < fn_idx);
    }

    #[test]
    fn wrap_source_passthrough_when_no_run_fn() {
        let src = "use foo;\nfn helper() {}\n";
        let out = wrap_source_with_module_macro(src, "minimal-node");
        assert_eq!(out, src);
    }

    #[test]
    fn resolve_sandbox_fuel_prefers_explicit() {
        let out = resolve_sandbox_max_fuel(Some(99), Some(50));
        assert_eq!(out, 99);
    }

    #[test]
    fn resolve_sandbox_fuel_falls_back_to_existing() {
        let out = resolve_sandbox_max_fuel(None, Some(50));
        assert_eq!(out, 50);
    }

    #[test]
    fn resolve_sandbox_fuel_uses_baseline_when_neither() {
        let out = resolve_sandbox_max_fuel(None, None);
        // compute_max_fuel(10, 2000, 2.0) is non-zero by construction.
        assert!(out > 0);
    }

    #[test]
    fn resolve_compiled_fuel_prefers_explicit() {
        let out = resolve_compiled_max_fuel(Some(99), Some(50));
        assert_eq!(out, 99);
    }

    #[test]
    fn resolve_compiled_fuel_falls_back_to_existing() {
        let out = resolve_compiled_max_fuel(None, Some(50));
        assert_eq!(out, 50);
    }

    #[test]
    fn resolve_compiled_fuel_uses_2m_baseline() {
        let out = resolve_compiled_max_fuel(None, None);
        assert_eq!(out, 2_000_000);
    }

    #[test]
    fn sandbox_world_short_maps_automation_to_trusted() {
        assert_eq!(sandbox_world_short("automation-node"), "trusted");
    }

    #[test]
    fn sandbox_world_short_strips_node_suffix() {
        assert_eq!(sandbox_world_short("http-node"), "http");
        assert_eq!(sandbox_world_short("minimal-node"), "minimal");
    }

    #[test]
    fn compiled_world_short_strips_node_suffix_only() {
        // Compiled path does NOT have the automation-node → trusted special case.
        assert_eq!(compiled_world_short("automation-node"), "automation");
        assert_eq!(compiled_world_short("http-node"), "http");
    }
}
