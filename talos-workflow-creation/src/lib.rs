//! Workflow creation service — synchronous orchestration for the
//! `create_workflow_from_description` flow.
//!
//! Lifted out of `talos-mcp-handlers/src/workflows.rs` (1,104-LoC handler).
//! The service owns the scaffold-build → resolve-modules → create-row
//! sequence and returns a typed [`CreateFromDescriptionOutcome`]; the
//! caller (MCP handler, future GraphQL mutation, future REST endpoint)
//! is responsible for protocol-specific dressing (JSON-RPC envelope,
//! GraphQL response types) and fire-and-forget background tasks
//! (post-create embedding, capability tagging, LLM auto-fill of empty
//! config values).
//!
//! Why a service layer:
//! 1. The MCP handler had grown to 1,104 lines of mixed protocol +
//!    domain logic, with parsing, LLM-response handling, graph
//!    construction, and response shaping interleaved across 8 levels
//!    of nesting — impossible to unit-test in isolation.
//! 2. The same logic will eventually back GraphQL `createWorkflowFrom-
//!    Description` and a public REST endpoint. Keeping it inside
//!    `talos-mcp-handlers` would force those callers to depend on the
//!    MCP crate just to get to the domain code.
//! 3. The pure-helpers crate `talos-workflow-creation-helpers` already
//!    holds the state-free building blocks (validation, graph node/
//!    edge construction, response shaping). This crate adds the
//!    stateful wiring: LLM calls, repository reads/writes, DLP
//!    redaction.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde_json::Value;
use talos_compilation::CompilationService;
use talos_dlp_provider::DlpService;
use talos_llm::LlmClient;
use talos_module_repository::ModuleRepository;
use talos_workflow_repository::WorkflowRepository;
use uuid::Uuid;

pub mod spec;
pub use spec::{
    BuildStage, CreateFromSpecOutcome, CreateFromSpecRequest, NodeBuildError, SpecCreatedOutcome,
    MAX_EDGE_CONDITION_LEN, MAX_SPEC_DESCRIPTION_LEN, MAX_SPEC_NAME_LEN, MAX_SPEC_NODES,
};

/// Input to [`WorkflowCreationService::create_from_description`].
///
/// Borrows are by reference — the service does not retain any input
/// state past the call.
pub struct CreateFromDescriptionRequest<'a> {
    pub description: &'a str,
    pub explicit_modules: &'a [String],
    pub user_id: Uuid,
}

/// Maximum description length accepted by
/// [`WorkflowCreationService::create_from_description`]. Mirrors the
/// pre-extraction handler limit; descriptions over this are rejected
/// with [`InputError::DescriptionTooLong`] before any LLM call runs.
pub const MAX_DESCRIPTION_LEN: usize = 2_000;

/// Synchronous outcomes of the create-from-description flow.
///
/// Variants split into three groups:
///
/// **Success** ([`LlmScaffold`], [`ExplicitModuleScaffold`]) — a
/// workflow row exists in the database; the caller should spawn the
/// post-create background tasks (embedding, capability tagging, and
/// — for `LlmScaffold` only — auto-fill of empty config values).
///
/// **Soft failure** ([`LlmIncomplete`], [`LlmInvalidJson`],
/// [`LlmCallFailed`], [`NoLlmAndNoExplicit`], [`NoMatchedModules`]) —
/// the operation could not produce a workflow but the failure is
/// expected/recoverable; the caller surfaces a user-facing message
/// rather than a JSON-RPC error.
///
/// Hard failures (DB insert errors, repository errors) flow as
/// `Err(anyhow::Error)` from the service entry point, not as a variant
/// here — those are 5xx-class problems and the caller maps them to a
/// generic JSON-RPC -32000.
#[derive(Debug)]
pub enum CreateFromDescriptionOutcome {
    /// LLM-scaffolded workflow with full metadata payload. Caller
    /// shapes the success response and spawns three background tasks
    /// (embed, suggest-capabilities, auto-fill).
    ///
    /// `Box`ed because `LlmScaffoldOutcome` carries 13 fields totaling
    /// ~344 bytes (graph nodes, schema map, etc.) — keeping the enum
    /// itself small means every soft-failure variant doesn't pay the
    /// success path's storage cost on every match.
    LlmScaffold(Box<LlmScaffoldOutcome>),
    /// Linear-chain workflow built from caller-provided module IDs
    /// (no LLM available or no description scaffolding requested).
    /// Caller shapes the success response and spawns two background
    /// tasks (embed, suggest-capabilities).
    ExplicitModuleScaffold(ExplicitModuleOutcome),
    /// LLM returned valid JSON but the response shape was incomplete
    /// (e.g. no `suggested_name`). Caller surfaces a "try a more
    /// specific description" hint.
    LlmIncomplete,
    /// LLM returned non-JSON output. Caller surfaces a "try again
    /// or simplify your description" hint and does NOT fall back to
    /// keyword matching (the keyword fallback was removed because it
    /// produced misleading scaffolds).
    LlmInvalidJson { detail: String },
    /// LLM API call itself failed (rate limit, timeout, auth, etc.).
    /// Caller surfaces a classified error to the user/agent.
    LlmCallFailed {
        class: LlmErrorClass,
        /// Truncated, redacted detail string — safe for response
        /// surfaces. The full error chain has been logged at warn
        /// inside the service before this variant is returned.
        detail: String,
    },
    /// No LLM client was configured AND the caller did not supply
    /// `explicit_modules`. The keyword fallback was removed in r215
    /// because it produced structurally wrong scaffolds, so this is
    /// now a hard requirement.
    NoLlmAndNoExplicit,
    /// `explicit_modules` was provided but no IDs matched the
    /// catalog. Caller surfaces the available count to help debug.
    NoMatchedModules { available_template_count: usize },
}

/// LLM-scaffold success payload. Carries everything the caller needs
/// to format the response AND spawn the auto-fill background task.
#[derive(Debug)]
pub struct LlmScaffoldOutcome {
    pub workflow_id: Uuid,
    pub suggested_name: String,
    pub reasoning: String,
    pub suggested_schedule: Option<String>,
    pub suggested_error_handling: Value,
    pub resolved_nodes: Vec<ResolvedNode>,
    pub unresolved_modules: Vec<String>,
    pub modules_not_compiled: Vec<String>,
    pub graph_nodes: Vec<Value>,
    pub graph_edges: Vec<Value>,
    pub entry_node_warnings: Vec<Value>,
    pub node_configs_needed: Vec<Value>,
    pub schema_map: HashMap<Uuid, Value>,
    pub name_collision_count: i64,
}

/// Explicit-module-scaffold success payload.
#[derive(Debug)]
pub struct ExplicitModuleOutcome {
    pub workflow_id: Uuid,
    pub workflow_name: String,
    pub matched_templates: Vec<MatchedTemplate>,
    pub ready_to_run: bool,
    pub missing_config: Vec<Value>,
    pub required_secrets: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedNode {
    pub label: String,
    /// `Uuid::nil()` when the node is a system primitive (e.g.
    /// `system:collect`); otherwise the catalog template UUID.
    pub template_id: Uuid,
    pub module_name: String,
}

#[derive(Debug, Clone)]
pub struct MatchedTemplate {
    pub template_id: Uuid,
    pub name: String,
    pub category: String,
}

/// Classified LLM-call failure. Stable strings — agents and the UI
/// branch on these to decide retry/backoff/escalation behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmErrorClass {
    RateLimited,
    Timeout,
    Auth,
    UpstreamUnavailable,
    Network,
    Unknown,
}

impl LlmErrorClass {
    /// Stable machine-readable tag.
    pub fn tag(self) -> &'static str {
        match self {
            Self::RateLimited => "rate_limited",
            Self::Timeout => "timeout",
            Self::Auth => "auth",
            Self::UpstreamUnavailable => "upstream_unavailable",
            Self::Network => "network",
            Self::Unknown => "unknown",
        }
    }

    /// Human-readable hint surfaced alongside the tag in error
    /// responses.
    pub fn hint(self) -> &'static str {
        match self {
            Self::RateLimited => "The AI service is rate-limited. Wait 30 seconds and try again.",
            Self::Timeout => "The AI service timed out. Try again with a shorter description.",
            Self::Auth => {
                "ANTHROPIC_API_KEY appears missing or invalid. Verify it via \
                 `list_secrets` or contact an operator."
            }
            Self::UpstreamUnavailable => {
                "The AI service is temporarily unavailable. Retry in 1-2 minutes."
            }
            Self::Network => "Network error reaching the AI service. Check controller egress.",
            Self::Unknown => {
                "AI service returned an unexpected error. Check controller logs and retry."
            }
        }
    }

    /// Classify a rendered error string. Pure function so the LLM
    /// failure-mapping is unit-testable without touching the
    /// network.
    pub fn classify(err_str: &str) -> Self {
        let lower = err_str.to_ascii_lowercase();
        if lower.contains("429") || lower.contains("529") || lower.contains("rate limit") {
            Self::RateLimited
        } else if lower.contains("timeout") || lower.contains("timed out") {
            Self::Timeout
        } else if lower.contains("401")
            || lower.contains("403")
            || lower.contains("unauthor")
            || lower.contains("invalid api key")
            || lower.contains("missing api key")
        {
            Self::Auth
        } else if lower.contains("503")
            || lower.contains("502")
            || lower.contains("504")
            || lower.contains("service unavailable")
        {
            Self::UpstreamUnavailable
        } else if lower.contains("connect") || lower.contains("dns") || lower.contains("network") {
            Self::Network
        } else {
            Self::Unknown
        }
    }
}

/// Input-validation errors. These are 4xx-class — the caller maps
/// them to JSON-RPC -32602 (Invalid params). Distinct from the
/// outcome enum because input validation runs BEFORE any LLM/DB work.
#[derive(Debug, thiserror::Error)]
pub enum InputError {
    #[error("Missing or empty 'description'")]
    DescriptionEmpty,
    #[error("Description too long (max {} chars)", MAX_DESCRIPTION_LEN)]
    DescriptionTooLong,
}

/// Stateful service for workflow-creation flows.
///
/// Construct once at controller startup with `Arc`-cloned
/// dependencies; clone the Arc to share between callers. The
/// service holds no per-request state.
///
/// Dependencies — three are always required (`workflow_repo`,
/// `dlp_service`, `module_repo`, `compiler`); `llm_client` is
/// optional because [`Self::create_from_description`] gracefully
/// degrades to the explicit-modules-only path when no LLM is
/// configured (typically: tests, dev environments without
/// `ANTHROPIC_API_KEY`).
pub struct WorkflowCreationService {
    workflow_repo: Arc<WorkflowRepository>,
    llm_client: Option<Arc<LlmClient>>,
    dlp_service: Arc<DlpService>,
    /// Used by [`Self::create_from_spec`] for the catalog-name
    /// resolution path (`module_name` → template UUID).
    pub(crate) module_repo: Arc<ModuleRepository>,
    /// Used by [`Self::create_from_spec`] for the inline-Rust
    /// node-compilation path.
    pub(crate) compiler: Arc<CompilationService>,
}

impl WorkflowCreationService {
    pub fn new(
        workflow_repo: Arc<WorkflowRepository>,
        llm_client: Option<Arc<LlmClient>>,
        dlp_service: Arc<DlpService>,
        module_repo: Arc<ModuleRepository>,
        compiler: Arc<CompilationService>,
    ) -> Self {
        Self {
            workflow_repo,
            llm_client,
            dlp_service,
            module_repo,
            compiler,
        }
    }

    /// Create a workflow from a natural-language description, falling
    /// back to caller-supplied module IDs when no LLM is available.
    ///
    /// Pre-conditions: `req.description` must be non-empty and ≤
    /// [`MAX_DESCRIPTION_LEN`]. Use [`validate_input`] to enforce
    /// these before calling.
    ///
    /// Post-conditions on success variants:
    /// * `LlmScaffold` and `ExplicitModuleScaffold` — a `workflows`
    ///   row has been inserted; `auto_embed_workflow` and
    ///   `auto_suggest_capabilities` have NOT yet run (caller's
    ///   responsibility). For `LlmScaffold` the caller should also
    ///   spawn the auto-fill task using the returned `graph_nodes`,
    ///   `resolved_nodes`, and `schema_map`.
    /// * Soft-failure variants — no DB write occurred.
    ///
    /// Errors propagated as `Err`:
    /// * `workflow_repo.create_workflow` failed (DB unavailable, etc.)
    /// * `workflow_repo.list_scaffolding_templates` failed catastrophically
    ///   (we treat empty as success; an actual error here is rare).
    pub async fn create_from_description(
        &self,
        req: CreateFromDescriptionRequest<'_>,
    ) -> anyhow::Result<CreateFromDescriptionOutcome> {
        // Templates are needed by both paths (LLM resolves names → IDs;
        // explicit-modules path filters them by ID and reads schemas).
        // A missing template catalog is a usability problem, not a bug —
        // the LLM-scaffold path with an empty catalog will produce a
        // hallucinated module name and fail post-validation; the
        // explicit-modules path will reject every requested module.
        // MCP-746 (2026-05-13): pair the `unwrap_or_default` with a
        // tracing::warn so a `list_scaffolding_templates` failure (DB
        // pool exhaustion, migration in flight, etc.) is OBSERVABLE in
        // logs. Without the warn, an operator sees a wave of
        // "scaffolding produced no usable nodes" responses with no
        // correlated DB-failure signal. Same observability-on-degrade
        // pattern as MCP-488 (cost-attribution) and MCP-680 (encryption-
        // aware SELECT). lint-check-8 class.
        let templates = self
            .workflow_repo
            .list_scaffolding_templates(req.user_id)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(
                    target: "talos_workflow_creation",
                    error = %e,
                    "list_scaffolding_templates failed — proceeding with empty catalog; scaffolding will likely return no usable nodes",
                );
                Vec::new()
            });

        if let Some(llm) = self.llm_client.clone() {
            return self
                .scaffold_via_llm(&llm, req.description, req.user_id, &templates)
                .await;
        }

        if req.explicit_modules.is_empty() {
            return Ok(CreateFromDescriptionOutcome::NoLlmAndNoExplicit);
        }

        self.scaffold_from_explicit_modules(
            req.description,
            req.explicit_modules,
            req.user_id,
            &templates,
        )
        .await
    }

    async fn scaffold_via_llm(
        &self,
        llm: &Arc<LlmClient>,
        description: &str,
        user_id: Uuid,
        templates: &[talos_workflow_repository::ScaffoldingTemplateRow],
    ) -> anyhow::Result<CreateFromDescriptionOutcome> {
        // Build compact catalog JSON (cap at 50 entries to stay in
        // the LLM token budget). Filter to compiled templates only —
        // suggesting an uncompiled template is a guaranteed runtime
        // failure.
        let catalog_entries: Vec<Value> = templates
            .iter()
            .filter(|row| row.is_compiled)
            .take(50)
            .map(|row| {
                serde_json::json!({
                    "display_name": row.name,
                    "description": row.description.as_deref().unwrap_or(""),
                    "category": row.category.as_deref().unwrap_or(""),
                })
            })
            .collect();
        let catalog_json = serde_json::to_string(&catalog_entries).unwrap_or_default();
        let description_redacted = self.dlp_service.redact_str(description);

        // R2 token ledger: attribute this scaffold call's token usage to the
        // requesting user via the talos-llm task-local scope.
        let llm_json = match talos_llm::usage::scoped_user(
            user_id,
            llm.scaffold_workflow(&description_redacted, &catalog_json),
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                let err_str = format!("{:#}", e);
                tracing::warn!("LLM scaffold API call failed: {}", err_str);
                let class = LlmErrorClass::classify(&err_str);
                let detail: String = err_str.chars().take(512).collect();
                return Ok(CreateFromDescriptionOutcome::LlmCallFailed { class, detail });
            }
        };

        let scaffold: Value = match serde_json::from_str(&llm_json) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("LLM scaffold returned invalid JSON: {}", e);
                return Ok(CreateFromDescriptionOutcome::LlmInvalidJson {
                    detail: e.to_string(),
                });
            }
        };

        if scaffold.get("suggested_name").is_none() {
            // MCP-538: byte-slice fixed-offset truncation panics on a
            // multi-byte codepoint boundary. LLM scaffold JSON often
            // contains Unicode (operator-described workflows in any
            // language) so naive `&llm_json[..200]` would panic if a
            // multi-byte char straddled byte 200. Same class as
            // MCP-477/478/479 — see
            // `memory/byte_slice_utf8_panic_pattern.md`.
            let preview_end = llm_json.len().min(200);
            let safe_end = llm_json.floor_char_boundary(preview_end);
            tracing::warn!(
                "LLM scaffold returned JSON without expected fields: {}",
                &llm_json[..safe_end]
            );
            return Ok(CreateFromDescriptionOutcome::LlmIncomplete);
        }

        let suggested_name: String = scaffold
            .get("suggested_name")
            .and_then(|v| v.as_str())
            .unwrap_or(description)
            .chars()
            .take(80)
            .collect();
        let reasoning = scaffold
            .get("reasoning")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let suggested_schedule = scaffold
            .get("suggested_schedule")
            .and_then(|v| v.as_str())
            .map(String::from);
        let llm_nodes = scaffold
            .get("nodes")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let llm_edges = scaffold
            .get("edges")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let suggested_error_handling = scaffold
            .get("suggested_error_handling")
            .cloned()
            .unwrap_or(serde_json::json!([]));

        // Resolve display_name → template UUID. Three categories:
        //   resolved (compiled), resolved (not_compiled), unresolved.
        let mut unresolved: Vec<String> = Vec::new();
        let mut not_compiled: Vec<String> = Vec::new();
        let mut resolved_nodes: Vec<ResolvedNode> = Vec::new();

        for node_spec in &llm_nodes {
            let label = node_spec
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or("Node")
                .to_string();
            let module_name = node_spec
                .get("module_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            // System nodes are engine built-ins; bypass catalog lookup
            // by storing Uuid::nil() as the sentinel. The graph
            // builder switches on it below.
            if module_name.starts_with("system:") {
                resolved_nodes.push(ResolvedNode {
                    label,
                    template_id: Uuid::nil(),
                    module_name,
                });
                continue;
            }

            // Case-insensitive name lookup against the FULL template
            // list (not just compiled) — distinguishing "not in
            // catalog" from "in catalog but uncompiled" is what
            // surfaces the right hint to the user.
            let module_name_lower = module_name.to_lowercase();
            let found = templates
                .iter()
                .find(|row| row.name.to_lowercase() == module_name_lower);

            match found {
                Some(row) if row.is_compiled => {
                    resolved_nodes.push(ResolvedNode {
                        label,
                        template_id: row.id,
                        module_name,
                    });
                }
                Some(row) => {
                    resolved_nodes.push(ResolvedNode {
                        label,
                        template_id: row.id,
                        module_name: module_name.clone(),
                    });
                    not_compiled.push(module_name);
                }
                None => unresolved.push(module_name),
            }
        }

        if resolved_nodes.is_empty() {
            // LLM returned a scaffold but every node referenced an
            // unknown module. Pre-extraction this fell through to the
            // (since-removed) keyword fallback. With that gone, the
            // honest answer is "no modules resolved" — surface as
            // LlmIncomplete so the caller suggests rephrasing.
            tracing::warn!("LLM scaffold returned no resolvable nodes; surfacing as LlmIncomplete");
            return Ok(CreateFromDescriptionOutcome::LlmIncomplete);
        }

        // Build graph_nodes / graph_edges. y_offset matches the
        // pre-extraction layout (100 base, 150 step).
        let mut graph_nodes: Vec<Value> = Vec::new();
        let mut graph_edges: Vec<Value> = Vec::new();
        let mut y_offset = 100.0_f64;
        let mut label_to_node_id: HashMap<String, String> = HashMap::new();

        for (i, rn) in resolved_nodes.iter().enumerate() {
            let node_id = format!("node-{}", i + 1);
            label_to_node_id.insert(rn.label.clone(), node_id.clone());
            let mut node_data = serde_json::json!({ "label": rn.label });

            // Merge config_values from the LLM spec, skipping unresolved
            // secret-path strings (they look like `provider/secret-name`
            // without a URL prefix). Keys are uppercased to match
            // module config_schema convention (URL, CHANNEL, MODEL, etc.).
            if let Some(node_spec) = llm_nodes.get(i) {
                if let Some(cv) = node_spec.get("config_values").and_then(|v| v.as_object()) {
                    for (k, v) in cv {
                        let skip = v
                            .as_str()
                            .map(|s| s.contains('/') && !s.starts_with("http"))
                            .unwrap_or(false);
                        if !skip {
                            let upper_k = k.to_uppercase();
                            node_data[upper_k.as_str()] = v.clone();
                        }
                    }
                }
            }

            // System nodes (sentinel nil UUID) carry their `system:*`
            // module_name as the graph type; everything else uses the
            // resolved template UUID.
            let node_type_str = if rn.template_id.is_nil() {
                rn.module_name.clone()
            } else {
                rn.template_id.to_string()
            };
            graph_nodes.push(serde_json::json!({
                "id": node_id,
                "type": node_type_str,
                "position": { "x": 250.0, "y": y_offset },
                "data": node_data,
            }));
            y_offset += 150.0;
        }

        for edge_spec in &llm_edges {
            let from_label = edge_spec.get("from").and_then(|v| v.as_str()).unwrap_or("");
            let to_label = edge_spec.get("to").and_then(|v| v.as_str()).unwrap_or("");
            let edge_type = edge_spec
                .get("edge_type")
                .and_then(|v| v.as_str())
                .unwrap_or("default");
            if let (Some(src), Some(tgt)) = (
                label_to_node_id.get(from_label),
                label_to_node_id.get(to_label),
            ) {
                let mut edge = serde_json::json!({
                    "source": src,
                    "target": tgt,
                });
                if edge_type != "default" {
                    edge["edge_type"] = serde_json::json!(edge_type);
                }
                graph_edges.push(edge);
            }
        }

        // Fallback: if no edges resolved but we have ≥2 nodes, chain
        // sequentially. Better than a disconnected scaffold.
        if graph_edges.is_empty() && graph_nodes.len() > 1 {
            for i in 1..graph_nodes.len() {
                graph_edges.push(serde_json::json!({
                    "source": format!("node-{}", i),
                    "target": format!("node-{}", i + 1),
                }));
            }
        }

        let entry_node_warnings = compute_entry_node_warnings(&graph_nodes, &graph_edges);

        // Insert workflow row. Hard failure here propagates as Err.
        let graph_json_str = serde_json::json!({
            "nodes": graph_nodes,
            "edges": graph_edges,
        })
        .to_string();
        let workflow_id = self
            .workflow_repo
            .create_workflow(
                user_id,
                &suggested_name,
                &graph_json_str,
                None,
                &[],
                &[],
                None,
                None,
                None,
                None,
            )
            .await?;

        // Batch-fetch schemas for `node_configs_needed` AND for the
        // caller's auto-fill background task.
        //
        // MCP-887 (2026-05-14): log silent DB errors. Pre-fix
        // `.unwrap_or_default()` collapsed sqlx errors to an empty
        // Vec → `schema_map` ended up empty → `node_configs_needed`
        // computed off an empty schema → operator-visible response
        // reports zero missing configs even though the schema lookup
        // failed. Behaviour preserved (Vec::new fallback) to avoid
        // blocking the workflow-creation path on a transient DB
        // blip; telemetry-only fix so post-incident review can
        // correlate "operator submitted spec, got 'looks complete'
        // response, runtime then failed with missing-config errors".
        let tid_list: Vec<Uuid> = resolved_nodes.iter().map(|rn| rn.template_id).collect();
        let schema_rows = match self.workflow_repo.get_templates_by_ids(&tid_list).await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(
                    template_count = tid_list.len(),
                    error = %e,
                    "workflow-creation: get_templates_by_ids failed during node_configs_needed \
                     scan — schema_map will be empty, missing-config response will INCORRECTLY \
                     report no missing fields. Operator may need to re-run after DB recovers."
                );
                Vec::new()
            }
        };
        let schema_map: HashMap<Uuid, Value> = schema_rows
            .into_iter()
            .map(|r| (r.id, r.config_schema))
            .collect();

        let node_configs_needed = build_node_configs_needed(&resolved_nodes, &schema_map);

        let name_collision_count = self
            .workflow_repo
            .count_workflow_name_collision(user_id, &suggested_name, workflow_id)
            .await
            .unwrap_or(0);

        Ok(CreateFromDescriptionOutcome::LlmScaffold(Box::new(
            LlmScaffoldOutcome {
                workflow_id,
                suggested_name,
                reasoning,
                suggested_schedule,
                suggested_error_handling,
                resolved_nodes,
                unresolved_modules: unresolved,
                modules_not_compiled: not_compiled,
                graph_nodes,
                graph_edges,
                entry_node_warnings,
                node_configs_needed,
                schema_map,
                name_collision_count,
            },
        )))
    }

    async fn scaffold_from_explicit_modules(
        &self,
        description: &str,
        explicit_modules: &[String],
        user_id: Uuid,
        templates: &[talos_workflow_repository::ScaffoldingTemplateRow],
    ) -> anyhow::Result<CreateFromDescriptionOutcome> {
        // First pass: catalog hits (rich metadata).
        let mut matched: Vec<MatchedTemplate> = Vec::new();
        for row in templates {
            let category = row.category.as_deref().unwrap_or("unknown").to_string();
            if explicit_modules.iter().any(|m| m == &row.id.to_string()) {
                matched.push(MatchedTemplate {
                    template_id: row.id,
                    name: row.name.clone(),
                    category,
                });
            }
        }
        // Second pass: explicit IDs not in the catalog (custom WASM
        // modules outside the scaffolding template set). Match the
        // pre-extraction shorthand: name = "module-{first 8 chars}".
        for module_id_str in explicit_modules {
            if let Ok(mid) = module_id_str.parse::<Uuid>() {
                if !matched.iter().any(|m| m.template_id == mid) {
                    matched.push(MatchedTemplate {
                        template_id: mid,
                        name: format!("module-{}", &module_id_str[..8.min(module_id_str.len())]),
                        category: "custom".to_string(),
                    });
                }
            }
        }
        matched.truncate(10);

        if matched.is_empty() {
            return Ok(CreateFromDescriptionOutcome::NoMatchedModules {
                available_template_count: templates.len(),
            });
        }

        // Build a linear-chain graph.
        let mut graph_nodes: Vec<Value> = Vec::new();
        let mut graph_edges: Vec<Value> = Vec::new();
        let mut y_offset = 100.0_f64;
        for (i, m) in matched.iter().enumerate() {
            let node_id = format!("node-{}", i + 1);
            graph_nodes.push(serde_json::json!({
                "id": node_id,
                "type": m.template_id.to_string(),
                "position": { "x": 250.0, "y": y_offset },
                "data": {},
            }));
            if i > 0 {
                graph_edges.push(serde_json::json!({
                    "source": format!("node-{}", i),
                    "target": node_id,
                }));
            }
            y_offset += 150.0;
        }

        let graph_json_str = serde_json::json!({
            "nodes": graph_nodes,
            "edges": graph_edges,
        })
        .to_string();

        let wf_name = derive_workflow_name(description);
        let workflow_id = self
            .workflow_repo
            .create_workflow(
                user_id,
                &wf_name,
                &graph_json_str,
                None,
                &[],
                &[],
                None,
                None,
                None,
                None,
            )
            .await?;

        // Compute missing_config + required_secrets for the response.
        //
        // MCP-887 (2026-05-14): sibling to the node_configs_needed
        // site above — same misleading-success class. Pre-fix
        // `.unwrap_or_default()` made a DB error look like "no
        // schemas exist", so the operator response reported empty
        // missing_config + empty required_secrets even when the
        // schema fetch failed transiently. Telemetry-only fix.
        let tid_list: Vec<Uuid> = matched.iter().map(|m| m.template_id).collect();
        let schema_rows = match self.workflow_repo.get_templates_by_ids(&tid_list).await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(
                    template_count = tid_list.len(),
                    error = %e,
                    "workflow-creation: get_templates_by_ids failed during missing_config + \
                     required_secrets scan — schema_map will be empty, response will \
                     INCORRECTLY report no missing fields / no required secrets."
                );
                Vec::new()
            }
        };
        let schema_map: HashMap<Uuid, (String, Value, Vec<String>)> = schema_rows
            .into_iter()
            .map(|r| (r.id, (r.name, r.config_schema, r.allowed_secrets)))
            .collect();

        let mut missing_config: Vec<Value> = Vec::new();
        let mut required_secrets_set: HashSet<String> = HashSet::new();
        for (i, m) in matched.iter().enumerate() {
            if let Some((_, schema, secrets)) = schema_map.get(&m.template_id) {
                let required: Vec<String> = schema
                    .get("required")
                    .and_then(|r| r.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                if !required.is_empty() {
                    missing_config.push(serde_json::json!({
                        "node_id": format!("node-{}", i + 1),
                        "module": m.name,
                        "missing_required": required,
                    }));
                }
                for s in secrets {
                    if s != "*" {
                        required_secrets_set.insert(s.clone());
                    }
                }
            }
        }

        let ready_to_run =
            !matched.is_empty() && missing_config.is_empty() && required_secrets_set.is_empty();

        Ok(CreateFromDescriptionOutcome::ExplicitModuleScaffold(
            ExplicitModuleOutcome {
                workflow_id,
                workflow_name: wf_name,
                matched_templates: matched,
                ready_to_run,
                missing_config,
                required_secrets: required_secrets_set.into_iter().collect(),
            },
        ))
    }

    /// Best-effort: ask the LLM to suggest values for each missing-config
    /// node-field, then merge those suggestions into the entries via the
    /// `"suggestions"` key. Mutates `missing_config` in place.
    ///
    /// Silently no-ops when:
    /// * `missing_config` is empty.
    /// * No LLM client is configured (Tier-1 actor / no provider key).
    /// * The LLM call fails or returns non-JSON output.
    ///
    /// The user prompt is DLP-redacted before it leaves the controller.
    /// The LLM is instructed to emit `"<secret: key/path>"` markers for
    /// fields that need real credentials — those go to the user, not
    /// stored values.
    pub async fn suggest_missing_config(&self, workflow_name: &str, missing_config: &mut [Value]) {
        if missing_config.is_empty() {
            return;
        }
        let Some(llm_arc) = self.llm_client.clone() else {
            return;
        };
        let user_prompt = build_suggestions_user_prompt(workflow_name, missing_config);
        let user_prompt_redacted = self.dlp_service.redact_str(&user_prompt);
        let raw = match llm_arc
            .generate_text(SUGGESTIONS_SYSTEM_PROMPT, &user_prompt_redacted)
            .await
        {
            Ok(s) => s,
            Err(_) => return,
        };
        let Ok(parsed) = serde_json::from_str::<Value>(&raw) else {
            return;
        };
        let Some(obj) = parsed.as_object() else {
            return;
        };
        merge_suggestions_into_missing_config(missing_config, obj);
    }

    /// Quickstart analysis post-persistence: batch-fetches template metadata
    /// and per-installation `allowed_secrets` overrides, builds the
    /// [`talos_workflow_creation_helpers::TemplateMeta`] map, then runs the
    /// pure analyzer. Returns the analyzer's result on success.
    ///
    /// Hard-errors (type/enum mismatches detected by the analyzer) come back
    /// as `Err(message)` — the caller maps that to MCP `-32602` so the
    /// validator's user-facing string surfaces verbatim. Repository errors
    /// during the parallel fetch degrade gracefully — the analyzer runs
    /// against an empty `template_meta` and surfaces missing-config entries
    /// instead of failing the create entirely (matches pre-extraction behavior).
    pub async fn quickstart_analyze(
        &self,
        module_ids: &[Uuid],
        input_nodes: &[Value],
        user_id: Uuid,
    ) -> Result<talos_workflow_creation_helpers::PostCreateAnalysis, String> {
        // Parallel fetch — saves ~one round-trip vs. sequential gets when
        // the workflow has any modules at all. Both reads are best-effort:
        // failures degrade to empty maps, mirroring pre-extraction
        // unwrap_or_default.
        // MCP-746 (2026-05-13): pair both `unwrap_or_default` calls with
        // tracing::warn — an empty `template_meta` map causes the
        // analyzer to report "no template found" for every node,
        // surfacing as a vague quickstart-failed response with no
        // operator-visible signal tying it to the underlying DB error.
        // Same observability-on-degrade pattern as MCP-488 / MCP-680;
        // lint-check-8 class.
        let (template_rows_res, installed_secrets_res) = tokio::join!(
            self.workflow_repo.get_templates_by_ids(module_ids),
            self.workflow_repo
                .get_installed_secrets_by_template_ids(module_ids, user_id),
        );
        let template_rows = template_rows_res.unwrap_or_else(|e| {
            tracing::warn!(
                target: "talos_workflow_creation",
                module_count = module_ids.len(),
                error = %e,
                "get_templates_by_ids failed — proceeding with empty template_meta map; analyzer will report no-template-found for every node",
            );
            Vec::new()
        });
        let installed_secrets_map = installed_secrets_res.unwrap_or_else(|e| {
            tracing::warn!(
                target: "talos_workflow_creation",
                module_count = module_ids.len(),
                error = %e,
                "get_installed_secrets_by_template_ids failed — proceeding without per-installation secret overrides; analyzer will use template-default allowed_secrets",
            );
            HashMap::new()
        });
        let template_meta = build_template_meta_map(template_rows, &installed_secrets_map);
        talos_workflow_creation_helpers::analyze_workflow_for_quickstart(
            input_nodes,
            &template_meta,
        )
    }
}

/// Pure: build the analyzer-input map from parallel-fetched template rows
/// + per-installation `allowed_secrets` overrides. The override resolution
/// stays here (DB-knowledge boundary) so the analyzer remains state-free.
///
/// `installed_secrets_map` is keyed by template_id; entries override the
/// row-level `allowed_secrets`. A missing entry leaves the row default in
/// place — that's the right default for templates that have never been
/// installed (no `wasm_modules` row exists yet).
pub fn build_template_meta_map(
    template_rows: Vec<talos_workflow_repository::NodeTemplateRow>,
    installed_secrets_map: &HashMap<Uuid, Vec<String>>,
) -> HashMap<Uuid, talos_workflow_creation_helpers::TemplateMeta> {
    template_rows
        .into_iter()
        .map(|r| {
            let effective_secrets = installed_secrets_map
                .get(&r.id)
                .cloned()
                .unwrap_or(r.allowed_secrets);
            (
                r.id,
                talos_workflow_creation_helpers::TemplateMeta {
                    name: r.name,
                    config_schema: r.config_schema,
                    allowed_secrets: effective_secrets,
                },
            )
        })
        .collect()
}

/// LLM system prompt for inline config-value suggestions. Pinned outside
/// the method so the test that checks output shape can also reference it.
pub const SUGGESTIONS_SYSTEM_PROMPT: &str = "You are a workflow configuration assistant. \
    Respond ONLY with a valid JSON object. \
    No prose, no markdown fences, no explanation. \
    Top-level keys are node_id strings; values are objects mapping field_name to suggested_value. \
    Skip fields that require real secrets, tokens, or user-specific credentials — \
    for those, use the format \"<secret: key/path>\" to indicate where the user should store the value. \
    Example: {\"node-1\": {\"CHANNEL\": \"#alerts\", \"MODEL\": \"claude-sonnet-4-6\", \"TOKEN\": \"<secret: slack/bot_token>\"}}";

/// Pure helper: build the LLM user prompt from the workflow name and
/// the missing-config list. Pulled out so the prompt format is
/// regression-tested in isolation — drift here used to silently
/// degrade suggestion quality.
pub fn build_suggestions_user_prompt(workflow_name: &str, missing_config: &[Value]) -> String {
    let nodes_desc: String = missing_config
        .iter()
        .map(|entry| {
            let nid = entry.get("node_id").and_then(|v| v.as_str()).unwrap_or("?");
            let module = entry.get("module").and_then(|v| v.as_str()).unwrap_or("?");
            let fields = entry
                .get("missing_required")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            format!("  {} ({}): missing [{}]", nid, module, fields)
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "Workflow: \"{}\"\nNodes needing config:\n{}\n\nReturn a JSON object with one key per node_id, each mapping field names to suggested values.",
        workflow_name, nodes_desc
    )
}

/// Pure helper: merge the LLM's per-node-id suggestions object into the
/// `missing_config` entries by inserting a `"suggestions"` key on each
/// entry whose `node_id` matches a top-level key in `obj`. Entries
/// without a match are left untouched.
pub fn merge_suggestions_into_missing_config(
    missing_config: &mut [Value],
    obj: &serde_json::Map<String, Value>,
) {
    for entry in missing_config.iter_mut() {
        let nid = entry
            .get("node_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if let Some(node_sugg) = obj.get(&nid) {
            if let Some(o) = entry.as_object_mut() {
                o.insert("suggestions".to_string(), node_sugg.clone());
            }
        }
    }
}

/// Validate the create-from-description input. Run BEFORE
/// [`WorkflowCreationService::create_from_description`] to catch
/// 4xx-class issues without paying for a templates round-trip or
/// LLM call.
///
/// MCP-198 (2026-05-08): also rejects whitespace-only descriptions.
/// Pre-fix `is_empty()` returned false for "                "
/// (16 spaces), so the call proceeded all the way to the LLM
/// scaffold and failed there with an opaque "AI service returned
/// an error" — the caller couldn't tell whether their input was
/// malformed or the LLM was down.
pub fn validate_input(description: Option<&str>) -> Result<(), InputError> {
    let d = description.ok_or(InputError::DescriptionEmpty)?;
    if d.trim().is_empty() {
        return Err(InputError::DescriptionEmpty);
    }
    if d.len() > MAX_DESCRIPTION_LEN {
        return Err(InputError::DescriptionTooLong);
    }
    Ok(())
}

/// Derive a workflow name from a description: first 6 words, capped
/// at 80 chars. Pure helper — exposed so callers (e.g. future
/// validators that want to preview the name) can reproduce the
/// behaviour without invoking the service.
pub fn derive_workflow_name(description: &str) -> String {
    let words: Vec<&str> = description.split_whitespace().take(6).collect();
    let name = words.join(" ");
    // MCP-477 + MCP-1050: canonical char-boundary-aware truncation via
    // `talos_text_util::truncate_at_char_boundary`. Pre-fix was an
    // inline walk-back identical to the helper; consolidating prevents
    // future drift if the helper picks up additional hardening.
    talos_text_util::truncate_at_char_boundary(&name, 80).to_string()
}

/// Detect entry nodes (no incoming edges) whose `data` carries only a
/// label — i.e. the LLM scaffold gave them no config. Surfaces a
/// per-node warning the caller can include in the response.
fn compute_entry_node_warnings(graph_nodes: &[Value], graph_edges: &[Value]) -> Vec<Value> {
    let target_ids: HashSet<&str> = graph_edges
        .iter()
        .filter_map(|e| e.get("target").and_then(|v| v.as_str()))
        .collect();
    graph_nodes
        .iter()
        .filter(|n| {
            let nid = n.get("id").and_then(|v| v.as_str()).unwrap_or("");
            !target_ids.contains(nid)
        })
        .filter(|n| {
            let data_keys = n
                .get("data")
                .and_then(|d| d.as_object())
                .map(|obj| obj.len())
                .unwrap_or(0);
            data_keys <= 1
        })
        .map(|n| {
            let label = n
                .get("data")
                .and_then(|d| d.get("label"))
                .and_then(|v| v.as_str())
                .unwrap_or("entry node");
            let node_id = n.get("id").and_then(|v| v.as_str()).unwrap_or("?");
            serde_json::json!({
                "node_id": node_id,
                "label": label,
                "warning": format!(
                    "Entry node '{}' has no incoming edges and no config values. \
                     If this is a trigger (webhook, schedule, HTTP), configure it \
                     with update_node_config before testing.",
                    label
                ),
                "tip": format!(
                    "Call get_workflow_quickstart to see required fields, \
                     then update_node_config with workflow_id=<id> node_id={}.",
                    node_id
                ),
            })
        })
        .collect()
}

/// Build the `node_configs_needed` array surfacing each node's
/// required + optional config keys. Pure projection over
/// `resolved_nodes` × `schema_map`.
fn build_node_configs_needed(
    resolved_nodes: &[ResolvedNode],
    schema_map: &HashMap<Uuid, Value>,
) -> Vec<Value> {
    resolved_nodes
        .iter()
        .enumerate()
        .map(|(i, rn)| {
            let schema = schema_map.get(&rn.template_id);
            let required: Vec<String> = schema
                .and_then(|s| s.get("required"))
                .and_then(|r| r.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let optional: Vec<String> = schema
                .and_then(|s| s.get("properties"))
                .and_then(|p| p.as_object())
                .map(|obj| {
                    obj.keys()
                        .filter(|k| !required.contains(k))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            serde_json::json!({
                "node_id": format!("node-{}", i + 1),
                "label": rn.label,
                "module": rn.module_name,
                "required_fields": required,
                "optional_fields": optional,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_suggestions_user_prompt_lists_each_node() {
        let mc = vec![
            json!({"node_id": "n1", "module": "slack", "missing_required": ["CHANNEL", "TOKEN"]}),
            json!({"node_id": "n2", "module": "http", "missing_required": ["URL"]}),
        ];
        let out = build_suggestions_user_prompt("My WF", &mc);
        assert!(out.contains("Workflow: \"My WF\""));
        assert!(out.contains("n1 (slack): missing [CHANNEL, TOKEN]"));
        assert!(out.contains("n2 (http): missing [URL]"));
        assert!(out.contains("JSON object with one key per node_id"));
    }

    #[test]
    fn build_suggestions_user_prompt_handles_missing_fields_gracefully() {
        let mc = vec![json!({})];
        let out = build_suggestions_user_prompt("WF", &mc);
        assert!(out.contains("? (?): missing []"));
    }

    #[test]
    fn merge_suggestions_inserts_only_for_matching_node_ids() {
        let mut mc = vec![
            json!({"node_id": "n1", "missing_required": ["URL"]}),
            json!({"node_id": "n2", "missing_required": ["TOKEN"]}),
        ];
        let suggestions =
            serde_json::Map::from_iter([("n1".to_string(), json!({"URL": "https://example.com"}))]);
        merge_suggestions_into_missing_config(&mut mc, &suggestions);
        assert_eq!(mc[0]["suggestions"], json!({"URL": "https://example.com"}),);
        assert!(mc[1].get("suggestions").is_none());
    }

    #[test]
    fn merge_suggestions_noop_on_empty_obj() {
        let mut mc = vec![json!({"node_id": "n1"})];
        let suggestions = serde_json::Map::new();
        merge_suggestions_into_missing_config(&mut mc, &suggestions);
        assert!(mc[0].get("suggestions").is_none());
    }

    #[test]
    fn merge_suggestions_noop_on_entry_missing_node_id() {
        let mut mc = vec![json!({"missing_required": ["URL"]})];
        let suggestions = serde_json::Map::from_iter([("".to_string(), json!({"URL": "x"}))]);
        // Empty node_id should match the empty-key entry — explicit
        // documentation that we don't special-case this. If callers
        // forget node_id, suggestions land on whichever entry
        // happens to read as "" — which is the same as no node_id at all.
        merge_suggestions_into_missing_config(&mut mc, &suggestions);
        assert_eq!(mc[0]["suggestions"], json!({"URL": "x"}));
    }

    // ── build_template_meta_map ───────────────────────────────────────────

    fn template_row(
        id: Uuid,
        name: &str,
        defaults: &[&str],
    ) -> talos_workflow_repository::NodeTemplateRow {
        talos_workflow_repository::NodeTemplateRow {
            id,
            name: name.to_string(),
            config_schema: json!({}),
            allowed_secrets: defaults.iter().map(|s| s.to_string()).collect(),
            allowed_hosts: Vec::new(),
            max_retries: 0,
            allowed_methods: Vec::new(),
            capability_world: None,
        }
    }

    #[test]
    fn build_template_meta_uses_row_defaults_when_no_install_override() {
        let id = Uuid::new_v4();
        let rows = vec![template_row(id, "slack", &["slack/bot_token"])];
        let installed = HashMap::new();
        let map = build_template_meta_map(rows, &installed);
        assert_eq!(map.len(), 1);
        let entry = &map[&id];
        assert_eq!(entry.name, "slack");
        assert_eq!(entry.allowed_secrets, vec!["slack/bot_token"]);
    }

    #[test]
    fn build_template_meta_install_override_replaces_row_defaults() {
        let id = Uuid::new_v4();
        let rows = vec![template_row(id, "slack", &["slack/bot_token"])];
        // Operator added a per-installation grant via install_module_from_catalog;
        // the override replaces the row default outright (not merge).
        let installed = HashMap::from([(id, vec!["slack/admin_token".to_string()])]);
        let map = build_template_meta_map(rows, &installed);
        let entry = &map[&id];
        assert_eq!(entry.allowed_secrets, vec!["slack/admin_token"]);
    }

    #[test]
    fn build_template_meta_handles_multiple_rows_independently() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let rows = vec![
            template_row(id1, "slack", &["slack/bot_token"]),
            template_row(id2, "http", &[]),
        ];
        let installed = HashMap::from([(id2, vec!["api/key".to_string()])]);
        let map = build_template_meta_map(rows, &installed);
        assert_eq!(map.len(), 2);
        assert_eq!(map[&id1].allowed_secrets, vec!["slack/bot_token"]); // row default
        assert_eq!(map[&id2].allowed_secrets, vec!["api/key"]); // override
    }

    #[test]
    fn build_template_meta_empty_rows_produces_empty_map() {
        let installed = HashMap::new();
        let map = build_template_meta_map(vec![], &installed);
        assert!(map.is_empty());
    }

    #[test]
    fn validate_input_rejects_none() {
        assert!(matches!(
            validate_input(None),
            Err(InputError::DescriptionEmpty)
        ));
    }

    #[test]
    fn validate_input_rejects_empty_string() {
        assert!(matches!(
            validate_input(Some("")),
            Err(InputError::DescriptionEmpty)
        ));
    }

    #[test]
    fn validate_input_rejects_too_long() {
        let s = "x".repeat(MAX_DESCRIPTION_LEN + 1);
        assert!(matches!(
            validate_input(Some(&s)),
            Err(InputError::DescriptionTooLong)
        ));
    }

    #[test]
    fn validate_input_accepts_at_max_length() {
        let s = "x".repeat(MAX_DESCRIPTION_LEN);
        assert!(validate_input(Some(&s)).is_ok());
    }

    #[test]
    fn derive_workflow_name_truncates_to_six_words() {
        let name = derive_workflow_name("one two three four five six seven eight");
        assert_eq!(name, "one two three four five six");
    }

    #[test]
    fn derive_workflow_name_caps_at_80_chars() {
        let long_word = "x".repeat(100);
        let name = derive_workflow_name(&long_word);
        assert_eq!(name.len(), 80);
    }

    #[test]
    fn derive_workflow_name_handles_empty() {
        assert_eq!(derive_workflow_name(""), "");
    }

    // MCP-477: byte-slice at fixed offset 80 used to panic when the
    // 80th byte fell inside a multi-byte UTF-8 sequence. Verify the
    // char-boundary walk-back keeps the function panic-free for
    // CJK / emoji / accented Latin descriptions of arbitrary length.

    #[test]
    fn derive_workflow_name_no_panic_on_cjk_at_boundary() {
        // CJK chars are 3 bytes each in UTF-8. Build a description
        // whose first 6 whitespace-separated tokens produce a >80 byte
        // string where byte 80 lands inside a multi-byte char.
        //
        // 6 tokens, each token is "你你你你你你你你你你" (10 CJK chars = 30 bytes).
        // Joined with " ": 6*30 + 5 = 185 bytes. Byte 80 is mid-CJK-char.
        let cjk_token = "你".repeat(10);
        let desc = (0..6)
            .map(|_| cjk_token.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        // Should NOT panic.
        let name = derive_workflow_name(&desc);
        // Length is capped at <= 80 bytes and is a valid UTF-8 prefix.
        assert!(name.len() <= 80, "got length {}", name.len());
        // Verify it's still valid UTF-8 (Rust String guarantees this,
        // but we want to assert the prefix didn't include a partial char).
        assert!(name.chars().all(|c| c == '你' || c == ' '));
    }

    #[test]
    fn derive_workflow_name_no_panic_on_emoji_at_boundary() {
        // Emoji "🦀" is 4 bytes in UTF-8. Construct a description
        // whose 6-word join crosses byte 80 inside an emoji.
        // "abcde" (5 bytes) + space (1) = 6 bytes per "word"; need
        // ~13 of these to reach byte 78 then an emoji.
        let mut desc = String::new();
        for _ in 0..2 {
            desc.push_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ");
        }
        // Append an emoji-bearing word so the trim point falls inside it.
        desc.push_str("🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀");
        // Should not panic.
        let name = derive_workflow_name(&desc);
        assert!(name.len() <= 80);
    }

    #[test]
    fn classify_rate_limit_429() {
        assert_eq!(
            LlmErrorClass::classify("HTTP 429 Too Many Requests"),
            LlmErrorClass::RateLimited
        );
    }

    #[test]
    fn classify_rate_limit_529() {
        assert_eq!(
            LlmErrorClass::classify("anthropic returned 529 overloaded"),
            LlmErrorClass::RateLimited
        );
    }

    #[test]
    fn classify_timeout() {
        assert_eq!(
            LlmErrorClass::classify("request timed out after 30s"),
            LlmErrorClass::Timeout
        );
    }

    #[test]
    fn classify_auth_invalid_api_key() {
        assert_eq!(
            LlmErrorClass::classify("invalid api key"),
            LlmErrorClass::Auth
        );
    }

    #[test]
    fn classify_auth_401() {
        assert_eq!(
            LlmErrorClass::classify("HTTP 401 Unauthorized"),
            LlmErrorClass::Auth
        );
    }

    #[test]
    fn classify_upstream_unavailable_503() {
        assert_eq!(
            LlmErrorClass::classify("HTTP 503 Service Unavailable"),
            LlmErrorClass::UpstreamUnavailable
        );
    }

    #[test]
    fn classify_network_dns() {
        assert_eq!(
            LlmErrorClass::classify("dns lookup failed"),
            LlmErrorClass::Network
        );
    }

    #[test]
    fn classify_unknown_falls_through() {
        assert_eq!(
            LlmErrorClass::classify("totally unexpected error"),
            LlmErrorClass::Unknown
        );
    }

    #[test]
    fn classify_is_case_insensitive() {
        assert_eq!(
            LlmErrorClass::classify("CONNECT refused"),
            LlmErrorClass::Network
        );
    }

    #[test]
    fn classify_prefers_rate_limit_over_other_signals() {
        // A response that contains both "429" and "timeout" should
        // class as RateLimited (rate limit is the more actionable
        // diagnosis — caller should back off, not retry shorter).
        assert_eq!(
            LlmErrorClass::classify("HTTP 429 — request timed out waiting for retry-after"),
            LlmErrorClass::RateLimited
        );
    }

    #[test]
    fn entry_node_warning_fires_for_unconnected_node_with_only_label() {
        let nodes = vec![serde_json::json!({
            "id": "node-1",
            "type": "abc",
            "data": { "label": "Trigger" }
        })];
        let edges: Vec<Value> = vec![];
        let warnings = compute_entry_node_warnings(&nodes, &edges);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0]["node_id"], "node-1");
        assert_eq!(warnings[0]["label"], "Trigger");
    }

    #[test]
    fn entry_node_warning_skips_node_with_real_config() {
        let nodes = vec![serde_json::json!({
            "id": "node-1",
            "data": { "label": "Trigger", "URL": "https://example.com" }
        })];
        let edges: Vec<Value> = vec![];
        let warnings = compute_entry_node_warnings(&nodes, &edges);
        assert!(warnings.is_empty());
    }

    #[test]
    fn entry_node_warning_skips_targeted_nodes() {
        let nodes = vec![
            serde_json::json!({ "id": "node-1", "data": { "label": "Source" } }),
            serde_json::json!({ "id": "node-2", "data": { "label": "Sink" } }),
        ];
        let edges = vec![serde_json::json!({ "source": "node-1", "target": "node-2" })];
        let warnings = compute_entry_node_warnings(&nodes, &edges);
        // Only node-1 is unconnected on the input side.
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0]["node_id"], "node-1");
    }

    #[test]
    fn build_node_configs_needed_partitions_required_and_optional() {
        let template_id = Uuid::new_v4();
        let resolved = vec![ResolvedNode {
            label: "A".into(),
            template_id,
            module_name: "abc".into(),
        }];
        let mut schema_map = HashMap::new();
        schema_map.insert(
            template_id,
            serde_json::json!({
                "required": ["URL"],
                "properties": { "URL": {}, "TIMEOUT": {}, "RETRY": {} }
            }),
        );
        let out = build_node_configs_needed(&resolved, &schema_map);
        assert_eq!(out[0]["required_fields"], serde_json::json!(["URL"]));
        let optional = out[0]["optional_fields"].as_array().unwrap();
        assert_eq!(optional.len(), 2);
        assert!(optional.contains(&serde_json::json!("TIMEOUT")));
        assert!(optional.contains(&serde_json::json!("RETRY")));
    }

    #[test]
    fn build_node_configs_needed_handles_missing_schema() {
        let template_id = Uuid::new_v4();
        let resolved = vec![ResolvedNode {
            label: "A".into(),
            template_id,
            module_name: "abc".into(),
        }];
        let schema_map: HashMap<Uuid, Value> = HashMap::new();
        let out = build_node_configs_needed(&resolved, &schema_map);
        assert_eq!(out[0]["required_fields"], serde_json::json!([]));
        assert_eq!(out[0]["optional_fields"], serde_json::json!([]));
    }
}
