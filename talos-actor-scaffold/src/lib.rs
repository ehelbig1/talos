//! Actor scaffolding — application service.
//!
//! Backing logic for the `scaffold_actor` MCP tool. Compresses the
//! 7+-call sequence required to stand up a useful actor (create_actor →
//! set_actor_budget → actor_remember×N → create_workflow) into a
//! single atomic-ish call that produces a usable, opinionated actor.
//!
//! Design choices:
//!
//! * **Not a single transaction.** Actor creation is the only step that
//!   must be atomic on its own (per-user limit check). After the actor
//!   exists, every other step is best-effort: a memory-seed failure
//!   shouldn't roll back actor creation, since the user can retry just
//!   the failed memory write. The outcome struct reports per-step
//!   status so callers see exactly what landed.
//! * **Opinionated starter workflow.** The optional starter workflow
//!   uses the `llm-inference` catalog template with `INJECT_CONTEXT=true`
//!   and `SPOTLIGHTING=true` baked in — those are the two settings
//!   every actor-bound LLM workflow we've built has needed. Callers
//!   pick the system prompt + output schema; everything else is the
//!   reviewed defaults.
//! * **Fails-closed on capability ceiling.** Same RBAC checks that
//!   `handle_create_actor` runs (user ceiling, world validation). The
//!   service refuses to create the actor if the user can't grant the
//!   requested capability_world ceiling.
//!
//! Architectural fit: follows `SubworkflowContractService` shape — a
//! plain async function with a typed request/outcome/error trio, MCP
//! handler stays thin (parse args → call service → format response).

use serde_json::{json, Value as JsonValue};
use uuid::Uuid;

use std::sync::Arc;

use talos_actor_repository::ActorRepository;
use talos_module_repository::ModuleRepository;
use talos_workflow_repository::WorkflowRepository;

/// Narrow dependency container for [`scaffold_actor`] and friends. Replaces
/// the pre-extraction `&McpState` parameter so this crate doesn't have to
/// pull in controller's full service-locator type. Construct from McpState
/// fields at the call-site (see `controller::mcp::actor::handle_scaffold_actor`):
///
/// ```ignore
/// ScaffoldServiceDeps {
///     db_pool: deps.db_pool.clone(),
///     actor_repo: deps.actor_repo.clone(),
///     module_repo: deps.module_repo.clone(),
///     workflow_repo: deps.workflow_repo.clone(),
/// }
/// ```
#[derive(Clone)]
pub struct ScaffoldServiceDeps {
    pub db_pool: sqlx::PgPool,
    pub actor_repo: Arc<ActorRepository>,
    pub module_repo: Arc<ModuleRepository>,
    pub workflow_repo: Arc<WorkflowRepository>,
}

// ── Request shape ────────────────────────────────────────────────────────────

/// Per-key memory entry to seed during scaffold.
#[derive(Debug, Clone)]
pub struct SeedMemorySpec {
    pub key: String,
    pub value: JsonValue,
    /// Defaults to `"semantic"` (persona, role, expertise — the kind of
    /// memory an actor needs to behave consistently across runs).
    pub memory_type: String,
    /// Optional `metadata.kind` label so consumers can filter via
    /// `agent_memory::search_filtered(exclude_kinds: [...])`.
    pub metadata_kind: Option<String>,
    /// Per-entry TTL override; `None` means use the memory_type default
    /// (semantic = no expiry, episodic = 168 h).
    pub ttl_hours: Option<f64>,
}

/// Budget knobs to apply via `ActorRepository::upsert_actor_budget`.
/// Mirrors `set_actor_budget` argument shape so callers can pass through
/// the same JSON they would have sent to that tool.
#[derive(Debug, Clone, Default)]
pub struct BudgetSpec {
    pub max_executions_per_hour: Option<i32>,
    pub max_executions_total: Option<i64>,
    pub max_fuel_per_execution: Option<i64>,
    pub max_fuel_per_hour: Option<i64>,
    pub max_outbound_requests_per_hour: Option<i32>,
    pub max_workflow_count: Option<i32>,
    pub max_workflows_per_minute: Option<i32>,
    pub max_compilations_per_hour: Option<i32>,
    /// `"suspend"` (default) | `"alert"` | `"block"`.
    pub on_budget_exceeded: Option<String>,
}

/// Optional starter workflow shape. When present, the service builds
/// a single-node graph using the catalog `llm-inference` template with
/// the supplied prompt + output schema.
#[derive(Debug, Clone)]
pub struct StarterWorkflowSpec {
    /// Workflow name. Must be unique per user.
    pub name: String,
    /// Optional human description (lands in workflows.description).
    pub description: Option<String>,
    /// Required: the system prompt the LLM sees on every run. The
    /// llm-inference template handles `{{key}}` interpolation against
    /// upstream node output at runtime, so callers can include
    /// placeholders here.
    pub system_prompt: String,
    /// Required keys in the LLM JSON output. The template enforces
    /// presence and fails the node if any are missing — this is the
    /// "make the LLM return structured data" knob.
    pub output_schema_keys: Vec<String>,
    /// Default `2048`.
    pub max_tokens: u32,
    /// Default `"anthropic"`. Pass `"ollama"` for tier-1 local actors.
    pub provider: String,
    /// Default `"claude-sonnet-4-6"` for anthropic; for ollama default
    /// to whatever the operator's preferred local model is.
    pub model: Option<String>,
}

/// LLM data-egress ceiling.
///
/// Pure-data enum lives in `talos-actor-types`; the wire-protocol
/// conversion stays in this module since the protocol crate is a
/// controller-side dep, not a domain-types dep.
pub use talos_actor_types::LlmTier;

/// Lower a domain `LlmTier` to its wire-protocol counterpart so the
/// request layer can hand it to `set_actor_max_llm_tier` and friends.
fn llm_tier_to_protocol(tier: LlmTier) -> talos_workflow_job_protocol::LlmTier {
    match tier {
        LlmTier::Tier1 => talos_workflow_job_protocol::LlmTier::Tier1,
        LlmTier::Tier2 => talos_workflow_job_protocol::LlmTier::Tier2,
    }
}

#[derive(Debug, Clone)]
pub struct ScaffoldRequest {
    pub name: String,
    pub description: Option<String>,
    /// Capability ceiling (e.g. `"agent-node"`, `"http-node"`).
    /// Defaults to `"agent-node"` since this service exists to scaffold
    /// actor-bound workflows; a lower ceiling like `"minimal-node"`
    /// blocks the standard agent loop.
    pub max_capability_world: String,
    pub llm_tier: Option<LlmTier>,
    pub budget: Option<BudgetSpec>,
    pub seed_memories: Vec<SeedMemorySpec>,
    pub starter_workflow: Option<StarterWorkflowSpec>,
}

// ── Outcome shape ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MemorySeedFailure {
    pub key: String,
    pub error: String,
}

#[derive(Debug, Clone)]
pub struct ScaffoldOutcome {
    pub actor_id: Uuid,
    pub actor_name: String,
    pub max_capability_world: String,
    pub llm_tier_set: Option<String>,
    pub budget_set: bool,
    pub memories_seeded: u32,
    pub memory_failures: Vec<MemorySeedFailure>,
    pub workflow_id: Option<Uuid>,
    /// Populated when the optional starter-workflow step failed AFTER the
    /// actor was successfully created. Lets the caller surface a soft
    /// warning instead of an error envelope.
    pub workflow_warning: Option<String>,
    /// Populated when the optional budget step failed AFTER the actor
    /// was successfully created. Same soft-failure rationale.
    pub budget_warning: Option<String>,
    /// Populated when the optional llm_tier step failed AFTER the actor
    /// was successfully created.
    pub llm_tier_warning: Option<String>,
}

impl ScaffoldOutcome {
    pub fn to_tool_body(&self) -> JsonValue {
        let mut body = json!({
            "actor_id": self.actor_id.to_string(),
            "name": self.actor_name,
            "max_capability_world": self.max_capability_world,
            "llm_tier": self.llm_tier_set,
            "budget_set": self.budget_set,
            "memories_seeded": self.memories_seeded,
            "memory_failures": self.memory_failures.iter().map(|f| json!({
                "key": f.key,
                "error": f.error,
            })).collect::<Vec<_>>(),
            "workflow_id": self.workflow_id.map(|i| i.to_string()),
        });
        if let Some(w) = &self.workflow_warning {
            body["workflow_warning"] = json!(w);
        }
        if let Some(w) = &self.budget_warning {
            body["budget_warning"] = json!(w);
        }
        if let Some(w) = &self.llm_tier_warning {
            body["llm_tier_warning"] = json!(w);
        }
        body
    }
}

// ── Error shape ──────────────────────────────────────────────────────────────

/// Failure modes from the *required* steps. Optional-step failures land
/// in the outcome's `*_warning` fields, not here.
#[derive(Debug)]
pub enum ScaffoldError {
    InvalidName(String),
    InvalidDescription(String),
    InvalidCapabilityWorld(String),
    /// User's own capability ceiling is below `max_capability_world`.
    CapabilityCeilingExceeded {
        user_ceiling: String,
        requested: String,
    },
    /// Per-user actor count limit hit before INSERT could land.
    ActorLimitReached(i64),
    /// Postgres unique-constraint violation on actor name.
    DuplicateName(String),
    InvalidLlmTier(String),
    InvalidBudgetField(String),
    InvalidStarterWorkflow(String),
    DatabaseError(String),
}

impl ScaffoldError {
    pub fn user_message(&self) -> String {
        match self {
            Self::InvalidName(m) => m.clone(),
            Self::InvalidDescription(m) => m.clone(),
            Self::InvalidCapabilityWorld(m) => m.clone(),
            Self::CapabilityCeilingExceeded { user_ceiling, requested } => format!(
                "Your capability ceiling is '{}'. Creating an actor with '{}' requires a higher grant. \
                 Contact a platform admin to request grant_capability_ceiling.",
                user_ceiling, requested
            ),
            Self::ActorLimitReached(n) => format!(
                "Actor limit reached (max {}). Delete unused actors before creating new ones.",
                n
            ),
            Self::DuplicateName(n) => format!("An actor named '{}' already exists", n),
            Self::InvalidLlmTier(m) => m.clone(),
            Self::InvalidBudgetField(m) => m.clone(),
            Self::InvalidStarterWorkflow(m) => m.clone(),
            Self::DatabaseError(_) => "Database error during scaffold".to_string(),
        }
    }
}

// ── Constants ────────────────────────────────────────────────────────────────

/// Same per-user cap `handle_create_actor` enforces. Kept here as a
/// const so a future single-source-of-truth move can swap both call
/// sites in lockstep.
const MAX_ACTORS_PER_USER: i64 = 1000;

// ── Service entry point ──────────────────────────────────────────────────────

pub async fn scaffold_actor(
    deps: &ScaffoldServiceDeps,
    user_id: Uuid,
    req: ScaffoldRequest,
) -> Result<ScaffoldOutcome, ScaffoldError> {
    // ── 1. Up-front validation (before any DB write) ─────────────────────
    validate_name(&req.name)?;
    if let Some(d) = &req.description {
        validate_description(d)?;
    }
    if !talos_capability_world::is_actor_ceiling_world(&req.max_capability_world) {
        // MCP-1030: cap reflected world at 64 chars.
        let preview = talos_text_util::bounded_preview(&req.max_capability_world, 64);
        return Err(ScaffoldError::InvalidCapabilityWorld(format!(
            "Invalid max_capability_world '{preview}'. Valid values: {}",
            talos_capability_world::actor_ceiling_worlds_csv()
        )));
    }

    // RBAC: user can only create actors at or below their own ceiling.
    let user_ceiling = user_max_world_str(&deps.db_pool, user_id).await;
    if talos_capability_world::world_rank(&req.max_capability_world)
        > talos_capability_world::world_rank(user_ceiling)
    {
        return Err(ScaffoldError::CapabilityCeilingExceeded {
            user_ceiling: user_ceiling.to_string(),
            requested: req.max_capability_world.clone(),
        });
    }

    // Validate budget shape before doing any work — same positivity
    // checks `handle_set_actor_budget` runs. Catching here avoids the
    // half-built-actor case where the actor exists but the budget call
    // returns a confusing -32602 separately.
    if let Some(b) = &req.budget {
        validate_budget(b)?;
    }
    if let Some(sw) = &req.starter_workflow {
        validate_starter_workflow(sw)?;
    }

    // ── 2. Create the actor (atomic, must succeed) ───────────────────────
    let actor_id = Uuid::new_v4();
    let inserted = deps
        .actor_repo
        .insert_actor_with_limit_check(
            actor_id,
            user_id,
            &req.name,
            req.description.as_deref(),
            &req.max_capability_world,
            MAX_ACTORS_PER_USER,
        )
        .await
        .map_err(|e| {
            let s = e.to_string();
            if s.contains("unique") || s.contains("duplicate") {
                ScaffoldError::DuplicateName(req.name.clone())
            } else {
                tracing::error!(?e, "scaffold_actor: insert_actor failed");
                ScaffoldError::DatabaseError(s)
            }
        })?;
    if inserted == 0 {
        return Err(ScaffoldError::ActorLimitReached(MAX_ACTORS_PER_USER));
    }

    // Best-effort audit log entry — same semantics as create_actor.
    talos_actor_repository::spawn_log_action(
        deps.db_pool.clone(),
        actor_id,
        "created",
        None,
        None,
        format!("Actor '{}' scaffolded", req.name),
        Some(json!({
            "max_capability_world": req.max_capability_world,
            "via": "scaffold_actor",
        })),
    );

    let mut outcome = ScaffoldOutcome {
        actor_id,
        actor_name: req.name.clone(),
        max_capability_world: req.max_capability_world.clone(),
        llm_tier_set: None,
        budget_set: false,
        memories_seeded: 0,
        memory_failures: Vec::new(),
        workflow_id: None,
        workflow_warning: None,
        budget_warning: None,
        llm_tier_warning: None,
    };

    // ── 3. LLM tier (best effort) ────────────────────────────────────────
    if let Some(tier) = req.llm_tier {
        match deps
            .actor_repo
            .set_actor_max_llm_tier(actor_id, user_id, llm_tier_to_protocol(tier))
            .await
        {
            Ok(true) => {
                outcome.llm_tier_set =
                    Some(llm_tier_to_protocol(tier).as_signing_str().to_string());
            }
            Ok(false) => {
                outcome.llm_tier_warning = Some(
                    "set_actor_max_llm_tier returned 0 rows — actor may have been deleted concurrently"
                        .to_string(),
                );
            }
            Err(e) => {
                tracing::warn!(%actor_id, error = %e, "scaffold_actor: set_actor_max_llm_tier failed");
                outcome.llm_tier_warning = Some(format!("Failed to set llm_tier: {}", e));
            }
        }
    }

    // ── 4. Budget (best effort) ──────────────────────────────────────────
    if let Some(b) = &req.budget {
        let on_exceeded = b.on_budget_exceeded.as_deref().unwrap_or("suspend");
        // Same platform-default safety nets as handle_set_actor_budget.
        let wpm = b.max_workflows_per_minute.unwrap_or(10);
        let cph = b.max_compilations_per_hour.unwrap_or(20);
        match deps
            .actor_repo
            .upsert_actor_budget(
                actor_id,
                user_id,
                b.max_executions_per_hour,
                b.max_executions_total,
                b.max_fuel_per_execution,
                b.max_fuel_per_hour,
                b.max_outbound_requests_per_hour,
                b.max_workflow_count,
                wpm,
                cph,
                on_exceeded,
            )
            .await
        {
            Ok(rows) if rows > 0 => outcome.budget_set = true,
            Ok(_) => {
                // L T4-2: zero rows_affected = actor not found / cross-tenant
                // mismatch. The scaffold flow just inserted the actor on the
                // same `user_id`, so this should be unreachable; warn loudly
                // if it ever fires.
                tracing::warn!(
                    %actor_id,
                    "scaffold_actor: upsert_actor_budget returned 0 rows — actor ownership mismatch"
                );
                outcome.budget_warning = Some(
                    "Failed to set budget: actor ownership mismatch".to_string(),
                );
            }
            Err(e) => {
                tracing::warn!(%actor_id, error = %e, "scaffold_actor: upsert_actor_budget failed");
                outcome.budget_warning = Some(format!("Failed to set budget: {}", e));
            }
        }
    }

    // ── 5. Seed memories (per-key best effort) ───────────────────────────
    for seed in &req.seed_memories {
        let metadata_value = seed.metadata_kind.as_ref().map(|k| json!({ "kind": k }));
        let result = talos_memory::persist_memory_with_metadata(
            &deps.db_pool,
            actor_id,
            &seed.key,
            &seed.value,
            metadata_value.as_ref(),
            &seed.memory_type,
            seed.ttl_hours,
        )
        .await;
        match result {
            Ok(_) => outcome.memories_seeded += 1,
            Err(e) => {
                tracing::warn!(
                    %actor_id, key = %seed.key, error = %e,
                    "scaffold_actor: seed memory failed"
                );
                outcome.memory_failures.push(MemorySeedFailure {
                    key: seed.key.clone(),
                    error: e.to_string(),
                });
            }
        }
    }

    // ── 6. Starter workflow (best effort) ────────────────────────────────
    if let Some(sw) = &req.starter_workflow {
        match build_and_create_starter_workflow(deps, user_id, actor_id, sw).await {
            Ok(wf_id) => outcome.workflow_id = Some(wf_id),
            Err(msg) => {
                tracing::warn!(%actor_id, error = %msg, "scaffold_actor: starter workflow failed");
                outcome.workflow_warning = Some(msg);
            }
        }
    }

    Ok(outcome)
}

// ── Validators ───────────────────────────────────────────────────────────────

fn validate_name(name: &str) -> Result<(), ScaffoldError> {
    // MCP-219 (2026-05-08): trim before the empty check so a
    // whitespace-only name (`"   "`) fails closed instead of being
    // persisted as an actor whose name is blank. Same family as
    // MCP-218 / MCP-203 / MCP-216 whitespace-bypass class.
    //
    // MCP-513: length check uses codepoint count, not byte length.
    // Pre-fix `name.len() > 100` was byte-length: a 34-character CJK
    // name (3 bytes per char ≈ 102 bytes) would fail despite the
    // user thinking they sent ≤100 characters as the error message
    // promised. The empty check was already correctly char-aware via
    // `trim()` + `is_empty()`; the length check now matches.
    // `trim()` is applied to BOTH for consistency — `"  hello  "` is
    // 5 chars, not 9, by the new rules.
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 100 {
        return Err(ScaffoldError::InvalidName(
            "Actor name must be 1–100 non-whitespace characters".to_string(),
        ));
    }
    Ok(())
}

fn validate_description(d: &str) -> Result<(), ScaffoldError> {
    // MCP-513: same byte-vs-char fix as `validate_name`. A 1700-char
    // CJK description (≈ 5100 bytes) would fail despite being well
    // under the documented "5000 characters" limit.
    if d.chars().count() > 5000 {
        return Err(ScaffoldError::InvalidDescription(
            "Actor description must be ≤ 5000 characters".to_string(),
        ));
    }
    Ok(())
}

fn validate_budget(b: &BudgetSpec) -> Result<(), ScaffoldError> {
    if let Some(s) = &b.on_budget_exceeded {
        if !["suspend", "alert", "block"].contains(&s.as_str()) {
            return Err(ScaffoldError::InvalidBudgetField(
                "on_budget_exceeded must be 'suspend', 'alert', or 'block'".to_string(),
            ));
        }
    }
    let positive: [(&str, Option<i64>); 8] = [
        (
            "max_executions_per_hour",
            b.max_executions_per_hour.map(|n| n as i64),
        ),
        ("max_executions_total", b.max_executions_total),
        ("max_fuel_per_execution", b.max_fuel_per_execution),
        ("max_fuel_per_hour", b.max_fuel_per_hour),
        (
            "max_outbound_requests_per_hour",
            b.max_outbound_requests_per_hour.map(|n| n as i64),
        ),
        ("max_workflow_count", b.max_workflow_count.map(|n| n as i64)),
        (
            "max_workflows_per_minute",
            b.max_workflows_per_minute.map(|n| n as i64),
        ),
        (
            "max_compilations_per_hour",
            b.max_compilations_per_hour.map(|n| n as i64),
        ),
    ];
    for (field, val) in &positive {
        if let Some(n) = val {
            if *n <= 0 {
                return Err(ScaffoldError::InvalidBudgetField(format!(
                    "{field} must be a positive integer, got {n}"
                )));
            }
        }
    }
    Ok(())
}

fn validate_starter_workflow(sw: &StarterWorkflowSpec) -> Result<(), ScaffoldError> {
    // MCP-219 (2026-05-08): trim-before-check so whitespace-only
    // values fail closed instead of being persisted.
    //
    // MCP-547: name length must be codepoint count, not byte length —
    // the error message promises "1–200 characters". Same byte-vs-char
    // mismatch class that MCP-513 fixed in `validate_name` and
    // `validate_description`; this site was missed in that sweep. A
    // 67-character CJK name (≈ 201 bytes) failed validation despite
    // being under the documented character cap.
    let trimmed_name = sw.name.trim();
    if trimmed_name.is_empty() || trimmed_name.chars().count() > 200 {
        return Err(ScaffoldError::InvalidStarterWorkflow(
            "starter_workflow.name must be 1–200 non-whitespace characters".to_string(),
        ));
    }
    if sw.system_prompt.trim().is_empty() {
        return Err(ScaffoldError::InvalidStarterWorkflow(
            "starter_workflow.system_prompt is required (non-empty, non-whitespace)".to_string(),
        ));
    }
    // MCP-547: system_prompt cap stays byte-based because the error
    // message documents it as "≤ 64 KiB" (a byte unit, not a character
    // count). Byte-based is also correct for the underlying concern —
    // the prompt eventually rides in a JobRequest envelope whose total
    // byte budget is what matters at the wire layer. Comment kept as a
    // tripwire if a future maintainer flips this to chars().count().
    if sw.system_prompt.len() > 64 * 1024 {
        return Err(ScaffoldError::InvalidStarterWorkflow(
            "starter_workflow.system_prompt must be ≤ 64 KiB".to_string(),
        ));
    }
    if sw.max_tokens == 0 || sw.max_tokens > 16_384 {
        return Err(ScaffoldError::InvalidStarterWorkflow(
            "starter_workflow.max_tokens must be 1–16384".to_string(),
        ));
    }
    if sw.output_schema_keys.len() > 32 {
        return Err(ScaffoldError::InvalidStarterWorkflow(
            "starter_workflow.output_schema_keys: at most 32 keys".to_string(),
        ));
    }
    Ok(())
}

// ── Starter workflow assembly ───────────────────────────────────────────────

/// Build and persist a single-node llm-inference workflow bound to the
/// freshly-created actor. Returns the new workflow_id.
async fn build_and_create_starter_workflow(
    deps: &ScaffoldServiceDeps,
    user_id: Uuid,
    actor_id: Uuid,
    sw: &StarterWorkflowSpec,
) -> Result<Uuid, String> {
    // Resolve the catalog `llm-inference` template's UUID. The OCI sync
    // path (`registry/sync.rs::sync_template`) prefers `display_name` over
    // `name` when populating `modules.name`, so the row ends up stored as
    // "LLM Inference" — a plain `find_template_id_by_name_ci("llm-inference")`
    // would silently miss it. The 4-way normaliser folds spaces↔dashes and
    // strips non-kebab chars on both sides so canonical-name lookups land
    // regardless of which install path wrote the row.
    let module_id = match deps
        .module_repo
        .find_template_id_by_name_normalised("llm-inference")
        .await
        .map_err(|e| format!("Lookup of catalog 'llm-inference' failed: {}", e))?
    {
        Some(id) => id,
        None => {
            // Enrich the not-found error with up to 5 closest names from the
            // existing modules table. Catches the "operator typed 'llm_inf'
            // but the row is named 'LLM Inference'" class of confusion that
            // an opaque "not found" leaves the caller guessing about.
            let suggestions = deps
                .module_repo
                .suggest_template_names_for_miss("llm-inference", user_id, 5)
                .await;
            let hint = if suggestions.is_empty() {
                "no nearby names — call `list_module_catalog` to see what's installed".to_string()
            } else {
                format!("did you mean: {}", suggestions.join(", "))
            };
            return Err(format!(
                "Catalog template 'llm-inference' not found ({hint}). \
                 Install it before scaffolding a starter workflow: \
                 `install_module_from_catalog name=llm-inference`."
            ));
        }
    };

    // Build the LLM node config matching the talos.json schema for the
    // llm-inference template. The fixed fields below are the defaults
    // we've validated in production for actor-bound workflows.
    let mut data = json!({
        "PROVIDER": sw.provider,
        "SYSTEM_PROMPT": sw.system_prompt,
        "MAX_TOKENS": sw.max_tokens,
        "INJECT_CONTEXT": true,
        "SPOTLIGHTING": true,
    });
    if let Some(model) = &sw.model {
        data["MODEL"] = json!(model);
    }
    if !sw.output_schema_keys.is_empty() {
        // Comma-separated form is what the template's parser
        // (`OUTPUT_SCHEMA: a,b,c`) expects; equally accepts JSON array
        // but the string form is shorter in graph_json.
        data["OUTPUT_SCHEMA"] = json!(sw.output_schema_keys.join(","));
    }

    // Single-node graph. retry_count=1 + retry_backoff_ms=500 matches
    // the default retry shape every actor-bound workflow we've shipped.
    let node_id = "synthesize";
    let graph = json!({
        "nodes": [{
            "id": node_id,
            "type": module_id.to_string(),
            "position": { "x": 100, "y": 200 },
            "data": data,
            "retry_count": 1,
            "retry_backoff_ms": 500,
        }],
        "edges": []
    });
    let graph_str = serde_json::to_string(&graph)
        .map_err(|e| format!("Failed to serialize starter graph: {}", e))?;

    let wf_id = deps
        .workflow_repo
        .create_workflow(
            user_id,
            &sw.name,
            &graph_str,
            sw.description.as_deref(),
            &[],            // tags
            &[],            // capabilities — engine derives from nodes
            None,           // intent
            None,           // max_concurrent
            None,           // timeout
            Some(actor_id), // actor binding — required for INJECT_CONTEXT
        )
        .await
        .map_err(|e| {
            let s = e.to_string();
            if s.contains("unique") || s.contains("duplicate") {
                format!("Workflow named '{}' already exists", sw.name)
            } else {
                tracing::error!(?e, "scaffold starter workflow create failed");
                format!("Failed to create starter workflow: {}", e)
            }
        })?;
    Ok(wf_id)
}

// ── Local helpers ────────────────────────────────────────────────────────────

/// Same default-ceiling helper `handle_create_actor` uses, lifted out
/// so the service doesn't reach into mcp/actor.rs internals beyond the
/// already-public `world_rank` + `is_actor_ceiling_world`.
async fn user_max_world_str(pool: &sqlx::PgPool, user_id: Uuid) -> &'static str {
    // MCP-816 (2026-05-14): delegate canonicalization to the
    // `talos_capability_world` crate instead of hand-rolling a match
    // arm per world. Pre-fix this match was missing `"agent-node"` and
    // `"trusted-node"` — users with those ceilings stored in the DB
    // fell through to `_ => "http-node"`, silently downgrading their
    // effective ceiling at the `create_actor` RBAC check. A user with
    // a granted `agent-node` ceiling who tried to spawn an agent-tier
    // actor would be rejected with "ceiling exceeded" — the user's
    // ACTUAL ceiling, returned via this helper, was http-node (rank 1),
    // while the requested actor ceiling (rank 6) sailed past it.
    //
    // Also accepted the dead `"standard-node"` and `"full-node"` labels
    // (closed at the grant-handler layer in the same MCP). Switching
    // to the canonical FromStr + `as_node_str()` round-trip:
    //   - Recognizes EVERY canonical ceiling (incl. agent-node,
    //     trusted-node, automation-node, llm-node).
    //   - Normalizes `trusted-node`/`automation-node` to the public-
    //     facing `automation-node` form.
    //   - Returns `Unknown` for legacy/dead labels — falls through to
    //     the safer `"http-node"` default rather than silently passing
    //     a label downstream that the dispatcher would reject.
    use std::str::FromStr;
    use talos_capability_world::CapabilityWorld;
    let repo = ActorRepository::new(pool.clone());
    let row = repo
        .get_user_max_capability_world(user_id)
        .await
        .ok()
        .flatten();
    row.as_deref()
        .and_then(|s| CapabilityWorld::from_str(s).ok())
        .filter(|w| !matches!(w, CapabilityWorld::Unknown))
        .map(|w| w.as_node_str())
        .unwrap_or("http-node")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_name_rejects_empty() {
        assert!(matches!(
            validate_name(""),
            Err(ScaffoldError::InvalidName(_))
        ));
    }

    #[test]
    fn validate_name_rejects_overlong() {
        let long = "a".repeat(101);
        assert!(matches!(
            validate_name(&long),
            Err(ScaffoldError::InvalidName(_))
        ));
    }

    #[test]
    fn validate_name_accepts_normal() {
        assert!(validate_name("aegix-vpe").is_ok());
    }

    /// MCP-513: pre-fix the length check was byte-based. A 50-char
    /// CJK name (≈ 150 bytes) would have been rejected as overlong
    /// despite being well under the documented 100-character limit.
    #[test]
    fn validate_name_accepts_unicode_under_char_cap() {
        // 50 CJK characters = 150 bytes when UTF-8 encoded. Pre-fix
        // this failed; post-fix it passes.
        let cjk_name: String = "京".repeat(50);
        assert_eq!(cjk_name.chars().count(), 50);
        assert!(cjk_name.len() > 100, "byte length must exceed 100 for this to be a useful test");
        assert!(validate_name(&cjk_name).is_ok());
    }

    /// MCP-513: a 101-codepoint name is rejected regardless of byte
    /// length — the cap is per-character per the error message.
    #[test]
    fn validate_name_rejects_overlong_unicode_by_char_count() {
        let cjk_name: String = "京".repeat(101);
        assert_eq!(cjk_name.chars().count(), 101);
        assert!(matches!(
            validate_name(&cjk_name),
            Err(ScaffoldError::InvalidName(_))
        ));
    }

    /// MCP-513: trim is applied to BOTH the empty check AND the
    /// length check. `"  hello  "` is 5 characters, not 9.
    #[test]
    fn validate_name_trim_applies_to_length() {
        // 100 chars of content surrounded by leading/trailing spaces.
        // Raw length is 104; trimmed length is 100. Must pass.
        let name = format!("  {}  ", "a".repeat(100));
        assert_eq!(name.len(), 104);
        assert!(validate_name(&name).is_ok());
    }

    /// MCP-513: same byte-vs-char fix for description length.
    #[test]
    fn validate_description_accepts_unicode_under_char_cap() {
        let cjk = "京".repeat(2000); // 2000 chars × 3 bytes = 6000 bytes
        assert_eq!(cjk.chars().count(), 2000);
        assert!(cjk.len() > 5000);
        assert!(validate_description(&cjk).is_ok());
    }

    #[test]
    fn validate_budget_rejects_zero() {
        let mut b = BudgetSpec::default();
        b.max_fuel_per_execution = Some(0);
        assert!(matches!(
            validate_budget(&b),
            Err(ScaffoldError::InvalidBudgetField(_))
        ));
    }

    #[test]
    fn validate_budget_rejects_negative() {
        let mut b = BudgetSpec::default();
        b.max_executions_per_hour = Some(-1);
        assert!(matches!(
            validate_budget(&b),
            Err(ScaffoldError::InvalidBudgetField(_))
        ));
    }

    #[test]
    fn validate_budget_rejects_unknown_on_exceeded() {
        let mut b = BudgetSpec::default();
        b.on_budget_exceeded = Some("explode".to_string());
        assert!(matches!(
            validate_budget(&b),
            Err(ScaffoldError::InvalidBudgetField(_))
        ));
    }

    #[test]
    fn validate_budget_accepts_empty() {
        // No fields = valid (operator wants defaults for everything).
        assert!(validate_budget(&BudgetSpec::default()).is_ok());
    }

    fn good_starter() -> StarterWorkflowSpec {
        StarterWorkflowSpec {
            name: "vpe-review".to_string(),
            description: None,
            system_prompt: "You review code.".to_string(),
            output_schema_keys: vec!["summary".to_string(), "issues".to_string()],
            max_tokens: 2048,
            provider: "anthropic".to_string(),
            model: None,
        }
    }

    #[test]
    fn validate_starter_rejects_empty_prompt() {
        let mut sw = good_starter();
        sw.system_prompt = "".to_string();
        assert!(matches!(
            validate_starter_workflow(&sw),
            Err(ScaffoldError::InvalidStarterWorkflow(_))
        ));
    }

    #[test]
    fn validate_starter_rejects_zero_tokens() {
        let mut sw = good_starter();
        sw.max_tokens = 0;
        assert!(matches!(
            validate_starter_workflow(&sw),
            Err(ScaffoldError::InvalidStarterWorkflow(_))
        ));
    }

    #[test]
    fn validate_starter_rejects_overlong_prompt() {
        let mut sw = good_starter();
        sw.system_prompt = "x".repeat(64 * 1024 + 1);
        assert!(matches!(
            validate_starter_workflow(&sw),
            Err(ScaffoldError::InvalidStarterWorkflow(_))
        ));
    }

    #[test]
    fn validate_starter_rejects_too_many_keys() {
        let mut sw = good_starter();
        sw.output_schema_keys = (0..33).map(|i| format!("k{i}")).collect();
        assert!(matches!(
            validate_starter_workflow(&sw),
            Err(ScaffoldError::InvalidStarterWorkflow(_))
        ));
    }

    #[test]
    fn validate_starter_accepts_good() {
        assert!(validate_starter_workflow(&good_starter()).is_ok());
    }

    /// MCP-547: name length cap must count CODEPOINTS, not bytes.
    /// Pre-fix `sw.name.len() > 200` (byte length) rejected a 67-char
    /// CJK name (~201 bytes) despite being well under the documented
    /// "200 characters" limit.
    #[test]
    fn validate_starter_accepts_unicode_under_char_cap() {
        let mut sw = good_starter();
        // 100 CJK characters = ~300 bytes — well over the byte cap,
        // well under the codepoint cap.
        sw.name = "工".repeat(100);
        assert_eq!(sw.name.chars().count(), 100);
        assert!(sw.name.len() > 200, "test setup: must exceed byte cap");
        assert!(
            validate_starter_workflow(&sw).is_ok(),
            "MCP-547: should accept 100-char Unicode name"
        );
    }

    /// MCP-547: name length cap rejects 201 codepoints (one above limit).
    #[test]
    fn validate_starter_rejects_overlong_unicode_by_char_count() {
        let mut sw = good_starter();
        sw.name = "工".repeat(201);
        assert_eq!(sw.name.chars().count(), 201);
        let err = validate_starter_workflow(&sw).unwrap_err();
        match err {
            ScaffoldError::InvalidStarterWorkflow(msg) => {
                assert!(msg.contains("1–200"), "got: {msg}");
            }
            other => panic!("expected InvalidStarterWorkflow, got {other:?}"),
        }
    }

    /// MCP-547: trim applies to the codepoint length too.
    /// `"   工工工   "` is 9 codepoints (3 spaces + 3 CJK + 3 spaces)
    /// but only 3 after trim. Length cap uses the trimmed form.
    #[test]
    fn validate_starter_name_trim_applies_to_length() {
        let mut sw = good_starter();
        // 200 chars of trimmed content + 50 chars of surrounding whitespace
        // = 250 raw codepoints but trim()'d to 200, which must accept.
        sw.name = format!("{}{}{}", " ".repeat(25), "工".repeat(200), " ".repeat(25));
        assert!(
            validate_starter_workflow(&sw).is_ok(),
            "trim before counting codepoints"
        );
    }

    #[test]
    fn llm_tier_from_arg_known_values() {
        assert_eq!(LlmTier::from_arg("tier1").unwrap(), LlmTier::Tier1);
        assert_eq!(LlmTier::from_arg("tier2").unwrap(), LlmTier::Tier2);
    }

    #[test]
    fn llm_tier_from_arg_unknown() {
        assert!(LlmTier::from_arg("super").is_err());
    }
}
