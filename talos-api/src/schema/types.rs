//! GraphQL type definitions, input types, enums, and DataLoaders.

use async_graphql::{ComplexObject, Context, InputObject, Result, SimpleObject};
use talos_module_executions as module_executions;
use uuid::Uuid;

use crate::schema::SafeErrorExtensions;

// Re-import types needed by DataLoaders and ComplexObject impls

#[derive(SimpleObject, Clone)]
#[graphql(complex)]
pub struct Workflow {
    pub id: Uuid,
    pub name: String,
    /// Serialized representation of the graph (flexible JSON).
    pub graph_json: String,
    /// Maximum number of concurrent executions allowed (null = unlimited).
    pub max_concurrent_executions: Option<i32>,
    /// Optional structured intent metadata.
    pub intent: Option<serde_json::Value>,
    /// Actor that owns this workflow, if any.
    pub actor_id: Option<Uuid>,
}

#[derive(SimpleObject, Clone)]
pub struct NodeTemplate {
    pub id: Uuid,
    pub name: String,
    pub category: String,
    pub description: Option<String>,
    pub config_schema: String, // Serialized JSON
    pub icon: Option<String>,
    pub allowed_hosts: Vec<String>,
    /// The WIT capability world this template compiles to (e.g.
    /// `"secrets-node"`, `"http-node"`, `"minimal-node"`). Surfaced so a
    /// caller can see, BEFORE installing, the minimum actor capability
    /// ceiling required to run a module built from this template — instead
    /// of discovering it via a ceiling-denial at trigger time. Pair with
    /// the `capabilityWorldHierarchy` query for the rank + description.
    pub capability_world: String,
    /// Vault secret paths (or prefix globs) this template needs granted,
    /// e.g. `["oauth/gmail/*"]`. Surfaced so a caller knows what to set up
    /// before running rather than hitting a resolution failure.
    pub requires_secrets: Vec<String>,
    /// Operation categories that make a module built from this template
    /// pause for human approval at run time (e.g. `["network_scan"]`).
    /// Empty for templates that never suspend. Surfaced so a suspension
    /// isn't a surprise.
    pub requires_approval_for: Vec<String>,
}

#[derive(SimpleObject, Clone)]
#[graphql(complex)]
pub struct WasmModule {
    pub id: Uuid,
    pub name: String,
    pub size_bytes: i32,
    pub content_hash: String,
    pub compiled_at: String, // ISO datetime
    pub config: String,      // JSON string of module configuration
    /// JSON string of the module's declared config schema (talos.json
    /// `config_schema`), when the module declares one. The editor uses the
    /// schema's REQUIRED KEYS as a rename-stable module identity.
    pub config_schema: Option<String>,
    /// Origin catalog template slug (e.g. "smart-classifier"); stable under
    /// display-name renames. None for sandbox/extracted modules.
    pub catalog_slug: Option<String>,
    pub capability_world: Option<String>,
    pub imported_interfaces: Option<Vec<String>>,
    pub source_code: Option<String>,
    /// Source language: "rust", "javascript", or "typescript". Defaults to "rust".
    pub language: Option<String>,
}

#[derive(SimpleObject, Clone)]
#[graphql(complex)]
pub struct WebhookTrigger {
    pub id: Uuid,
    #[graphql(skip)]
    pub module_id: Option<Uuid>,
    pub name: String,
    pub webhook_url: String,
    pub verification_token: Option<String>, // Only populated on creation
    pub enabled: bool,
    pub max_requests_per_minute: i32,
    pub trigger_count: i32,
    pub success_count: i32,
    pub error_count: i32,
    pub last_triggered_at: Option<String>,
    /// RFC 0007: the trigger's event filter, if any (null = fire on every
    /// verified delivery). Read-only; set via `createWebhookTrigger`.
    pub event_filter: Option<serde_json::Value>,
}
#[ComplexObject]
impl WebhookTrigger {
    async fn module(&self, ctx: &Context<'_>) -> Result<Option<WasmModule>> {
        if let Some(id) = self.module_id {
            let loader = ctx.data::<async_graphql::dataloader::DataLoader<ModuleLoader>>()?;
            Ok(loader.load_one(id).await?)
        } else {
            Ok(None)
        }
    }
}

#[derive(SimpleObject, Clone)]
pub struct Secret {
    pub id: Uuid,
    pub name: String,
    pub key_path: String,
    pub description: Option<String>,
    pub created_at: String,
    pub last_accessed_at: Option<String>,
    pub access_count: i32,
    pub expires_at: Option<String>,
}

#[derive(SimpleObject, Clone)]
pub struct SecretAuditLog {
    pub id: Uuid,
    pub action: String,
    pub actor_type: String,
    pub success: bool,
    pub timestamp: String,
    pub error_message: Option<String>,
}

#[derive(SimpleObject, Clone)]
pub struct ApiKeyInfo {
    pub id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub scopes: Vec<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub is_active: bool,
    pub usage_count: i32,
}

#[derive(SimpleObject, Clone)]
pub struct ApiKeyCreated {
    pub id: Uuid,
    pub name: String,
    pub key: String, // Full key - only shown once!
    pub scopes: Vec<String>,
    pub expires_at: Option<String>,
}

/// Result of a DEK rotation operation.
#[derive(SimpleObject, Clone)]
pub struct DekRotationResult {
    /// The UUID of the newly created DEK.
    pub new_dek_id: Uuid,
    /// Human-readable status message.
    pub message: String,
}

/// Result of a re-encryption operation.
#[derive(SimpleObject, Clone)]
pub struct ReEncryptionResult {
    /// Number of secrets that were re-encrypted with the new active DEK.
    pub re_encrypted_count: u64,
    /// L T2-6: number of secrets that failed to re-encrypt (decrypt
    /// error, cipher init failure, UPDATE failure). Operators MUST
    /// inspect this field — a non-zero value means some secrets are
    /// still wrapped with a non-active DEK and may become un-decryptable
    /// if the source DEK is purged. Re-run after fixing the root cause.
    pub failed_count: u64,
    /// L T2-6: secret IDs that failed (capped at 100). Empty when
    /// `failed_count == 0`. The full list appears in server-side logs.
    pub failed_ids: Vec<Uuid>,
    /// Human-readable status message.
    pub message: String,
}

/// Result of a master key rotation operation.
#[derive(SimpleObject, Clone)]
pub struct MasterKeyRotationResult {
    /// Number of DEKs that were re-encrypted with the new master key.
    pub re_encrypted_dek_count: u64,
    /// Human-readable status message.
    pub message: String,
}

#[derive(SimpleObject, Clone)]
pub struct OAuthAccount {
    pub id: Uuid,
    pub provider: String,
    pub email: String,
    pub name: Option<String>,
    pub picture_url: Option<String>,
    pub linked_at: String,
    pub last_login_at: Option<String>,
}

#[derive(SimpleObject, Clone)]
pub struct OAuthAuthUrl {
    pub auth_url: String,
    pub provider: String,
}

#[derive(SimpleObject, Clone)]
#[graphql(complex)]
pub struct WorkflowScheduleObj {
    pub id: Uuid,
    #[graphql(name = "workflowId")]
    pub workflow_id: Uuid,
    #[graphql(name = "cronExpression")]
    pub cron_expression: String,
    pub timezone: String,
    #[graphql(name = "isEnabled")]
    pub is_enabled: bool,
    #[graphql(name = "lastTriggeredAt")]
    pub last_triggered_at: Option<String>,
    #[graphql(name = "nextTriggerAt")]
    pub next_trigger_at: Option<String>,
    #[graphql(name = "createdAt")]
    pub created_at: String,
    #[graphql(name = "updatedAt")]
    pub updated_at: String,
}

#[derive(InputObject)]
pub struct CreateModuleInput {
    pub template_id: Uuid,
    pub name: String,
    pub config: String, // JSON string
    pub job_id: Option<Uuid>,
}

#[derive(InputObject)]
pub struct AnalyzeRhaiInput {
    pub script: String,
}

#[derive(InputObject)]
pub struct TestRhaiExpressionInput {
    pub script: String,
    pub mock_context: String, // JSON string
}

#[derive(SimpleObject, Clone)]
pub struct TestRhaiExpressionResult {
    pub success: bool,
    pub output: Option<String>, // JSON stringified result
    pub error: Option<String>,
}

#[derive(SimpleObject, Clone)]
pub struct AnalyzeCustomModuleResult {
    pub success: bool,
    pub errors: Vec<CompilationErrorObj>,
}

#[derive(SimpleObject, Clone)]
pub struct CompilationErrorObj {
    pub line: Option<i32>,
    pub column: Option<i32>,
    pub end_line: Option<i32>,
    pub end_column: Option<i32>,
    pub message: String,
    pub severity: String,
}

#[derive(InputObject)]
pub struct CreateWorkflowInput {
    pub name: String,
    pub graph_json: String,
    pub max_concurrent_executions: Option<i32>,
    pub intent: Option<serde_json::Value>,
    /// Organization that owns this workflow (RFC 0004 tenant = org).
    /// Omit to create it in your **personal org** (the default). When set
    /// to a shared org, the caller must have Member+ role there
    /// (validated against `user_writable_org_ids`); teammates then see
    /// the workflow via the org-union read path.
    pub organization_id: Option<Uuid>,
}

/// Input for `createWorkflowFromDescription`. Mirrors the MCP
/// `create_workflow_from_description` tool — natural-language
/// description plus an optional fallback list of module UUIDs to
/// chain when no LLM is configured.
#[derive(InputObject)]
pub struct CreateWorkflowFromDescriptionInput {
    pub description: String,
    /// Optional explicit module UUIDs. Used when no LLM is
    /// available, or when the caller wants to force a specific set
    /// of modules instead of relying on AI scaffolding.
    pub modules: Option<Vec<String>>,
}

/// Result envelope for `createWorkflowFromDescription`. Maps the
/// service's typed `CreateFromDescriptionOutcome` enum into a
/// flattened struct with stable shape — GraphQL doesn't have great
/// ergonomics for multi-variant union responses, and this shape
/// matches what callers actually need to branch on (`success`,
/// `scaffolded_by`, optional error class).
#[derive(SimpleObject)]
pub struct CreateWorkflowFromDescriptionResult {
    pub success: bool,
    /// Set on the two success cases (`LlmScaffold`,
    /// `ExplicitModuleScaffold`).
    pub workflow_id: Option<Uuid>,
    /// "llm" | "explicit_modules" | "none". Mirrors the MCP
    /// response's `scaffolded_by` field so a UI built off the MCP
    /// surface can switch onto the same value.
    pub scaffolded_by: String,
    pub name: Option<String>,
    /// LLM-only — the natural-language reasoning the LLM provided
    /// for its scaffold choice.
    pub reasoning: Option<String>,
    /// Module names the LLM suggested but couldn't be resolved
    /// against the catalog.
    pub unresolved_modules: Option<Vec<String>>,
    /// Module names that exist in the catalog but have no compiled
    /// WASM. Caller should run `compile_template` before triggering.
    pub modules_not_compiled: Option<Vec<String>>,
    /// LLM-only — suggested cron expression for automatic triggering.
    pub suggested_schedule: Option<String>,
    /// Per-soft-failure-mode tag: `"llm_incomplete"`,
    /// `"llm_invalid_json"`, `"llm_failed"`, `"no_llm_and_no_explicit"`,
    /// `"no_matched_modules"`, or null on success. Stable strings —
    /// agents and the UI branch on these.
    pub error_class: Option<String>,
    /// Human-readable message paired with `error_class`.
    pub error_message: Option<String>,
    /// Sub-class for `error_class = "llm_failed"`: `"rate_limited"`,
    /// `"timeout"`, `"auth"`, `"upstream_unavailable"`, `"network"`,
    /// `"unknown"`. Null otherwise.
    pub llm_error_class: Option<String>,
}

#[derive(InputObject)]
pub struct CreateWebhookTriggerInput {
    pub name: String,
    pub module_id: Uuid,
    pub verification_token: Option<String>,
    pub signing_secret: Option<String>,
    pub max_requests_per_minute: Option<i32>,
    pub enabled: Option<bool>,
    pub allowed_ips: Option<Vec<String>>,
    /// RFC 0007: optional provider-agnostic event filter, evaluated AFTER
    /// signature verification. A non-matching delivery is acknowledged 200 with
    /// no dispatch (so it doesn't burn an execution). Omit to fire on every
    /// verified delivery. Shape (validated via `talos_webhooks::validate_event_filter`):
    /// `{ "header": "X-GitHub-Event", "values": ["pull_request"],
    ///    "payload_match": { "action": ["opened","synchronize","reopened"] } }`.
    pub event_filter: Option<serde_json::Value>,
}

#[derive(InputObject)]
pub struct CreateSecretInput {
    pub name: String,
    pub key_path: String,
    pub value: String,
    pub description: Option<String>,
    pub allowed_modules: Option<Vec<Uuid>>,
    /// Optional organization to assign the secret to. When set, all org
    /// members can access this secret.
    pub org_id: Option<Uuid>,
}

#[derive(InputObject)]
pub struct UpdateSecretInput {
    pub key_path: String,
    pub value: String,
}

#[derive(InputObject)]
pub struct SignupInput {
    pub email: String,
    pub password: String,
    pub name: Option<String>,
}

#[derive(InputObject)]
pub struct LoginInput {
    pub email: String,
    pub password: String,
}

#[derive(SimpleObject, Clone)]
pub struct AuthPayload {
    // Tokens are delivered exclusively via httpOnly cookies — not in the response body.
    pub user: UserInfo,
}

#[derive(SimpleObject, Clone)]
pub struct UserInfo {
    pub id: Uuid,
    pub email: String,
    pub name: Option<String>,
    pub created_at: String,
    #[graphql(name = "twoFactorEnabled")]
    pub two_factor_enabled: bool,
    #[graphql(name = "isTwoFactorVerified")]
    pub is_two_factor_verified: bool,
}

#[derive(SimpleObject, Clone)]
pub struct TwoFactorSetup {
    pub secret: String,
    #[graphql(name = "qrCodeUrl")]
    pub qr_code_url: String,
    #[graphql(name = "qrCodePng")]
    pub qr_code_png: String,
}

#[derive(SimpleObject, Clone)]
pub struct TwoFactorEnrollment {
    #[graphql(name = "backupCodes")]
    pub backup_codes: Vec<String>,
}

#[derive(InputObject)]
pub struct Enable2FAInput {
    pub secret: String,
    pub code: String,
}

#[derive(InputObject)]
pub struct Verify2FAInput {
    pub code: String,
}

#[derive(InputObject)]
pub struct CreateApiKeyInput {
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_in_days: Option<i64>,
}

/// Pagination input for list queries
#[derive(InputObject, Clone)]
pub struct PaginationInput {
    /// Maximum number of items to return (default: 100, max: 1000)
    pub limit: Option<i32>,
    /// Number of items to skip (default: 0)
    pub offset: Option<i32>,
}

impl PaginationInput {
    /// Get limit with defaults and caps
    pub fn get_limit(&self) -> i64 {
        self.limit.unwrap_or(100).clamp(1, 1000) as i64
    }

    /// Get offset with default
    pub fn get_offset(&self) -> i64 {
        self.offset.unwrap_or(0).max(0) as i64
    }
}

#[derive(InputObject)]
pub struct GenerateCodeInput {
    pub prompt: String,
    pub current_code: String,
    pub capability_world: String,
}

#[derive(SimpleObject, Clone)]
pub struct GenerateCodeResult {
    pub code: String,
}

#[derive(SimpleObject, Clone)]
pub struct UserAuditSettings {
    pub streaming_enabled: bool,
    pub otlp_endpoint: Option<String>,
    pub otlp_protocol: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

pub struct ModuleLoader(pub sqlx::Pool<sqlx::Postgres>);

impl async_graphql::dataloader::Loader<Uuid> for ModuleLoader {
    type Value = WasmModule;
    type Error = std::sync::Arc<anyhow::Error>;

    /// NOTE: This DataLoader is only invoked via ComplexObject resolvers (e.g.,
    /// WebhookTrigger.module) where the parent entity has already been scoped to
    /// the authenticated user. The module IDs passed here are therefore
    /// pre-validated through user-scoped parent queries. Additionally, modules
    /// may be referenced across users via the workflow_module_refs junction table,
    /// so the repository method intentionally has no user_id filter.
    async fn load(
        &self,
        keys: &[Uuid],
    ) -> std::result::Result<std::collections::HashMap<Uuid, Self::Value>, Self::Error> {
        // Phase 5.1: unified `modules` table; bare-pool read preserved
        // (the loader's own pool backs the per-call repository).
        let repo = talos_module_repository::ModuleRepository::new(self.0.clone());
        let modules = repo
            .get_modules_by_ids(keys)
            .await
            .map_err(std::sync::Arc::new)?;

        let mut map = std::collections::HashMap::new();
        for m in modules {
            let wm = WasmModule {
                id: m.id,
                name: m.name,
                size_bytes: m.size_bytes,
                content_hash: m.content_hash,
                compiled_at: m.compiled_at.to_rfc3339(),
                config: m
                    .config
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "{}".to_string()),
                config_schema: m.config_schema.map(|c| c.to_string()),
                catalog_slug: m.catalog_slug,
                source_code: m.source_code,
                capability_world: m.capability_world,
                imported_interfaces: m.imported_interfaces,
                language: m.language,
            };
            map.insert(m.id, wm);
        }

        Ok(map)
    }
}

pub struct ModuleExecutionLogLoader(
    pub std::sync::Arc<talos_module_executions::ModuleExecutionService>,
);

impl async_graphql::dataloader::Loader<Uuid> for ModuleExecutionLogLoader {
    type Value = Vec<ModuleExecutionLog>;
    type Error = std::sync::Arc<anyhow::Error>;

    async fn load(
        &self,
        keys: &[Uuid],
    ) -> std::result::Result<std::collections::HashMap<Uuid, Self::Value>, Self::Error> {
        // MCP-1191 (2026-05-17): cap rows returned PER execution_id at
        // 200 via a ROW_NUMBER() window (in
        // `ModuleExecutionService::get_execution_logs_batched`). Pre-fix
        // the DataLoader did `WHERE execution_id = ANY($1)` with NO
        // per-group cap — a GraphQL caller writing
        // `{ moduleExecutions(limit: 1000) { logs { ... } } }` would
        // trigger a single batched query for up to N executions ×
        // MAX_LOGS_PER_EXECUTION (1000 enforced by the
        // `module_execution_logs` insert trigger) = 1 000 000 rows ×
        // ~500 bytes per row = ~500 MiB heap on a single request.
        //
        // The DB trigger caps insert rate at 1000 logs per execution,
        // but that's a per-execution cap, not a per-DataLoader-call
        // cap; a caller with many executions still amplifies the
        // batched query. Capping each execution_id at 200 rows brings
        // the worst-case batched response to roughly
        // `batch_size × 200 × ~500 B`, which is bounded enough that
        // the controller can absorb concurrent dashboard calls.
        //
        // 200 matches the canonical MAX_LIST_LIMIT used by
        // `talos_memory::list_memories` and the MCP
        // `handle_list_pending_approvals` ceiling. Callers needing the
        // full per-execution log set should use the top-level
        // `module_execution_logs(executionId)` query (bounded by the
        // DB trigger at 1000) rather than the fan-out DataLoader.
        const MAX_LOGS_PER_EXECUTION: i32 = 200;
        let logs = self
            .0
            .get_execution_logs_batched(keys, MAX_LOGS_PER_EXECUTION)
            .await
            .map_err(std::sync::Arc::new)?;

        let mut map: std::collections::HashMap<Uuid, Vec<ModuleExecutionLog>> =
            std::collections::HashMap::new();

        for &key in keys {
            map.insert(key, Vec::new());
        }

        for log in logs {
            let exec_id = log.execution_id;
            let graphql_log = ModuleExecutionLog::from(log);
            map.entry(exec_id).or_default().push(graphql_log);
        }

        Ok(map)
    }
}

/// Composite DataLoader key: `(user, workflow)`. The user id rides in the
/// key so the batched lookup preserves the SAME per-user scoping the
/// per-row query had (`WHERE id = ANY($1) AND user_id = $2`) — batching
/// by bare workflow id would let two users' keys share one unscoped
/// query. In practice one GraphQL request = one user, so the loader
/// still collapses a page of parents into a single round-trip.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct WorkflowNameKey {
    pub user_id: Uuid,
    pub workflow_id: Uuid,
}

/// Batched `workflow_id → name` resolution for id-only child objects
/// (`WorkflowScheduleObj`, `ExecutionApproval`, `WorkflowExecution`).
///
/// N+1 this closes: `mySchedules` returns up to 1000 rows carrying a bare
/// `workflowId`; resolving a display name per row means 1000 point
/// queries — the frontend's historical workaround was fetching the ENTIRE
/// `workflows` list (every row carrying `graph_json`, up to 10 MiB each
/// per the MCP-1189 note) just to build an id→name map client-side.
///
/// Tenancy: `WorkflowRepository::get_workflow_names_by_ids` filters
/// `AND user_id = $2` (owner only). Org-shared workflows owned by a
/// teammate resolve to `null` — under-permissive, never leaking.
pub struct WorkflowNameLoader(pub sqlx::Pool<sqlx::Postgres>);

impl async_graphql::dataloader::Loader<WorkflowNameKey> for WorkflowNameLoader {
    type Value = String;
    type Error = std::sync::Arc<anyhow::Error>;

    async fn load(
        &self,
        keys: &[WorkflowNameKey],
    ) -> std::result::Result<std::collections::HashMap<WorkflowNameKey, Self::Value>, Self::Error>
    {
        let repo = talos_workflow_repository::WorkflowRepository::new(self.0.clone());

        // Group by user so each batched query keeps its own tenancy
        // predicate (one group — one query — for the typical request).
        let mut by_user: std::collections::HashMap<Uuid, Vec<Uuid>> =
            std::collections::HashMap::new();
        for key in keys {
            by_user
                .entry(key.user_id)
                .or_default()
                .push(key.workflow_id);
        }

        let mut out = std::collections::HashMap::new();
        for (user_id, workflow_ids) in by_user {
            let names = repo
                .get_workflow_names_by_ids(&workflow_ids, user_id)
                .await
                .map_err(std::sync::Arc::new)?;
            for (workflow_id, name) in names {
                out.insert(
                    WorkflowNameKey {
                        user_id,
                        workflow_id,
                    },
                    name,
                );
            }
        }
        Ok(out)
    }
}

/// Composite DataLoader key: `(user, actor)` — same scoping rationale as
/// [`WorkflowNameKey`]; actors are personal so `user_id` IS the tenancy
/// predicate.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ActorNameKey {
    pub user_id: Uuid,
    pub actor_id: Uuid,
}

/// Batched `actor_id → name` resolution for actor attribution on
/// `Workflow` / `WorkflowExecution` rows.
///
/// N+1 this closes: `workflowExecutionHistory` returns up to 1000 rows
/// each carrying a bare `actorId`; the only pre-existing way to show
/// "which agent ran this" was a per-id `actor(id)` query — and that
/// resolver runs the heavyweight `get_actor_details_scoped` COUNT
/// aggregation per call. The loader collapses a page into one
/// `WHERE id = ANY($1) AND user_id = $2` round-trip (and load_one
/// dedupes: 1000 executions by 3 actors = 3 keys).
pub struct ActorNameLoader(pub sqlx::Pool<sqlx::Postgres>);

impl async_graphql::dataloader::Loader<ActorNameKey> for ActorNameLoader {
    type Value = String;
    type Error = std::sync::Arc<anyhow::Error>;

    async fn load(
        &self,
        keys: &[ActorNameKey],
    ) -> std::result::Result<std::collections::HashMap<ActorNameKey, Self::Value>, Self::Error>
    {
        let repo = talos_actor_repository::ActorRepository::new(self.0.clone());

        let mut by_user: std::collections::HashMap<Uuid, Vec<Uuid>> =
            std::collections::HashMap::new();
        for key in keys {
            by_user.entry(key.user_id).or_default().push(key.actor_id);
        }

        let mut out = std::collections::HashMap::new();
        for (user_id, actor_ids) in by_user {
            let names = repo
                .get_actor_names_by_ids(&actor_ids, user_id)
                .await
                .map_err(std::sync::Arc::new)?;
            for (actor_id, name) in names {
                out.insert(ActorNameKey { user_id, actor_id }, name);
            }
        }
        Ok(out)
    }
}

/// Composite DataLoader key for the latest-execution lookup. Carries the
/// caller's org scope alongside the user so the batched query preserves
/// the EXACT `we.user_id = $2 OR w.org_id = ANY($3)` predicate the
/// top-level `latestWorkflowExecutions` query uses.
///
/// `org_scope` mirrors `user_accessible_org_ids`' `ApiKeyOrgScope`
/// short-circuit: `Some(org)` = org-scoped API key (restrict to that one
/// org even if the user belongs to others); `None` = session/user key
/// (the loader resolves the full membership list itself, ONCE per batch —
/// resolving it in the field resolver would re-introduce a per-parent
/// `organization_members` query, since the `UserOrgIds` request cache is
/// never populated).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LatestExecutionKey {
    pub user_id: Uuid,
    pub org_scope: Option<Uuid>,
    pub workflow_id: Uuid,
}

/// Batched latest-execution-per-workflow resolution for `Workflow` rows.
///
/// N+1 this closes: a dashboard page of `workflows(limit)` (up to 1000
/// rows) resolving "current status" per workflow. The pre-existing
/// batched escape hatch is the top-level `latestWorkflowExecutions`
/// query (≤200 ids) that clients must stitch manually; this field makes
/// the single-request shape (`workflows { latestExecution { … } }`)
/// resolve through ONE `DISTINCT ON` round-trip via
/// `ExecutionRepository::list_latest_executions_for_workflows_scoped`,
/// run on a tenant-scoped tx so the `workflow_executions` RLS policy
/// backstops the app-layer predicate (same contract as the top-level
/// query — the repo method's docs forbid routing through the bare pool).
pub struct LatestExecutionLoader(pub sqlx::Pool<sqlx::Postgres>);

impl async_graphql::dataloader::Loader<LatestExecutionKey> for LatestExecutionLoader {
    type Value = WorkflowExecution;
    type Error = std::sync::Arc<anyhow::Error>;

    async fn load(
        &self,
        keys: &[LatestExecutionKey],
    ) -> std::result::Result<std::collections::HashMap<LatestExecutionKey, Self::Value>, Self::Error>
    {
        let exec_repo = talos_execution_repository::ExecutionRepository::new(self.0.clone());

        // Group by (user, org_scope) so each batched query carries its
        // own tenancy scope — one group per request in practice.
        let mut groups: std::collections::HashMap<(Uuid, Option<Uuid>), Vec<Uuid>> =
            std::collections::HashMap::new();
        for key in keys {
            groups
                .entry((key.user_id, key.org_scope))
                .or_default()
                .push(key.workflow_id);
        }

        let mut out = std::collections::HashMap::new();
        for ((user_id, org_scope), workflow_ids) in groups {
            // Resolve accessible orgs once per batch, mirroring
            // `user_accessible_org_ids`: org-scoped API key → that single
            // org; otherwise the user's full membership list, failing
            // CLOSED to an empty list on DB error (reader sees only
            // personally-owned executions; MCP-617 fail-mode).
            let org_ids: Vec<Uuid> = match org_scope {
                Some(org) => vec![org],
                None => match talos_organizations::OrganizationService::list_user_org_ids(
                    &self.0, user_id,
                )
                .await
                {
                    Ok(ids) => ids,
                    Err(e) => {
                        tracing::error!(
                            user_id = %user_id,
                            error = %e,
                            "latest_execution loader: org membership read failed — falling back to empty (reader denied org-shared rows)"
                        );
                        Vec::new()
                    }
                },
            };

            let scope = talos_tenancy::TenantReadScope::new(user_id, org_ids);
            let mut tx = talos_db::begin_tenant_read_scoped(&self.0, &scope)
                .await
                .map_err(|e| std::sync::Arc::new(anyhow::anyhow!(e)))?;
            let rows = exec_repo
                .list_latest_executions_for_workflows_scoped(
                    &mut tx,
                    &workflow_ids,
                    user_id,
                    &scope.accessible_org_ids,
                )
                .await
                .map_err(std::sync::Arc::new)?;
            tx.commit()
                .await
                .map_err(|e| std::sync::Arc::new(anyhow::anyhow!(e)))?;

            for r in rows {
                out.insert(
                    LatestExecutionKey {
                        user_id,
                        org_scope,
                        workflow_id: r.workflow_id,
                    },
                    // Same lean projection the top-level
                    // `latestWorkflowExecutions` resolver returns —
                    // duration/output/trigger stay None by design (the
                    // DISTINCT ON row doesn't carry them).
                    WorkflowExecution {
                        id: r.id,
                        workflow_id: r.workflow_id,
                        status: r.status,
                        started_at: r.started_at.to_rfc3339(),
                        completed_at: r.completed_at.map(|d| d.to_rfc3339()),
                        error_message: r.error_message,
                        created_at: r.created_at.to_rfc3339(),
                        duration_ms: None,
                        output_data: None,
                        trigger_type: None,
                        actor_id: None,
                    },
                );
            }
        }
        Ok(out)
    }
}

/// Shared helper for the loader-backed ComplexObject fields below:
/// authenticated user id or a safe error.
fn loader_user_id(ctx: &Context<'_>) -> Result<Uuid> {
    ctx.data_opt::<Uuid>()
        .copied()
        .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())
}

/// Map a DataLoader failure to a generic client-safe error (lint check
/// 14): the underlying anyhow chain can carry SQL/schema detail that must
/// not cross the GraphQL boundary.
fn loader_err(
    context: &'static str,
) -> impl FnOnce(std::sync::Arc<anyhow::Error>) -> async_graphql::Error {
    move |e| {
        tracing::error!(error = %e, "graphql dataloader: {context} failed");
        async_graphql::Error::new("Request could not be completed").extend_safe()
    }
}

#[ComplexObject]
impl Workflow {
    /// Display name of the owning actor (null when unbound, or when the
    /// actor belongs to another user). Batched via [`ActorNameLoader`].
    async fn actor_name(&self, ctx: &Context<'_>) -> Result<Option<String>> {
        let Some(actor_id) = self.actor_id else {
            return Ok(None);
        };
        let user_id = loader_user_id(ctx)?;
        let loader = ctx.data::<async_graphql::dataloader::DataLoader<ActorNameLoader>>()?;
        loader
            .load_one(ActorNameKey { user_id, actor_id })
            .await
            .map_err(loader_err("actor name"))
    }

    /// Most recent execution of this workflow (null when never run or
    /// not visible to the caller). Batched via [`LatestExecutionLoader`]
    /// with the same user/org predicate as `latestWorkflowExecutions`.
    async fn latest_execution(&self, ctx: &Context<'_>) -> Result<Option<WorkflowExecution>> {
        let user_id = loader_user_id(ctx)?;
        let org_scope = ctx
            .data::<crate::schema::ApiKeyOrgScope>()
            .ok()
            .map(|s| s.0);
        let loader = ctx.data::<async_graphql::dataloader::DataLoader<LatestExecutionLoader>>()?;
        loader
            .load_one(LatestExecutionKey {
                user_id,
                org_scope,
                workflow_id: self.id,
            })
            .await
            .map_err(loader_err("latest execution"))
    }
}

#[ComplexObject]
impl WorkflowScheduleObj {
    /// Display name of the scheduled workflow (null when the workflow is
    /// owned by another user). Batched via [`WorkflowNameLoader`] — the
    /// per-row alternative is a point query per schedule row.
    async fn workflow_name(&self, ctx: &Context<'_>) -> Result<Option<String>> {
        let user_id = loader_user_id(ctx)?;
        let loader = ctx.data::<async_graphql::dataloader::DataLoader<WorkflowNameLoader>>()?;
        loader
            .load_one(WorkflowNameKey {
                user_id,
                workflow_id: self.workflow_id,
            })
            .await
            .map_err(loader_err("workflow name"))
    }
}

#[ComplexObject]
impl ExecutionApproval {
    /// Display name of the workflow awaiting approval (null when owned by
    /// another user). Batched via [`WorkflowNameLoader`].
    async fn workflow_name(&self, ctx: &Context<'_>) -> Result<Option<String>> {
        let user_id = loader_user_id(ctx)?;
        let loader = ctx.data::<async_graphql::dataloader::DataLoader<WorkflowNameLoader>>()?;
        loader
            .load_one(WorkflowNameKey {
                user_id,
                workflow_id: self.workflow_id,
            })
            .await
            .map_err(loader_err("workflow name"))
    }
}

#[ComplexObject]
impl WorkflowExecution {
    /// Display name of the executed workflow (null when owned by another
    /// user). Batched via [`WorkflowNameLoader`].
    async fn workflow_name(&self, ctx: &Context<'_>) -> Result<Option<String>> {
        let user_id = loader_user_id(ctx)?;
        let loader = ctx.data::<async_graphql::dataloader::DataLoader<WorkflowNameLoader>>()?;
        loader
            .load_one(WorkflowNameKey {
                user_id,
                workflow_id: self.workflow_id,
            })
            .await
            .map_err(loader_err("workflow name"))
    }

    /// Display name of the actor that dispatched this execution (null for
    /// non-actor executions). Batched via [`ActorNameLoader`].
    async fn actor_name(&self, ctx: &Context<'_>) -> Result<Option<String>> {
        let Some(actor_id) = self.actor_id else {
            return Ok(None);
        };
        let user_id = loader_user_id(ctx)?;
        let loader = ctx.data::<async_graphql::dataloader::DataLoader<ActorNameLoader>>()?;
        loader
            .load_one(ActorNameKey { user_id, actor_id })
            .await
            .map_err(loader_err("actor name"))
    }
}

#[ComplexObject]
impl WasmModule {
    async fn capability_description(&self) -> Option<String> {
        // MCP-846 (2026-05-14): delegate to canonical
        // `CapabilityWorld::from_str` instead of the hand-rolled match.
        // The inline version drifted from canonical on two strings:
        //   * `"automation"` (no -node suffix) → previously mapped to
        //     Trusted here but canonical returns Unknown.
        //   * `"trusted-node"` → previously mapped to Unknown here but
        //     canonical returns Trusted.
        // Production stores `-node`-suffixed forms exclusively (per the
        // CLAUDE.md `secrets-node` convention) so the practical drift
        // is narrow, but the canonical helper is the single source of
        // truth for capability-world parsing across the workspace
        // (MCP-815/816 swept the inline matches in talos-registry,
        // talos-mcp-handlers, talos-actor-scaffold, talos-api/actors).
        // This site was the lone unmigrated reference in talos-api.
        use std::str::FromStr;
        self.capability_world.as_ref().map(|w| {
            let world = worker::CapabilityWorld::from_str(w.as_str())
                .unwrap_or(worker::CapabilityWorld::Unknown);
            talos_mcp_tool_schema::capability_world_description(&world).to_string()
        })
    }
}

#[derive(SimpleObject, Clone)]
#[graphql(complex)]
pub struct WorkflowExecution {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub status: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    /// How the execution was triggered: "manual", "scheduled", "webhook", "actor_dispatch", etc.
    pub trigger_type: Option<String>,
    /// Actor that dispatched this execution, if any.
    pub actor_id: Option<Uuid>,
    pub error_message: Option<String>,
    pub created_at: String,
    pub duration_ms: Option<i32>,
    pub output_data: Option<serde_json::Value>,
}

/// A published, immutable snapshot of a workflow graph.
#[derive(SimpleObject, Clone)]
pub struct WorkflowVersion {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub version_number: i32,
    pub graph_json: String,
    pub description: Option<String>,
    pub published_at: String,
    pub published_by: Uuid,
    pub is_active: bool,
    pub created_at: String,
}

impl From<talos_workflow_versions::WorkflowVersion> for WorkflowVersion {
    fn from(v: talos_workflow_versions::WorkflowVersion) -> Self {
        Self {
            id: v.id,
            workflow_id: v.workflow_id,
            version_number: v.version_number,
            graph_json: v.graph_json.to_string(),
            description: v.description,
            published_at: v.published_at.to_rfc3339(),
            published_by: v.published_by,
            is_active: v.is_active,
            created_at: v.created_at.to_rfc3339(),
        }
    }
}

#[derive(SimpleObject, Clone)]
#[graphql(complex)]
pub struct ModuleExecution {
    pub id: Uuid,
    pub module_id: Uuid,
    pub status: String,
    pub trigger_type: String,
    pub trigger_metadata: Option<String>,
    pub input_data: Option<String>,
    pub output_data: Option<String>,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub duration_ms: Option<i32>,
    pub error_message: Option<String>,
    pub error_type: Option<String>,
    pub fuel_consumed: Option<i64>,
    pub memory_used_mb: Option<i32>,
    pub created_at: String,
}
#[ComplexObject]
impl ModuleExecution {
    async fn module(&self, ctx: &Context<'_>) -> Result<Option<WasmModule>> {
        let loader = ctx.data::<async_graphql::dataloader::DataLoader<ModuleLoader>>()?;
        Ok(loader.load_one(self.module_id).await?)
    }

    async fn logs(&self, ctx: &Context<'_>) -> Result<Vec<ModuleExecutionLog>> {
        let loader =
            ctx.data::<async_graphql::dataloader::DataLoader<ModuleExecutionLogLoader>>()?;
        let logs = loader.load_one(self.id).await?.unwrap_or_default();
        Ok(logs)
    }
}

impl From<module_executions::ModuleExecution> for ModuleExecution {
    fn from(exec: module_executions::ModuleExecution) -> Self {
        Self {
            id: exec.id,
            module_id: exec.module_id,
            status: exec.status.to_string(),
            trigger_type: exec.trigger_type.to_string(),
            trigger_metadata: exec.trigger_metadata.map(|v| v.to_string()),
            input_data: exec.input_data.map(|v| v.to_string()),
            output_data: exec.output_data.map(|v| v.to_string()),
            started_at: exec.started_at.to_rfc3339(),
            completed_at: exec.completed_at.map(|d| d.to_rfc3339()),
            duration_ms: exec.duration_ms,
            error_message: exec.error_message,
            error_type: exec.error_type,
            fuel_consumed: exec.fuel_consumed,
            memory_used_mb: exec.memory_used_mb,
            created_at: exec.created_at.to_rfc3339(),
        }
    }
}

#[derive(SimpleObject, Clone)]
pub struct ModuleExecutionLog {
    pub id: Uuid,
    pub execution_id: Uuid,
    pub level: String,
    pub message: String,
    pub metadata: Option<String>,
    pub created_at: String,
}

impl From<module_executions::ModuleExecutionLog> for ModuleExecutionLog {
    fn from(log: module_executions::ModuleExecutionLog) -> Self {
        Self {
            id: log.id,
            execution_id: log.execution_id,
            level: log.level.to_string(),
            message: log.message,
            metadata: log.metadata.map(|v| v.to_string()),
            created_at: log.created_at.to_rfc3339(),
        }
    }
}

// ── Organization types ─────────────────────────────────────────────────

/// GraphQL enum for organization member roles.
#[derive(async_graphql::Enum, Copy, Clone, Eq, PartialEq)]
pub enum OrgRoleEnum {
    Owner,
    Admin,
    Member,
    Viewer,
}

impl From<talos_organizations::OrgRole> for OrgRoleEnum {
    fn from(role: talos_organizations::OrgRole) -> Self {
        match role {
            talos_organizations::OrgRole::Owner => OrgRoleEnum::Owner,
            talos_organizations::OrgRole::Admin => OrgRoleEnum::Admin,
            talos_organizations::OrgRole::Member => OrgRoleEnum::Member,
            talos_organizations::OrgRole::Viewer => OrgRoleEnum::Viewer,
        }
    }
}

/// GraphQL representation of an organization.
#[derive(SimpleObject, Clone)]
pub struct OrganizationObj {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    #[graphql(name = "ownerId")]
    pub owner_id: Uuid,
    #[graphql(name = "createdAt")]
    pub created_at: String,
    #[graphql(name = "updatedAt")]
    pub updated_at: String,
}

impl From<talos_organizations::Organization> for OrganizationObj {
    fn from(org: talos_organizations::Organization) -> Self {
        Self {
            id: org.id,
            name: org.name,
            slug: org.slug,
            owner_id: org.owner_id,
            created_at: org.created_at.to_rfc3339(),
            updated_at: org.updated_at.to_rfc3339(),
        }
    }
}

/// GraphQL representation of an organization member.
#[derive(SimpleObject, Clone)]
pub struct OrgMemberObj {
    pub id: Uuid,
    #[graphql(name = "orgId")]
    pub org_id: Uuid,
    #[graphql(name = "userId")]
    pub user_id: Uuid,
    pub role: String,
    #[graphql(name = "invitedBy")]
    pub invited_by: Option<Uuid>,
    #[graphql(name = "joinedAt")]
    pub joined_at: String,
}

impl From<talos_organizations::OrgMember> for OrgMemberObj {
    fn from(m: talos_organizations::OrgMember) -> Self {
        Self {
            id: m.id,
            org_id: m.org_id,
            user_id: m.user_id,
            role: m.role,
            invited_by: m.invited_by,
            joined_at: m.joined_at.to_rfc3339(),
        }
    }
}

// ── Workflow Testing types ──────────────────────────────────────────

/// A single node's trace during a test workflow execution.
/// Aggregated per-workflow stats for the dashboard.
#[derive(SimpleObject, Clone)]
pub struct WorkflowStats {
    pub id: Uuid,
    pub name: String,
    pub total: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub avg_duration_secs: Option<f64>,
}

/// Human-readable changelog entry for a workflow version.
#[derive(SimpleObject, Clone)]
pub struct ChangelogEntry {
    pub version_number: i32,
    pub published_at: String,
    pub description: Option<String>,
    pub summary: String,
}

/// Summary of differences between the current draft and the last published version.
#[derive(SimpleObject, Clone)]
pub struct VersionDiffSummary {
    pub summary: String,
    pub nodes_added: i32,
    pub nodes_removed: i32,
    pub nodes_changed: i32,
    pub edges_added: i32,
    pub edges_removed: i32,
    pub has_published_version: bool,
}

/// Result of testing a module in isolation.
#[derive(SimpleObject, Clone)]
pub struct TestModuleResult {
    pub success: bool,
    pub output: Option<String>,
    pub error: Option<String>,
    pub duration_ms: u64,
}

#[derive(SimpleObject, Clone)]
pub struct TestNodeTrace {
    /// The node UUID.
    pub node_id: Uuid,
    /// The input JSON that was fed to this node.
    pub input: String,
    /// The output JSON produced by this node (null if skipped/failed).
    pub output: Option<String>,
    /// "completed", "failed", or "skipped".
    pub status: String,
    /// Error message if the node failed.
    pub error: Option<String>,
}

/// Result of a testWorkflow dry-run execution.
#[derive(SimpleObject, Clone)]
pub struct TestWorkflowResult {
    /// The temporary execution ID (not persisted long-term).
    pub execution_id: Uuid,
    /// Overall status: "completed" or "failed".
    pub status: String,
    /// Per-node execution trace.
    pub node_traces: Vec<TestNodeTrace>,
    /// Edge schema validation warnings (if any).
    pub schema_warnings: Vec<String>,
    /// Total duration in milliseconds.
    pub duration_ms: u64,
    /// Error message if the workflow failed overall.
    pub error: Option<String>,
}

#[derive(SimpleObject, Clone)]
pub struct ActorSummary {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    pub max_capability_world: String,
    pub workflow_count: i64,
    pub execution_count: i64,
    /// Lifetime budget cap in USD. None = unlimited.
    pub total_budget_usd: Option<f64>,
    /// Lifetime budget consumed. Always 0 until budget tracking is wired.
    pub spent_budget_usd: f64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(SimpleObject, Clone)]
pub struct ActorDetails {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    pub max_capability_world: String,
    pub metadata: Option<String>,
    pub workflow_count: i64,
    pub execution_count: i64,
    /// Lifetime budget cap in USD. None = unlimited.
    pub total_budget_usd: Option<f64>,
    /// Lifetime budget consumed. Always 0 until budget tracking is wired.
    pub spent_budget_usd: f64,
    /// MCP bearer token — intentionally always None via GraphQL (shown once at MCP creation).
    pub mcp_token: Option<String>,
    /// Per-minute execution rate limit. None = unlimited.
    pub rate_limit: Option<i32>,
    /// ISO-8601 timestamp of the most recent execution dispatched by this actor.
    pub last_active_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Input type for createActor mutation.
#[derive(async_graphql::InputObject)]
pub struct CreateActorInput {
    pub name: String,
    pub description: Option<String>,
    pub max_capability_world: Option<String>,
    /// Lifetime budget cap in USD (informational — enforcement via budget policies).
    pub total_budget_usd: Option<f64>,
    /// Per-minute execution rate limit (informational — reserved for future enforcement).
    pub rate_limit: Option<i32>,
}

#[derive(SimpleObject, Clone)]
pub struct ActorExecutionsSummary {
    pub total_executions: i64,
    pub successful_executions: i64,
    pub failed_executions: i64,
    pub active_executions: i64,
}

#[derive(SimpleObject, Clone)]
pub struct ActorWorkflowsSummary {
    pub total_workflows: i64,
    pub active_workflows: i64,
}

/// One (provider, model) LLM usage aggregate within a trailing window —
/// the per-model/provider spend breakdown row for the token-spend panel.
#[derive(SimpleObject, Clone)]
pub struct LlmUsageModelRow {
    pub provider: String,
    pub model: String,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub calls: i64,
}

/// Read-only per-actor LLM token spend summary (R2 token ledger). Mirrors
/// the `current_usage`/`policy` numbers the MCP `get_actor_budget` tool
/// already exposes — budget POLICY *writes* stay MCP-only (see
/// `BudgetPanel`'s "configured via MCP tools" note), this is visibility
/// only.
#[derive(SimpleObject, Clone)]
pub struct LlmUsageSummary {
    pub actor_id: Uuid,
    /// Trailing-24h SUM(prompt_tokens + completion_tokens) — the same
    /// figure `max_llm_tokens_per_day` is enforced against.
    pub tokens_last_24h: i64,
    /// Daily token ceiling from the actor's budget policy. `None` =
    /// unlimited (no policy row, or an explicit NULL ceiling).
    pub max_llm_tokens_per_day: Option<i64>,
    /// Per-(provider, model) breakdown over the trailing window (`days`
    /// arg on the query, default 7, clamped 1..=90).
    pub by_model: Vec<LlmUsageModelRow>,
}

#[derive(SimpleObject, Clone)]
pub struct ActorActionLogEntry {
    pub id: Uuid,
    pub action_type: String,
    pub summary: String,
    pub timestamp: String,
    pub workflow_id: Option<Uuid>,
    pub execution_id: Option<Uuid>,
}

#[derive(SimpleObject, Clone)]
pub struct ActorWorkflowItem {
    pub id: Uuid,
    pub name: String,
    pub status: Option<String>,
    pub node_count: i64,
    /// Serialized graph JSON — used client-side to detect AI Actor (LLM + INJECT_CONTEXT).
    pub graph_json: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// A single memory entry stored against an actor.
#[derive(SimpleObject, Clone)]
pub struct ActorMemoryEntry {
    pub key: String,
    /// JSON-serialized value — parse on the client.
    pub value: String,
    /// "working" | "episodic" | "semantic" | "scratchpad"
    pub memory_type: String,
    /// ISO-8601 expiry, null means permanent (semantic).
    pub expires_at: Option<String>,
    pub updated_at: String,
}

/// One actor's memory entries within a batched `actorsMemories` read.
/// Groups are returned ONLY for actors the caller owns — a requested id
/// that is unknown (or another tenant's) simply has no group, so its
/// absence is indistinguishable from non-existence.
#[derive(SimpleObject, Clone)]
pub struct ActorMemoryGroup {
    pub actor_id: Uuid,
    pub memories: Vec<ActorMemoryEntry>,
}

#[derive(async_graphql::InputObject)]
pub struct WriteActorMemoryInput {
    pub actor_id: Uuid,
    pub key: String,
    /// JSON value to store.
    pub value: String,
    /// "working" | "episodic" | "semantic" | "scratchpad". Default: "working".
    pub memory_type: Option<String>,
    /// Custom TTL in hours. Overrides memory_type default. Null = use type default.
    pub ttl_hours: Option<f64>,
}

/// A webhook payload that was dropped (e.g. circuit breaker) and persisted for replay.
#[derive(SimpleObject, Clone)]
pub struct WebhookDlqEntry {
    pub id: Uuid,
    pub trigger_id: Option<Uuid>,
    pub source_ip: Option<String>,
    /// Reason the original request was dropped: 'circuit_breaker' | 'rate_limit' | 'sig_invalid' | 'disabled'
    pub drop_reason: String,
    /// DLP-scrubbed request headers (auth headers stripped).
    pub headers: Option<String>,
    /// DLP-scrubbed request payload.
    pub payload: Option<String>,
    pub created_at: String,
    pub replayed_at: Option<String>,
    pub replayed_by: Option<Uuid>,
}

/// A node execution that failed and was moved to the Dead Letter Queue.
#[derive(SimpleObject, Clone)]
pub struct DeadLetterEntry {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub execution_id: Uuid,
    pub node_id: Uuid,
    pub error_message: String,
    pub payload: Option<String>,
    pub created_at: String,
    pub replayed_at: Option<String>,
    pub replayed_by: Option<Uuid>,
}

/// A pending authorization request for a module execution.
#[derive(SimpleObject, Clone)]
#[graphql(complex)]
pub struct ExecutionApproval {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub execution_id: Uuid,
    pub node_id: Uuid,
    pub required_for: Vec<String>,
    pub status: String,
    pub requested_at: String,
    pub decided_at: Option<String>,
    pub decided_by: Option<Uuid>,
    pub reason: Option<String>,
}

/// Resource quotas for an organization.
#[derive(SimpleObject, Clone)]
pub struct ResourceQuota {
    pub cpu_cores: i64,
    pub used_cpu: i64,
    pub memory_gb: i64,
    pub used_memory: i64,
    pub storage_gb: i64,
    pub used_storage: i64,
    pub concurrent_executions: i64,
    pub active_executions: i64,
}

/// Input for updating organization resource quotas.
#[derive(InputObject)]
pub struct UpdateResourceQuotasInput {
    pub cpu_cores: Option<i64>,
    pub memory_gb: Option<i64>,
    pub storage_gb: Option<i64>,
    pub concurrent_executions: Option<i64>,
}

// ── Integration & MCP Agent types ───────────────────────────────────────

#[derive(async_graphql::Enum, Copy, Clone, Eq, PartialEq, Debug)]
pub enum IntegrationService {
    GoogleCalendar,
    Gmail,
    Slack,
    Jira,
    GoogleCloud,
}

#[derive(SimpleObject, Clone, Debug)]
pub struct ServiceIntegration {
    pub id: Uuid,
    pub service: IntegrationService,
    pub account_identifier: String,
    pub connected_at: String,
    pub status: String,
}

#[derive(SimpleObject, Clone, Debug)]
pub struct McpAgent {
    pub id: Uuid,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

// ── Capability Ceiling types ────────────────────────────────────────────

/// Detailed capability ceiling information for the current user.
#[derive(SimpleObject, Clone, Debug)]
pub struct CapabilityCeilingDetail {
    pub ceiling: String,
    pub source: String,
    pub granted_by_email: Option<String>,
    pub granted_at: Option<String>,
    pub notes: Option<String>,
}

/// A single world in the capability hierarchy.
#[derive(SimpleObject, Clone, Debug)]
pub struct CapabilityWorldInfo {
    pub name: String,
    pub rank: i32,
    pub description: String,
}

/// A capability grant record (admin view).
#[derive(SimpleObject, Clone, Debug)]
pub struct CapabilityGrant {
    pub user_id: Uuid,
    pub email: String,
    pub max_capability_world: String,
    pub granted_by: Option<Uuid>,
    pub granted_at: String,
    pub notes: Option<String>,
}

/// Input for granting a capability ceiling to a user.
#[derive(InputObject)]
pub struct GrantCapabilityCeilingInput {
    pub user_id: Uuid,
    pub max_capability_world: String,
    pub notes: Option<String>,
}

/// One integrity failure found while verifying a persisted audit chain.
/// Flattened from `talos_audit_ledger::ChainBreak` for the GraphQL surface.
#[derive(SimpleObject, Clone)]
pub struct AuditChainBreak {
    /// `sequence_gap` | `duplicate_sequence` | `genesis_mismatch` |
    /// `linkage_mismatch` | `bad_signature` | `unsigned`.
    pub kind: String,
    /// The sequence number the break is associated with, if applicable.
    pub sequence: Option<i64>,
    /// Expected value (prior/genesis hash, or expected sequence), if applicable.
    pub expected: Option<String>,
    /// Found value, if applicable.
    pub found: Option<String>,
}

impl From<&talos_audit_ledger::ChainBreak> for AuditChainBreak {
    fn from(b: &talos_audit_ledger::ChainBreak) -> Self {
        use talos_audit_ledger::ChainBreak as CB;
        match b {
            CB::SequenceGap { expected, found } => Self {
                kind: "sequence_gap".to_string(),
                sequence: i64::try_from(*found).ok(),
                expected: Some(expected.to_string()),
                found: Some(found.to_string()),
            },
            CB::DuplicateSequence { seq } => Self {
                kind: "duplicate_sequence".to_string(),
                sequence: i64::try_from(*seq).ok(),
                expected: None,
                found: None,
            },
            CB::GenesisMismatch {
                seq,
                expected,
                found,
            } => Self {
                kind: "genesis_mismatch".to_string(),
                sequence: i64::try_from(*seq).ok(),
                expected: Some(expected.clone()),
                found: Some(found.clone()),
            },
            CB::LinkageMismatch {
                seq,
                expected_previous,
                found_previous,
            } => Self {
                kind: "linkage_mismatch".to_string(),
                sequence: i64::try_from(*seq).ok(),
                expected: Some(expected_previous.clone()),
                found: Some(found_previous.clone()),
            },
            CB::BadSignature { seq } => Self {
                kind: "bad_signature".to_string(),
                sequence: i64::try_from(*seq).ok(),
                expected: None,
                found: None,
            },
            CB::Unsigned { seq } => Self {
                kind: "unsigned".to_string(),
                sequence: i64::try_from(*seq).ok(),
                expected: None,
                found: None,
            },
        }
    }
}

/// Result of verifying the cryptographic audit chain for one execution
/// (finding #2). `ok` is true iff there are no `breaks` and — when signing
/// keys are configured — every event's HMAC verified.
#[derive(SimpleObject, Clone)]
pub struct AuditChainVerification {
    pub execution_id: String,
    pub workflow_id: String,
    pub total_events: i32,
    pub ok: bool,
    /// Whether HMAC verification was attempted (signing keys configured).
    pub signatures_checked: bool,
    pub breaks: Vec<AuditChainBreak>,
}

impl From<talos_audit_ledger::ChainVerificationReport> for AuditChainVerification {
    fn from(r: talos_audit_ledger::ChainVerificationReport) -> Self {
        Self {
            execution_id: r.execution_id,
            workflow_id: r.workflow_id,
            total_events: i32::try_from(r.total_events).unwrap_or(i32::MAX),
            ok: r.ok,
            signatures_checked: r.signatures_checked,
            breaks: r.breaks.iter().map(AuditChainBreak::from).collect(),
        }
    }
}

#[cfg(test)]
mod audit_chain_mapping_tests {
    use super::*;
    use talos_audit_ledger::ChainBreak;

    #[test]
    fn sequence_gap_maps_found_to_sequence_and_both_to_expected_found() {
        let b = AuditChainBreak::from(&ChainBreak::SequenceGap {
            expected: 2,
            found: 4,
        });
        assert_eq!(b.kind, "sequence_gap");
        assert_eq!(b.sequence, Some(4));
        assert_eq!(b.expected.as_deref(), Some("2"));
        assert_eq!(b.found.as_deref(), Some("4"));
    }

    #[test]
    fn linkage_mismatch_maps_prev_hashes_to_expected_found() {
        let b = AuditChainBreak::from(&ChainBreak::LinkageMismatch {
            seq: 3,
            expected_previous: "aaa".to_string(),
            found_previous: "bbb".to_string(),
        });
        assert_eq!(b.kind, "linkage_mismatch");
        assert_eq!(b.sequence, Some(3));
        assert_eq!(b.expected.as_deref(), Some("aaa"));
        assert_eq!(b.found.as_deref(), Some("bbb"));
    }

    #[test]
    fn signature_variants_carry_only_the_sequence() {
        let bad = AuditChainBreak::from(&ChainBreak::BadSignature { seq: 5 });
        assert_eq!(bad.kind, "bad_signature");
        assert_eq!(bad.sequence, Some(5));
        assert!(bad.expected.is_none() && bad.found.is_none());

        let unsigned = AuditChainBreak::from(&ChainBreak::Unsigned { seq: 6 });
        assert_eq!(unsigned.kind, "unsigned");
        assert_eq!(unsigned.sequence, Some(6));
    }

    #[test]
    fn report_total_events_saturates_not_wraps() {
        let report = talos_audit_ledger::ChainVerificationReport {
            execution_id: "ex".to_string(),
            workflow_id: "wf".to_string(),
            total_events: usize::MAX,
            ok: false,
            signatures_checked: true,
            breaks: vec![],
        };
        let v = AuditChainVerification::from(report);
        assert_eq!(v.total_events, i32::MAX);
        assert!(!v.ok);
        assert!(v.signatures_checked);
    }
}
