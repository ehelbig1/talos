use crate::compilation::CompilationService;
use crate::engine::parallel::ParallelWorkflowEngine;
use crate::registry::ModuleRegistry;
use async_graphql::*;

pub struct ApiKeyScopes(pub Vec<crate::api_keys::ApiKeyScope>);

use futures_util::Stream;
use sha2::Digest;
use std::sync::Arc;
use tower_cookies::{Cookie, Cookies};
use tracing::info;
use uuid::Uuid;

const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024; // 10MB

fn validate_payload_size(name: &str, payload: &str) -> Result<()> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(async_graphql::Error::new(format!(
            "{} payload exceeds maximum size of 10MB",
            name
        )));
    }
    Ok(())
}

use worker::runtime::TalosRuntime;

/// Request metadata for audit logging
#[derive(Clone)]
pub struct RequestMetadata {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(SimpleObject)]
pub struct Workflow {
    pub id: Uuid,
    pub name: String,
    /// Serialized representation of the graph (flexible JSON).
    pub graph_json: String,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq, Debug)]
pub enum ExecutionStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

#[derive(SimpleObject, Clone, Debug)]
pub struct ExecutionEvent {
    pub execution_id: Uuid,
    pub node_id: Option<Uuid>,
    pub status: ExecutionStatus,
    pub log_message: Option<String>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
}

#[derive(SimpleObject, Clone)]
pub struct NodeTemplate {
    pub id: Uuid,
    pub name: String,
    pub category: String,
    pub description: Option<String>,
    pub config_schema: String, // Serialized JSON
    pub icon: Option<String>,
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
    pub capability_world: Option<String>,
    pub imported_interfaces: Option<Vec<String>>,
    pub source_code: Option<String>,
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

#[derive(InputObject)]
pub struct CreateModuleInput {
    pub template_id: Uuid,
    pub name: String,
    pub config: String, // JSON string
}

#[derive(InputObject)]
pub struct CreateCustomModuleInput {
    pub name: String,
    pub source_code: String,
    pub config: String,               // JSON string
    pub dependencies: Option<String>, // JSON string
}

#[derive(InputObject)]
pub struct AnalyzeCustomModuleInput {
    pub source_code: String,
}

#[derive(SimpleObject)]
pub struct AnalyzeCustomModuleResult {
    pub success: bool,
    pub errors: Vec<CompilationErrorObj>,
}

#[derive(SimpleObject)]
pub struct CompilationErrorObj {
    pub line: Option<i32>,
    pub column: Option<i32>,
    pub end_line: Option<i32>,
    pub end_column: Option<i32>,
    pub message: String,
    pub severity: String,
}

#[derive(InputObject)]
pub struct UpdateCustomModuleInput {
    pub id: Uuid,
    pub name: String,
    pub source_code: String,
    pub config: String,               // JSON string
    pub dependencies: Option<String>, // JSON string
}

#[derive(InputObject)]
pub struct TestCustomModuleInput {
    pub source_code: String,
    pub config: String,     // JSON string
    pub mock_input: String, // JSON string
}

#[derive(SimpleObject)]
pub struct TestCustomModuleResult {
    pub success: bool,
    pub output: Option<String>,
    pub logs: Vec<String>,
    pub errors: Vec<String>,
    pub execution_time_ms: i32,
}

#[derive(InputObject)]
pub struct CreateWorkflowInput {
    pub name: String,
    pub graph_json: String,
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
}

#[derive(InputObject)]
pub struct CreateSecretInput {
    pub name: String,
    pub key_path: String,
    pub value: String,
    pub description: Option<String>,
    pub allowed_modules: Option<Vec<Uuid>>,
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

#[derive(SimpleObject)]
pub struct AuthPayload {
    // Rename fields to camelCase for GraphQL clients.
    #[graphql(name = "accessToken")]
    pub access_token: String,
    #[graphql(name = "refreshToken")]
    pub refresh_token: String,
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
}

#[derive(SimpleObject)]
pub struct TwoFactorSetup {
    pub secret: String,
    #[graphql(name = "qrCodeUrl")]
    pub qr_code_url: String,
    #[graphql(name = "qrCodePng")]
    pub qr_code_png: String,
}

#[derive(SimpleObject)]
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
        self.limit.unwrap_or(100).max(1).min(1000) as i64
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

#[derive(SimpleObject)]
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
    type Error = std::sync::Arc<sqlx::Error>;

    async fn load(
        &self,
        keys: &[Uuid],
    ) -> std::result::Result<std::collections::HashMap<Uuid, Self::Value>, Self::Error> {
        #[derive(sqlx::FromRow)]
        struct ModuleRow {
            id: Uuid,
            name: String,
            size_bytes: i32,
            content_hash: String,
            compiled_at: chrono::DateTime<chrono::Utc>,
            config: Option<serde_json::Value>,
            source_code: Option<String>,
            capability_world: Option<String>,
            imported_interfaces: Option<Vec<String>>,
        }

        let modules = sqlx::query_as::<_, ModuleRow>(
            "SELECT id, name, size_bytes, content_hash, compiled_at, config, source_code, capability_world, imported_interfaces
             FROM wasm_modules
             WHERE id = ANY($1)"
        )
        .bind(keys)
        .fetch_all(&self.0)
        .await.map_err(std::sync::Arc::new)?;

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
                source_code: m.source_code,
                capability_world: m.capability_world,
                imported_interfaces: m.imported_interfaces,
            };
            map.insert(m.id, wm);
        }

        Ok(map)
    }
}

pub struct ModuleExecutionLogLoader(pub sqlx::Pool<sqlx::Postgres>);

impl async_graphql::dataloader::Loader<Uuid> for ModuleExecutionLogLoader {
    type Value = Vec<ModuleExecutionLog>;
    type Error = std::sync::Arc<sqlx::Error>;

    async fn load(
        &self,
        keys: &[Uuid],
    ) -> std::result::Result<std::collections::HashMap<Uuid, Self::Value>, Self::Error> {
        let logs = sqlx::query_as::<_, module_executions::ModuleExecutionLog>(
            r#"
            SELECT
                id, execution_id,
                level as "level: module_executions::LogLevel",
                message, metadata, created_at
            FROM module_execution_logs
            WHERE execution_id = ANY($1)
            ORDER BY created_at ASC
            "#,
        )
        .bind(keys)
        .fetch_all(&self.0)
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

pub struct QueryRoot;
pub struct MutationRoot;
pub struct SubscriptionRoot;

#[Object]
impl QueryRoot {
    async fn audit_settings(&self, ctx: &Context<'_>) -> Result<Option<UserAuditSettings>> {
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        #[derive(sqlx::FromRow)]
        struct SettingsRow {
            streaming_enabled: bool,
            otlp_endpoint: Option<String>,
            otlp_protocol: Option<String>,
            created_at: chrono::DateTime<chrono::Utc>,
            updated_at: chrono::DateTime<chrono::Utc>,
        }

        let row = sqlx::query_as::<_, SettingsRow>(
            r#"
            SELECT streaming_enabled, otlp_endpoint, otlp_protocol, created_at, updated_at
            FROM user_audit_settings
            WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(db_pool)
        .await?;

        Ok(row.map(|r| UserAuditSettings {
            streaming_enabled: r.streaming_enabled,
            otlp_endpoint: r.otlp_endpoint,
            otlp_protocol: r.otlp_protocol,
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
        }))
    }

    /// Get the latest execution for a list of workflows
    async fn latest_workflow_executions(
        &self,
        ctx: &Context<'_>,
        workflow_ids: Vec<Uuid>,
    ) -> Result<Vec<WorkflowExecution>> {
        let _user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        if workflow_ids.is_empty() {
            return Ok(vec![]);
        }

        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            workflow_id: Uuid,
            status: String,
            started_at: chrono::DateTime<chrono::Utc>,
            completed_at: Option<chrono::DateTime<chrono::Utc>>,
            error_message: Option<String>,
            created_at: chrono::DateTime<chrono::Utc>,
            output_data: Option<serde_json::Value>,
        }

        let rows = sqlx::query_as::<_, Row>(
            r#"
            SELECT DISTINCT ON (workflow_id)
                id, workflow_id, status, started_at, completed_at, error_message, created_at, output_data
            FROM workflow_executions
            WHERE workflow_id = ANY($1)
            ORDER BY workflow_id, started_at DESC
            "#,
        )
        .bind(&workflow_ids)
        .fetch_all(db_pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| WorkflowExecution {
                id: r.id,
                workflow_id: r.workflow_id,
                status: r.status,
                started_at: r.started_at.to_rfc3339(),
                completed_at: r.completed_at.map(|d| d.to_rfc3339()),
                error_message: r.error_message,
                created_at: r.created_at.to_rfc3339(),
                duration_ms: None,
                output_data: r.output_data,
            })
            .collect())
    }

    /// Get execution history for an entire workflow
    async fn workflow_execution_history(
        &self,
        ctx: &Context<'_>,
        workflow_id: Uuid,
        pagination: Option<PaginationInput>,
    ) -> Result<Vec<WorkflowExecution>> {
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        let limit_val = pagination
            .as_ref()
            .and_then(|p| p.limit)
            .unwrap_or(50)
            .min(1000) as i64;
        let offset_val = pagination.as_ref().and_then(|p| p.offset).unwrap_or(0) as i64;

        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            workflow_id: Uuid,
            status: String,
            started_at: chrono::DateTime<chrono::Utc>,
            completed_at: Option<chrono::DateTime<chrono::Utc>>,
            error_message: Option<String>,
            created_at: chrono::DateTime<chrono::Utc>,
            output_data: Option<serde_json::Value>,
        }

        let rows = sqlx::query_as::<_, Row>(
            r#"
            SELECT id, workflow_id, status, started_at, completed_at, error_message, created_at, output_data
            FROM workflow_executions
            WHERE workflow_id = $1 AND user_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(workflow_id)
        .bind(user_id)
        .bind(limit_val)
        .bind(offset_val)
        .fetch_all(db_pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let duration_ms = if let Some(completed) = r.completed_at {
                    Some((completed - r.started_at).num_milliseconds() as i32)
                } else {
                    None
                };

                WorkflowExecution {
                    id: r.id,
                    workflow_id: r.workflow_id,
                    status: r.status,
                    started_at: r.started_at.to_rfc3339(),
                    completed_at: r.completed_at.map(|d| d.to_rfc3339()),
                    error_message: r.error_message,
                    created_at: r.created_at.to_rfc3339(),
                    duration_ms,
                    output_data: r.output_data,
                }
            })
            .collect())
    }

    /// Get execution history for a module
    async fn module_execution_history(
        &self,
        ctx: &Context<'_>,
        module_id: Uuid,
        pagination: Option<PaginationInput>,
    ) -> Result<Vec<ModuleExecution>> {
        let execution_service =
            ctx.data::<Arc<crate::module_executions::ModuleExecutionService>>()?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        let limit_val = pagination
            .as_ref()
            .and_then(|p| p.limit)
            .unwrap_or(50)
            .min(1000) as i64;
        let offset_val = pagination.as_ref().and_then(|p| p.offset).unwrap_or(0) as i64;

        let executions = execution_service
            .get_module_executions(module_id, *user_id, limit_val, offset_val)
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch execution history: {}", e);
                async_graphql::Error::new("Failed to fetch execution history")
            })?;

        Ok(executions.into_iter().map(Into::into).collect())
    }

    /// Get logs for a specific module execution
    async fn module_execution_logs(
        &self,
        ctx: &Context<'_>,
        execution_id: Uuid,
    ) -> Result<Vec<ModuleExecutionLog>> {
        let execution_service =
            ctx.data::<Arc<crate::module_executions::ModuleExecutionService>>()?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // Explicit authorization check
        if execution_service
            .get_execution(execution_id, *user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to verify execution access: {}", e);
                async_graphql::Error::new("Failed to verify execution access")
            })?
            .is_none()
        {
            return Err(async_graphql::Error::new("Not found or permission denied"));
        }

        let logs = execution_service
            .get_execution_logs(execution_id, *user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch execution logs: {}", e);
                async_graphql::Error::new("Failed to fetch execution logs")
            })?;

        Ok(logs.into_iter().map(Into::into).collect())
    }
    /// Get current authenticated user
    async fn me(&self, ctx: &Context<'_>) -> Result<UserInfo> {
        let auth_service = ctx.data::<Arc<crate::auth::AuthService>>()?;
        let totp_service = ctx.data::<Arc<crate::totp_2fa::TotpService>>()?;

        // Get user_id from context (set by auth middleware)
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Not authenticated"))?;

        let user = auth_service.get_user(*user_id).await.map_err(|e| {
            tracing::error!("Failed to get user: {}", e);
            async_graphql::Error::new("Failed to get user")
        })?;

        // Check if 2FA is enabled
        let two_factor_enabled = totp_service.is_2fa_enabled(*user_id).await.unwrap_or(false);

        Ok(UserInfo {
            id: user.id,
            email: user.email,
            name: user.name,
            created_at: user.created_at.to_rfc3339(),
            two_factor_enabled,
        })
    }

    /// Fetch a workflow definition by ID.
    async fn workflow(&self, ctx: &Context<'_>, id: Uuid) -> Result<Workflow> {
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // Query workflow with ownership check
        let workflow = sqlx::query!(
            r#"
            SELECT id, name, module_uri, graph_json
            FROM workflows
            WHERE id = $1 AND user_id = $2
            "#,
            id,
            user_id
        )
        .fetch_optional(db_pool)
        .await?
        .ok_or_else(|| async_graphql::Error::new("Workflow not found or access denied"))?;

        Ok(Workflow {
            id: workflow.id,
            name: workflow.name,
            graph_json: workflow.graph_json,
        })
    }

    /// List available node templates with pagination
    async fn node_templates(
        &self,
        ctx: &Context<'_>,
        category: Option<String>,
        pagination: Option<PaginationInput>,
    ) -> Result<Vec<NodeTemplate>> {
        let registry = ctx.data::<Arc<ModuleRegistry>>()?;

        // Get pagination parameters
        let pagination = pagination.unwrap_or(PaginationInput {
            limit: Some(100),
            offset: Some(0),
        });
        let limit = pagination.get_limit();
        let offset = pagination.get_offset();

        let templates = registry
            .list_templates_paginated(category.as_deref(), limit, offset)
            .await?;

        Ok(templates
            .into_iter()
            .map(|t| NodeTemplate {
                id: t.id,
                name: t.name,
                category: t.category,
                description: t.description,
                // Serialize the JSON schema; panic only on unexpected serialization failure.
                config_schema: serde_json::to_string(&t.config_schema)
                    .unwrap_or_else(|_| "{}".to_string()),
                icon: t.icon,
            })
            .collect())
    }

    /// Get single template by ID
    async fn node_template(&self, ctx: &Context<'_>, id: Uuid) -> Result<NodeTemplate> {
        let registry = ctx.data::<Arc<ModuleRegistry>>()?;
        let t = registry.get_template(id).await?;

        Ok(NodeTemplate {
            id: t.id,
            name: t.name,
            category: t.category,
            description: t.description,
            config_schema: serde_json::to_string(&t.config_schema)
                .unwrap_or_else(|_| "{}".to_string()),
            icon: t.icon,
        })
    }

    /// List workflows for current user
    async fn workflows(
        &self,
        ctx: &Context<'_>,
        pagination: Option<PaginationInput>,
    ) -> Result<Vec<Workflow>> {
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        let limit_val = pagination
            .as_ref()
            .and_then(|p| p.limit)
            .unwrap_or(100)
            .min(1000) as i64;
        let offset_val = pagination.as_ref().and_then(|p| p.offset).unwrap_or(0) as i64;

        #[derive(sqlx::FromRow)]
        struct WorkflowRow {
            id: Uuid,
            name: String,
            graph_json: String,
        }

        let workflows = sqlx::query_as::<_, WorkflowRow>(
            "SELECT id, name, graph_json FROM workflows WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
        )
        .bind(user_id)
        .bind(limit_val)
        .bind(offset_val)
        .fetch_all(db_pool)
        .await?;

        Ok(workflows
            .into_iter()
            .map(|w| Workflow {
                id: w.id,
                name: w.name,
                graph_json: w.graph_json,
            })
            .collect())
    }

    /// Fetch WASM modules by IDs (for loading workflow nodes)
    async fn wasm_modules(&self, ctx: &Context<'_>, ids: Vec<Uuid>) -> Result<Vec<WasmModule>> {
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        #[derive(sqlx::FromRow)]
        struct ModuleRow {
            id: Uuid,
            name: String,
            size_bytes: i32,
            content_hash: String,
            compiled_at: chrono::DateTime<chrono::Utc>,
            config: Option<serde_json::Value>,
            source_code: Option<String>,
            capability_world: Option<String>,
            imported_interfaces: Option<Vec<String>>,
        }

        let modules = sqlx::query_as::<_, ModuleRow>(
            "SELECT id, name, size_bytes, content_hash, compiled_at, config, source_code, capability_world, imported_interfaces
             FROM wasm_modules
             WHERE id = ANY($1) AND user_id = $2"
        )
        .bind(&ids)
        .bind(user_id)
        .fetch_all(db_pool)
        .await?;

        Ok(modules
            .into_iter()
            .map(|m| WasmModule {
                id: m.id,
                name: m.name,
                size_bytes: m.size_bytes,
                content_hash: m.content_hash,
                compiled_at: m.compiled_at.to_rfc3339(),
                config: m
                    .config
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "{}".to_string()),
                capability_world: m.capability_world,
                imported_interfaces: m.imported_interfaces,
                source_code: m.source_code,
            })
            .collect())
    }

    /// List all compiled WASM modules for current user
    async fn my_modules(
        &self,
        ctx: &Context<'_>,
        pagination: Option<PaginationInput>,
    ) -> Result<Vec<WasmModule>> {
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        let limit_val = pagination
            .as_ref()
            .and_then(|p| p.limit)
            .unwrap_or(100)
            .min(1000) as i64;
        let offset_val = pagination.as_ref().and_then(|p| p.offset).unwrap_or(0) as i64;

        #[derive(sqlx::FromRow)]
        struct ModuleRow {
            id: Uuid,
            name: String,
            size_bytes: i32,
            content_hash: String,
            compiled_at: chrono::DateTime<chrono::Utc>,
            config: Option<serde_json::Value>,
            source_code: Option<String>,
            capability_world: Option<String>,
            imported_interfaces: Option<Vec<String>>,
        }

        let modules = sqlx::query_as::<_, ModuleRow>(
            "SELECT id, name, size_bytes, content_hash, compiled_at, config, source_code, capability_world, imported_interfaces
             FROM wasm_modules
             WHERE user_id = $1
             ORDER BY compiled_at DESC
             LIMIT $2 OFFSET $3"
        )
        .bind(user_id)
        .bind(limit_val)
        .bind(offset_val)
        .fetch_all(db_pool)
        .await?;

        Ok(modules
            .into_iter()
            .map(|m| WasmModule {
                id: m.id,
                name: m.name,
                size_bytes: m.size_bytes,
                content_hash: m.content_hash,
                compiled_at: m.compiled_at.to_rfc3339(),
                config: m
                    .config
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "{}".to_string()),
                capability_world: m.capability_world,
                imported_interfaces: m.imported_interfaces,
                source_code: m.source_code,
            })
            .collect())
    }

    /// List webhook listeners - scoped to current user with pagination
    async fn webhook_triggers(
        &self,
        ctx: &Context<'_>,
        pagination: Option<PaginationInput>,
    ) -> Result<Vec<WebhookTrigger>> {
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;
        let base_url =
            std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8000".to_string());

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // Get pagination parameters
        let pagination = pagination.unwrap_or(PaginationInput {
            limit: Some(100),
            offset: Some(0),
        });
        let limit = pagination.get_limit();
        let offset = pagination.get_offset();

        let listeners = sqlx::query!(
            r#"
            SELECT id, name, module_id,
                   enabled as "enabled!",
                   max_requests_per_minute as "max_requests_per_minute!",
                   trigger_count as "trigger_count!",
                   success_count as "success_count!",
                   error_count as "error_count!",
                   last_triggered_at
            FROM webhook_triggers
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
            user_id,
            limit,
            offset
        )
        .fetch_all(db_pool)
        .await?;

        Ok(listeners
            .into_iter()
            .map(|l| WebhookTrigger {
                id: l.id,
                module_id: l.module_id,
                name: l.name,
                webhook_url: format!("{}/webhooks/{}", base_url, l.id),
                verification_token: None, // Don't expose token in list queries
                enabled: l.enabled,
                max_requests_per_minute: l.max_requests_per_minute,
                trigger_count: l.trigger_count,
                success_count: l.success_count,
                error_count: l.error_count,
                last_triggered_at: l.last_triggered_at.map(|dt| dt.to_rfc3339()),
            })
            .collect())
    }

    /// List all secrets (without values) - scoped to current user with pagination
    async fn secrets(
        &self,
        ctx: &Context<'_>,
        pagination: Option<PaginationInput>,
    ) -> Result<Vec<Secret>> {
        let secrets_manager = ctx.data::<Arc<crate::secrets::SecretsManager>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // Get pagination parameters
        let pagination = pagination.unwrap_or(PaginationInput {
            limit: Some(100),
            offset: Some(0),
        });
        let limit = pagination.get_limit();
        let offset = pagination.get_offset();

        let secrets = secrets_manager
            .list_secrets_paginated(Some(*user_id), limit, offset)
            .await?;

        Ok(secrets
            .into_iter()
            .map(|s| Secret {
                id: s.id,
                name: s.name,
                key_path: s.key_path,
                description: s.description,
                created_at: s.created_at.to_rfc3339(),
                last_accessed_at: s.last_accessed_at.map(|dt| dt.to_rfc3339()),
                access_count: s.access_count,
                expires_at: s.expires_at.map(|dt| dt.to_rfc3339()),
            })
            .collect())
    }

    /// Get secret metadata by key path
    async fn secret(&self, ctx: &Context<'_>, key_path: String) -> Result<Secret> {
        let secrets_manager = ctx.data::<Arc<crate::secrets::SecretsManager>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        let s = secrets_manager
            .get_secret_metadata(&key_path)
            .await
            .map_err(|_| async_graphql::Error::new("Secret not found"))?;

        // Verify ownership - user must be owner or creator
        if s.owner_user_id != Some(*user_id) && s.created_by != Some(*user_id) {
            return Err(async_graphql::Error::new(
                "Secret not found or permission denied",
            ));
        }

        Ok(Secret {
            id: s.id,
            name: s.name,
            key_path: s.key_path,
            description: s.description,
            created_at: s.created_at.to_rfc3339(),
            last_accessed_at: s.last_accessed_at.map(|dt| dt.to_rfc3339()),
            access_count: s.access_count,
            expires_at: s.expires_at.map(|dt| dt.to_rfc3339()),
        })
    }

    /// Get audit log for a secret
    async fn secret_audit_log(
        &self,
        ctx: &Context<'_>,
        secret_id: Uuid,
        pagination: Option<PaginationInput>,
    ) -> Result<Vec<SecretAuditLog>> {
        let secrets_manager = ctx.data::<Arc<crate::secrets::SecretsManager>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // Cap limit at 1000 to prevent excessive queries
        let capped_limit = pagination
            .as_ref()
            .and_then(|p| p.limit)
            .unwrap_or(100)
            .min(1000) as i64;
        let offset_val = pagination.as_ref().and_then(|p| p.offset).unwrap_or(0) as i64;

        let logs = secrets_manager
            .get_audit_log(secret_id, capped_limit, offset_val, Some(*user_id))
            .await?;

        Ok(logs
            .into_iter()
            .map(|l| SecretAuditLog {
                id: l.id,
                action: l.action,
                actor_type: l.actor_type,
                success: l.success,
                timestamp: l.timestamp.to_rfc3339(),
                error_message: l.error_message,
            })
            .collect())
    }

    /// List API keys for current user with pagination
    async fn api_keys(
        &self,
        ctx: &Context<'_>,
        pagination: Option<PaginationInput>,
    ) -> Result<Vec<ApiKeyInfo>> {
        let api_key_service = ctx.data::<Arc<crate::api_keys::ApiKeyService>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // Get pagination parameters
        let pagination = pagination.unwrap_or(PaginationInput {
            limit: Some(100),
            offset: Some(0),
        });
        let limit = pagination.get_limit();
        let offset = pagination.get_offset();

        let keys = api_key_service
            .list_keys_paginated(*user_id, limit, offset)
            .await
            .map_err(|e| {
                tracing::error!("Failed to list API keys: {}", e);
                async_graphql::Error::new("Failed to list API keys")
            })?;

        Ok(keys
            .into_iter()
            .map(|k| ApiKeyInfo {
                id: k.id,
                name: k.name,
                key_prefix: k.key_prefix,
                scopes: k.scopes.iter().map(|s| s.to_string()).collect(),
                created_at: k.created_at.to_rfc3339(),
                expires_at: k.expires_at.map(|dt| dt.to_rfc3339()),
                last_used_at: k.last_used_at.map(|dt| dt.to_rfc3339()),
                is_active: k.is_active,
                usage_count: k.usage_count,
            })
            .collect())
    }

    /// Get OAuth login URL for a provider
    async fn oauth_login_url(&self, ctx: &Context<'_>, provider: String) -> Result<OAuthAuthUrl> {
        let oauth_service = ctx.data::<Arc<crate::oauth::OAuthService>>()?;

        let provider_enum = crate::oauth::OAuthProvider::from_str(&provider).map_err(|e| {
            tracing::error!("Invalid provider: {}", e);
            async_graphql::Error::new("Invalid provider")
        })?;

        if !oauth_service.is_provider_enabled(&provider_enum) {
            return Err(async_graphql::Error::new(format!(
                "{} OAuth is not configured",
                provider
            )));
        }

        let (auth_url, _csrf_token) = oauth_service
            .get_authorization_url(provider_enum, None)
            .await
            .map_err(|e| {
                tracing::error!("Failed to generate auth URL: {}", e);
                async_graphql::Error::new("Failed to generate auth URL")
            })?;

        Ok(OAuthAuthUrl { auth_url, provider })
    }

    /// List linked OAuth accounts for current user
    async fn linked_oauth_accounts(&self, ctx: &Context<'_>) -> Result<Vec<OAuthAccount>> {
        let oauth_service = ctx.data::<Arc<crate::oauth::OAuthService>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        let accounts = oauth_service
            .get_user_oauth_accounts(*user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to get OAuth accounts: {}", e);
                async_graphql::Error::new("Failed to get OAuth accounts")
            })?;

        Ok(accounts
            .into_iter()
            .map(|a| OAuthAccount {
                id: a.id,
                provider: a.provider,
                email: a.email,
                name: a.name,
                picture_url: a.picture_url,
                linked_at: a.created_at.map(|dt| dt.to_rfc3339()).unwrap_or_default(),
                last_login_at: a.last_login_at.map(|dt| dt.to_rfc3339()),
            })
            .collect())
    }

    /// Analyze custom module source code
    async fn analyze_custom_module(
        &self,
        ctx: &Context<'_>,
        input: AnalyzeCustomModuleInput,
    ) -> Result<AnalyzeCustomModuleResult> {
        validate_payload_size("source_code", &input.source_code)?;
        let compiler = ctx.data::<Arc<CompilationService>>()?;

        let _user_id = ctx
            .data_opt::<uuid::Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        let raw_errors = compiler
            .analyze_code("analysis", &input.source_code)
            .await
            .map_err(|e| {
                tracing::error!("Analysis failed: {}", e);
                async_graphql::Error::new("Analysis failed")
            })?;

        let errors = raw_errors
            .into_iter()
            .map(|e| CompilationErrorObj {
                line: e.line,
                column: e.column,
                end_line: e.end_line,
                end_column: e.end_column,
                message: e.message,
                severity: e.severity,
            })
            .collect::<Vec<_>>();

        Ok(AnalyzeCustomModuleResult {
            success: errors.is_empty(),
            errors,
        })
    }
}

#[Object]
impl MutationRoot {
    /// Sign up a new user
    async fn signup(&self, ctx: &Context<'_>, input: SignupInput) -> Result<AuthPayload> {
        let auth_service = ctx.data::<Arc<crate::auth::AuthService>>()?;
        let metadata = ctx.data_opt::<RequestMetadata>();

        // Create user
        let user_id = auth_service
            .create_user(
                &input.email,
                &input.password,
                input.name.as_deref(),
                metadata.and_then(|m| m.ip_address.as_deref()),
                metadata.and_then(|m| m.user_agent.as_deref()),
            )
            .await
            .map_err(|e| {
                tracing::error!("Signup failed: {}", e);
                async_graphql::Error::new("Signup failed")
            })?;

        // Get user details
        let user = auth_service.get_user(user_id).await.map_err(|e| {
            tracing::error!("Failed to get user: {}", e);
            async_graphql::Error::new("Failed to get user")
        })?;

        // Generate access token (short-lived: 15 minutes)
        let access_token = auth_service.generate_access_token(&user).map_err(|e| {
            tracing::error!("Failed to generate access token: {}", e);
            async_graphql::Error::new("Failed to generate access token")
        })?;

        // Generate refresh token (long-lived: 7 days)
        let refresh_token = auth_service
            .generate_refresh_token(user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to generate refresh token: {}", e);
                async_graphql::Error::new("Failed to generate refresh token")
            })?;

        // Set httpOnly cookies if Cookies extension is available
        if let Ok(cookies) = ctx.data::<Cookies>() {
            // Only require HTTPS in production (secure cookies won't work on http://localhost)
            let is_production = std::env::var("RUST_ENV").unwrap_or_default() == "production";

            let mut access_cookie = Cookie::new("talos_access_token", access_token.clone());
            access_cookie.set_http_only(true); // Secure: prevent JavaScript access (XSS protection)
            access_cookie.set_secure(is_production); // HTTPS only in production
            access_cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
            access_cookie.set_path("/");
            access_cookie.set_max_age(tower_cookies::cookie::time::Duration::minutes(15));
            cookies.add(access_cookie);

            let mut refresh_cookie = Cookie::new("talos_refresh_token", refresh_token.clone());
            refresh_cookie.set_http_only(true);
            refresh_cookie.set_secure(is_production);
            refresh_cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
            refresh_cookie.set_path("/");
            refresh_cookie.set_max_age(tower_cookies::cookie::time::Duration::days(7));
            cookies.add(refresh_cookie);
        }

        Ok(AuthPayload {
            access_token,
            refresh_token,
            user: UserInfo {
                id: user.id,
                email: user.email,
                name: user.name,
                created_at: user.created_at.to_rfc3339(),
                two_factor_enabled: user.totp_enabled.unwrap_or(false),
            },
        })
    }

    /// Login with email and password
    async fn login(&self, ctx: &Context<'_>, input: LoginInput) -> Result<AuthPayload> {
        let auth_service = ctx.data::<Arc<crate::auth::AuthService>>()?;
        let metadata = ctx.data_opt::<RequestMetadata>();

        // Authenticate user and get both access token and refresh token
        let (access_token, refresh_token, user) = auth_service
            .login(
                &input.email,
                &input.password,
                metadata.and_then(|m| m.ip_address.as_deref()),
                metadata.and_then(|m| m.user_agent.as_deref()),
            )
            .await
            .map_err(|e| {
                tracing::error!("Login failed: {}", e);
                async_graphql::Error::new("Login failed")
            })?;

        // Set httpOnly cookies if Cookies extension is available
        if let Ok(cookies) = ctx.data::<Cookies>() {
            // Only require HTTPS in production (secure cookies won't work on http://localhost)
            let is_production = std::env::var("RUST_ENV").unwrap_or_default() == "production";

            let mut access_cookie = Cookie::new("talos_access_token", access_token.clone());
            access_cookie.set_http_only(true); // Secure: prevent JavaScript access (XSS protection)
            access_cookie.set_secure(is_production); // HTTPS only in production
            access_cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
            access_cookie.set_path("/");
            access_cookie.set_max_age(tower_cookies::cookie::time::Duration::minutes(15));
            cookies.add(access_cookie);

            let mut refresh_cookie = Cookie::new("talos_refresh_token", refresh_token.clone());
            refresh_cookie.set_http_only(true);
            refresh_cookie.set_secure(is_production);
            refresh_cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
            refresh_cookie.set_path("/");
            refresh_cookie.set_max_age(tower_cookies::cookie::time::Duration::days(7));
            cookies.add(refresh_cookie);
        }

        Ok(AuthPayload {
            access_token,
            refresh_token,
            user: UserInfo {
                id: user.id,
                email: user.email,
                name: user.name,
                created_at: user.created_at.to_rfc3339(),
                two_factor_enabled: user.totp_enabled.unwrap_or(false),
            },
        })
    }

    /// Refresh access token using refresh token from httpOnly cookie
    async fn refresh_token(&self, ctx: &Context<'_>) -> Result<AuthPayload> {
        let auth_service = ctx.data::<Arc<crate::auth::AuthService>>()?;

        // Get refresh token from httpOnly cookie
        let cookies = ctx.data::<Cookies>()?;
        let refresh_token = cookies
            .get("talos_refresh_token")
            .ok_or_else(|| async_graphql::Error::new("No refresh token found in cookies"))?
            .value()
            .to_string();

        // Validate refresh token and generate new access token
        let (access_token, user) = auth_service
            .refresh_access_token(&refresh_token)
            .await
            .map_err(|e| {
                tracing::error!("Token refresh failed: {}", e);
                async_graphql::Error::new("Token refresh failed")
            })?;

        // Update access token cookie
        let mut access_cookie = Cookie::new("talos_access_token", access_token.clone());
        access_cookie.set_http_only(true);
        let is_production = std::env::var("RUST_ENV").unwrap_or_default() == "production";
        access_cookie.set_secure(is_production);
        access_cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
        access_cookie.set_path("/");
        access_cookie.set_max_age(tower_cookies::cookie::time::Duration::minutes(15));
        cookies.add(access_cookie);

        // Return the same refresh token (it's still valid)
        Ok(AuthPayload {
            access_token,
            refresh_token,
            user: UserInfo {
                id: user.id,
                email: user.email,
                name: user.name,
                created_at: user.created_at.to_rfc3339(),
                two_factor_enabled: user.totp_enabled.unwrap_or(false),
            },
        })
    }

    /// Logout (revoke refresh token from httpOnly cookie)
    async fn logout(&self, ctx: &Context<'_>) -> Result<bool> {
        let auth_service = ctx.data::<Arc<crate::auth::AuthService>>()?;

        // Get refresh token from httpOnly cookie
        let cookies = ctx.data::<Cookies>()?;
        let refresh_token = cookies
            .get("talos_refresh_token")
            .ok_or_else(|| async_graphql::Error::new("No refresh token found in cookies"))?
            .value()
            .to_string();

        auth_service
            .revoke_refresh_token(&refresh_token)
            .await
            .map_err(|e| {
                tracing::error!("Logout failed: {}", e);
                async_graphql::Error::new("Logout failed")
            })?;

        // Clear cookies
        cookies.remove(Cookie::from("talos_access_token"));
        cookies.remove(Cookie::from("talos_refresh_token"));

        Ok(true)
    }

    /// Initiate 2FA setup - generates secret and QR code
    async fn setup_two_factor(&self, ctx: &Context<'_>) -> Result<TwoFactorSetup> {
        let totp_service = ctx.data::<Arc<crate::totp_2fa::TotpService>>()?;
        let auth_service = ctx.data::<Arc<crate::auth::AuthService>>()?;

        // Get authenticated user
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        let user = auth_service.get_user(*user_id).await.map_err(|e| {
            tracing::error!("Failed to get user: {}", e);
            async_graphql::Error::new("Failed to get user")
        })?;

        // Generate secret
        let secret = totp_service.generate_secret();

        // Generate QR code URL and PNG
        let qr_code_url = totp_service
            .generate_qr_code_url(&secret, &user.email)
            .map_err(|e| {
                tracing::error!("Failed to generate QR URL: {}", e);
                async_graphql::Error::new("Failed to generate QR URL")
            })?;

        let qr_code_png = totp_service
            .generate_qr_code_png(&secret, &user.email)
            .map_err(|e| {
                tracing::error!("Failed to generate QR code: {}", e);
                async_graphql::Error::new("Failed to generate QR code")
            })?;

        Ok(TwoFactorSetup {
            secret,
            qr_code_url,
            qr_code_png,
        })
    }

    /// Enable 2FA - verify code and get backup codes
    async fn enable_two_factor(
        &self,
        ctx: &Context<'_>,
        input: Enable2FAInput,
    ) -> Result<TwoFactorEnrollment> {
        let totp_service = ctx.data::<Arc<crate::totp_2fa::TotpService>>()?;
        let auth_service = ctx.data::<Arc<crate::auth::AuthService>>()?;

        // Get authenticated user
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        let user = auth_service.get_user(*user_id).await.map_err(|e| {
            tracing::error!("Failed to get user: {}", e);
            async_graphql::Error::new("Failed to get user")
        })?;

        // Enable 2FA (verifies code and generates backup codes)
        let backup_codes = totp_service
            .enable_2fa(*user_id, &input.secret, &input.code, &user.email)
            .await
            .map_err(|e| {
                tracing::error!("Failed to enable 2FA: {}", e);
                async_graphql::Error::new("Failed to enable 2FA")
            })?;

        Ok(TwoFactorEnrollment { backup_codes })
    }

    /// Disable 2FA
    async fn disable_two_factor(&self, ctx: &Context<'_>) -> Result<bool> {
        let totp_service = ctx.data::<Arc<crate::totp_2fa::TotpService>>()?;

        // Get authenticated user
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        totp_service.disable_2fa(*user_id).await.map_err(|e| {
            tracing::error!("Failed to disable 2FA: {}", e);
            async_graphql::Error::new("Failed to disable 2FA")
        })?;

        Ok(true)
    }

    /// Verify 2FA code (used during login after password verification)
    async fn verify_two_factor(
        &self,
        ctx: &Context<'_>,
        input: Verify2FAInput,
    ) -> Result<AuthPayload> {
        let totp_service = ctx.data::<Arc<crate::totp_2fa::TotpService>>()?;
        let auth_service = ctx.data::<Arc<crate::auth::AuthService>>()?;

        // Get authenticated user (they've already passed password check)
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        let user = auth_service.get_user(*user_id).await.map_err(|e| {
            tracing::error!("Failed to get user: {}", e);
            async_graphql::Error::new("Failed to get user")
        })?;

        // Verify 2FA code
        let valid = totp_service
            .verify_2fa_login(*user_id, &input.code, &user.email)
            .await
            .map_err(|e| {
                tracing::error!("2FA verification failed: {}", e);
                async_graphql::Error::new("2FA verification failed")
            })?;

        if !valid {
            return Err(async_graphql::Error::new("Invalid 2FA code"));
        }

        // Generate new tokens
        let access_token = auth_service.generate_access_token(&user).map_err(|e| {
            tracing::error!("Failed to generate token: {}", e);
            async_graphql::Error::new("Failed to generate token")
        })?;

        let refresh_token = auth_service
            .generate_refresh_token(*user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to generate refresh token: {}", e);
                async_graphql::Error::new("Failed to generate refresh token")
            })?;

        // Set httpOnly cookies if available
        if let Ok(cookies) = ctx.data::<Cookies>() {
            let mut access_cookie = Cookie::new("talos_access_token", access_token.clone());
            access_cookie.set_http_only(true); // Secure: prevent JavaScript access (XSS protection)
            let is_production = std::env::var("RUST_ENV").unwrap_or_default() == "production";
            access_cookie.set_secure(is_production);
            access_cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
            access_cookie.set_path("/");
            access_cookie.set_max_age(tower_cookies::cookie::time::Duration::minutes(15));
            cookies.add(access_cookie);

            let mut refresh_cookie = Cookie::new("talos_refresh_token", refresh_token.clone());
            refresh_cookie.set_http_only(true);
            refresh_cookie.set_secure(is_production);
            refresh_cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
            refresh_cookie.set_path("/");
            refresh_cookie.set_max_age(tower_cookies::cookie::time::Duration::days(7));
            cookies.add(refresh_cookie);
        }

        Ok(AuthPayload {
            access_token,
            refresh_token,
            user: UserInfo {
                id: user.id,
                email: user.email,
                name: user.name,
                created_at: user.created_at.to_rfc3339(),
                two_factor_enabled: true,
            },
        })
    }

    /// Trigger execution of a workflow. Returns an execution UUID.
    async fn trigger_workflow(&self, ctx: &Context<'_>, workflow_id: Uuid) -> Result<Uuid> {
        // Get authenticated user
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?.clone();
        let execution_id = Uuid::new_v4();
        let sender = ctx
            .data::<tokio::sync::broadcast::Sender<ExecutionEvent>>()?
            .clone();
        let nats_client = ctx
            .data_opt::<Option<Arc<async_nats::Client>>>()
            .cloned()
            .flatten()
            .ok_or_else(|| async_graphql::Error::new("NATS client not available"))?;
        let worker_shared_key = ctx.data_opt::<Option<Arc<Vec<u8>>>>().cloned().flatten();
        let registry = ctx.data::<Arc<ModuleRegistry>>().ok().cloned();
        let secrets_manager = ctx
            .data::<Arc<crate::secrets::SecretsManager>>()
            .ok()
            .cloned();

        // Verify user owns the workflow
        let workflow_exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM workflows WHERE id = $1 AND user_id = $2)",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_one(&db_pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to check workflow: {}", e);
            async_graphql::Error::new("Failed to check workflow")
        })?;

        if !workflow_exists {
            return Err(async_graphql::Error::new(
                "Workflow not found or access denied",
            ));
        }

        // Create execution record in database BEFORE spawning task
        // This ensures the record exists when subscription checks authorization
        sqlx::query(
            r#"
            INSERT INTO workflow_executions (id, workflow_id, user_id, status)
            VALUES ($1, $2, $3, 'pending')
            "#,
        )
        .bind(execution_id)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&db_pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create execution: {}", e);
            async_graphql::Error::new("Failed to create execution")
        })?;

        // Spawn the actual execution in background
        let user_id = *user_id;
        tokio::spawn(async move {
            // Helper macro to store event in database AND broadcast
            macro_rules! store_and_send {
                ($event:expr) => {{
                    let event = $event;
                    // Store in database for audit trail and replay
                    let event_type = match (&event.node_id, &event.status) {
                        (None, ExecutionStatus::Running) => "started",
                        (Some(_), ExecutionStatus::Running) => "node_started",
                        (Some(_), ExecutionStatus::Completed) => "node_completed",
                        (Some(_), ExecutionStatus::Failed) => "node_failed",
                        (None, ExecutionStatus::Completed) => "completed",
                        (None, ExecutionStatus::Failed) => "failed",
                        (None, ExecutionStatus::Pending) => "pending",
                        (Some(_), ExecutionStatus::Pending) => "pending",
                    };

                    if let Err(db_err) = sqlx::query(
                        r#"
                        INSERT INTO execution_events (execution_id, event_type, node_id, status, log_message)
                        VALUES ($1, $2, $3, $4, $5)
                        "#
                    )
                    .bind(event.execution_id)
                    .bind(event_type)
                    .bind(event.node_id)
                    .bind(format!("{:?}", event.status))
                    .bind(&event.log_message)
                    .execute(&db_pool)
                    .await {
    tracing::error!("Database operation failed in schema: {}", db_err);
}

                    // Broadcast to subscriptions
                    info!("sending event: {:?}", event);
                    let _ = sender.send(event);
                }};
            }

            // Fetch workflow definition from database
            #[derive(sqlx::FromRow)]
            struct WorkflowGraph {
                graph_json: String,
            }

            let workflow_result = sqlx::query_as::<_, WorkflowGraph>(
                "SELECT graph_json FROM workflows WHERE id = $1 AND user_id = $2",
            )
            .bind(workflow_id)
            .bind(user_id)
            .fetch_one(&db_pool)
            .await;

            let workflow = match workflow_result {
                Ok(w) => w,
                Err(e) => {
                    let error_msg = format!("Failed to load workflow: {}", e);
                    if let Err(db_err) = sqlx::query(
                        "UPDATE workflow_executions SET status = 'failed', completed_at = NOW(), error_message = $2 WHERE id = $1"
                    )
                    .bind(execution_id)
                    .bind(&error_msg)
                    .execute(&db_pool)
                    .await {
    tracing::error!("Database operation failed in schema: {}", db_err);
}

                    let event = ExecutionEvent {
                        execution_id,
                        node_id: None,
                        status: ExecutionStatus::Failed,
                        trace_id: None,
                        span_id: None,
                        log_message: Some(error_msg),
                    };
                    store_and_send!(event);
                    return;
                }
            };

            // Update execution status to running
            if let Err(db_err) = sqlx::query(
                "UPDATE workflow_executions SET status = 'running', started_at = NOW() WHERE id = $1"
            )
            .bind(execution_id)
            .execute(&db_pool)
            .await {
    tracing::error!("Database operation failed in schema: {}", db_err);
}

            // Send "Running" event (NO DELAY - events are persisted now)
            let event = ExecutionEvent {
                execution_id,
                node_id: None,
                status: ExecutionStatus::Running,
                trace_id: None,
                span_id: None,
                log_message: Some("Workflow started".to_string()),
            };
            store_and_send!(event);

            // Parse workflow graph JSON from string
            let graph: serde_json::Value = match serde_json::from_str(&workflow.graph_json) {
                Ok(g) => g,
                Err(e) => {
                    let error_msg = format!("Failed to parse workflow graph: {}", e);
                    if let Err(db_err) = sqlx::query(
                        "UPDATE workflow_executions SET status = 'failed', completed_at = NOW(), error_message = $2 WHERE id = $1"
                    )
                    .bind(execution_id)
                    .bind(&error_msg)
                    .execute(&db_pool)
                    .await {
    tracing::error!("Database operation failed in schema: {}", db_err);
}

                    let event = ExecutionEvent {
                        execution_id,
                        node_id: None,
                        status: ExecutionStatus::Failed,
                        trace_id: None,
                        span_id: None,
                        log_message: Some(error_msg),
                    };
                    store_and_send!(event);
                    return;
                }
            };

            // Extract nodes from workflow graph JSON
            let graph = &graph;
            let empty_nodes = vec![];
            let nodes = graph
                .get("nodes")
                .and_then(|n| n.as_array())
                .unwrap_or(&empty_nodes);

            if nodes.is_empty() {
                let error_msg = "Workflow has no nodes to execute".to_string();
                if let Err(db_err) = sqlx::query(
                    "UPDATE workflow_executions SET status = 'failed', completed_at = NOW(), error_message = $2 WHERE id = $1"
                )
                .bind(execution_id)
                .bind(&error_msg)
                .execute(&db_pool)
                .await {
    tracing::error!("Database operation failed in schema: {}", db_err);
}

                let event = ExecutionEvent {
                    execution_id,
                    node_id: None,
                    status: ExecutionStatus::Failed,
                    trace_id: None,
                    span_id: None,
                    log_message: Some(error_msg),
                };
                store_and_send!(event);
                return;
            }

            // Build workflow engine with actual nodes
            let mut engine = match (registry, secrets_manager) {
                (Some(reg), Some(sm)) => ParallelWorkflowEngine::with_services(reg, sm, user_id),
                (Some(reg), None) => ParallelWorkflowEngine::with_registry(reg),
                _ => ParallelWorkflowEngine::new(),
            };

            // Add all nodes from workflow graph
            // Note: "type" field contains the module UUID, "id" is just UI tracking
            let mut node_ids = Vec::new();
            // We need to map UI Node IDs to WASM Module IDs so we can save executions correctly
            let mut ui_to_wasm_map: std::collections::HashMap<Uuid, Uuid> =
                std::collections::HashMap::new();

            for node in nodes {
                let ui_id_str = node.get("id").and_then(|i| i.as_str());
                let wasm_id_str = node.get("type").and_then(|i| i.as_str());

                if let (Some(ui_id_str), Some(wasm_id_str)) = (ui_id_str, wasm_id_str) {
                    if let (Ok(_ui_id), Ok(wasm_id)) =
                        (Uuid::parse_str(ui_id_str), Uuid::parse_str(wasm_id_str))
                    {
                        // The engine currently uses the WASM module ID as the graph node ID.
                        // (Ideally it should use the UI node ID so identical modules can run twice, but we'll respect current architecture).
                        engine.add_node(wasm_id);
                        node_ids.push(wasm_id);

                        // BUT we need a mapping so we know what WASM module actually ran
                        ui_to_wasm_map.insert(wasm_id, wasm_id);
                        info!("Added module to workflow: {}", wasm_id);
                    }
                }
            }

            // Execute workflow
            match engine
                .run(nats_client, worker_shared_key, execution_id)
                .await
            {
                Ok(ctx) => {
                    // Convert entire ctx.results hashmap to JSON to save on the workflow_execution
                    let mut aggregated_output = serde_json::Map::new();
                    for (node_id, output) in &ctx.results {
                        aggregated_output.insert(node_id.to_string(), output.clone());
                    }
                    let aggregated_json = serde_json::Value::Object(aggregated_output);

                    // Update execution status
                    if let Err(db_err) = sqlx::query(
                        "UPDATE workflow_executions SET status = 'completed', completed_at = NOW(), output_data = $2 WHERE id = $1"
                    )
                    .bind(execution_id)
                    .bind(&aggregated_json)
                    .execute(&db_pool)
                    .await {
    tracing::error!("Database operation failed in schema: {}", db_err);
}

                    // Insert the node execution results into module_executions so they appear in ExecutionHistory!
                    for (module_id, output) in ctx.results {
                        let module_exec_id = Uuid::new_v4();
                        let wasm_module_id =
                            ui_to_wasm_map.get(&module_id).copied().unwrap_or(module_id);

                        let res = sqlx::query(
                            r#"
                            INSERT INTO module_executions 
                            (id, module_id, user_id, status, trigger_type, output_data, started_at, completed_at, duration_ms)
                            VALUES ($1, $2, $3, 'completed', 'manual', $4, NOW(), NOW(), 100)
                            "#
                        )
                        .bind(module_exec_id)
                        .bind(wasm_module_id)
                        .bind(user_id)
                        .bind(&output)
                        .execute(&db_pool)
                        .await;

                        if let Err(e) = res {
                            tracing::warn!(
                                "Failed to save execution history for module {}: {:?}",
                                wasm_module_id,
                                e
                            );
                        }
                    }

                    let event = ExecutionEvent {
                        execution_id,
                        node_id: None,
                        status: ExecutionStatus::Completed,
                        trace_id: None,
                        span_id: None,
                        log_message: Some("Workflow finished successfully".to_string()),
                    };
                    store_and_send!(event);
                }
                Err(e) => {
                    // Update execution status with error
                    let error_msg = format!("Workflow failed: {}", e);
                    if let Err(db_err) = sqlx::query(
                        "UPDATE workflow_executions SET status = 'failed', completed_at = NOW(), error_message = $2 WHERE id = $1"
                    )
                    .bind(execution_id)
                    .bind(&error_msg)
                    .execute(&db_pool)
                    .await {
    tracing::error!("Database operation failed in schema: {}", db_err);
}

                    // Note: sending node_id=None signals to the frontend that the *entire workflow* has failed.
                    let event = ExecutionEvent {
                        execution_id,
                        node_id: None,
                        status: ExecutionStatus::Failed,
                        trace_id: None,
                        span_id: None,
                        log_message: Some(error_msg),
                    };
                    store_and_send!(event);
                }
            }
        });
        Ok(execution_id)
    }

    /// Test a custom module without saving it
    async fn test_custom_module(
        &self,
        ctx: &Context<'_>,
        input: TestCustomModuleInput,
    ) -> Result<TestCustomModuleResult> {
        let compiler = ctx.data::<Arc<CompilationService>>()?;
        let runtime = ctx.data::<Arc<TalosRuntime>>()?;

        // Get authenticated user_id from context
        let _user_id = ctx
            .data_opt::<uuid::Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // Parse config & input

        let config: serde_json::Value = serde_json::from_str(&input.config).map_err(|e| {
            tracing::error!("Invalid JSON config: {}", e);
            async_graphql::Error::new("Invalid JSON config")
        })?;
        let mock_input: serde_json::Value =
            serde_json::from_str(&input.mock_input).map_err(|e| {
                tracing::error!("Invalid JSON mock input: {}", e);
                async_graphql::Error::new("Invalid JSON mock input")
            })?;

        // 1. Compile it (ephemeral)
        let result = compiler
            .compile_to_wasm_with_config("test-module", &input.source_code, &config, None)
            .await
            .map_err(|e| {
                tracing::error!("Compilation failed: {}", e);
                async_graphql::Error::new("Compilation failed")
            })?;

        if !result.success {
            let error_messages: Vec<String> =
                result.errors.iter().map(|e| e.message.clone()).collect();
            return Ok(TestCustomModuleResult {
                success: false,
                output: None,
                logs: vec![],
                errors: error_messages,
                execution_time_ms: 0,
            });
        }

        let wasm_bytes = result
            .wasm_bytes
            .ok_or_else(|| async_graphql::Error::new("Missing wasm bytes in compilation result"))?;

        // Prepare the execution payload
        let exec_payload = serde_json::json!({
            "config": config,
            "input": mock_input,
        })
        .to_string();

        let start = std::time::Instant::now();
        let (exec_result, logs) = runtime
            .execute_test_module_string(&wasm_bytes, &exec_payload)
            .await;
        let duration_ms = start.elapsed().as_millis() as i32;

        match exec_result {
            Ok(output) => Ok(TestCustomModuleResult {
                success: true,
                output: Some(output),
                logs,
                errors: vec![],
                execution_time_ms: duration_ms,
            }),
            Err(e) => Ok(TestCustomModuleResult {
                success: false,
                output: None,
                logs,
                errors: vec![e],
                execution_time_ms: duration_ms,
            }),
        }
    }

    /// Create a custom module from raw source code
    async fn create_custom_module(
        &self,
        ctx: &Context<'_>,
        input: CreateCustomModuleInput,
    ) -> Result<WasmModule> {
        let registry = ctx.data::<Arc<ModuleRegistry>>()?;
        let compiler = ctx.data::<Arc<CompilationService>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // Parse config
        let config: serde_json::Value = serde_json::from_str(&input.config).map_err(|e| {
            tracing::error!("Invalid JSON config: {}", e);
            async_graphql::Error::new("Invalid JSON config")
        })?;

        let dependencies = if let Some(deps_str) = &input.dependencies {
            let deps: serde_json::Value = serde_json::from_str(deps_str).map_err(|e| {
                tracing::error!("Invalid JSON dependencies: {}", e);
                async_graphql::Error::new("Invalid JSON dependencies")
            })?;
            Some(deps)
        } else {
            None
        };

        // Compile custom source code
        let result = compiler
            .compile_to_wasm_with_config(
                &input.name,
                &input.source_code,
                &config,
                dependencies.as_ref(),
            )
            .await
            .map_err(|e| {
                tracing::error!("Compilation failed: {}", e);
                async_graphql::Error::new("Compilation failed")
            })?;

        if !result.success {
            let error_messages: Vec<String> =
                result.errors.iter().map(|e| e.message.clone()).collect();
            return Err(Error::new("Compilation failed")
                .extend_with(|_, e| e.set("errors", error_messages)));
        }

        // Store module
        let module = crate::registry::WasmModule {
            name: input.name.clone(),
            content_hash: result.content_hash,
            capability_world: result.capability_world,
            imported_interfaces: result.imported_interfaces,
            allowed_methods: vec![],
            wasm_bytes: result.wasm_bytes.ok_or_else(|| {
                async_graphql::Error::new("Missing wasm bytes in compilation result")
            })?,
            source_code: Some(input.source_code),
            template_id: None,
            config: Some(config), // Config stored as metadata, NOT compiled into WASM
            dependencies,
            size_bytes: result.size_bytes,
            max_fuel: 1_000_000,
            max_memory_mb: 128,
            allowed_hosts: vec![],
            user_id: Some(*user_id),
            oci_url: None,
        };

        let module_id = registry.store_module(module.clone()).await?;

        Ok(WasmModule {
            id: module_id,
            name: module.name,
            size_bytes: module.size_bytes,
            content_hash: module.content_hash,
            compiled_at: chrono::Utc::now().to_rfc3339(),
            config: module
                .config
                .map(|c| c.to_string())
                .unwrap_or_else(|| "{}".to_string()),
            capability_world: Some(module.capability_world.to_string()),
            imported_interfaces: Some(module.imported_interfaces),
            source_code: None,
        })
    }

    /// Update an existing custom module
    async fn update_custom_module(
        &self,
        ctx: &Context<'_>,
        input: UpdateCustomModuleInput,
    ) -> Result<WasmModule> {
        let registry = ctx.data::<Arc<ModuleRegistry>>()?;
        let compiler = ctx.data::<Arc<CompilationService>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // Verify module ownership
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;
        let owns_module = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM wasm_modules WHERE id = $1 AND user_id = $2)",
        )
        .bind(input.id)
        .bind(user_id)
        .fetch_one(db_pool)
        .await
        .unwrap_or(false);

        if !owns_module {
            return Err(Error::new("Module not found or access denied"));
        }

        // Parse config
        let config: serde_json::Value = serde_json::from_str(&input.config).map_err(|e| {
            tracing::error!("Invalid JSON config: {}", e);
            async_graphql::Error::new("Invalid JSON config")
        })?;

        let dependencies = if let Some(deps_str) = &input.dependencies {
            let deps: serde_json::Value = serde_json::from_str(deps_str).map_err(|e| {
                tracing::error!("Invalid JSON dependencies: {}", e);
                async_graphql::Error::new("Invalid JSON dependencies")
            })?;
            Some(deps)
        } else {
            None
        };

        // Compile custom source code
        let result = compiler
            .compile_to_wasm_with_config(
                &input.name,
                &input.source_code,
                &config,
                dependencies.as_ref(),
            )
            .await
            .map_err(|e| {
                tracing::error!("Compilation failed: {}", e);
                async_graphql::Error::new("Compilation failed")
            })?;

        if !result.success {
            let error_messages: Vec<String> =
                result.errors.iter().map(|e| e.message.clone()).collect();
            return Err(Error::new("Compilation failed")
                .extend_with(|_, e| e.set("errors", error_messages)));
        }

        // Create updated module object
        let module = crate::registry::WasmModule {
            name: input.name.clone(),
            content_hash: result.content_hash,
            capability_world: result.capability_world,
            imported_interfaces: result.imported_interfaces,
            allowed_methods: vec![],
            wasm_bytes: result.wasm_bytes.ok_or_else(|| {
                async_graphql::Error::new("Missing wasm bytes in compilation result")
            })?,
            source_code: Some(input.source_code),
            template_id: None,
            config: Some(config), // Config stored as metadata, NOT compiled into WASM
            dependencies,
            size_bytes: result.size_bytes,
            max_fuel: 1_000_000,
            max_memory_mb: 128,
            allowed_hosts: vec![],
            user_id: Some(*user_id),
            oci_url: None,
        };

        // Update module in DB
        registry.update_module(input.id, module.clone()).await?;

        Ok(WasmModule {
            id: input.id,
            name: module.name,
            size_bytes: module.size_bytes,
            content_hash: module.content_hash,
            compiled_at: chrono::Utc::now().to_rfc3339(),
            config: module
                .config
                .map(|c| c.to_string())
                .unwrap_or_else(|| "{}".to_string()),
            capability_world: Some(module.capability_world.to_string()),
            imported_interfaces: Some(module.imported_interfaces),
            source_code: None,
        })
    }

    /// Create node from template
    async fn create_module_from_template(
        &self,
        ctx: &Context<'_>,
        input: CreateModuleInput,
    ) -> Result<WasmModule> {
        let registry = ctx.data::<Arc<ModuleRegistry>>()?;
        let compiler = ctx.data::<Arc<CompilationService>>()?;
        let secrets_manager = ctx.data::<Arc<crate::secrets::SecretsManager>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // 1. Fetch template
        let template = registry.get_template(input.template_id).await?;

        // 2. Parse config
        let config: serde_json::Value = serde_json::from_str(&input.config).map_err(|e| {
            tracing::error!("Invalid JSON config: {}", e);
            async_graphql::Error::new("Invalid JSON config")
        })?;

        // 3. Extract secret references and validate they exist
        let secret_refs = crate::secrets::extract_secret_references(&config);
        for secret_path in &secret_refs {
            if !secrets_manager.secret_exists(secret_path).await? {
                return Err(Error::new(format!(
                    "Secret not found: {}. Please create it first.",
                    secret_path
                )));
            }
        }

        // 4. Use precompiled WASM if available, otherwise compile template
        let mut oci_url_opt = None;

        let (
            wasm_bytes,
            source_code,
            size_bytes,
            content_hash,
            capability_world,
            imported_interfaces,
        ) = if let Some(precompiled) = template.precompiled_wasm {
            // Use precompiled template WASM
            let mut hasher = sha2::Sha256::new();
            hasher.update(&precompiled);
            let hash = format!("{:x}", hasher.finalize());
            let inspection = worker::inspect_component(&precompiled);

            (
                precompiled.clone(),
                template.code_template.clone(),
                precompiled.len() as i32,
                hash,
                inspection.capability_world,
                inspection.imported_interfaces,
            )
        } else if let Some(ref url) = template.oci_url {
            // It's an OCI image - we don't compile anything, and we don't store WASM bytes.
            // The Worker will pull the image from the registry and inspect it at runtime.
            oci_url_opt = Some(url.clone());

            // We use a dummy hash since it's fetched at runtime
            let mut hasher = sha2::Sha256::new();
            hasher.update(url.as_bytes());
            hasher.update(
                serde_json::to_string(&config)
                    .unwrap_or_default()
                    .as_bytes(),
            );
            hasher.update(Uuid::new_v4().to_string().as_bytes()); // Force uniqueness to bypass WASM deduplication layer
            let hash = format!("{:x}", hasher.finalize());

            (
                vec![],         // Empty WASM bytes
                "".to_string(), // Empty source
                0,
                hash,
                worker::CapabilityWorld::Unknown, // Worker will determine this at runtime
                vec![],
            )
        } else {
            // Compile template with config rendering
            // Config is rendered into template at compile-time for optimal performance
            let result = compiler
                .compile_to_wasm_with_config(&input.name, &template.code_template, &config, None)
                .await
                .map_err(|e| {
                    tracing::error!("Compilation failed: {}", e);
                    async_graphql::Error::new("Compilation failed")
                })?;

            if !result.success {
                let error_messages: Vec<String> =
                    result.errors.iter().map(|e| e.message.clone()).collect();
                return Err(Error::new("Compilation failed")
                    .extend_with(|_, e| e.set("errors", error_messages)));
            }

            (
                result.wasm_bytes.ok_or_else(|| {
                    async_graphql::Error::new("Missing wasm bytes in compilation result")
                })?,
                template.code_template.clone(),
                result.size_bytes,
                result.content_hash,
                result.capability_world,
                result.imported_interfaces,
            )
        };

        // 5. Store module with config as metadata
        let module = crate::registry::WasmModule {
            name: input.name.clone(),
            content_hash,
            capability_world,
            imported_interfaces,
            allowed_methods: vec![],
            wasm_bytes,
            source_code: Some(source_code),
            template_id: Some(input.template_id),
            config: Some(config.clone()), // Config stored as metadata, NOT compiled into WASM
            dependencies: None,
            size_bytes,
            max_fuel: 1_000_000,
            max_memory_mb: 128,
            allowed_hosts: {
                let mut hosts = vec![];
                // Fallback hardcode for the analyzer since it might not be passing the array correctly through UI schema
                if template.name.contains("GitHub Repo Analyzer") {
                    hosts.push("api.github.com".to_string());
                }

                if let Some(schema_hosts) = template
                    .config_schema
                    .get("talos_allowed_hosts")
                    .and_then(|h| h.as_array())
                {
                    for h in schema_hosts {
                        if let Some(h_str) = h.as_str() {
                            hosts.push(h_str.to_string());
                        }
                    }
                }
                hosts
            },
            user_id: Some(*user_id),
            oci_url: oci_url_opt,
        };

        let module_id = registry.store_module(module.clone()).await?;

        // AUTO-SETUP: Create Google Calendar watch channels for webhook nodes
        if template.category == "calendar" && template.name.contains("Webhook") {
            tracing::info!(
                "🔧 Auto-setting up Google Calendar webhook for module {}",
                module_id
            );

            // Extract integration and calendar IDs from config
            tracing::debug!(
                "Config keys: {:?}",
                config.as_object().map(|o| o.keys().collect::<Vec<_>>())
            );

            if let (Some(integration_id_str), Some(calendar_ids)) = (
                config
                    .get("GOOGLE_CALENDAR_INTEGRATION_ID")
                    .and_then(|v| v.as_str()),
                config.get("CALENDAR_IDS").and_then(|v| v.as_array()),
            ) {
                tracing::info!(
                    "Found integration_id: {}, calendars: {:?}",
                    integration_id_str,
                    calendar_ids
                );

                if let Ok(integration_id) = Uuid::parse_str(integration_id_str) {
                    tracing::info!("Parsed integration UUID: {}", integration_id);

                    // SECURITY: Verify the user owns this integration before creating watch channels
                    // This prevents users from creating watch channels using other users' credentials
                    let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;
                    let owns_integration = sqlx::query_scalar::<_, bool>(
                        "SELECT EXISTS(
                            SELECT 1 FROM google_calendar_integrations
                            WHERE id = $1 AND user_id = $2 AND is_active = true
                        )",
                    )
                    .bind(integration_id)
                    .bind(user_id)
                    .fetch_one(db_pool)
                    .await
                    .unwrap_or(false);

                    if !owns_integration {
                        tracing::warn!(
                            "🚨 SECURITY: User {} attempted to use integration {} they don't own. Skipping auto-setup.",
                            user_id, integration_id
                        );
                        // Continue with module creation but skip watch channel setup
                        // This prevents the entire mutation from failing
                    } else {
                        // Get Google Calendar service
                        match ctx.data::<Arc<crate::google_calendar::GoogleCalendarService>>() {
                            Ok(google_calendar_service) => {
                                tracing::info!("Got Google Calendar service from context");
                                let base_url = std::env::var("BASE_URL")
                                    .unwrap_or_else(|_| "http://localhost:8000".to_string());
                                let webhook_url =
                                    format!("{}/api/google-calendar/webhook", base_url);

                                let mut watch_channel_ids = Vec::new();
                                let mut errors = Vec::new();

                                // Create watch channel for each calendar
                                for calendar_id_val in calendar_ids {
                                    if let Some(calendar_id) = calendar_id_val.as_str() {
                                        match google_calendar_service
                                            .create_watch_channel(
                                                integration_id,
                                                calendar_id,
                                                &webhook_url,
                                                Some(module_id),
                                            )
                                            .await
                                        {
                                            Ok(channel) => {
                                                tracing::info!(
                                            "✅ Created watch channel {} for calendar {} (expires: {})",
                                            channel.id, calendar_id, channel.expiration
                                        );
                                                watch_channel_ids.push(serde_json::json!({
                                                    "id": channel.id.to_string(),
                                                    "calendar_id": calendar_id,
                                                    "channel_id": channel.channel_id,
                                                    "expiration": channel.expiration.to_rfc3339(),
                                                }));
                                            }
                                            Err(e) => {
                                                let error_msg =
                                                    format!("Calendar '{}': {}", calendar_id, e);
                                                tracing::warn!(
                                                    "⚠️ Failed to create watch channel: {}",
                                                    error_msg
                                                );
                                                errors.push(error_msg);
                                            }
                                        }
                                    }
                                }

                                // Update module config with created watch channels
                                if !watch_channel_ids.is_empty() {
                                    let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;
                                    let updated_config = {
                                        let mut cfg = config.clone();
                                        cfg["WATCH_CHANNELS"] =
                                            serde_json::json!(watch_channel_ids);
                                        cfg
                                    };

                                    // CRITICAL: Handle database update errors properly
                                    // If this fails, we have orphaned watch channels in Google Calendar
                                    match sqlx::query!(
                                        "UPDATE wasm_modules SET config = $1 WHERE id = $2",
                                        updated_config,
                                        module_id
                                    )
                                    .execute(db_pool)
                                    .await
                                    {
                                        Ok(_) => {
                                            tracing::info!(
                                        "✅ Auto-setup complete: {} watch channel(s) created for module {}",
                                        watch_channel_ids.len(), module_id
                                    );
                                        }
                                        Err(e) => {
                                            tracing::error!(
                                        "❌ CRITICAL: Failed to update module config with watch channels: {}. Cleaning up orphaned channels.",
                                        e
                                    );

                                            // Clean up orphaned watch channels to prevent resource leaks
                                            let mut cleanup_tasks = vec![];
                                            for watch_info in &watch_channel_ids {
                                                if let Some(id_str) =
                                                    watch_info.get("id").and_then(|v| v.as_str())
                                                {
                                                    if let Ok(channel_uuid) =
                                                        Uuid::parse_str(id_str)
                                                    {
                                                        let service = std::sync::Arc::clone(
                                                            &google_calendar_service,
                                                        );
                                                        cleanup_tasks.push(tokio::spawn(async move {
                                                            match service.stop_watch_channel(channel_uuid).await {
                                                                Ok(_) => tracing::info!("✅ Cleaned up orphaned watch channel {}", channel_uuid),
                                                                Err(err) => tracing::error!("❌ Failed to cleanup orphaned watch channel {}: {}", channel_uuid, err),
                                                            }
                                                        }));
                                                    }
                                                }
                                            }
                                            futures::future::join_all(cleanup_tasks).await;

                                            errors.push(format!(
                                                "Failed to save watch channel configuration: {}",
                                                e
                                            ));
                                        }
                                    }
                                }

                                // If there were partial failures, log them but don't fail the mutation
                                if !errors.is_empty() {
                                    tracing::warn!(
                                        "⚠️ Some watch channels failed to create: {}",
                                        errors.join("; ")
                                    );
                                }
                            }
                            Err(_) => {
                                tracing::warn!("⚠️ Google Calendar service not available in GraphQL context for auto-setup");
                            }
                        }
                    } // End of authorization check block
                } else {
                    tracing::warn!(
                        "⚠️ Failed to parse integration_id as UUID: {}",
                        integration_id_str
                    );
                }
            } else {
                tracing::warn!(
                    "⚠️ Missing GOOGLE_CALENDAR_INTEGRATION_ID or CALENDAR_IDS in config"
                );
            }
        }

        Ok(WasmModule {
            id: module_id,
            name: module.name,
            size_bytes: module.size_bytes,
            content_hash: module.content_hash,
            compiled_at: chrono::Utc::now().to_rfc3339(),
            config: module
                .config
                .map(|c| c.to_string())
                .unwrap_or_else(|| "{}".to_string()),
            capability_world: Some(module.capability_world.to_string()),
            imported_interfaces: Some(module.imported_interfaces),
            source_code: None,
        })
    }

    /// Create a webhook listener
    async fn create_webhook_trigger(
        &self,
        ctx: &Context<'_>,
        input: CreateWebhookTriggerInput,
    ) -> Result<WebhookTrigger> {
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;
        let base_url =
            std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8000".to_string());

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // Verify the user owns the module
        let module_exists: Option<bool> = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM wasm_modules WHERE id = $1 AND user_id = $2)",
        )
        .bind(input.module_id)
        .bind(user_id)
        .fetch_one(db_pool)
        .await?;

        if !module_exists.unwrap_or(false) {
            return Err(async_graphql::Error::new(
                "Module not found or access denied",
            ));
        }

        let enabled = input.enabled.unwrap_or(true);
        // Convert Option<Vec<String>> to Option<&[String]> without extra allocation.
        let allowed_ips = input.allowed_ips.as_deref();

        // Validate IP addresses/CIDRs
        if let Some(ips) = allowed_ips {
            if let Err(e) = crate::rate_limit::IpWhitelist::from_string(&ips.join(",")) {
                return Err({
                    tracing::error!("Invalid allowed IPs: {}", e);
                    async_graphql::Error::new("Invalid allowed IPs")
                });
            }
        }

        // Generate verification token if not provided
        let verification_token = input.verification_token.unwrap_or_else(|| {
            use rand::Rng;
            let random_bytes: [u8; 32] = rand::thread_rng().gen();
            hex::encode(random_bytes)
        });

        let listener_id = sqlx::query_scalar!(
            r#"
            INSERT INTO webhook_triggers (
                name, module_id, verification_token, signing_secret,
                max_requests_per_minute, enabled, allowed_ips, user_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id
            "#,
            input.name,
            input.module_id,
            verification_token,
            input.signing_secret,
            input.max_requests_per_minute.unwrap_or(100),
            enabled,
            allowed_ips,
            user_id
        )
        .fetch_one(db_pool)
        .await?;

        Ok(WebhookTrigger {
            id: listener_id,
            module_id: Some(input.module_id),
            name: input.name,
            webhook_url: format!("{}/webhooks/{}", base_url, listener_id),
            verification_token: Some(verification_token), // Return token on creation
            enabled,
            max_requests_per_minute: input.max_requests_per_minute.unwrap_or(100),
            trigger_count: 0,
            success_count: 0,
            error_count: 0,
            last_triggered_at: None,
        })
    }

    /// Create a secret
    async fn create_secret(&self, ctx: &Context<'_>, input: CreateSecretInput) -> Result<Secret> {
        let secrets_manager = ctx.data::<Arc<crate::secrets::SecretsManager>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        let secret_id = secrets_manager
            .create_secret(
                &input.name,
                &input.key_path,
                &input.value,
                input.description.as_deref(),
                Some(*user_id), // Set creator to current user
                input.allowed_modules.unwrap_or_default(),
            )
            .await?;

        let secret = secrets_manager.get_secret_metadata(&input.key_path).await?;

        Ok(Secret {
            id: secret_id,
            name: secret.name,
            key_path: secret.key_path,
            description: secret.description,
            created_at: secret.created_at.to_rfc3339(),
            last_accessed_at: secret.last_accessed_at.map(|dt| dt.to_rfc3339()),
            access_count: secret.access_count,
            expires_at: secret.expires_at.map(|dt| dt.to_rfc3339()),
        })
    }

    /// Update a secret (rotation) - requires ownership
    async fn update_secret(&self, ctx: &Context<'_>, input: UpdateSecretInput) -> Result<Secret> {
        let secrets_manager = ctx.data::<Arc<crate::secrets::SecretsManager>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // Verify ownership before update
        let secret = secrets_manager
            .get_secret_metadata(&input.key_path)
            .await
            .map_err(|_| async_graphql::Error::new("Secret not found"))?;

        if secret.owner_user_id != Some(*user_id) {
            return Err(async_graphql::Error::new(
                "Secret not found or permission denied",
            ));
        }

        secrets_manager
            .update_secret(&input.key_path, &input.value, Some(*user_id))
            .await?;

        let secret = secrets_manager.get_secret_metadata(&input.key_path).await?;

        Ok(Secret {
            id: secret.id,
            name: secret.name,
            key_path: secret.key_path,
            description: secret.description,
            created_at: secret.created_at.to_rfc3339(),
            last_accessed_at: secret.last_accessed_at.map(|dt| dt.to_rfc3339()),
            access_count: secret.access_count,
            expires_at: secret.expires_at.map(|dt| dt.to_rfc3339()),
        })
    }

    /// Delete a secret - requires ownership
    async fn delete_secret(&self, ctx: &Context<'_>, key_path: String) -> Result<bool> {
        let secrets_manager = ctx.data::<Arc<crate::secrets::SecretsManager>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        secrets_manager
            .delete_secret(&key_path, Some(*user_id))
            .await
            .map_err(|_| async_graphql::Error::new("Secret not found or permission denied"))?;
        Ok(true)
    }

    /// Create a new API key
    async fn create_api_key(
        &self,
        ctx: &Context<'_>,
        input: CreateApiKeyInput,
    ) -> Result<ApiKeyCreated> {
        let api_key_service = ctx.data::<Arc<crate::api_keys::ApiKeyService>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // Parse scopes
        let scopes: Vec<crate::api_keys::ApiKeyScope> = input
            .scopes
            .iter()
            .filter_map(|s| crate::api_keys::ApiKeyScope::from_string(s))
            .collect();

        if scopes.is_empty() {
            return Err(async_graphql::Error::new(
                "At least one valid scope is required",
            ));
        }

        // Create the key - returns (full_key, id, expires_at) directly
        // This avoids the N+1 query of fetching all keys to find the new one
        let (key, id, expires_at) = api_key_service
            .create_api_key(*user_id, &input.name, scopes.clone(), input.expires_in_days)
            .await
            .map_err(|e| {
                tracing::error!("Failed to create API key: {}", e);
                async_graphql::Error::new("Failed to create API key")
            })?;

        Ok(ApiKeyCreated {
            id,
            name: input.name,
            key, // Full key - only shown once!
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            expires_at: expires_at.map(|dt| dt.to_rfc3339()),
        })
    }

    /// Revoke an API key
    async fn revoke_api_key(&self, ctx: &Context<'_>, key_id: Uuid) -> Result<bool> {
        let api_key_service = ctx.data::<Arc<crate::api_keys::ApiKeyService>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        api_key_service
            .revoke_key(key_id, *user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to revoke API key: {}", e);
                async_graphql::Error::new("Failed to revoke API key")
            })?;

        Ok(true)
    }

    /// Delete an API key permanently
    async fn delete_api_key(&self, ctx: &Context<'_>, key_id: Uuid) -> Result<bool> {
        let api_key_service = ctx.data::<Arc<crate::api_keys::ApiKeyService>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        api_key_service
            .delete_key(key_id, *user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to delete API key: {}", e);
                async_graphql::Error::new("Failed to delete API key")
            })?;

        Ok(true)
    }

    /// Rotate an API key (creates new key, deactivates old one)
    async fn rotate_api_key(&self, ctx: &Context<'_>, key_id: Uuid) -> Result<ApiKeyCreated> {
        let api_key_service = ctx.data::<Arc<crate::api_keys::ApiKeyService>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // Get old key info first
        let old_key = api_key_service
            .get_key(key_id, *user_id)
            .await
            .map_err(|_| async_graphql::Error::new("API key not found"))?;

        // Rotate the key
        let new_key = api_key_service
            .rotate_key(key_id, *user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to rotate API key: {}", e);
                async_graphql::Error::new("Failed to rotate API key")
            })?;

        Ok(ApiKeyCreated {
            id: key_id,
            name: old_key.name.clone(),
            key: new_key, // Full key - only shown once!
            scopes: old_key.scopes.iter().map(|s| s.to_string()).collect(),
            expires_at: old_key.expires_at.map(|dt| dt.to_rfc3339()),
        })
    }

    /// Unlink OAuth account
    async fn unlink_oauth_account(&self, ctx: &Context<'_>, provider: String) -> Result<bool> {
        let oauth_service = ctx.data::<Arc<crate::oauth::OAuthService>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        let provider_enum = crate::oauth::OAuthProvider::from_str(&provider).map_err(|e| {
            tracing::error!("Invalid provider: {}", e);
            async_graphql::Error::new("Invalid provider")
        })?;

        oauth_service
            .unlink_oauth_account(*user_id, provider_enum)
            .await
            .map_err(|e| {
                tracing::error!("Failed to unlink OAuth account: {}", e);
                async_graphql::Error::new("Failed to unlink OAuth account")
            })?;

        Ok(true)
    }

    /// Create or update a workflow
    async fn create_workflow(
        &self,
        ctx: &Context<'_>,
        input: CreateWorkflowInput,
    ) -> Result<Workflow> {
        validate_payload_size("graph_json", &input.graph_json)?;
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // Insert or update workflow
        let workflow_id = sqlx::query_scalar!(
            r#"
            INSERT INTO workflows (name, module_uri, graph_json, user_id)
            VALUES ($1, '', $2, $3)
            RETURNING id
            "#,
            input.name,
            input.graph_json,
            user_id
        )
        .fetch_one(db_pool)
        .await?;

        Ok(Workflow {
            id: workflow_id,
            name: input.name,
            graph_json: input.graph_json,
        })
    }

    /// Update an existing workflow
    async fn update_workflow(
        &self,
        ctx: &Context<'_>,
        id: Uuid,
        input: CreateWorkflowInput,
    ) -> Result<Workflow> {
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // Update workflow (ensure ownership)
        let result = sqlx::query(
            r#"
            UPDATE workflows
            SET name = $1, graph_json = $2, updated_at = NOW()
            WHERE id = $3 AND user_id = $4
            "#,
        )
        .bind(&input.name)
        .bind(&input.graph_json)
        .bind(id)
        .bind(user_id)
        .execute(db_pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(async_graphql::Error::new(
                "Workflow not found or you don't have permission to update it",
            ));
        }

        Ok(Workflow {
            id,
            name: input.name,
            graph_json: input.graph_json,
        })
    }

    /// Delete a workflow
    async fn delete_workflow(&self, ctx: &Context<'_>, id: Uuid) -> Result<bool> {
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // Delete workflow (ensure ownership)
        let result = sqlx::query("DELETE FROM workflows WHERE id = $1 AND user_id = $2")
            .bind(id)
            .bind(user_id)
            .execute(db_pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(async_graphql::Error::new(
                "Workflow not found or you don't have permission to delete it",
            ));
        }

        Ok(true)
    }

    /// Generate or modify code using AI
    async fn generate_code(
        &self,
        ctx: &Context<'_>,
        input: GenerateCodeInput,
    ) -> Result<GenerateCodeResult> {
        let llm_client = ctx.data::<crate::llm::LlmClient>().map_err(|_| {
            async_graphql::Error::new("AI generation is not configured. Please set the ANTHROPIC_API_KEY environment variable on the server.")
        })?;

        let code = llm_client
            .generate_code(&input.prompt, &input.current_code, &input.capability_world)
            .await
            .map_err(|e: anyhow::Error| {
                tracing::error!("Internal error: {}", e);
                async_graphql::Error::new("An internal error occurred")
            })?;

        Ok(GenerateCodeResult { code })
    }
}

#[Subscription]
impl SubscriptionRoot {
    /// Real‑time updates for a specific execution ID.
    ///
    /// SECURITY: Authorization is enforced - users can only subscribe to their own executions.
    /// Events are replayed from the database before streaming new events, ensuring no events are lost.
    async fn execution_updates(
        &self,
        ctx: &Context<'_>,
        execution_id: Uuid,
    ) -> Result<impl Stream<Item = ExecutionEvent>> {
        // Get authenticated user
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        // SECURITY: Verify the execution belongs to this user
        #[derive(sqlx::FromRow)]
        struct ExecutionAuth {
            user_id: Uuid,
            status: String,
        }

        let execution: Option<ExecutionAuth> = sqlx::query_as(
            r#"
            SELECT user_id, status
            FROM workflow_executions
            WHERE id = $1
            "#,
        )
        .bind(execution_id)
        .fetch_optional(db_pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error: {}", e);
            async_graphql::Error::new("Database error")
        })?;

        match execution {
            None => {
                return Err(async_graphql::Error::new("Execution not found"));
            }
            Some(exec) if exec.user_id != *user_id => {
                // SECURITY: Return generic error to avoid leaking execution IDs
                return Err(async_graphql::Error::new("Execution not found"));
            }
            Some(_) => {
                // Authorization passed, continue
            }
        }

        // Fetch historical events from database for replay
        #[derive(sqlx::FromRow)]
        struct EventRow {
            event_type: String,
            node_id: Option<Uuid>,
            status: String,
            log_message: Option<String>,
        }

        let historical_events: Vec<EventRow> = sqlx::query_as(
            r#"
            SELECT
                event_type,
                node_id,
                status,
                log_message
            FROM execution_events
            WHERE execution_id = $1
            ORDER BY created_at ASC
            "#,
        )
        .bind(execution_id)
        .fetch_all(db_pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch events: {}", e);
            async_graphql::Error::new("Failed to fetch events")
        })?;

        // Convert database rows to ExecutionEvent structs
        let historical: Vec<ExecutionEvent> = historical_events
            .into_iter()
            .map(|row| {
                let status = match row.status.as_str() {
                    "Running" => ExecutionStatus::Running,
                    "Completed" => ExecutionStatus::Completed,
                    "Failed" => ExecutionStatus::Failed,
                    _ => ExecutionStatus::Running, // Default fallback
                };

                ExecutionEvent {
                    execution_id,
                    node_id: row.node_id,
                    status,
                    trace_id: None,
                    span_id: None,
                    log_message: row.log_message,
                }
            })
            .collect();

        // Subscribe to broadcast for new events
        let sender = ctx.data_unchecked::<tokio::sync::broadcast::Sender<ExecutionEvent>>();
        let mut rx = sender.subscribe();

        Ok(async_stream::stream! {
            // First, replay all historical events
            for event in historical {
                info!("replaying historical event: {:?}", event);
                yield event;
            }

            // Then stream new events as they arrive
            while let Ok(event) = rx.recv().await {
                if event.execution_id == execution_id {
                    info!("streaming live event: {:?}", event);
                    yield event;
                }
            }
        })
    }
}

#[ComplexObject]
impl WasmModule {
    async fn capability_description(&self) -> Option<String> {
        self.capability_world.as_ref().map(|w| {
            let world = match w.as_str() {
                "minimal" | "minimal-node" => worker::CapabilityWorld::Minimal,
                "http" | "http-node" => worker::CapabilityWorld::Http,
                "network" | "network-node" => worker::CapabilityWorld::Network,
                "secrets" | "secrets-node" => worker::CapabilityWorld::Secrets,
                "filesystem" | "filesystem-node" => worker::CapabilityWorld::Filesystem,
                "messaging" | "messaging-node" => worker::CapabilityWorld::Messaging,
                "cache" | "cache-node" => worker::CapabilityWorld::Cache,
                "database" | "database-node" => worker::CapabilityWorld::Database,
                "automation" | "automation-node" | "trusted" => worker::CapabilityWorld::Trusted,
                _ => worker::CapabilityWorld::Unknown,
            };
            crate::wit_inspector::capability_world_description(&world).to_string()
        })
    }
}
use crate::module_executions;

#[derive(SimpleObject, Clone)]
pub struct WorkflowExecution {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub status: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub error_message: Option<String>,
    pub created_at: String,
    pub duration_ms: Option<i32>,
    pub output_data: Option<serde_json::Value>,
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
