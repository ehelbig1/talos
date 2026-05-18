//! DataLoaders for efficient N+1 query resolution in GraphQL.
//!
//! DataLoaders provide batching and caching for database queries,
//! preventing N+1 query problems when resolving nested GraphQL fields.

use async_graphql::dataloader::{DataLoader, Loader};
use async_graphql::Result;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::schema::types::*;

/// Batch loader for WasmModules by ID.
///
/// Used by WebhookTrigger.module and other nested module resolutions
/// to batch multiple module lookups into a single query.
pub struct ModuleLoader {
    db_pool: sqlx::PgPool,
}

impl ModuleLoader {
    pub fn new(db_pool: sqlx::PgPool) -> Self {
        Self { db_pool }
    }
}

impl Loader<Uuid> for ModuleLoader {
    type Value = WasmModule;
    type Error = Arc<sqlx::Error>;

    async fn load(&self, keys: &[Uuid]) -> Result<HashMap<Uuid, Self::Value>, Self::Error> {
        if keys.is_empty() {
            return Ok(HashMap::new());
        }

        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            name: String,
            size_bytes: i32,
            content_hash: String,
            compiled_at: chrono::DateTime<chrono::Utc>,
            config: Option<serde_json::Value>,
            capability_world: Option<String>,
            imported_interfaces: Option<Vec<String>>,
            source_code: Option<String>,
            language: Option<String>,
        }

        // Phase 5.1: unified `modules` table. `compiled_at` / `size_bytes`
        // / `content_hash` are nullable on catalog-only rows; COALESCE
        // to keep the non-null `Row` shape the loader already expects.
        let rows: Vec<Row> = sqlx::query_as(
            r#"
                SELECT
                    id, name,
                    COALESCE(size_bytes, 0) AS size_bytes,
                    COALESCE(content_hash, '') AS content_hash,
                    COALESCE(compiled_at, created_at) AS compiled_at,
                    config, capability_world, imported_interfaces, source_code, language
                FROM modules
                WHERE id = ANY($1)
                "#,
        )
        .bind(keys)
        .fetch_all(&self.db_pool)
        .await
        .map_err(Arc::new)?;

        let mut map = HashMap::with_capacity(rows.len());
        for row in rows {
            let module = WasmModule {
                id: row.id,
                name: row.name,
                size_bytes: row.size_bytes,
                content_hash: row.content_hash,
                compiled_at: row.compiled_at.to_rfc3339(),
                config: row
                    .config
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "{}".to_string()),
                capability_world: row.capability_world,
                imported_interfaces: row.imported_interfaces,
                source_code: row.source_code,
                language: row.language,
            };
            map.insert(row.id, module);
        }

        Ok(map)
    }
}

/// Batch loader for Workflows by ID.
///
/// Used when resolving workflow references in execution results
/// to batch multiple workflow lookups into a single query.
pub struct WorkflowLoader {
    db_pool: sqlx::PgPool,
}

impl WorkflowLoader {
    pub fn new(db_pool: sqlx::PgPool) -> Self {
        Self { db_pool }
    }
}

impl Loader<Uuid> for WorkflowLoader {
    type Value = Workflow;
    type Error = Arc<sqlx::Error>;

    async fn load(&self, keys: &[Uuid]) -> Result<HashMap<Uuid, Self::Value>, Self::Error> {
        if keys.is_empty() {
            return Ok(HashMap::new());
        }

        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            name: String,
            graph_json: String,
            max_concurrent_executions: Option<i32>,
            intent: Option<serde_json::Value>,
            actor_id: Option<Uuid>,
        }

        let rows: Vec<Row> = sqlx::query_as(
            r#"
                SELECT id, name, graph_json, max_concurrent_executions, intent, actor_id
                FROM workflows
                WHERE id = ANY($1)
                "#,
        )
        .bind(keys)
        .fetch_all(&self.db_pool)
        .await
        .map_err(Arc::new)?;

        let mut map = HashMap::with_capacity(rows.len());
        for row in rows {
            let workflow = Workflow {
                id: row.id,
                name: row.name,
                graph_json: row.graph_json,
                max_concurrent_executions: row.max_concurrent_executions,
                intent: row.intent,
                actor_id: row.actor_id,
            };
            map.insert(row.id, workflow);
        }

        Ok(map)
    }
}

/// Batch loader for NodeTemplates by ID.
///
/// Used when resolving template references in module queries
/// to batch multiple template lookups into a single query.
pub struct TemplateLoader {
    db_pool: sqlx::PgPool,
}

impl TemplateLoader {
    pub fn new(db_pool: sqlx::PgPool) -> Self {
        Self { db_pool }
    }
}

impl Loader<Uuid> for TemplateLoader {
    type Value = NodeTemplate;
    type Error = Arc<sqlx::Error>;

    async fn load(&self, keys: &[Uuid]) -> Result<HashMap<Uuid, Self::Value>, Self::Error> {
        if keys.is_empty() {
            return Ok(HashMap::new());
        }

        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            name: String,
            category: String,
            description: Option<String>,
            config_schema: serde_json::Value,
            icon: Option<String>,
            allowed_hosts: Option<Vec<String>>,
        }

        // Phase 5.1: unified `modules` table. `category` is nullable on
        // modules (free-form catalog label), so COALESCE to keep the
        // non-null Row.category contract. `icon` was not carried over
        // during the schema consolidation — always NULL for now.
        let rows: Vec<Row> = sqlx::query_as(
            r#"
                SELECT
                    id, name,
                    COALESCE(category, '') AS category,
                    description, config_schema,
                    NULL::TEXT AS icon,
                    allowed_hosts
                FROM modules
                WHERE id = ANY($1)
                "#,
        )
        .bind(keys)
        .fetch_all(&self.db_pool)
        .await
        .map_err(Arc::new)?;

        let mut map = HashMap::with_capacity(rows.len());
        for row in rows {
            let template = NodeTemplate {
                id: row.id,
                name: row.name,
                category: row.category,
                description: row.description,
                config_schema: row.config_schema.to_string(),
                icon: row.icon,
                allowed_hosts: row.allowed_hosts.unwrap_or_default(),
            };
            map.insert(row.id, template);
        }

        Ok(map)
    }
}

/// Creates a DataLoader for Modules with caching enabled.
pub fn create_module_loader(db_pool: sqlx::PgPool) -> DataLoader<ModuleLoader> {
    DataLoader::new(ModuleLoader::new(db_pool), tokio::spawn)
}

/// Creates a DataLoader for Workflows with caching enabled.
pub fn create_workflow_loader(db_pool: sqlx::PgPool) -> DataLoader<WorkflowLoader> {
    DataLoader::new(WorkflowLoader::new(db_pool), tokio::spawn)
}

/// Creates a DataLoader for Templates with caching enabled.
pub fn create_template_loader(db_pool: sqlx::PgPool) -> DataLoader<TemplateLoader> {
    DataLoader::new(TemplateLoader::new(db_pool), tokio::spawn)
}
