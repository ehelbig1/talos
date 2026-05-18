pub mod api;
pub mod sync;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::{Pool, Postgres};
use uuid::Uuid;
use worker::CapabilityWorld;

pub struct ModuleRegistry {
    pub(crate) db_pool: Pool<Postgres>,
    pub(crate) redis_client: Option<std::sync::Arc<redis::Client>>,
}

#[allow(dead_code)]

pub struct ModuleExecutionInfo {
    pub module_uri: String,
    pub config: Option<JsonValue>,
    pub allowed_hosts: Vec<String>,
    pub allowed_methods: Vec<String>,
}

impl ModuleRegistry {
    pub fn new(
        db_pool: Pool<Postgres>,
        redis_client: Option<std::sync::Arc<redis::Client>>,
    ) -> Self {
        Self {
            db_pool,
            redis_client,
        }
    }

    /// List all templates, optionally filtered by category
    pub async fn list_templates(&self, category: Option<&str>) -> Result<Vec<NodeTemplate>> {
        let templates = if let Some(cat) = category {
            sqlx::query_as::<_, NodeTemplateRow>(
                "SELECT id, name, category, description, config_schema, code_template, precompiled_wasm, icon, oci_url FROM node_templates WHERE category = $1"
            )
            .bind(cat)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query_as::<_, NodeTemplateRow>(
                "SELECT id, name, category, description, config_schema, code_template, precompiled_wasm, icon, oci_url FROM node_templates"
            )
            .fetch_all(&self.db_pool)
            .await?
        };

        Ok(templates.into_iter().map(|row| row.into()).collect())
    }

    /// List templates with pagination, optionally filtered by category
    pub async fn list_templates_paginated(
        &self,
        category: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<NodeTemplate>> {
        let templates = if let Some(cat) = category {
            sqlx::query_as::<_, NodeTemplateRow>(
                "SELECT id, name, category, description, config_schema, code_template, precompiled_wasm, icon, oci_url FROM node_templates WHERE category = $1 ORDER BY name ASC LIMIT $2 OFFSET $3"
            )
            .bind(cat)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query_as::<_, NodeTemplateRow>(
                "SELECT id, name, category, description, config_schema, code_template, precompiled_wasm, icon, oci_url FROM node_templates ORDER BY name ASC LIMIT $1 OFFSET $2"
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db_pool)
            .await?
        };

        Ok(templates.into_iter().map(|row| row.into()).collect())
    }

    /// Get single template by ID
    pub async fn get_template(&self, id: Uuid) -> Result<NodeTemplate> {
        let row = sqlx::query_as::<_, NodeTemplateRow>(
            "SELECT id, name, category, description, config_schema, code_template, precompiled_wasm, icon, oci_url FROM node_templates WHERE id = $1"
        )
        .bind(id)
        .fetch_one(&self.db_pool)
        .await
        .context("Template not found")?;

        Ok(row.into())
    }

    /// Store compiled WASM module
    pub async fn store_module(&self, module: WasmModule) -> Result<Uuid> {
        // Check if content_hash exists (deduplication)
        if let Ok(existing) =
            sqlx::query_scalar::<_, Uuid>("SELECT id FROM wasm_modules WHERE content_hash = $1")
                .bind(&module.content_hash)
                .fetch_one(&self.db_pool)
                .await
        {
            return Ok(existing);
        }

        // Insert new module with capability metadata
        let capability_world_str = module.capability_world.to_string();
        let id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO wasm_modules
            (name, content_hash, wasm_bytes, source_code, template_id, config, size_bytes, max_fuel, max_memory_mb, allowed_hosts, allowed_methods, user_id, capability_world, imported_interfaces, dependencies, oci_url)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
            RETURNING id"
        )
        .bind(&module.name)
        .bind(&module.content_hash)
        .bind(&module.wasm_bytes)
        .bind(&module.source_code)
        .bind(&module.template_id)
        .bind(&module.config)
        .bind(module.size_bytes)
        .bind(module.max_fuel)
        .bind(module.max_memory_mb)
        .bind(&module.allowed_hosts)
        .bind(&module.allowed_methods)
        .bind(&module.user_id)
        .bind(&capability_world_str)
        .bind(&module.imported_interfaces)
        .bind(&module.dependencies)
        .bind(&module.oci_url)
        .fetch_one(&self.db_pool)
        .await
        .context("Failed to insert module")?;

        // Cache in Redis for fast access
        if true {
            if let Some(ref client) = self.redis_client {
                let key = format!("wasm:{}", id);
                match client.get_multiplexed_async_connection().await {
                    Ok(mut conn) => {
                        let _ = redis::cmd("SETEX")
                            .arg(&key)
                            .arg(86400)
                            .arg(&module.wasm_bytes)
                            .query_async::<()>(&mut conn)
                            .await;
                    }
                    Err(e) => {
                        tracing::warn!("Redis connection error during SET in store_module: {}", e)
                    }
                }
            }
        }

        Ok(id)
    }

    pub async fn update_module(&self, id: Uuid, module: WasmModule) -> Result<Uuid> {
        let capability_world_str = module.capability_world.to_string();
        let result = sqlx::query(
            "UPDATE wasm_modules
            SET name = $1, content_hash = $2, wasm_bytes = $3, source_code = $4, config = $5, size_bytes = $6, capability_world = $7, imported_interfaces = $8, dependencies = $9, oci_url = $10, compiled_at = NOW()
            WHERE id = $11 AND user_id = $12"
        )
        .bind(&module.name)
        .bind(&module.content_hash)
        .bind(&module.wasm_bytes)
        .bind(&module.source_code)
        .bind(&module.config)
        .bind(module.size_bytes)
        .bind(&capability_world_str)
        .bind(&module.imported_interfaces)
        .bind(&module.dependencies)
        .bind(&module.oci_url)
        .bind(id)
        .bind(module.user_id)
        .execute(&self.db_pool)
        .await
        .context("Failed to update module")?;

        if result.rows_affected() == 0 {
            anyhow::bail!("Module not found or access denied");
        }

        // Cache updated WASM in Redis
        if true {
            if let Some(ref client) = self.redis_client {
                let key = format!("wasm:{}", id);
                match client.get_multiplexed_async_connection().await {
                    Ok(mut conn) => {
                        let _ = redis::cmd("SETEX")
                            .arg(&key)
                            .arg(86400)
                            .arg(&module.wasm_bytes)
                            .query_async::<()>(&mut conn)
                            .await;
                    }
                    Err(e) => {
                        tracing::warn!("Redis connection error during SET in update_module: {}", e)
                    }
                }
            }
        }

        Ok(id)
    }

    pub async fn get_module(&self, module_id: Uuid, user_id: Uuid) -> Result<WasmModule> {
        use sqlx::Row;
        let row = sqlx::query(
            r#"
            SELECT name, content_hash, wasm_bytes, source_code, template_id, config, size_bytes, 
                   max_fuel, max_memory_mb, allowed_hosts, allowed_methods, user_id, 
                   capability_world, imported_interfaces, dependencies, oci_url 
            FROM wasm_modules 
            WHERE id = $1 AND user_id = $2
            "#,
        )
        .bind(module_id)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await
        .context("Module not found or access denied")?;

        let cap_str: String = row.try_get("capability_world")?;
        let capability_world = match cap_str.as_str() {
            "minimal" => CapabilityWorld::Minimal,
            "network" => CapabilityWorld::Network,
            "secrets" => CapabilityWorld::Secrets,
            "filesystem" => CapabilityWorld::Filesystem,
            "messaging" => CapabilityWorld::Messaging,
            "cache" => CapabilityWorld::Cache,
            "database" => CapabilityWorld::Database,
            "trusted" => CapabilityWorld::Trusted,
            "governance" => CapabilityWorld::Governance,
            _ => CapabilityWorld::Unknown,
        };

        Ok(WasmModule {
            name: row.try_get("name")?,
            content_hash: row.try_get("content_hash")?,
            wasm_bytes: row.try_get("wasm_bytes")?,
            source_code: row.try_get("source_code")?,
            template_id: row.try_get("template_id")?,
            config: row.try_get("config")?,
            size_bytes: row.try_get("size_bytes")?,
            max_fuel: row.try_get("max_fuel")?,
            max_memory_mb: row.try_get("max_memory_mb")?,
            allowed_hosts: row.try_get("allowed_hosts")?,
            allowed_methods: row.try_get("allowed_methods")?,
            user_id: row.try_get("user_id")?,
            capability_world,
            imported_interfaces: row.try_get("imported_interfaces")?,
            dependencies: row.try_get("dependencies")?,
            oci_url: row.try_get("oci_url")?,
        })
    }

    pub async fn get_module_bytes(&self, module_id: Uuid, user_id: Uuid) -> Result<Vec<u8>> {
        // 1. Try to fetch from Redis cache
        if let Some(ref client) = self.redis_client {
            let key = format!("wasm:{}", module_id);
            match client.get_multiplexed_async_connection().await {
                Ok(mut conn) => {
                    match redis::cmd("GET")
                        .arg(&key)
                        .query_async::<Option<Vec<u8>>>(&mut conn)
                        .await
                    {
                        Ok(Some(bytes)) if !bytes.is_empty() => {
                            tracing::debug!("Cache hit for module {}/{}", user_id, module_id);
                            return Ok(bytes);
                        }
                        Ok(_) => tracing::debug!("Cache miss for module {}/{}", user_id, module_id),
                        Err(e) => tracing::warn!("Redis GET error for module {}: {}", module_id, e),
                    }
                }
                Err(e) => tracing::warn!("Redis connection error: {}", e),
            }
        }

        // 2. Fetch from Postgres
        let bytes = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT wasm_bytes FROM wasm_modules WHERE id = $1 AND user_id = $2",
        )
        .bind(module_id)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await
        .context("Module not found or access denied")?;

        // 3. Populate Redis cache
        if let Some(ref client) = self.redis_client {
            let key = format!("wasm:{}", module_id);
            match client.get_multiplexed_async_connection().await {
                Ok(mut conn) => {
                    // Set with 24-hour expiration
                    let _ = redis::cmd("SETEX")
                        .arg(&key)
                        .arg(86400)
                        .arg(&bytes)
                        .query_async::<()>(&mut conn)
                        .await;
                }
                Err(e) => tracing::warn!("Redis connection error during SET: {}", e),
            }
        }

        Ok(bytes)
    }

    /// Prepares a module for execution and returns the necessary information.
    /// If the module is not an OCI image, it ensures the module is loaded into the Redis cache.
    pub async fn get_execution_info(
        &self,
        module_id: Uuid,
        user_id: Uuid,
    ) -> Result<ModuleExecutionInfo> {
        let module = self.get_module(module_id, user_id).await?;

        let module_uri = if let Some(ref url) = module.oci_url {
            url.clone()
        } else {
            if !module.wasm_bytes.is_empty() {
                if let Err(e) = self.ensure_module_in_cache(module_id, user_id).await {
                    tracing::warn!(
                        "Failed to cache module {} before execution: {}",
                        module_id,
                        e
                    );
                }
            }
            format!("redis:wasm:{}", module_id)
        };

        Ok(ModuleExecutionInfo {
            module_uri,
            config: module.config,
            // Fallback to ensuring googleapis.com and api.github.com are always allowed for backwards compat
            allowed_hosts: if module.allowed_hosts.is_empty() {
                vec![
                    "www.googleapis.com".to_string(),
                    "oauth2.googleapis.com".to_string(),
                    "api.github.com".to_string(),
                ]
            } else {
                module.allowed_hosts
            },
            allowed_methods: module.allowed_methods,
        })
    }

    /// Track module usage

    /// Ensures the module is loaded into the Redis cache without downloading it into memory if it already exists.
    pub async fn ensure_module_in_cache(&self, module_id: Uuid, user_id: Uuid) -> Result<()> {
        if let Some(ref client) = self.redis_client {
            let key = format!("wasm:{}", module_id);
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                let exists: bool = redis::cmd("EXISTS")
                    .arg(&key)
                    .query_async(&mut conn)
                    .await
                    .unwrap_or(false);
                if exists {
                    return Ok(());
                }
            }
        }

        // If we reach here, it's missing from Redis. Fetch from Postgres to trigger the caching logic.
        self.get_module_bytes(module_id, user_id).await?;
        Ok(())
    }

    pub async fn increment_usage(&self, module_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE wasm_modules SET usage_count = usage_count + 1, last_used = NOW() WHERE id = $1"
        )
        .bind(module_id)
        .execute(&self.db_pool)
        .await?;

        Ok(())
    }

    /// Get module configuration (enforces ownership via user_id)
    pub async fn get_module_config(
        &self,
        module_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<JsonValue>> {
        let config = sqlx::query_scalar::<_, Option<JsonValue>>(
            "SELECT config FROM wasm_modules WHERE id = $1 AND user_id = $2",
        )
        .bind(module_id)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await
        .context("Module not found or access denied")?;

        Ok(config)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeTemplate {
    pub id: Uuid,
    pub name: String,
    pub category: String,
    pub description: Option<String>,
    pub config_schema: JsonValue,
    pub code_template: String,
    pub precompiled_wasm: Option<Vec<u8>>,
    pub icon: Option<String>,
    pub oci_url: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct NodeTemplateRow {
    id: Uuid,
    name: String,
    category: String,
    description: Option<String>,
    config_schema: JsonValue,
    code_template: String,
    precompiled_wasm: Option<Vec<u8>>,
    icon: Option<String>,
    oci_url: Option<String>,
}

impl From<NodeTemplateRow> for NodeTemplate {
    fn from(row: NodeTemplateRow) -> Self {
        NodeTemplate {
            id: row.id,
            name: row.name,
            category: row.category,
            description: row.description,
            config_schema: row.config_schema,
            code_template: row.code_template,
            precompiled_wasm: row.precompiled_wasm,
            icon: row.icon,
            oci_url: row.oci_url,
        }
    }
}

impl ModuleRegistry {
    /// Clean up old unused WASM modules (default: 30 days)
    pub async fn cleanup_old_modules(&self, retention_days: i64) -> anyhow::Result<u64> {
        let result =
            sqlx::query("DELETE FROM wasm_modules WHERE last_used < NOW() - INTERVAL '1 day' * $1")
                .bind(retention_days)
                .execute(&self.db_pool)
                .await?;

        Ok(result.rows_affected())
    }

    /// Enforce cache size limit by removing least recently used modules
    pub async fn enforce_cache_limits(
        &self,
        max_modules: i64,
        max_size_mb: i64,
    ) -> anyhow::Result<(u64, u64)> {
        let max_size_bytes = max_size_mb * 1_048_576; // Convert MB to bytes

        // Get current cache stats
        let stats = sqlx::query_as::<_, (i64, i64)>(
            "SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM wasm_modules",
        )
        .fetch_one(&self.db_pool)
        .await?;

        let (current_count, current_size) = stats;
        let mut modules_deleted = 0u64;
        let mut bytes_freed = 0u64;

        // Evict by count if over limit
        if current_count > max_modules {
            let to_delete = current_count - max_modules;
            let result = sqlx::query(
                r#"
                DELETE FROM wasm_modules
                WHERE id IN (
                    SELECT id FROM wasm_modules
                    ORDER BY last_used ASC NULLS FIRST
                    LIMIT $1
                )
                "#,
            )
            .bind(to_delete)
            .execute(&self.db_pool)
            .await?;

            modules_deleted += result.rows_affected();
        }

        // Evict by size if over limit
        if current_size > max_size_bytes {
            // Keep deleting oldest modules until under size limit
            let result = sqlx::query(
                r#"
                WITH to_delete AS (
                    SELECT id, size_bytes,
                           SUM(size_bytes) OVER (ORDER BY last_used ASC NULLS FIRST) as running_total
                    FROM wasm_modules
                )
                DELETE FROM wasm_modules
                WHERE id IN (
                    SELECT id FROM to_delete
                    WHERE running_total <= $1
                )
                "#
            )
            .bind(current_size - max_size_bytes)
            .execute(&self.db_pool)
            .await?;

            bytes_freed = result.rows_affected();
        }

        Ok((modules_deleted, bytes_freed))
    }

    /// Get cache statistics
    pub async fn get_cache_stats(&self) -> anyhow::Result<CacheStats> {
        let stats = sqlx::query_as::<_, (i64, i64, i64)>(
            r#"
            SELECT
                COUNT(*) as module_count,
                COALESCE(SUM(size_bytes), 0) as total_size_bytes,
                COALESCE(SUM(usage_count), 0) as total_usage_count
            FROM wasm_modules
            "#,
        )
        .fetch_one(&self.db_pool)
        .await?;

        Ok(CacheStats {
            module_count: stats.0,
            total_size_bytes: stats.1,
            total_size_mb: (stats.1 as f64 / 1_048_576.0),
            total_usage_count: stats.2,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub module_count: i64,
    pub total_size_bytes: i64,
    pub total_size_mb: f64,
    pub total_usage_count: i64,
}

#[derive(Debug, Clone)]
pub struct WasmModule {
    pub name: String,
    pub content_hash: String,
    pub wasm_bytes: Vec<u8>,
    pub source_code: Option<String>,
    pub template_id: Option<Uuid>,
    pub config: Option<JsonValue>,
    pub size_bytes: i32,
    pub max_fuel: i64,
    pub max_memory_mb: i32,
    pub allowed_hosts: Vec<String>,
    /// HTTP method allowlist. Empty = allow all methods. Non-empty = only those methods.
    pub allowed_methods: Vec<String>,
    pub user_id: Option<Uuid>,
    /// WIT capability world detected at compile time.
    pub capability_world: CapabilityWorld,
    /// WIT interface names imported by the component (e.g. ["talos:core/http"]).
    pub imported_interfaces: Vec<String>,
    pub dependencies: Option<JsonValue>,
    pub oci_url: Option<String>,
}

impl ModuleRegistry {
    /// Store an AOT‑precompiled WASM blob for a node template.
    /// Persists the blob into the `precompiled_wasm` column.
    pub async fn store_precompiled_template(
        &self,
        template_id: uuid::Uuid,
        precompiled: Vec<u8>,
    ) -> anyhow::Result<()> {
        sqlx::query("UPDATE node_templates SET precompiled_wasm = $1 WHERE id = $2")
            .bind(precompiled)
            .bind(template_id)
            .execute(&self.db_pool)
            .await
            .context("Failed to store precompiled AOT blob for template")?;
        Ok(())
    }
}
