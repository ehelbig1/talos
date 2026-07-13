/// ModuleRepository — centralises SQL for module reference checks and metadata.
///
/// Follows the ActorRepository pattern: plain struct, `new(db_pool)`,
/// all methods `pub async fn`, return `anyhow::Result<T>`. Handlers in
/// `mcp/modules.rs` should call these rather than inlining SQL.
use anyhow::Result;
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub struct ModuleRepository {
    db_pool: PgPool,
    /// Optional SecretsManager for transparent decryption of
    /// `module_executions.{input,output,trigger_metadata}_enc` on read.
    /// Wired by `with_encryption(secrets)`. None in tests + legacy
    /// construction sites.
    secrets_manager: Option<std::sync::Arc<talos_secrets_manager::SecretsManager>>,
}

/// Module reference counts for pre-delete validation.
#[derive(Debug)]
pub struct ModuleRefCounts {
    pub workflow_count: i64,
    pub webhook_count: i64,
    pub webhook_ids_sample: Vec<String>,
}

/// Result of `install_catalog_module_to_modules`. Returned with enough
/// signal for callers to verify that the WASM bytes they expected to
/// install actually landed:
/// - `content_hash` — hex SHA-256 of the post-install WASM bytes.
/// - `compiled_at` — NOW() at the moment the upsert ran.
/// - `bytes_changed` — true if the prior row was absent OR had a different
///   content_hash. Lets the caller distinguish "real recompile" from
///   "idempotent no-op upsert" without a second DB round-trip.
#[derive(Debug, Clone)]
pub struct CatalogInstallResult {
    pub module_id: Uuid,
    pub allowed_secrets: Vec<String>,
    pub content_hash: String,
    pub compiled_at: chrono::DateTime<chrono::Utc>,
    pub bytes_changed: bool,
}

/// Module metadata returned by `get_module_metadata`.
#[derive(Debug)]
pub struct ModuleMetadata {
    pub id: Uuid,
    pub name: String,
    pub capability_world: Option<String>,
    pub max_fuel: Option<i64>,
    pub user_id: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Operator-facing snapshot of module entity unification state.
/// Returned by `module_unification_snapshot` for the
/// `get_module_unification_status` MCP tool. Counts come from live
/// COUNT(*) queries — accurate at request time, no caching.
#[derive(Debug)]
pub struct ModuleUnificationSnapshot {
    pub total: i64,
    pub by_kind: std::collections::HashMap<String, i64>,
    pub wasm_modules: i64,
    pub node_templates: i64,
    /// wasm_modules rows without a `modules` sibling (drift).
    pub wasm_unmirrored: i64,
    /// node_templates rows that have neither a wasm_modules sibling
    /// nor a `modules` mirror by legacy_template_id (drift).
    pub template_unmirrored: i64,
    /// Phase 1.4 backfill: rows where `dependencies` is populated.
    pub phase14_dependencies_set: i64,
    /// Phase 1.4 backfill: rows where `imported_interfaces` is non-empty.
    pub phase14_imports_set: i64,
}

/// Specification for a single dual-write into the `modules` table
/// (Phase 1.2 of module-entity-consolidation). Construct inline at the
/// call site so each write path can supply its own `kind`, allowlists,
/// fuel/memory budget, and integration metadata. Field order intentionally
/// matches the SQL bind order in `mirror_module_write` for grep-ability.
pub struct ModuleMirrorWrite<'a> {
    pub wasm_module_id: Uuid,
    pub template_id: Uuid,
    pub user_id: Option<Uuid>,
    pub name: &'a str,
    pub kind: &'a str,
    pub capability_world_short: &'a str,
    pub wasm_bytes: &'a [u8],
    pub content_hash: &'a str,
    pub rust_code: &'a str,
    pub max_fuel: i64,
    pub max_memory_mb: i32,
    pub allowed_hosts: &'a [String],
    pub allowed_methods: &'a [String],
    pub allowed_secrets: &'a [String],
    pub imported_interfaces: &'a [String],
    pub dependencies: Option<&'a serde_json::Value>,
    pub config: Option<&'a serde_json::Value>,
    pub integration_name: Option<&'a str>,
    /// Source language of the module ("rust" | "javascript" | "python" | …).
    /// Persisted to `modules.language`, which routes hot-update recompiles
    /// to the right toolchain (jco / componentize-py / cargo). Pre-fix this
    /// was a hardcoded `'rust'` literal in the SQL, so every JS/Python
    /// sandbox compile was stored as rust (functional-sweep finding,
    /// 2026-07-07).
    pub language: &'a str,
}

/// Module info for listing.
#[derive(Debug)]
pub struct ModuleListItem {
    pub id: Uuid,
    pub name: String,
    pub capability_world: Option<String>,
    pub max_fuel: Option<i64>,
    pub usage_count: Option<i64>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Full module detail row for the GraphQL `wasm_modules` / `my_modules`
/// resolvers. Nullable storage columns are COALESCEd in the query so the
/// non-null fields deserialize for catalog-only rows (Phase 5 unified
/// `modules` table).
#[derive(Debug, sqlx::FromRow)]
pub struct ModuleDetailsRow {
    pub id: Uuid,
    pub name: String,
    pub size_bytes: i32,
    pub content_hash: String,
    pub compiled_at: chrono::DateTime<chrono::Utc>,
    pub config: Option<serde_json::Value>,
    /// The module's declared config contract (talos.json `config_schema`).
    /// Exposed so the editor can identify a module by its CONTRACT (stable
    /// under rename) instead of its mutable display name.
    pub config_schema: Option<serde_json::Value>,
    /// Origin template slug for catalog modules (stable under display-name
    /// renames); NULL for sandbox/extracted modules.
    pub catalog_slug: Option<String>,
    pub source_code: Option<String>,
    pub capability_world: Option<String>,
    pub imported_interfaces: Option<Vec<String>>,
    pub language: Option<String>,
}

/// Discriminator for `get_module_capability_world` — wasm_modules vs node_templates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleSource {
    Compiled,
    Template,
}

/// Row from the `user_modules` view (union of wasm_modules + node_templates).
#[derive(Debug)]
pub struct UserModuleViewRow {
    pub id: Uuid,
    pub name: String,
    pub capability_world: String,
    pub source: String,
    pub template_id: Option<Uuid>,
}

/// Compiled module info returned by `get_wasm_module_info`.
#[derive(Debug)]
pub struct WasmModuleInfo {
    pub wm_id: Uuid,
    pub name: String,
    pub capability_world: String,
    pub compiled_at: Option<chrono::DateTime<chrono::Utc>>,
    pub template_id: Option<Uuid>,
    pub allowed_hosts: Vec<String>,
    pub allowed_secrets: Vec<String>,
    pub size_bytes: i64,
    pub has_source_code: bool,
    pub rate_limit_per_minute: Option<i32>,
}

/// Sandbox-template info returned by `get_node_template_info`.
#[derive(Debug)]
pub struct NodeTemplateInfo {
    pub name: String,
    pub category: String,
    pub capability_world: Option<String>,
    pub size_bytes: i64,
    pub has_source_code: bool,
    pub allowed_hosts: Vec<String>,
    pub allowed_secrets: Vec<String>,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Workflow reference returned by the dependency-scan helpers.
#[derive(Debug)]
pub struct WorkflowRef {
    pub id: Uuid,
    pub name: String,
}

/// Unreferenced module row returned by `find_unreferenced_modules`.
#[derive(Debug)]
pub struct UnreferencedModule {
    pub id: Uuid,
    pub name: String,
    pub compiled_at: chrono::DateTime<chrono::Utc>,
}

/// Module update history row.
#[derive(Debug)]
pub struct ModuleHistoryRow {
    pub id: Uuid,
    pub previous_hash: Option<String>,
    pub new_hash: String,
    pub size_bytes: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Module shared with an organization.
#[derive(Debug)]
pub struct OrgModuleRow {
    pub id: Uuid,
    pub name: String,
    pub capability_world: String,
}

/// One pinned-module row from `list_user_pinned_modules`.
#[derive(Debug)]
pub struct PinnedModuleStatus {
    pub module_name: String,
    pub has_wasm: bool,
}

/// Row returned by find_module_alternatives queries — covers both the
/// "target lookup" projection and the trigram/category/ilike result projection
/// (the latter add `score` and `same_category` as optional fields).
#[derive(Debug)]
pub struct TemplateAlternativeRow {
    pub id: Uuid,
    pub name: String,
    pub category: String,
    pub description: Option<String>,
    pub allowed_secrets: Vec<String>,
    pub config_schema: serde_json::Value,
    pub score: Option<f64>,
    pub same_category: Option<bool>,
}

fn template_alternative_row_from_pg(row: sqlx::postgres::PgRow) -> Result<TemplateAlternativeRow> {
    Ok(TemplateAlternativeRow {
        id: row.try_get::<Option<_>, _>("id")?.unwrap_or_default(),
        name: row.try_get::<Option<_>, _>("name")?.unwrap_or_default(),
        category: row.try_get::<Option<_>, _>("category")?.unwrap_or_default(),
        description: row.try_get::<Option<String>, _>("description")?,
        allowed_secrets: row
            .try_get::<Option<_>, _>("allowed_secrets")?
            .unwrap_or_default(),
        config_schema: row
            .try_get::<Option<serde_json::Value>, _>("config_schema")?
            .unwrap_or(serde_json::Value::Null),
        // similarity() returns PostgreSQL real (f32); cast to f64. Missing column → None.
        score: row.try_get::<f32, _>("score").ok().map(|s| s as f64),
        same_category: row.try_get("same_category").ok(),
    })
}

/// Snapshot used by `hot_update_module` to resolve a module's current state
/// before recompiling. Accepts EITHER `wasm_modules.id` OR `node_templates.id`
/// (dual-UUID model — see CLAUDE.md).
///
/// The resolved `effective_wm_id` is the canonical `wasm_modules.id` that
/// should be targeted by the downstream UPDATE. When `is_sandbox_only` is
/// true, there is no `wasm_modules` row yet — the caller is hot-updating a
/// sandbox template that has never been compiled.
#[derive(Debug)]
pub struct HotUpdateContext {
    pub effective_wm_id: Uuid,
    pub name: String,
    pub stored_source: Option<String>,
    pub stored_config: serde_json::Value,
    pub template_id: Option<Uuid>,
    pub is_sandbox_only: bool,
    pub old_content_hash: Option<String>,
    /// Capability world of the existing module — used to preserve the world
    /// when the caller doesn't pass one explicitly. Never None in practice
    /// (default `"automation-node"` when the DB column is null).
    pub capability_world: String,
    /// Existing per-module fuel ceiling. Hot-update sites use this as the
    /// default when the caller omits `fuel_budget`, so a no-args recompile
    /// doesn't silently reset an operator-tuned ceiling back to the
    /// `compute_max_fuel(10, 2000, 2.0)` baseline. None for legacy rows
    /// where the column was null at the time of read.
    pub existing_max_fuel: Option<i64>,
}

/// Normalise a stored `capability_world` value to the suffixed form
/// declared in `talos.wit` (`"minimal-node"`, `"http-node"`, …).
///
/// Two storage forms exist in the wild:
/// - `node_templates.capability_world` typically stores the suffixed form.
/// - `wasm_modules.capability_world` historically stores the bare form
///   (`"minimal"`, `"http"`).
///
/// `worker::CapabilityWorld::FromStr` accepts both forms (so authorization
/// + dispatch are unaffected), but cargo-component's WIT world selection
/// at compile time requires the EXACT name from talos.wit. Hot-update
/// recompiles must therefore feed it the suffixed form.
///
/// Idempotent: `"minimal-node"` returns unchanged. `"automation-node"`
/// returns unchanged (the public alias for the `Trusted` world).
/// `"unknown"` returns unchanged so the caller can surface it as an
/// invalid world rather than silently coercing.
fn normalise_capability_world(world: String) -> String {
    if world.ends_with("-node") || world == "unknown" {
        return world;
    }
    format!("{}-node", world)
}

impl ModuleRepository {
    pub fn new(db_pool: PgPool) -> Self {
        Self {
            db_pool,
            secrets_manager: None,
        }
    }

    /// Builder: attach SecretsManager so reader methods can transparently
    /// decrypt `module_executions.*_enc` columns. Without this wiring,
    /// readers that touch encrypted rows return None for the payload
    /// fields (the legacy plaintext columns are NULL post-Phase-A).
    #[must_use]
    pub fn with_encryption(
        mut self,
        sm: std::sync::Arc<talos_secrets_manager::SecretsManager>,
    ) -> Self {
        self.secrets_manager = Some(sm);
        self
    }

    /// Decrypt one `module_executions` payload slot (input/output/trigger).
    /// Prefers ciphertext when present + SecretsManager wired; falls back to
    /// the plaintext column for legacy rows.
    ///
    /// MUST route through `decrypt_payload_slot` (version+slot-bound AAD),
    /// mirroring the canonical reader in `talos-module-executions`. The prior
    /// implementation called the bare `decrypt_value_by_key` (empty AAD = v0
    /// format), which AES-GCM-tag-fails on every v1+ row the writer produces
    /// — silently breaking replay-from-history on any encrypted deploy. The
    /// caller MUST therefore SELECT the row `id` (the AAD root) and
    /// `payload_format`; omitting `payload_format` (defaulting to 0) would
    /// reintroduce the v0 mismatch.
    async fn read_module_payload(
        &self,
        module_execution_id: Uuid,
        slot: talos_module_payload_encryption::PayloadSlot,
        plaintext: Option<serde_json::Value>,
        enc_bytes: Option<Vec<u8>>,
        key_id: Option<Uuid>,
        format_version: i16,
    ) -> Result<Option<serde_json::Value>> {
        if let (Some(sm), Some(bytes), Some(kid)) = (&self.secrets_manager, &enc_bytes, key_id) {
            let s = talos_module_payload_encryption::decrypt_payload_slot(
                sm,
                kid,
                bytes,
                module_execution_id,
                slot,
                format_version,
            )
            .await?;
            let v: serde_json::Value = serde_json::from_str(&s)?;
            return Ok(Some(v));
        }
        Ok(plaintext)
    }

    /// Decrypt a `workflow_executions.output_data_enc` column. Unlike module
    /// payloads (per-slot AAD), workflow output binds only the execution `id`
    /// as AAD — mirroring `talos_execution_repository`'s `decrypt_output` so
    /// the two readers stay in lockstep on the wire format. The caller MUST
    /// SELECT the row `id` and `output_data_format`.
    async fn read_workflow_output(
        &self,
        execution_id: Uuid,
        plaintext: Option<serde_json::Value>,
        enc_bytes: Option<Vec<u8>>,
        key_id: Option<Uuid>,
        format_version: i16,
    ) -> Result<Option<serde_json::Value>> {
        if let (Some(sm), Some(bytes), Some(kid)) = (&self.secrets_manager, &enc_bytes, key_id) {
            let s = sm
                .decrypt_versioned(kid, bytes, execution_id.as_bytes(), format_version)
                .await?;
            let v: serde_json::Value = serde_json::from_str(&s)?;
            return Ok(Some(v));
        }
        Ok(plaintext)
    }

    // ── Reference checking ────────────────────────────────────────────────

    /// Count workflows + webhooks that reference a module, plus a sample of webhook IDs.
    /// Used by delete_module and batch_delete to determine if force is needed.
    pub async fn get_module_ref_counts(
        &self,
        module_id: Uuid,
        user_id: Uuid,
    ) -> Result<ModuleRefCounts> {
        let workflow_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM workflows \
             WHERE user_id = $1 AND graph_json LIKE '%' || $2 || '%'",
        )
        .bind(user_id)
        .bind(module_id.to_string())
        .fetch_one(&self.db_pool)
        .await?;

        let webhook_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM webhook_triggers WHERE module_id = $1 AND user_id = $2",
        )
        .bind(module_id)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;

        let webhook_ids_sample: Vec<String> = if webhook_count > 0 {
            sqlx::query(
                "SELECT id::text FROM webhook_triggers \
                 WHERE module_id = $1 AND user_id = $2 LIMIT 5",
            )
            .bind(module_id)
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await?
            .iter()
            .filter_map(|r| r.try_get::<String, _>("id").ok())
            .collect()
        } else {
            Vec::new()
        };

        Ok(ModuleRefCounts {
            workflow_count,
            webhook_count,
            webhook_ids_sample,
        })
    }

    /// Delete a module by ID (user-scoped). Returns rows affected.
    ///
    /// Accepts EITHER `wasm_modules.id` OR `node_templates.id` for the caller's
    /// convenience — the dual-UUID module-entity model (see CLAUDE.md) means
    /// users frequently don't remember which UUID they were given. We resolve
    /// template-id aliases upfront so `delete_module(<template_id>)` does the
    /// right thing.
    ///
    /// Cleans up orphan `node_templates` rows for sandbox-source modules
    /// (`category = 'sandbox'`) in the same transaction. Before this fix,
    /// deleting a sandbox module removed the `wasm_modules` row but left the
    /// `node_templates` shell, producing a confusing "Access denied — this
    /// module is system-owned or belongs to another user" on any subsequent
    /// delete attempt keyed on the template_id.
    /// Phase 3.2: also deletes from the unified `modules` table so the
    /// new authoritative store stays in sync with legacy. ON DELETE CASCADE
    /// is set for user_id; for module_id we have to hit it explicitly.
    /// Delete a user-owned module. Phase 5.1: modules-only, canonical id only.
    pub async fn delete_module(&self, module_id: Uuid, user_id: Uuid) -> Result<u64> {
        let rows = sqlx::query(
            "DELETE FROM modules \
             WHERE id = $1 \
               AND user_id = $2",
        )
        .bind(module_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(rows.rows_affected())
    }

    /// Fetch a module's effective `max_fuel` (NOT NULL on the table,
    /// but we model the absent-row case as `None`).
    ///
    /// Used by `add_node_to_workflow` to surface the resulting fuel
    /// budget back to the caller. Pre-r247 this lived as inline
    /// `sqlx::query_scalar` in the MCP handler; lifted here so the
    /// handler stays repo-pure and the SQL has one home. Read-only,
    /// no user_id check — the caller has already authorised the
    /// surrounding mutation by the time it asks.
    pub async fn get_max_fuel(&self, module_id: Uuid) -> Result<Option<i64>> {
        let row: Option<i64> =
            sqlx::query_scalar::<_, i64>("SELECT max_fuel FROM modules WHERE id = $1")
                .bind(module_id)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(row)
    }

    /// Batch delete modules by IDs (user-scoped). Returns rows affected.
    pub async fn batch_delete_modules(&self, module_ids: &[Uuid], user_id: Uuid) -> Result<u64> {
        // Reuse the per-id helper so orphan-template cleanup + template-id
        // alias resolution apply consistently. The cost is O(N) round trips
        // instead of a single DELETE, but `batch_delete_modules` is not on
        // a hot path and N is tiny in practice (cleanup scripts, < 100).
        let mut total: u64 = 0;
        for id in module_ids {
            total = total.saturating_add(self.delete_module(*id, user_id).await?);
        }
        Ok(total)
    }

    /// True if the module exists AND is owned by `user_id`. Used as the
    /// ownership gate before attaching user-scoped resources (e.g. webhook
    /// triggers) to a module.
    pub async fn module_owned_by_user(&self, module_id: Uuid, user_id: Uuid) -> Result<bool> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS( \
               SELECT 1 FROM modules \
               WHERE id = $1 \
                 AND user_id = $2 \
             )",
        )
        .bind(module_id)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(exists)
    }

    /// Check whether a module exists but belongs to a different user or is a catalog entry.
    /// Used to distinguish "not found" from "access denied" in error messages.
    /// Phase 3.2: queries the unified modules table.
    pub async fn module_exists_elsewhere(&self, module_id: Uuid, user_id: Uuid) -> Result<bool> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS( \
               SELECT 1 FROM modules \
               WHERE id = $1 \
                 AND (user_id IS NULL OR user_id != $2) \
             )",
        )
        .bind(module_id)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(exists)
    }

    /// Fetch the pre-recompile snapshot used by `handle_hot_update_module`.
    ///
    /// Dual-UUID resolution: the caller may pass either `wasm_modules.id` or
    /// `node_templates.id` — both resolve to the same module. `template_id`
    /// (preferred) AND `source_template_id` (legacy VARCHAR column from
    /// `store_module_fresh`) are both consulted so modules created via
    /// either compile path resolve correctly.
    ///
    /// When NO `wasm_modules` row exists but a `node_templates` row does,
    /// we return a sandbox-only context — the caller compiles from the
    /// template's `code_template` and INSERTs a fresh `wasm_modules` row.
    ///
    /// Returns `Ok(None)` when the id matches nothing the user owns; the
    /// caller should surface a "Module not found or access denied" error.
    pub async fn get_hot_update_context(
        &self,
        module_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<HotUpdateContext>> {
        // Phase 5.1: single query against the unified `modules` table.
        // `is_sandbox_only` means "no compiled bytes yet" — detected via
        // `wasm_bytes IS NULL OR length = 0`.
        let row_opt = sqlx::query(
            "SELECT id, name, source_code, config, \
                    content_hash, capability_world, wasm_bytes, kind, max_fuel \
             FROM modules \
             WHERE id = $1 \
               AND user_id = $2 \
             ORDER BY compiled_at DESC NULLS LAST LIMIT 1",
        )
        .bind(module_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        if let Some(row) = row_opt {
            let wm_id: Uuid = row.try_get::<Option<_>, _>("id")?.unwrap_or(module_id);
            let name: String = row.try_get::<Option<_>, _>("name")?.unwrap_or_default();
            let source: Option<String> = row.try_get::<Option<String>, _>("source_code")?;
            let config: serde_json::Value = row
                .try_get::<Option<serde_json::Value>, _>("config")
                .ok()
                .flatten()
                .unwrap_or_else(|| serde_json::json!({}));
            let old_hash: Option<String> = row.try_get::<Option<String>, _>("content_hash")?;
            let world: String = row
                .try_get::<Option<String>, _>("capability_world")?
                .map(normalise_capability_world)
                .unwrap_or_else(|| "automation-node".to_string());
            let wasm_bytes: Option<Vec<u8>> = row.try_get::<Option<Vec<u8>>, _>("wasm_bytes")?;
            let is_sandbox_only = wasm_bytes.as_ref().map(|b| b.is_empty()).unwrap_or(true);
            // max_fuel is NOT NULL on the modules table, but use try_get → Option
            // to stay defensive against schema drift / older mirrored rows.
            // Treat <= 0 as None too — the CHECK constraint disallows it but
            // a stray 0 would silently mean "use baseline" without surprising
            // the caller.
            let existing_fuel: Option<i64> =
                row.try_get::<i64, _>("max_fuel").ok().filter(|v| *v > 0);

            return Ok(Some(HotUpdateContext {
                effective_wm_id: wm_id,
                name,
                stored_source: source,
                stored_config: config,
                template_id: Some(wm_id),
                is_sandbox_only,
                old_content_hash: old_hash,
                capability_world: world,
                existing_max_fuel: existing_fuel,
            }));
        }

        Ok(None)
    }

    /// Rename a module. Phase 3.2: dual-mutate so both the legacy
    /// wasm_modules row AND the unified modules row stay in sync.
    /// Rename a user-owned module. Phase 5.1: modules-only, canonical id.
    pub async fn rename_module(
        &self,
        module_id: Uuid,
        user_id: Uuid,
        new_name: &str,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE modules SET name = $1 \
             WHERE id = $2 \
               AND user_id = $3",
        )
        .bind(new_name)
        .bind(module_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Check if the user is a member of the given org.
    pub async fn is_org_member(&self, user_id: Uuid, org_id: Uuid) -> Result<bool> {
        let is_member: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM organization_members WHERE org_id = $1 AND user_id = $2)",
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(is_member)
    }

    /// Stricter variant of `is_org_member`: returns true only when the user
    /// holds a writable role (member, admin, or owner). Viewer is excluded.
    /// Use this for write-side checks like `share_module_with_org` so a
    /// Viewer-role auditor can't push their own modules into the org's
    /// shared pool — the GraphQL `user_writable_org_ids` helper enforces
    /// the same role filter for org-scoped writes.
    pub async fn is_org_member_writable(&self, user_id: Uuid, org_id: Uuid) -> Result<bool> {
        let writable: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM organization_members \
             WHERE org_id = $1 AND user_id = $2 \
               AND role IN ('member', 'admin', 'owner'))",
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(writable)
    }

    /// Share a module with an organization.
    pub async fn share_module_with_org(
        &self,
        module_id: Uuid,
        user_id: Uuid,
        org_id: Uuid,
    ) -> Result<u64> {
        // Phase 5.1: org_id on the unified `modules` table. Canonical id only.
        let result = sqlx::query(
            "UPDATE modules SET org_id = $1 \
              WHERE id = $2 \
                AND user_id = $3",
        )
        .bind(org_id)
        .bind(module_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// List modules for a user (sandbox only, ordered by updated_at desc).
    /// List modules whose name starts with `prefix`, sorted by
    /// `compiled_at DESC` (newest first). Used by
    /// `handle_cleanup_module_versions` to identify the keeper vs the
    /// older versions safely. Caller MUST own the rows (`user_id` filter).
    /// Phase 3.2: reads from the unified `modules` table. The LIKE
    /// pattern uses sqlx's parameterized binding so prefix injection is
    /// not a concern; the handler additionally rejects `%`/`_` in the
    /// caller-supplied prefix.
    pub async fn list_modules_by_name_prefix(
        &self,
        user_id: Uuid,
        prefix: &str,
    ) -> Result<Vec<(Uuid, String, chrono::DateTime<chrono::Utc>)>> {
        let pattern = format!("{}%", prefix);
        let rows = sqlx::query(
            "SELECT id, name, compiled_at FROM modules \
             WHERE user_id = $1 AND name LIKE $2 \
               AND compiled_at IS NOT NULL \
             ORDER BY compiled_at DESC",
        )
        .bind(user_id)
        .bind(pattern)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(
                |r| -> Result<(Uuid, String, chrono::DateTime<chrono::Utc>)> {
                    Ok((
                        r.try_get::<Option<_>, _>("id")?.unwrap_or_default(),
                        r.try_get::<Option<_>, _>("name")?.unwrap_or_default(),
                        r.try_get::<Option<_>, _>("compiled_at")?
                            .unwrap_or_else(chrono::Utc::now),
                    ))
                },
            )
            .collect::<Result<Vec<_>>>()
    }

    /// Phase 3.2: queries the unified modules table directly. The
    /// previous LEFT JOIN to node_templates was needed only because
    /// capability_world was stored on the template row in the legacy
    /// dual-row model — modules has it inline.
    pub async fn list_user_modules(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<ModuleListItem>> {
        let rows = sqlx::query(
            "SELECT id, name, capability_world, max_fuel, usage_count, updated_at \
             FROM modules \
             WHERE user_id = $1 \
             ORDER BY updated_at DESC \
             LIMIT $2",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;

        rows.iter()
            .map(|r| -> Result<ModuleListItem> {
                Ok(ModuleListItem {
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
                    // capability_world is NOT NULL on modules; surface as
                    // Some(_) so the type matches the dual-row contract.
                    capability_world: r.try_get::<String, _>("capability_world").ok(),
                    max_fuel: r.try_get("max_fuel")?,
                    usage_count: r.try_get::<i64, _>("usage_count").ok(),
                    updated_at: r.try_get("updated_at")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Batch-fetch full module details by id, scoped to modules the user
    /// owns directly or through org membership. Backs the GraphQL
    /// `wasm_modules` resolver (bare-pool read — the `modules` table is
    /// not RLS-scoped through this path; scoping is the explicit
    /// `(user_id, org_ids)` predicate).
    pub async fn get_modules_by_ids_scoped(
        &self,
        ids: &[Uuid],
        user_id: Uuid,
        org_ids: &[Uuid],
    ) -> Result<Vec<ModuleDetailsRow>> {
        let rows = sqlx::query_as::<_, ModuleDetailsRow>(
            "SELECT id, name,
                    COALESCE(size_bytes, 0) AS size_bytes,
                    COALESCE(content_hash, '') AS content_hash,
                    COALESCE(compiled_at, created_at) AS compiled_at,
                    config, config_schema, catalog_slug, source_code, capability_world, imported_interfaces, language
             FROM modules
             WHERE id = ANY($1)
               AND (user_id = $2 OR org_id = ANY($3))",
        )
        .bind(ids)
        .bind(user_id)
        .bind(org_ids)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    /// Unscoped batch fetch of full module details by id. Backs the GraphQL
    /// `ModuleLoader` DataLoader, which is only invoked via ComplexObject
    /// resolvers (e.g. WebhookTrigger.module) where the parent entity has
    /// already been scoped to the authenticated user; modules may also be
    /// referenced across users via `workflow_module_refs`, so deliberately
    /// NO user_id filter here. Do not call from a surface that hasn't
    /// pre-scoped the ids.
    pub async fn get_modules_by_ids(&self, ids: &[Uuid]) -> Result<Vec<ModuleDetailsRow>> {
        let rows = sqlx::query_as::<_, ModuleDetailsRow>(
            "SELECT id, name,
                    COALESCE(size_bytes, 0) AS size_bytes,
                    COALESCE(content_hash, '') AS content_hash,
                    COALESCE(compiled_at, created_at) AS compiled_at,
                    config, config_schema, catalog_slug, source_code, capability_world, imported_interfaces, language
             FROM modules
             WHERE id = ANY($1)",
        )
        .bind(ids)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    /// Paginated full-detail listing of the modules a user owns directly
    /// or through org membership. Backs the GraphQL `my_modules` resolver.
    /// Catalog rows (NULL user_id, NULL org_id) are excluded by the scope
    /// predicate. Unique `id DESC` tiebreaker keeps OFFSET pages stable.
    pub async fn list_modules_for_user_paginated(
        &self,
        user_id: Uuid,
        org_ids: &[Uuid],
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ModuleDetailsRow>> {
        let rows = sqlx::query_as::<_, ModuleDetailsRow>(
            "SELECT id, name,
                    COALESCE(size_bytes, 0) AS size_bytes,
                    COALESCE(content_hash, '') AS content_hash,
                    COALESCE(compiled_at, created_at) AS compiled_at,
                    config, config_schema, catalog_slug, source_code, capability_world, imported_interfaces, language
             FROM modules
             WHERE (user_id = $1 OR org_id = ANY($4))
             ORDER BY COALESCE(compiled_at, created_at) DESC, id DESC
             LIMIT $2 OFFSET $3",
        )
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .bind(org_ids)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    /// Overwrite a module's `config` JSON by canonical id (Phase 5.1:
    /// unified `modules` table). Caller is responsible for authorization —
    /// used by the GraphQL `create_module_from_template` auto-setup path to
    /// persist created watch-channel ids onto a module it just created.
    pub async fn update_module_config(
        &self,
        module_id: Uuid,
        config: &serde_json::Value,
    ) -> Result<()> {
        sqlx::query("UPDATE modules SET config = $1 WHERE id = $2")
            .bind(config)
            .bind(module_id)
            .execute(&self.db_pool)
            .await?;
        Ok(())
    }

    // ── MCP-handler support: listing + info + scanning ─────────────────────

    /// List a user's modules from the unified `user_modules` view (unions
    /// `wasm_modules` + user-owned `node_templates` with deduplication).
    /// Used by `handle_list_modules` so list_modules / list_module_catalog /
    /// system_status all agree on what counts as a "module".
    pub async fn list_user_modules_view(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<UserModuleViewRow>> {
        self.list_user_modules_view_filtered(user_id, None, limit)
            .await
    }

    /// `list_user_modules_view` with an optional case-insensitive name
    /// substring filter. `name_like` must be a pre-escaped LIKE pattern
    /// (caller escapes `\`/`%`/`_` — backslash first — and wraps in `%`).
    pub async fn list_user_modules_view_filtered(
        &self,
        user_id: Uuid,
        name_like: Option<&str>,
        limit: i64,
    ) -> Result<Vec<UserModuleViewRow>> {
        let rows = sqlx::query(
            "SELECT id, name, capability_world, source, template_id \
             FROM user_modules WHERE user_id = $1 \
               AND ($3::text IS NULL OR name ILIKE $3 ESCAPE '\\') \
             ORDER BY compiled_at DESC LIMIT $2",
        )
        .bind(user_id)
        .bind(limit)
        .bind(name_like)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(|r| -> Result<UserModuleViewRow> {
                Ok(UserModuleViewRow {
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
                    capability_world: r.try_get("capability_world")?,
                    source: r.try_get("source")?,
                    template_id: r.try_get("template_id").ok().flatten(),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Delete user-owned modules whose ids are NOT referenced by any of
    /// the user's workflows. `prefix_filter` is matched as
    /// `name LIKE prefix || '%'` when provided. Phase 5: modules-only.
    /// The 3-shape alias NOT-IN check stays until the alias columns are
    /// dropped in the follow-up migration — a workflow still carrying a
    /// legacy UUID must not get its module deleted out from under it.
    pub async fn cleanup_unreferenced_modules(
        &self,
        user_id: Uuid,
        prefix_filter: Option<&str>,
    ) -> Result<u64> {
        // Single statement with optional name filter via boolean parameter so
        // there's no dynamic SQL — the `$2::bool` arm short-circuits when no
        // prefix was given.
        let pattern = prefix_filter.map(|p| format!("{}%", p));
        let result = sqlx::query(
            "DELETE FROM modules \
             WHERE user_id = $1 \
               AND ($2::bool IS FALSE OR name LIKE $3) \
               AND id NOT IN ( \
                 SELECT DISTINCT unnest(regexp_matches( \
                   graph_json, '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'g' \
                 ))::uuid \
                 FROM workflows WHERE user_id = $1 \
               )",
        )
        .bind(user_id)
        .bind(prefix_filter.is_some())
        .bind(pattern.as_deref())
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Fetch a module row for the get_module_info handler. Phase 5.1:
    /// reads from the unified `modules` table via canonical id only.
    ///
    /// Returns None when no match (caller's fallback to
    /// get_node_template_info is now a no-op for the modules-table era).
    pub async fn get_wasm_module_info(
        &self,
        module_or_template_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<WasmModuleInfo>> {
        let row = sqlx::query(
            "SELECT id, name, capability_world, compiled_at, \
                    allowed_hosts, allowed_secrets, \
                    COALESCE(LENGTH(wasm_bytes)::bigint, size_bytes::bigint) AS size_bytes, \
                    (source_code IS NOT NULL) AS has_source_code, \
                    rate_limit_per_minute \
             FROM modules \
             WHERE id = $1 \
               AND (user_id = $2 OR user_id IS NULL) \
             ORDER BY compiled_at DESC NULLS LAST LIMIT 1",
        )
        .bind(module_or_template_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        row.map(|r| -> Result<WasmModuleInfo> {
            Ok(WasmModuleInfo {
                wm_id: r
                    .try_get::<Option<_>, _>("id")?
                    .unwrap_or(module_or_template_id),
                name: r.try_get::<Option<_>, _>("name")?.unwrap_or_default(),
                capability_world: r
                    .try_get::<Option<_>, _>("capability_world")?
                    .unwrap_or_else(|| "unknown".to_string()),
                compiled_at: r.try_get::<Option<_>, _>("compiled_at")?,
                template_id: Some(
                    r.try_get::<Option<_>, _>("id")?
                        .unwrap_or(module_or_template_id),
                ),
                allowed_hosts: r
                    .try_get::<Option<_>, _>("allowed_hosts")?
                    .unwrap_or_default(),
                allowed_secrets: r
                    .try_get::<Option<_>, _>("allowed_secrets")?
                    .unwrap_or_default(),
                size_bytes: r.try_get::<Option<_>, _>("size_bytes")?.unwrap_or(0),
                has_source_code: r
                    .try_get::<Option<_>, _>("has_source_code")?
                    .unwrap_or(false),
                rate_limit_per_minute: r.try_get::<Option<_>, _>("rate_limit_per_minute")?,
            })
        })
        .transpose()
    }

    // Removed: the unscoped `get_node_template_info(template_id)` — it had
    // ZERO live callers (MCP-795 routed the two fallback sites,
    // `handle_get_module_info` and `handle_test_secret_access`, to the
    // user-scoped variant below precisely because the unscoped form leaked
    // private template metadata — name / capability_world / allowed_hosts /
    // allowed_secrets / has_source_code — of EVERY user's templates and let an
    // attacker probe another user's secret-path grants). Leaving it in the
    // repo was a latent IDOR footgun: a future handler could call it with a
    // caller-supplied `template_id` and silently reintroduce the leak. Use
    // `get_node_template_info_for_user` — the only correct path.

    /// User-scoped variant — returns metadata
    /// only for catalog templates (`user_id IS NULL`) or templates owned
    /// by `user_id`. Mirrors the MCP-793/794 scope-pair pattern:
    /// `get_template_for_user` / `list_templates_paginated_for_user`.
    ///
    /// Use this from any handler where `template_id` originates from a
    /// caller-supplied argument (typically as a fallback after a
    /// user-scoped `get_wasm_module_info` lookup misses). MCP-795 (2026-05-14)
    /// closed two such fallback sites — `handle_get_module_info` and
    /// `handle_test_secret_access` — where the unscoped variant leaked
    /// metadata (name, capability_world, allowed_hosts, allowed_secrets,
    /// has_source_code) of every user's private templates, and let an
    /// attacker probe whether another user's template grants access to
    /// specific secret paths.
    pub async fn get_node_template_info_for_user(
        &self,
        template_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<NodeTemplateInfo>> {
        let row = sqlx::query(
            "SELECT name, kind, capability_world, allowed_hosts, allowed_secrets, \
                    COALESCE(LENGTH(wasm_bytes)::bigint, size_bytes::bigint) AS size_bytes, \
                    (source_code IS NOT NULL) AS has_source_code, \
                    created_at \
             FROM modules \
             WHERE id = $1 \
               AND (user_id IS NULL OR user_id = $2) \
             LIMIT 1",
        )
        .bind(template_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Self::row_to_template_info(row)
    }

    fn row_to_template_info(
        row: Option<sqlx::postgres::PgRow>,
    ) -> Result<Option<NodeTemplateInfo>> {
        row.map(|r| -> Result<NodeTemplateInfo> {
            Ok(NodeTemplateInfo {
                name: r.try_get::<Option<_>, _>("name")?.unwrap_or_default(),
                // Map kind → category for back-compat with the old
                // get_node_template_info contract. `kind=catalog` was
                // historically `category=<the actual category column>`,
                // but most consumers just want a label, and kind is the
                // post-Phase-3.2 source-of-truth.
                category: r
                    .try_get::<Option<_>, _>("kind")?
                    .unwrap_or_else(|| "template".to_string()),
                capability_world: r.try_get::<Option<_>, _>("capability_world")?,
                size_bytes: r.try_get::<Option<_>, _>("size_bytes")?.unwrap_or(0),
                has_source_code: r
                    .try_get::<Option<_>, _>("has_source_code")?
                    .unwrap_or(false),
                allowed_hosts: r
                    .try_get::<Option<_>, _>("allowed_hosts")?
                    .unwrap_or_default(),
                allowed_secrets: r
                    .try_get::<Option<_>, _>("allowed_secrets")?
                    .unwrap_or_default(),
                created_at: r.try_get::<Option<_>, _>("created_at")?,
            })
        })
        .transpose()
    }

    /// Find non-archived workflows that reference a module id by substring
    /// match on `graph_json`. Used by `list_module_usage` and
    /// `get_module_dependents` direct-reference scans.
    pub async fn find_workflows_referencing_module(
        &self,
        user_id: Uuid,
        module_id: Uuid,
        limit: i64,
    ) -> Result<Vec<WorkflowRef>> {
        let pattern = format!("%{}%", module_id);
        let rows = sqlx::query(
            "SELECT id, name FROM workflows \
             WHERE user_id = $1 AND graph_json LIKE $2 \
               AND (status IS NULL OR status != 'archived') \
             ORDER BY updated_at DESC LIMIT $3",
        )
        .bind(user_id)
        .bind(&pattern)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(|r| -> Result<WorkflowRef> {
                Ok(WorkflowRef {
                    id: r.try_get::<Option<_>, _>("id")?.unwrap_or_default(),
                    name: r.try_get::<Option<_>, _>("name")?.unwrap_or_default(),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Find sub-workflows: workflows that reference one of the given
    /// workflow IDs (call_workflow / trigger_workflow patterns). Excludes
    /// the referenced workflow itself.
    pub async fn find_workflows_referencing_workflow(
        &self,
        user_id: Uuid,
        target_workflow_id: Uuid,
        limit: i64,
    ) -> Result<Vec<WorkflowRef>> {
        let pattern = format!("%{}%", target_workflow_id);
        let rows = sqlx::query(
            "SELECT id, name FROM workflows \
             WHERE user_id = $1 AND graph_json LIKE $2 AND id != $3 \
               AND (status IS NULL OR status != 'archived') \
             ORDER BY updated_at DESC LIMIT $4",
        )
        .bind(user_id)
        .bind(&pattern)
        .bind(target_workflow_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(|r| -> Result<WorkflowRef> {
                Ok(WorkflowRef {
                    id: r.try_get::<Option<_>, _>("id")?.unwrap_or_default(),
                    name: r.try_get::<Option<_>, _>("name")?.unwrap_or_default(),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Batch sibling to [`find_workflows_referencing_workflow`]. Single
    /// CROSS-JOIN-UNNEST + window-function query replaces the per-target
    /// loop used by `handle_get_module_dependents` (N table-scans → 1).
    /// Per-target `limit_per_target` is enforced inside SQL via
    /// `ROW_NUMBER() OVER (PARTITION BY target_id ORDER BY updated_at DESC)`,
    /// preserving the prior per-target cap.
    ///
    /// Returns rows of `(target_workflow_id, referencing_workflow_id,
    /// referencing_workflow_name)`. Empty input short-circuits without
    /// touching the DB.
    ///
    /// Security: same `WHERE user_id = $1` scoping as the per-target
    /// method — references to workflows owned by other users contribute
    /// nothing to the result.
    pub async fn find_workflows_referencing_workflows(
        &self,
        user_id: Uuid,
        target_workflow_ids: &[Uuid],
        limit_per_target: i64,
    ) -> Result<Vec<(Uuid, Uuid, String)>> {
        if target_workflow_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            "SELECT target_id, id, name FROM ( \
                 SELECT t.target_id, w.id, w.name, \
                        ROW_NUMBER() OVER (PARTITION BY t.target_id \
                                           ORDER BY w.updated_at DESC) AS rn \
                 FROM workflows w \
                 CROSS JOIN UNNEST($2::uuid[]) AS t(target_id) \
                 WHERE w.user_id = $1 \
                   AND w.graph_json LIKE '%' || t.target_id::text || '%' \
                   AND w.id != t.target_id \
                   AND (w.status IS NULL OR w.status != 'archived') \
             ) ranked \
             WHERE rn <= $3",
        )
        .bind(user_id)
        .bind(target_workflow_ids)
        .bind(limit_per_target)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(|r| -> Result<(Uuid, Uuid, String)> {
                Ok((
                    r.try_get::<Option<Uuid>, _>("target_id")?
                        .unwrap_or_default(),
                    r.try_get::<Option<Uuid>, _>("id")?.unwrap_or_default(),
                    r.try_get::<Option<String>, _>("name")?.unwrap_or_default(),
                ))
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Find user-owned modules that haven't been referenced by any
    /// workflow in the past `days` days. Capped at 50 rows. Phase 5:
    /// queries the unified `modules` table.
    pub async fn find_unreferenced_modules(
        &self,
        user_id: Uuid,
        days: i32,
    ) -> Result<Vec<UnreferencedModule>> {
        let rows = sqlx::query(
            "SELECT m.id, m.name, m.compiled_at \
             FROM modules m \
             WHERE m.user_id = $1 \
               AND m.compiled_at IS NOT NULL \
               AND m.compiled_at < NOW() - make_interval(days => $2::int) \
               AND NOT EXISTS ( \
                   SELECT 1 FROM workflows w \
                   WHERE w.user_id = $1 AND w.graph_json LIKE '%' || m.id::text || '%' \
               ) \
             ORDER BY m.compiled_at ASC LIMIT 50",
        )
        .bind(user_id)
        .bind(days)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(|r| -> Result<UnreferencedModule> {
                Ok(UnreferencedModule {
                    id: r.try_get::<Option<_>, _>("id")?.unwrap_or_default(),
                    name: r.try_get::<Option<_>, _>("name")?.unwrap_or_default(),
                    compiled_at: r
                        .try_get::<Option<_>, _>("compiled_at")?
                        .unwrap_or_default(),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// List the update history rows for a module.
    pub async fn list_module_history(
        &self,
        module_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<ModuleHistoryRow>> {
        let rows = sqlx::query(
            "SELECT id, previous_hash, new_hash, size_bytes, created_at \
             FROM module_update_history \
             WHERE module_id = $1 AND user_id = $2 \
             ORDER BY created_at DESC LIMIT 20",
        )
        .bind(module_id)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(|r| -> Result<ModuleHistoryRow> {
                Ok(ModuleHistoryRow {
                    id: r.try_get::<Option<_>, _>("id")?.unwrap_or_default(),
                    previous_hash: r.try_get::<Option<String>, _>("previous_hash")?,
                    new_hash: r.try_get::<Option<_>, _>("new_hash")?.unwrap_or_default(),
                    size_bytes: r.try_get::<Option<_>, _>("size_bytes")?.unwrap_or(0),
                    created_at: r.try_get::<Option<_>, _>("created_at")?.unwrap_or_default(),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Lookup just the capability_world of a module. Phase 5.1: reads from
    /// the unified `modules` table by canonical id.
    /// Returns the world string + a synthetic source indicator for callers
    /// that pivot on it (catalog → Template, sandbox/extracted → Compiled).
    /// Security-critical: this backs the workflow capability-ceiling auth
    /// check; the modules table is single source of truth.
    pub async fn get_module_capability_world(
        &self,
        module_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<(String, ModuleSource)>> {
        let row = sqlx::query(
            "SELECT capability_world, kind FROM modules \
             WHERE id = $1 \
               AND (user_id = $2 OR user_id IS NULL) \
             ORDER BY compiled_at DESC NULLS LAST LIMIT 1",
        )
        .bind(module_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        row.map(|r| -> Result<(String, ModuleSource)> {
            let kind: String = r.try_get::<Option<_>, _>("kind")?.unwrap_or_default();
            let source = if kind == "catalog" {
                ModuleSource::Template
            } else {
                ModuleSource::Compiled
            };
            Ok((
                r.try_get::<Option<_>, _>("capability_world")?
                    .unwrap_or_default(),
                source,
            ))
        })
        .transpose()
    }

    // ── Batch-delete + rate-limit + org helpers ────────────────────────────

    /// Find which of the given module ids are referenced by any of the
    /// user's workflows. Returns one row per (module_id, referencing_workflow_name)
    /// pair. Used by batch_delete_modules to skip referenced modules.
    /// Phase 5: queries the unified `modules` table. The 3-shape id
    /// filter handles callers still passing legacy UUIDs.
    pub async fn find_referenced_modules_in_workflows(
        &self,
        module_ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<Vec<(Uuid, String)>> {
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT DISTINCT m.id, w.name FROM modules m \
             JOIN workflows w ON w.user_id = $2 AND w.graph_json::text LIKE '%' || m.id::text || '%' \
             WHERE m.id = ANY($1) \
               AND m.user_id = $2",
        )
        .bind(module_ids)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    /// Classify a batch of module ids by where they live + who owns them.
    /// Used by batch_delete to distinguish "deletable" from "access_denied"
    /// from "not_found" before calling delete_module. Phase 5: queries the
    /// unified `modules` table. Source is derived from `kind` — `catalog`
    /// → `"template"` (matches historical labelling: catalog rows were
    /// template-only), otherwise `"wasm"`.
    pub async fn classify_modules_for_delete(
        &self,
        module_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, String, Option<Uuid>)>> {
        let rows = sqlx::query(
            "SELECT id, \
                    CASE WHEN kind = 'catalog' THEN 'template'::text \
                         ELSE 'wasm'::text END AS source, \
                    user_id \
               FROM modules \
              WHERE id = ANY($1)",
        )
        .bind(module_ids)
        .fetch_all(&self.db_pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            // id/source are NOT NULL projections; skip a malformed row rather
            // than abort the batch (preserves the prior filter_map behaviour).
            let Some(id) = r.try_get::<Uuid, _>("id").ok() else {
                continue;
            };
            let Some(source) = r.try_get::<String, _>("source").ok() else {
                continue;
            };
            // user_id is nullable (catalog rows) — Option decode maps NULL → None,
            // but a missing column fails loud instead of silently defaulting.
            let owner: Option<Uuid> = r.try_get::<Option<_>, _>("user_id")?;
            out.push((id, source, owner));
        }
        Ok(out)
    }

    /// Find webhook_triggers rows that reference any of the given module ids
    /// (scoped to user). Returns one row per module with the list of webhook
    /// ids referencing it. Used by batch_delete to surface webhook
    /// dependencies.
    pub async fn find_webhook_dependencies_for_modules(
        &self,
        module_ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<std::collections::HashMap<Uuid, Vec<String>>> {
        let rows = sqlx::query(
            "SELECT module_id, array_agg(id::text ORDER BY id) AS webhook_ids \
             FROM webhook_triggers \
             WHERE module_id = ANY($1) AND user_id = $2 \
             GROUP BY module_id",
        )
        .bind(module_ids)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        let mut out = std::collections::HashMap::new();
        for row in rows {
            if let (Ok(mid), Ok(ids)) = (
                row.try_get::<Uuid, _>("module_id"),
                row.try_get::<Vec<String>, _>("webhook_ids"),
            ) {
                out.insert(mid, ids);
            }
        }
        Ok(out)
    }

    /// Update rate_limit_per_minute on the unified modules table.
    /// Phase 5: modules-only. Returns (rows_affected, 0) for signature
    /// stability with pre-Phase-5 callers that expected the tuple shape.
    ///
    /// Owner-scoped by default. A global CATALOG module (`user_id IS NULL`) is a
    /// SHARED row whose `rate_limit_per_minute` affects every tenant that runs
    /// it, so mutating one requires `allow_catalog` (the caller is a
    /// platform-admin). Without this gate any authenticated user could throttle
    /// or unthrottle a shared template deployment-wide — a cross-tenant write.
    pub async fn set_module_rate_limit(
        &self,
        module_id: Uuid,
        user_id: Uuid,
        rpm: Option<i32>,
        allow_catalog: bool,
    ) -> Result<(u64, u64)> {
        let result = if allow_catalog {
            sqlx::query(
                "UPDATE modules SET rate_limit_per_minute = $1 \
                 WHERE id = $2 \
                   AND (user_id = $3 OR user_id IS NULL)",
            )
            .bind(rpm)
            .bind(module_id)
            .bind(user_id)
            .execute(&self.db_pool)
            .await?
        } else {
            sqlx::query(
                "UPDATE modules SET rate_limit_per_minute = $1 \
                 WHERE id = $2 AND user_id = $3",
            )
            .bind(rpm)
            .bind(module_id)
            .bind(user_id)
            .execute(&self.db_pool)
            .await?
        };
        Ok((result.rows_affected(), 0))
    }

    /// Fetch rate_limit_per_minute for a module. Phase 3.2: queries the
    /// unified `modules` table.
    pub async fn get_module_rate_limit(
        &self,
        module_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<i32>> {
        let row = sqlx::query(
            "SELECT rate_limit_per_minute FROM modules \
             WHERE id = $1 \
               AND (user_id = $2 OR user_id IS NULL) \
             LIMIT 1",
        )
        .bind(module_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row
            .map(|r| r.try_get::<Option<i32>, _>("rate_limit_per_minute"))
            .transpose()?
            .flatten())
    }

    /// Org-membership check.
    pub async fn check_org_membership(&self, user_id: Uuid, org_id: Uuid) -> Result<bool> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM organization_members WHERE org_id = $1 AND user_id = $2)",
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(exists)
    }

    /// List modules shared with an organization. Phase 5: modules-only;
    /// `org_id` lives on the unified table thanks to the Phase 1.5
    /// schema add. NULLS LAST on compiled_at so catalog modules (compiled
    /// at build time) still surface.
    pub async fn list_org_modules(&self, org_id: Uuid) -> Result<Vec<OrgModuleRow>> {
        let rows = sqlx::query(
            "SELECT id, name, capability_world FROM modules \
             WHERE org_id = $1 ORDER BY compiled_at DESC NULLS LAST LIMIT 100",
        )
        .bind(org_id)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(|r| -> Result<OrgModuleRow> {
                Ok(OrgModuleRow {
                    id: r.try_get("id")?,
                    name: r
                        .try_get::<Option<_>, _>("name")?
                        .unwrap_or_else(|| "unknown".to_string()),
                    capability_world: r
                        .try_get::<Option<_>, _>("capability_world")?
                        .unwrap_or_else(|| "unknown".to_string()),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    // ── install_module_from_catalog support ────────────────────────────────

    /// Count user-owned modules. Used by install_from_catalog to enforce
    /// the per-user installed module cap. Catalog rows (NULL user_id)
    /// are intentionally excluded.
    pub async fn count_user_modules(&self, user_id: Uuid) -> Result<i64> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM modules WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&self.db_pool)
            .await?;
        Ok(count)
    }

    // Phase 5: `upsert_node_template_for_install` + `upsert_wasm_module_for_install`
    // deleted. The Phase 3.2 final drop routed every catalog install through
    // `install_catalog_module_to_modules` (modules-only), leaving these
    // legacy helpers unreachable. The wasm_modules + node_templates tables
    // disappear in the Phase 5 drop migration; any residual caller would
    // fail to compile (modules_repository doesn't expose this API anymore).

    /// Pin a module for a user (idempotent — ON CONFLICT DO NOTHING).
    pub async fn pin_user_module(&self, user_id: Uuid, module_name: &str) -> Result<()> {
        // RFC 0004 M4: user_module_pins is RLS-enforced — run on a
        // per-user scoped tx so the policy's user_id clause matches.
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        sqlx::query(
            "INSERT INTO user_module_pins (user_id, module_name) VALUES ($1, $2) \
             ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(module_name)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// List a user's pinned modules with a flag indicating whether the
    /// module currently has compiled wasm bytes. Phase 5: LEFT JOIN
    /// resolves against the unified `modules` table; "has_wasm" becomes
    /// `wasm_bytes IS NOT NULL AND length > 0`. Used by
    /// `restore_pinned_modules` to decide which entries need a recompile.
    pub async fn list_user_pinned_modules(&self, user_id: Uuid) -> Result<Vec<PinnedModuleStatus>> {
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let rows = sqlx::query(
            "SELECT pm.module_name, \
                    (m.wasm_bytes IS NOT NULL AND octet_length(m.wasm_bytes) > 0) AS has_wasm \
             FROM user_module_pins pm \
             LEFT JOIN modules m ON m.name = pm.module_name \
             WHERE pm.user_id = $1 \
             ORDER BY pm.pinned_at ASC",
        )
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.iter()
            .map(|r| -> Result<PinnedModuleStatus> {
                Ok(PinnedModuleStatus {
                    module_name: r
                        .try_get::<Option<_>, _>("module_name")?
                        .unwrap_or_default(),
                    has_wasm: r.try_get::<Option<_>, _>("has_wasm")?.unwrap_or(false),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Phase 5: update a module's precompiled wasm bytes by name (modules
    /// table; `wasm_bytes` replaces the legacy `precompiled_wasm` column).
    pub async fn update_template_precompiled_wasm(
        &self,
        module_name: &str,
        wasm_bytes: &[u8],
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE modules \
             SET wasm_bytes = $1, \
                 size_bytes = length($1)::INTEGER, \
                 compiled_at = NOW() \
             WHERE name = $2",
        )
        .bind(wasm_bytes)
        .bind(module_name)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    // ── find_module_alternatives support ───────────────────────────────────

    /// Lookup a module by case-insensitive name match. Used as the
    /// "target" anchor for find_module_alternatives. Phase 3.2: queries
    /// the unified modules table; `kind` projected as `category` for
    /// back-compat (catalog/sandbox/extracted instead of the old free-form
    /// category strings — coarser but consistent with the new model).
    pub async fn lookup_template_by_name_ci(
        &self,
        name: &str,
    ) -> Result<Option<TemplateAlternativeRow>> {
        let row = sqlx::query(
            "SELECT id, name, kind AS category, description, allowed_secrets, config_schema \
             FROM modules WHERE LOWER(name) = LOWER($1) LIMIT 1",
        )
        .bind(name)
        .fetch_optional(&self.db_pool)
        .await?;
        row.map(template_alternative_row_from_pg).transpose()
    }

    /// pg_trgm-based search for similar templates. Returns score + same_category
    /// flag to drive UI ranking. The pg_trgm extension may not be installed
    /// in all deployments — callers should fall back to category ordering on
    /// error.
    pub async fn find_template_alternatives_trgm(
        &self,
        target_id: Uuid,
        search_text: &str,
        target_category: &str,
        limit: i64,
    ) -> Result<Vec<TemplateAlternativeRow>> {
        // Phase 5.1: query the unified `modules` table; canonical id exclusion.
        let rows = sqlx::query(
            "SELECT id, name, category, description, allowed_secrets, config_schema, \
                GREATEST( \
                    similarity(name, $2), \
                    similarity(COALESCE(description, ''), $2) \
                ) AS score, \
                (category = $3) AS same_category \
             FROM modules \
             WHERE id != $1 \
               AND category IS NOT NULL \
             ORDER BY (GREATEST(similarity(name, $2), similarity(COALESCE(description, ''), $2)) \
                       + 0.1 * CASE WHEN (category = $3) THEN 1.0::float8 ELSE 0.0::float8 END) DESC \
             LIMIT $4",
        )
        .bind(target_id)
        .bind(search_text)
        .bind(target_category)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(template_alternative_row_from_pg)
            .collect::<Result<Vec<_>>>()
    }

    /// Fallback for `find_template_alternatives_trgm` when pg_trgm is unavailable —
    /// orders by `same_category DESC, name ASC`.
    pub async fn find_template_alternatives_by_category(
        &self,
        target_id: Uuid,
        target_category: &str,
        limit: i64,
    ) -> Result<Vec<TemplateAlternativeRow>> {
        // Phase 5.1: canonical id exclusion only.
        let rows = sqlx::query(
            "SELECT id, name, category, description, allowed_secrets, config_schema \
             FROM modules \
             WHERE id != $1 \
               AND category IS NOT NULL \
             ORDER BY (category = $2) DESC, name ASC \
             LIMIT $3",
        )
        .bind(target_id)
        .bind(target_category)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(template_alternative_row_from_pg)
            .collect::<Result<Vec<_>>>()
    }

    /// pg_trgm + ILIKE hybrid search by capability keyword.
    pub async fn find_templates_by_capability_trgm(
        &self,
        capability: &str,
        ilike_pattern: &str,
        limit: i64,
    ) -> Result<Vec<TemplateAlternativeRow>> {
        // Phase 4 prep: query the unified `modules` table. No target
        // exclusion (this is a free-form discovery search).
        let rows = sqlx::query(
            "SELECT id, name, category, description, allowed_secrets, config_schema, \
                GREATEST( \
                    similarity(name, $1), \
                    similarity(COALESCE(description, ''), $1) \
                ) AS score \
             FROM modules \
             WHERE category IS NOT NULL \
               AND ( similarity(name, $1) > 0.05 \
                  OR similarity(COALESCE(description, ''), $1) > 0.05 \
                  OR LOWER(name) LIKE LOWER($2) \
                  OR LOWER(COALESCE(description, '')) LIKE LOWER($2) ) \
             ORDER BY score DESC \
             LIMIT $3",
        )
        .bind(capability)
        .bind(ilike_pattern)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(template_alternative_row_from_pg)
            .collect::<Result<Vec<_>>>()
    }

    /// ILIKE-only fallback for capability search when pg_trgm is unavailable.
    pub async fn find_templates_by_capability_ilike(
        &self,
        ilike_pattern: &str,
        limit: i64,
    ) -> Result<Vec<TemplateAlternativeRow>> {
        // Phase 4 prep: query the unified `modules` table.
        let rows = sqlx::query(
            "SELECT id, name, category, description, allowed_secrets, config_schema \
             FROM modules \
             WHERE category IS NOT NULL \
               AND (LOWER(name) LIKE LOWER($1) OR LOWER(COALESCE(description, '')) LIKE LOWER($1)) \
             ORDER BY name ASC \
             LIMIT $2",
        )
        .bind(ilike_pattern)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(template_alternative_row_from_pg)
            .collect::<Result<Vec<_>>>()
    }

    // ── workflows.rs MCP-handler support ───────────────────────────────────

    /// Phase 5.1: post-table-drop, "the template id" is simply the
    /// canonical `modules.id`. Returns `Some(input_id)` if the module
    /// exists, else None. Signature preserved for caller stability.
    pub async fn find_template_id_via_wasm_module(
        &self,
        wasm_module_id: Uuid,
    ) -> Result<Option<Uuid>> {
        let id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM modules WHERE id = $1 LIMIT 1")
            .bind(wasm_module_id)
            .fetch_optional(&self.db_pool)
            .await?;
        Ok(id)
    }

    /// Phase 5: find a `modules.id` by 4-way normalised name match: exact
    /// LOWER, space/underscore→dash on stored name, kebab+strip on stored
    /// name, AND a symmetric normalisation that handles inputs like
    /// "Data_Validator" matching stored "Data Validator". Used by
    /// `create_workflow_from_spec`.
    pub async fn find_template_id_by_name_normalised(&self, name: &str) -> Result<Option<Uuid>> {
        let row: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM modules \
             WHERE LOWER(name) = LOWER($1) \
                OR LOWER(REPLACE(REPLACE(name, ' ', '-'), '_', '-')) = LOWER($1) \
                OR LOWER(REGEXP_REPLACE(REPLACE(REPLACE(name, ' ', '-'), '_', '-'), \
                         '[^a-z0-9-]', '', 'gi')) = LOWER($1) \
                OR LOWER(REPLACE(REPLACE($1, ' ', '-'), '_', '-')) \
                   = LOWER(REPLACE(REPLACE(name, ' ', '-'), '_', '-')) \
             LIMIT 1",
        )
        .bind(name)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row.map(|(id,)| id))
    }

    /// Phase 5: find a `modules.id` by stripping `-` and `_` then ILIKE
    /// comparison against the stripped name column. Used by
    /// `plan_and_execute` (primary matcher).
    pub async fn find_template_id_by_strip_normalise(&self, name: &str) -> Result<Option<Uuid>> {
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM modules \
             WHERE LOWER(REPLACE(REPLACE(name, '-', ''), '_', '')) \
                ILIKE LOWER(REPLACE(REPLACE($1, '-', ''), '_', '')) \
             LIMIT 1",
        )
        .bind(name)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(id)
    }

    /// Phase 5: find a `modules.id` by ILIKE pattern. Caller supplies the
    /// pre-built `%pattern%` string. Used by `plan_and_execute` as a
    /// fallback.
    pub async fn find_template_id_by_ilike(&self, ilike_pattern: &str) -> Result<Option<Uuid>> {
        let id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM modules WHERE LOWER(name) ILIKE $1 LIMIT 1")
                .bind(ilike_pattern)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(id)
    }

    /// Delete user-owned modules whose ids are in the given list.
    /// Used by the hygiene-fix path in `mcp/analytics.rs`. Returns rows
    /// affected.
    pub async fn delete_orphaned_modules(&self, ids: &[Uuid], user_id: Uuid) -> Result<u64> {
        if ids.is_empty() {
            return Ok(0);
        }
        let result = sqlx::query(
            "DELETE FROM modules \
             WHERE id = ANY($1) \
               AND user_id = $2",
        )
        .bind(ids)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// True if a module exists with the given canonical id. Used by
    /// `create_webhook` as a pre-flight check — `webhook_triggers.module_id`
    /// FK references `modules(id)`.
    pub async fn module_exists(&self, module_id: Uuid) -> Result<bool> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS( \
               SELECT 1 FROM modules \
               WHERE id = $1 \
             )",
        )
        .bind(module_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(exists)
    }

    /// Existence check scoped to what the requesting user can actually
    /// dispatch: catalog rows (`user_id IS NULL`) OR rows they own. Mirrors
    /// the runtime authorization in `Registry::get_module_bytes` so create
    /// paths fail loudly at create time instead of silently creating bricked
    /// triggers — and so the global existence check (`module_exists`)
    /// can't be used to enumerate other users' module UUIDs.
    pub async fn module_accessible_by_user(&self, module_id: Uuid, user_id: Uuid) -> Result<bool> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS( \
               SELECT 1 FROM modules \
               WHERE id = $1 AND (user_id = $2 OR user_id IS NULL) \
             )",
        )
        .bind(module_id)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(exists)
    }

    // ── graph.rs template-suggestion support ───────────────────────────────

    /// Phase 5: find a `modules.id` by case-insensitive exact-name match.
    /// Used by `add_error_handler` for resolving a `handler_module_name`
    /// to a UUID. Distinct from `lookup_template_by_name_ci` (which
    /// returns full row); this returns just the id for the common path
    /// that only needs that.
    ///
    /// MCP-956 (2026-05-15): scope by user. Pre-fix the SELECT was
    /// unscoped, so a user could resolve a name to ANY tenant's
    /// module UUID. The downstream caller (`add_error_handler`) would
    /// fail to actually use the foreign-tenant UUID, but the
    /// existence + UUID disclosure was a cross-tenant info leak.
    /// Catalog templates (`user_id IS NULL`) remain visible to all.
    /// Sibling-class fix to MCP-793/794/795 for the suggestion-side
    /// surface.
    pub async fn find_template_id_by_name_ci(
        &self,
        name: &str,
        user_id: Uuid,
    ) -> Result<Option<Uuid>> {
        let row: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM modules \
             WHERE LOWER(name) = LOWER($1) \
               AND (user_id IS NULL OR user_id = $2) \
             LIMIT 1",
        )
        .bind(name)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row.map(|(id,)| id))
    }

    /// Phase 5: substring-LIKE name search returning up to `limit` module
    /// names. Used as the first suggestion fallback when an exact-name
    /// lookup fails.
    ///
    /// MCP-956 (2026-05-15): scope by user + escape LIKE wildcards
    /// in `needle`. Pre-fix the SELECT was unscoped (cross-tenant
    /// module-name leak — sibling class to MCP-793/794/795) and bound
    /// the raw `needle` into `LIKE '%' || LOWER($1) || '%'` with no
    /// wildcard escape — a needle of `%` matched every module
    /// name in the database. Two real failure modes in one call.
    /// MCP-955 fixed the same wildcard-escape gap in
    /// `talos_memory::list_memories`.
    pub async fn suggest_template_names_like(
        &self,
        needle: &str,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<String>> {
        let escaped = needle
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM modules \
             WHERE LOWER(name) LIKE '%' || LOWER($1) || '%' ESCAPE '\\' \
               AND (user_id IS NULL OR user_id = $2) \
             LIMIT $3",
        )
        .bind(escaped)
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    /// Phase 5: pg_trgm `word_similarity` suggestion search — catches
    /// phonetic mismatches like "slak" → "Slack". Returns Err if pg_trgm
    /// is not installed (caller silently skips).
    ///
    /// MCP-956 (2026-05-15): scope by user (catalog + user's own).
    /// Pre-fix the trgm scan ranked across all tenants' module names;
    /// returned cross-tenant suggestions on miss.
    pub async fn suggest_template_names_trgm(
        &self,
        needle: &str,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<String>> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM modules \
             WHERE word_similarity(LOWER($1), LOWER(name)) > 0.2 \
               AND (user_id IS NULL OR user_id = $2) \
             ORDER BY word_similarity(LOWER($1), LOWER(name)) DESC \
             LIMIT $3",
        )
        .bind(needle)
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    /// Combine trgm + substring suggestion paths into a single "did you mean"
    /// list for error messages. Tries pg_trgm first (catches phonetic /
    /// transposition / case mismatches like canonical-name vs display-name —
    /// the exact class of bug that motivated `find_template_id_by_name_normalised`),
    /// falls back to substring LIKE if pg_trgm returns nothing OR isn't installed,
    /// dedupes while preserving rank order, returns at most `limit` names.
    ///
    /// Returns an empty Vec on database error rather than propagating —
    /// suggestion enrichment should never turn a not-found error into an
    /// infrastructure error. The original lookup miss is what the user
    /// needs to see.
    pub async fn suggest_template_names_for_miss(
        &self,
        needle: &str,
        user_id: Uuid,
        limit: i64,
    ) -> Vec<String> {
        let mut out: Vec<String> = Vec::with_capacity(limit as usize);
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        if let Ok(rows) = self
            .suggest_template_names_trgm(needle, user_id, limit)
            .await
        {
            for n in rows {
                let key = n.to_lowercase();
                if seen.insert(key) {
                    out.push(n);
                    if out.len() >= limit as usize {
                        return out;
                    }
                }
            }
        }
        if out.len() < limit as usize {
            if let Ok(rows) = self
                .suggest_template_names_like(needle, user_id, limit)
                .await
            {
                for n in rows {
                    let key = n.to_lowercase();
                    if seen.insert(key) {
                        out.push(n);
                        if out.len() >= limit as usize {
                            return out;
                        }
                    }
                }
            }
        }
        out
    }

    /// Phase 5: final fallback for module-name suggestions — first N
    /// alphabetical.
    ///
    /// MCP-956 (2026-05-15): scope by user (catalog + user's own) so
    /// the alphabetical fallback can't enumerate other tenants'
    /// module names.
    pub async fn list_template_names_alphabetical(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<String>> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM modules \
             WHERE user_id IS NULL OR user_id = $1 \
             ORDER BY name ASC LIMIT $2",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    // ── platform.rs export/import support ──────────────────────────────────

    /// Phase 5: look up module name for each id. Used by
    /// `export_platform_state` to build the module manifest mapping
    /// old_uuid → name. 3-shape id match handles legacy UUIDs.
    pub async fn list_template_names_by_ids(&self, ids: &[Uuid]) -> Result<Vec<(Uuid, String)>> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, name FROM modules \
             WHERE id = ANY($1)",
        )
        .bind(ids)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    /// Phase 5.1: look up user-owned module names for each id. Used by
    /// `export_platform_state` to mark sandbox-source modules in the
    /// manifest.
    pub async fn list_user_wasm_module_names_by_ids(
        &self,
        ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<Vec<(Uuid, String)>> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, name FROM modules \
             WHERE id = ANY($1) \
               AND user_id = $2",
        )
        .bind(ids)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    /// Phase 5: all modules the user can resolve for import remap — their
    /// own first, then catalog modules (`user_id IS NULL`). Sort key
    /// ensures user-installed rows come first so the caller's HashMap-insert
    /// preserves them on collision.
    pub async fn list_templates_for_import_remap(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(Uuid, String, Option<Uuid>)>> {
        let rows: Vec<(Uuid, String, Option<Uuid>)> = sqlx::query_as(
            "SELECT id, name, user_id FROM modules \
             WHERE user_id = $1 OR user_id IS NULL \
             ORDER BY (user_id IS NULL) ASC",
            // false < true → user-installed (user_id IS NULL = false) sorts first
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    /// Phase 5: most-recent capability_world per module in the given id
    /// set. Used by `get_platform_info` to count catalog tools visible
    /// to the agent. After Phase 4's graph rewrite every reference is a
    /// canonical `modules.id`, so this is a straight SELECT.
    pub async fn list_template_world_overrides(
        &self,
        template_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, String)>> {
        if template_ids.is_empty() {
            return Ok(vec![]);
        }
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, capability_world FROM modules \
             WHERE id = ANY($1)",
        )
        .bind(template_ids)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    // ── sandbox.rs / compile / hot_update / replay support ────────────────

    /// Latest completed module_executions IO for a user-owned module.
    /// Returns (input_data, output_data). Used by `generate_typed_scaffold`
    /// to seed scrubbed I/O samples from a sibling module's history.
    pub async fn find_latest_completed_execution_io(
        &self,
        module_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<(Option<serde_json::Value>, Option<serde_json::Value>)>> {
        // Fetch both plaintext and ciphertext columns; read_module_payload
        // chooses the right one based on whether SecretsManager is wired.
        // `id` + `payload_format` are required to rebuild the per-row,
        // per-slot AAD (see read_module_payload).
        let row: Option<(
            Uuid,
            Option<serde_json::Value>,
            Option<serde_json::Value>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<Uuid>,
            i16,
        )> = sqlx::query_as(
            "SELECT id, input_data, output_data, input_data_enc, output_data_enc, payload_enc_key_id, payload_format \
             FROM module_executions \
             WHERE module_id = $1 AND user_id = $2 AND status = 'completed' \
             ORDER BY completed_at DESC NULLS LAST, started_at DESC \
             LIMIT 1",
        )
        .bind(module_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        let Some((id, pt_in, pt_out, enc_in, enc_out, kid, fmt)) = row else {
            return Ok(None);
        };
        use talos_module_payload_encryption::PayloadSlot;
        let input = self
            .read_module_payload(id, PayloadSlot::Input, pt_in, enc_in, kid, fmt)
            .await?;
        let output = self
            .read_module_payload(id, PayloadSlot::Output, pt_out, enc_out, kid, fmt)
            .await?;
        Ok(Some((input, output)))
    }

    /// Phase 5: source-hash cache lookup for `compile_custom_sandbox`.
    /// Returns (modules.id, wasm_bytes) when an identical source+world+user
    /// combo already has a compiled module. The modules table stores
    /// capability_world in the long form (`minimal-node`), so callers
    /// passing the short form get normalised here.
    pub async fn find_compiled_sandbox_template(
        &self,
        user_id: Option<Uuid>,
        code_template: &str,
        capability_world_short: &str,
    ) -> Result<Option<(Uuid, Vec<u8>)>> {
        let cw_long = if capability_world_short == "trusted" {
            "automation-node".to_string()
        } else if capability_world_short.ends_with("-node") {
            capability_world_short.to_string()
        } else {
            format!("{}-node", capability_world_short)
        };
        let row: Option<(Uuid, Vec<u8>)> = sqlx::query_as(
            "SELECT id, wasm_bytes FROM modules \
             WHERE user_id = $1 AND source_code = $2 \
               AND (capability_world = $3 OR capability_world = $4) \
               AND wasm_bytes IS NOT NULL AND octet_length(wasm_bytes) > 0 \
             LIMIT 1",
        )
        .bind(user_id)
        .bind(code_template)
        .bind(&cw_long)
        .bind(capability_world_short)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row)
    }

    /// True if a sandbox node_templates row already exists with this name+user.
    /// Used by `compile_custom_sandbox` to fail fast on duplicates before
    /// burning 30-60s on compilation. Phase 3.2: queries unified modules
    /// table (kind='sandbox' or kind='extracted' since both are user-authored).
    pub async fn sandbox_template_name_exists(
        &self,
        name: &str,
        user_id: Option<Uuid>,
    ) -> Result<bool> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS( \
               SELECT 1 FROM modules \
               WHERE name = $1 AND user_id = $2 AND kind IN ('sandbox', 'extracted') \
             )",
        )
        .bind(name)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(exists)
    }

    /// Phase 5: true if a module row already exists with this name+user.
    /// Used by `compile_template` for early collision detection.
    pub async fn wasm_module_name_exists(&self, name: &str, user_id: Uuid) -> Result<bool> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS( \
               SELECT 1 FROM modules \
               WHERE name = $1 AND user_id = $2 \
             )",
        )
        .bind(name)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(exists)
    }

    // Phase 5: `insert_sandbox_node_template`, `find_node_template_id_by_name`,
    // and `upsert_wasm_module_for_sandbox_compile` were removed — they wrote
    // exclusively to the legacy `node_templates` / `wasm_modules` tables.
    // All compile / install / hot-update paths now route through
    // `mirror_module_write` (or `install_catalog_module_to_modules` /
    // `compile_custom_sandbox`'s modules-only INSERT) and no longer touch
    // the legacy tables.

    /// Resolve a module's canonical `modules.id`. Phase 5.1: queries the
    /// unified modules table by canonical id.
    pub async fn find_wasm_module_id_by_template(
        &self,
        template_id: Uuid,
        user_id: Option<Uuid>,
    ) -> Result<Option<Uuid>> {
        let row: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM modules \
             WHERE id = $1 \
               AND ($2::uuid IS NULL OR user_id = $2 OR user_id IS NULL) \
             ORDER BY compiled_at DESC NULLS LAST LIMIT 1",
        )
        .bind(template_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row.map(|(id,)| id))
    }

    // ── Module entity unification mirror types ──

    // Defined as a separate item rather than associated `pub struct` so
    // call sites can construct it inline with named-field syntax. Keep the
    // field order matching the SQL bind order in `mirror_module_write` for
    // grep-ability.

    /// Phase 1.2 of module entity unification (docs/module-entity-consolidation.md):
    /// mirror a successful module write (compile / install / hot-update /
    /// inline-extract) into the new `modules` table. Reads still flow
    /// through `wasm_modules` / `node_templates`; this is purely
    /// write-side dual-write so the new table stays current.
    ///
    /// `kind` MUST be one of `"catalog"`, `"sandbox"`, `"extracted"` —
    /// matches the CHECK constraint on the table. Caller passes the
    /// classification appropriate to the write path:
    ///   - `compile_custom_sandbox`           → `"sandbox"`
    ///   - `install_module_from_catalog`      → `"catalog"` (or `"sandbox"` for re-installs into a user's namespace)
    ///   - `hot_update_module`                → preserve existing row's kind via DO UPDATE
    ///   - `add_node_to_workflow rust_code`   → `"extracted"`
    ///
    /// Best-effort. Failures are logged at WARN by the caller — the
    /// reconciliation job (Phase 1.3) sweeps anything missed here.
    /// Idempotent: ON CONFLICT DO UPDATE keeps subsequent writes in sync.
    #[allow(clippy::too_many_arguments)]
    pub async fn mirror_sandbox_compile_to_modules(
        &self,
        wasm_module_id: Uuid,
        template_id: Uuid,
        user_id: Option<Uuid>,
        name: &str,
        kind: &str,
        capability_world_short: &str,
        wasm_bytes: &[u8],
        content_hash: &str,
        rust_code: &str,
        max_fuel: i64,
        allowed_hosts: &[String],
        allowed_methods: &[String],
        allowed_secrets: &[String],
        integration_name: Option<&str>,
        dependencies: Option<&serde_json::Value>,
        language: &str,
    ) -> Result<()> {
        // Convenience overload: callers with no extra metadata
        // (max_memory_mb, imported_interfaces, config) get sensible
        // defaults. Use mirror_module_write for full control.
        //
        // L-5/L-33: `dependencies` is now passed through (was hardcoded
        // None pre-fix, dropping the inline-compile sandbox dep set).
        self.mirror_module_write(ModuleMirrorWrite {
            wasm_module_id,
            template_id,
            user_id,
            name,
            kind,
            capability_world_short,
            wasm_bytes,
            content_hash,
            rust_code,
            max_fuel,
            max_memory_mb: 128,
            allowed_hosts,
            allowed_methods,
            allowed_secrets,
            imported_interfaces: &[],
            dependencies,
            config: None,
            integration_name,
            language,
        })
        .await
    }

    /// Full-control mirror used by the rare callers that have the new
    /// Phase 1.4 metadata (max_memory_mb override, dependencies,
    /// imported_interfaces, config) at hand. Most callers should use
    /// `mirror_sandbox_compile_to_modules` and let the defaults kick in;
    /// the reconciliation sweep + Phase 1.4 backfill have already
    /// populated existing rows from the legacy tables.
    pub async fn mirror_module_write<'a>(&self, spec: ModuleMirrorWrite<'a>) -> Result<()> {
        // Defensive: refuse unknown kind values rather than letting the DB
        // CHECK fail with a generic error. Callers know exactly which kind
        // they meant.
        if !matches!(spec.kind, "catalog" | "sandbox" | "extracted") {
            return Err(anyhow::anyhow!(
                "mirror_module_write: invalid kind '{}' (must be catalog|sandbox|extracted)",
                spec.kind
            ));
        }
        // Re-bind the spec fields locally so the existing SQL block below
        // can keep its variable names without the `spec.` prefix sprinkled
        // through every bind.
        let wasm_module_id = spec.wasm_module_id;
        let template_id = spec.template_id;
        let user_id = spec.user_id;
        let name = spec.name;
        let kind = spec.kind;
        let capability_world_short = spec.capability_world_short;
        let wasm_bytes = spec.wasm_bytes;
        let content_hash = spec.content_hash;
        let rust_code = spec.rust_code;
        let max_fuel = spec.max_fuel;
        let max_memory_mb = spec.max_memory_mb;
        let allowed_hosts = spec.allowed_hosts;
        let allowed_methods = spec.allowed_methods;
        let allowed_secrets = spec.allowed_secrets;
        let imported_interfaces = spec.imported_interfaces;
        let dependencies = spec.dependencies;
        let config = spec.config;
        let integration_name = spec.integration_name;
        let language = spec.language;
        // capability_world is stored in long form (`secrets-node`) on the
        // new modules table to match the worker's CapabilityWorld parser.
        // wasm_modules stores the short form (`secrets`); convert here.
        let cw_long = if capability_world_short == "trusted" {
            "automation-node".to_string()
        } else if capability_world_short.ends_with("-node") {
            capability_world_short.to_string()
        } else {
            format!("{}-node", capability_world_short)
        };

        // ON CONFLICT preserves the existing `kind` (via COALESCE check
        // on the conflict row) so a hot_update of an `extracted` module
        // doesn't silently re-classify it as `sandbox`. The kind column
        // is intentionally NOT in the SET list for the same reason.
        // Phase 5.1: legacy_template_id / legacy_wasm_module_id columns
        // dropped; `template_id` arg is no longer bound (kind for
        // back-compat with callers). `_ = template_id;` silences the
        // unused-var warning without changing the signature.
        let _ = template_id;
        let res = sqlx::query(
            "INSERT INTO modules ( \
                id, user_id, name, kind, capability_world, \
                allowed_hosts, allowed_methods, allowed_secrets, \
                source_code, wasm_bytes, content_hash, size_bytes, max_fuel, \
                max_memory_mb, imported_interfaces, dependencies, config, \
                integration_name, language, \
                created_at, compiled_at, updated_at \
             ) VALUES ( \
                $1, $2, $3, $14, $4, \
                $5, $6, $7, \
                $8, $9, $10, $11, $12, \
                $15, $16, $17, $18, \
                $13, $19, \
                NOW(), NOW(), NOW() \
             ) \
             ON CONFLICT (id) DO UPDATE SET \
                name = EXCLUDED.name, \
                capability_world = EXCLUDED.capability_world, \
                source_code = EXCLUDED.source_code, \
                wasm_bytes = EXCLUDED.wasm_bytes, \
                content_hash = EXCLUDED.content_hash, \
                size_bytes = EXCLUDED.size_bytes, \
                max_fuel = EXCLUDED.max_fuel, \
                /* language follows the recompile: a hot-update that switches \
                   source language (rust rewrite of a js module, etc.) must \
                   update the routing metadata or the NEXT hot-update would \
                   re-route compilation to the wrong toolchain. */ \
                language = EXCLUDED.language, \
                /* max_memory_mb: preserve existing value (CASE WHEN guard) — \
                   default 128 from new INSERT shouldn't overwrite an operator- \
                   tuned ceiling on hot-update. Use COALESCE NULLIF since \
                   default is non-NULL. */ \
                max_memory_mb = CASE WHEN EXCLUDED.max_memory_mb = 128 \
                                     THEN modules.max_memory_mb \
                                     ELSE EXCLUDED.max_memory_mb END, \
                imported_interfaces = COALESCE( \
                    NULLIF(EXCLUDED.imported_interfaces, '{}'), \
                    modules.imported_interfaces), \
                dependencies = COALESCE(EXCLUDED.dependencies, modules.dependencies), \
                config = COALESCE(EXCLUDED.config, modules.config), \
                compiled_at = NOW(), \
                updated_at = NOW() \
             /* INTENTIONALLY OMITTED from SET list — preserve existing values: \
                  - allowed_hosts/methods/secrets: permission changes go through \
                    their own audited paths (update_module_allowed_secrets etc.). \
                    Letting hot-updates overwrite would silently drop grants when \
                    the caller didn't supply them. \
                  - integration_name: changing the namespace would strand every \
                    integration_state row written under the old name. \
                  - kind: hot-updating an `extracted` module must NOT reclassify \
                    it as `sandbox`. */ \
             /* Defense-in-depth ownership guard: if a caller accidentally \
                passes an `id` that collides with a row owned by a different \
                user, the WHERE predicate filters the UPDATE out — we do \
                NOT silently clobber another user's module. `IS NOT DISTINCT \
                FROM` handles the NULL-NULL case (catalog modules). \
                Caller bails on 0 rows_affected below. */ \
             WHERE modules.user_id IS NOT DISTINCT FROM EXCLUDED.user_id",
        )
        .bind(wasm_module_id)
        .bind(user_id)
        .bind(name)
        .bind(cw_long)
        .bind(allowed_hosts)
        .bind(allowed_methods)
        .bind(allowed_secrets)
        .bind(rust_code)
        .bind(wasm_bytes)
        .bind(content_hash)
        .bind(wasm_bytes.len() as i32)
        .bind(max_fuel)
        .bind(integration_name)
        .bind(kind)
        .bind(max_memory_mb)
        .bind(imported_interfaces)
        .bind(dependencies)
        .bind(config)
        .bind(language)
        .execute(&self.db_pool)
        .await?;
        // rows_affected == 0 means the INSERT conflicted on `id` AND the
        // UPDATE's WHERE filtered it out — the conflicting row is owned
        // by a DIFFERENT user. Bail loudly rather than let the caller
        // assume the write succeeded.
        if res.rows_affected() == 0 {
            return Err(anyhow::anyhow!(
                "mirror_module_write: module id {} is owned by a \
                 different user — refusing to overwrite",
                wasm_module_id
            ));
        }
        Ok(())
    }

    /// Phase 3.2 install path: write a catalog-installed module to the
    /// unified `modules` table directly, with install-specific UPSERT
    /// semantics that DO refresh permission columns (unlike the
    /// hot-update mirror, which intentionally preserves them). Returns
    /// (modules.id, stored_allowed_secrets) — the caller surfaces both
    /// in the install response.
    ///
    /// Re-install pattern: a user re-installing the same catalog
    /// template by name lands on the existing `(user_id, name)` row,
    /// keeping the same modules.id so workflows that reference it
    /// continue to resolve. Permissions are refreshed from the latest
    /// install args (matching the legacy ON CONFLICT semantic).
    #[allow(clippy::too_many_arguments)]
    pub async fn install_catalog_module_to_modules(
        &self,
        user_id: Option<Uuid>,
        name: &str,
        capability_world_short: &str,
        wasm_bytes: &[u8],
        content_hash: &str,
        rust_code: &str,
        max_fuel: i64,
        allowed_hosts: &[String],
        allowed_methods: &[String],
        allowed_secrets: &[String],
        requires_approval_for: &[String],
        config_schema: &serde_json::Value,
        catalog_slug: Option<&str>,
    ) -> Result<CatalogInstallResult> {
        let cw_long = if capability_world_short == "trusted" {
            "automation-node".to_string()
        } else if capability_world_short.ends_with("-node") {
            capability_world_short.to_string()
        } else {
            format!("{}-node", capability_world_short)
        };

        // CTE pattern: capture prior content_hash in the SAME statement as the
        // upsert. `prev` and `upsert` see the same snapshot so the
        // `bytes_changed` flag is race-free under concurrent installs of the
        // same module — a separate SELECT-then-UPSERT would have a TOCTOU
        // window.
        //
        // RETURNING includes compiled_at + content_hash + bytes_changed so
        // callers can verify "the WASM I just installed is actually the one
        // I expected to install" without having to follow up with a
        // get_module_info call. Surfaced through MCP as the recompile
        // receipt added 2026-04-30 (post-watch-ghas debug session).
        let row: (Uuid, Vec<String>, String, chrono::DateTime<chrono::Utc>, bool) =
            sqlx::query_as(
                "WITH prev AS ( \
                    SELECT content_hash AS prev_hash \
                    FROM modules \
                    WHERE user_id = $1 AND name = $2 \
                 ), upsert AS ( \
                    INSERT INTO modules ( \
                        user_id, name, kind, capability_world, config_schema, \
                        allowed_hosts, allowed_methods, allowed_secrets, requires_approval_for, \
                        source_code, wasm_bytes, content_hash, size_bytes, max_fuel, \
                        catalog_slug, language, created_at, compiled_at, updated_at \
                     ) VALUES ( \
                        $1, $2, 'catalog', $3, $4, \
                        $5, $6, $7, $8, \
                        $9, $10, $11, $12, $13, \
                        $14, 'rust', NOW(), NOW(), NOW() \
                     ) \
                     ON CONFLICT (user_id, name) WHERE user_id IS NOT NULL DO UPDATE SET \
                        capability_world = EXCLUDED.capability_world, \
                        catalog_slug = COALESCE(EXCLUDED.catalog_slug, modules.catalog_slug), \
                        config_schema = EXCLUDED.config_schema, \
                        allowed_hosts = EXCLUDED.allowed_hosts, \
                        allowed_methods = EXCLUDED.allowed_methods, \
                        allowed_secrets = EXCLUDED.allowed_secrets, \
                        requires_approval_for = EXCLUDED.requires_approval_for, \
                        source_code = EXCLUDED.source_code, \
                        wasm_bytes = EXCLUDED.wasm_bytes, \
                        content_hash = EXCLUDED.content_hash, \
                        size_bytes = EXCLUDED.size_bytes, \
                        max_fuel = EXCLUDED.max_fuel, \
                        compiled_at = NOW(), \
                        updated_at = NOW() \
                     RETURNING id, allowed_secrets, content_hash, compiled_at \
                 ) \
                 SELECT \
                    upsert.id, \
                    upsert.allowed_secrets, \
                    upsert.content_hash, \
                    upsert.compiled_at, \
                    COALESCE(prev.prev_hash IS DISTINCT FROM upsert.content_hash, true) AS bytes_changed \
                 FROM upsert LEFT JOIN prev ON true",
            )
            .bind(user_id)
            .bind(name)
            .bind(cw_long)
            .bind(config_schema)
            .bind(allowed_hosts)
            .bind(allowed_methods)
            .bind(allowed_secrets)
            .bind(requires_approval_for)
            .bind(rust_code)
            .bind(wasm_bytes)
            .bind(content_hash)
            .bind(wasm_bytes.len() as i32)
            .bind(max_fuel)
            .bind(catalog_slug)
            .fetch_one(&self.db_pool)
            .await?;
        Ok(CatalogInstallResult {
            module_id: row.0,
            allowed_secrets: row.1,
            content_hash: row.2,
            compiled_at: row.3,
            bytes_changed: row.4,
        })
    }

    /// Platform catalog rows (user_id IS NULL, kind='catalog') for the
    /// get_catalog_status diagnostic — name, origin slug, category. Catalog
    /// rows are deployment-shared metadata (no tenant content), safe for any
    /// authenticated caller to enumerate.
    pub async fn list_catalog_rows(&self) -> Result<Vec<(String, Option<String>, String)>> {
        let rows = sqlx::query(
            "SELECT name, catalog_slug, COALESCE(category, 'General') AS category \
             FROM modules WHERE user_id IS NULL AND kind = 'catalog' ORDER BY name",
        )
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(|r| -> Result<(String, Option<String>, String)> {
                Ok((
                    r.try_get("name")?,
                    r.try_get::<Option<String>, _>("catalog_slug")?,
                    r.try_get("category")?,
                ))
            })
            .collect()
    }

    /// Phase 5: reconciliation sweep is now a no-op. The legacy tables it
    /// used to read from (`wasm_modules`, `node_templates`) are being
    /// dropped in the Phase 5 migration — there are no un-mirrored rows
    /// to backfill. Signature preserved for `main.rs` caller stability;
    /// the background task loop will simply see (0, 0) each tick.
    pub async fn reconcile_modules_table(&self) -> Result<(u64, u64)> {
        Ok((0, 0))
    }

    /// Operator tool support: snapshot of the module entity unification
    /// state. Used by `get_module_unification_status` to surface drift
    /// between the new `modules` table and the legacy pair, plus
    /// per-kind counts. Read-only; runs in <10ms even on a fully
    /// populated DB (the COUNT-based queries hit indexes).
    pub async fn module_unification_snapshot(&self) -> Result<ModuleUnificationSnapshot> {
        // One round-trip per logical question — the DB optimizer will
        // batch them in the same connection. Could be a single CTE for
        // marginal speed, but readability + ease of modification wins.
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM modules")
            .fetch_one(&self.db_pool)
            .await
            .unwrap_or(0);
        let by_kind_rows: Vec<(String, i64)> =
            sqlx::query_as("SELECT kind, COUNT(*) FROM modules GROUP BY kind")
                .fetch_all(&self.db_pool)
                .await
                .unwrap_or_default();
        let mut by_kind = std::collections::HashMap::new();
        for (k, c) in by_kind_rows {
            by_kind.insert(k, c);
        }

        // Phase 5.1: legacy alias columns dropped; both counts structurally 0
        // since the modules table is now the only source of truth.
        let wasm_modules: i64 = 0;
        let node_templates: i64 = 0;

        // Drift counts: structurally 0 post-Phase-3.2 (the modules table is
        // the only write target). These fields are kept on the snapshot for
        // operator-tool API stability.
        let wasm_unmirrored: i64 = 0;
        let template_unmirrored: i64 = 0;

        // Phase 1.4 column population — operators want to see how much of
        // the corpus has been backfilled with the new metadata so they can
        // judge Phase 3 readiness for the field-loss aspect.
        let phase14_dependencies_set: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM modules WHERE dependencies IS NOT NULL")
                .fetch_one(&self.db_pool)
                .await
                .unwrap_or(0);
        let phase14_imports_set: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM modules WHERE array_length(imported_interfaces, 1) > 0",
        )
        .fetch_one(&self.db_pool)
        .await
        .unwrap_or(0);

        Ok(ModuleUnificationSnapshot {
            total,
            by_kind,
            wasm_modules,
            node_templates,
            wasm_unmirrored,
            template_unmirrored,
            phase14_dependencies_set,
            phase14_imports_set,
        })
    }

    /// Phase 5: stored `dependencies` JSONB on a module. Used by
    /// `hot_update_module` to re-inject the same third-party crates at
    /// recompile time. 3-shape id match accepts legacy aliases.
    pub async fn get_template_dependencies(
        &self,
        template_id: Uuid,
    ) -> Result<Option<serde_json::Value>> {
        let deps: Option<Option<serde_json::Value>> = sqlx::query_scalar(
            "SELECT dependencies FROM modules \
             WHERE id = $1 \
             LIMIT 1",
        )
        .bind(template_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(deps.flatten())
    }

    /// Phase 5: same storage as `get_template_dependencies` now that the
    /// modules table is the single source of truth. Kept as a distinct
    /// helper so the two hot-update code paths (template-first vs
    /// module-first) stay independently greppable; both delegate to the
    /// same SELECT.
    pub async fn get_wasm_module_dependencies(
        &self,
        module_id: Uuid,
    ) -> Result<Option<serde_json::Value>> {
        self.get_template_dependencies(module_id).await
    }

    /// Phase 5: dead write path — the sandbox branch of `hot_update_module`
    /// now routes through `mirror_module_write`. Stub preserved for caller
    /// signature stability.
    pub async fn update_sandbox_template_after_hot_update(
        &self,
        _template_id: Uuid,
        _wasm_bytes: &[u8],
        _source_code: &str,
        _capability_world: &str,
    ) -> Result<()> {
        Ok(())
    }

    /// Phase 5: `(allowed_secrets, allowed_hosts)` projected from the
    /// unified modules table. Used by `hot_update_module` to preserve
    /// permissions across recompiles.
    pub async fn get_template_secrets_and_hosts(
        &self,
        template_id: Uuid,
    ) -> Result<(Vec<String>, Vec<String>)> {
        let row: Option<(Vec<String>, Vec<String>)> = sqlx::query_as(
            "SELECT allowed_secrets, allowed_hosts FROM modules \
             WHERE id = $1 \
             LIMIT 1",
        )
        .bind(template_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row.unwrap_or_default())
    }

    /// Phase 5: stored integration_name on a module — used by
    /// `hot_update_module` to preserve the namespace across recompiles.
    pub async fn get_template_integration_name(&self, template_id: Uuid) -> Result<Option<String>> {
        let row: Option<Option<String>> = sqlx::query_scalar(
            "SELECT integration_name FROM modules \
             WHERE id = $1 \
             LIMIT 1",
        )
        .bind(template_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row.flatten())
    }

    /// Phase 5: dead write path — the compiled-module branch of
    /// `hot_update_module` now routes through `mirror_module_write`.
    /// Stub preserved for caller signature stability. Returns 1 to match
    /// the old "one row updated" success signal so callers' rows-affected
    /// checks don't mistake this for a miss.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_wasm_module_after_hot_update(
        &self,
        _wasm_module_id: Uuid,
        _user_id: Uuid,
        _wasm_bytes: &[u8],
        _content_hash: &str,
        _source_code: &str,
        _config: &serde_json::Value,
        _size_bytes: i32,
        _max_fuel: Option<i64>,
    ) -> Result<u64> {
        Ok(1)
    }

    /// Phase 5: dead write path — compiled-module hot-update routes
    /// through `mirror_module_write`. Stub preserved for caller signature
    /// stability.
    pub async fn update_template_precompiled_wasm_by_id(
        &self,
        _template_id: Uuid,
        _wasm_bytes: &[u8],
    ) -> Result<()> {
        Ok(())
    }

    /// Most-recent `new_hash` from `module_update_history` for a module —
    /// used by `hot_update_module` to chain history entries when the module
    /// is sandbox-only (no wasm_modules.content_hash to chain from).
    pub async fn last_history_hash_for_module(&self, module_id: Uuid) -> Result<Option<String>> {
        let row: Option<String> = sqlx::query_scalar(
            "SELECT new_hash FROM module_update_history \
             WHERE module_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(module_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row)
    }

    /// Insert a `module_update_history` audit row.
    pub async fn insert_module_update_history(
        &self,
        module_id: Uuid,
        user_id: Uuid,
        previous_hash: &str,
        new_hash: &str,
        size_bytes: i32,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO module_update_history (module_id, user_id, previous_hash, new_hash, size_bytes) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(module_id)
        .bind(user_id)
        .bind(previous_hash)
        .bind(new_hash)
        .bind(size_bytes)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// Find non-archived workflows that reference a module by EITHER its
    /// wasm_modules.id OR its template_id (the dual-UUID problem). Returns
    /// (workflow_id, name, owning_user_id) so the post-hot-update validator
    /// can run with the workflow's actual owner. Capped at 50 rows.
    pub async fn find_dependent_workflows_dual_id(
        &self,
        module_id: Uuid,
        template_id: Option<Uuid>,
    ) -> Result<Vec<(Uuid, String, Uuid)>> {
        let pattern_self = format!("%{}%", module_id);
        let pattern_template = template_id.map(|tid| format!("%{}%", tid));
        let rows: Vec<(Uuid, String, Uuid)> = match &pattern_template {
            Some(pt) if pt != &pattern_self => {
                sqlx::query_as(
                    "SELECT id, name, user_id FROM workflows \
                 WHERE (graph_json LIKE $1 OR graph_json LIKE $2) \
                   AND (status IS NULL OR status != 'archived') \
                 ORDER BY updated_at DESC LIMIT 50",
                )
                .bind(&pattern_self)
                .bind(pt)
                .fetch_all(&self.db_pool)
                .await?
            }
            _ => {
                sqlx::query_as(
                    "SELECT id, name, user_id FROM workflows \
                 WHERE graph_json LIKE $1 \
                   AND (status IS NULL OR status != 'archived') \
                 ORDER BY updated_at DESC LIMIT 50",
                )
                .bind(&pattern_self)
                .fetch_all(&self.db_pool)
                .await?
            }
        };
        Ok(rows)
    }

    /// M3 (2026-05-22): variant of `find_dependent_workflows_dual_id` that
    /// also returns each dependent workflow's `actor_id` so the
    /// hot-update service can enforce a capability-world ceiling against
    /// every actor that currently binds the module.
    ///
    /// Returns (workflow_id, workflow_name, Option<actor_id>). Workflows
    /// without an actor_id pass through as `None` — they don't impose a
    /// ceiling. Same 50-row cap and same dual-UUID matcher as the sibling
    /// method; kept as a separate query so callers that don't care about
    /// actor_id pay nothing.
    pub async fn find_dependent_workflows_with_actors_dual_id(
        &self,
        module_id: Uuid,
        template_id: Option<Uuid>,
    ) -> Result<Vec<(Uuid, String, Option<Uuid>)>> {
        let pattern_self = format!("%{}%", module_id);
        let pattern_template = template_id.map(|tid| format!("%{}%", tid));
        let rows: Vec<(Uuid, String, Option<Uuid>)> = match &pattern_template {
            Some(pt) if pt != &pattern_self => {
                sqlx::query_as(
                    "SELECT id, name, actor_id FROM workflows \
                 WHERE (graph_json LIKE $1 OR graph_json LIKE $2) \
                   AND (status IS NULL OR status != 'archived') \
                 ORDER BY updated_at DESC LIMIT 50",
                )
                .bind(&pattern_self)
                .bind(pt)
                .fetch_all(&self.db_pool)
                .await?
            }
            _ => {
                sqlx::query_as(
                    "SELECT id, name, actor_id FROM workflows \
                 WHERE graph_json LIKE $1 \
                   AND (status IS NULL OR status != 'archived') \
                 ORDER BY updated_at DESC LIMIT 50",
                )
                .bind(&pattern_self)
                .fetch_all(&self.db_pool)
                .await?
            }
        };
        Ok(rows)
    }

    /// Phase 5: update `allowed_secrets` on the unified `modules` table.
    /// Returns `(rows, 0)` for signature stability with callers that
    /// expected the pre-Phase-5 `(node_templates_rows, wasm_modules_rows)`
    /// tuple shape — the second value is always 0 now. Callers detect
    /// "module not found" via `rows == 0`.
    pub async fn update_module_allowed_secrets(
        &self,
        module_id: Uuid,
        user_id: Uuid,
        allowed_secrets: &[String],
    ) -> Result<(u64, u64)> {
        let result = sqlx::query(
            "UPDATE modules SET allowed_secrets = $1 \
             WHERE id = $2 \
               AND user_id = $3",
        )
        .bind(allowed_secrets)
        .bind(module_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;

        Ok((result.rows_affected(), 0))
    }

    /// Companion to `update_module_allowed_secrets`: replace the
    /// `allowed_hosts` column on a user-owned module. Returns rows
    /// affected (0 = not found / not owned, caller surfaces as a
    /// permission-denied-shaped error).
    pub async fn update_module_allowed_hosts(
        &self,
        module_id: Uuid,
        user_id: Uuid,
        allowed_hosts: &[String],
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE modules SET allowed_hosts = $1 \
             WHERE id = $2 \
               AND user_id = $3",
        )
        .bind(allowed_hosts)
        .bind(module_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Companion to `update_module_allowed_secrets`: replace the
    /// `allowed_methods` column on a user-owned module.
    pub async fn update_module_allowed_methods(
        &self,
        module_id: Uuid,
        user_id: Uuid,
        allowed_methods: &[String],
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE modules SET allowed_methods = $1 \
             WHERE id = $2 \
               AND user_id = $3",
        )
        .bind(allowed_methods)
        .bind(module_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// `workflow_executions JOIN workflows` graph_json fetch by execution id.
    /// Used by `lookup_node_config_for_module` to reconstruct the dispatch
    /// envelope for replay.
    pub async fn get_workflow_graph_via_execution_id(
        &self,
        execution_id: Uuid,
    ) -> Result<Option<String>> {
        let graph: Option<String> = sqlx::query_scalar(
            "SELECT w.graph_json FROM workflow_executions we \
             JOIN workflows w ON w.id = we.workflow_id \
             WHERE we.id = $1",
        )
        .bind(execution_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(graph)
    }

    /// Recent completed module_executions for replay. Returns
    /// (id, input_data, output_data, workflow_execution_id) per row.
    pub async fn list_completed_module_executions(
        &self,
        module_id: Uuid,
        user_id: Uuid,
        limit: i64,
    ) -> Result<
        Vec<(
            Uuid,
            Option<serde_json::Value>,
            Option<serde_json::Value>,
            Option<Uuid>,
        )>,
    > {
        // Same dual-column SELECT + decrypt cascade as
        // `find_latest_completed_execution_io`. `payload_format` is required
        // to rebuild the per-row, per-slot AAD (see read_module_payload).
        let raw: Vec<(
            Uuid,
            Option<serde_json::Value>, Option<serde_json::Value>,
            Option<Vec<u8>>, Option<Vec<u8>>, Option<Uuid>,
            Option<Uuid>,
            i16,
        )> = sqlx::query_as(
            "SELECT id, input_data, output_data, input_data_enc, output_data_enc, payload_enc_key_id, workflow_execution_id, payload_format \
             FROM module_executions \
             WHERE module_id = $1 AND user_id = $2 AND status = 'completed' \
             ORDER BY completed_at DESC NULLS LAST, started_at DESC \
             LIMIT $3",
        )
        .bind(module_id)
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        use talos_module_payload_encryption::PayloadSlot;
        let mut out = Vec::with_capacity(raw.len());
        for (id, pt_in, pt_out, enc_in, enc_out, kid, wf_id, fmt) in raw {
            let input = self
                .read_module_payload(id, PayloadSlot::Input, pt_in, enc_in, kid, fmt)
                .await?;
            let output = self
                .read_module_payload(id, PayloadSlot::Output, pt_out, enc_out, kid, fmt)
                .await?;
            out.push((id, input, output, wf_id));
        }
        Ok(out)
    }

    /// Recent completed workflow_executions with non-NULL output (plaintext
    /// OR encrypted) for `replay_workflow_mode`.
    ///
    /// MCP-680 (2026-05-13): pre-fix the SELECT pulled only
    /// `output_data` (plaintext column) and filtered `output_data IS NOT
    /// NULL`. `workflow_executions.mark_execution_completed` writes
    /// `output_data = NULL` on the encrypted branch (when
    /// SecretsManager is wired — which is the production default) and
    /// stores the JSON in `output_data_enc + output_enc_key_id`. So on
    /// every production deployment with encryption enabled, this query
    /// returned ZERO rows, and the `replay_workflow_mode` MCP tool
    /// silently reported "no executions to replay" even when the
    /// workflow had hundreds of completed runs. Sibling class to the
    /// `swallowed_error_unwrap_or_masks_broken_query.md` family but
    /// the failure mode is "WHERE predicate skips encrypted rows"
    /// rather than "column not exists swallowed".
    ///
    /// Fix: SELECT both column families, filter `(output_data IS NOT
    /// NULL OR output_data_enc IS NOT NULL)`, return all three columns
    /// to the caller. Decryption routes through `read_workflow_output`
    /// (id-bound AAD) before the value reaches the caller.
    pub async fn list_completed_workflow_executions_with_output(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<(Uuid, Option<serde_json::Value>)>> {
        // `output_data_format` is required to rebuild the id-bound AAD for
        // the workflow-output scheme (see read_workflow_output).
        let raw: Vec<(
            Uuid,
            Option<serde_json::Value>,
            Option<Vec<u8>>,
            Option<Uuid>,
            i16,
        )> = sqlx::query_as(
            "SELECT id, output_data, output_data_enc, output_enc_key_id, output_data_format \
             FROM workflow_executions \
             WHERE workflow_id = $1 AND user_id = $2 AND status = 'completed' \
               AND (output_data IS NOT NULL OR output_data_enc IS NOT NULL) \
             ORDER BY started_at DESC \
             LIMIT $3",
        )
        .bind(workflow_id)
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        let mut out = Vec::with_capacity(raw.len());
        for (id, plaintext, enc_bytes, key_id, fmt) in raw {
            let output = self
                .read_workflow_output(id, plaintext, enc_bytes, key_id, fmt)
                .await?;
            out.push((id, output));
        }
        Ok(out)
    }

    /// Phase 5: map of module name → id for a user. Used by the catalog
    /// listing handler to mark catalog entries as installed without N+1
    /// queries.
    pub async fn list_user_template_names(
        &self,
        user_id: Uuid,
    ) -> Result<std::collections::HashMap<String, Uuid>> {
        let rows = sqlx::query("SELECT id, name FROM modules WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await?;
        Ok(rows
            .into_iter()
            .filter_map(|row| {
                let name: String = row.try_get("name").ok()?;
                let id: Uuid = row.try_get("id").ok()?;
                Some((name, id))
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::normalise_capability_world;

    #[test]
    fn normalises_bare_form_to_suffixed() {
        assert_eq!(normalise_capability_world("minimal".into()), "minimal-node");
        assert_eq!(normalise_capability_world("http".into()), "http-node");
        assert_eq!(normalise_capability_world("agent".into()), "agent-node");
    }

    #[test]
    fn idempotent_on_suffixed_form() {
        assert_eq!(
            normalise_capability_world("minimal-node".into()),
            "minimal-node"
        );
        assert_eq!(
            normalise_capability_world("automation-node".into()),
            "automation-node"
        );
    }

    #[test]
    fn passes_through_unknown() {
        // Caller decides whether `unknown` is acceptable; we don't append a suffix.
        assert_eq!(normalise_capability_world("unknown".into()), "unknown");
    }
}
