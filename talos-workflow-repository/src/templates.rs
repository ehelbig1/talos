//! Node template + wasm module aggregate: template lookups,
//! compiled-wasm upserts, permissions, and export metadata.

use crate::*;

/// MCP-548: decode `allowed_secrets TEXT[]` from a Postgres row, logging
/// loudly on decode failure. The column is `NOT NULL DEFAULT '{}'` so a
/// decode error indicates real schema drift (TEXT[] → JSONB regression,
/// projection-loss, SQLx mapping change). Returning Vec::new() is
/// fail-closed (empty allowed_secrets denies every vault path via
/// `vault_path_permitted`), but the previous silent `unwrap_or_default()`
/// made the symptom indistinguishable from a module installed with no
/// secret grants. Surfacing the sqlx error lets operators tell apart
/// schema drift from a legitimately empty grant. Mirrors the helper
/// in `talos-registry`.
fn decode_allowed_secrets_row(
    row: &sqlx::postgres::PgRow,
    context_id: Option<Uuid>,
) -> Vec<String> {
    match row.try_get::<Vec<String>, _>("allowed_secrets") {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                target: "talos_workflow_repository",
                event_kind = "allowed_secrets_decode_failed",
                context_id = ?context_id,
                error = %e,
                "MCP-548: allowed_secrets column decode failed — falling back to empty (deny-all). \
                 Every vault path will be denied for this module until schema parity is restored."
            );
            Vec::new()
        }
    }
}

impl WorkflowRepository {
    // ── Module / capability ────────────────────────────────────────────────

    /// Batch-fetch the capability_world for a set of module IDs.
    /// Phase 5.1: queries the unified `modules` table by canonical id.
    pub async fn get_module_capability_worlds(
        &self,
        module_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, String>> {
        if module_ids.is_empty() {
            return Ok(HashMap::new());
        }
        // Project the input id back as the key so callers can lookup by
        let rows: Vec<(Uuid, String)> =
            sqlx::query_as("SELECT id, capability_world FROM modules WHERE id = ANY($1)")
                .bind(module_ids)
                .fetch_all(&self.db_pool)
                .await?;

        // Dedupe — multiple aliases to the same modules row may match the
        // same input_id; HashMap collapses them.
        Ok(rows.into_iter().collect())
    }

    /// Batch-fetch display names for a set of module IDs.
    /// Phase 3.2: queries the unified `modules` table.
    pub async fn get_module_names(&self, module_ids: &[Uuid]) -> Result<HashMap<Uuid, String>> {
        if module_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let rows: Vec<(Uuid, String)> =
            sqlx::query_as("SELECT id, name FROM modules WHERE id = ANY($1)")
                .bind(module_ids)
                .fetch_all(&self.db_pool)
                .await?;

        Ok(rows.into_iter().collect())
    }

    /// Return the subset of module_ids that are resolvable at execution time.
    ///
    /// Phase 5.1: single SELECT against unified modules table by canonical id.
    pub async fn modules_exist(&self, module_ids: &[Uuid]) -> Result<Vec<Uuid>> {
        if module_ids.is_empty() {
            return Ok(vec![]);
        }
        let rows: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM modules WHERE id = ANY($1)")
            .bind(module_ids)
            .fetch_all(&self.db_pool)
            .await?;

        Ok(rows)
    }

    // ── Node template helpers ─────────────────────────────────────────────

    // MCP-957 (2026-05-15): deleted dead `find_template_by_name(name)`
    // — unscoped `SELECT id FROM modules WHERE name = $1` with zero
    // call sites; same cross-tenant module-ID leak class as MCP-956
    // had it ever been used. Canonical scoped lookups live in
    // `ModuleRepository::find_template_id_by_name_ci(name, user_id)`.

    /// Find a node template that also has a compiled wasm payload
    /// (catalog templates compile once and are shared; user-private
    /// templates compile per owner).
    ///
    /// MCP-957 (2026-05-15): scoped by user. Pre-fix the SELECT was
    /// unscoped — `instantiate_workflow_pattern` would resolve a
    /// pattern's `module_name` against ANY tenant's compiled module
    /// row, producing a workflow whose `module_id` pointed at the
    /// foreign tenant's UUID. Downstream load would fail (the
    /// owning-user check on read denies cross-tenant access) but the
    /// failure mode was confusing and the cross-tenant UUID-by-name
    /// disclosure was a real info leak. Sibling-class fix to MCP-956
    /// on the workflow-repo side.
    ///
    /// Used by `instantiate_workflow_pattern` to avoid the class of bug
    /// where the resolver reports `missing_modules: []` because the
    /// name exists in `modules`, but the engine then fails at
    /// execution time because no `wasm_bytes` carries the
    /// compiled payload for that template. Returns `None` for templates
    /// that exist but haven't been compiled — callers should treat
    /// these as missing and surface them so users install or compile
    /// the module before instantiation.
    pub async fn find_compiled_template_by_name(
        &self,
        name: &str,
        user_id: Uuid,
    ) -> Result<Option<Uuid>> {
        // Phase 5.1: query the unified `modules` table. Compiled-ness is
        // signalled by a non-empty `wasm_bytes` column. Returns canonical id.
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id \
               FROM modules \
              WHERE name = $1 \
                AND wasm_bytes IS NOT NULL AND octet_length(wasm_bytes) > 0 \
                AND (user_id IS NULL OR user_id = $2) \
              LIMIT 1",
        )
        .bind(name)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(id)
    }

    /// Batch-fetch the *installed* allowed_secrets for a set of template IDs.
    ///
    /// Phase 5: queries the unified `modules` table. When multiple rows resolve
    /// under the same input id (e.g. different content_hash after source
    /// change), the most recent compiled_at wins. Returns a map keyed by the
    /// input id shape (callers index by what they passed in).
    pub async fn get_installed_secrets_by_template_ids(
        &self,
        template_ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<std::collections::HashMap<Uuid, Vec<String>>> {
        if template_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let rows = sqlx::query(
            "SELECT id AS template_id, allowed_secrets FROM modules \
             WHERE id = ANY($1) AND user_id = $2 \
             ORDER BY id, compiled_at DESC NULLS LAST",
        )
        .bind(template_ids)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(|r| {
                let tid: Uuid = r.try_get("template_id").ok()?;
                let secrets: Vec<String> = decode_allowed_secrets_row(&r, Some(tid));
                Some((tid, secrets))
            })
            .collect())
    }

    /// Batch-fetch node template metadata (name, config_schema, allowed_secrets).
    /// Phase 5.1: queries the unified modules table by canonical id.
    pub async fn get_templates_by_ids(&self, ids: &[Uuid]) -> Result<Vec<NodeTemplateRow>> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let rows = sqlx::query(
            "SELECT id, name, config_schema, allowed_secrets, allowed_hosts, max_retries, \
                    allowed_methods, capability_world \
             FROM modules \
             WHERE id = ANY($1)",
        )
        .bind(ids)
        .fetch_all(&self.db_pool)
        .await?;

        rows.into_iter()
            .map(|r| -> Result<NodeTemplateRow> {
                let id: Uuid = r.try_get("id")?;
                Ok(NodeTemplateRow {
                    id,
                    name: r.try_get("name")?,
                    config_schema: r
                        .try_get::<Option<_>, _>("config_schema")?
                        .unwrap_or(serde_json::json!({})),
                    allowed_secrets: decode_allowed_secrets_row(&r, Some(id)),
                    allowed_hosts: r
                        .try_get::<Option<_>, _>("allowed_hosts")?
                        .unwrap_or_default(),
                    max_retries: r.try_get::<Option<_>, _>("max_retries")?.unwrap_or(0),
                    allowed_methods: r
                        .try_get::<Option<_>, _>("allowed_methods")?
                        .unwrap_or_default(),
                    capability_world: r.try_get::<Option<_>, _>("capability_world")?,
                })
            })
            .collect()
    }

    /// Find a module by display name (case-insensitive) — for swap_node_module.
    ///
    /// Phase 5.1: queries the unified `modules` table by canonical id.
    /// Prefers the caller's user-installed instance over the system-seeded
    /// catalog row when both exist. Without this preference the swap would
    /// land on `user_id IS NULL` rows the caller can't `hot_update_module`,
    /// so fuel/config tuning would silently fail post-swap.
    pub async fn find_template_by_display_name(
        &self,
        display_name: &str,
        user_id: Uuid,
    ) -> Result<Option<NodeTemplateRow>> {
        let row = sqlx::query(
            "SELECT id, name, config_schema, \
                    allowed_secrets, max_retries \
             FROM modules \
             WHERE LOWER(name) = LOWER($1) \
               AND (user_id = $2 OR user_id IS NULL) \
             ORDER BY (user_id IS NOT NULL) DESC, created_at DESC \
             LIMIT 1",
        )
        .bind(display_name)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        row.map(|r| -> Result<NodeTemplateRow> {
            let id: Uuid = r.try_get("id")?;
            Ok(NodeTemplateRow {
                id,
                name: r.try_get("name")?,
                config_schema: r
                    .try_get::<Option<_>, _>("config_schema")?
                    .unwrap_or(serde_json::json!({})),
                allowed_secrets: decode_allowed_secrets_row(&r, Some(id)),
                // Not selected on this path (swap_node_module doesn't need egress
                // hosts or retry-default inputs; effective_max_retries() on this
                // row fails closed to the explicit column value).
                allowed_hosts: Vec::new(),
                max_retries: r.try_get::<Option<_>, _>("max_retries")?.unwrap_or(0),
                allowed_methods: Vec::new(),
                capability_world: None,
            })
        })
        .transpose()
    }

    /// Find a node template by name for a specific user (used by inline compilation).
    /// Phase 3.2: queries the unified modules table (kind='extracted' is what
    /// add_node_to_workflow rust_code creates; kind='sandbox' covers
    /// compile_custom_sandbox if that name was reused).
    pub async fn find_node_template_by_name_and_user(
        &self,
        name: &str,
        user_id: Uuid,
    ) -> Result<Option<Uuid>> {
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM modules \
             WHERE name = $1 AND user_id = $2 \
               AND kind IN ('extracted', 'sandbox') \
               AND wasm_bytes IS NOT NULL \
             LIMIT 1",
        )
        .bind(name)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(id)
    }

    /// Fetch the installed permissions + capability_world for an owned module.
    /// Used by the inline-compile path to surface permission drift between a
    /// caller's explicit allowed_hosts / allowed_secrets / allowed_methods and
    /// an existing same-named module's stored values — so the caller isn't
    /// silently saddled with narrower (or broader) permissions than they asked for.
    pub async fn get_module_permissions(
        &self,
        module_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<ModulePermissions>> {
        use sqlx::Row;
        let row = sqlx::query(
            "SELECT allowed_hosts, allowed_secrets, allowed_methods, capability_world \
             FROM modules \
             WHERE id = $1 AND user_id = $2",
        )
        .bind(module_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        row.map(|r| -> Result<ModulePermissions> {
            Ok(ModulePermissions {
                allowed_hosts: r
                    .try_get::<Option<_>, _>("allowed_hosts")?
                    .unwrap_or_default(),
                allowed_secrets: decode_allowed_secrets_row(&r, Some(module_id)),
                allowed_methods: r
                    .try_get::<Option<_>, _>("allowed_methods")?
                    .unwrap_or_default(),
                capability_world: r
                    .try_get::<Option<_>, _>("capability_world")?
                    .unwrap_or_default(),
            })
        })
        .transpose()
    }

    /// Update an existing module's WASM + metadata (inline compilation retry path).
    ///
    /// Phase 5.1: writes directly to the unified `modules` table by canonical id.
    /// `capability_world` is stored in long form (`secrets-node`) on `modules`;
    /// convert from the short form callers pass in.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_node_template_wasm(
        &self,
        id: Uuid,
        wasm_bytes: &[u8],
        code: &str,
        world: &str,
        secrets: &[String],
        hosts: &[String],
        integration_name: Option<&str>,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};
        let content_hash = format!("{:x}", Sha256::digest(wasm_bytes));
        // Normalise to long form (`secrets-node`) — modules table CHECK expects it.
        let cw_long = if world == "trusted" {
            "automation-node".to_string()
        } else if world.ends_with("-node") {
            world.to_string()
        } else {
            format!("{}-node", world)
        };
        sqlx::query(
            "UPDATE modules \
             SET wasm_bytes = $1, source_code = $2, capability_world = $3, \
                 allowed_secrets = $4, allowed_hosts = $5, \
                 integration_name = $7, content_hash = $8, \
                 size_bytes = $9, compiled_at = NOW(), updated_at = NOW() \
             WHERE id = $6",
        )
        .bind(wasm_bytes)
        .bind(code)
        .bind(cw_long)
        .bind(secrets)
        .bind(hosts)
        .bind(id)
        .bind(integration_name)
        .bind(&content_hash)
        .bind(wasm_bytes.len() as i32)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// Insert a new module (inline compilation when name is new).
    ///
    /// Phase 5.1: writes directly to the unified `modules` table with
    /// `kind = 'extracted'` (matches the `add_node_to_workflow` rust_code
    /// path).
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_node_template(
        &self,
        id: Uuid,
        name: &str,
        wasm_bytes: &[u8],
        code: &str,
        world: &str,
        secrets: &[String],
        hosts: &[String],
        user_id: Uuid,
        integration_name: Option<&str>,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};
        let content_hash = format!("{:x}", Sha256::digest(wasm_bytes));
        // Normalise to long form (`secrets-node`) — modules table CHECK expects it.
        let cw_long = if world == "trusted" {
            "automation-node".to_string()
        } else if world.ends_with("-node") {
            world.to_string()
        } else {
            format!("{}-node", world)
        };
        let empty: Vec<String> = Vec::new();
        sqlx::query(
            "INSERT INTO modules ( \
                id, user_id, name, kind, capability_world, \
                allowed_hosts, allowed_methods, allowed_secrets, \
                source_code, wasm_bytes, content_hash, size_bytes, \
                integration_name, language, \
                created_at, compiled_at, updated_at \
             ) VALUES ( \
                $1, $2, $3, 'extracted', $4, \
                $5, $6, $7, \
                $8, $9, $10, $11, \
                $12, 'rust', \
                NOW(), NOW(), NOW() \
             )",
        )
        .bind(id)
        .bind(user_id)
        .bind(name)
        .bind(cw_long)
        .bind(hosts)
        .bind(&empty)
        .bind(secrets)
        .bind(code)
        .bind(wasm_bytes)
        .bind(&content_hash)
        .bind(wasm_bytes.len() as i32)
        .bind(integration_name)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// Returns the (id, name) of every non-archived workflow owned by `user_id`
    /// whose graph references `module_id`, EXCLUDING `current_workflow_id`.
    ///
    /// Used by `add_node_to_workflow` to refuse a silent overwrite when an
    /// inline `node_id` collides with an existing module that other workflows
    /// already depend on. Without this guard, the BUG-25 retry-after-failure
    /// path silently mutates production modules — a correctness + security
    /// hazard since the new code may have a different capability set.
    ///
    /// Capped at 20 for bounded response size; that's enough rows to make
    /// the collision explanation actionable without dumping the full call
    /// graph into the error message.
    pub async fn workflows_using_module_excluding(
        &self,
        module_id: Uuid,
        current_workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<(Uuid, String)>> {
        let pattern = format!("%{}%", module_id);
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, name FROM workflows \
             WHERE user_id = $1 \
               AND id != $2 \
               AND graph_json LIKE $3 \
               AND (status IS NULL OR status != 'archived') \
             ORDER BY updated_at DESC \
             LIMIT 20",
        )
        .bind(user_id)
        .bind(current_workflow_id)
        .bind(&pattern)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    // ── Secrets provisioning ──────────────────────────────────────────────

    /// Return which of the provided secret key-paths are already provisioned.
    pub async fn get_provisioned_secrets(
        &self,
        paths: &[String],
        user_id: Uuid,
    ) -> Result<Vec<String>> {
        if paths.is_empty() {
            return Ok(vec![]);
        }
        // MCP-676 (2026-05-13): canonical owner column is `owner_user_id`,
        // NOT `user_id`. The `user_id` column is a 001_initial_schema
        // leftover never written by any production code path; using it
        // as the ownership predicate returned an empty Vec for every
        // user regardless of secret count. Sibling fix to the
        // controller `/metrics` user-stats endpoint that had the same
        // copy-paste bug. The talos-secrets-manager INSERT path writes
        // BOTH `created_by` AND `owner_user_id` to the creating user
        // (verified at manager.rs:865 — `INSERT INTO secrets (..., created_by,
        // owner_user_id, ...)`).
        let provisioned: Vec<String> = sqlx::query_scalar(
            "SELECT key_path FROM secrets WHERE key_path = ANY($1) AND owner_user_id = $2",
        )
        .bind(paths)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(provisioned)
    }

    // ── Module export ──────────────────────────────────────────────────────

    /// Batch-fetch module metadata for export.
    ///
    /// Phase 5: queries the unified `modules` table with 3-shape id matching.
    /// Preserves the legacy "compiled vs template" split in the `category`
    /// projection so export bundles keep their existing schema: rows with
    /// `wasm_bytes` populated project `category = "compiled"` + `source_code`
    /// (from `modules.source_code`); rows without project the persisted
    /// `category` (from Phase 1.5 column) or fall back to "template" and
    /// expose `code_template` (also from `modules.source_code`, where inline
    /// catalog templates originally lived).
    pub async fn get_module_export_metadata(
        &self,
        module_ids: &[Uuid],
        include_source: bool,
    ) -> Result<Vec<ModuleExportInfo>> {
        if module_ids.is_empty() {
            return Ok(vec![]);
        }

        let rows = sqlx::query(
            "SELECT id AS input_id, name, capability_world, \
                    wasm_bytes IS NOT NULL AND octet_length(wasm_bytes) > 0 AS is_compiled, \
                    category, source_code \
             FROM modules \
             WHERE id = ANY($1) \
             ORDER BY id, (wasm_bytes IS NOT NULL) DESC",
        )
        .bind(module_ids)
        .fetch_all(&self.db_pool)
        // FAIL CLOSED: a query error must propagate, not silently yield an
        // empty set. This feeds export_platform_state / export_workflow — a
        // default `[]` produces a bundle missing every module's
        // capability_world / source_code / is_compiled, which the export
        // reports as SUCCESS but re-imports to a wrong/incomplete state.
        .await?;

        let mut out: Vec<ModuleExportInfo> = Vec::new();
        for r in &rows {
            let id: Uuid = r.try_get("input_id")?;
            let is_compiled: bool = r.try_get::<Option<_>, _>("is_compiled")?.unwrap_or(false);
            let name: String = r.try_get("name")?;
            let capability_world: Option<String> = r.try_get("capability_world").ok();
            let category_persisted: Option<String> = r.try_get("category").ok();
            let source_code: Option<String> = if include_source {
                r.try_get::<Option<String>, _>("source_code")
                    .unwrap_or(None)
            } else {
                None
            };
            if is_compiled {
                out.push(ModuleExportInfo {
                    id,
                    name,
                    category: category_persisted.unwrap_or_else(|| "compiled".to_string()),
                    capability_world,
                    source_code,
                    code_template: None,
                });
            } else {
                out.push(ModuleExportInfo {
                    id,
                    name,
                    category: category_persisted.unwrap_or_else(|| "template".to_string()),
                    capability_world: None,
                    source_code: None,
                    // `code_template` historically came from
                    // node_templates.code_template, which maps to
                    // `modules.source_code` post-consolidation. Emit it
                    // in the export bundle when requested so existing
                    // importers keep parsing.
                    code_template: if include_source { source_code } else { None },
                });
            }
        }

        Ok(out)
    }

    /// Insert a compiled WASM module from an import bundle. Skips on conflict.
    ///
    /// Phase 5.1: writes directly to the unified `modules` table with
    /// `kind = 'sandbox'` (import bundles represent compile-time artifacts
    /// of user-authored modules; matches `compile_custom_sandbox`'s kind).
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_wasm_module(
        &self,
        id: Uuid,
        user_id: Uuid,
        name: &str,
        wasm_bytes: &[u8],
        source_code: &str,
        capability_world: &str,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};
        let content_hash = format!("{:x}", Sha256::digest(wasm_bytes));
        // Normalise to long form for the modules table CHECK.
        let cw_long = if capability_world == "trusted" {
            "automation-node".to_string()
        } else if capability_world.ends_with("-node") {
            capability_world.to_string()
        } else {
            format!("{}-node", capability_world)
        };
        let empty: Vec<String> = Vec::new();
        sqlx::query(
            "INSERT INTO modules ( \
                id, user_id, name, kind, capability_world, \
                allowed_hosts, allowed_methods, allowed_secrets, \
                source_code, wasm_bytes, content_hash, size_bytes, \
                language, \
                created_at, compiled_at, updated_at \
             ) VALUES ( \
                $1, $2, $3, 'sandbox', $4, \
                $5, $5, $5, \
                $6, $7, $8, $9, \
                'rust', \
                NOW(), NOW(), NOW() \
             ) ON CONFLICT (id) DO NOTHING",
        )
        .bind(id)
        .bind(user_id)
        .bind(name)
        .bind(cw_long)
        .bind(&empty)
        .bind(source_code)
        .bind(wasm_bytes)
        .bind(&content_hash)
        .bind(wasm_bytes.len() as i32)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// All modules ordered by name — used by LLM scaffolding to build a
    /// compact catalog of available node types.
    ///
    /// Phase 5.1: reads from the unified `modules` table by canonical id.
    /// `is_compiled` is true when `wasm_bytes` is populated. `category`
    /// prefers the persisted Phase 1.5 column, falling back to `kind` so
    /// sandbox / extracted rows still label sensibly.
    pub async fn list_scaffolding_templates(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<ScaffoldingTemplateRow>> {
        // Tenant scoping (mirrors `find_compiled_template_by_name`): system
        // catalog entries (`user_id IS NULL`, `kind='catalog'`) PLUS the
        // caller's own `sandbox`/`extracted` modules. WITHOUT the `user_id`
        // predicate this `SELECT … FROM modules` returned EVERY user's private
        // modules, leaking their names + descriptions into the requesting
        // user's scaffolding LLM context (module names routinely encode what
        // someone is building). The explicit-modules path still wires an
        // explicitly-named ID via its shorthand second pass even when the row
        // isn't in this list, so scoping can't break a user referencing their
        // own module by id.
        //
        // `LIMIT` is a safety bound on an otherwise-unbounded read (the
        // "no unbounded in-memory collections" rule). Both consumers degrade
        // gracefully past it: the LLM catalog only needs a representative
        // sample, and the explicit-modules path falls back to the id shorthand.
        let rows = sqlx::query(
            "SELECT id, name, \
                    COALESCE(category, kind) AS category, description, \
                    (wasm_bytes IS NOT NULL AND octet_length(wasm_bytes) > 0) AS is_compiled \
             FROM modules \
             WHERE (user_id IS NULL OR user_id = $1) \
             ORDER BY name LIMIT 1000",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;

        let result = rows
            .iter()
            .map(|r| -> Result<ScaffoldingTemplateRow> {
                Ok(ScaffoldingTemplateRow {
                    id: r.try_get::<Option<_>, _>("id")?.unwrap_or_default(),
                    name: r.try_get::<Option<_>, _>("name")?.unwrap_or_default(),
                    category: r.try_get::<Option<_>, _>("category")?.unwrap_or_default(),
                    description: r.try_get::<Option<_>, _>("description")?,
                    is_compiled: r.try_get::<Option<_>, _>("is_compiled")?.unwrap_or(false),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(result)
    }

    // ── configuration.rs MCP-handler support ───────────────────────────────

    /// List module names by id, NOT scoped to user. Used by
    /// `get_workflow_graph` for label resolution — the workflow's ownership is
    /// already verified, and exposing module names referenced from one's own
    /// graph is intentional (system + cross-user catalog labels are public).
    ///
    /// Phase 5.1: reads from the unified `modules` table by canonical id.
    pub async fn list_wasm_module_names_by_ids_unscoped(
        &self,
        ids: &[Uuid],
    ) -> Result<Vec<(Uuid, String)>> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let rows: Vec<(Uuid, String)> =
            sqlx::query_as("SELECT id, name FROM modules WHERE id = ANY($1)")
                .bind(ids)
                .fetch_all(&self.db_pool)
                .await?;
        Ok(rows)
    }

    /// `(id, capability_world)` for modules — same unscoped semantics as
    /// `list_wasm_module_names_by_ids_unscoped`. Complements
    /// `list_template_world_overrides`.
    ///
    /// Phase 5.1: reads from the unified `modules` table by canonical id.
    pub async fn list_wasm_module_worlds_by_ids(
        &self,
        ids: &[Uuid],
    ) -> Result<Vec<(Uuid, String)>> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let rows: Vec<(Uuid, String)> =
            sqlx::query_as("SELECT id, capability_world FROM modules WHERE id = ANY($1)")
                .bind(ids)
                .fetch_all(&self.db_pool)
                .await?;
        Ok(rows)
    }
}

#[derive(Debug)]
pub struct NodeTemplateRow {
    pub id: Uuid,
    pub name: String,
    pub config_schema: serde_json::Value,
    pub allowed_secrets: Vec<String>,
    /// Egress allowlist — a non-empty value means the module makes external
    /// calls (side-effecting). Used by `validate_workflow` to surface the
    /// at-least-once crash-recovery contract for these nodes.
    pub allowed_hosts: Vec<String>,
    /// Raw `modules.max_retries`. Nothing in the platform writes this
    /// column, so `0` is the untouched DB default ("no opinion"), NOT an
    /// explicit no-retry choice — consumers stamping node retry defaults
    /// must go through [`Self::effective_max_retries`], which resolves 0
    /// via the method-aware classifier. A value > 0 is an explicit
    /// operator override and is honored verbatim.
    pub max_retries: i32,
    /// HTTP method allowlist — input to the method-aware retry default.
    pub allowed_methods: Vec<String>,
    /// Capability world — input to the method-aware retry default.
    pub capability_world: Option<String>,
}

impl NodeTemplateRow {
    /// Default `retry_count` to stamp on a node created from this
    /// template when the caller supplies none.
    ///
    /// `max_retries > 0` on the module row is an explicit override and
    /// wins. The DB-default `0` resolves via
    /// [`talos_workflow_engine_core::default_max_retries_for_module`]:
    /// read-only / pure-compute modules get transient retries,
    /// side-effect-capable modules (governance approval gates,
    /// messaging senders, state-changing HTTP) stay at 0. Pre-fix,
    /// the raw 0 was stamped verbatim onto every MCP-created node,
    /// which disabled the engine's retry machinery fleet-wide — the
    /// 2026-07-23 outage failed ~125 read-only Gmail fetches that
    /// each ran exactly once.
    pub fn effective_max_retries(&self) -> i32 {
        if self.max_retries > 0 {
            return self.max_retries;
        }
        i32::try_from(talos_workflow_engine_core::default_max_retries_for_module(
            &self.allowed_methods,
            self.capability_world.as_deref(),
        ))
        .unwrap_or(0)
    }
}

/// The four per-module permission columns, fetched together for drift checks.
#[derive(Debug, Clone, Default)]
pub struct ModulePermissions {
    pub allowed_hosts: Vec<String>,
    pub allowed_secrets: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub capability_world: String,
}

#[derive(Debug)]
pub struct ModuleExportInfo {
    pub id: Uuid,
    pub name: String,
    pub category: String,
    pub capability_world: Option<String>,
    pub source_code: Option<String>,
    pub code_template: Option<String>,
}

/// Pure: project a `ModuleExportInfo` into the export-bundle JSON shape.
///
/// Always emits `id` / `name` / `category` / `capability_world`. Adds
/// `source_code` and `code_template` only when present (mirrors the
/// existing `handle_export_workflow` behavior so omitted fields stay
/// omitted from the bundle).
pub fn module_export_info_to_json(info: &ModuleExportInfo) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "id": info.id.to_string(),
        "name": info.name,
        "category": info.category,
        "capability_world": info.capability_world,
    });
    if let Some(src) = &info.source_code {
        obj["source_code"] = serde_json::json!(src);
    }
    if let Some(tpl) = &info.code_template {
        obj["code_template"] = serde_json::json!(tpl);
    }
    obj
}

/// Sanitize an arbitrary module name into a cargo-package-safe identifier.
///
/// Lowercases ASCII alphanumerics, replaces every other character with `-`,
/// and trims leading/trailing dashes. Used at workflow-import time to
/// derive a `cargo new` package name from the bundle module's display name.
/// The result may be empty (e.g. when the input is `"!!!"`); callers
/// should fall back to a default in that case.
pub fn sanitize_module_cargo_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

/// Bundle-module metadata extracted from an `import_workflow` bundle entry.
///
/// `source` is the source code (`source_code` or legacy `code_template`),
/// `mod_name` is the display name (defaults to `"imported-module"`),
/// `cap_world` is the requested capability world (defaults to `"minimal-node"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleModuleMetadata<'a> {
    pub source: Option<&'a str>,
    pub mod_name: &'a str,
    pub cap_world: &'a str,
}

/// Pure: parse a bundle's per-module entry into the three fields the
/// import handler needs. The fallback chain matches the handler's
/// historical behavior:
///   * `source_code` → fallback `code_template` → `None`
///   * `name` → `"imported-module"`
///   * `capability_world` → `"minimal-node"`
pub fn extract_bundle_module_metadata(bundle_mod: &serde_json::Value) -> BundleModuleMetadata<'_> {
    let source = bundle_mod
        .get("source_code")
        .and_then(|v| v.as_str())
        .or_else(|| bundle_mod.get("code_template").and_then(|v| v.as_str()));
    let mod_name = bundle_mod
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("imported-module");
    let cap_world = bundle_mod
        .get("capability_world")
        .and_then(|v| v.as_str())
        .unwrap_or("minimal-node");
    BundleModuleMetadata {
        source,
        mod_name,
        cap_world,
    }
}

#[derive(Debug)]
pub struct ScaffoldingTemplateRow {
    pub id: Uuid,
    pub name: String,
    pub category: Option<String>,
    pub description: Option<String>,
    /// True when `precompiled_wasm IS NOT NULL` — the template can run immediately.
    pub is_compiled: bool,
}
