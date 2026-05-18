//! Workflow manifest service: platform-wide export and import of a user's
//! workflows + schedules + secret-references + module mapping.
//!
//! Owns the orchestration that previously lived inline in
//! `talos-mcp-handlers/src/platform.rs::handle_export_platform_state` and
//! `handle_import_platform_state`. The pure helpers (graph-walking,
//! UUID-remapping, schedule parsing, dry-run preview) already live in
//! `talos_workflow_repository`; this crate composes them with the
//! repositories' SQL surface to produce the canonical manifest shape.
//!
//! Cross-protocol: a single `Arc<WorkflowManifestService>` is consumed by
//! both the MCP `import_platform_state` / `export_platform_state` tools
//! today and is ready to back a future GraphQL mutation without protocol
//! branching.
//!
//! Same architectural pattern as `talos-execution-orchestration` (r295):
//! Arc-injected dependencies, thiserror enum mapped to JSON-RPC codes,
//! typed input + outcome structs.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

use talos_module_repository::ModuleRepository;
use talos_secrets_manager::SecretsManager;
use talos_workflow_repository::WorkflowRepository;

/// Service-level errors. The `jsonrpc_code()` helper maps each variant
/// to a stable JSON-RPC error code so the MCP handler wrapper stays
/// trivial.
#[derive(Debug, Error)]
pub enum ManifestError {
    /// Caller-supplied argument failed structural validation
    /// (missing field, wrong type, exceeded size cap, etc.). Maps to
    /// `-32602` (Invalid params).
    #[error("{0}")]
    InvalidArg(String),

    /// `manifest.version` field present but not a supported value. Maps
    /// to `-32602` (Invalid params).
    #[error("Unsupported manifest version {0}. Only version 2 is supported.")]
    UnsupportedVersion(u64),

    /// Workflow array exceeded the per-manifest cap. Maps to `-32602`.
    #[error("Manifest exceeds 5000 workflows — split into smaller manifests")]
    TooManyWorkflows,

    /// Secret-references array exceeded the per-manifest cap. Maps to
    /// `-32602`.
    #[error("secret_references array exceeds maximum of 1000 entries")]
    TooManySecretRefs,

    /// Required-path repository call returned an error. The detail is
    /// logged at `error!` level by the service; callers receive the
    /// generic mapped error. Maps to `-32000` (Server error).
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl ManifestError {
    /// Stable JSON-RPC error code for protocol wrappers.
    pub fn jsonrpc_code(&self) -> i32 {
        match self {
            Self::InvalidArg(_)
            | Self::UnsupportedVersion(_)
            | Self::TooManyWorkflows
            | Self::TooManySecretRefs => -32602,
            Self::Internal(_) => -32000,
        }
    }

    /// Generic, callable-safe message for the protocol response. Internal
    /// errors collapse to `"Database error"` to avoid leaking schema or
    /// query details.
    pub fn user_facing_message(&self) -> String {
        match self {
            Self::InvalidArg(msg) => msg.clone(),
            Self::UnsupportedVersion(_)
            | Self::TooManyWorkflows
            | Self::TooManySecretRefs => self.to_string(),
            Self::Internal(_) => "Database error".to_string(),
        }
    }
}

/// Caller input for [`WorkflowManifestService::import`].
pub struct ImportInput<'a> {
    /// The complete manifest object (must be `version: 2`).
    pub manifest: &'a serde_json::Value,
    /// When `true`, validate + preview without writing.
    pub dry_run: bool,
    /// User the import is scoped to. All workflows + schedules are
    /// upserted under this user_id.
    pub user_id: Uuid,
}

/// Outcome of an [`WorkflowManifestService::export`] call.
pub struct ExportOutcome {
    /// The full manifest object, ready to be JSON-serialized as the MCP
    /// or REST response body. Shape:
    /// `{ version: 2, exported_at, workflows, secret_references, module_manifest, restore_note }`.
    pub manifest: serde_json::Value,
}

/// Outcome of an [`WorkflowManifestService::import`] call.
///
/// Field semantics differ between dry-run and live runs:
///
/// * **Dry-run** (`dry_run: true`): only `dry_run`, `would_import_workflows`,
///   `workflows_already_exist`, `secret_refs_to_register`,
///   `module_uuids_will_remap`, `module_uuids_unresolvable`, and `warnings`
///   are populated. Live counters (`imported_workflows` etc.) are 0.
/// * **Live** (`dry_run: false`): the live counters are populated;
///   the dry-run fields are `None`.
#[derive(Debug, Default, Serialize)]
pub struct ImportOutcome {
    pub dry_run: bool,
    pub imported_workflows: usize,
    pub imported_schedules: usize,
    pub secret_refs_registered: usize,
    pub module_uuids_remapped: usize,
    pub module_uuids_unresolved: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflows_already_exist: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub would_import_workflows: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_refs_to_register: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_uuids_will_remap: Option<usize>,
    /// Pre-formatted "name (uuid: old_uuid)" strings for source-instance
    /// modules with no current-instance match — operators paste these
    /// into `install_module_from_catalog` invocations. Dry-run only;
    /// `None` on live import (which surfaces individual unresolved
    /// modules through `warnings` instead).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_uuids_unresolvable: Option<Vec<String>>,
    pub warnings: Vec<String>,
}

/// Workflow manifest service. Holds Arc-wrapped dependencies; safe to
/// clone (cheap reference-count bumps). Constructed once at controller
/// boot and shared across the MCP handler tree (and any future GraphQL
/// surface).
pub struct WorkflowManifestService {
    workflow_repo: Arc<WorkflowRepository>,
    module_repo: Arc<ModuleRepository>,
    secrets_manager: Arc<SecretsManager>,
}

impl WorkflowManifestService {
    pub fn new(
        workflow_repo: Arc<WorkflowRepository>,
        module_repo: Arc<ModuleRepository>,
        secrets_manager: Arc<SecretsManager>,
    ) -> Self {
        Self {
            workflow_repo,
            module_repo,
            secrets_manager,
        }
    }

    /// Build the canonical export manifest for `user_id`. Always returns
    /// `version: 2`. The workflows fetch is required (any error is
    /// fatal); secrets and module lookups degrade to empty maps on
    /// error so a partial Vault outage still produces a valid manifest.
    pub async fn export(&self, user_id: Uuid) -> Result<ExportOutcome, ManifestError> {
        // Workflows + secret refs are independent → fetch in parallel.
        // Workflow fetch is required; secrets fetch is best-effort
        // (matches pre-extraction behavior).
        let (wf_rows_res, secret_refs_res) = tokio::join!(
            self.workflow_repo.list_user_workflows_with_schedule(user_id),
            self.secrets_manager.list_secret_refs_for_export(user_id),
        );

        let wf_rows = wf_rows_res.map_err(|e| {
            tracing::error!("export_platform_state: workflow query failed: {:#}", e);
            ManifestError::Internal(e)
        })?;

        let workflows: Vec<serde_json::Value> = wf_rows
            .iter()
            .map(talos_workflow_repository::project_exported_workflow)
            .collect();

        let secret_refs: Vec<serde_json::Value> = match secret_refs_res {
            Ok(refs) => refs.iter().map(|r| r.to_export_json()).collect(),
            Err(e) => {
                tracing::warn!("export_platform_state: secrets query failed: {:#}", e);
                vec![]
            }
        };

        // Build module manifest: maps old UUID → {name, source} so
        // import_platform_state can remap instance-local module UUIDs
        // to the target instance's equivalents (BUG-59).
        let uuid_list = talos_workflow_repository::collect_referenced_module_uuids(&wf_rows);
        let mut module_manifest_map: serde_json::Map<String, serde_json::Value> =
            serde_json::Map::new();

        if !uuid_list.is_empty() {
            // Templates and user-installed wasm modules are independent
            // lookups over the same id set → run in parallel. Both paths
            // degrade to an empty Vec on error (logged upstream); the
            // module_manifest_map ends up partial in that case, matching
            // pre-extraction behaviour.
            let (tmpl_res, sandbox_res) = tokio::join!(
                self.module_repo.list_template_names_by_ids(&uuid_list),
                self.module_repo
                    .list_user_wasm_module_names_by_ids(&uuid_list, user_id),
            );
            for (id, name) in tmpl_res.unwrap_or_default() {
                module_manifest_map.insert(
                    id.to_string(),
                    serde_json::json!({"name": name, "source": "template"}),
                );
            }
            for (id, name) in sandbox_res.unwrap_or_default() {
                module_manifest_map.insert(
                    id.to_string(),
                    serde_json::json!({"name": name, "source": "sandbox"}),
                );
            }
        }

        let exported_at = chrono::Utc::now().to_rfc3339();
        let manifest = serde_json::json!({
            "version": 2,
            "exported_at": exported_at,
            "workflows": workflows,
            "secret_references": secret_refs,
            "module_manifest": module_manifest_map,
            "restore_note": "Secret values are not exported. Re-provision in the dashboard (Settings → Secrets) before running workflows — secret writes require 2FA and aren't available through MCP. Module UUIDs are automatically remapped by import_platform_state using the module_manifest.",
        });

        Ok(ExportOutcome { manifest })
    }

    /// Validate, optionally dry-run, then upsert workflows + schedules
    /// from a manifest. The pure-helper validation (`version`, array
    /// caps) runs first and short-circuits before any DB calls. Module
    /// UUID remap is single-round-trip via the pre-loop name → new-uuid
    /// map; per-workflow upsert errors are surfaced as warnings rather
    /// than aborting the whole import (consistent with pre-extraction
    /// behaviour).
    pub async fn import(
        &self,
        input: ImportInput<'_>,
    ) -> Result<ImportOutcome, ManifestError> {
        let ImportInput {
            manifest,
            dry_run,
            user_id,
        } = input;

        // Manifest version gate.
        let version = manifest
            .get("version")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if version != 2 {
            return Err(ManifestError::UnsupportedVersion(version));
        }

        let workflows = match manifest.get("workflows").and_then(|v| v.as_array()) {
            Some(w) if w.len() > 5_000 => return Err(ManifestError::TooManyWorkflows),
            Some(w) => w,
            None => {
                return Err(ManifestError::InvalidArg(
                    "Manifest missing 'workflows' array".to_string(),
                ))
            }
        };

        let secret_refs: Vec<serde_json::Value> =
            match manifest.get("secret_references").and_then(|v| v.as_array()) {
                Some(refs) if refs.len() > 1000 => return Err(ManifestError::TooManySecretRefs),
                Some(refs) => refs.clone(),
                None => vec![],
            };

        // BUG-59: remap instance-local module UUIDs to current-instance
        // equivalents. Pure helpers in `talos_workflow_repository`:
        //   * extract_old_uuid_to_name_from_manifest reads the
        //     `module_manifest` section.
        //   * build_name_to_new_uuid_map collapses (id, name, _) rows
        //     with first-insertion-wins so the SQL ordering
        //     (user-installed first) promotes user-installed over
        //     system fallback.
        let old_uuid_to_name =
            talos_workflow_repository::extract_old_uuid_to_name_from_manifest(manifest);
        let name_to_new_uuid: HashMap<String, Uuid> = if !old_uuid_to_name.is_empty() {
            let rows = self
                .module_repo
                .list_templates_for_import_remap(user_id)
                .await
                .unwrap_or_default();
            talos_workflow_repository::build_name_to_new_uuid_map(rows)
        } else {
            HashMap::new()
        };

        let mut outcome = ImportOutcome {
            dry_run,
            ..Default::default()
        };

        if dry_run {
            outcome
                .warnings
                .extend(talos_workflow_repository::preview_dry_run_workflow_warnings(workflows));

            // Single round-trip via WHERE name = ANY($2) — replaces a
            // prior per-workflow round-trip pattern.
            let candidate_names: Vec<String> = workflows
                .iter()
                .filter_map(|wf| wf.get("name").and_then(|v| v.as_str()))
                .filter(|n| !n.is_empty())
                .map(String::from)
                .collect();
            let existing_map = self
                .workflow_repo
                .find_workflow_ids_by_names_any_status(user_id, &candidate_names)
                .await
                .unwrap_or_default();

            let preview = talos_workflow_repository::preview_module_remap(
                &old_uuid_to_name,
                &name_to_new_uuid,
            );

            outcome.would_import_workflows = Some(workflows.len());
            outcome.workflows_already_exist = Some(existing_map.len());
            outcome.secret_refs_to_register = Some(secret_refs.len());
            outcome.module_uuids_will_remap = Some(preview.remapped);
            outcome.module_uuids_unresolvable = Some(preview.unresolved);
            // The live counter mirrors the unresolvable count for
            // observability symmetry; live imports surface individual
            // entries via `warnings` and leave the field zeroed.
            outcome.module_uuids_unresolved = outcome
                .module_uuids_unresolvable
                .as_ref()
                .map(|v| v.len())
                .unwrap_or(0);
            return Ok(outcome);
        }

        // Live import — batched name → existing-id lookup (single
        // round-trip).
        let import_candidate_names: Vec<String> = workflows
            .iter()
            .filter_map(|wf| wf.get("name").and_then(|v| v.as_str()))
            .filter(|n| !n.is_empty())
            .map(String::from)
            .collect();
        let existing_id_map = self
            .workflow_repo
            .find_workflow_ids_by_names_any_status(user_id, &import_candidate_names)
            .await
            .unwrap_or_default();

        for (i, wf) in workflows.iter().enumerate() {
            // MCP-422 (2026-05-11): defense-in-depth parity with the
            // MCP create / import handlers. Pre-fix `Some(n) if
            // !n.is_empty()` accepted:
            //   * whitespace-only names (silent persist of
            //     `name: "   "` — same MCP-218 family the mcp handler
            //     fixed at the boundary);
            //   * names with `\0` / control chars (would hit Postgres
            //     "invalid byte sequence" via opaque -32000 at
            //     upsert time, killing the whole import tx);
            //   * names with length > 255 (Postgres would accept up
            //     to TEXT max but list_workflows / dashboard rendering
            //     pre-supposes ≤ 255).
            // Manifest import is a bulk surface — a single malformed
            // name shouldn't crash the entire import. Skip the
            // workflow with a warning instead of failing closed, so
            // the operator sees which entries were problematic
            // without losing the rest. Same skip-with-warning pattern
            // as the missing-graph_json branch below.
            let name = match wf.get("name").and_then(|v| v.as_str()) {
                Some(n) if !n.trim().is_empty() => {
                    let trimmed = n.trim();
                    if trimmed.len() > 255 {
                        outcome.warnings.push(format!(
                            "Skipped workflow at index {}: name exceeds 255 characters",
                            i
                        ));
                        continue;
                    }
                    if trimmed.contains('\0')
                        || trimmed.chars().any(|c| c.is_control() && c != '\t')
                    {
                        outcome.warnings.push(format!(
                            "Skipped workflow at index {}: name contains control characters or null bytes",
                            i
                        ));
                        continue;
                    }
                    trimmed
                }
                _ => {
                    outcome
                        .warnings
                        .push(format!("Skipped workflow at index {}: missing name", i));
                    continue;
                }
            };

            let graph_json_raw = match wf.get("graph_json") {
                Some(g) => g.clone(),
                None => {
                    outcome
                        .warnings
                        .push(format!("Skipped workflow '{}': missing graph_json", name));
                    continue;
                }
            };

            // Remap instance-local module UUIDs. Pure helper handles
            // empty-manifest fast path internally.
            let remap_outcome = talos_workflow_repository::remap_graph_module_uuids(
                &graph_json_raw,
                &old_uuid_to_name,
                &name_to_new_uuid,
            );
            outcome.module_uuids_remapped += remap_outcome.remapped_count;
            outcome.module_uuids_unresolved += remap_outcome.unresolved_module_names.len();
            for unresolved in &remap_outcome.unresolved_module_names {
                outcome.warnings.push(format!(
                    "Workflow '{}': module '{}' not found on this instance — reinstall via install_module_from_catalog",
                    name, unresolved
                ));
            }
            let graph_json = remap_outcome.graph_json;

            let existing_id = existing_id_map.get(name).copied();
            let workflow_id = match self
                .workflow_repo
                .upsert_workflow_graph_by_name(user_id, name, &graph_json, existing_id)
                .await
            {
                Ok(id) => {
                    outcome.imported_workflows += 1;
                    id
                }
                Err(e) => {
                    tracing::error!(
                        "import_platform_state: failed to upsert workflow '{}': {:#}",
                        name,
                        e
                    );
                    outcome.warnings.push(format!(
                        "Failed to import workflow '{}': database error",
                        name
                    ));
                    continue;
                }
            };

            // Optional schedule import. Parser short-circuits on
            // missing/empty cron — defends against hand-crafted
            // manifests; the export side never produces those.
            //
            // MCP-512: when the manifest INCLUDES a `schedule` object
            // but the parse fails (missing or empty `cron_expression`,
            // wrong types), the schedule was silently dropped pre-fix.
            // An operator who intentionally crafted a `schedule` entry
            // for this workflow would see `imported_schedules += 0`
            // for it and discover the missing cron only when their
            // workflow never fired — days or weeks after the import.
            // Surface a warning so the operator sees the dropped entry
            // immediately. A workflow with no schedule at all simply
            // omits the `schedule` key and doesn't trigger this branch.
            if let Some(schedule_json) = wf.get("schedule") {
                match talos_workflow_repository::parse_imported_schedule(schedule_json) {
                    Some(schedule) => match self
                        .workflow_repo
                        .upsert_workflow_schedule(
                            workflow_id,
                            user_id,
                            schedule.cron_expression,
                            schedule.timezone,
                            schedule.is_enabled,
                        )
                        .await
                    {
                        Ok(_) => outcome.imported_schedules += 1,
                        Err(e) => {
                            tracing::warn!(
                                "import_platform_state: schedule upsert failed for '{}': {:#}",
                                name,
                                e
                            );
                            outcome
                                .warnings
                                .push(format!("Failed to import schedule for workflow '{}'", name));
                        }
                    },
                    None => {
                        outcome.warnings.push(format!(
                            "Workflow '{}': schedule object present but missing or empty \
                             cron_expression — schedule not imported. Add a valid cron \
                             string to the manifest entry or remove the `schedule` key \
                             entirely.",
                            name
                        ));
                    }
                }
            }
        }

        // Secret-references existence check — single batched lookup
        // via WHERE key_path = ANY($1). SECURITY: encrypted_value from
        // import input is never read; we only check existence.
        let candidate_secret_paths: Vec<String> = secret_refs
            .iter()
            .filter_map(|s| s.get("key_path").and_then(|v| v.as_str()))
            .filter(|k| !k.is_empty())
            .map(String::from)
            .collect();
        let existing_secrets = self
            .secrets_manager
            .existing_secret_key_paths(&candidate_secret_paths, user_id)
            .await
            .unwrap_or_default();
        for secret_ref in &secret_refs {
            let key_path = match secret_ref.get("key_path").and_then(|v| v.as_str()) {
                Some(k) if !k.is_empty() => k,
                _ => continue,
            };
            let ref_name = secret_ref
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(key_path);

            if existing_secrets.contains(key_path) {
                outcome.secret_refs_registered += 1;
            } else {
                outcome.warnings.push(format!(
                    "Secret '{}' (key_path='{}') is not provisioned. Add it in the dashboard (Settings → Secrets) before running workflows — secret writes require 2FA and aren't available through MCP.",
                    ref_name, key_path
                ));
            }
        }

        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonrpc_code_invalid_arg_is_minus_32602() {
        assert_eq!(
            ManifestError::InvalidArg("missing field".to_string()).jsonrpc_code(),
            -32602
        );
    }

    #[test]
    fn jsonrpc_code_unsupported_version_is_minus_32602() {
        assert_eq!(ManifestError::UnsupportedVersion(1).jsonrpc_code(), -32602);
    }

    #[test]
    fn jsonrpc_code_too_many_workflows_is_minus_32602() {
        assert_eq!(ManifestError::TooManyWorkflows.jsonrpc_code(), -32602);
    }

    #[test]
    fn jsonrpc_code_too_many_secret_refs_is_minus_32602() {
        assert_eq!(ManifestError::TooManySecretRefs.jsonrpc_code(), -32602);
    }

    #[test]
    fn jsonrpc_code_internal_is_minus_32000() {
        let e: ManifestError = anyhow::anyhow!("db boom").into();
        assert_eq!(e.jsonrpc_code(), -32000);
    }

    #[test]
    fn user_facing_message_internal_is_generic() {
        let e: ManifestError = anyhow::anyhow!("postgres connection refused: leaking schema details").into();
        // Internal errors must NOT leak details to API clients.
        assert_eq!(e.user_facing_message(), "Database error");
    }

    #[test]
    fn user_facing_message_unsupported_version_includes_version() {
        let msg = ManifestError::UnsupportedVersion(7).user_facing_message();
        assert!(msg.contains("7"), "got: {}", msg);
        assert!(msg.contains("version"), "got: {}", msg);
    }

    #[test]
    fn import_outcome_serializes_dry_run_only_fields_when_present() {
        let mut o = ImportOutcome {
            dry_run: true,
            ..Default::default()
        };
        o.would_import_workflows = Some(3);
        o.workflows_already_exist = Some(1);
        let v = serde_json::to_value(&o).unwrap();
        assert_eq!(v["dry_run"], true);
        assert_eq!(v["would_import_workflows"], 3);
        assert_eq!(v["workflows_already_exist"], 1);
        // The live-only counters stay at their default 0; not skipped.
        assert_eq!(v["imported_workflows"], 0);
    }

    #[test]
    fn import_outcome_skips_dry_run_only_fields_when_none() {
        let o = ImportOutcome {
            dry_run: false,
            imported_workflows: 5,
            ..Default::default()
        };
        let v = serde_json::to_value(&o).unwrap();
        assert_eq!(v["dry_run"], false);
        assert_eq!(v["imported_workflows"], 5);
        // None-valued dry-run fields must NOT appear in the live response.
        assert!(v.get("would_import_workflows").is_none());
        assert!(v.get("workflows_already_exist").is_none());
        assert!(v.get("secret_refs_to_register").is_none());
        assert!(v.get("module_uuids_will_remap").is_none());
        assert!(v.get("module_uuids_unresolvable").is_none());
    }
}
