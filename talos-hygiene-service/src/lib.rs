//! Platform hygiene report service — backs the `get_platform_hygiene_report`
//! MCP tool. Extracted from `talos-mcp-handlers/src/analytics.rs` (~700 LoC
//! handler) following the cross-protocol Arc-injected service pattern
//! (see `WorkflowManifestService` / `ReplayService` / `InlineCompileService`):
//! typed input + outcome structs, `thiserror` enum with stable
//! `jsonrpc_code()` mapping, and `user_facing_message()` collapsing internal
//! errors to a generic string (never leaks schema/query details).
//!
//! The handler is now a thin wrapper: parse `fix_all`/`confirm` → call
//! [`HygieneService::generate`] → optionally [`HygieneService::apply_fixes`]
//! → format. Output JSON is byte-identical to the pre-extraction handler —
//! the response shape is operator-facing API.

pub mod graph_heuristics;

pub use graph_heuristics::{count_nodes_with_empty_data, is_substantive_workflow};

use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

/// Service-level errors. The `jsonrpc_code()` helper maps each variant
/// to the stable JSON-RPC code the protocol wrapper emits.
#[derive(Debug, Error)]
pub enum HygieneError {
    /// Required-path repository call returned an error. The detail is
    /// logged by the caller at `error!` level; callers receive the
    /// generic mapped message. Maps to `-32000` (Server error).
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl HygieneError {
    /// Stable JSON-RPC error code for protocol wrappers.
    pub fn jsonrpc_code(&self) -> i32 {
        match self {
            Self::Internal(_) => -32000,
        }
    }

    /// Generic, caller-safe message for the protocol response. Internal
    /// errors collapse to the historical handler string so no schema or
    /// query detail leaks to the caller.
    pub fn user_facing_message(&self) -> String {
        match self {
            Self::Internal(_) => "Failed to generate hygiene report".to_string(),
        }
    }
}

/// Caller input for [`HygieneService::generate`].
pub struct HygieneReportInput {
    /// User the report is scoped to.
    pub user_id: Uuid,
}

/// The actionable-fix candidates computed alongside the report. The
/// preview is embedded in both the dry-run and executed `fix_all`
/// envelopes; the id vectors drive the actual mutations.
pub struct FixCandidates {
    /// The `fix_all.preview` JSON (auto-deletable drafts, substantive
    /// drafts skipped, stale executions to cancel, orphaned modules).
    pub preview: serde_json::Value,
    /// Auto-deletable stale draft workflow ids (substantive drafts are
    /// excluded per the M-I audit finding — see `is_substantive_workflow`).
    pub draft_ids: Vec<Uuid>,
    /// Stale (stuck >2h) execution ids.
    pub stale_exec_ids: Vec<Uuid>,
    /// Compiled modules not referenced by any workflow.
    pub orphaned_module_ids: Vec<Uuid>,
}

/// Outcome of [`HygieneService::generate`].
pub struct HygieneReportOutcome {
    /// The full hygiene report JSON (without any `fix_all` envelope).
    pub report: serde_json::Value,
    /// Pre-computed fix candidates for the `fix_all` flow.
    pub fix_candidates: FixCandidates,
}

/// Cross-protocol hygiene-report service. One Arc is shared by the MCP
/// handler (and, in time, any GraphQL consumer).
pub struct HygieneService {
    analytics_repo: Arc<talos_analytics_repository::AnalyticsRepository>,
    workflow_repo: Arc<talos_workflow_repository::WorkflowRepository>,
    execution_repo: Arc<talos_execution_repository::ExecutionRepository>,
    module_repo: Arc<talos_module_repository::ModuleRepository>,
}

impl HygieneService {
    pub fn new(
        analytics_repo: Arc<talos_analytics_repository::AnalyticsRepository>,
        workflow_repo: Arc<talos_workflow_repository::WorkflowRepository>,
        execution_repo: Arc<talos_execution_repository::ExecutionRepository>,
        module_repo: Arc<talos_module_repository::ModuleRepository>,
    ) -> Self {
        Self {
            analytics_repo,
            workflow_repo,
            execution_repo,
            module_repo,
        }
    }

    /// Build the full hygiene report + fix candidates for `user_id`.
    /// Read-only — no mutations happen here.
    pub async fn generate(
        &self,
        input: HygieneReportInput,
    ) -> Result<HygieneReportOutcome, HygieneError> {
        let user_id = input.user_id;
        let h = self.analytics_repo.get_hygiene_report(user_id).await?;

        // Auto-classify workflows whose names start with known QA/test prefixes.
        // These should be classified as workflow_type='test' but often aren't — exclude
        // them from readiness warnings and surface them as a separate recommendation.
        let test_name_prefixes = [
            "QA-", "qa-", "QA_", "qa_", "test-", "test_", "Test-", "Test_", "TEST-", "TEST_",
        ];
        let is_test_like = |name: &str| test_name_prefixes.iter().any(|p| name.starts_with(p));

        let auto_classified_count = h
            .undescribed
            .iter()
            .chain(h.uncapabilized.iter())
            .filter(|r| is_test_like(&r.name))
            .map(|r| r.id)
            .collect::<std::collections::HashSet<_>>()
            .len();

        let undescribed: Vec<serde_json::Value> = h
            .undescribed
            .iter()
            .filter(|r| !is_test_like(&r.name))
            .map(|r| {
                serde_json::json!({
                    "id": r.id.to_string(),
                    "name": r.name,
                    "readiness_score": r.readiness_score,
                    "created_at": r.created_at.to_rfc3339(),
                })
            })
            .collect();

        let uncapabilized: Vec<serde_json::Value> = h
            .uncapabilized
            .iter()
            .filter(|r| !is_test_like(&r.name))
            .map(|r| {
                serde_json::json!({
                    "id": r.id.to_string(),
                    "name": r.name,
                    "description": r.description,
                    "readiness_score": r.readiness_score,
                    "created_at": r.created_at.to_rfc3339(),
                })
            })
            .collect();

        let suppressed_count = h.suppressed_count;
        let suppressed_low_score_count = h.suppressed_low_score_count;
        let unembedded_count = h.unembedded_count;
        let total_workflow_count = h.total_workflow_count;

        // --- 4. Orphaned compiled modules ---
        let orphaned_modules: Vec<serde_json::Value> = h
            .orphaned_modules
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id.to_string(),
                    "name": r.name,
                    "size_bytes": r.size_bytes,
                    "compiled_at": r.compiled_at.to_rfc3339(),
                })
            })
            .collect();

        // --- 5. Stale stuck executions ---
        let stale_executions: Vec<serde_json::Value> = h
            .stale_executions
            .iter()
            .map(|r| {
                let hours_stuck = chrono::Utc::now()
                    .signed_duration_since(r.started_at)
                    .num_minutes() as f64
                    / 60.0;
                serde_json::json!({
                    "id": r.id.to_string(),
                    "workflow_id": r.workflow_id.to_string(),
                    "workflow_name": r.workflow_name,
                    "status": r.status,
                    "started_at": r.started_at.to_rfc3339(),
                    "hours_stuck": format!("{:.1}", hours_stuck),
                })
            })
            .collect();

        // --- 6. Dormant enabled workflows ---
        let dormant_workflows: Vec<serde_json::Value> = h
            .dormant_workflows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id.to_string(),
                    "name": r.name,
                    "created_at": r.created_at.to_rfc3339(),
                    "last_execution": r.last_execution.map(|t| t.to_rfc3339()),
                })
            })
            .collect();

        let stale_draft_workflows: Vec<serde_json::Value> = h
            .stale_draft_workflows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id.to_string(),
                    "name": r.name,
                    "created_at": r.created_at.to_rfc3339(),
                })
            })
            .collect();

        let idle_actors: Vec<serde_json::Value> = h
            .idle_actors
            .iter()
            .map(|r| {
                // MCP-6: emit a string-typed `last_active_label` ("never" or
                // RFC3339) alongside the raw `last_active` Option. Keeps the
                // semantic-correct null for programmatic null-check while
                // giving ops dashboards a label that's always renderable
                // without "missing field" confusion.
                let last_active_label = match r.last_active {
                    Some(ref t) => t.to_rfc3339(),
                    None => "never".to_string(),
                };
                serde_json::json!({
                    "actor_id": r.id.to_string(),
                    "name": r.name,
                    "status": r.status,
                    "last_active": r.last_active.map(|t| t.to_rfc3339()),
                    "last_active_label": last_active_label,
                    "total_executions": r.total_executions,
                })
            })
            .collect();

        // --- 10. Orphaned secrets ---
        let orphaned_secrets: Vec<serde_json::Value> = if h.has_wildcard_module {
            Vec::new()
        } else {
            h.orphaned_secrets
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "name": r.name,
                        "key_path": r.key_path,
                        "namespace": r.namespace.as_deref().unwrap_or("default"),
                        "created_at": r.created_at.to_rfc3339(),
                        "has_expiry": r.expires_at.is_some(),
                    })
                })
                .collect()
        };

        // --- 11. Secrets missing expiry ---
        let secrets_without_expiry: Vec<serde_json::Value> = h
            .secrets_without_expiry
            .iter()
            .map(|r| {
                serde_json::json!({
                    "name": r.name,
                    "key_path": r.key_path,
                    "created_at": r.created_at.to_rfc3339(),
                })
            })
            .collect();

        // --- Actor memories expiring within 24 hours ---
        let expiring_actor_memories: Vec<serde_json::Value> = h
            .expiring_actor_memories
            .iter()
            .map(|r| {
                serde_json::json!({
                    "actor_id": r.actor_id.to_string(),
                    "actor_name": r.actor_name,
                    "key": r.key,
                    "memory_type": r.memory_type,
                    "expires_at": r.expires_at.to_rfc3339(),
                })
            })
            .collect();

        // --- Production workflows needing input_schema ---
        let workflows_needing_schema: Vec<serde_json::Value> = h
            .workflows_needing_schema
            .iter()
            .map(|r| {
                serde_json::json!({
                    "workflow_id": r.id.to_string(),
                    "name": r.name,
                    "execution_count": r.execution_count,
                    "last_run": r.last_run.map(|t| t.to_rfc3339()).unwrap_or_default(),
                })
            })
            .collect();

        // --- Build summary and recommendations ---
        let mut recommendations: Vec<serde_json::Value> = Vec::new();

        if !undescribed.is_empty() {
            recommendations.push(serde_json::json!({
                "priority": "high",
                "category": "documentation",
                "action": format!("Add descriptions to {} published workflow(s) using set_workflow_description. Undescribed workflows score poorly in readiness and are hard for agents to discover.", undescribed.len()),
                "affected_count": undescribed.len(),
            }));
        }

        if !uncapabilized.is_empty() {
            recommendations.push(serde_json::json!({
                "priority": "high",
                "category": "discoverability",
                "action": format!("Add capabilities to {} workflow(s) using set_workflow_capabilities or suggest_capabilities. Workflows without capabilities cannot be found by get_workflows_by_capability.", uncapabilized.len()),
                "affected_count": uncapabilized.len(),
            }));
        }

        if unembedded_count > 0 {
            let pct = if total_workflow_count > 0 {
                unembedded_count * 100 / total_workflow_count
            } else {
                0
            };
            recommendations.push(serde_json::json!({
                "priority": "medium",
                "category": "semantic_search",
                "action": format!("{} of {} workflows ({pct}%) lack embeddings — semantic search falls back to keyword matching for these. Run generate_workflow_embeddings to index them for true vector search.", unembedded_count, total_workflow_count),
                "affected_count": unembedded_count,
            }));
        }

        if !orphaned_modules.is_empty() {
            let total_size: i64 = orphaned_modules
                .iter()
                .filter_map(|m| m.get("size_bytes").and_then(|v| v.as_i64()))
                .sum();
            recommendations.push(serde_json::json!({
                "priority": "low",
                "category": "cleanup",
                "action": format!("{} compiled module(s) are not used by any workflow ({}KB total). Use cleanup_modules to reclaim storage.", orphaned_modules.len(), total_size / 1024),
                "affected_count": orphaned_modules.len(),
            }));
        }

        if !stale_executions.is_empty() {
            recommendations.push(serde_json::json!({
                "priority": "critical",
                "category": "operations",
                "action": format!("{} execution(s) have been stuck in running/queued state for more than 2 hours. Use cleanup_stale_executions or cancel them individually.", stale_executions.len()),
                "affected_count": stale_executions.len(),
            }));
        }

        if !dormant_workflows.is_empty() {
            recommendations.push(serde_json::json!({
                "priority": "low",
                "category": "cleanup",
                "action": format!("{} enabled workflow(s) have had no executions in 30+ days. Consider disabling or deleting them with batch_delete_workflows to reduce registry noise.", dormant_workflows.len()),
                "affected_count": dormant_workflows.len(),
            }));
        }

        if !stale_draft_workflows.is_empty() {
            recommendations.push(serde_json::json!({
                "priority": "low",
                "category": "cleanup",
                "action": format!("{} draft workflow(s) have never been published or executed in 7+ days — likely scaffolding leftovers. Review with get_workflow_quickstart then publish_version or delete with batch_delete_workflows.", stale_draft_workflows.len()),
                "affected_count": stale_draft_workflows.len(),
            }));
        }

        if !idle_actors.is_empty() {
            recommendations.push(serde_json::json!({
                "priority": "low",
                "category": "cleanup",
                "action": format!("Terminate or archive {} idle actor(s) to reduce attack surface and noise in list_actors. Use archive_actor to preserve history or terminate_actor for full cleanup.", idle_actors.len()),
                "affected_count": idle_actors.len(),
            }));
        }

        // MCP-1208 (2026-05-17): recommendation text routes operators to
        // the dashboard for both deletion and expiry-set actions. The
        // previous text referenced the `delete_secret` / `set_secret` MCP
        // tools that MCP-1201 removed — operators following the old text
        // would call a tool that no longer exists. Same docs-drift class
        // closed by MCP-1202 (CLAUDE.md + docs/*) but the hygiene-report
        // recommendation generator was missed in that sweep.
        if !orphaned_secrets.is_empty() {
            recommendations.push(serde_json::json!({
                "priority": "medium",
                "category": "security",
                "action": format!("{} secret(s) are not referenced by any module's allowed_secrets list. Delete them in the dashboard (Settings → Secrets) to reduce vault clutter and limit credential exposure — secret writes require 2FA and aren't available through MCP.", orphaned_secrets.len()),
                "affected_count": orphaned_secrets.len(),
            }));
        }

        if !secrets_without_expiry.is_empty() {
            recommendations.push(serde_json::json!({
                "priority": "medium",
                "category": "security",
                "action": format!("{} API key/token secret(s) have no expiry date set. Set an expiry in the dashboard (Settings → Secrets) to enforce rotation cadence — secret writes require 2FA and aren't available through MCP.", secrets_without_expiry.len()),
                "affected_count": secrets_without_expiry.len(),
            }));
        }

        // Wildcard secret grant: at least one installed module can read any vault path.
        // This is a security risk — a single compromised workflow can exfiltrate the entire vault.
        // Note: orphaned_secrets is suppressed when has_wildcard_module=true (every secret
        // might be referenced), so this recommendation surfaces in that scenario.
        if h.has_wildcard_module {
            let names_str = if h.wildcard_module_names.is_empty() {
                "unknown".to_string()
            } else {
                h.wildcard_module_names
                    .iter()
                    .map(|n| format!("'{}'", n))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            recommendations.push(serde_json::json!({
                "priority": "medium",
                "category": "security",
                "wildcard_modules": h.wildcard_module_names,
                "action": format!(
                    "{} module(s) have wildcard secret access (allowed_secrets: [\"*\"]): {}. \
                     Each can read every secret in your vault — a single compromised or misbehaving \
                     workflow can exfiltrate all credentials. Reinstall with explicit allowed_secrets \
                     paths to limit blast radius. Use get_workflow_risk_assessment on workflows \
                     containing these modules to identify affected nodes.",
                    h.wildcard_module_names.len(),
                    names_str
                ),
                "affected_count": h.wildcard_module_names.len(),
            }));
        }

        if !expiring_actor_memories.is_empty() {
            let keys_preview: Vec<&str> = expiring_actor_memories
                .iter()
                .take(3)
                .filter_map(|m| m.get("key").and_then(|k| k.as_str()))
                .collect();
            recommendations.push(serde_json::json!({
                "priority": "high",
                "category": "actor_memory",
                "action": format!(
                    "{} actor memory key(s) expire within 24 hours (e.g. {}). Use refresh_memory_ttl to extend TTL, or let them expire if the data is no longer needed.",
                    expiring_actor_memories.len(),
                    keys_preview.join(", ")
                ),
                "affected_count": expiring_actor_memories.len(),
            }));
        }

        if !workflows_needing_schema.is_empty() {
            let names_preview: Vec<&str> = workflows_needing_schema
                .iter()
                .take(3)
                .filter_map(|w| w.get("name").and_then(|n| n.as_str()))
                .collect();
            recommendations.push(serde_json::json!({
                "priority": "medium",
                "category": "input_schema",
                "action": format!(
                    "{} published workflow(s) have execution history but no input_schema (e.g. {}). Run infer_workflow_input_schema on each, then set_workflow_input_schema to lock the contract and enable input validation.",
                    workflows_needing_schema.len(),
                    names_preview.join(", ")
                ),
                "affected_count": workflows_needing_schema.len(),
            }));
        }

        if auto_classified_count > 0 {
            recommendations.push(serde_json::json!({
                "priority": "low",
                "category": "classification",
                "action": format!(
                    "{} workflow(s) have test-like name prefixes (QA-, test-, Test-) but are classified as production type — excluded from readiness warnings automatically. Use set_workflow_type with type='test' to formally classify them and keep your production metrics clean.",
                    auto_classified_count
                ),
                "affected_count": auto_classified_count,
            }));
        }

        // Untyped serde_json::Value parsing is a wasmtime fuel anti-pattern.
        // Flag user modules whose source uses it and emit a ready-to-paste
        // generate_typed_scaffold fix command per module, seeded with the real
        // module_id so the capture path can pull a scrubbed sample from the
        // most recent completed execution. This turns the lint into a
        // one-click remediation: copy the command, review the generated
        // structs, fill in the run body, compile.
        if !h.untyped_value_modules.is_empty() {
            let names_preview = h
                .untyped_value_modules
                .iter()
                .take(5)
                .map(|m| format!("'{}'", m.name))
                .collect::<Vec<_>>()
                .join(", ");
            let suffix = if h.untyped_value_modules.len() > 5 {
                format!(" and {} more", h.untyped_value_modules.len() - 5)
            } else {
                String::new()
            };
            // Emit a fix command per flagged module. The commands are plain
            // JSON-RPC-style argument blocks the operator can copy-paste into
            // any MCP client; they reference source_module_id so the scaffold
            // generator pulls real captured samples via the DLP-scrubbed path
            // shipped in commit 1355e86 — no hand-crafted JSON required.
            let fix_commands: Vec<serde_json::Value> = h
                .untyped_value_modules
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "module_name": m.name,
                        "module_id": m.id.to_string(),
                        "tool": "generate_typed_scaffold",
                        "arguments": {
                            "name": format!("{}-typed", m.name),
                            "source_module_id": m.id.to_string(),
                        },
                        "next": "Review generated structs, fill in run body, then call compile_custom_sandbox with a fuel_budget derived from expected payload shape, then hot_update_module on the original to swap the implementation.",
                    })
                })
                .collect();
            // Serialize the HygieneReport struct's module list into a compact
            // {id,name} array for the recommendation payload. Keeping the id
            // surfaced makes the recommendation self-contained.
            let flagged_modules: Vec<serde_json::Value> = h
                .untyped_value_modules
                .iter()
                .map(|m| serde_json::json!({ "id": m.id.to_string(), "name": m.name }))
                .collect();
            recommendations.push(serde_json::json!({
                "priority": "medium",
                "category": "performance",
                "untyped_value_modules": flagged_modules,
                "fix_commands": fix_commands,
                "action": format!(
                    "{} module(s) parse input via untyped serde_json::Value: {}{}. \
                     Value parsing allocates HashMap<String, Value> per JSON object and dominates \
                     wasmtime fuel on large payloads — 3–10× more expensive than typed #[derive(Deserialize)] \
                     structs. Each flagged module has a ready-to-paste fix command in `fix_commands` that \
                     calls generate_typed_scaffold with source_module_id pre-filled — the tool will pull a \
                     real captured sample from the module's most recent completed execution (DLP-scrubbed) \
                     and emit typed Deserialize structs for review. Reference incident: smart-email-drafts \
                     fetch-threads exhausted 30M fuel on Value parsing; typed rewrite dropped it below 1M.",
                    h.untyped_value_modules.len(),
                    names_preview,
                    suffix
                ),
                "affected_count": h.untyped_value_modules.len(),
            }));
        }

        let secret_issues = orphaned_secrets.len()
            + secrets_without_expiry.len()
            + if h.has_wildcard_module { 1 } else { 0 };
        let issues_found = undescribed.len()
            + uncapabilized.len()
            + stale_executions.len()
            + orphaned_modules.len()
            + dormant_workflows.len()
            + stale_draft_workflows.len()
            + idle_actors.len()
            + secret_issues
            + expiring_actor_memories.len()
            + workflows_needing_schema.len()
            + if unembedded_count > 0 { 1 } else { 0 };

        let note = {
            let base = match (suppressed_count, auto_classified_count as i64) {
                (0, 0) => String::new(),
                (s, 0) => format!("{} internal/test workflow(s) excluded from readiness warnings (workflow_type=test/internal). Use set_workflow_type to classify QA fixtures.", s),
                (0, a) => format!("{} workflow(s) auto-excluded: test-like name prefix (QA-/test-) but no formal type set. Use set_workflow_type with type='test' to classify them.", a),
                (s, a) => format!("{} internal/test workflow(s) formally suppressed; {} more auto-excluded via name-prefix heuristic. Use set_workflow_type to normalize all test fixtures.", s, a),
            };
            if suppressed_low_score_count > 0 {
                format!("{}{}{} draft(s) with readiness_score<10 suppressed from documentation recommendations.", base, if base.is_empty() { "" } else { " " }, suppressed_low_score_count)
            } else {
                base
            }
        };

        // MCP-76 (2026-05-07): sort recommendations by priority desc so that
        // medium / high / critical entries appear above low-priority cleanup
        // items in the rendered output. Pre-fix, the order was insertion order
        // and a medium-severity "API key without expiry" landed below
        // low-priority "draft workflows" cleanup. Operators triaging would
        // miss security-class gaps unless they manually re-sorted.
        fn priority_rank(s: &str) -> u8 {
            match s {
                "critical" => 0,
                "high" => 1,
                "medium" => 2,
                "low" => 3,
                _ => 4,
            }
        }
        recommendations.sort_by(|a, b| {
            let ap = a.get("priority").and_then(|v| v.as_str()).unwrap_or("");
            let bp = b.get("priority").and_then(|v| v.as_str()).unwrap_or("");
            priority_rank(ap).cmp(&priority_rank(bp))
        });

        let report = serde_json::json!({
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "summary": {
                "total_issues": issues_found,
                "critical": stale_executions.len(),
                "high": undescribed.len() + uncapabilized.len() + expiring_actor_memories.len(),
                "medium": (if unembedded_count > 0 { 1 } else { 0 }) + secret_issues + workflows_needing_schema.len(),
                "low": orphaned_modules.len() + dormant_workflows.len() + stale_draft_workflows.len() + idle_actors.len(),
                "total_workflows": total_workflow_count,
                "idle_actors_count": idle_actors.len(),
                "wildcard_secret_grant": h.has_wildcard_module,
                "orphaned_secrets_count": orphaned_secrets.len(),
                "secrets_without_expiry_count": secrets_without_expiry.len(),
                "expiring_memories_count": expiring_actor_memories.len(),
                "workflows_needing_schema_count": workflows_needing_schema.len(),
                "suppressed_internal_test_workflows": suppressed_count,
                "suppressed_low_score_count": suppressed_low_score_count,
                "auto_classified_test_like_workflows": auto_classified_count,
                "embedding_coverage_percent": if total_workflow_count > 0 {
                    (total_workflow_count - unembedded_count) * 100 / total_workflow_count
                } else { 100 },
                "note": note,
            },
            "stale_executions": stale_executions,
            "undescribed_workflows": undescribed,
            "uncapabilized_workflows": uncapabilized,
            "unembedded_workflow_count": unembedded_count,
            "orphaned_modules": orphaned_modules,
            "dormant_workflows": dormant_workflows,
            "stale_draft_workflows": stale_draft_workflows,
            "idle_actors": idle_actors,
            "orphaned_secrets": orphaned_secrets,
            "secrets_without_expiry": secrets_without_expiry,
            "expiring_actor_memories": expiring_actor_memories,
            "workflows_needing_schema": workflows_needing_schema,
            "recommendations": recommendations,
        });

        // Build the list of actionable fixes.
        //
        // M-I (2026-05-06): partition stale_draft_workflows into
        // auto-deletable vs substantive_skipped via the shared
        // `is_substantive_workflow` predicate. Pre-fix,
        // ALL stale drafts went into `stale_draft_workflows_to_delete` —
        // including drafts that `session_start` simultaneously surfaced as
        // "ready for publish_version" (the unpublished_substantive_drafts
        // list). An operator running `fix_all confirm=true` after seeing
        // session_start's "5 substantive draft(s) ready to publish"
        // message would have nuked exactly the workflows they were about
        // to ship. Now: substantive drafts appear in `substantive_drafts_skipped`
        // (informational; surfaces the safety net to the operator) and
        // are EXCLUDED from auto-delete.
        let (substantive_drafts_skipped, auto_deletable_drafts): (Vec<_>, Vec<_>) = h
            .stale_draft_workflows
            .iter()
            .partition(|r| is_substantive_workflow(r.graph_json.as_deref()));
        let draft_ids: Vec<uuid::Uuid> = auto_deletable_drafts.iter().map(|r| r.id).collect();
        let stale_exec_ids: Vec<uuid::Uuid> = h.stale_executions.iter().map(|r| r.id).collect();
        let orphaned_module_ids: Vec<uuid::Uuid> =
            h.orphaned_modules.iter().map(|r| r.id).collect();

        let fix_preview = serde_json::json!({
            "stale_draft_workflows_to_delete": auto_deletable_drafts.iter().map(|r| serde_json::json!({
                "id": r.id.to_string(), "name": r.name,
            })).collect::<Vec<_>>(),
            "substantive_drafts_skipped": substantive_drafts_skipped.iter().map(|r| serde_json::json!({
                "id": r.id.to_string(),
                "name": r.name,
                "reason": "Has SYSTEM_PROMPT/OUTPUT_SCHEMA/retry/description markers — auto-delete refused. \
                          Use publish_version, or delete explicitly via batch_delete_workflows.",
            })).collect::<Vec<_>>(),
            "stale_executions_to_cancel": h.stale_executions.iter().map(|r| serde_json::json!({
                "id": r.id.to_string(),
                "workflow_name": r.workflow_name,
                "status": r.status,
            })).collect::<Vec<_>>(),
            "orphaned_modules_to_delete": h.orphaned_modules.iter().map(|r| serde_json::json!({
                "id": r.id.to_string(), "name": r.name,
            })).collect::<Vec<_>>(),
            "total_fixable": draft_ids.len() + stale_exec_ids.len() + orphaned_module_ids.len(),
        });

        Ok(HygieneReportOutcome {
            report,
            fix_candidates: FixCandidates {
                preview: fix_preview,
                draft_ids,
                stale_exec_ids,
                orphaned_module_ids,
            },
        })
    }

    /// The `fix_all` envelope for the dry-run (preview, no mutations) path.
    pub fn dry_run_envelope(candidates: &FixCandidates) -> serde_json::Value {
        serde_json::json!({
            "dry_run": true,
            "preview": candidates.preview,
            "note": "Set confirm: true to execute these fixes. Items not listed (undescribed workflows, missing capabilities, expiring secrets) require manual attention.",
        })
    }

    /// Execute the fixes (delete stale drafts, cancel stale executions,
    /// delete orphaned modules) and return the executed `fix_all` envelope.
    pub async fn apply_fixes(
        &self,
        user_id: Uuid,
        candidates: &FixCandidates,
    ) -> serde_json::Value {
        let mut fix_results = serde_json::json!({});

        // 1. Delete stale draft workflows
        if !candidates.draft_ids.is_empty() {
            let (deleted, blocked) = self
                .workflow_repo
                .delete_workflows(&candidates.draft_ids, user_id)
                .await
                .unwrap_or((vec![], vec![]));
            tracing::warn!(
                user_id = %user_id,
                deleted = deleted.len(),
                blocked = blocked.len(),
                "hygiene fix: deleted stale draft workflows"
            );
            fix_results["stale_drafts_deleted"] = serde_json::json!(deleted.len());
            fix_results["stale_drafts_blocked"] = serde_json::json!(blocked.len());
        }

        // 2. Cancel/fail stale executions (mark as failed after >120 min stuck)
        if !candidates.stale_exec_ids.is_empty() {
            let cancelled = self
                .execution_repo
                .cleanup_stale_executions(120, user_id)
                .await
                .unwrap_or(0);
            fix_results["stale_executions_cancelled"] = serde_json::json!(cancelled);
        }

        // 3. Delete orphaned compiled modules (not referenced by any workflow)
        if !candidates.orphaned_module_ids.is_empty() {
            let deleted_modules = self
                .module_repo
                .delete_orphaned_modules(&candidates.orphaned_module_ids, user_id)
                .await
                .unwrap_or(0);
            tracing::warn!(
                user_id = %user_id,
                deleted = deleted_modules,
                "hygiene fix: deleted orphaned modules"
            );
            fix_results["orphaned_modules_deleted"] = serde_json::json!(deleted_modules);
        }

        serde_json::json!({
            "dry_run": false,
            "executed": true,
            "preview": candidates.preview,
            "results": fix_results,
            "note": "Fixes applied. Re-run get_platform_hygiene_report to verify the updated state.",
        })
    }
}

#[cfg(test)]
mod error_mapping_tests {
    use super::HygieneError;

    #[test]
    fn jsonrpc_code_internal_is_minus_32000() {
        let e = HygieneError::Internal(anyhow::anyhow!("boom"));
        assert_eq!(e.jsonrpc_code(), -32000);
    }

    /// Security invariant (ManifestError pattern): internal errors must
    /// collapse to the generic historical handler string — never leak
    /// schema/query details to the protocol caller.
    #[test]
    fn user_facing_message_internal_is_generic() {
        let e = HygieneError::Internal(anyhow::anyhow!(
            "db error: relation \"actor_memory\" does not exist at query XYZ"
        ));
        assert_eq!(e.user_facing_message(), "Failed to generate hygiene report");
        assert!(!e.user_facing_message().contains("relation"));
    }
}
