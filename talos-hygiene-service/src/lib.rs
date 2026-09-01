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
pub mod twin_divergence;

pub use graph_heuristics::{count_nodes_with_empty_data, is_substantive_workflow};
pub use twin_divergence::{analyze_twins, TwinAnalysis, TwinCandidate};

use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

/// How to read `summary.embedding_coverage_percent`, including its null.
pub const EMBEDDING_COVERAGE_NOTE: &str =
    "share of this user's counted workflows (denominator = summary.total_workflows) that have a \
     semantic-search embedding, rounded to one decimal; null when there are no counted workflows \
     — an empty platform has no coverage to report, and 100 would read as 'fully indexed'. \
     Exactly 100 means EVERY counted workflow is embedded and exactly 0 means none are: a \
     near-miss that would round onto an endpoint is held at 99.9 / 0.1 instead, so the number \
     never contradicts unembedded_workflow_count";

/// A share of a whole as a percentage, rounded to ONE decimal
/// (half-away-from-zero), or `None` when there is no whole.
///
/// D4 (2026-07-29). Every percent in this crate was `part * 100 / whole` on
/// `i64` — INTEGER division, which truncates toward zero. Two ways that
/// misleads, both observed in this file:
///   * `249 * 100 / 250` = `99`, not `99.6`. On a coverage metric an operator
///     drives to 100, the truncation is systematically pessimistic and hides
///     the last percent of progress.
///   * `1 * 100 / 250` = `0`. A real, actionable gap renders as literally
///     nothing, in a sentence that says "1 of 250" two words earlier.
///
/// `None` rather than `0` or `100` on a zero denominator: a share of an empty
/// population is not a share, and both of the plausible defaults read as a
/// verdict (`0` = "none of it", `100` = "all of it"). Same doctrine as
/// [`talos_measurement::Measurement::rate`] and the digest's
/// `failure_rate_24h_pct`.
///
/// Nonsense inputs (negative counts, `part > whole`) return `None` too —
/// refused rather than clamped into a plausible-looking number.
///
/// **The endpoints are reserved for the exact cases.** Rounding to one decimal
/// re-creates D4's own bug at the other end of the scale: `1999/2000` is
/// 99.95%, which `format_percent` rounds to `100.0` — "fully indexed" printed
/// beside `unembedded_workflow_count: 1`, the same self-contradicting sentence
/// the `1 * 100 / 250 == 0` truncation produced. So a non-exact share that
/// would land on an endpoint is held one step short (99.9 / 0.1). `100.0`
/// therefore means EXACTLY all and `0.0` EXACTLY none, and the reader never
/// has to reconcile the percent against the count beside it.
#[must_use]
pub fn share_pct(part: i64, whole: i64) -> Option<f64> {
    if whole <= 0 || part < 0 || part > whole {
        return None;
    }
    // `format_percent` is the platform's one percent-rounding contract (1
    // decimal, JSON number) — reused rather than re-implemented so hygiene
    // percents round exactly like every other percent surface.
    let pct = talos_analytics_repository::format_percent((part as f64 / whole as f64) * 100.0);
    Some(match pct {
        p if p >= 100.0 && part < whole => 99.9,
        p if p <= 0.0 && part > 0 => 0.1,
        p => p,
    })
}

/// Render a [`share_pct`] result for interpolation into operator prose.
///
/// An unmeasurable share renders as `"share unknown"`, never as `"0%"` — the
/// string form has to carry the same refusal the number does, or the null is
/// undone the moment it reaches a sentence.
#[must_use]
/// The copy-pasteable `generate_typed_scaffold` calls the untyped-Value
/// recommendation carries, one per flagged module.
///
/// Extracted out of `HygieneService::generate` (async, DB-backed, untestable)
/// so the hint can be checked against `generate_typed_scaffold`'s real schema
/// — see `talos_mcp_handlers::tool_hints`. A hint that names a tool or an
/// argument the server does not declare is worse than no hint: the operator
/// pastes it and the call is rejected.
pub fn build_typed_scaffold_fix_commands(
    modules: &[talos_analytics_repository::UntypedValueModuleRow],
) -> Vec<serde_json::Value> {
    modules
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
        .collect()
}

pub fn render_share_pct(pct: Option<f64>) -> String {
    match pct {
        Some(p) => format!("{p}%"),
        None => "share unknown".to_string(),
    }
}

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

        // --- 4b. Promote-to-template candidates (high fan-out DB modules) ---
        let promotable_modules: Vec<serde_json::Value> = h
            .promotable_modules
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id.to_string(),
                    "name": r.name,
                    "dependent_count": r.dependent_count,
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

        // --- Twinned-workflow divergence (advisory) ---
        //
        // A defect fixed on ONE instance of a duplicated workflow is not
        // fixed — the twin keeps running the old behavior until someone
        // notices. That happened twice in one week on the inbox organizers
        // (a missing `coverage_judge` leaf, then judge verdict drift), so
        // the hygiene report now diffs name-paired twins. Grading is
        // deliberate: only structural + control-logic divergence earns a
        // recommendation. Module/prompt/auth differences are how real twins
        // are SUPPOSED to differ, and an entry that fires on those would
        // train operators to ignore the one that matters.
        let twin_candidates: Vec<twin_divergence::TwinCandidate> = h
            .workflow_graphs
            .iter()
            .map(|g| twin_divergence::TwinCandidate {
                id: g.id.to_string(),
                name: g.name.clone(),
                graph_json: g.graph_json.clone(),
            })
            .collect();
        let twin_analysis = twin_divergence::analyze_twins(&twin_candidates);
        let diverged_twin_pairs = twin_analysis.diverged_pairs().count();
        let workflow_twins = twin_divergence::twins_section(
            &twin_analysis,
            twin_divergence::ScanCoverage {
                truncated: h.workflow_graphs_truncated,
                skipped_graphs: h.workflow_graphs_skipped,
                scan_failed: h.workflow_graphs_scan_failed,
            },
        );

        // --- Build summary and recommendations ---
        let mut recommendations: Vec<serde_json::Value> = Vec::new();

        if let Some(rec) = twin_divergence::twin_recommendation(&twin_analysis) {
            recommendations.push(rec);
        }

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
            // D4 (2026-07-29): honest rounding. `unembedded * 100 / total`
            // is INTEGER division — 1 unembedded workflow out of 250 rendered
            // "(0%) lack embeddings" directly beside "1 of 250", i.e. the
            // sentence contradicted itself and the actionable number rounded
            // away to nothing. `share_pct` rounds half-away-from-zero to one
            // decimal, so that case reads 0.4%.
            let pct = share_pct(unembedded_count, total_workflow_count);
            recommendations.push(serde_json::json!({
                "priority": "medium",
                "category": "semantic_search",
                "action": format!("{} of {} workflows ({}) lack embeddings — semantic search falls back to keyword matching for these. Run generate_workflow_embeddings to index them for true vector search.", unembedded_count, total_workflow_count, render_share_pct(pct)),
                "affected_count": unembedded_count,
                // The rendered share as a number, for a consumer that would
                // otherwise re-parse it out of `action`.
                "affected_share_pct": pct,
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

        if !promotable_modules.is_empty() {
            let names: Vec<String> = promotable_modules
                .iter()
                .filter_map(|m| {
                    let n = m.get("name").and_then(|v| v.as_str())?;
                    let c = m
                        .get("dependent_count")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
                    Some(format!("{n} ({c} workflows)"))
                })
                .collect();
            recommendations.push(serde_json::json!({
                "priority": "medium",
                "category": "maintainability",
                "action": format!(
                    "{} custom module(s) are used by 3+ workflows but live only as DB-resident compiled blobs (no version control, no shared fix): {}. Promote each to a versioned catalog template under module-templates/ so its source is reviewable and a fix applies everywhere. Retrieve the current source with get_module_source.",
                    promotable_modules.len(),
                    names.join(", ")
                ),
                "affected_count": promotable_modules.len(),
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
                "action": format!("{} STATIC API key/token secret(s) have no expiry date set — nothing rotates them. Set an expiry in the dashboard (Settings → Secrets) to enforce a rotation cadence — secret writes require 2FA and aren't available through MCP. (Platform-managed `oauth/*` credentials are excluded: refresh_oauth_token already rotates those, and hand-expiring one breaks the integration until its next refresh.)", secrets_without_expiry.len()),
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
            let fix_commands = build_typed_scaffold_fix_commands(&h.untyped_value_modules);
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
            + diverged_twin_pairs
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
                "high": undescribed.len() + uncapabilized.len() + expiring_actor_memories.len() + diverged_twin_pairs,
                "medium": (if unembedded_count > 0 { 1 } else { 0 }) + secret_issues + workflows_needing_schema.len(),
                "low": orphaned_modules.len() + dormant_workflows.len() + stale_draft_workflows.len() + idle_actors.len(),
                "total_workflows": total_workflow_count,
                "idle_actors_count": idle_actors.len(),
                "wildcard_secret_grant": h.has_wildcard_module,
                "orphaned_secrets_count": orphaned_secrets.len(),
                "secrets_without_expiry_count": secrets_without_expiry.len(),
                "expiring_memories_count": expiring_actor_memories.len(),
                "workflows_needing_schema_count": workflows_needing_schema.len(),
                "promotable_modules_count": promotable_modules.len(),
                // Three DIFFERENT populations, all reported, because reading
                // any one alone misstates the check:
                //   twin_pairs_count        — name pairs that also passed the
                //                             STRUCTURAL confirmation gate,
                //                             i.e. the pairs actually diffed;
                //   diverged_twin_pairs_count — of those, the ones carrying
                //                             recommendation-grade divergence
                //                             (the only ones counted as issues);
                //   name_related_only_count — pairs that share a name shape but
                //                             failed the gate. Never diffed, so
                //                             they contribute NO findings and NO
                //                             recommendation; listed with their
                //                             node counts in `workflow_twins` so
                //                             the omission is visible.
                "twin_pairs_count": twin_analysis.pairs.len(),
                "diverged_twin_pairs_count": diverged_twin_pairs,
                "name_related_only_count": twin_analysis.name_related_only.len(),
                "suppressed_internal_test_workflows": suppressed_count,
                "suppressed_low_score_count": suppressed_low_score_count,
                "auto_classified_test_like_workflows": auto_classified_count,
                // D4 (2026-07-29): two fixes on one line.
                //   1. Integer division truncated TOWARD ZERO, so 249 of 250
                //      embedded rendered 99 — and, worse, the truncation is
                //      systematically pessimistic on a metric an operator
                //      chases to 100. `share_pct` rounds to one decimal
                //      (99.6), so the last workflow is visibly the last one.
                //   2. The zero-workflow case claimed `100` — a coverage
                //      verdict from an empty population, the exact
                //      "0.0 reads as healthy" defect inverted. It is now
                //      `null`: nothing to embed is not full coverage.
                // Denominator is `total_workflow_count`, the same population
                // `unembedded_workflow_count` is counted out of.
                "embedding_coverage_percent": share_pct(
                    total_workflow_count - unembedded_count,
                    total_workflow_count,
                ),
                "embedding_coverage_note": EMBEDDING_COVERAGE_NOTE,
                "note": note,
            },
            "stale_executions": stale_executions,
            "undescribed_workflows": undescribed,
            "uncapabilized_workflows": uncapabilized,
            "unembedded_workflow_count": unembedded_count,
            "orphaned_modules": orphaned_modules,
            "promotable_modules": promotable_modules,
            "dormant_workflows": dormant_workflows,
            "stale_draft_workflows": stale_draft_workflows,
            "idle_actors": idle_actors,
            "orphaned_secrets": orphaned_secrets,
            "secrets_without_expiry": secrets_without_expiry,
            "expiring_actor_memories": expiring_actor_memories,
            "workflows_needing_schema": workflows_needing_schema,
            "workflow_twins": workflow_twins,
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
            // Every list above is a per-check finding vector capped at
            // HYGIENE_FINDING_LIMIT by SQL, so `total_fixable` is a sum of
            // capped counts and cannot exceed 3x that cap. Without this the
            // number reads as "everything fixable", which is what an operator
            // is being asked to confirm.
            "coverage": {
                "stale_draft_workflows": talos_measurement::Coverage::new(
                    i64::try_from(auto_deletable_drafts.len() + substantive_drafts_skipped.len())
                        .unwrap_or(i64::MAX),
                    talos_analytics_repository::HYGIENE_FINDING_LIMIT,
                ).to_json(),
                "stale_executions": talos_measurement::Coverage::new(
                    i64::try_from(stale_exec_ids.len()).unwrap_or(i64::MAX),
                    talos_analytics_repository::HYGIENE_FINDING_LIMIT,
                ).to_json(),
                "orphaned_modules": talos_measurement::Coverage::new(
                    i64::try_from(orphaned_module_ids.len()).unwrap_or(i64::MAX),
                    talos_analytics_repository::HYGIENE_FINDING_LIMIT,
                ).to_json(),
                "note": "total_fixable counts only the findings LISTED here, and each list is \
                         capped independently. A `truncated: true` above means fix_all will \
                         address a bounded subset and leave the rest — re-run it after \
                         confirming.",
            },
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
        //
        // 2026-08-19: this passes `stale_exec_ids` because it once did NOT.
        // The call was `cleanup_stale_executions(120, user_id)` — user-wide,
        // with the id list used only as an `is_empty()` trigger — while the
        // preview the operator confirmed was capped at 25 rows. Confirming a
        // 25-row preview marked EVERY stale execution for the user as failed.
        // Steps 1 and 3 below always passed their id lists; this one did not.
        // The action is now a subset of the preview by construction.
        if !candidates.stale_exec_ids.is_empty() {
            let cancelled = self
                .execution_repo
                .cleanup_stale_executions_by_ids(&candidates.stale_exec_ids, 120, user_id)
                .await
                .unwrap_or(0);
            fix_results["stale_executions_cancelled"] = serde_json::json!(cancelled);
            // `cancelled` can legitimately be LOWER than the previewed count:
            // the preview selects running/queued/resuming, the write touches
            // only `running`, and a row may have finished in between. Saying so
            // stops the gap reading as a partial failure.
            fix_results["stale_executions_previewed"] =
                serde_json::json!(candidates.stale_exec_ids.len());
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

#[cfg(test)]
mod share_pct_tests {
    use super::{render_share_pct, share_pct, EMBEDDING_COVERAGE_NOTE};

    /// The two cases integer division got wrong, both from a 250-workflow
    /// platform — the exact shape this crate reports on.
    #[test]
    fn integer_division_truncation_is_gone() {
        // 249/250 embedded: was `99` (the pessimistic truncation an operator
        // chasing 100% sees stall), now 99.6.
        assert_eq!(share_pct(249, 250), Some(99.6));
        // 1/250 unembedded: was `0` — a real gap rendering as nothing, in a
        // sentence that says "1 of 250".
        assert_eq!(share_pct(1, 250), Some(0.4));
    }

    /// Rounding is half-away-from-zero to ONE decimal, matching
    /// `format_percent` — the platform's single percent contract.
    #[test]
    fn rounds_to_one_decimal_not_toward_zero() {
        // 2/3 = 66.666…  → 66.7 (rounds UP; truncation gave 66).
        assert_eq!(share_pct(2, 3), Some(66.7));
        // 1/3 = 33.333…  → 33.3.
        assert_eq!(share_pct(1, 3), Some(33.3));
        // 1/8 = 12.5 exactly — no rounding to do.
        assert_eq!(share_pct(1, 8), Some(12.5));
    }

    /// The endpoints stay exact: a full or empty share must not drift off
    /// 100.0 / 0.0 through float noise.
    #[test]
    fn endpoints_are_exact() {
        assert_eq!(share_pct(250, 250), Some(100.0));
        assert_eq!(share_pct(0, 250), Some(0.0));
    }

    /// …and the endpoints are RESERVED for those exact cases. Rounding to one
    /// decimal otherwise re-creates D4's own bug at the top of the scale:
    /// 1999/2000 is 99.95%, which rounds to 100.0 — "fully indexed" printed
    /// beside a nonzero `unembedded_workflow_count`, exactly the sentence that
    /// contradicts itself.
    #[test]
    fn a_nonzero_gap_never_renders_as_a_hundred() {
        assert_eq!(share_pct(1999, 2000), Some(99.9));
        assert_eq!(share_pct(19_999, 20_000), Some(99.9));
        // Symmetrically at the bottom: a real, single unembedded workflow out
        // of 20 000 is not "none of them".
        assert_eq!(share_pct(1, 20_000), Some(0.1));
        // The step below each endpoint is untouched — the guard only fires on
        // a value that ROUNDED onto the endpoint.
        assert_eq!(share_pct(999, 1000), Some(99.9));
        assert_eq!(share_pct(1, 1000), Some(0.1));
    }

    /// A share of an empty population is refused, in BOTH directions — the
    /// pre-fix code answered `0` at one site and `100` at the other, and both
    /// are verdicts drawn from nothing.
    #[test]
    fn zero_denominator_is_null_never_zero_and_never_a_hundred() {
        assert_eq!(share_pct(0, 0), None);
        assert_eq!(share_pct(5, 0), None);
        assert_eq!(share_pct(0, -3), None);
    }

    /// Impossible inputs are refused rather than clamped into something
    /// plausible.
    #[test]
    fn impossible_shares_are_refused() {
        assert_eq!(share_pct(5, 4), None);
        assert_eq!(share_pct(-1, 4), None);
    }

    /// The prose renderer must carry the refusal too — a null that becomes
    /// "0%" the moment it reaches a sentence is not a null.
    #[test]
    fn rendered_prose_never_turns_an_unknown_share_into_zero_percent() {
        assert_eq!(render_share_pct(Some(0.4)), "0.4%");
        assert_eq!(render_share_pct(Some(100.0)), "100%");
        assert_eq!(render_share_pct(None), "share unknown");
        assert!(!render_share_pct(None).contains('%'));
    }

    #[test]
    fn the_coverage_note_states_its_denominator_and_its_null() {
        let n = EMBEDDING_COVERAGE_NOTE;
        assert!(n.contains("summary.total_workflows"), "{n}");
        assert!(n.contains("null when"), "{n}");
        assert!(n.contains("one decimal"), "{n}");
    }
}

#[cfg(test)]
mod destructive_preview_pins {
    //! The `fix_all` confirmation prompt must never under-state what it runs.
    //!
    //! These are SOURCE pins rather than behavioural tests because
    //! `execute_fixes` needs Postgres, an S3/WORM endpoint and a populated
    //! hygiene report to drive, and the property at stake is structural: which
    //! repository method the destructive step calls. A behavioural test would
    //! need the very fixture that made the original bug invisible (a tenant with
    //! more than HYGIENE_FINDING_LIMIT stale executions).

    /// The bug, 2026-08-19: step 2 of `execute_fixes` called the USER-WIDE
    /// `cleanup_stale_executions(120, user_id)` while the operator had confirmed
    /// a preview capped at 25 rows — the id list was built, rendered, and then
    /// used only as an `is_empty()` trigger. Confirming a 25-row preview marked
    /// every stale execution for the user as `failed`.
    ///
    /// This test FAILS on that tree and passes on the fix.
    #[test]
    fn fix_all_cancels_only_the_executions_it_previewed() {
        // Needles are `concat!`-assembled so this test's own source text is not
        // a match — a self-scanning `include_str!` that matches itself is a
        // test that can never fail.
        let src = include_str!("lib.rs");

        assert!(
            src.contains(concat!(
                "cleanup_stale_executions",
                "_by_ids(&candidates.stale_exec_ids"
            )),
            "fix_all's stale-execution step must pass the previewed id list; without it the \
             action is user-wide while the preview is capped, and the operator confirms a \
             subset while a superset executes"
        );

        // And the user-wide sibling must not reappear here. Scoped to a `self.`
        // receiver so the doc-comment prose naming the old method (which is
        // deliberate — it explains the bug) does not satisfy or trip the pin.
        assert!(
            !src.contains(concat!(".", "cleanup_stale_executions(")),
            "the user-wide cleanup_stale_executions is back in the hygiene path; it is correct \
             for the cleanup_stale_executions MCP tool, which asks the operator for a time \
             window, and wrong here, where a bounded preview was already shown"
        );
    }

    /// Steps 1 and 3 always passed their id lists. Pinning them alongside step 2
    /// states the invariant as a property of the whole `fix_all`, not as a
    /// patch to the one step that broke it.
    #[test]
    fn every_destructive_fix_all_step_is_bounded_by_its_preview() {
        let src = include_str!("lib.rs");
        for needle in [
            concat!("delete_workflows(&candidates.", "draft_ids"),
            concat!(
                "delete_orphaned_modules(&candidates.",
                "orphaned_module_ids"
            ),
            concat!(
                "cleanup_stale_executions_by_ids(&candidates.",
                "stale_exec_ids"
            ),
        ] {
            assert!(
                src.contains(needle),
                "a destructive fix_all step stopped passing its previewed id list: {needle}"
            );
        }
    }
}
