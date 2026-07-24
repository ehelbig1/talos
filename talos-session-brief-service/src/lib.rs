//! Session-brief service — backs the `session_start` MCP tool (and its
//! deprecated `agent_session_start` alias). Extracted from
//! `talos-mcp-handlers/src/advanced.rs` (~760 LoC handler) following the
//! cross-protocol Arc-injected service pattern (see
//! `WorkflowManifestService` / `ReplayService` / `InlineCompileService`):
//! typed input + outcome structs, `thiserror` enum with stable
//! `jsonrpc_code()` mapping, and `user_facing_message()` collapsing internal
//! errors to a generic string.
//!
//! The handler is now a thin wrapper: validate `auto_archive_stale_days` →
//! call [`SessionBriefService::build`] → spawn the auto-heal background
//! tasks the outcome requests → format. Output JSON is byte-identical to
//! the pre-extraction handler.
//!
//! Compile-time identity (server version / build time / static tool count)
//! stays in the HANDLER crate — `env!("GIT_SHA")` etc. are stamped by
//! `talos-mcp-handlers`' build script, and `static_tool_count()` counts the
//! handler crate's registered schemas — so they arrive here as inputs.

use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

/// Service-level errors. In practice every repository read in the brief is
/// best-effort (`unwrap_or_default`, matching the historical handler), so
/// `build` only fails on future required-path additions — the enum exists
/// for the stable protocol mapping.
#[derive(Debug, Error)]
pub enum SessionBriefError {
    /// Required-path repository call returned an error. Maps to `-32000`.
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl SessionBriefError {
    /// Stable JSON-RPC error code for protocol wrappers.
    pub fn jsonrpc_code(&self) -> i32 {
        match self {
            Self::Internal(_) => -32000,
        }
    }

    /// Generic, caller-safe message for the protocol response. Internal
    /// errors collapse to a generic string so no schema or query detail
    /// leaks to the caller.
    pub fn user_facing_message(&self) -> String {
        match self {
            Self::Internal(_) => "Failed to build session brief".to_string(),
        }
    }
}

/// Caller input for [`SessionBriefService::build`].
pub struct SessionBriefInput {
    /// User the brief is scoped to.
    pub user_id: Uuid,
    /// Validated `auto_archive_stale_days` (None = skip auto-archive;
    /// range-validation is protocol-level and stays in the handler).
    pub auto_archive_days: Option<i64>,
    /// Composite server version (`pkg+sha[-dirty]`) — compile-time identity
    /// of the handler crate, passed through.
    pub server_version: String,
    /// RFC3339 build timestamp — compile-time identity of the handler
    /// crate, passed through.
    pub build_time: String,
    /// Live static MCP tool count from the handler crate's registry.
    pub static_tool_count: usize,
}

/// Outcome of [`SessionBriefService::build`]. The two `spawn_*` flags tell
/// the caller which fire-and-forget auto-heal tasks to start; the spawns
/// stay caller-side because capability auto-tagging lives in the handler
/// crate (`analytics::auto_suggest_capabilities`).
pub struct SessionBriefOutcome {
    /// The full session brief JSON.
    pub report: serde_json::Value,
    /// True when unembedded workflows exist AND the embedding provider is
    /// available — the caller should spawn the background embed loop.
    pub spawn_embedding_heal: bool,
    /// True when uncapabilized workflows exist — the caller should spawn
    /// the background capability-tagging loop.
    pub spawn_capability_heal: bool,
}

/// Cross-protocol session-brief service. One Arc is shared by the MCP
/// handler (and, in time, any GraphQL consumer).
pub struct SessionBriefService {
    advanced_repo: Arc<talos_advanced_repository::AdvancedRepository>,
}

impl SessionBriefService {
    pub fn new(advanced_repo: Arc<talos_advanced_repository::AdvancedRepository>) -> Self {
        Self { advanced_repo }
    }

    /// Assemble the session brief for `input.user_id`. Mutating side
    /// effect: archives stale drafts when `auto_archive_days` is set.
    pub async fn build(
        &self,
        input: SessionBriefInput,
    ) -> Result<SessionBriefOutcome, SessionBriefError> {
        let user_id = input.user_id;
        let auto_archive_days = input.auto_archive_days;

        // 1. Embedding coverage
        let (total_wf, embedded_wf) = self
            .advanced_repo
            .get_embedding_coverage(user_id)
            .await
            .unwrap_or((0, 0));

        let unembedded = total_wf - embedded_wf;
        // When total_wf == 0 there are no workflows to embed — return null rather than
        // the misleading "100%" that a zero-division guard would produce.
        let embedding_pct: Option<i64> = if total_wf > 0 {
            Some(embedded_wf * 100 / total_wf)
        } else {
            None
        };

        // Auto-heal: the caller spawns background embedding for any unembedded
        // workflows (idempotent — auto_embed_workflow checks before writing).
        //
        // Gate on provider availability (added 2026-04-28, r239). Pre-r239 we
        // unconditionally spawned a per-workflow loop that all silently no-op'd
        // at DEBUG level when EMBEDDING_API_KEY / EMBEDDING_API_URL were unset
        // — operators saw "auto-embedding triggered in background" forever while
        // coverage stayed at 0/N. Now we skip the spawn AND surface the gap in
        // the response so the agent reports the misconfiguration instead of
        // promising "fully operational within seconds".
        let embedding_provider_available = talos_search_service::embedding_provider_available();
        let auto_healing_embeddings = unembedded > 0 && embedding_provider_available;

        // 2. Draft workflows (unpublished, no executions) — recent first
        let draft_rows = self
            .advanced_repo
            .get_draft_workflows(user_id)
            .await
            .unwrap_or_default();

        // Auto-archive stale drafts if requested
        let mut auto_archived_count = 0i64;
        if let Some(stale_days) = auto_archive_days {
            if let Ok(n) = self
                .advanced_repo
                .archive_stale_drafts(user_id, stale_days as i32)
                .await
            {
                auto_archived_count = n as i64;
            }
        }

        // Drafts split by substantive-ness (pain point #1, addressed r234):
        //   * `unpublished_substantive_drafts` — workflows that are well-configured
        //     but unpublished. The right next step is publish_version, not
        //     get_workflow_quickstart. Pre-r234 these were lumped into
        //     in_progress_drafts with a misleading "0 unconfigured nodes" hint.
        //   * `in_progress_drafts` — true work-in-progress: empty graph, mostly
        //     unconfigured nodes, recently-scaffolded skeletons. The right next
        //     step is still get_workflow_quickstart.
        //
        // "Substantive" criteria (any one is enough):
        //   - all non-structural nodes have non-empty data, AND node_count > 0
        //   - any node has SYSTEM_PROMPT > 200 chars (LLM node thoughtfully prompted)
        //   - any node has OUTPUT_SCHEMA configured (structured output authored)
        //   - any node has retry_count / retry_condition / retry_delay_expression
        //   - any node has description / skip_condition / continue_on_error set
        let mut in_progress_drafts: Vec<serde_json::Value> = Vec::new();
        let mut unpublished_substantive_drafts: Vec<serde_json::Value> = Vec::new();
        for r in draft_rows.iter().take(5) {
            let id = r.id.to_string();
            let graph: serde_json::Value = r
                .graph_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));
            let nodes = graph
                .get("nodes")
                .and_then(|n| n.as_array())
                .cloned()
                .unwrap_or_default();
            let node_count = nodes.len();
            let unconfigured_node_count =
                talos_hygiene_service::count_nodes_with_empty_data(&nodes);
            let days_old = (chrono::Utc::now() - r.created_at).num_days();

            // Substantive detection: walk graph_json once, look for any
            // marker of authored intent. Cheap to compute (capped at 5 drafts).
            let has_thoughtful_node = nodes.iter().any(|n| {
                let data = n.get("data");
                let prompt_len = data
                    .and_then(|d| d.get("SYSTEM_PROMPT"))
                    .and_then(|v| v.as_str())
                    .map(str::len)
                    .unwrap_or(0);
                let has_output_schema = data
                    .and_then(|d| d.get("OUTPUT_SCHEMA"))
                    .map(|v| !v.is_null())
                    .unwrap_or(false);
                let has_retry = n.get("retry_count").is_some()
                    || n.get("retry_condition").is_some()
                    || n.get("retry_delay_expression").is_some();
                let has_per_node_meta = n.get("description").is_some()
                    || n.get("skip_condition").is_some()
                    || n.get("continue_on_error").is_some();
                prompt_len > 200 || has_output_schema || has_retry || has_per_node_meta
            });
            let all_nodes_configured = node_count > 0 && unconfigured_node_count == 0;
            let is_substantive = all_nodes_configured || has_thoughtful_node;

            let next_step = if is_substantive {
                format!("publish_version with workflow_id={}", id)
            } else {
                format!("get_workflow_quickstart with workflow_id={}", id)
            };

            let entry = serde_json::json!({
                "workflow_id": id,
                "name": r.name,
                "node_count": node_count,
                "unconfigured_node_count": unconfigured_node_count,
                // MCP-2 / MCP-17: label the readiness mode so operators
                // know this is the coarse data-presence check, not the
                // strict schema-required check that get_workflow_quickstart
                // runs. The two surfaces can disagree for the same workflow.
                "unconfigured_check_mode": "data_presence_only",
                "days_old": days_old,
                "is_substantive": is_substantive,
                "next_step": next_step,
            });
            if is_substantive {
                unpublished_substantive_drafts.push(entry);
            } else {
                in_progress_drafts.push(entry);
            }
        }

        // 2b. Duplicate-name ghost workflow detection.
        // Multiple workflows with the same name indicate leftover test artifacts or
        // deliberate force=true duplicates that weren't cleaned up. Surface the
        // actual IDs + creation timestamps so the caller doesn't need a follow-up
        // list_workflows + filter pass.
        //
        // Performance: a single GROUP BY query (earlier version) avoids N+1, but
        // then forces a second query to resolve IDs. The current shape — select
        // id/name/created_at for every row in duplicate groups via a subquery —
        // stays O(duplicate_rows), which is tiny by definition (we only surface up
        // to 10 *groups*, each typically 2-3 rows).
        let duplicate_name_groups: Vec<serde_json::Value> = {
            let rows = self
                .advanced_repo
                .find_workflow_duplicate_name_groups(user_id)
                .await
                .unwrap_or_default();

            // Group rows by name. BTreeMap preserves alphabetical order for stable output.
            let mut groups: std::collections::BTreeMap<
                String,
                Vec<(uuid::Uuid, chrono::DateTime<chrono::Utc>)>,
            > = std::collections::BTreeMap::new();
            for r in rows {
                groups.entry(r.name).or_default().push((r.id, r.created_at));
            }

            groups
                .into_iter()
                .map(|(name, members)| {
                    // Oldest first; recommend deleting the older duplicates (the last
                    // force=true create is usually the one the author wanted to keep).
                    let workflows: Vec<serde_json::Value> = members
                        .iter()
                        .map(|(id, created_at)| {
                            serde_json::json!({
                                "id": id.to_string(),
                                "created_at": created_at.to_rfc3339(),
                            })
                        })
                        .collect();
                    let oldest_ids: Vec<String> = members
                        .iter()
                        .take(members.len().saturating_sub(1))
                        .map(|(id, _)| id.to_string())
                        .collect();
                    serde_json::json!({
                        "name": name,
                        "count": members.len(),
                        "workflows": workflows,
                        "suggested_cleanup": format!(
                            "Consider deleting the {} older duplicate(s): {}. \
                             The newest entry is typically the one the author wanted to keep.",
                            oldest_ids.len(),
                            oldest_ids.join(", "),
                        ),
                    })
                })
                .collect()
        };

        // 3. Uncapabilized workflows
        let uncap_count: i64 = self
            .advanced_repo
            .get_uncapabilized_count(user_id)
            .await
            .unwrap_or(0);

        // Auto-heal: the caller spawns background capability tagging for any
        // uncapabilized workflows. Idempotent — auto_suggest_capabilities only
        // applies when capabilities IS NULL or empty.
        let auto_healing_caps = uncap_count > 0;

        // 4. Next scheduled run.
        //
        // Pre-r234 this read from the wrong table (`schedules`) which was empty
        // in prod, so the field was always null even when active schedules existed
        // (pain point #8). Repo now queries `workflow_schedules` (the canonical
        // table since 20260309000200) and includes `next_trigger_at` so callers
        // can distinguish "no schedule" from "next firing is far out" without
        // a follow-up list_schedules call.
        let next_schedule = self
            .advanced_repo
            .get_next_scheduled_run(user_id)
            .await
            .ok()
            .flatten()
            .map(|s| {
                serde_json::json!({
                    "workflow": s.workflow_name,
                    "cron": s.cron_expression,
                    "timezone": s.timezone,
                    "next_trigger_at": s.next_trigger_at.map(|t| t.to_rfc3339()),
                })
            });

        // 4b. No-schedule health check: active workflows with no schedule
        let active_wf_count: i64 = self
            .advanced_repo
            .get_active_workflow_count(user_id)
            .await
            .unwrap_or(0);

        let active_schedule_count: i64 = self
            .advanced_repo
            .get_active_schedule_count(user_id)
            .await
            .unwrap_or(0);

        // Count of active workflows that ACTUALLY have ≥1 enabled schedule attached
        // — distinct from `active_wf_count` (every status='active' workflow) and
        // `active_schedule_count` (schedule-row count; a workflow can have several).
        // This is the field most callers think `active_workflows` means.
        let active_workflows_with_schedule: i64 = self
            .advanced_repo
            .get_active_workflows_with_schedule_count(user_id)
            .await
            .unwrap_or(0);

        let no_schedule_warning = active_wf_count > 0 && active_schedule_count == 0;

        // 5. Detect frequently-executed workflows without a schedule.
        // Condition: ≥3 executions in the last 60 days AND no active schedule
        // AND not a sub-workflow of another workflow AND not tagged `interactive`.
        // r242 renamed from `previously_scheduled_unscheduled` for honesty —
        // workflow_schedules are hard-deleted (no audit trail), so we have no
        // way to know if a workflow was ever scheduled. The pre-r242 name +
        // "may have lost their trigger" framing produced false positives for
        // pure manual-trigger utilities. The two new filters + the softer
        // framing below cut the false-positive rate sharply.
        // r243: surface query failures via tracing::warn so future schema/SQL
        // regressions are visible — pre-r243 the bare `.unwrap_or_default()`
        // swallowed the SQL error from r242's wrong JSONB path silently, and
        // session_start reported "clean" coverage while the query was broken.
        let prev_scheduled_rows = self
            .advanced_repo
            .get_frequently_executed_unscheduled(user_id)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(
                    error = %e,
                    "session_start: get_frequently_executed_unscheduled failed; \
                     frequently_executed_unscheduled will be reported as empty"
                );
                Vec::new()
            });

        let frequently_executed_unscheduled: Vec<serde_json::Value> = prev_scheduled_rows
            .iter()
            .map(|r| {
                let id = r.id.to_string();
                serde_json::json!({
                    "workflow_id": id,
                    "name": r.name,
                    "recent_executions": r.exec_count,
                    "tip": format!(
                        "If recurring is intended, schedule with create_schedule(workflow_id={}). \
                         If this is an on-demand utility, suppress this signal with \
                         tag_workflow(workflow_id={}, tag='interactive').",
                        id, id
                    ),
                })
            })
            .collect();

        // 6. Pinned modules: check which are present vs need restore.
        // IMPORTANT: check the user's actual wasm_modules row (installed copy), not just whether
        // the system node_templates row has WASM. A deleted wasm_modules row must show as
        // needs_restore even if the catalog template still has precompiled_wasm.
        let pinned_rows = self
            .advanced_repo
            .list_pinned_modules_with_user_install_status(user_id, 200)
            .await
            .unwrap_or_default();

        let mut pinned_present: Vec<String> = Vec::new();
        let mut pinned_needs_restore: Vec<String> = Vec::new();
        for r in pinned_rows {
            if r.has_wasm {
                pinned_present.push(r.module_name);
            } else {
                pinned_needs_restore.push(r.module_name);
            }
        }

        let needs_restore_count = pinned_needs_restore.len();
        let pinned_modules_field = serde_json::json!({
            "present": pinned_present,
            "needs_restore": pinned_needs_restore,
            // Always surface the tool name so agents don't have to discover it.
            // needs_restore being empty means nothing currently requires action.
            "restore_tool": "restore_pinned_modules",
            "restore_needed": needs_restore_count > 0,
        });

        // 7. Active actors — surface identity/persona context at session start so agents
        //    know what actors exist without a separate list_actors call.
        let actor_rows = self
            .advanced_repo
            .list_active_actors_with_memory_count(user_id, 20)
            .await
            .unwrap_or_default();

        let active_actors: Vec<serde_json::Value> = actor_rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "actor_id": r.id.to_string(),
                    "name": r.name,
                    "description": r.description,
                    "status": r.status,
                    "max_capability_world": r.max_capability_world,
                    "memory_count": r.memory_count,
                    "tip": if r.memory_count == 0 {
                        Some(format!(
                            "No memories set — define a persona with actor_remember(actor_id: '{}', key: 'persona', value: {{...}}, memory_type: 'semantic')",
                            r.id
                        ))
                    } else {
                        None
                    },
                })
            })
            .collect();

        // 8. Stuck executions: running > 1 hour
        let stuck_rows = self
            .advanced_repo
            .list_stuck_executions(user_id, 1, 10)
            .await
            .unwrap_or_default();

        let stuck_executions: Vec<serde_json::Value> = stuck_rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "execution_id": r.execution_id.to_string(),
                    "workflow_id": r.workflow_id.to_string(),
                    "hours_stuck": r.hours_stuck,
                    "tip": "cancel_execution or investigate with get_execution_status(detail: true)",
                })
            })
            .collect();

        // 8b. Recent execution activity for MCP-transport-drop awareness.
        //
        // Surfaces (a) currently-running executions of any age and
        // (b) executions that completed within the last RECENT_EXEC_WINDOW_MIN
        // minutes. The agent reads this on every session_start and can spot
        // executions it kicked off but lost the response for — preventing the
        // ghost-work pattern where a dropped MCP response is misread as
        // "execution failed", the agent retries, and the LLM provider is
        // double-billed for identical work.
        //
        // Window of 5 minutes is short enough not to be noisy on rapid
        // reconnects but long enough to catch the typical 15–30s LLM
        // workflow that the agent kicked off and immediately lost. Limit
        // of 25 caps the response size at the noisiest extreme.
        const RECENT_EXEC_WINDOW_MIN: i32 = 5;
        let recent_exec_rows = self
            .advanced_repo
            .list_recent_executions_for_session_awareness(user_id, RECENT_EXEC_WINDOW_MIN, 25)
            .await
            .unwrap_or_default();

        let recent_executions: Vec<serde_json::Value> = recent_exec_rows
            .iter()
            .map(|r| {
                let tip = match r.status.as_str() {
                    "running" => "Still in flight. get_execution_status(execution_id: ...) for live state, \
                                  or watch_execution to stream events. cancel_execution if you need to stop it.",
                    "completed" => "Already finished. get_execution_output(execution_id: ...) for the full \
                                    output — your client may have lost the response while the workflow was \
                                    still running on the server.",
                    "failed" | "cancelled" | "timeout" => "Reached terminal failure state. \
                                                           get_execution_status(execution_id: ..., detail: true) for the error.",
                    _ => "get_execution_status(execution_id: ...) to inspect.",
                };
                serde_json::json!({
                    "execution_id": r.execution_id.to_string(),
                    "workflow_id": r.workflow_id.to_string(),
                    "workflow_name": r.workflow_name,
                    "status": r.status,
                    "started_at": r.started_at.map(|t| t.to_rfc3339()),
                    "completed_at": r.completed_at.map(|t| t.to_rfc3339()),
                    "duration_ms": r.duration_ms,
                    "tip": tip,
                })
            })
            .collect();
        let recent_executions_count = recent_executions.len();
        let recent_running_count = recent_exec_rows
            .iter()
            .filter(|r| r.status == "running")
            .count();

        // 8. Determine single most impactful action
        //
        // Priority order: pinned-restore (data loss risk) → embedding provider
        // misconfigured (whole feature silently broken — surface ABOVE the
        // auto-healing branches because we WON'T be auto-healing in that case)
        // → auto-healing in progress → drafts → schedules.
        let embedding_provider_misconfigured = unembedded > 0 && !embedding_provider_available;
        let priority_action = if !pinned_needs_restore.is_empty() {
            format!(
                "{} pinned module(s) need WASM restore: {}. Call restore_pinned_modules.",
                pinned_needs_restore.len(),
                pinned_needs_restore.join(", ")
            )
        } else if embedding_provider_misconfigured {
            format!(
                "Embedding provider not configured — {} workflow(s) are unembedded and \
                 semantic search is degraded. Set EMBEDDING_API_KEY (or OPENAI_API_KEY) \
                 on the controller, or set EMBEDDING_API_URL to a keyless local \
                 endpoint (e.g. http://ollama:11434/v1/embeddings). Coverage will \
                 auto-heal on the next session_start once configured.",
                unembedded
            )
        } else if auto_healing_embeddings && auto_healing_caps {
            format!(
                "{} workflow(s) had no embedding and {} had no capability tags — \
                 both auto-healing in background. Platform will be fully indexed within seconds.",
                unembedded, uncap_count
            )
        } else if auto_healing_embeddings {
            format!(
                "{} workflow(s) had no embedding — auto-embedding triggered in background. \
                 Semantic search will be fully operational within seconds.",
                unembedded
            )
        } else if auto_healing_caps {
            format!(
                "{} workflow(s) have no capability tags — auto-tagging triggered in background. \
                 Capability-based discovery will be available within seconds.",
                uncap_count
            )
        } else if !unpublished_substantive_drafts.is_empty() {
            // Substantive drafts dominate priority over stub-class drafts —
            // the user has already done the work, just needs publish_version.
            format!(
                "You have {} substantive draft workflow(s) ready for publish_version. \
                 See unpublished_substantive_drafts for the list.",
                unpublished_substantive_drafts.len()
            )
        } else if !in_progress_drafts.is_empty() {
            format!(
                "You have {} stub draft workflow(s) (mostly unconfigured nodes). \
                 Call get_workflow_quickstart on the first one to see what's needed.",
                in_progress_drafts.len()
            )
        } else if !frequently_executed_unscheduled.is_empty() {
            format!(
                "{} active workflow(s) ran recently without a schedule — schedule with \
                 create_schedule if recurring is intended, or tag 'interactive' to suppress \
                 this signal for on-demand utilities. See frequently_executed_unscheduled \
                 for per-workflow tips.",
                frequently_executed_unscheduled.len()
            )
        } else if no_schedule_warning {
            format!(
                "{} active workflow(s) have no scheduled trigger. \
                 Call deploy_workflow with a cron_expression to automate execution.",
                active_wf_count
            )
        } else {
            "Platform looks healthy. All workflows are embedded, capabilized, and scheduled."
                .to_string()
        };

        let mut report = serde_json::json!({
            "embedding_coverage": {
                "total_workflows": total_wf,
                "embedded": embedded_wf,
                "unembedded": unembedded,
                // null when total_workflows == 0 (no workflows exist yet — not a real gap)
                "coverage_pct": embedding_pct,
                "auto_healing": auto_healing_embeddings,
                // "available" / "unavailable" — added r239 so the agent can
                // distinguish "auto-heal still running" from "provider missing,
                // nothing will ever heal". Pre-r239 the response always claimed
                // auto-heal was running even when it was a guaranteed no-op.
                "provider_status": if embedding_provider_available { "available" } else { "unavailable" },
                // r241: surface the cached `last_error` from the provider probe so the
                // agent can see "Voyage 429" or "DNS lookup failed" instead of just
                // "unavailable". Pre-r241 we couldn't distinguish "env vars unset"
                // from "URL unreachable" from "key revoked" — all collapsed to the
                // same syntactic-check failure.
                "provider_last_error": talos_search_service::embedding_provider_status().1,
                "provider_tip": if embedding_provider_misconfigured {
                    Some("Set EMBEDDING_API_KEY (or OPENAI_API_KEY) on the controller, OR set EMBEDDING_API_URL to a reachable OpenAI-compatible endpoint. See provider_last_error for the actual failure mode the boot probe observed. Without a working provider, semantic_search and auto-embedding silently no-op.")
                } else {
                    None
                },
                "note": if total_wf == 0 {
                    Some("No workflows created yet — create your first workflow to start tracking coverage.")
                } else {
                    None
                },
                // MCP-113 (2026-05-08): inline `field_meanings` so operators
                // reading the response don't have to guess what flags mean.
                // Same pattern as `schedule_health.field_meanings` further
                // down — applied here to embedding_coverage and below to
                // capabilities_coverage.
                "field_meanings": {
                    "auto_healing": "True when an auto-heal task is currently running to embed unembedded workflows in the background. False = no heal needed (coverage is complete) OR provider is unavailable (provider_status reports which). Look at provider_status + unembedded count to disambiguate.",
                    "coverage_pct": "Fraction (0–100) of workflows with usable embeddings. Below 100 means semantic_search will fall back to keyword/trigram matching for unembedded entries.",
                    "provider_status": "available = embedding provider responding to probes. unavailable = provider env vars unset OR endpoint unreachable OR key revoked. See provider_last_error for the specific failure mode.",
                    "unembedded": "Count of workflows whose vector embedding is missing or stale. While auto_healing is true, this number drops over time as the background task progresses.",
                },
            },
            "capabilities_coverage": {
                "uncapabilized_count": uncap_count,
                "auto_healing": auto_healing_caps,
                "tip": if uncap_count > 0 {
                    "Capability tags are being auto-applied in the background. \
                     Call run_workflow_hygiene to see which workflows still lack tags, \
                     or suggest_capabilities(workflow_id) to apply them manually."
                } else {
                    "All workflows have capability tags."
                },
                // MCP-113 (2026-05-08): mirror field_meanings on the
                // capabilities_coverage block.
                "field_meanings": {
                    "auto_healing": "True when an auto-suggest task is currently running to populate capability tags for uncapabilized workflows in the background. False = no heal needed (every workflow has tags) OR auto-heal is disabled.",
                    "uncapabilized_count": "Number of workflows with no capability tags. Workflows without tags are invisible to capability-based search and dispatch routing.",
                },
            },
            "in_progress_drafts": in_progress_drafts,
            "unpublished_substantive_drafts": unpublished_substantive_drafts,
            "duplicate_name_groups": duplicate_name_groups,
            "uncapabilized_count": uncap_count,
            "next_scheduled_run": next_schedule,
            "frequently_executed_unscheduled": frequently_executed_unscheduled,
            "schedule_health": {
                // Total count of `workflows.status='active'` — INCLUDES workflows
                // with no schedule attached (manual-trigger workflows, webhook-
                // driven workflows, etc.). Misleading legacy field name kept for
                // back-compat; prefer `workflows_with_active_schedules` for the
                // intuitive "how many active workflows are actually scheduled"
                // count.
                "active_workflows": active_wf_count,
                // Distinct count of active workflows that have at least one enabled
                // workflow_schedules row. Always ≤ active_workflows.
                "workflows_with_active_schedules": active_workflows_with_schedule,
                // Total count of enabled `workflow_schedules` rows. May exceed
                // workflows_with_active_schedules if a workflow has multiple
                // schedules attached (e.g. weekday morning + weekend evening).
                "active_schedules": active_schedule_count,
                // True when at least one workflow is active but ZERO schedules
                // are enabled across the user's namespace — a strong signal
                // that scheduling was forgotten or accidentally disabled.
                "no_schedule_warning": no_schedule_warning,
                "field_meanings": {
                    "active_workflows": "All workflows with status='active' (includes manual-trigger / webhook-only workflows). Not 'workflows that have a schedule'.",
                    "workflows_with_active_schedules": "Active workflows that have ≥1 enabled schedule attached.",
                    "active_schedules": "Total enabled schedule rows. ≥ workflows_with_active_schedules when workflows have multiple schedules."
                },
            },
            "pinned_modules": pinned_modules_field,
            "stuck_executions": stuck_executions,
            // Recent execution activity (running of any age + completed in last
            // RECENT_EXEC_WINDOW_MIN minutes). Surfaces work that ran in the
            // gap between MCP sessions so dropped tool-call responses don't
            // translate to ghost retries. Empty when nothing recent.
            "recent_executions": {
                "count": recent_executions_count,
                "running_count": recent_running_count,
                "window_minutes": RECENT_EXEC_WINDOW_MIN,
                "items": recent_executions,
                "tip": if recent_executions_count == 0 {
                    None
                } else if recent_running_count > 0 {
                    Some(format!(
                        "{} execution(s) still running. If you kicked one off and lost the response, \
                         do NOT retry — get_execution_status / watch_execution / get_execution_output \
                         with the execution_id from the items array.",
                        recent_running_count
                    ))
                } else {
                    Some(format!(
                        "{} execution(s) completed in the last {} minute(s). \
                         If your client lost the response from a recent test_workflow / call_workflow / trigger_workflow, \
                         pull get_execution_output(execution_id: ...) from the items array instead of retrying.",
                        recent_executions_count, RECENT_EXEC_WINDOW_MIN
                    ))
                },
            },
            "active_actors": active_actors,
            "priority_action": priority_action,
            // Schema staleness detection: compare this against your cached tools/list version.
            // If the version differs from what you connected with, reconnect to re-fetch the schema.
            // Composite version: pkg version + git SHA (+ "-dirty" if working
            // tree had uncommitted changes at build time). Operators can grep
            // for this exact string against `git log` to find the deployed
            // commit. Build.rs captures GIT_SHA / GIT_DIRTY / BUILD_TIME from
            // the source tree at compile time.
            "server_version": input.server_version,
            "build_time": input.build_time,
            // Client transport advisory: the server exposes 300+ tools via tools/list.
            // Some MCP clients (claude.ai web connector, Claude Desktop with large tool sets)
            // only make a FIXED SUBSET callable at session init, regardless of which tools appear
            // in tools/list. The callable set is client-determined and cannot be expanded server-side.
            // Symptoms: tool_search shows a tool schema but calling it returns "has not been loaded yet".
            // Resolution: use Claude Code CLI (stdio transport) for full 300+ tool access.
            // The tools/list ordering fix (session_start at index 0) ensures critical tools are
            // callable on clients that truncate by position (Claude Desktop, narrow-context clients).
            "client_compatibility": {
                "full_tool_access": "Use Claude Code CLI (claude mcp add talos ...) for all tools callable via stdio transport",
                "partial_access_clients": ["claude.ai web connector", "Claude Desktop with large tool sets"],
                "symptom": "tool_search shows schema but tool call returns 'has not been loaded yet'",
                "workaround": "Reconnect to server to reset callable set, or switch to Claude Code CLI"
            },
            // Stale-cache tripwire for the agent. The server registers this
            // many static MCP tools right now. If the agent has observed
            // fewer tools than this in `tools/list` / `tool_search`
            // since connecting, the client's tool cache is stale relative
            // to the server (the server was rebuilt with new tools after
            // the client connected). Action: prompt the user to `/mcp`
            // reconnect. See `mcp::static_tool_count` for the source of
            // truth.
            "static_tool_count": input.static_tool_count,
        });

        // DX #17: image staleness. BUILD_TIME is stamped at compile time; a dev
        // stack whose controller predates recent merges is a recurring trap —
        // "the fix is on main but the running image doesn't have it" cost two
        // rebuild cycles on 2026-07-13 alone. Surface the age always, and an
        // actionable tip once it exceeds a day.
        if let Ok(built) = chrono::DateTime::parse_from_rfc3339(&input.build_time) {
            let age_hours = (chrono::Utc::now() - built.with_timezone(&chrono::Utc)).num_minutes()
                as f64
                / 60.0;
            report["build_age_hours"] = serde_json::json!((age_hours * 10.0).round() / 10.0);
            if age_hours > 24.0 {
                report["build_staleness_tip"] = serde_json::json!(format!(
                    "controller image was built {age_hours:.0}h ago — if code merged since, this \
                     process doesn't have it; rebuild + recreate before live-testing \
                     (make rebuild SERVICE=controller)"
                ));
            }
        }

        if auto_archive_days.is_some() {
            report["auto_archived_stale_drafts"] = serde_json::json!(auto_archived_count);
        }

        // #7 — hint to enable auto_archive when in-progress drafts accumulate
        let in_progress_count = report
            .get("in_progress_drafts")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        if in_progress_count > 0 && auto_archive_days.is_none() {
            report["auto_archive_hint"] = serde_json::json!(
                "Pass auto_archive_stale_days: 14 to automatically clean up drafts older than 14 days on next session_start."
            );
        }

        Ok(SessionBriefOutcome {
            report,
            spawn_embedding_heal: auto_healing_embeddings,
            spawn_capability_heal: auto_healing_caps,
        })
    }
}

#[cfg(test)]
mod error_mapping_tests {
    use super::SessionBriefError;

    #[test]
    fn jsonrpc_code_internal_is_minus_32000() {
        let e = SessionBriefError::Internal(anyhow::anyhow!("boom"));
        assert_eq!(e.jsonrpc_code(), -32000);
    }

    /// Security invariant (ManifestError pattern): internal errors must
    /// collapse to a generic string — never leak schema/query details.
    #[test]
    fn user_facing_message_internal_is_generic() {
        let e = SessionBriefError::Internal(anyhow::anyhow!(
            "db error: relation \"workflows\" does not exist at query XYZ"
        ));
        assert_eq!(e.user_facing_message(), "Failed to build session brief");
        assert!(!e.user_facing_message().contains("relation"));
    }
}
