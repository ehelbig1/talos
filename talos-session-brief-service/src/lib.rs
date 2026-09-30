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

/// Service-level errors. Every repository read in the brief is best-effort:
/// a read that fails renders its field as `null` and names it under
/// `measurement.not_measured` (`talos_measurement::Readings`), so `build`
/// only fails on future required-path additions — the enum exists for the
/// stable protocol mapping.
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
    /// The full session brief JSON, with the `measurement` disclosure
    /// attached when a read failed.
    pub report: serde_json::Value,
    /// The brief's one ledger. A caller that adds a section records its read
    /// through [`SessionBriefOutcome::record`], so the disclosure covers it.
    readings: talos_measurement::Readings,
    /// True when unembedded workflows exist AND the embedding provider is
    /// available — the caller should spawn the background embed loop.
    pub spawn_embedding_heal: bool,
    /// True when uncapabilized workflows exist — the caller should spawn
    /// the background capability-tagging loop.
    pub spawn_capability_heal: bool,
}

impl SessionBriefOutcome {
    /// Record a read the CALLER adds to the brief (the handler's catalog-drift
    /// section, say): `None` on failure, and the field is named in
    /// `measurement.not_measured` alongside the service's own reads. One
    /// ledger per report — a second one would publish "complete" over this
    /// failure.
    pub fn record<T, E: std::fmt::Display>(
        &mut self,
        field: &'static str,
        result: Result<T, E>,
    ) -> Option<T> {
        let value = self.readings.record(field, result);
        self.readings.attach(&mut self.report);
        value
    }
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

        // ONE ledger for the whole brief. A read that fails yields `None`, its
        // field renders `null` and is named under `measurement.not_measured`,
        // and `priority_action` may not call the platform healthy. Until
        // 2026-09-30 twelve of these reads defaulted to `0` / `[]` on error,
        // so a database fault read as "nothing stuck, nothing to restore,
        // platform healthy". Check 74b now scans this function because it
        // constructs a `Readings`: a new awaited read that is defaulted here
        // fails the lint.
        let mut readings = talos_measurement::Readings::new();

        // 1. Embedding coverage
        let coverage = readings.record(
            "embedding_coverage",
            self.advanced_repo.get_embedding_coverage(user_id).await,
        );
        let total_wf: Option<i64> = coverage.map(|(total, _)| total);
        let embedded_wf: Option<i64> = coverage.map(|(_, embedded)| embedded);
        let unembedded: Option<i64> = coverage.map(|(total, embedded)| total - embedded);
        // When total_wf == 0 there are no workflows to embed — return null rather than
        // the misleading "100%" that a zero-division guard would produce.
        let embedding_pct: Option<i64> = match coverage {
            Some((total, embedded)) if total > 0 => Some(embedded * 100 / total),
            _ => None,
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
        let auto_healing_embeddings =
            unembedded.is_some_and(|n| n > 0) && embedding_provider_available;

        // 2. Auto-archive stale drafts if requested — BEFORE the draft display
        // read, deliberately.
        //
        // The order is the second half of the disjointness this response owes
        // an operator. The first half is that the sweep now refuses to archive
        // a draft a human visibly shaped, so a row can never appear under
        // `unpublished_substantive_drafts` ("ready for publish_version") AND be
        // archived by the same call — measured on pristine `origin/main`
        // 2026-09-05, where exactly that happened with
        // `auto_archived_stale_drafts: 1`. The second half is this ordering:
        // `get_draft_workflows` filters `status = 'draft'`, so reading it AFTER
        // the sweep means neither list can name a row this response just
        // archived. Pre-2026-09-05 the read came first, so even a STUB was
        // listed with `next_step: get_workflow_quickstart` moments after being
        // archived — a smaller version of the same defect, and one no
        // substantive-ness rule would have closed.
        //
        // An `Err` here is DISCLOSED, not defaulted to 0: the sweep aborts
        // rather than archive without the child exclusion (see
        // `archive_stale_drafts_excluding_children`), and "0 archived" beside a
        // silent failure reads as "there was nothing stale" — a claim about
        // system state nobody measured.
        let mut auto_archived_count = 0i64;
        let mut auto_archive_outcome: Option<talos_advanced_repository::StaleDraftArchiveOutcome> =
            None;
        let mut auto_archive_failed = false;
        if let Some(stale_days) = auto_archive_days {
            match self
                .advanced_repo
                .archive_stale_drafts_excluding_children(user_id, stale_days as i32)
                .await
            {
                Ok(outcome) => {
                    auto_archived_count = i64::try_from(outcome.archived).unwrap_or(i64::MAX);
                    auto_archive_outcome = Some(outcome);
                }
                Err(e) => {
                    tracing::warn!(
                        %user_id,
                        error = %e,
                        "session_start auto-archive failed; no draft was archived"
                    );
                    auto_archive_failed = true;
                    readings.mark_derived("auto_archived_stale_drafts");
                }
            }
        }

        // 2b. Draft workflows (unpublished, no executions) — recent first.
        // Post-sweep by construction (see above).
        let draft_read = readings.record(
            "in_progress_drafts",
            self.advanced_repo.get_draft_workflows(user_id).await,
        );
        let drafts_measured = draft_read.is_some();
        if !drafts_measured {
            // Both lists come from the one read.
            readings.mark_derived("unpublished_substantive_drafts");
        }
        let draft_rows = draft_read.unwrap_or_default();

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
        // Which of the drafts about to be listed is somebody's CHILD. The
        // list's own premise ("never executed") is blind to a sub-workflow —
        // it runs in-process and leaves no `workflow_executions` row — and
        // the hygiene report has said so beside the same row since #760. This
        // brief did not: until 2026-09-11 it listed the fleet's one live
        // child, `cos-team-recall`, under `unpublished_substantive_drafts`
        // with `next_step: publish_version …` and made that the
        // `priority_action` of every session, while `publish_version` on a
        // child changes NOTHING at runtime (the parent dispatches the draft's
        // `graph_json` column directly, no version join, no status filter).
        // Two surfaces, one recommendation, contradicting each other. A child
        // stays LISTED — hiding it would be a different misleading report —
        // but its `next_step` says what is true and it does not count toward
        // the publish nudge. A failed scan is DISCLOSED on every entry as
        // `child_status: "unknown"` rather than defaulted to "not a child".
        let listed_ids: Vec<Uuid> = draft_rows.iter().take(5).map(|r| r.id).collect();
        let child_scan = match self
            .advanced_repo
            .scan_child_parents_for(user_id, &listed_ids)
            .await
        {
            Ok(scan) => Some(scan),
            Err(e) => {
                tracing::warn!(
                    %user_id,
                    error = %e,
                    "session_start draft list: child-reference scan failed; \
                     child status is UNKNOWN for every listed draft"
                );
                None
            }
        };

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

            // Substantive detection. Until 2026-09-05 this was an INLINE COPY
            // of the walk in `talos-draft-heuristics` — behaviourally
            // identical, and asserted to be the same predicate by that
            // module's own doc comment, which claimed both surfaces "consult
            // this helper". They did not. The copy is gone; this is the same
            // call the ARCHIVE sweep below makes about the same row, which is
            // what makes the two lists in this response disjoint by
            // construction rather than by coincidence.
            let is_substantive =
                talos_hygiene_service::is_substantive_workflow(r.graph_json.as_deref());

            let protection = child_scan
                .as_ref()
                .and_then(|scan| scan.protection_for(r.id));
            let (child_status, publish_is_no_op, next_step) = match (&child_scan, &protection) {
                (None, _) => (
                    "unknown",
                    serde_json::Value::Null,
                    if is_substantive {
                        format!(
                            "publish_version with workflow_id={id} — BUT the child-reference \
                             scan failed this call, so whether an enabled parent dispatches \
                             this draft (making publish_version a no-op) is UNKNOWN"
                        )
                    } else {
                        format!("get_workflow_quickstart with workflow_id={id}")
                    },
                ),
                (
                    Some(_),
                    Some(talos_child_workflow_refs::ChildProtection::ReferencedBy(parents)),
                ) => (
                    "child",
                    serde_json::Value::Bool(true),
                    format!(
                        "No publish_version needed: enabled parent(s) {} dispatch this \
                         workflow's DRAFT graph_json directly (no version join, no status \
                         filter), so publishing changes nothing at runtime. To change what \
                         the parent runs, edit this draft.",
                        parents.join(", ")
                    ),
                ),
                (
                    Some(_),
                    Some(talos_child_workflow_refs::ChildProtection::MentionedByUnreadableParent(
                        parents,
                    )),
                ) => (
                    "unknown",
                    serde_json::Value::Null,
                    format!(
                        "Check before publishing: the graph of enabled workflow(s) {} could not \
                         be read and mentions this id — if one dispatches it as a child, \
                         publish_version is a no-op (the parent runs the draft graph directly).",
                        parents.join(", ")
                    ),
                ),
                (Some(_), None) => (
                    "not_a_child",
                    serde_json::Value::Bool(false),
                    if is_substantive {
                        format!("publish_version with workflow_id={id}")
                    } else {
                        format!("get_workflow_quickstart with workflow_id={id}")
                    },
                ),
            };

            let mut entry = serde_json::json!({
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
                // child | not_a_child | unknown — "unknown" is a statement
                // about THIS CALL's scan, never a claim about the workflow.
                "child_status": child_status,
                // true = an enabled parent runs this draft directly, so
                // publish_version changes nothing; false = publishable; null =
                // unknown (scan failed, or an unreadable parent mentions it).
                "publish_is_no_op": publish_is_no_op,
            });
            if let Some(p) = &protection {
                entry["runs_as_child_of"] = serde_json::json!(p.parent_names());
                entry["child_note"] = serde_json::json!(p.reason());
            }
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
        let duplicate_rows = readings.record(
            "duplicate_name_groups",
            self.advanced_repo
                .find_workflow_duplicate_name_groups(user_id)
                .await,
        );
        let duplicate_name_groups: Option<Vec<serde_json::Value>> = duplicate_rows.map(|rows| {
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
        });

        // 3. Uncapabilized workflows
        let uncap_count: Option<i64> = readings.record(
            "uncapabilized_count",
            self.advanced_repo.get_uncapabilized_count(user_id).await,
        );

        // Auto-heal: the caller spawns background capability tagging for any
        // uncapabilized workflows. Idempotent — auto_suggest_capabilities only
        // applies when capabilities IS NULL or empty.
        let auto_healing_caps = uncap_count.is_some_and(|n| n > 0);

        // 4. Next scheduled run.
        //
        // Pre-r234 this read from the wrong table (`schedules`) which was empty
        // in prod, so the field was always null even when active schedules existed
        // (pain point #8). Repo now queries `workflow_schedules` (the canonical
        // table since 20260309000200) and includes `next_trigger_at` so callers
        // can distinguish "no schedule" from "next firing is far out" without
        // a follow-up list_schedules call.
        let next_schedule = readings
            .record(
                "next_scheduled_run",
                self.advanced_repo.get_next_scheduled_run(user_id).await,
            )
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
        let active_wf_count: Option<i64> = readings.record(
            "schedule_health.active_workflows",
            self.advanced_repo.get_active_workflow_count(user_id).await,
        );

        let active_schedule_count: Option<i64> = readings.record(
            "schedule_health.active_schedules",
            self.advanced_repo.get_active_schedule_count(user_id).await,
        );

        // Count of active workflows that ACTUALLY have ≥1 enabled schedule attached
        // — distinct from `active_wf_count` (every status='active' workflow) and
        // `active_schedule_count` (schedule-row count; a workflow can have several).
        // This is the field most callers think `active_workflows` means.
        let active_workflows_with_schedule: Option<i64> = readings.record(
            "schedule_health.workflows_with_active_schedules",
            self.advanced_repo
                .get_active_workflows_with_schedule_count(user_id)
                .await,
        );

        // Unknown unless both counts were read.
        let no_schedule_warning: Option<bool> = match (active_wf_count, active_schedule_count) {
            (Some(workflows), Some(schedules)) => Some(workflows > 0 && schedules == 0),
            _ => None,
        };

        // 5. Detect frequently-executed workflows without a schedule.
        // Condition: ≥3 executions in the last 60 days AND no active schedule
        // AND not a sub-workflow of another workflow AND not tagged `interactive`.
        // r242 renamed from `previously_scheduled_unscheduled` for honesty —
        // workflow_schedules are hard-deleted (no audit trail), so we have no
        // way to know if a workflow was ever scheduled. The pre-r242 name +
        // "may have lost their trigger" framing produced false positives for
        // pure manual-trigger utilities. The two new filters + the softer
        // framing below cut the false-positive rate sharply.
        // r243 logged a failure of this read; since 2026-09-30 it is also
        // `null` in the response rather than an empty list, because pre-r243
        // the swallowed SQL error from r242's wrong JSONB path read as
        // "clean" coverage while the query was broken.
        let prev_scheduled_rows = readings.record(
            "frequently_executed_unscheduled",
            self.advanced_repo
                .get_frequently_executed_unscheduled(user_id)
                .await,
        );

        let frequently_executed_unscheduled: Option<Vec<serde_json::Value>> =
            prev_scheduled_rows.as_deref().map(|rows| {
                rows.iter().map(|r| {
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
            }).collect()
            });

        // 6. Pinned modules: check which are present vs need restore.
        // IMPORTANT: check the user's actual wasm_modules row (installed copy), not just whether
        // the system node_templates row has WASM. A deleted wasm_modules row must show as
        // needs_restore even if the catalog template still has precompiled_wasm.
        let pinned_rows = readings.record(
            "pinned_modules",
            self.advanced_repo
                .list_pinned_modules_with_user_install_status(user_id, 200)
                .await,
        );

        // `None` = the pins could not be read. That is NOT "nothing needs
        // restoring": the three lists below render null, never empty.
        let pinned_split: Option<(Vec<String>, Vec<String>)> = pinned_rows.map(|rows| {
            let mut present: Vec<String> = Vec::new();
            let mut needs_restore: Vec<String> = Vec::new();
            for r in rows {
                if r.has_wasm {
                    present.push(r.module_name);
                } else {
                    needs_restore.push(r.module_name);
                }
            }
            (present, needs_restore)
        });
        let pinned_needs_restore: Vec<String> = pinned_split
            .as_ref()
            .map(|(_, needs)| needs.clone())
            .unwrap_or_default();

        let pinned_modules_field = serde_json::json!({
            "present": pinned_split.as_ref().map(|(present, _)| present),
            "needs_restore": pinned_split.as_ref().map(|(_, needs)| needs),
            // Always surface the tool name so agents don't have to discover it.
            // needs_restore being empty means nothing currently requires action.
            "restore_tool": "restore_pinned_modules",
            "restore_needed": pinned_split.as_ref().map(|(_, needs)| !needs.is_empty()),
        });

        // 7. Actors — surface identity/persona context at session start so agents
        //    know what actors exist without a separate list_actors call.
        //    `active_actors` holds ONLY `status = 'active'` actors (until
        //    2026-09-30 it held every non-archived one, terminated included);
        //    the rest are counted in `inactive_actors`. A read that fails is
        //    `null` — unknown — never `[]`, which would read as "no actors".
        let active_actors = readings
            .record(
                "active_actors",
                self.advanced_repo
                    .list_active_actors_with_memory_count(user_id, 20)
                    .await,
            )
            .map_or(serde_json::Value::Null, |rows| {
                serde_json::Value::Array(render_active_actors(&rows))
            });
        let inactive_actors = readings
            .record(
                "inactive_actors",
                self.advanced_repo.count_actors_by_status(user_id).await,
            )
            .map_or(serde_json::Value::Null, |counts| {
                inactive_actor_summary(&counts)
            });

        // 8. Stuck executions: running > 1 hour
        let stuck_rows = readings.record(
            "stuck_executions",
            self.advanced_repo
                .list_stuck_executions(user_id, 1, 10)
                .await,
        );

        let stuck_executions: Option<Vec<serde_json::Value>> = stuck_rows.as_deref().map(|rows| {
            rows.iter()
            .map(|r| {
                serde_json::json!({
                    "execution_id": r.execution_id.to_string(),
                    "workflow_id": r.workflow_id.to_string(),
                    "hours_stuck": r.hours_stuck,
                    "tip": "cancel_execution or investigate with get_execution_status(detail: true)",
                })
            })
            .collect()
        });

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
        let recent_exec_rows = readings.record(
            "recent_executions",
            self.advanced_repo
                .list_recent_executions_for_session_awareness(user_id, RECENT_EXEC_WINDOW_MIN, 25)
                .await,
        );

        let recent_executions: Option<Vec<serde_json::Value>> = recent_exec_rows.as_deref().map(|rows| {
            rows.iter()
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
            .collect()
        });
        let recent_executions_count: Option<usize> = recent_executions.as_ref().map(Vec::len);
        let recent_running_count: Option<usize> = recent_exec_rows
            .as_deref()
            .map(|rows| rows.iter().filter(|r| r.status == "running").count());

        // 8. Determine single most impactful action
        //
        // Priority order: pinned-restore (data loss risk) → embedding provider
        // misconfigured (whole feature silently broken — surface ABOVE the
        // auto-healing branches because we WON'T be auto-healing in that case)
        // → auto-healing in progress → drafts → schedules.
        let embedding_provider_misconfigured =
            unembedded.is_some_and(|n| n > 0) && !embedding_provider_available;
        // Drafts the publish nudge may count: substantive AND known not to be
        // a child. An UNKNOWN child status counts (the nudge stays, and the
        // entry's next_step says the scan failed) — the failure mode of a
        // scan that did not answer must not be "the nudge quietly vanished".
        let child_substantive_count = unpublished_substantive_drafts
            .iter()
            .filter(|e| e["publish_is_no_op"] == serde_json::Value::Bool(true))
            .count();
        let publishable_substantive_count =
            unpublished_substantive_drafts.len() - child_substantive_count;
        let priority_action = priority_action(&PriorityInputs {
            pinned_needs_restore: &pinned_needs_restore,
            embedding_provider_misconfigured,
            unembedded: unembedded.unwrap_or(0),
            auto_healing_embeddings,
            auto_healing_caps,
            uncap_count: uncap_count.unwrap_or(0),
            publishable_substantive_count,
            child_substantive_count,
            in_progress_count: in_progress_drafts.len(),
            frequently_executed_unscheduled_count: frequently_executed_unscheduled
                .as_ref()
                .map_or(0, Vec::len),
            no_schedule_warning: no_schedule_warning.unwrap_or(false),
            active_wf_count: active_wf_count.unwrap_or(0),
            not_measured: readings.not_measured(),
        });

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
                "note": if total_wf == Some(0) {
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
                "tip": match uncap_count {
                    None => "The capability-tag count could not be read, so this brief does not \
                             say whether any workflow lacks tags (see measurement.not_measured).",
                    Some(n) if n > 0 => "Capability tags are being auto-applied in the background. \
                     Call get_platform_hygiene_report to see which workflows still lack tags, \
                     or suggest_capabilities(workflow_id) to apply them manually.",
                    Some(_) => "All workflows have capability tags.",
                },
                // MCP-113 (2026-05-08): mirror field_meanings on the
                // capabilities_coverage block.
                "field_meanings": {
                    "auto_healing": "True when an auto-suggest task is currently running to populate capability tags for uncapabilized workflows in the background. False = no heal needed (every workflow has tags) OR auto-heal is disabled.",
                    "uncapabilized_count": "Number of workflows with no capability tags. Workflows without tags are invisible to capability-based search and dispatch routing.",
                },
            },
            // `null`, not `[]`, when the draft read failed.
            "in_progress_drafts": drafts_measured.then_some(&in_progress_drafts),
            "unpublished_substantive_drafts": drafts_measured.then_some(&unpublished_substantive_drafts),
            // The two numbers the publish nudge is built from, rendered so a
            // reader (and a test) can see them whatever else outranks drafts
            // in `priority_action` this session. A child is substantive AND
            // not publishable; it is in the list above and in the second
            // count only.
            "publishable_substantive_draft_count": drafts_measured.then_some(publishable_substantive_count),
            "child_substantive_draft_count": drafts_measured.then_some(child_substantive_count),
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
                "tip": match (recent_executions_count, recent_running_count) {
                    (None, _) | (_, None) => Some(
                        "Recent executions could not be read. If you kicked one off and lost the \
                         response, check list_recent_executions before retrying."
                            .to_string(),
                    ),
                    (Some(0), _) => None,
                    (Some(_), Some(running)) if running > 0 => Some(format!(
                        "{} execution(s) still running. If you kicked one off and lost the response, \
                         do NOT retry — get_execution_status / watch_execution / get_execution_output \
                         with the execution_id from the items array.",
                        running
                    )),
                    (Some(count), Some(_)) => Some(format!(
                        "{} execution(s) completed in the last {} minute(s). \
                         If your client lost the response from a recent test_workflow / call_workflow / trigger_workflow, \
                         pull get_execution_output(execution_id: ...) from the items array instead of retrying.",
                        count, RECENT_EXEC_WINDOW_MIN
                    )),
                },
            },
            "active_actors": active_actors,
            "inactive_actors": inactive_actors,
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
            if auto_archive_failed {
                // Null, not zero. A count of 0 here is indistinguishable from
                // "nothing was stale", which is exactly the reassuring answer
                // the surface must not invent.
                report["auto_archived_stale_drafts"] = serde_json::Value::Null;
                report["auto_archive_error"] = serde_json::json!(
                    "the stale-draft sweep could not run, so NO draft was archived and this \
                     response does not say how many were eligible (see the server log)"
                );
            } else {
                report["auto_archived_stale_drafts"] = serde_json::json!(auto_archived_count);
            }
            if let Some(outcome) = auto_archive_outcome.as_ref() {
                if !outcome.skipped_children.is_empty() {
                    // The count and the eligible population deliberately
                    // disagree, so say why — same vocabulary the hygiene
                    // report uses for the same exclusion.
                    report["auto_archive_skipped_children"] = serde_json::json!(outcome
                        .skipped_children
                        .iter()
                        .map(|c| serde_json::json!({
                            "id": c.id.to_string(),
                            "name": c.name,
                            "runs_as_child_of": c.runs_as_child_of,
                            "reason": c.reason,
                        }))
                        .collect::<Vec<_>>());
                }
                if !outcome.skipped_substantive.is_empty() {
                    // The other half of the count/population disagreement, and
                    // the one this response would otherwise contradict itself
                    // about: every id here is (or was, before it aged past the
                    // 5-row display cap) a row `unpublished_substantive_drafts`
                    // calls ready to publish. Same `reason` vocabulary
                    // `fix_all` prints under `substantive_drafts_skipped`.
                    report["auto_archive_skipped_substantive"] = serde_json::json!(outcome
                        .skipped_substantive
                        .iter()
                        .map(|d| serde_json::json!({
                            "id": d.id.to_string(),
                            "name": d.name,
                            "reason": d.reason,
                        }))
                        .collect::<Vec<_>>());
                }
                if !outcome.unreadable_parents.is_empty() {
                    report["auto_archive_unreadable_parents"] =
                        serde_json::json!(outcome.unreadable_parents);
                }
                if !outcome.skipped_children.is_empty() || !outcome.skipped_substantive.is_empty() {
                    report["auto_archive_note"] = serde_json::json!(
                        "auto_archived_stale_drafts counts only rows this sweep MOVED. Drafts \
                          listed under auto_archive_skipped_children / \
                          auto_archive_skipped_substantive were eligible by age and by \
                          'never executed' and were deliberately left alone — there is no flag \
                          that widens the sweep to include them, by design. Archive one \
                          explicitly with archive_workflow, or publish it with publish_version."
                    );
                }
            }
        }

        // #7 — hint to enable auto_archive when in-progress drafts accumulate
        let in_progress_count = report
            .get("in_progress_drafts")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        if in_progress_count > 0 && auto_archive_days.is_none() {
            report["auto_archive_hint"] = serde_json::json!(
                "Pass auto_archive_stale_days: 14 to automatically clean up STUB drafts older than \
                 14 days on next session_start. Drafts a human visibly shaped (the \
                 unpublished_substantive_drafts list) and drafts an enabled parent dispatches \
                 into are never swept — archive those explicitly with archive_workflow."
            );
        }

        // `measurement` appears only when a read failed, so a healthy brief is
        // byte-identical to the pre-ledger one.
        readings.attach(&mut report);

        Ok(SessionBriefOutcome {
            report,
            readings,
            spawn_embedding_heal: auto_healing_embeddings,
            spawn_capability_heal: auto_healing_caps,
        })
    }
}

/// What `priority_action` is decided from. Unknown counts arrive as `0` /
/// `false`, so an unread section never RAISES an action; `not_measured` is
/// what stops the brief from calling an unread platform healthy.
struct PriorityInputs<'a> {
    pinned_needs_restore: &'a [String],
    embedding_provider_misconfigured: bool,
    unembedded: i64,
    auto_healing_embeddings: bool,
    auto_healing_caps: bool,
    uncap_count: i64,
    publishable_substantive_count: usize,
    child_substantive_count: usize,
    in_progress_count: usize,
    frequently_executed_unscheduled_count: usize,
    no_schedule_warning: bool,
    active_wf_count: i64,
    not_measured: &'a [&'static str],
}

/// The single most impactful action. Priority order: pinned-restore (data
/// loss risk) → embedding provider misconfigured (whole feature silently
/// broken — surfaced ABOVE the auto-healing branches because we WON'T be
/// auto-healing in that case) → auto-healing in progress → drafts →
/// schedules → an incomplete read → healthy. Pure, so it is tested without a
/// database.
fn priority_action(i: &PriorityInputs<'_>) -> String {
    if !i.pinned_needs_restore.is_empty() {
        format!(
            "{} pinned module(s) need WASM restore: {}. Call restore_pinned_modules.",
            i.pinned_needs_restore.len(),
            i.pinned_needs_restore.join(", ")
        )
    } else if i.embedding_provider_misconfigured {
        format!(
            "Embedding provider not configured — {} workflow(s) are unembedded and \
             semantic search is degraded. Set EMBEDDING_API_KEY (or OPENAI_API_KEY) \
             on the controller, or set EMBEDDING_API_URL to a keyless local \
             endpoint (e.g. http://ollama:11434/v1/embeddings). Coverage will \
             auto-heal on the next session_start once configured.",
            i.unembedded
        )
    } else if i.auto_healing_embeddings && i.auto_healing_caps {
        format!(
            "{} workflow(s) had no embedding and {} had no capability tags — \
             both auto-healing in background. Platform will be fully indexed within seconds.",
            i.unembedded, i.uncap_count
        )
    } else if i.auto_healing_embeddings {
        format!(
            "{} workflow(s) had no embedding — auto-embedding triggered in background. \
             Semantic search will be fully operational within seconds.",
            i.unembedded
        )
    } else if i.auto_healing_caps {
        format!(
            "{} workflow(s) have no capability tags — auto-tagging triggered in background. \
             Capability-based discovery will be available within seconds.",
            i.uncap_count
        )
    } else if i.publishable_substantive_count > 0 {
        // Substantive drafts dominate priority over stub-class drafts —
        // the user has already done the work, just needs publish_version.
        // A CHILD draft is not "ready for publish_version": its parent
        // runs the draft graph directly and publishing changes nothing, so
        // it is counted separately and never makes this the priority.
        if i.child_substantive_count > 0 {
            format!(
                "You have {} substantive draft workflow(s) ready for publish_version \
                 ({} more are sub-workflow children whose parent runs the draft graph \
                 directly — nothing to publish; see runs_as_child_of). \
                 See unpublished_substantive_drafts for the list.",
                i.publishable_substantive_count, i.child_substantive_count
            )
        } else {
            format!(
                "You have {} substantive draft workflow(s) ready for publish_version. \
                 See unpublished_substantive_drafts for the list.",
                i.publishable_substantive_count
            )
        }
    } else if i.in_progress_count > 0 {
        format!(
            "You have {} stub draft workflow(s) (mostly unconfigured nodes). \
             Call get_workflow_quickstart on the first one to see what's needed.",
            i.in_progress_count
        )
    } else if i.frequently_executed_unscheduled_count > 0 {
        format!(
            "{} active workflow(s) ran recently without a schedule — schedule with \
             create_schedule if recurring is intended, or tag 'interactive' to suppress \
             this signal for on-demand utilities. See frequently_executed_unscheduled \
             for per-workflow tips.",
            i.frequently_executed_unscheduled_count
        )
    } else if i.no_schedule_warning {
        format!(
            "{} active workflow(s) have no scheduled trigger. \
             Call deploy_workflow with a cron_expression to automate execution.",
            i.active_wf_count
        )
    } else if !i.not_measured.is_empty() {
        format!(
            "Part of the platform state could not be read ({}). Those fields are null in \
             this brief, so it cannot say the platform is healthy. See \
             measurement.not_measured; the error is in the server log under \
             event_kind=report_field_not_measured.",
            i.not_measured.join(", ")
        )
    } else {
        "Platform looks healthy. All workflows are embedded, capabilized, and scheduled."
            .to_string()
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

/// The `active_actors` entries of the session brief. Pure, so the rendering
/// is tested without a database.
fn render_active_actors(
    rows: &[talos_advanced_repository::ActiveActorWithMemoryRow],
) -> Vec<serde_json::Value> {
    rows.iter()
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
        .collect()
}

/// The `inactive_actors` field of the session brief: how many actors are in
/// each non-active status. Every status in the `actors.status` CHECK set is
/// rendered, as 0 when absent, so an absent key cannot be mistaken for an
/// unread one. `suspended` is reversible; `terminated` and `archived` are
/// final.
fn inactive_actor_summary(counts: &[(String, i64)]) -> serde_json::Value {
    let count = |status: &str| {
        counts
            .iter()
            .filter(|(s, _)| s == status)
            .map(|(_, n)| *n)
            .sum::<i64>()
    };
    serde_json::json!({
        "suspended": count("suspended"),
        "terminated": count("terminated"),
        "archived": count("archived"),
        "detail": "list_actors(status: 'suspended' | 'terminated' | 'archived')",
    })
}

#[cfg(test)]
mod actor_section_tests {
    use super::{inactive_actor_summary, render_active_actors};

    #[test]
    fn inactive_statuses_are_counted_and_absent_ones_are_zero() {
        let v = inactive_actor_summary(&[
            ("active".to_string(), 6),
            ("terminated".to_string(), 1),
            ("archived".to_string(), 4),
        ]);
        assert_eq!(v["suspended"], 0);
        assert_eq!(v["terminated"], 1);
        assert_eq!(v["archived"], 4);
        assert!(
            v.get("active").is_none(),
            "active actors are listed, not counted here"
        );
    }

    #[test]
    fn an_active_actor_renders_with_its_persona_tip() {
        let rows = vec![talos_advanced_repository::ActiveActorWithMemoryRow {
            id: uuid::Uuid::nil(),
            name: "a".into(),
            description: None,
            status: "active".into(),
            max_capability_world: "minimal-node".into(),
            memory_count: 0,
        }];
        let v = render_active_actors(&rows);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0]["status"], "active");
        assert!(v[0]["tip"].as_str().unwrap().contains("actor_remember"));
    }
}

#[cfg(test)]
mod priority_action_tests {
    use super::{priority_action, PriorityInputs};

    fn quiet<'a>(not_measured: &'a [&'static str], pinned: &'a [String]) -> PriorityInputs<'a> {
        PriorityInputs {
            pinned_needs_restore: pinned,
            embedding_provider_misconfigured: false,
            unembedded: 0,
            auto_healing_embeddings: false,
            auto_healing_caps: false,
            uncap_count: 0,
            publishable_substantive_count: 0,
            child_substantive_count: 0,
            in_progress_count: 0,
            frequently_executed_unscheduled_count: 0,
            no_schedule_warning: false,
            active_wf_count: 0,
            not_measured,
        }
    }

    #[test]
    fn an_unread_platform_is_never_called_healthy() {
        let action = priority_action(&quiet(&["pinned_modules", "stuck_executions"], &[]));
        assert!(!action.starts_with("Platform looks healthy"), "{action}");
        assert!(
            action.contains("pinned_modules, stuck_executions"),
            "{action}"
        );
        assert!(action.contains("measurement.not_measured"), "{action}");
    }

    #[test]
    fn a_fully_read_quiet_platform_is_healthy() {
        assert!(priority_action(&quiet(&[], &[])).starts_with("Platform looks healthy."));
    }

    #[test]
    fn a_known_action_still_outranks_an_incomplete_read() {
        let pinned = vec!["LLM Inference".to_string()];
        let action = priority_action(&quiet(&["stuck_executions"], &pinned));
        assert!(
            action.contains("need WASM restore: LLM Inference"),
            "{action}"
        );
    }
}

#[cfg(test)]
mod unreadable_platform_tests {
    use super::{SessionBriefInput, SessionBriefService};
    use std::sync::Arc;

    /// Every read fails (nothing listens on port 1), so every section must
    /// render `null`, be named in `measurement.not_measured`, and start no
    /// auto-heal. Before 2026-09-30 this brief rendered zeros and empty lists
    /// here and could end in "Platform looks healthy."
    #[tokio::test]
    async fn every_unreadable_section_is_null_and_named() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://nobody:nothing@127.0.0.1:1/none")
            .expect("lazy pool");
        let service = SessionBriefService::new(Arc::new(
            talos_advanced_repository::AdvancedRepository::new(pool),
        ));
        let outcome = service
            .build(SessionBriefInput {
                user_id: uuid::Uuid::new_v4(),
                auto_archive_days: None,
                server_version: "test".into(),
                build_time: "not-a-timestamp".into(),
                static_tool_count: 0,
            })
            .await
            .expect("a failed read is disclosed, not an error");
        let r = &outcome.report;

        for pointer in [
            "/embedding_coverage/total_workflows",
            "/embedding_coverage/unembedded",
            "/capabilities_coverage/uncapabilized_count",
            "/uncapabilized_count",
            "/in_progress_drafts",
            "/unpublished_substantive_drafts",
            "/publishable_substantive_draft_count",
            "/duplicate_name_groups",
            "/next_scheduled_run",
            "/frequently_executed_unscheduled",
            "/schedule_health/active_workflows",
            "/schedule_health/active_schedules",
            "/schedule_health/workflows_with_active_schedules",
            "/schedule_health/no_schedule_warning",
            "/pinned_modules/present",
            "/pinned_modules/needs_restore",
            "/pinned_modules/restore_needed",
            "/stuck_executions",
            "/recent_executions/count",
            "/recent_executions/items",
            "/active_actors",
            "/inactive_actors",
        ] {
            assert_eq!(
                r.pointer(pointer),
                Some(&serde_json::Value::Null),
                "{pointer} must be null when its read failed"
            );
        }

        let not_measured: Vec<&str> = r["measurement"]["not_measured"]
            .as_array()
            .expect("the failures are disclosed")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        for field in [
            "embedding_coverage",
            "in_progress_drafts",
            "unpublished_substantive_drafts",
            "duplicate_name_groups",
            "uncapabilized_count",
            "next_scheduled_run",
            "schedule_health.active_workflows",
            "schedule_health.active_schedules",
            "schedule_health.workflows_with_active_schedules",
            "frequently_executed_unscheduled",
            "pinned_modules",
            "active_actors",
            "inactive_actors",
            "stuck_executions",
            "recent_executions",
        ] {
            assert!(
                not_measured.contains(&field),
                "{field} not disclosed: {not_measured:?}"
            );
        }

        let action = r["priority_action"].as_str().unwrap_or_default();
        assert!(!action.starts_with("Platform looks healthy"), "{action}");
        assert!(!outcome.spawn_embedding_heal && !outcome.spawn_capability_heal);
    }
}

#[cfg(test)]
mod caller_read_tests {
    use super::SessionBriefOutcome;

    fn outcome() -> SessionBriefOutcome {
        SessionBriefOutcome {
            report: serde_json::json!({"priority_action": "x"}),
            readings: talos_measurement::Readings::new(),
            spawn_embedding_heal: false,
            spawn_capability_heal: false,
        }
    }

    #[test]
    fn a_failed_caller_read_joins_the_disclosure() {
        let mut o = outcome();
        let v: Option<u8> = o.record("catalog_drift", Err::<u8, _>("db down"));
        assert_eq!(v, None);
        assert_eq!(
            o.report["measurement"]["not_measured"],
            serde_json::json!(["catalog_drift"])
        );
    }

    #[test]
    fn a_successful_caller_read_adds_no_disclosure() {
        let mut o = outcome();
        assert_eq!(o.record("catalog_drift", Ok::<u8, String>(3)), Some(3));
        assert!(o.report.get("measurement").is_none());
    }
}
