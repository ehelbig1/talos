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
     never contradicts unembedded_workflow_count. ALSO null when either the workflow count or \
     the unembedded count could not be READ — a share needs both, and a defaulted denominator \
     would silently turn a coverage share into a share of nothing; `measurement.not_measured` \
     says which of the two is missing";

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
    ///
    /// The only I/O is the single repository call; everything else is
    /// [`build_report`], which is pure and therefore testable against a
    /// synthetic degraded [`talos_analytics_repository::HygieneReport`]
    /// without Postgres. That split is load-bearing for this surface: the
    /// property that matters most here is what the report SAYS when its reads
    /// fail, and a DB-bound assembly function can only be pinned by source
    /// greps.
    pub async fn generate(
        &self,
        input: HygieneReportInput,
    ) -> Result<HygieneReportOutcome, HygieneError> {
        let h = self
            .analytics_repo
            .get_hygiene_report(input.user_id)
            .await?;
        Ok(build_report(&h))
    }
}

/// A count that is only a count when every source it sums actually ran.
///
/// # Why a type rather than an `Option` at each site
///
/// `total_issues` and the four severity buckets are all sums over the SAME
/// pool of checks, and each one is wrong in the same way for the same reason:
/// a check whose query failed contributes `0`, which is indistinguishable from
/// a check that ran and found nothing. Summing them yields a number that is
/// not a count of anything, presented as the report's headline.
///
/// The three rules it encodes, all of them the `talos_measurement` doctrine
/// applied to an integer sum:
///
/// * **A partial sum is not a sum.** [`Self::value`] is `None` the moment any
///   contributing source is in the ledger. A consumer comparing `total_issues`
///   against a threshold cannot read `null` as "under the limit" the way it
///   reads `0`.
/// * **The floor that IS known is still worth having.** [`Self::lower_bound`]
///   sums the sources that ran. That is exactly what the `tokio::join!` (not
///   `try_join!`) design buys — one dead query must not destroy fifteen live
///   ones — and it is only safe to publish because it is LABELLED a floor.
/// * **The disclosure names the sources, not the error.** The upstream error
///   was logged and dropped at the repository boundary; only the report-key
///   names travel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialCount {
    lower_bound: i64,
    unavailable: Vec<&'static str>,
}

impl PartialCount {
    /// Add up `contributions` (report key → count), nulling the result if any
    /// of those keys appears in `readings`.
    ///
    /// A failed check contributes `0` to the lower bound, which is correct: it
    /// found no issues *that anyone saw*. That is precisely why the sum must
    /// not be published as a total.
    #[must_use]
    pub fn tally(
        readings: &talos_measurement::Readings,
        contributions: &[(&'static str, i64)],
    ) -> Self {
        let missing = readings.not_measured();
        let mut unavailable: Vec<&'static str> = Vec::new();
        let mut lower_bound: i64 = 0;
        for (field, count) in contributions {
            if missing.contains(field) {
                if !unavailable.contains(field) {
                    unavailable.push(field);
                }
            } else {
                lower_bound = lower_bound.saturating_add(*count);
            }
        }
        Self {
            lower_bound,
            unavailable,
        }
    }

    /// The count, or `None` when at least one source could not be read.
    #[must_use]
    pub fn value(&self) -> Option<i64> {
        self.unavailable.is_empty().then_some(self.lower_bound)
    }

    /// The sum over the sources that DID run — a floor, never a total.
    #[must_use]
    pub fn lower_bound(&self) -> i64 {
        self.lower_bound
    }

    /// Report keys that could not be read, in ledger order.
    #[must_use]
    pub fn sources_unavailable(&self) -> &[&'static str] {
        &self.unavailable
    }

    /// One sentence stating what the null means and what the floor is worth.
    #[must_use]
    pub fn note(&self, label: &str) -> String {
        format!(
            "`{label}` is null because {} of its source check(s) could not be read ({}). \
             A count over partially-failed reads is not a count, and 0 would read as \
             \"nothing wrong\". `{label}_lower_bound` = {} counts ONLY the checks that ran and \
             is a floor, never a total — the true value is at least that and is not bounded above.",
            self.unavailable.len(),
            self.unavailable.join(", "),
            self.lower_bound,
        )
    }
}

/// Insert `*_lower_bound` + `*_note` beside each nulled severity count.
///
/// A no-op for any count that is not null, so a healthy report gains nothing.
fn attach_partial_counts(
    report: &mut serde_json::Value,
    total: &PartialCount,
    critical: &PartialCount,
    high: &PartialCount,
    medium: &PartialCount,
    low: &PartialCount,
) {
    let Some(summary) = report
        .get_mut("summary")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    for (label, pc) in [
        ("total_issues", total),
        ("critical", critical),
        ("high", high),
        ("medium", medium),
        ("low", low),
    ] {
        if pc.value().is_some() {
            continue;
        }
        summary.insert(
            format!("{label}_lower_bound"),
            serde_json::json!(pc.lower_bound()),
        );
        summary.insert(format!("{label}_note"), serde_json::json!(pc.note(label)));
    }
}

/// Attach `summary.coverage`: what ceiling every finding list ran under, and
/// which of them came back AT that ceiling.
///
/// The truncation-saturation problem stated on
/// `talos_analytics_repository::HYGIENE_FINDING_LIMIT` — eleven independently
/// capped lists summed into one headline that saturates near 270, so a
/// platform with 5 000 real issues and one with 300 print an
/// indistinguishable number — is not fixable by a bigger cap. It is fixable
/// only by the number stating its own ceiling. Note there are THREE distinct
/// caps and two genuinely uncapped checks, so the single exported constant
/// would have misstated five of the thirteen list checks.
fn attach_coverage(report: &mut serde_json::Value, h: &talos_analytics_repository::HygieneReport) {
    let lengths = finding_list_lengths(h);
    let mut caps = serde_json::Map::new();
    let mut truncated: Vec<serde_json::Value> = Vec::new();
    for check in talos_analytics_repository::HYGIENE_CHECKS
        .iter()
        .filter(|c| c.is_list)
    {
        caps.insert(
            check.field.to_string(),
            if check.cap > 0 {
                serde_json::json!(check.cap)
            } else {
                serde_json::Value::Null
            },
        );
        let Some(returned) = lengths
            .iter()
            .find(|(f, _)| *f == check.field)
            .map(|(_, n)| *n)
        else {
            continue;
        };
        let coverage = if check.cap > 0 {
            talos_measurement::Coverage::new(returned, check.cap)
        } else {
            talos_measurement::Coverage::complete(returned)
        };
        if coverage.truncated() {
            let mut entry = coverage.to_json();
            if let Some(obj) = entry.as_object_mut() {
                obj.insert("check".to_string(), serde_json::json!(check.field));
            }
            truncated.push(entry);
        }
    }
    let Some(summary) = report
        .get_mut("summary")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    summary.insert(
        "coverage".to_string(),
        serde_json::json!({
            "caps": caps,
            "truncated_checks": truncated,
            "note": COVERAGE_NOTE,
        }),
    );
}

/// How to read `summary.coverage`.
pub const COVERAGE_NOTE: &str =
    "caps: the row ceiling each finding list ran under (null = the read is genuinely uncapped). \
     truncated_checks: the lists that came back AT their ceiling, so rows exist that were never \
     examined and every count derived from them — including total_issues and the severity \
     buckets — is a LOWER BOUND, not a total. Truncation is decided with >=, which over-reports \
     by at most the exact-fit boundary case. orphaned_secrets carries a SECOND, upstream ceiling \
     this block cannot see: only the first 200 of the user's secrets are ever tested for \
     orphanhood, so on a larger vault its finding list is bounded by that scan and not by its \
     own cap.";

/// The list-valued checks and how many rows each returned, keyed by the report
/// field they are rendered under.
fn finding_list_lengths(h: &talos_analytics_repository::HygieneReport) -> Vec<(&'static str, i64)> {
    let n = |v: usize| i64::try_from(v).unwrap_or(i64::MAX);
    vec![
        ("undescribed_workflows", n(h.undescribed.len())),
        ("uncapabilized_workflows", n(h.uncapabilized.len())),
        ("orphaned_modules", n(h.orphaned_modules.len())),
        ("promotable_modules", n(h.promotable_modules.len())),
        ("stale_executions", n(h.stale_executions.len())),
        ("dormant_workflows", n(h.dormant_workflows.len())),
        ("stale_draft_workflows", n(h.stale_draft_workflows.len())),
        ("idle_actors", n(h.idle_actors.len())),
        ("orphaned_secrets", n(h.orphaned_secrets.len())),
        ("secrets_without_expiry", n(h.secrets_without_expiry.len())),
        (
            "expiring_actor_memories",
            n(h.expiring_actor_memories.len()),
        ),
        (
            "workflows_needing_schema",
            n(h.workflows_needing_schema.len()),
        ),
        ("untyped_value_modules", n(h.untyped_value_modules.len())),
        (
            talos_analytics_repository::HYGIENE_FIELD_TWINS,
            n(h.workflow_graphs.len()),
        ),
    ]
}

/// The recommendation a degraded sweep owes the operator, or `None` when every
/// check ran.
///
/// `critical` on purpose: an unmeasured check is not a low-priority annotation,
/// it is the reason every other number on the page might be wrong. It sorts
/// above the findings for the same reason MCP-76 sorted security above cleanup.
#[must_use]
pub fn degraded_recommendation(
    readings: &talos_measurement::Readings,
) -> Option<serde_json::Value> {
    if readings.complete() {
        return None;
    }
    let missing = readings.not_measured();
    Some(serde_json::json!({
        "priority": "critical",
        "category": "data_quality",
        "not_measured": missing,
        "action": format!(
            "{} hygiene check(s) could not be read this run ({}). Their findings are ABSENT from \
             this report, not zero: every count they feed is null and every recommendation they \
             would have raised is missing, so this report cannot be read as an all-clear for \
             those areas. Re-run get_platform_hygiene_report once the database is healthy; the \
             underlying errors are in the controller log under \
             event_kind=report_field_not_measured.",
            missing.len(),
            missing.join(", ")
        ),
        "affected_count": missing.len(),
    }))
}

/// Assemble the operator-facing hygiene report from one sweep's rows.
///
/// PURE — no I/O, no clock beyond `generated_at`. Split out of
/// [`HygieneService::generate`] so the degraded-read behaviour can be driven
/// end-to-end in a unit test: the whole point of this surface is what it says
/// when its inputs are missing, and that is not a property a source pin can
/// check.
#[must_use]
pub fn build_report(h: &talos_analytics_repository::HygieneReport) -> HygieneReportOutcome {
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
    //
    // A row with a non-empty `runs_as_child_of` is NOT dormant-by-neglect: it
    // is dispatched in-process by an enabled parent, which records no
    // `workflow_executions` row, so its silence in that table is the expected
    // shape and not evidence. It stays in the LIST — an operator asking "what
    // has no executions?" should still see it, with the reason — and is
    // excluded from the cleanup RECOMMENDATION below, which is the half that
    // points at `batch_delete_workflows`.
    let dormant_workflows: Vec<serde_json::Value> = h
        .dormant_workflows
        .iter()
        .map(|r| {
            let mut entry = serde_json::json!({
                "id": r.id.to_string(),
                "name": r.name,
                "created_at": r.created_at.to_rfc3339(),
                "last_execution": r.last_execution.map(|t| t.to_rfc3339()),
            });
            if !r.runs_as_child_of.is_empty() {
                entry["runs_as_child_of"] = serde_json::json!(r.runs_as_child_of);
                entry["last_execution_note"] =
                    serde_json::json!(talos_analytics_repository::DORMANT_CHILD_NOTE);
                entry["last_child_activity_at"] =
                    serde_json::json!(r.last_child_activity_at.map(|t| t.to_rfc3339()));
                entry["last_child_activity_caveat"] =
                    serde_json::json!(talos_analytics_repository::DORMANT_CHILD_ACTIVITY_CAVEAT);
            }
            entry
        })
        .collect();
    // The population the cleanup recommendation is allowed to speak about.
    let deletable_dormant: Vec<&talos_analytics_repository::DormantWorkflowRow> = h
        .dormant_workflows
        .iter()
        .filter(|r| r.runs_as_child_of.is_empty())
        .collect();
    let dormant_children_excluded = h.dormant_workflows.len() - deletable_dormant.len();

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
    // Rendered ONLY when the wildcard scan ran AND found no wildcard grant.
    // `None` (the scan itself was unreadable) suppresses exactly like `true`
    // does; the repository has already recorded `orphaned_secrets` as derived-
    // unmeasured for that case, so the `[]` is accompanied.
    let orphaned_secrets: Vec<serde_json::Value> = if h.has_wildcard_module != Some(false) {
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

    // `is_some_and`, not `> 0`: an unread count must not be able to produce a
    // recommendation, and — more importantly — must not be able to SUPPRESS
    // one by reading as zero. The suppression is disclosed in `measurement`.
    if unembedded_count.is_some_and(|c| c > 0) {
        // D4 (2026-07-29): honest rounding. `unembedded * 100 / total`
        // is INTEGER division — 1 unembedded workflow out of 250 rendered
        // "(0%) lack embeddings" directly beside "1 of 250", i.e. the
        // sentence contradicted itself and the actionable number rounded
        // away to nothing. `share_pct` rounds half-away-from-zero to one
        // decimal, so that case reads 0.4%.
        let unembedded_count = unembedded_count.unwrap_or_default();
        let pct = total_workflow_count.and_then(|t| share_pct(unembedded_count, t));
        let total_label = total_workflow_count
            .map_or_else(|| "an unmeasured number of".to_string(), |t| t.to_string());
        recommendations.push(serde_json::json!({
            "priority": "medium",
            "category": "semantic_search",
            "action": format!("{} of {} workflows ({}) lack embeddings — semantic search falls back to keyword matching for these. Run generate_workflow_embeddings to index them for true vector search.", unembedded_count, total_label, render_share_pct(pct)),
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

    if !deletable_dormant.is_empty() {
        let mut action = format!(
            "{} enabled workflow(s) have had no executions in 30+ days. Consider disabling or deleting them with batch_delete_workflows to reduce registry noise.",
            deletable_dormant.len()
        );
        if !h.child_scan_unreadable_parents.is_empty() {
            // The exclusion is INCOMPLETE and the advice says so, rather than
            // presenting a short exclusion list as a full one. Named parents,
            // not a count: the operator can go look at them.
            action.push_str(&format!(
                " NOTE: the child-reference scan could not parse the graph of {} enabled                  workflow(s) ({}), so a workflow dispatched only by one of those may be listed                  here in error — check before deleting.",
                h.child_scan_unreadable_parents.len(),
                h.child_scan_unreadable_parents.join(", "),
            ));
        }
        if dormant_children_excluded > 0 {
            // The count and the list deliberately disagree, so say why. A
            // recommendation whose number silently excludes rows the reader
            // can see above it is its own small misleading report.
            action.push_str(&format!(
                " {dormant_children_excluded} further listed workflow(s) are EXCLUDED from this                  count: an enabled parent dispatches into them as sub-workflows, which leaves no                  execution row — deleting one would remove a node its parent runs."
            ));
        }
        recommendations.push(serde_json::json!({
            "priority": "low",
            "category": "cleanup",
            "action": action,
            "affected_count": deletable_dormant.len(),
            "excluded_child_workflows": dormant_children_excluded,
            "deletable": deletable_dormant.iter().map(|r| r.name.clone()).collect::<Vec<_>>(),
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
    if h.has_wildcard_module == Some(true) {
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
    // Rendered at the top level as well as inside its recommendation. Every
    // other finding list has a top-level key and this one did not — which the
    // disclosure exposed: a ledger entry naming `untyped_value_modules` pointed
    // at a field that existed only when the list was NON-empty, i.e. it
    // resolved in exactly the case it was never needed for.
    let untyped_value_modules: Vec<serde_json::Value> = h
        .untyped_value_modules
        .iter()
        .map(|m| serde_json::json!({ "id": m.id.to_string(), "name": m.name }))
        .collect();

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
        recommendations.push(serde_json::json!({
            "priority": "medium",
            "category": "performance",
            "untyped_value_modules": untyped_value_modules.clone(),
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

    // --- Severity tallies -------------------------------------------------
    //
    // Every one of these is a SUM OVER SOURCES, and a sum over sources some of
    // which never ran is not a sum. Each bucket names the checks it adds up so
    // `PartialCount` can null it when any of them is in the ledger; the
    // buckets are then concatenated for the headline, which is the reason the
    // two can never disagree (they were previously two independently written
    // expressions that happened to be term-for-term identical — a coincidence
    // one edit away from being false).
    let n = |v: usize| i64::try_from(v).unwrap_or(i64::MAX);
    let critical_sources: Vec<(&'static str, i64)> =
        vec![("stale_executions", n(stale_executions.len()))];
    let high_sources: Vec<(&'static str, i64)> = vec![
        ("undescribed_workflows", n(undescribed.len())),
        ("uncapabilized_workflows", n(uncapabilized.len())),
        ("expiring_actor_memories", n(expiring_actor_memories.len())),
        (
            talos_analytics_repository::HYGIENE_FIELD_TWINS,
            n(diverged_twin_pairs),
        ),
    ];
    let medium_sources: Vec<(&'static str, i64)> = vec![
        (
            "unembedded_workflow_count",
            i64::from(unembedded_count.is_some_and(|c| c > 0)),
        ),
        ("orphaned_secrets", n(orphaned_secrets.len())),
        ("secrets_without_expiry", n(secrets_without_expiry.len())),
        (
            "summary.wildcard_secret_grant",
            i64::from(h.has_wildcard_module == Some(true)),
        ),
        (
            "workflows_needing_schema",
            n(workflows_needing_schema.len()),
        ),
    ];
    let low_sources: Vec<(&'static str, i64)> = vec![
        ("orphaned_modules", n(orphaned_modules.len())),
        ("dormant_workflows", n(dormant_workflows.len())),
        ("stale_draft_workflows", n(stale_draft_workflows.len())),
        ("idle_actors", n(idle_actors.len())),
    ];
    let critical = PartialCount::tally(&h.readings, &critical_sources);
    let high = PartialCount::tally(&h.readings, &high_sources);
    let medium = PartialCount::tally(&h.readings, &medium_sources);
    let low = PartialCount::tally(&h.readings, &low_sources);
    let total_issues = PartialCount::tally(
        &h.readings,
        &[
            critical_sources.as_slice(),
            high_sources.as_slice(),
            medium_sources.as_slice(),
            low_sources.as_slice(),
        ]
        .concat(),
    );
    // Every `*_count` in the summary below is the length of a list rendered
    // elsewhere in the same document, so it inherits that list's provenance:
    // null when the check could not be read, because `0` is exactly as
    // reassuring there as it is in `total_issues`.
    let count_of = |field: &'static str, v: usize| -> Option<i64> {
        (!h.readings.not_measured().contains(&field)).then(|| n(v))
    };
    let child_scan_measured = !h
        .readings
        .not_measured()
        .contains(&"summary.child_workflow_exclusion");

    let note = {
        // An UNREAD suppression count must not render as "nothing was
        // suppressed" — that is this whole change in one sentence. The
        // unmeasured case says so and points at the ledger.
        let base = match (suppressed_count, auto_classified_count as i64) {
            (None, a) => format!(
                "The internal/test suppression count could not be read, so this report does not \
                 say how many workflows were excluded from readiness warnings (see \
                 measurement.not_measured){}",
                if a > 0 {
                    format!("; {a} more were auto-excluded via the test-like name-prefix heuristic.")
                } else {
                    ".".to_string()
                }
            ),
            (Some(0), 0) => String::new(),
            (Some(s), 0) => format!("{} internal/test workflow(s) excluded from readiness warnings (workflow_type=test/internal). Use set_workflow_type to classify QA fixtures.", s),
            (Some(0), a) => format!("{} workflow(s) auto-excluded: test-like name prefix (QA-/test-) but no formal type set. Use set_workflow_type with type='test' to classify them.", a),
            (Some(s), a) => format!("{} internal/test workflow(s) formally suppressed; {} more auto-excluded via name-prefix heuristic. Use set_workflow_type to normalize all test fixtures.", s, a),
        };
        match suppressed_low_score_count {
            Some(c) if c > 0 => format!("{}{}{} draft(s) with readiness_score<10 suppressed from documentation recommendations.", base, if base.is_empty() { "" } else { " " }, c),
            _ => base,
        }
    };

    // A check that could not be read produces no findings, and a check with no
    // findings produces no recommendation — so before this, fifteen dead
    // queries and a spotless platform emitted the SAME empty
    // `recommendations` list. The degradation is itself the top-priority
    // finding: an operator cannot act on a report they do not know is partial.
    if let Some(rec) = degraded_recommendation(&h.readings) {
        recommendations.push(rec);
    }

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

    let mut report = serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "summary": {
            // NULL, never a bare sum, when any source that feeds it could not
            // be read. A count over partially-failed reads is not a count, and
            // `0` is the one value an operator reads as "you are fine". The
            // floor that IS known travels beside it as
            // `total_issues_lower_bound`, injected below only when it differs
            // in meaning — so a healthy report is byte-identical to the
            // pre-disclosure one.
            "total_issues": total_issues.value(),
            "critical": critical.value(),
            "high": high.value(),
            "medium": medium.value(),
            "low": low.value(),
            "total_workflows": total_workflow_count,
            "idle_actors_count": count_of("idle_actors", idle_actors.len()),
            "wildcard_secret_grant": h.has_wildcard_module,
            // The scan behind `dormant_workflows[].runs_as_child_of`. Rendered
            // as an object rather than a bare count so the INCOMPLETE case has
            // somewhere to live: `unreadable_parents` non-empty means a
            // workflow dispatched only by one of those may still be listed as
            // dormant. When the scan could not run at all, this whole key is
            // nulled by the ledger and named under `measurement.not_measured`.
            "child_workflow_exclusion": if child_scan_measured {
                serde_json::json!({
                    "excluded_from_cleanup_count": dormant_children_excluded,
                    "unreadable_parents": h.child_scan_unreadable_parents,
                })
            } else {
                serde_json::Value::Null
            },
            "orphaned_secrets_count": count_of("orphaned_secrets", orphaned_secrets.len()),
            "secrets_without_expiry_count": count_of("secrets_without_expiry", secrets_without_expiry.len()),
            "expiring_memories_count": count_of("expiring_actor_memories", expiring_actor_memories.len()),
            "workflows_needing_schema_count": count_of("workflows_needing_schema", workflows_needing_schema.len()),
            "promotable_modules_count": count_of("promotable_modules", promotable_modules.len()),
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
            "twin_pairs_count": count_of(talos_analytics_repository::HYGIENE_FIELD_TWINS, twin_analysis.pairs.len()),
            "diverged_twin_pairs_count": count_of(talos_analytics_repository::HYGIENE_FIELD_TWINS, diverged_twin_pairs),
            "name_related_only_count": count_of(talos_analytics_repository::HYGIENE_FIELD_TWINS, twin_analysis.name_related_only.len()),
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
            //   3. #726: both operands are now `Option`. A defaulted `0`
            //      denominator did not merely misstate a total — it turned a
            //      coverage share into a share of nothing, and `share_pct`
            //      would have returned `None` for a reason the reader could
            //      not distinguish from an empty platform. Unmeasured on
            //      EITHER side is unmeasured here.
            "embedding_coverage_percent": match (total_workflow_count, unembedded_count) {
                (Some(total), Some(unembedded)) => share_pct(total - unembedded, total),
                _ => None,
            },
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
        "untyped_value_modules": untyped_value_modules,
        "workflow_twins": workflow_twins,
        "recommendations": recommendations,
    });

    // --- Disclosure ---------------------------------------------------------
    //
    // Everything below is ADDITIVE and, apart from `summary.coverage`, appears
    // only on a degraded run. A report whose every check ran is byte-identical
    // to the pre-disclosure one plus the coverage block — which is the
    // `Readings::attach` contract, held one level up.
    attach_partial_counts(&mut report, &total_issues, &critical, &high, &medium, &low);
    attach_coverage(&mut report, h);
    h.readings.attach(&mut report);

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
    let orphaned_module_ids: Vec<uuid::Uuid> = h.orphaned_modules.iter().map(|r| r.id).collect();

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

    HygieneReportOutcome {
        report,
        fix_candidates: FixCandidates {
            preview: fix_preview,
            draft_ids,
            stale_exec_ids,
            orphaned_module_ids,
        },
    }
}

impl HygieneService {
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

/// #726: what the report SAYS when its reads fail.
///
/// These drive the real production assembly function, [`build_report`], end to
/// end — not a test-local reimplementation of it, and not a source grep. That
/// is only possible because `generate`'s single repository call was split out;
/// before, the sixteen-query sweep and the assembly were one DB-bound `async
/// fn` and the only available guard was a pin.
///
/// The property under test is the one the pre-fix code got exactly backwards:
/// **an empty finding list and an unasked question must not render the same.**
#[cfg(test)]
mod partial_report_disclosure_tests {
    use super::{build_report, PartialCount};
    use talos_analytics_repository::{HygieneReport, HYGIENE_CHECKS, HYGIENE_FIELD_TWINS};
    use talos_measurement::Readings;

    /// A ledger in which exactly `fields` failed to read.
    fn ledger(fields: &[&'static str]) -> Readings {
        let mut r = Readings::new();
        for f in fields {
            r.mark_derived(f);
        }
        r
    }

    fn report_for(fields: &[&'static str]) -> serde_json::Value {
        build_report(&HygieneReport::empty(ledger(fields))).report
    }

    /// Resolve a `.`-separated path, the way the disclosure asks a reader to.
    fn at<'a>(v: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
        let mut cur = v;
        for seg in path.split('.') {
            cur = cur.get(seg)?;
        }
        Some(cur)
    }

    /// The healthy case. A report whose every check ran must still say `0`,
    /// carry no `measurement` block, no lower bounds and no data-quality
    /// recommendation — otherwise the disclosure becomes noise an operator
    /// learns to skip, which is this defect class one level up.
    #[test]
    fn a_complete_sweep_reports_a_number_and_discloses_nothing() {
        let r = report_for(&[]);
        assert_eq!(r["summary"]["total_issues"], serde_json::json!(0));
        assert_eq!(r["summary"]["critical"], serde_json::json!(0));
        assert!(
            r.get("measurement").is_none(),
            "a clean run attaches nothing"
        );
        assert!(r["summary"].get("total_issues_lower_bound").is_none());
        assert!(r["summary"].get("total_issues_note").is_none());
        assert!(
            r["recommendations"]
                .as_array()
                .expect("an array")
                .is_empty(),
            "a clean, empty platform raises no recommendations"
        );
    }

    /// THE BUG. Pre-#726 this assertion could not even be written: both of
    /// these produced `total_issues: 0` and an empty `recommendations`.
    #[test]
    fn a_failed_read_and_an_empty_result_are_distinguishable() {
        let clean = report_for(&[]);
        let broken = report_for(&["stale_executions"]);

        assert_eq!(clean["stale_executions"], broken["stale_executions"]);
        assert_ne!(
            clean["summary"], broken["summary"],
            "an unread check and an empty check must not summarise identically"
        );
        assert_eq!(clean["summary"]["critical"], serde_json::json!(0));
        assert!(
            broken["summary"]["critical"].is_null(),
            "the critical bucket sums only stale_executions; with that unread it is not a count"
        );
        assert!(broken["summary"]["total_issues"].is_null());
    }

    /// `total_issues: 0` is the sentence an operator reads as "you are fine".
    /// It must be unreachable from a failed read, and the null must explain
    /// itself in the same object.
    #[test]
    fn total_issues_is_null_and_explains_itself_under_partial_failure() {
        let r = report_for(&["dormant_workflows", "orphaned_modules"]);
        assert!(r["summary"]["total_issues"].is_null());
        assert_eq!(
            r["summary"]["total_issues_lower_bound"],
            serde_json::json!(0)
        );
        let note = r["summary"]["total_issues_note"]
            .as_str()
            .expect("the null carries a note");
        assert!(note.contains("dormant_workflows") && note.contains("orphaned_modules"));
        assert!(
            note.contains("lower_bound") && note.contains("floor"),
            "the note must say what the surviving number is worth: {note}"
        );
    }

    /// The lower bound is the whole reason the sweep uses `join!` rather than
    /// `try_join!`: fifteen live queries must survive one dead one. It counts
    /// the checks that RAN, and it is labelled a floor.
    #[test]
    fn the_lower_bound_counts_only_the_checks_that_ran() {
        let mut h = HygieneReport::empty(ledger(&["stale_executions"]));
        h.dormant_workflows = vec![dormant("a"), dormant("b"), dormant("c")];
        let r = build_report(&h).report;
        assert!(r["summary"]["total_issues"].is_null());
        assert_eq!(
            r["summary"]["total_issues_lower_bound"],
            serde_json::json!(3),
            "the three dormant workflows are known; the stale executions are not"
        );
        assert_eq!(
            r["summary"]["low"],
            serde_json::json!(3),
            "the low bucket does not sum stale_executions, so it is still a count"
        );
        assert!(r["summary"]["critical"].is_null());
    }

    /// A dead check must not null a bucket it never contributed to. Nulling
    /// everything on any failure would be the fix over-reaching into the same
    /// uselessness from the other side.
    #[test]
    fn only_the_buckets_that_consume_the_dead_check_are_nulled() {
        let r = report_for(&["stale_executions"]);
        assert!(r["summary"]["critical"].is_null());
        for still_a_count in ["high", "medium", "low"] {
            assert_eq!(
                r["summary"][still_a_count],
                serde_json::json!(0),
                "`{still_a_count}` does not sum stale_executions and must stay a count"
            );
            assert!(r["summary"]
                .get(format!("{still_a_count}_lower_bound"))
                .is_none());
        }
    }

    /// The degradation is itself a finding, and the top one: every other
    /// number on the page may be wrong. Before this, a failed check produced
    /// no findings, and no findings produced no recommendation.
    #[test]
    fn a_degraded_sweep_raises_a_critical_data_quality_recommendation() {
        let r = report_for(&["idle_actors"]);
        let recs = r["recommendations"].as_array().expect("an array");
        let rec = recs
            .iter()
            .find(|x| x["category"] == "data_quality")
            .expect("a degraded sweep must raise a data_quality recommendation");
        assert_eq!(rec["priority"], "critical");
        assert_eq!(rec["not_measured"], serde_json::json!(["idle_actors"]));
        let action = rec["action"].as_str().expect("prose");
        assert!(
            action.contains("not zero") && action.contains("all-clear"),
            "the recommendation must say what the absence is NOT: {action}"
        );
        assert_eq!(
            recs.first().map(|x| &x["category"]),
            Some(&serde_json::json!("data_quality")),
            "it sorts above the findings — an operator cannot triage a report they do not know \
             is partial"
        );
    }

    /// Every name the ledger discloses must be findable in the document the
    /// operator is holding. A disclosure naming `undescribed` when the JSON key
    /// is `undescribed_workflows` names nothing.
    ///
    /// This is the cross-crate anti-drift guard: the names live in
    /// `talos-analytics-repository`, the JSON is emitted here, and nothing else
    /// connects the two.
    #[test]
    fn every_disclosed_check_name_resolves_to_a_key_in_the_report() {
        for check in HYGIENE_CHECKS {
            let r = report_for(&[check.field]);
            assert!(
                at(&r, check.field).is_some(),
                "`{}` is disclosed under measurement.not_measured but no such path exists in the \
                 report, so an operator is pointed at a field that is not there",
                check.field
            );
            let disclosed = r["measurement"]["not_measured"]
                .as_array()
                .expect("the ledger is attached");
            assert!(
                disclosed.contains(&serde_json::json!(check.field)),
                "`{}` did not reach measurement.not_measured",
                check.field
            );
        }
    }

    /// The wildcard scan has three states, not two. `Some(false)` means the
    /// scan ran and found no module that can read the whole vault; `None`
    /// means nobody looked — and the two must not both render as "no wildcard
    /// grant", which is a security claim.
    #[test]
    fn an_unread_wildcard_scan_is_not_a_clean_wildcard_scan() {
        let clean = report_for(&[]);
        assert_eq!(
            clean["summary"]["wildcard_secret_grant"],
            serde_json::json!(false)
        );

        let r = report_for(&["summary.wildcard_secret_grant"]);
        assert!(
            r["summary"]["wildcard_secret_grant"].is_null(),
            "an unread wildcard scan must not report `false`"
        );
        assert!(
            !r["recommendations"]
                .as_array()
                .expect("an array")
                .iter()
                .any(|x| x["action"]
                    .as_str()
                    .is_some_and(|a| a.contains("wildcard secret access"))),
            "and it must not raise the wildcard recommendation either"
        );
    }

    /// A coverage share needs BOTH operands. A defaulted `0` denominator does
    /// not misstate the share — it changes which population is being shared.
    #[test]
    fn embedding_coverage_needs_both_of_its_operands() {
        let mut h = HygieneReport::empty(ledger(&["summary.total_workflows"]));
        h.unembedded_count = Some(3);
        let r = build_report(&h).report;
        assert!(r["summary"]["embedding_coverage_percent"].is_null());
        assert!(r["summary"]["total_workflows"].is_null());
        // And the recommendation it feeds must not invent a denominator.
        let action = r["recommendations"]
            .as_array()
            .expect("an array")
            .iter()
            .find(|x| x["category"] == "semantic_search")
            .and_then(|x| x["action"].as_str())
            .expect("the unembedded recommendation still fires — 3 is a real finding")
            .to_string();
        assert!(
            action.contains("3 of an unmeasured number of workflows"),
            "the recommendation must not print `3 of 0 workflows`: {action}"
        );
        assert!(action.contains("share unknown"));
    }

    /// An unread suppression count must not read as "nothing was suppressed".
    #[test]
    fn an_unread_suppression_count_says_so_in_the_note() {
        let r = report_for(&["summary.suppressed_internal_test_workflows"]);
        assert!(r["summary"]["suppressed_internal_test_workflows"].is_null());
        let note = r["summary"]["note"].as_str().expect("prose");
        assert!(
            note.contains("could not be read"),
            "the note must not be empty, which reads as `nothing suppressed`: {note:?}"
        );
    }

    /// Every finding list states the ceiling it ran under, and a list that came
    /// back AT its ceiling says so. Three distinct caps and two uncapped reads,
    /// so a single exported constant would misstate five of them.
    #[test]
    fn coverage_names_every_cap_and_flags_the_truncated_lists() {
        let clean = report_for(&[]);
        let caps = clean["summary"]["coverage"]["caps"]
            .as_object()
            .expect("a caps map");
        assert_eq!(
            caps.len(),
            HYGIENE_CHECKS.iter().filter(|c| c.is_list).count(),
            "every list check states its ceiling"
        );
        assert_eq!(caps["stale_executions"], serde_json::json!(25));
        assert_eq!(caps["expiring_actor_memories"], serde_json::json!(50));
        assert_eq!(caps["workflows_needing_schema"], serde_json::json!(20));
        assert_eq!(caps[HYGIENE_FIELD_TWINS], serde_json::json!(100));
        assert!(
            caps["idle_actors"].is_null(),
            "an uncapped read declares null, not 0 — 0 would read as a ceiling of nothing"
        );
        assert!(clean["summary"]["coverage"]["truncated_checks"]
            .as_array()
            .expect("an array")
            .is_empty());

        let mut h = HygieneReport::empty(Readings::new());
        h.dormant_workflows = (0..25).map(|i| dormant(&format!("w{i}"))).collect();
        let r = build_report(&h).report;
        let trunc = r["summary"]["coverage"]["truncated_checks"]
            .as_array()
            .expect("an array");
        assert_eq!(trunc.len(), 1);
        assert_eq!(trunc[0]["check"], "dormant_workflows");
        assert_eq!(trunc[0]["truncated"], serde_json::json!(true));
        assert!(trunc[0]["note"]
            .as_str()
            .is_some_and(|n| n.contains("lower bounds")));
    }

    /// `PartialCount` itself: a failed source contributes `0` to the floor,
    /// which is correct AND is exactly why the floor may not be published as a
    /// total.
    #[test]
    fn partial_count_nulls_on_any_missing_source() {
        let r = ledger(&["b"]);
        let pc = PartialCount::tally(&r, &[("a", 4), ("b", 0), ("c", 1)]);
        assert_eq!(pc.value(), None);
        assert_eq!(pc.lower_bound(), 5);
        assert_eq!(pc.sources_unavailable(), ["b"]);

        let clean = PartialCount::tally(&Readings::new(), &[("a", 4), ("c", 1)]);
        assert_eq!(clean.value(), Some(5));
        assert!(clean.sources_unavailable().is_empty());

        // A source named twice (the concatenated total sums each bucket's
        // sources) must be disclosed once.
        let dup = PartialCount::tally(&ledger(&["b"]), &[("b", 0), ("b", 0)]);
        assert_eq!(dup.sources_unavailable(), ["b"]);
    }

    /// The headline and the four buckets are built from ONE source list, so
    /// they cannot disagree. Pre-#726 they were two independently written
    /// expressions that happened to be term-for-term identical — a coincidence
    /// one edit away from being false, and nothing checked it.
    #[test]
    fn the_buckets_sum_to_the_headline() {
        let mut h = HygieneReport::empty(Readings::new());
        h.dormant_workflows = vec![dormant("a"), dormant("b")];
        h.secrets_without_expiry = vec![talos_analytics_repository::SecretWithoutExpiryRow {
            name: "k".into(),
            key_path: "svc/api_key".into(),
            created_at: chrono::Utc::now(),
        }];
        let r = build_report(&h).report;
        let s = &r["summary"];
        let sum: i64 = ["critical", "high", "medium", "low"]
            .iter()
            .map(|k| s[*k].as_i64().expect("a count"))
            .sum();
        assert_eq!(s["total_issues"].as_i64(), Some(sum));
        assert_eq!(sum, 3);
    }

    /// Each `*_count` in the summary is the length of a list rendered
    /// elsewhere in the same document, so it inherits that list's provenance.
    /// `orphaned_secrets_count: 0` beside a failed secrets read is the
    /// headline defect at per-check scale.
    #[test]
    fn a_per_check_summary_count_is_null_when_its_list_was_not_read() {
        let clean = report_for(&[]);
        let broken = report_for(&["orphaned_secrets", "idle_actors", HYGIENE_FIELD_TWINS]);
        for (key, source) in [
            ("orphaned_secrets_count", "orphaned_secrets"),
            ("idle_actors_count", "idle_actors"),
            ("twin_pairs_count", HYGIENE_FIELD_TWINS),
            ("diverged_twin_pairs_count", HYGIENE_FIELD_TWINS),
            ("name_related_only_count", HYGIENE_FIELD_TWINS),
        ] {
            assert_eq!(
                clean["summary"][key],
                serde_json::json!(0),
                "`{key}` must still be a number when `{source}` was read"
            );
            assert!(
                broken["summary"][key].is_null(),
                "`{key}` renders 0 while its source `{source}` was never read"
            );
        }
        // A count whose source DID run is untouched by a sibling's failure.
        assert_eq!(
            broken["summary"]["secrets_without_expiry_count"],
            serde_json::json!(0)
        );
    }

    /// The orphan-secret list is meaningless without a wildcard verdict: an
    /// empty grants union makes every secret look orphaned, and this list is
    /// pointed at a delete button. `None` must suppress exactly as `Some(true)`
    /// does — the service holds this gate independently of the repository's,
    /// because a suppression that exists in only one layer is one refactor from
    /// existing in neither.
    #[test]
    fn an_unknown_wildcard_verdict_suppresses_the_orphan_secret_list() {
        let mut h = HygieneReport::empty(ledger(&["summary.wildcard_secret_grant"]));
        h.has_wildcard_module = None;
        h.orphaned_secrets = vec![talos_analytics_repository::OrphanedSecretRow {
            name: "k".into(),
            key_path: "svc/api_key".into(),
            namespace: None,
            created_at: chrono::Utc::now(),
            expires_at: None,
        }];
        let r = build_report(&h).report;
        assert_eq!(
            r["orphaned_secrets"],
            serde_json::json!([]),
            "an orphan list computed under an unknown wildcard verdict must not be rendered"
        );
        assert!(
            !r["recommendations"]
                .as_array()
                .expect("an array")
                .iter()
                .any(|x| x["action"]
                    .as_str()
                    .is_some_and(|a| a.contains("not referenced by any module"))),
            "and it must not produce a delete-these recommendation either"
        );

        // The same list DOES render once the scan has run and come back clean.
        let mut ok = HygieneReport::empty(Readings::new());
        ok.orphaned_secrets = h.orphaned_secrets;
        let r2 = build_report(&ok).report;
        assert_eq!(r2["orphaned_secrets"].as_array().map(Vec::len), Some(1));
    }

    fn dormant(name: &str) -> talos_analytics_repository::DormantWorkflowRow {
        talos_analytics_repository::DormantWorkflowRow {
            id: uuid::Uuid::nil(),
            name: name.to_string(),
            created_at: chrono::Utc::now(),
            last_execution: None,
            runs_as_child_of: Vec::new(),
            last_child_activity_at: None,
        }
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
