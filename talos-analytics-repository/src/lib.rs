/// AnalyticsRepository -- centralises all SQL for the analytics domain.
///
/// Follows the ExecutionRepository pattern: plain struct, `new(db_pool)`,
/// all methods `pub async fn`, return `anyhow::Result<T>` so callers can `?`.
/// Handlers in `mcp/analytics.rs` should be thin wrappers that call these
/// methods and format the JSON-RPC response.
use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

// ------------------------------------------------------------------
// Row DTOs
// ------------------------------------------------------------------

/// Outcome of a single-alert acknowledgement (N-M, 2026-05-06):
/// distinguishes "fresh ack" from "already acked" from "not found"
/// in the response so callers can surface the right operator
/// signal. Pre-fix the bare `u64 rows_affected` couldn't tell them
/// apart — already-acked returned `1` (the row matched) and looked
/// indistinguishable from a fresh ack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckOutcome {
    /// Alert was unacknowledged before this call; now acknowledged.
    Acknowledged,
    /// Alert was already acknowledged before this call; no state change.
    AlreadyAcknowledged,
    /// No alert with this id belongs to the calling user.
    NotFound,
}

#[derive(Debug)]
pub struct ExecStats {
    pub total: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub running: i64,
    /// Average wall-clock duration of *successful* runs only — the
    /// underlying SQL filters on `status = 'completed'` so phantom
    /// durations from stale-cleanup failures don't distort the metric.
    /// `None` when no completed runs exist in the window.
    pub avg_duration_secs: Option<f64>,
}

impl ExecStats {
    /// All-zeros stats — handler fall-back when the underlying query fails.
    pub fn empty() -> Self {
        Self {
            total: 0,
            succeeded: 0,
            failed: 0,
            running: 0,
            avg_duration_secs: None,
        }
    }

    /// Success rate as 0.0–100.0; zero when no runs.
    pub fn success_rate_percent(&self) -> f64 {
        if self.total > 0 {
            (self.succeeded as f64 / self.total as f64) * 100.0
        } else {
            0.0
        }
    }
}

/// Pure: compute a stable error-message fingerprint by collapsing
/// concrete IDs/timestamps/numbers/embedded payloads into placeholder
/// tokens.
///
/// Four substitutions:
///   * UUIDs → `<UUID>`
///   * ISO-8601 timestamps → `<TIMESTAMP>`
///   * `(after|attempt|retry|timeout|took|elapsed) <N>` → `$1 N`
///   * Long double-quoted strings (≥16 chars between the quotes) → `"<QUOTED>"`
///
/// The quoted-string collapse handles error patterns that embed
/// variable user-data inside quotes — e.g. OUTPUT_SCHEMA enforcement
/// errors that include the LLM's literal prose preview ("Got prose:
/// \"I notice the untrusted data block ...\""). Two runs whose only
/// difference is the model wording would otherwise produce distinct
/// fingerprints, defeating top-K aggregation. The 16-char floor keeps
/// short literal tokens (`"id"`, `"name"`, `"true"`) legible.
///
/// Used by `get_workflow_stats` and `get_error_report` to group
/// otherwise-distinct error strings ("timeout after 32s", "timeout
/// after 91s") into the same fingerprint for top-K aggregation.
/// Pattern statics use `LazyLock` so the regexes compile exactly once
/// per process — calling this in a tight loop is cheap.
pub fn fingerprint_error_message(msg: &str) -> String {
    static RE_UUID: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
            .expect("valid UUID regex")
    });
    static RE_TS: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*")
            .expect("valid timestamp regex")
    });
    static RE_NUM: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(after|attempt|retry|timeout|took|elapsed)\s+\d+")
            .expect("valid number regex")
    });
    static RE_LONG_QUOTE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r#""[^"]{16,}""#).expect("valid long-quoted-string regex")
    });
    let result = RE_UUID.replace_all(msg, "<UUID>");
    let result = RE_TS.replace_all(&result, "<TIMESTAMP>");
    let result = RE_NUM.replace_all(&result, "$1 N");
    RE_LONG_QUOTE
        .replace_all(&result, r#""<QUOTED>""#)
        .to_string()
}

#[derive(Debug)]
pub struct WorkflowGraphRow {
    pub id: Uuid,
    pub name: String,
    pub graph_json: Option<String>,
    pub status: Option<String>,
    pub is_enabled: bool,
    pub workflow_type: Option<String>,
    pub tags: Option<Vec<String>>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct WorkflowBasicRow {
    pub id: Uuid,
    pub name: String,
    pub status: Option<String>,
    pub is_enabled: bool,
    pub workflow_type: Option<String>,
    pub capabilities: Option<Vec<String>>,
    pub readiness_score: Option<i32>,
    pub description: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct WorkflowFullRow {
    pub id: Uuid,
    pub name: String,
    pub graph_json: Option<String>,
    pub tags: Option<Vec<String>>,
    pub description: Option<String>,
    pub max_concurrent_executions: Option<i32>,
    pub capabilities: Option<Vec<String>>,
    pub intent: Option<String>,
}

#[derive(Debug)]
pub struct ModuleNameRow {
    pub id: Uuid,
    pub name: String,
}

#[derive(Debug)]
pub struct FailingWorkflowRow {
    pub id: Uuid,
    pub name: String,
    pub fail_count: i64,
    pub total_count: i64,
}

#[derive(Debug)]
pub struct SystemStatusCounts {
    pub workflows: i64,
    pub executions: i64,
    pub modules: i64,
    pub templates: i64,
    pub secrets: i64,
    pub schedules: i64,
    pub webhooks: i64,
}

#[derive(Debug)]
pub struct LatencyPercentilesMs {
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub p99_ms: Option<f64>,
}

/// Compact stats returned by `get_sla_window_stats` for SLA evaluation.
#[derive(Debug, Clone, Copy)]
pub struct SlaWindowStats {
    pub total: i64,
    pub successes: i64,
    pub p95_ms: Option<f64>,
}

/// Per-module fuel statistics aggregated from `execution_cost_rollup`.
///
/// Source of truth for `get_fuel_usage_report`. Joined against
/// `modules.max_fuel` so callers can compute utilization (p95 ÷ ceiling)
/// and surface budget recommendations without a second query.
#[derive(Debug)]
pub struct ModuleFuelStats {
    pub module_id: Uuid,
    pub module_name: String,
    pub kind: String,
    /// Current `modules.max_fuel` ceiling. Compared against `fuel_p95` to
    /// produce the utilization recommendation in the handler.
    pub current_max_fuel: i64,
    pub executions: i64,
    pub fuel_p50: i64,
    pub fuel_p95: i64,
    pub fuel_max: i64,
    pub fuel_avg: i64,
    pub wall_time_p50_ms: i64,
    pub wall_time_p95_ms: i64,
}

#[derive(Debug)]
pub struct VersionChangelogRow {
    pub version_number: Option<i32>,
    pub graph_json: Option<String>,
    pub description: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
}

/// Readiness-score listing row.
#[derive(Debug)]
pub struct ReadinessScoreRow {
    pub id: Uuid,
    pub name: String,
    pub readiness_score: Option<i32>,
    pub readiness_scored_at: Option<DateTime<Utc>>,
    pub has_description: bool,
    pub has_capabilities: bool,
}

/// Workflow alert row for `list_alerts`. Joined with workflow name.
#[derive(Debug)]
pub struct WorkflowAlertRow {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub execution_id: Uuid,
    pub alert_type: String,
    pub message: String,
    pub created_at: DateTime<Utc>,
    pub workflow_name: String,
    pub occurrence_count: i32,
    pub last_occurred_at: DateTime<Utc>,
    /// MCP-40 (2026-05-07): true when the alert's `execution_id` is no
    /// longer present in `workflow_executions` (archived/pruned).
    /// Surfaced so list_alerts can flag dead pointers; operators can
    /// then filter / bulk-acknowledge orphan alerts cleanly.
    pub execution_archived: bool,
}

/// Compact alert row for `get_recent_alerts_summary`.
#[derive(Debug)]
pub struct RecentAlertSummaryRow {
    pub workflow_name: String,
    pub message: String,
    pub occurrence_count: i32,
    pub last_occurred_at: DateTime<Utc>,
    pub acknowledged: bool,
}

#[derive(Debug)]
pub struct VersionAuditRow {
    pub version_number: Option<i32>,
    pub description: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
    pub is_active: bool,
}

#[derive(Debug)]
pub struct VersionSummaryRow {
    pub total_versions: i64,
    pub latest_version: Option<i32>,
    pub last_published: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct ScheduleRow {
    pub id: Uuid,
    pub cron_expression: String,
    pub is_enabled: bool,
    /// MCP-35 (2026-05-07): timezone the cron is interpreted in.
    /// Operators chaining list_workflow_triggers → get_schedule_health
    /// previously had to call list_schedules separately to get this.
    pub timezone: Option<String>,
    pub last_triggered_at: Option<chrono::DateTime<chrono::Utc>>,
    pub next_trigger_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug)]
pub struct WebhookRow {
    pub id: Uuid,
    pub endpoint_path: String,
    pub is_enabled: bool,
}

#[derive(Debug)]
pub struct AuditEventRow {
    pub id: Uuid,
    pub event_type: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub actor_id: Option<Uuid>,
}

#[derive(Debug)]
pub struct ExecutionAuditRow {
    pub id: Uuid,
    pub status: String,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub trigger_type: Option<String>,
}

#[derive(Debug)]
pub struct NodeFailureCountRow {
    pub node_id: Uuid,
    pub fail_count: i64,
}

#[derive(Debug)]
pub struct NodeFailureDetailRow {
    pub node_id: Uuid,
    pub fail_count: i64,
    pub latest_at: Option<DateTime<Utc>>,
    pub latest_error: Option<String>,
}

#[derive(Debug)]
pub struct HourlyFailureRow {
    pub hour: i32,
    pub fail_count: i64,
}

#[derive(Debug)]
pub struct WorkflowStatSummaryRow {
    pub id: Uuid,
    pub name: String,
    pub total: i64,
    pub succeeded: i64,
    pub failed: i64,
    /// Average wall-clock duration of *successful* runs only — same
    /// filter discipline as `ExecStats::avg_duration_secs`.
    pub avg_duration_secs: Option<f64>,
}

#[derive(Debug)]
pub struct LongRunningRow {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub name: String,
    pub running_secs: i32,
}

#[derive(Debug)]
pub struct HealthSummaryCounts {
    pub running: i64,
    pub failed_24h: i64,
    pub completed_24h: i64,
}

#[derive(Debug)]
pub struct UnusedSecretRow {
    pub name: String,
    pub key_path: String,
    pub description: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub namespace: Option<String>,
}

#[derive(Debug)]
pub struct ModuleInfoRow {
    pub name: String,
    pub capability_world: Option<String>,
}

#[derive(Debug)]
pub struct WorkflowCapabilityRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub capabilities: Option<Vec<String>>,
    pub readiness_score: Option<i32>,
    pub success_rate: Option<f64>,
}

#[derive(Debug)]
pub struct ReuseStatRow {
    pub workflow_id: Uuid,
    pub name: String,
    pub graph_json: Option<String>,
    pub total_invocations: i64,
    pub unique_days: i64,
}

#[derive(Debug)]
pub struct ReadinessExecData {
    pub success_rate: Option<f64>,
    pub total_count: i64,
}

#[derive(Debug)]
pub struct WaterfallExecRow {
    pub status: String,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub output_data: Option<serde_json::Value>,
    pub workflow_id: Uuid,
}

#[derive(Debug)]
pub struct WaterfallEventRow {
    pub event_type: String,
    pub node_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct PerformanceMetricsRow {
    pub total: i64,
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub p99_ms: Option<f64>,
    pub avg_ms: Option<f64>,
}

#[derive(Debug)]
pub struct DailyExecSummary {
    pub total: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub cancelled: i64,
    pub running: i64,
}

/// Extremes for `get_workflow_performance_report`. Surfaces the
/// slowest and fastest completed executions in the configured
/// window so the caller can navigate straight to the
/// outlier (`get_execution_waterfall(execution_id: ...)`).
#[derive(Debug)]
pub struct ExtremeExecution {
    pub id: Uuid,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub duration_ms: f64,
}

#[derive(Debug)]
pub struct TopWorkflowRow {
    pub id: Uuid,
    pub name: String,
    pub exec_count: i64,
}

#[derive(Debug)]
pub struct ScheduleUpcomingRow {
    pub id: Uuid,
    pub cron_expression: String,
    pub timezone: Option<String>,
    pub workflow_name: String,
    pub workflow_id: Uuid,
}

#[derive(Debug)]
pub struct HygieneWorkflowRow {
    pub id: Uuid,
    pub name: String,
    pub readiness_score: Option<i32>,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct OrphanedModuleRow {
    pub id: Uuid,
    pub name: String,
    pub size_bytes: Option<i32>,
    pub compiled_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct StaleExecutionRow {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub workflow_name: String,
    pub started_at: DateTime<Utc>,
    pub status: String,
}

#[derive(Debug)]
pub struct DormantWorkflowRow {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_execution: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct StaleDraftRow {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    /// M-I (2026-05-06): include the workflow's graph_json so the
    /// hygiene report's `fix_all` preview can run the substantive-draft
    /// predicate (lifted from `advanced.rs::is_substantive_workflow`)
    /// before recommending auto-deletion. Without this, fix_all would
    /// recommend deleting workflows that `session_start` simultaneously
    /// flags as "ready for publish_version" — destructive contradiction.
    pub graph_json: Option<String>,
}

#[derive(Debug)]
pub struct IdleActorRow {
    pub id: Uuid,
    pub name: String,
    pub status: String,
    pub last_active: Option<DateTime<Utc>>,
    pub total_executions: i64,
}

#[derive(Debug)]
pub struct OrphanedSecretRow {
    pub name: String,
    pub key_path: String,
    pub namespace: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct SecretWithoutExpiryRow {
    pub name: String,
    pub key_path: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct ExpiringMemoryRow {
    pub actor_id: Uuid,
    pub key: String,
    pub memory_type: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub actor_name: String,
}

#[derive(Debug)]
pub struct NeedsSchemaRow {
    pub id: Uuid,
    pub name: String,
    pub execution_count: i64,
    pub last_run: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct HygieneReport {
    pub undescribed: Vec<HygieneWorkflowRow>,
    pub uncapabilized: Vec<HygieneWorkflowRow>,
    pub suppressed_count: i64,
    pub suppressed_low_score_count: i64,
    pub unembedded_count: i64,
    pub total_workflow_count: i64,
    pub orphaned_modules: Vec<OrphanedModuleRow>,
    pub stale_executions: Vec<StaleExecutionRow>,
    pub dormant_workflows: Vec<DormantWorkflowRow>,
    pub stale_draft_workflows: Vec<StaleDraftRow>,
    pub idle_actors: Vec<IdleActorRow>,
    pub has_wildcard_module: bool,
    /// Names of modules/templates that have wildcard secret access, for attribution.
    pub wildcard_module_names: Vec<String>,
    pub orphaned_secrets: Vec<OrphanedSecretRow>,
    pub secrets_without_expiry: Vec<SecretWithoutExpiryRow>,
    pub expiring_actor_memories: Vec<ExpiringMemoryRow>,
    pub workflows_needing_schema: Vec<NeedsSchemaRow>,
    /// Modules whose Rust source uses untyped `serde_json::Value` parsing —
    /// a wasmtime fuel anti-pattern. Typed `#[derive(Deserialize)]` structs
    /// are 3–10× cheaper because they skip HashMap<String, Value> allocation
    /// per object. Each entry carries both the UUID and the display name so
    /// the hygiene report can surface a ready-to-paste
    /// `generate_typed_scaffold` fix command per flagged module.
    pub untyped_value_modules: Vec<UntypedValueModuleRow>,
}

#[derive(Debug, Clone)]
pub struct UntypedValueModuleRow {
    pub id: Uuid,
    pub name: String,
}

// ------------------------------------------------------------------
// Vault path grant matcher
// ------------------------------------------------------------------

/// Returns true if `key_path` is permitted by any entry in `grants`.
///
/// Mirrors `worker/src/host_impl.rs::vault_path_allowed` semantics exactly so
/// the hygiene report's orphan detector and the runtime enforcement agree on
/// what "referenced" means. Used by `get_hygiene_report` to decide whether a
/// stored secret has any grant that could resolve it.
/// Delegates to the shared `talos_workflow_job_protocol::vault_path_permitted` matcher so
/// hygiene-report orphan detection uses exactly the same semantics as the
/// runtime enforcement in `worker/src/host_impl.rs` and the static validator
/// in `mcp/workflows.rs`. See `talos_workflow_job_protocol::vault_path_permitted` for rules.
fn secret_path_in_any_grant(grants: &[String], key_path: &str) -> bool {
    talos_workflow_job_protocol::vault_path_permitted(grants, key_path)
}

/// Pure: compute the freshness component (0–20 pts) of a workflow's
/// readiness score from the days-since-last-execution.
///
/// Identical formula in both `validate_workflow` and
/// `get_readiness_breakdown`:
///   * `≤ 7 days` → 20 pts
///   * `≤ 30 days` → 10 pts
///   * else (incl. never-executed) → 0 pts
pub fn compute_freshness_score(days_since_last: Option<i64>) -> f64 {
    match days_since_last {
        Some(d) if d <= 7 => 20.0,
        Some(d) if d <= 30 => 10.0,
        _ => 0.0,
    }
}

/// Pure: compute the risk component (0–10 pts) of a workflow's readiness
/// score. Starts at 10 and deducts for missing safeguards:
///   * `!has_timeout` → −3
///   * `!has_error_edges` → −3
///   * `expiring_secrets > 0` → −4
///
/// Result is clamped at zero. Identical formula in both
/// `validate_workflow` and `get_readiness_breakdown`.
pub fn compute_risk_score(has_timeout: bool, has_error_edges: bool, expiring_secrets: i64) -> f64 {
    let mut risk = 10.0_f64;
    if !has_timeout {
        risk -= 3.0;
    }
    if !has_error_edges {
        risk -= 3.0;
    }
    if expiring_secrets > 0 {
        risk -= 4.0;
    }
    risk.max(0.0)
}

/// Pure: compute the reliability component (0–50 pts) of a workflow's
/// readiness score from observed executions.
///
/// Saturates at 10 runs — 10+ successful runs = full credit. The earlier
/// 100-run saturation in `validate_workflow` was overly punitive (a typical
/// pre-publish workflow has <10 runs), and produced the canonical MCP-1
/// inconsistency:
///   validate_workflow → 50, get_readiness_breakdown → 77
/// for the same workflow with 7 successful runs.
///
/// `success_rate` should be in [0.0, 1.0] (None → 0.0).
pub fn compute_reliability_score(success_rate: Option<f64>, exec_count: i64) -> f64 {
    success_rate.unwrap_or(0.0) * (exec_count as f64 / 10.0).min(1.0) * 50.0
}

/// Pure: compute the documentation component (0–20 pts) of a workflow's
/// readiness score.
///
/// `has_desc=10, has_node_desc=5, has_caps=5`. Pre-MCP-1-fix `validate_workflow`
/// used 10/10/10 (30 max), inconsistent with `get_readiness_breakdown`.
pub fn compute_documentation_score(has_desc: bool, has_node_desc: bool, has_caps: bool) -> f64 {
    (if has_desc { 10.0 } else { 0.0 })
        + (if has_node_desc { 5.0 } else { 0.0 })
        + (if has_caps { 5.0 } else { 0.0 })
}

/// Format a percentage value as a JSON number rounded to 1 decimal place.
///
/// MCP-19 (2026-05-07): pre-fix five surfaces formatted percentages as
/// `format!("{:.1}", v)` strings while `get_queue_status.progress_percent`
/// emitted a JSON number, forcing operators to type-test per surface.
/// Worse, the precision varied (`{:.1}` in 4, `{:.2}` in 1).
///
/// Standardize on JSON numbers rounded to 1 decimal place. Callers should
/// emit the result directly into `serde_json::json!` macros — `f64` becomes
/// a JSON number with the rounding preserved.
pub fn format_percent(value: f64) -> f64 {
    if !value.is_finite() {
        return 0.0;
    }
    (value * 10.0).round() / 10.0
}

#[cfg(test)]
mod orphan_secret_tests {
    use super::secret_path_in_any_grant;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn empty_grants_means_orphan() {
        assert!(!secret_path_in_any_grant(&[], "anthropic/api_key"));
    }

    #[test]
    fn exact_match_not_orphan() {
        assert!(secret_path_in_any_grant(
            &s(&["anthropic/api_key"]),
            "anthropic/api_key"
        ));
    }

    #[test]
    fn prefix_grant_matches_subpath() {
        assert!(secret_path_in_any_grant(
            &s(&["oauth/gmail"]),
            "oauth/gmail/user/access_token"
        ));
    }

    #[test]
    fn glob_grant_matches_subpath() {
        // Regression for the hygiene report false-positive: tightening grants
        // to "oauth/gmail/*" made every gmail token show as orphaned.
        assert!(secret_path_in_any_grant(
            &s(&["oauth/gmail/*"]),
            "oauth/gmail/USER_ID/WORKSPACE/access_token"
        ));
    }

    #[test]
    fn prefix_grant_does_not_match_sibling() {
        assert!(!secret_path_in_any_grant(
            &s(&["oauth/gmail"]),
            "oauth/gmailicious/user/token"
        ));
        assert!(!secret_path_in_any_grant(
            &s(&["oauth/gmail"]),
            "oauth/atlassian/token"
        ));
    }

    #[test]
    fn wildcard_matches_everything() {
        assert!(secret_path_in_any_grant(&s(&["*"]), "anything/at/all"));
    }

    #[test]
    fn any_grant_in_union_can_claim() {
        let grants = s(&["anthropic/api_key", "oauth/gmail/*", "github/pat"]);
        assert!(secret_path_in_any_grant(&grants, "anthropic/api_key"));
        assert!(secret_path_in_any_grant(&grants, "oauth/gmail/u/token"));
        assert!(secret_path_in_any_grant(&grants, "github/pat"));
        assert!(!secret_path_in_any_grant(&grants, "oauth/atlassian/token"));
    }
}

#[cfg(test)]
mod readiness_score_tests {
    use super::{compute_freshness_score, compute_risk_score};

    #[test]
    fn freshness_within_seven_days_full_credit() {
        assert_eq!(compute_freshness_score(Some(0)), 20.0);
        assert_eq!(compute_freshness_score(Some(7)), 20.0);
    }

    #[test]
    fn freshness_eight_to_thirty_half_credit() {
        assert_eq!(compute_freshness_score(Some(8)), 10.0);
        assert_eq!(compute_freshness_score(Some(30)), 10.0);
    }

    #[test]
    fn freshness_over_thirty_days_zero() {
        assert_eq!(compute_freshness_score(Some(31)), 0.0);
        assert_eq!(compute_freshness_score(Some(365)), 0.0);
    }

    #[test]
    fn freshness_never_executed_zero() {
        assert_eq!(compute_freshness_score(None), 0.0);
    }

    #[test]
    fn risk_full_credit_when_safeguards_present() {
        assert_eq!(compute_risk_score(true, true, 0), 10.0);
    }

    #[test]
    fn risk_deducts_for_missing_timeout() {
        assert_eq!(compute_risk_score(false, true, 0), 7.0);
    }

    #[test]
    fn risk_deducts_for_missing_error_edges() {
        assert_eq!(compute_risk_score(true, false, 0), 7.0);
    }

    #[test]
    fn risk_deducts_for_expiring_secrets() {
        assert_eq!(compute_risk_score(true, true, 1), 6.0);
        assert_eq!(compute_risk_score(true, true, 99), 6.0);
    }

    #[test]
    fn risk_clamps_at_zero_when_all_missing() {
        // -3 -3 -4 = -10 → clamped to 0
        assert_eq!(compute_risk_score(false, false, 1), 0.0);
    }

    #[test]
    fn risk_zero_secrets_no_deduct() {
        assert_eq!(compute_risk_score(true, true, 0), 10.0);
    }

    use super::{compute_documentation_score, compute_reliability_score};

    /// MCP-1 regression: validate_workflow and get_readiness_breakdown
    /// produced different scores for the same inputs because each had its
    /// own inlined formula. Both now go through these shared helpers; the
    /// tests pin the formula so future drift between callers is impossible.
    #[test]
    fn reliability_zero_executions_is_zero() {
        assert_eq!(compute_reliability_score(None, 0), 0.0);
        assert_eq!(compute_reliability_score(Some(1.0), 0), 0.0);
    }

    #[test]
    fn reliability_saturates_at_ten_runs() {
        // 5 perfect runs → 50% of credit (5/10 × 1.0 × 50)
        assert_eq!(compute_reliability_score(Some(1.0), 5), 25.0);
        // 10 perfect runs → full credit (1.0 × 1.0 × 50)
        assert_eq!(compute_reliability_score(Some(1.0), 10), 50.0);
        // 100 perfect runs → still full credit (saturation)
        assert_eq!(compute_reliability_score(Some(1.0), 100), 50.0);
    }

    #[test]
    fn reliability_scales_with_success_rate() {
        // 80% success rate, 10 runs → 0.8 × 1.0 × 50 = 40
        assert_eq!(compute_reliability_score(Some(0.8), 10), 40.0);
    }

    /// The MCP-1 regression value: 7 perfect executions of daily-brief.
    /// Pre-fix validate_workflow computed 7/100 × 40 = 2.8 (≈3).
    /// Post-fix both surfaces compute 7/10 × 50 = 35.
    #[test]
    fn reliability_seven_runs_perfect_matches_breakdown() {
        assert_eq!(compute_reliability_score(Some(1.0), 7), 35.0);
    }

    #[test]
    fn documentation_max_is_twenty() {
        assert_eq!(compute_documentation_score(true, true, true), 20.0);
    }

    #[test]
    fn documentation_components() {
        assert_eq!(compute_documentation_score(true, false, false), 10.0); // desc only
        assert_eq!(compute_documentation_score(false, true, false), 5.0); // node-desc only
        assert_eq!(compute_documentation_score(false, false, true), 5.0); // caps only
        assert_eq!(compute_documentation_score(false, false, false), 0.0);
    }

    use super::format_percent;

    #[test]
    fn format_percent_rounds_to_one_decimal() {
        assert_eq!(format_percent(99.0), 99.0);
        assert_eq!(format_percent(99.95), 100.0);
        assert_eq!(format_percent(99.94), 99.9);
        assert_eq!(format_percent(76.92307692), 76.9);
        assert_eq!(format_percent(0.0), 0.0);
        assert_eq!(format_percent(100.0), 100.0);
    }

    #[test]
    fn format_percent_handles_non_finite() {
        assert_eq!(format_percent(f64::NAN), 0.0);
        assert_eq!(format_percent(f64::INFINITY), 0.0);
        assert_eq!(format_percent(f64::NEG_INFINITY), 0.0);
    }
}

#[cfg(test)]
mod fingerprint_tests {
    use super::{fingerprint_error_message, ExecStats};

    #[test]
    fn replaces_uuid_with_placeholder() {
        let msg = "execution 550e8400-e29b-41d4-a716-446655440000 failed";
        assert_eq!(fingerprint_error_message(msg), "execution <UUID> failed");
    }

    #[test]
    fn replaces_iso_timestamp() {
        let msg = "deadline 2026-04-12T15:30:00Z exceeded";
        let out = fingerprint_error_message(msg);
        assert!(out.contains("<TIMESTAMP>"));
        assert!(!out.contains("2026-04-12"));
    }

    #[test]
    fn collapses_after_n_to_n_placeholder() {
        let a = fingerprint_error_message("timeout after 32");
        let b = fingerprint_error_message("timeout after 91");
        assert_eq!(a, b);
        // The (after|...|timeout|...) alternation matches `after 32` here,
        // which collapses to `after N`. The leading "timeout " is preserved.
        assert_eq!(a, "timeout after N");
    }

    #[test]
    fn keeps_unmatched_text_unchanged() {
        let msg = "connection refused by upstream";
        assert_eq!(fingerprint_error_message(msg), msg);
    }

    #[test]
    fn handles_multiple_substitutions_in_one_msg() {
        let msg =
            "exec 550e8400-e29b-41d4-a716-446655440000 timeout after 30 at 2026-04-12T10:00:00Z";
        let out = fingerprint_error_message(msg);
        assert!(out.contains("<UUID>"));
        assert!(out.contains("<TIMESTAMP>"));
        // `timeout after 30` → `timeout after N` (alternation matches "after").
        assert!(out.contains("after N"));
    }

    #[test]
    fn collapses_long_quoted_prose_previews() {
        // Real production case: two OUTPUT_SCHEMA failures whose only
        // difference is the LLM's literal output preview ("untrusted
        // data" vs "untrusted_data"). Without the long-quote collapse,
        // these produce distinct fingerprints with count=1 each instead
        // of one fingerprint with count=2 — defeating top-K aggregation.
        let a = fingerprint_error_message(
            r#"OUTPUT_SCHEMA enforcement fired. Got prose: "I notice the untrusted data block contains what appears to b...""#,
        );
        let b = fingerprint_error_message(
            r#"OUTPUT_SCHEMA enforcement fired. Got prose: "I notice the untrusted_data block contains what appears to b...""#,
        );
        assert_eq!(a, b);
        assert!(a.contains(r#""<QUOTED>""#));
    }

    #[test]
    fn preserves_short_quoted_tokens() {
        // Short tokens (< 16 chars) stay legible — `"id"`, `"true"`,
        // `"timeout"` carry useful signal that aggregation shouldn't lose.
        let msg = r#"missing field "id" in payload"#;
        let out = fingerprint_error_message(msg);
        assert!(out.contains(r#""id""#));
        assert!(!out.contains("<QUOTED>"));
    }

    #[test]
    fn exec_stats_empty_zeros_all() {
        let s = ExecStats::empty();
        assert_eq!(s.total, 0);
        assert_eq!(s.succeeded, 0);
        assert_eq!(s.failed, 0);
    }

    #[test]
    fn exec_stats_success_rate_zero_total() {
        assert_eq!(ExecStats::empty().success_rate_percent(), 0.0);
    }

    #[test]
    fn exec_stats_success_rate_proportional() {
        let s = ExecStats {
            total: 4,
            succeeded: 1,
            failed: 3,
            running: 0,
            avg_duration_secs: None,
        };
        assert_eq!(s.success_rate_percent(), 25.0);
    }
}

// ------------------------------------------------------------------
// Repository
// ------------------------------------------------------------------

pub struct AnalyticsRepository {
    db_pool: PgPool,
    /// MCP-680 (2026-05-13): SecretsManager for transparent decryption
    /// of `workflow_executions.output_data_enc`. None on legacy builders
    /// (the analytics surface degrades to plaintext-only — encrypted
    /// rows skipped). Production paths should wire this via
    /// `with_secrets_manager`.
    secrets_manager: Option<std::sync::Arc<talos_secrets_manager::SecretsManager>>,
}

impl AnalyticsRepository {
    pub fn new(db_pool: PgPool) -> Self {
        Self {
            db_pool,
            secrets_manager: None,
        }
    }

    /// Wire a SecretsManager so output-reading queries can decrypt
    /// encrypted rows. Without this, the `get_*_completed_executions_output`
    /// methods return ZERO rows on encryption-enabled deployments (every
    /// completed row has `output_data IS NULL`, ciphertext lives in
    /// `output_data_enc + output_enc_key_id`). See MCP-680 +
    /// `memory/encrypted_output_select_blindness.md`.
    pub fn with_secrets_manager(
        mut self,
        sm: std::sync::Arc<talos_secrets_manager::SecretsManager>,
    ) -> Self {
        self.secrets_manager = Some(sm);
        self
    }

    /// Decrypt a single output row (plaintext fallback for legacy).
    /// Returns None when both columns are NULL or decryption fails.
    ///
    /// MCP-S2: `output_data_enc` is AAD-bound to the execution `id`
    /// (`encrypt_value_aad_v1`), so the read MUST dispatch on
    /// `output_data_format` and supply the same AAD via `decrypt_versioned`.
    /// A bare `decrypt_value_by_key` (empty AAD) tag-fails every v1 row,
    /// re-introducing the MCP-680 output-blindness on encrypted deploys.
    /// Callers MUST therefore SELECT `id` + `output_data_format`.
    async fn decode_output_row(
        &self,
        exec_id: Uuid,
        plaintext: Option<serde_json::Value>,
        enc_bytes: Option<Vec<u8>>,
        key_id: Option<Uuid>,
        format_version: i16,
    ) -> Option<serde_json::Value> {
        match (&self.secrets_manager, enc_bytes, key_id) {
            (Some(sm), Some(bytes), Some(kid)) => {
                match sm
                    .decrypt_versioned(kid, &bytes, exec_id.as_bytes(), format_version)
                    .await
                {
                    Ok(s) => serde_json::from_str(&s).ok(),
                    Err(e) => {
                        tracing::warn!(
                            err = ?e,
                            "AnalyticsRepository: output decrypt failed — skipping row"
                        );
                        None
                    }
                }
            }
            _ => plaintext,
        }
    }

    // -- Exec stats -------------------------------------------------------

    pub async fn get_exec_stats(&self, wf_id: Uuid, user_id: Uuid, days: i32) -> Result<ExecStats> {
        // avg_duration_secs is filtered to status='completed' so stale-
        // cleanup failures (auto-marked failed at timeout, carrying a
        // ~1h phantom duration) don't distort the metric. See sibling
        // method in talos-workflow-repository for the production
        // incident rationale.
        // RFC 0005 S3: self-scope so the workflow_executions RLS policy
        // backstops this read for all (MCP analytics) callers.
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let row = sqlx::query(
            "SELECT COUNT(*)::bigint AS total, \
                    COUNT(*) FILTER (WHERE status = 'completed')::bigint AS succeeded, \
                    COUNT(*) FILTER (WHERE status = 'failed')::bigint AS failed, \
                    COUNT(*) FILTER (WHERE status = 'running')::bigint AS running, \
                    (AVG(EXTRACT(EPOCH FROM (completed_at - started_at))) FILTER (WHERE completed_at IS NOT NULL AND status = 'completed'))::float8 AS avg_duration_secs \
             FROM workflow_executions \
             WHERE workflow_id = $1 AND user_id = $2 AND started_at > NOW() - make_interval(days => $3::int)",
        )
        .bind(wf_id)
        .bind(user_id)
        .bind(days)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(ExecStats {
            total: row.try_get::<Option<_>, _>("total")?.unwrap_or(0),
            succeeded: row.try_get::<Option<_>, _>("succeeded")?.unwrap_or(0),
            failed: row.try_get::<Option<_>, _>("failed")?.unwrap_or(0),
            running: row.try_get::<Option<_>, _>("running")?.unwrap_or(0),
            avg_duration_secs: row.try_get::<Option<_>, _>("avg_duration_secs")?,
        })
    }

    pub async fn get_exec_stats_global(&self, user_id: Uuid, days: i32) -> Result<ExecStats> {
        // See `get_exec_stats` for the status='completed' AVG-filter
        // rationale.
        // RFC 0005 S3: self-scope (see get_exec_stats).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let row = sqlx::query(
            "SELECT COUNT(*)::bigint AS total, \
                    COUNT(*) FILTER (WHERE status = 'completed')::bigint AS succeeded, \
                    COUNT(*) FILTER (WHERE status = 'failed')::bigint AS failed, \
                    COUNT(*) FILTER (WHERE status = 'running')::bigint AS running, \
                    (AVG(EXTRACT(EPOCH FROM (completed_at - started_at))) FILTER (WHERE completed_at IS NOT NULL AND status = 'completed'))::float8 AS avg_duration_secs \
             FROM workflow_executions \
             WHERE user_id = $1 AND started_at > NOW() - make_interval(days => $2::int)",
        )
        .bind(user_id)
        .bind(days)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(ExecStats {
            total: row.try_get::<Option<_>, _>("total")?.unwrap_or(0),
            succeeded: row.try_get::<Option<_>, _>("succeeded")?.unwrap_or(0),
            failed: row.try_get::<Option<_>, _>("failed")?.unwrap_or(0),
            running: row.try_get::<Option<_>, _>("running")?.unwrap_or(0),
            avg_duration_secs: row.try_get::<Option<_>, _>("avg_duration_secs")?,
        })
    }

    // -- Workflow reads ----------------------------------------------------

    pub async fn get_workflow_for_analytics(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<WorkflowGraphRow>> {
        let row = sqlx::query(
            "SELECT id, name, graph_json::text AS graph_json, status, is_enabled, \
                    workflow_type, tags, created_at, updated_at \
             FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(wf_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        row.map(|r| -> Result<WorkflowGraphRow> {
            Ok(WorkflowGraphRow {
                id: r.get("id"),
                name: r.get("name"),
                graph_json: r.try_get::<Option<_>, _>("graph_json")?,
                status: r.try_get::<Option<_>, _>("status")?,
                is_enabled: r.try_get::<Option<_>, _>("is_enabled")?.unwrap_or(false),
                workflow_type: r.try_get::<Option<_>, _>("workflow_type")?,
                tags: r.try_get::<Option<_>, _>("tags")?,
                created_at: r.try_get::<Option<_>, _>("created_at")?,
                updated_at: r.try_get::<Option<_>, _>("updated_at")?,
            })
        })
        .transpose()
    }

    pub async fn get_workflow_full(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<WorkflowFullRow>> {
        let row = sqlx::query(
            "SELECT id, name, graph_json::text AS graph_json, tags, description, \
                    max_concurrent_executions, capabilities, intent \
             FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(wf_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        row.map(|r| -> Result<WorkflowFullRow> {
            Ok(WorkflowFullRow {
                id: r.get("id"),
                name: r.get("name"),
                graph_json: r.try_get::<Option<_>, _>("graph_json")?,
                tags: r.try_get::<Option<_>, _>("tags")?,
                description: r.try_get::<Option<_>, _>("description")?,
                max_concurrent_executions: r
                    .try_get::<Option<_>, _>("max_concurrent_executions")?,
                capabilities: r.try_get::<Option<_>, _>("capabilities")?,
                intent: r.try_get::<Option<_>, _>("intent")?,
            })
        })
        .transpose()
    }

    pub async fn get_workflow_graph_json(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<String>> {
        let row = sqlx::query(
            "SELECT graph_json::text AS graph_json FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(wf_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row
            .map(|r| r.try_get::<Option<String>, _>("graph_json"))
            .transpose()?
            .flatten())
    }

    pub async fn list_workflows_for_user(&self, user_id: Uuid) -> Result<Vec<WorkflowBasicRow>> {
        // RFC 0005 S3: self-scope (workflows RLS backstop for MCP callers).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let rows = sqlx::query(
            "SELECT id, name, status, is_enabled, workflow_type, capabilities, \
                    readiness_score, description, created_at, updated_at \
             FROM workflows \
             WHERE user_id = $1 AND (status IS NULL OR status != 'archived') \
             ORDER BY updated_at DESC",
        )
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.into_iter()
            .map(|r| -> Result<WorkflowBasicRow> {
                Ok(WorkflowBasicRow {
                    id: r.get("id"),
                    name: r.get("name"),
                    status: r.try_get::<Option<_>, _>("status")?,
                    is_enabled: r.try_get::<Option<_>, _>("is_enabled")?.unwrap_or(false),
                    workflow_type: r.try_get::<Option<_>, _>("workflow_type")?,
                    capabilities: r.try_get::<Option<_>, _>("capabilities")?,
                    readiness_score: r.try_get::<Option<_>, _>("readiness_score")?,
                    description: r.try_get::<Option<_>, _>("description")?,
                    created_at: r.try_get::<Option<_>, _>("created_at")?,
                    updated_at: r.try_get::<Option<_>, _>("updated_at")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    pub async fn list_workflows_with_graphs(&self, user_id: Uuid) -> Result<Vec<WorkflowGraphRow>> {
        self.list_workflows_with_graphs_limited(user_id, 500).await
    }

    pub async fn list_workflows_with_graphs_limited(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<WorkflowGraphRow>> {
        // RFC 0005 S3: self-scope (workflows RLS backstop for MCP callers).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let rows = sqlx::query(
            "SELECT id, name, graph_json::text AS graph_json, status, is_enabled, \
                    workflow_type, tags, created_at, updated_at \
             FROM workflows \
             WHERE user_id = $1 AND (status IS NULL OR status != 'archived') \
             ORDER BY updated_at DESC \
             LIMIT $2",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.into_iter()
            .map(|r| -> Result<WorkflowGraphRow> {
                Ok(WorkflowGraphRow {
                    id: r.get("id"),
                    name: r.get("name"),
                    graph_json: r.try_get::<Option<_>, _>("graph_json")?,
                    status: r.try_get::<Option<_>, _>("status")?,
                    is_enabled: r.try_get::<Option<_>, _>("is_enabled")?.unwrap_or(false),
                    workflow_type: r.try_get::<Option<_>, _>("workflow_type")?,
                    tags: r.try_get::<Option<_>, _>("tags")?,
                    created_at: r.try_get::<Option<_>, _>("created_at")?,
                    updated_at: r.try_get::<Option<_>, _>("updated_at")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// MCP-435 (2026-05-11): find workflows whose `graph_json` references
    /// the given workflow_id as a sub_workflow. Substring search on the
    /// TEXT column with a leading `%` is a sequential scan regardless of
    /// index, but PostgreSQL can stop after `limit` matches — drastically
    /// cheaper than the pre-MCP-435 pattern that loaded every workflow's
    /// full graph_json into memory and substring-scanned in Rust.
    ///
    /// For a user with 500 workflows of 50KB avg graph: pre-fix ~25MB
    /// result set + 500-row JSON deserialisation; post-fix at most
    /// `limit` rows of {id, name} (~5KB). Sort order is undefined —
    /// the call site only counts matches and lists them, not relevance-
    /// ranks them.
    ///
    /// SECURITY: `target_id_str` is interpolated as a LIKE parameter
    /// via sqlx bind ($3) — UUIDs are hex+hyphens only, so no
    /// injection vector, but the bind parameter is the right shape
    /// regardless. Excludes archived rows for parity with
    /// `list_workflows_with_graphs`.
    pub async fn find_workflows_referencing_workflow_id(
        &self,
        user_id: Uuid,
        exclude_workflow_id: Uuid,
        target_id_str: &str,
        limit: i64,
    ) -> Result<Vec<(Uuid, String)>> {
        let pattern = format!("%{target_id_str}%");
        let rows = sqlx::query(
            "SELECT id, name FROM workflows \
             WHERE user_id = $1 AND id != $2 AND graph_json LIKE $3 \
               AND (status IS NULL OR status != 'archived') \
             LIMIT $4",
        )
        .bind(user_id)
        .bind(exclude_workflow_id)
        .bind(&pattern)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| (r.get("id"), r.get("name")))
            .collect())
    }

    // -- Module/template lookups ------------------------------------------

    /// Phase 5.1: queries the unified modules table; canonical id only.
    pub async fn list_module_and_template_names(&self, ids: &[Uuid]) -> Result<Vec<ModuleNameRow>> {
        let rows = sqlx::query("SELECT id, name FROM modules WHERE id = ANY($1)")
            .bind(ids)
            .fetch_all(&self.db_pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| ModuleNameRow {
                id: r.get("id"),
                name: r.get("name"),
            })
            .collect())
    }

    /// Phase 5.1: queries unified modules table; canonical id only.
    pub async fn check_template_ids_exist(&self, ids: &[Uuid]) -> Result<Vec<Uuid>> {
        let rows: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM modules WHERE id = ANY($1)")
            .bind(ids)
            .fetch_all(&self.db_pool)
            .await?;
        Ok(rows)
    }

    /// Phase 5.1: queries unified modules table; canonical id only.
    pub async fn check_module_ids_exist(&self, ids: &[Uuid]) -> Result<Vec<Uuid>> {
        let rows: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM modules WHERE id = ANY($1)")
            .bind(ids)
            .fetch_all(&self.db_pool)
            .await?;
        Ok(rows)
    }

    // -- System status ----------------------------------------------------

    pub async fn get_system_status_counts(&self, user_id: Uuid) -> Result<SystemStatusCounts> {
        // Phase 5: `templates` count now sources from the unified `modules`
        // table (counts user-owned + catalog rows, matching the legacy
        // `node_templates.user_id = $1 OR IS NULL` predicate).
        // RFC 0005 S3: self-scope so the workflows / workflow_executions /
        // secrets RLS policies backstop the per-user count subqueries.
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let row = sqlx::query(
            "SELECT \
               (SELECT COUNT(*)::bigint FROM workflows WHERE user_id = $1) AS workflows, \
               (SELECT COUNT(*)::bigint FROM workflow_executions WHERE user_id = $1) AS executions, \
               (SELECT COUNT(*)::bigint FROM user_modules WHERE user_id = $1) AS modules, \
               (SELECT COUNT(*)::bigint FROM modules WHERE user_id = $1 OR user_id IS NULL) AS templates, \
               (SELECT COUNT(*)::bigint FROM secrets WHERE created_by = $1) AS secrets, \
               (SELECT COUNT(*)::bigint FROM workflow_schedules WHERE user_id = $1) AS schedules, \
               (SELECT COUNT(*)::bigint FROM webhook_triggers WHERE user_id = $1) AS webhooks",
        )
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(SystemStatusCounts {
            workflows: row.try_get::<Option<_>, _>("workflows")?.unwrap_or(0),
            executions: row.try_get::<Option<_>, _>("executions")?.unwrap_or(0),
            modules: row.try_get::<Option<_>, _>("modules")?.unwrap_or(0),
            templates: row.try_get::<Option<_>, _>("templates")?.unwrap_or(0),
            secrets: row.try_get::<Option<_>, _>("secrets")?.unwrap_or(0),
            schedules: row.try_get::<Option<_>, _>("schedules")?.unwrap_or(0),
            webhooks: row.try_get::<Option<_>, _>("webhooks")?.unwrap_or(0),
        })
    }

    // -- Failing workflows ------------------------------------------------

    pub async fn get_failing_workflows(
        &self,
        user_id: Uuid,
        hours: i32,
    ) -> Result<Vec<FailingWorkflowRow>> {
        // MCP-1211 follow-up 7 (2026-05-18): pre-fix predicate was
        // `NOT IN ('archived', 'draft')`. The 'draft' exclusion was
        // wrong — workflows can be `status='draft'` while still
        // scheduled and running (operator publish-once-then-iterate
        // pattern). Excluding drafts silently hid every failure for
        // that class — daily-brief's failed runs at 13:00 + 13:34
        // never showed up in failing_workflows. Only `archived`
        // should suppress observability; `draft` is an authoring
        // state, not an "ignore this workflow" signal. Same root
        // cause as the loop_capped sibling fix (see
        // ExecutionRepository::find_loop_capped_workflows_24h).
        // RFC 0005 S3: self-scope (workflows + workflow_executions backstop).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let rows = sqlx::query(
            "SELECT w.id, w.name, \
                    COUNT(*) FILTER (WHERE we.status = 'failed')::bigint AS fail_count, \
                    COUNT(*)::bigint AS total_count \
             FROM workflows w \
             JOIN workflow_executions we ON we.workflow_id = w.id \
             WHERE w.user_id = $1 AND we.started_at > NOW() - make_interval(hours => $2::int) \
               AND (w.status IS NULL OR w.status != 'archived') \
             GROUP BY w.id, w.name \
             HAVING COUNT(*) FILTER (WHERE we.status = 'failed') > 0 \
             ORDER BY fail_count DESC LIMIT 10",
        )
        .bind(user_id)
        .bind(hours)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.into_iter()
            .map(|r| -> Result<FailingWorkflowRow> {
                Ok(FailingWorkflowRow {
                    id: r.get("id"),
                    name: r.get("name"),
                    fail_count: r.try_get::<Option<_>, _>("fail_count")?.unwrap_or(0),
                    total_count: r.try_get::<Option<_>, _>("total_count")?.unwrap_or(0),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    // -- Health dashboard -------------------------------------------------

    pub async fn get_long_running_executions(&self, user_id: Uuid) -> Result<Vec<LongRunningRow>> {
        // RFC 0005 S3: self-scope (workflow_executions + workflows backstop).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let rows = sqlx::query(
            "SELECT we.id, we.workflow_id, w.name, \
                    EXTRACT(EPOCH FROM (NOW() - we.started_at))::int AS running_secs \
             FROM workflow_executions we \
             JOIN workflows w ON w.id = we.workflow_id \
             WHERE we.user_id = $1 AND we.status = 'running' \
               AND we.started_at < NOW() - INTERVAL '10 minutes' \
             ORDER BY we.started_at ASC LIMIT 10",
        )
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.into_iter()
            .map(|r| -> Result<LongRunningRow> {
                Ok(LongRunningRow {
                    id: r.get("id"),
                    workflow_id: r.get("workflow_id"),
                    name: r.get("name"),
                    running_secs: r.try_get::<Option<_>, _>("running_secs")?.unwrap_or(0),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    pub async fn get_health_summary_counts(&self, user_id: Uuid) -> Result<HealthSummaryCounts> {
        // RFC 0005 S3: self-scope (workflow_executions backstop).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let row = sqlx::query(
            "SELECT \
               COUNT(*) FILTER (WHERE status = 'running')::bigint AS running, \
               COUNT(*) FILTER (WHERE status = 'failed' AND started_at > NOW() - INTERVAL '24 hours')::bigint AS failed_24h, \
               COUNT(*) FILTER (WHERE status = 'completed' AND started_at > NOW() - INTERVAL '24 hours')::bigint AS completed_24h \
             FROM workflow_executions WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(HealthSummaryCounts {
            running: row.try_get::<Option<_>, _>("running")?.unwrap_or(0),
            failed_24h: row.try_get::<Option<_>, _>("failed_24h")?.unwrap_or(0),
            completed_24h: row.try_get::<Option<_>, _>("completed_24h")?.unwrap_or(0),
        })
    }

    // -- Latency ----------------------------------------------------------

    /// Compact stats for SLA threshold evaluation: total execution count,
    /// completed count, and p95 latency over a time window. Returns None if
    /// no executions exist in the window. Used by the background SLA task
    /// in `main.rs` (formerly an inline query that duplicated the latency
    /// percentile logic from `get_latency_percentiles_ms`).
    ///
    /// Unlike `get_latency_percentiles_ms`, this method does NOT filter by
    /// user_id — SLA alerting runs as a platform-wide background task.
    pub async fn get_sla_window_stats(&self, wf_id: Uuid, hours: i32) -> Option<SlaWindowStats> {
        let row: Option<(i64, i64, Option<f64>)> = sqlx::query_as(
            "SELECT COUNT(*), \
                    COUNT(*) FILTER (WHERE status = 'completed'), \
                    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY \
                        EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000) \
             FROM workflow_executions \
             WHERE workflow_id = $1 \
               AND started_at > NOW() - make_interval(hours => $2::int)",
        )
        .bind(wf_id)
        .bind(hours)
        .fetch_optional(&self.db_pool)
        .await
        .ok()
        .flatten();
        row.map(|(total, successes, p95_ms)| SlaWindowStats {
            total,
            successes,
            p95_ms,
        })
    }

    pub async fn get_latency_percentiles_ms(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
        days: i32,
    ) -> Result<LatencyPercentilesMs> {
        // status = 'completed' filter mirrors `get_extreme_executions`
        // and the avg_duration_secs fix in
        // talos-workflow-repository::get_workflow_execution_stats
        // (commit a42fdf2). Without it, percentiles include
        // stale-cleanup ghosts (1-hour phantom durations) and
        // quick-failed runs — producing values that contradict
        // fastest_execution / slowest_execution which already
        // filter to completed-only.
        let row = sqlx::query(
            "SELECT \
               PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000) AS p50_ms, \
               PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000) AS p95_ms, \
               PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000) AS p99_ms \
             FROM workflow_executions \
             WHERE workflow_id = $1 AND user_id = $2 \
               AND status = 'completed' AND completed_at IS NOT NULL \
               AND started_at > NOW() - make_interval(days => $3::int)",
        )
        .bind(wf_id)
        .bind(user_id)
        .bind(days)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(LatencyPercentilesMs {
            p50_ms: row.try_get::<Option<_>, _>("p50_ms")?,
            p95_ms: row.try_get::<Option<_>, _>("p95_ms")?,
            p99_ms: row.try_get::<Option<_>, _>("p99_ms")?,
        })
    }

    // -- Versions ---------------------------------------------------------

    pub async fn list_workflow_versions_changelog(
        &self,
        wf_id: Uuid,
        limit: i64,
    ) -> Result<Vec<VersionChangelogRow>> {
        let rows = sqlx::query(
            "SELECT version_number, graph_json::text AS graph_json, description, published_at \
             FROM workflow_versions WHERE workflow_id = $1 ORDER BY version_number ASC LIMIT $2",
        )
        .bind(wf_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<VersionChangelogRow> {
                Ok(VersionChangelogRow {
                    version_number: r.try_get::<Option<_>, _>("version_number")?,
                    graph_json: r.try_get::<Option<_>, _>("graph_json")?,
                    description: r.try_get::<Option<_>, _>("description")?,
                    published_at: r.try_get::<Option<_>, _>("published_at")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    pub async fn list_workflow_versions_audit(
        &self,
        wf_id: Uuid,
        limit: i64,
    ) -> Result<Vec<VersionAuditRow>> {
        let rows = sqlx::query(
            "SELECT version_number, description, published_at, is_active \
             FROM workflow_versions WHERE workflow_id = $1 ORDER BY published_at DESC LIMIT $2",
        )
        .bind(wf_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<VersionAuditRow> {
                Ok(VersionAuditRow {
                    version_number: r.try_get::<Option<_>, _>("version_number")?,
                    description: r.try_get::<Option<_>, _>("description")?,
                    published_at: r.try_get::<Option<_>, _>("published_at")?,
                    is_active: r.try_get::<Option<_>, _>("is_active")?.unwrap_or(false),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    pub async fn check_has_active_version(&self, wf_id: Uuid) -> Result<bool> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM workflow_versions WHERE workflow_id = $1 AND is_active = true)",
        )
        .bind(wf_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(exists)
    }

    pub async fn get_version_summary(&self, wf_id: Uuid) -> Result<VersionSummaryRow> {
        let row = sqlx::query(
            "SELECT COUNT(*)::bigint AS total_versions, \
                    MAX(version_number) AS latest_version, \
                    MAX(published_at) AS last_published \
             FROM workflow_versions WHERE workflow_id = $1",
        )
        .bind(wf_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(VersionSummaryRow {
            total_versions: row.try_get::<Option<_>, _>("total_versions")?.unwrap_or(0),
            latest_version: row.try_get::<Option<_>, _>("latest_version")?,
            last_published: row.try_get::<Option<_>, _>("last_published")?,
        })
    }

    // -- Schedules and webhooks -------------------------------------------

    pub async fn list_workflow_schedules(&self, wf_id: Uuid) -> Result<Vec<ScheduleRow>> {
        let rows = sqlx::query(
            "SELECT id, cron_expression, is_enabled, timezone, \
                    last_triggered_at, next_trigger_at \
             FROM workflow_schedules WHERE workflow_id = $1",
        )
        .bind(wf_id)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<ScheduleRow> {
                Ok(ScheduleRow {
                    id: r.get("id"),
                    cron_expression: r.get("cron_expression"),
                    is_enabled: r.try_get::<Option<_>, _>("is_enabled")?.unwrap_or(false),
                    timezone: r.try_get("timezone").ok(),
                    last_triggered_at: r.try_get("last_triggered_at").ok(),
                    next_trigger_at: r.try_get("next_trigger_at").ok(),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    pub async fn count_active_schedules(&self, wf_id: Uuid) -> Result<i64> {
        // workflow_schedules column is `is_enabled`, NOT `is_active`
        // (migration 20260309000200). Same column-name-drift class as
        // get_workflow_schedule_count — caller's unwrap_or(0)
        // swallowed the error so dashboards reported "0 active
        // schedules" everywhere.
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM workflow_schedules WHERE workflow_id = $1 AND is_enabled = true",
        )
        .bind(wf_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(count)
    }

    pub async fn list_workflow_webhooks(&self, wf_id: Uuid) -> Result<Vec<WebhookRow>> {
        let rows = sqlx::query(
            "SELECT id, endpoint_path, is_enabled \
             FROM webhook_triggers WHERE workflow_id = $1",
        )
        .bind(wf_id)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<WebhookRow> {
                Ok(WebhookRow {
                    id: r.get("id"),
                    endpoint_path: r.get("endpoint_path"),
                    is_enabled: r.try_get::<Option<_>, _>("is_enabled")?.unwrap_or(false),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    pub async fn list_webhooks_for_modules(
        &self,
        module_ids: &[Uuid],
        wf_id: Uuid,
    ) -> Result<Vec<WebhookRow>> {
        let rows = sqlx::query(
            "SELECT id, endpoint_path, is_enabled \
             FROM webhook_triggers WHERE module_id = ANY($1) AND workflow_id = $2",
        )
        .bind(module_ids)
        .bind(wf_id)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<WebhookRow> {
                Ok(WebhookRow {
                    id: r.get("id"),
                    endpoint_path: r.get("endpoint_path"),
                    is_enabled: r.try_get::<Option<_>, _>("is_enabled")?.unwrap_or(false),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    pub async fn count_active_webhooks_for_modules(
        &self,
        module_ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<i64> {
        // webhook_triggers column is `enabled` (initial schema, never
        // renamed). Same column-drift class as the schedules count —
        // pre-fix this query referenced `is_active`, errored at runtime,
        // and the caller's unwrap_or(0) silently reported zero
        // active webhooks for every workflow with a webhook attached.
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM webhook_triggers \
             WHERE module_id = ANY($1) AND enabled = true AND user_id = $2",
        )
        .bind(module_ids)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(count)
    }

    // -- Audit ------------------------------------------------------------

    pub async fn list_audit_events(&self, wf_id: Uuid, limit: i64) -> Result<Vec<AuditEventRow>> {
        let rows = sqlx::query(
            "SELECT id, event_type, description, created_at, actor_id \
             FROM workflow_audit_log WHERE workflow_id = $1 ORDER BY created_at DESC LIMIT $2",
        )
        .bind(wf_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<AuditEventRow> {
                Ok(AuditEventRow {
                    id: r.get("id"),
                    event_type: r.get("event_type"),
                    description: r.try_get::<Option<_>, _>("description")?,
                    created_at: r.get("created_at"),
                    actor_id: r.try_get::<Option<_>, _>("actor_id")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    pub async fn list_executions_for_audit(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<ExecutionAuditRow>> {
        // `workflow_executions` has no top-level `trigger_type` column —
        // see the doc comment on
        // `WorkflowRepository::get_scheduled_24h_execution_stats` for
        // the full backstory. Pre-fix this query referenced the missing
        // column; the handler's `unwrap_or_default()` swallowed the
        // resulting Postgres error and `get_workflow_audit_trail`
        // silently returned 0 execution events for every workflow,
        // including ones with hundreds of runs. Caught via MCP probe
        // 2026-05-06.
        let rows = sqlx::query(
            "SELECT id, status, started_at, completed_at, error_message, \
                    provenance->>'trigger_type' AS trigger_type \
             FROM workflow_executions \
             WHERE workflow_id = $1 AND user_id = $2 \
             ORDER BY started_at DESC LIMIT $3",
        )
        .bind(wf_id)
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<ExecutionAuditRow> {
                Ok(ExecutionAuditRow {
                    id: r.get("id"),
                    status: r.get("status"),
                    started_at: r.try_get::<Option<_>, _>("started_at")?,
                    completed_at: r.try_get::<Option<_>, _>("completed_at")?,
                    error_message: r.try_get::<Option<_>, _>("error_message")?,
                    trigger_type: r.try_get::<Option<_>, _>("trigger_type")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    // -- Error / node failures --------------------------------------------

    pub async fn get_error_messages(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
        days: i32,
        limit: i64,
    ) -> Result<Vec<String>> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT error_message FROM workflow_executions \
             WHERE workflow_id = $1 AND user_id = $2 AND status = 'failed' \
               AND error_message IS NOT NULL \
               AND started_at > NOW() - make_interval(days => $3::int) \
             ORDER BY started_at DESC LIMIT $4",
        )
        .bind(wf_id)
        .bind(user_id)
        .bind(days)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    /// MCP-99 (2026-05-08): error messages paired with started_at so callers
    /// (currently `get_error_report`) can surface a `latest_at` per
    /// fingerprint group. Same SQL as `get_error_messages` but selects
    /// the timestamp too — kept as a separate method so the existing
    /// caller (workflow_stats) doesn't pay the extra projection.
    pub async fn get_error_messages_with_started_at(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
        days: i32,
        limit: i64,
    ) -> Result<Vec<(String, DateTime<Utc>)>> {
        let rows = sqlx::query(
            "SELECT error_message, started_at FROM workflow_executions \
             WHERE workflow_id = $1 AND user_id = $2 AND status = 'failed' \
               AND error_message IS NOT NULL \
               AND started_at IS NOT NULL \
               AND started_at > NOW() - make_interval(days => $3::int) \
             ORDER BY started_at DESC LIMIT $4",
        )
        .bind(wf_id)
        .bind(user_id)
        .bind(days)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<(String, DateTime<Utc>)> {
                Ok((
                    r.try_get::<Option<String>, _>("error_message")?
                        .unwrap_or_default(),
                    r.try_get::<Option<DateTime<Utc>>, _>("started_at")?
                        .unwrap_or_else(Utc::now),
                ))
            })
            .collect::<Result<Vec<_>>>()
    }

    pub async fn get_node_failure_counts(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
        days: i32,
    ) -> Result<Vec<NodeFailureCountRow>> {
        let rows = sqlx::query(
            "SELECT ee.node_id, COUNT(*)::bigint AS fail_count \
             FROM execution_events ee \
             JOIN workflow_executions we ON we.id = ee.execution_id \
             WHERE we.workflow_id = $1 AND we.user_id = $2 AND ee.event_type = 'node_failed' \
               AND we.started_at > NOW() - make_interval(days => $3::int) \
             GROUP BY ee.node_id ORDER BY fail_count DESC LIMIT 20",
        )
        .bind(wf_id)
        .bind(user_id)
        .bind(days)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<NodeFailureCountRow> {
                Ok(NodeFailureCountRow {
                    node_id: r.get("node_id"),
                    fail_count: r.try_get::<Option<_>, _>("fail_count")?.unwrap_or(0),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    pub async fn get_node_failure_details(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
        days: i32,
    ) -> Result<Vec<NodeFailureDetailRow>> {
        let rows = sqlx::query(
            "SELECT ee.node_id, COUNT(*)::bigint AS fail_count, \
                    MAX(ee.created_at) AS latest_at, \
                    (ARRAY_AGG(ee.log_message ORDER BY ee.created_at DESC))[1] AS latest_error \
             FROM execution_events ee \
             JOIN workflow_executions we ON we.id = ee.execution_id \
             WHERE we.workflow_id = $1 AND we.user_id = $2 AND ee.event_type = 'node_failed' \
               AND we.started_at > NOW() - make_interval(days => $3::int) \
             GROUP BY ee.node_id ORDER BY fail_count DESC LIMIT 50",
        )
        .bind(wf_id)
        .bind(user_id)
        .bind(days)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<NodeFailureDetailRow> {
                Ok(NodeFailureDetailRow {
                    node_id: r.get("node_id"),
                    fail_count: r.try_get::<Option<_>, _>("fail_count")?.unwrap_or(0),
                    latest_at: r.try_get::<Option<_>, _>("latest_at")?,
                    latest_error: r.try_get::<Option<_>, _>("latest_error")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    pub async fn get_hourly_failure_breakdown(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
        days: i32,
    ) -> Result<Vec<HourlyFailureRow>> {
        let rows = sqlx::query(
            "SELECT EXTRACT(HOUR FROM started_at)::int AS hour, COUNT(*)::bigint AS fail_count \
             FROM workflow_executions \
             WHERE workflow_id = $1 AND user_id = $2 AND status = 'failed' \
               AND started_at > NOW() - make_interval(days => $3::int) \
             GROUP BY hour ORDER BY hour",
        )
        .bind(wf_id)
        .bind(user_id)
        .bind(days)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<HourlyFailureRow> {
                Ok(HourlyFailureRow {
                    hour: r.try_get::<Option<_>, _>("hour")?.unwrap_or(0),
                    fail_count: r.try_get::<Option<_>, _>("fail_count")?.unwrap_or(0),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    // -- All-workflow stats -----------------------------------------------

    pub async fn list_workflow_stat_summaries(
        &self,
        user_id: Uuid,
        days: i32,
        limit: i64,
    ) -> Result<Vec<WorkflowStatSummaryRow>> {
        // See `get_exec_stats` for the status='completed' AVG-filter
        // rationale.
        let rows = sqlx::query(
            "SELECT w.id, w.name, \
                    COUNT(*)::bigint AS total, \
                    COUNT(*) FILTER (WHERE we.status = 'completed')::bigint AS succeeded, \
                    COUNT(*) FILTER (WHERE we.status = 'failed')::bigint AS failed, \
                    (AVG(EXTRACT(EPOCH FROM (we.completed_at - we.started_at))) FILTER (WHERE we.completed_at IS NOT NULL AND we.status = 'completed'))::float8 AS avg_duration_secs \
             FROM workflows w \
             LEFT JOIN workflow_executions we ON we.workflow_id = w.id \
               AND we.started_at > NOW() - make_interval(days => $2::int) \
             WHERE w.user_id = $1 \
             GROUP BY w.id, w.name \
             HAVING COUNT(we.id) > 0 \
             ORDER BY COUNT(*) FILTER (WHERE we.status = 'failed') DESC, COUNT(*) DESC \
             LIMIT $3",
        )
        .bind(user_id)
        .bind(days)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<WorkflowStatSummaryRow> {
                Ok(WorkflowStatSummaryRow {
                    id: r.get("id"),
                    name: r.get("name"),
                    total: r.try_get::<Option<_>, _>("total")?.unwrap_or(0),
                    succeeded: r.try_get::<Option<_>, _>("succeeded")?.unwrap_or(0),
                    failed: r.try_get::<Option<_>, _>("failed")?.unwrap_or(0),
                    avg_duration_secs: r.try_get::<Option<_>, _>("avg_duration_secs")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    // -- Unused secrets ---------------------------------------------------

    pub async fn get_unused_secrets(&self, user_id: Uuid) -> Result<Vec<UnusedSecretRow>> {
        let rows = sqlx::query(
            "SELECT name, key_path, description, created_at, namespace \
             FROM secrets WHERE created_by = $1 ORDER BY created_at DESC LIMIT 200",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<UnusedSecretRow> {
                Ok(UnusedSecretRow {
                    name: r.get("name"),
                    key_path: r.get("key_path"),
                    description: r.try_get::<Option<_>, _>("description")?,
                    created_at: r.try_get::<Option<_>, _>("created_at")?,
                    namespace: r.try_get::<Option<_>, _>("namespace")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    pub async fn get_secrets_allowed_by_modules(&self, user_id: Uuid) -> Result<Vec<String>> {
        // Phase 4 prep: query the unified `modules` table. The previous
        // UNION over (node_templates ∪ wasm_modules) was deduplicating the
        // same secret names by accident — every row from both tables now
        // lives once in `modules`, so a single SELECT DISTINCT suffices.
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT unnest(allowed_secrets) AS secret_name \
               FROM modules \
              WHERE user_id = $1 \
                AND allowed_secrets IS NOT NULL \
                AND array_length(allowed_secrets, 1) > 0",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    // -- Module info ------------------------------------------------------

    pub async fn get_module_info(
        &self,
        module_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<ModuleInfoRow>> {
        // Phase 4 prep: query the unified `modules` table with the 3-shape
        // id match so callers passing a legacy template_id or
        // wasm_module_id continue to resolve until graph_json is rewritten.
        let row = sqlx::query(
            "SELECT name, capability_world \
               FROM modules \
              WHERE id = $1 \
                AND user_id = $2",
        )
        .bind(module_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        row.map(|r| -> Result<ModuleInfoRow> {
            Ok(ModuleInfoRow {
                name: r.get("name"),
                capability_world: r.try_get::<Option<_>, _>("capability_world")?,
            })
        })
        .transpose()
    }

    // -- Capabilities -----------------------------------------------------

    pub async fn set_workflow_capabilities(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
        capabilities: &[String],
    ) -> Result<bool> {
        let result =
            sqlx::query("UPDATE workflows SET capabilities = $1 WHERE id = $2 AND user_id = $3")
                .bind(capabilities)
                .bind(wf_id)
                .bind(user_id)
                .execute(&self.db_pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_workflows_by_capability(
        &self,
        user_id: Uuid,
        capabilities: &[String],
    ) -> Result<Vec<WorkflowCapabilityRow>> {
        let rows = sqlx::query(
            "SELECT w.id, w.name, w.description, w.capabilities, w.readiness_score, \
                    (SELECT COUNT(*) FILTER (WHERE status = 'completed')::float / NULLIF(COUNT(*), 0) \
                     FROM workflow_executions WHERE workflow_id = w.id AND started_at > NOW() - interval '30 days') AS success_rate \
             FROM workflows w \
             WHERE w.user_id = $1 AND w.capabilities @> $2 \
             ORDER BY w.readiness_score DESC NULLS LAST LIMIT 20",
        )
        .bind(user_id)
        .bind(capabilities)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<WorkflowCapabilityRow> {
                Ok(WorkflowCapabilityRow {
                    id: r.get("id"),
                    name: r.get("name"),
                    description: r.try_get::<Option<_>, _>("description")?,
                    capabilities: r.try_get::<Option<_>, _>("capabilities")?,
                    readiness_score: r.try_get::<Option<_>, _>("readiness_score")?,
                    success_rate: r.try_get::<Option<_>, _>("success_rate")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    pub async fn get_workflow_capabilities(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Vec<String>>> {
        let row = sqlx::query("SELECT capabilities FROM workflows WHERE id = $1 AND user_id = $2")
            .bind(wf_id)
            .bind(user_id)
            .fetch_optional(&self.db_pool)
            .await?;
        Ok(row
            .map(|r| r.try_get::<Option<Vec<String>>, _>("capabilities"))
            .transpose()?
            .flatten())
    }

    pub async fn get_untagged_workflows(
        &self,
        user_id: Uuid,
        filter_ids: Option<&[Uuid]>,
    ) -> Result<Vec<WorkflowGraphRow>> {
        let rows = if let Some(ids) = filter_ids {
            sqlx::query(
                "SELECT id, name, graph_json::text AS graph_json, status, is_enabled, \
                        workflow_type, tags, created_at, updated_at \
                 FROM workflows \
                 WHERE user_id = $1 AND (capabilities IS NULL OR capabilities = '{}') \
                   AND id = ANY($2) \
                 ORDER BY created_at DESC LIMIT 200",
            )
            .bind(user_id)
            .bind(ids)
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id, name, graph_json::text AS graph_json, status, is_enabled, \
                        workflow_type, tags, created_at, updated_at \
                 FROM workflows \
                 WHERE user_id = $1 AND (capabilities IS NULL OR capabilities = '{}') \
                 ORDER BY created_at DESC LIMIT 200",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await?
        };
        rows.into_iter()
            .map(|r| -> Result<WorkflowGraphRow> {
                Ok(WorkflowGraphRow {
                    id: r.get("id"),
                    name: r.get("name"),
                    graph_json: r.try_get::<Option<_>, _>("graph_json")?,
                    status: r.try_get::<Option<_>, _>("status")?,
                    is_enabled: r.try_get::<Option<_>, _>("is_enabled")?.unwrap_or(false),
                    workflow_type: r.try_get::<Option<_>, _>("workflow_type")?,
                    tags: r.try_get::<Option<_>, _>("tags")?,
                    created_at: r.try_get::<Option<_>, _>("created_at")?,
                    updated_at: r.try_get::<Option<_>, _>("updated_at")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    pub async fn set_workflow_capabilities_if_empty(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
        capabilities: &[String],
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE workflows SET capabilities = $1 \
             WHERE id = $2 AND user_id = $3 AND (capabilities IS NULL OR capabilities = '{}')",
        )
        .bind(capabilities)
        .bind(wf_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_workflow_graph_and_capabilities(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<(String, Vec<String>)>> {
        let row = sqlx::query(
            "SELECT graph_json::text AS graph_json, COALESCE(capabilities, '{}') AS capabilities \
             FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(wf_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        row.map(|r| -> Result<(String, Vec<String>)> {
            let gj: String = r.try_get::<Option<_>, _>("graph_json")?.unwrap_or_default();
            let caps: Vec<String> = r
                .try_get::<Option<_>, _>("capabilities")?
                .unwrap_or_default();
            Ok((gj, caps))
        })
        .transpose()
    }

    // -- Capability suggestion helpers ------------------------------------

    /// Phase 3.2: queries the unified modules table.
    pub async fn get_capability_worlds_for_modules(
        &self,
        module_ids: &[Uuid],
    ) -> Result<Vec<String>> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT capability_world FROM modules \
             WHERE id = ANY($1)",
        )
        .bind(module_ids)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    /// Phase 3.2: queries the unified modules table; `kind` projected as
    /// `category` for back-compat. Note: kind is coarser than the old
    /// free-form category strings (catalog/sandbox/extracted only) — if a
    /// caller needs the original categories they should be migrated to
    /// query a future Phase 1.5 `category` column.
    pub async fn get_template_categories_lower(&self, module_ids: &[Uuid]) -> Result<Vec<String>> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT LOWER(kind) FROM modules \
             WHERE id = ANY($1)",
        )
        .bind(module_ids)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    pub async fn set_capabilities_if_empty(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
        capabilities: &[String],
    ) -> Result<()> {
        sqlx::query(
            "UPDATE workflows SET capabilities = $1 \
             WHERE id = $2 AND user_id = $3 AND (capabilities IS NULL OR capabilities = '{}')",
        )
        .bind(capabilities)
        .bind(wf_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    // -- Reuse stats ------------------------------------------------------

    pub async fn get_workflow_reuse_stats(
        &self,
        user_id: Uuid,
        days: i32,
    ) -> Result<Vec<ReuseStatRow>> {
        let rows = sqlx::query(
            "SELECT w.id AS workflow_id, w.name, w.graph_json::text AS graph_json, \
                    COUNT(we.id) AS total_invocations, \
                    COUNT(DISTINCT DATE(we.started_at)) AS unique_days \
             FROM workflows w \
             JOIN workflow_executions we ON we.workflow_id = w.id \
             WHERE w.user_id = $1 AND we.started_at > NOW() - make_interval(days => $2::int) \
               AND (w.status IS NULL OR w.status != 'archived') \
             GROUP BY w.id, w.name, w.graph_json \
             ORDER BY total_invocations DESC LIMIT 20",
        )
        .bind(user_id)
        .bind(days)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<ReuseStatRow> {
                Ok(ReuseStatRow {
                    workflow_id: r.get("workflow_id"),
                    name: r.get("name"),
                    graph_json: r.try_get::<Option<_>, _>("graph_json")?,
                    total_invocations: r.try_get::<Option<_>, _>("total_invocations")?.unwrap_or(0),
                    unique_days: r.try_get::<Option<_>, _>("unique_days")?.unwrap_or(0),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    // -- Fuel / output data -----------------------------------------------

    /// Returns output_data for completed executions scoped to a specific workflow.
    /// Always filters by both workflow_id and user_id to prevent cross-workflow data leakage.
    ///
    /// MCP-680 (2026-05-13): pre-fix this query filtered
    /// `output_data IS NOT NULL` (plaintext column only). With output
    /// encryption enabled (production default), every completed
    /// execution row has `output_data = NULL` (ciphertext lives in
    /// `output_data_enc + output_enc_key_id`), so the query returned
    /// ZERO rows. Downstream: per-node timing breakdowns in
    /// `get_workflow_stats` showed empty for every workflow on
    /// encryption-enabled deployments. Fix: SELECT both column
    /// families, accept either plaintext OR encrypted, decrypt via
    /// `decode_output_row` (which routes through SecretsManager when
    /// `with_secrets_manager` was wired in).
    pub async fn get_completed_executions_output(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        days: i32,
        limit: i64,
    ) -> Result<Vec<serde_json::Value>> {
        let raw: Vec<(
            Uuid,
            Option<serde_json::Value>,
            Option<Vec<u8>>,
            Option<Uuid>,
            i16,
        )> = sqlx::query_as(
            "SELECT we.id, we.output_data, we.output_data_enc, we.output_enc_key_id, we.output_data_format \
             FROM workflow_executions we \
             WHERE we.workflow_id = $1 AND we.user_id = $2 AND we.status = 'completed' \
               AND we.started_at > NOW() - make_interval(days => $3::int) \
               AND (we.output_data IS NOT NULL OR we.output_data_enc IS NOT NULL) \
             ORDER BY we.started_at DESC LIMIT $4",
        )
        .bind(workflow_id)
        .bind(user_id)
        .bind(days)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        let mut out = Vec::with_capacity(raw.len());
        for (id, plaintext, enc_bytes, key_id, fmt) in raw {
            if let Some(v) = self
                .decode_output_row(id, plaintext, enc_bytes, key_id, fmt)
                .await
            {
                out.push(v);
            }
        }
        Ok(out)
    }

    /// Returns output_data across ALL workflows for a user — used only by fuel-usage reports
    /// and other cross-workflow aggregations. Do NOT use for single-workflow reports;
    /// use `get_completed_executions_output` (workflow-scoped) instead.
    ///
    /// MCP-680: same encryption fix as the workflow-scoped sibling.
    pub async fn get_all_completed_executions_output(
        &self,
        user_id: Uuid,
        days: i32,
        limit: i64,
    ) -> Result<Vec<serde_json::Value>> {
        let raw: Vec<(
            Uuid,
            Option<serde_json::Value>,
            Option<Vec<u8>>,
            Option<Uuid>,
            i16,
        )> = sqlx::query_as(
            "SELECT we.id, we.output_data, we.output_data_enc, we.output_enc_key_id, we.output_data_format \
             FROM workflow_executions we \
             WHERE we.user_id = $1 AND we.status = 'completed' \
               AND we.started_at > NOW() - make_interval(days => $2::int) \
               AND (we.output_data IS NOT NULL OR we.output_data_enc IS NOT NULL) \
             ORDER BY we.started_at DESC LIMIT $3",
        )
        .bind(user_id)
        .bind(days)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        let mut out = Vec::with_capacity(raw.len());
        for (id, plaintext, enc_bytes, key_id, fmt) in raw {
            if let Some(v) = self
                .decode_output_row(id, plaintext, enc_bytes, key_id, fmt)
                .await
            {
                out.push(v);
            }
        }
        Ok(out)
    }

    // -- Readiness breakdown ----------------------------------------------

    pub async fn get_readiness_exec_data(&self, wf_id: Uuid) -> Result<ReadinessExecData> {
        let row = sqlx::query(
            "SELECT (COUNT(*) FILTER (WHERE status = 'completed'))::float / NULLIF(COUNT(*), 0) AS success_rate, \
                    COUNT(*)::bigint AS total_count \
             FROM workflow_executions \
             WHERE workflow_id = $1 AND started_at > NOW() - interval '30 days' \
               AND NOT (status = 'failed' AND acknowledged_at IS NOT NULL)",
        )
        .bind(wf_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(ReadinessExecData {
            success_rate: row.try_get::<Option<_>, _>("success_rate")?,
            total_count: row.try_get::<Option<_>, _>("total_count")?.unwrap_or(0),
        })
    }

    pub async fn get_max_execution_started_at(&self, wf_id: Uuid) -> Result<Option<DateTime<Utc>>> {
        let ts: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT MAX(started_at) FROM workflow_executions WHERE workflow_id = $1",
        )
        .bind(wf_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(ts)
    }

    pub async fn count_expiring_secrets(&self, user_id: Uuid) -> Result<i64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM secrets \
             WHERE created_by = $1 AND expires_at IS NOT NULL AND expires_at < NOW() + interval '7 days'",
        )
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(count)
    }

    pub async fn count_active_schedules_for_user(&self, user_id: Uuid) -> Result<i64> {
        // See note on `count_active_schedules` — column is `is_enabled`.
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM workflow_schedules WHERE user_id = $1 AND is_enabled = true",
        )
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(count)
    }

    pub async fn count_active_webhooks_for_user(&self, user_id: Uuid) -> Result<i64> {
        // webhook_triggers column is `enabled` (per migration
        // 001_initial_schema.sql line 153, table renamed via
        // 015_rename_tables.sql but column kept its name). Pre-fix
        // this query referenced `is_active` which doesn't exist;
        // get_system_health silently reported 0 active webhooks.
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM webhook_triggers WHERE user_id = $1 AND enabled = true",
        )
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(count)
    }

    pub async fn count_stale_running_executions(&self, user_id: Uuid) -> Result<i64> {
        // RFC 0005 S3: self-scope (workflow_executions backstop).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM workflow_executions \
             WHERE user_id = $1 AND status = 'running' AND started_at < NOW() - interval '60 minutes'",
        )
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(count)
    }

    pub async fn count_unacknowledged_alerts(&self, user_id: Uuid) -> Result<i64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM workflow_alerts \
             WHERE user_id = $1 AND acknowledged = false",
        )
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(count)
    }

    // ── analytics.rs MCP-handler support ───────────────────────────────────

    /// Count recent auth-failure executions for a workflow (last N days).
    /// Returns `(count, last_failure_text)` so the caller can surface a
    /// human-readable timestamp. Filters on common error-message patterns
    /// indicating a vault path / secret-grant misconfiguration.
    pub async fn count_recent_auth_failures(
        &self,
        workflow_id: Uuid,
        days: i32,
    ) -> Result<Option<(i64, String)>> {
        let row: Option<(i64, String)> = sqlx::query_as(
            "SELECT COUNT(*)::bigint, \
                    MAX(started_at)::text AS last_failure \
             FROM workflow_executions \
             WHERE workflow_id = $1 \
               AND status = 'failed' \
               AND started_at > NOW() - make_interval(days => $2::int) \
               AND (error_message ILIKE '%unauthorized%' \
                    OR error_message ILIKE '%access denied%' \
                    OR error_message ILIKE '%access-denied%')",
        )
        .bind(workflow_id)
        .bind(days)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row)
    }

    /// Write back the computed readiness_score AND its timestamp atomically.
    ///
    /// MCP-1211 (2026-05-18): pre-fix this was two separate UPDATE statements
    /// — one for the score, one for `readiness_scored_at = NOW()`. A
    /// transient DB error (lock contention, connection drop, restart between
    /// the two calls) could leave the row with `readiness_score` set but
    /// `readiness_scored_at` NULL, which `classify_readiness_state` then had
    /// to paper over by treating the row as "unscored" even though a score
    /// was present. The two-statement pattern was originally defensive
    /// scaffolding for the window when migration 20260326000001 was
    /// rolling out (the `readiness_scored_at` column didn't exist yet); the
    /// migration is long-since applied. Collapse to one atomic UPDATE.
    pub async fn set_workflow_readiness_score(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
        score: i32,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE workflows \
             SET readiness_score = $1, readiness_scored_at = NOW() \
             WHERE id = $2 AND user_id = $3",
        )
        .bind(score)
        .bind(workflow_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// List readiness scores for a user with optional filters: explicit
    /// workflow IDs, max score threshold, and include-archived flag.
    /// Capped at 50 rows; the handler doesn't currently expose limit
    /// configurability.
    pub async fn list_readiness_scores(
        &self,
        user_id: Uuid,
        filter_ids: Option<&[Uuid]>,
        max_score: Option<i32>,
        include_archived: bool,
    ) -> Result<Vec<ReadinessScoreRow>> {
        let rows = sqlx::query(
            "SELECT id, name, readiness_score, readiness_scored_at, \
                   CASE WHEN description IS NOT NULL AND description != '' THEN true ELSE false END AS has_description, \
                   CASE WHEN capabilities IS NOT NULL AND array_length(capabilities, 1) > 0 THEN true ELSE false END AS has_capabilities, \
                   updated_at \
             FROM workflows \
             WHERE user_id = $1 \
               AND ($2::uuid[] IS NULL OR id = ANY($2::uuid[])) \
               AND ($3::int IS NULL OR COALESCE(readiness_score, 0) <= $3) \
               AND ($4 OR status != 'archived') \
             ORDER BY COALESCE(readiness_score, 0) ASC \
             LIMIT 50",
        )
        .bind(user_id)
        .bind(filter_ids)
        .bind(max_score)
        .bind(include_archived)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(|r| -> Result<ReadinessScoreRow> {
                Ok(ReadinessScoreRow {
                    id: r.try_get::<Option<_>, _>("id")?.unwrap_or_default(),
                    name: r.try_get::<Option<_>, _>("name")?.unwrap_or_default(),
                    readiness_score: r.try_get::<Option<_>, _>("readiness_score")?,
                    readiness_scored_at: r.try_get::<Option<_>, _>("readiness_scored_at")?,
                    has_description: r
                        .try_get::<Option<_>, _>("has_description")?
                        .unwrap_or(false),
                    has_capabilities: r
                        .try_get::<Option<_>, _>("has_capabilities")?
                        .unwrap_or(false),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    // ── alerts.rs MCP-handler support ──────────────────────────────────────

    /// List alerts for a user filtered by `acknowledged`.
    ///
    /// N-L (2026-05-06): the workflow name is sourced from the
    /// snapshot column populated at INSERT time (
    /// migration `20260506120000_alerts_workflow_name_snapshot.sql`),
    /// falling back to the live workflow row, then to "unknown" if
    /// both are gone. The snapshot path means alerts that reference
    /// a since-deleted workflow still surface their original name.
    pub async fn list_alerts_for_user(
        &self,
        user_id: Uuid,
        acknowledged: bool,
        limit: i32,
    ) -> Result<Vec<WorkflowAlertRow>> {
        // MCP-40 (2026-05-07): LEFT JOIN workflow_executions so each
        // alert row carries an `execution_archived` flag — true when
        // the FK target has been auto-archived. The flag is computed
        // as `we.id IS NULL` (the LEFT JOIN couldn't find a live
        // workflow_executions row). Single-query — no extra round-trip.
        let rows = sqlx::query(
            "SELECT a.id, a.workflow_id, a.execution_id, a.alert_type, a.message, a.created_at, \
                    a.occurrence_count, a.last_occurred_at, \
                    COALESCE(a.workflow_name, w.name, 'unknown') AS workflow_name, \
                    (we.id IS NULL) AS execution_archived \
             FROM workflow_alerts a \
             LEFT JOIN workflows w ON w.id = a.workflow_id \
             LEFT JOIN workflow_executions we ON we.id = a.execution_id \
             WHERE a.user_id = $1 AND a.acknowledged = $2 \
             ORDER BY a.last_occurred_at DESC LIMIT $3",
        )
        .bind(user_id)
        .bind(acknowledged)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(|r| -> Result<WorkflowAlertRow> {
                let created_at: chrono::DateTime<chrono::Utc> =
                    r.try_get::<Option<_>, _>("created_at")?.unwrap_or_default();
                Ok(WorkflowAlertRow {
                    id: r.try_get::<Option<_>, _>("id")?.unwrap_or_default(),
                    workflow_id: r
                        .try_get::<Option<_>, _>("workflow_id")?
                        .unwrap_or_default(),
                    execution_id: r
                        .try_get::<Option<_>, _>("execution_id")?
                        .unwrap_or_default(),
                    alert_type: r.try_get::<Option<_>, _>("alert_type")?.unwrap_or_default(),
                    message: r.try_get::<Option<_>, _>("message")?.unwrap_or_default(),
                    created_at,
                    workflow_name: r
                        .try_get::<Option<_>, _>("workflow_name")?
                        .unwrap_or_default(),
                    occurrence_count: r.try_get::<Option<_>, _>("occurrence_count")?.unwrap_or(1),
                    last_occurred_at: r
                        .try_get::<Option<_>, _>("last_occurred_at")?
                        .unwrap_or(created_at),
                    execution_archived: r
                        .try_get::<Option<_>, _>("execution_archived")?
                        .unwrap_or(false),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Mark a single alert acknowledged (scoped to user).
    ///
    /// Returns an [`AckOutcome`] so the caller can distinguish fresh
    /// acks from no-op repeat acks. Single-transaction (`SELECT FOR
    /// UPDATE` then `UPDATE`) so the read+write is atomic — no race
    /// where two concurrent acks both observe `false` and both
    /// claim "fresh."
    pub async fn acknowledge_alert(&self, alert_id: Uuid, user_id: Uuid) -> Result<AckOutcome> {
        let mut tx = self.db_pool.begin().await?;
        let prev: Option<bool> = sqlx::query_scalar(
            "SELECT acknowledged FROM workflow_alerts \
             WHERE id = $1 AND user_id = $2 FOR UPDATE",
        )
        .bind(alert_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        match prev {
            None => {
                // Roll back the unused tx — no row to update.
                tx.rollback().await?;
                Ok(AckOutcome::NotFound)
            }
            Some(true) => {
                // Already acknowledged; commit the empty tx (no UPDATE
                // issued) so we release the row lock cleanly.
                tx.commit().await?;
                Ok(AckOutcome::AlreadyAcknowledged)
            }
            Some(false) => {
                sqlx::query(
                    "UPDATE workflow_alerts SET acknowledged = true \
                     WHERE id = $1 AND user_id = $2",
                )
                .bind(alert_id)
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(AckOutcome::Acknowledged)
            }
        }
    }

    /// Mark all unacknowledged alerts for a user as acknowledged.
    pub async fn acknowledge_all_alerts(&self, user_id: Uuid) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE workflow_alerts SET acknowledged = true WHERE user_id = $1 AND acknowledged = false",
        )
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Recent alerts within a window of `hours`, joined with workflow name.
    /// Cap at 20 — this is a summary view.
    pub async fn list_recent_alerts_summary(
        &self,
        user_id: Uuid,
        hours: i32,
    ) -> Result<Vec<RecentAlertSummaryRow>> {
        let rows = sqlx::query(
            "SELECT w.name AS workflow_name, wa.message, wa.occurrence_count, wa.last_occurred_at, wa.acknowledged \
             FROM workflow_alerts wa \
             JOIN workflows w ON w.id = wa.workflow_id \
             WHERE wa.user_id = $1 AND wa.created_at > NOW() - make_interval(hours => $2::int) \
             ORDER BY wa.last_occurred_at DESC LIMIT 20",
        )
        .bind(user_id)
        .bind(hours)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| RecentAlertSummaryRow {
                workflow_name: r.get("workflow_name"),
                message: r.get("message"),
                occurrence_count: r.get("occurrence_count"),
                last_occurred_at: r.get("last_occurred_at"),
                acknowledged: r.get("acknowledged"),
            })
            .collect())
    }

    /// Delete acknowledged alerts older than `older_than_days`. CTE shape
    /// returns the count of deleted rows in a single round-trip.
    pub async fn cleanup_old_alerts(&self, user_id: Uuid, older_than_days: i32) -> Result<i64> {
        // MCP-1062 (2026-05-15): refuse non-positive `older_than_days`.
        // Sibling caller-supplied-negative class as MCP-997 (registry/
        // secrets/auth/webhooks cleanup). `make_interval(days => -N)`
        // flips `NOW() - INTERVAL` into `NOW() + INTERVAL`, which
        // matches every row in the past → silent total purge of all
        // acknowledged alerts for the user. The MCP handler already
        // validates [7, 365] but defense-in-depth at the function
        // boundary covers future callers that bypass the handler.
        if older_than_days <= 0 {
            tracing::warn!(
                target: "talos_audit",
                older_than_days,
                "alerts cleanup refused: older_than_days must be positive (would purge all acknowledged alerts)"
            );
            return Ok(0);
        }
        let count: i64 = sqlx::query_scalar(
            "WITH deleted AS ( \
                DELETE FROM workflow_alerts \
                WHERE user_id = $1 AND acknowledged = true \
                  AND created_at < NOW() - make_interval(days => $2::int) \
                RETURNING 1 \
             ) SELECT COUNT(*)::bigint FROM deleted",
        )
        .bind(user_id)
        .bind(older_than_days)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(count)
    }

    pub async fn get_recent_exec_error_rate(&self, user_id: Uuid) -> Result<(i64, i64)> {
        // RFC 0005 S3: self-scope (workflow_executions backstop).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let row = sqlx::query(
            "SELECT COUNT(*)::bigint AS total, \
                    COUNT(*) FILTER (WHERE status = 'failed')::bigint AS failed \
             FROM workflow_executions \
             WHERE user_id = $1 AND started_at > NOW() - interval '1 hour'",
        )
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        let total: i64 = row.try_get::<Option<_>, _>("total")?.unwrap_or(0);
        let failed: i64 = row.try_get::<Option<_>, _>("failed")?.unwrap_or(0);
        Ok((total, failed))
    }

    pub async fn get_storage_bytes(&self, user_id: Uuid) -> Result<(i64, i64)> {
        // Phase 5: both buckets read from the unified `modules` table.
        // `modules_bytes` — user-owned sandbox/extracted rows (legacy
        // equivalent of `wasm_modules.user_id = $1`).
        // `templates_bytes` — catalog + user-owned compiled rows with
        // bytes populated (legacy equivalent of
        // `node_templates.precompiled_wasm` where user_id=$1 OR IS NULL).
        let modules_bytes: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(size_bytes)::bigint, 0) FROM modules \
             WHERE user_id = $1 AND wasm_bytes IS NOT NULL",
        )
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        let templates_bytes: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(octet_length(wasm_bytes))::bigint, 0) \
             FROM modules \
             WHERE (user_id = $1 OR user_id IS NULL) \
               AND wasm_bytes IS NOT NULL",
        )
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok((modules_bytes, templates_bytes))
    }

    // -- Waterfall --------------------------------------------------------

    pub async fn get_execution_waterfall_data(
        &self,
        exec_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<WaterfallExecRow>> {
        let row = sqlx::query(
            "SELECT status, started_at, completed_at, output_data, workflow_id \
             FROM workflow_executions WHERE id = $1 AND user_id = $2",
        )
        .bind(exec_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        row.map(|r| -> Result<WaterfallExecRow> {
            Ok(WaterfallExecRow {
                status: r.get("status"),
                started_at: r.try_get::<Option<_>, _>("started_at")?,
                completed_at: r.try_get::<Option<_>, _>("completed_at")?,
                output_data: r.try_get::<Option<_>, _>("output_data")?,
                workflow_id: r.get("workflow_id"),
            })
        })
        .transpose()
    }

    pub async fn list_execution_events_waterfall(
        &self,
        exec_id: Uuid,
        limit: i64,
    ) -> Result<Vec<WaterfallEventRow>> {
        let rows = sqlx::query(
            "SELECT event_type, node_id, created_at \
             FROM execution_events WHERE execution_id = $1 ORDER BY created_at ASC LIMIT $2",
        )
        .bind(exec_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<WaterfallEventRow> {
                Ok(WaterfallEventRow {
                    event_type: r.get("event_type"),
                    node_id: r.try_get::<Option<_>, _>("node_id")?,
                    created_at: r.get("created_at"),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    // -- Performance metrics ----------------------------------------------

    pub async fn get_performance_metrics(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
        days: i32,
    ) -> Result<PerformanceMetricsRow> {
        // status = 'completed' filter so avg_ms / p50 / p95 / p99
        // describe SUCCESSFUL runs only — same predicate as
        // get_extreme_executions (which feeds fastest/slowest).
        // Without this, the response would have avg_ms BELOW the
        // reported fastest_execution (the prod bug that surfaced
        // this fix: avg_ms=19606 < fastest=23283).
        let row = sqlx::query(
            "SELECT COUNT(*)::bigint AS total, \
                    PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000) AS p50_ms, \
                    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000) AS p95_ms, \
                    PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000) AS p99_ms, \
                    AVG(EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000)::float8 AS avg_ms \
             FROM workflow_executions \
             WHERE workflow_id = $1 AND user_id = $2 \
               AND status = 'completed' AND completed_at IS NOT NULL \
               AND started_at > NOW() - make_interval(days => $3::int)",
        )
        .bind(wf_id)
        .bind(user_id)
        .bind(days)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(PerformanceMetricsRow {
            total: row.try_get::<Option<_>, _>("total")?.unwrap_or(0),
            p50_ms: row.try_get::<Option<_>, _>("p50_ms")?,
            p95_ms: row.try_get::<Option<_>, _>("p95_ms")?,
            p99_ms: row.try_get::<Option<_>, _>("p99_ms")?,
            avg_ms: row.try_get::<Option<_>, _>("avg_ms")?,
        })
    }

    pub async fn get_performance_trend(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<(Option<f64>, Option<f64>)> {
        // Trend filter on status = 'completed' too — failures
        // shouldn't make the trend look better/worse than reality
        // for a "is this workflow getting faster or slower"
        // capacity-planning question.
        let row = sqlx::query(
            "SELECT \
               AVG(EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000) FILTER (WHERE started_at > NOW() - INTERVAL '24 hours' AND status = 'completed') AS recent_avg_ms, \
               AVG(EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000) FILTER (WHERE started_at > NOW() - INTERVAL '48 hours' AND started_at <= NOW() - INTERVAL '24 hours' AND status = 'completed') AS previous_avg_ms \
             FROM workflow_executions \
             WHERE workflow_id = $1 AND user_id = $2 AND completed_at IS NOT NULL \
               AND started_at > NOW() - INTERVAL '48 hours'",
        )
        .bind(wf_id)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        let recent: Option<f64> = row.try_get::<Option<_>, _>("recent_avg_ms")?;
        let previous: Option<f64> = row.try_get::<Option<_>, _>("previous_avg_ms")?;
        Ok((recent, previous))
    }

    /// Count completed executions whose duration exceeded the target
    /// in the given window. Used by `get_workflow_sla_report` —
    /// pre-fix this surface hardcoded `violations_count: 0` even when
    /// p95/p99 latencies were 100x the target, making the metric
    /// useless. Same "no dedicated repo method" pattern as the
    /// extreme-executions feature gap.
    pub async fn count_sla_duration_violations(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
        days: i64,
        target_max_duration_ms: f64,
    ) -> Result<i64> {
        let interval = format!("{} days", days);
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM workflow_executions \
             WHERE workflow_id = $1 AND user_id = $2 \
               AND status = 'completed' \
               AND completed_at IS NOT NULL \
               AND started_at > NOW() - $3::interval \
               AND EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000 > $4",
        )
        .bind(wf_id)
        .bind(user_id)
        .bind(&interval)
        .bind(target_max_duration_ms)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(count)
    }

    /// Slowest + fastest completed executions for a workflow over the
    /// given period. Returns `None` for either field when no completed
    /// executions exist in the window. Used by
    /// `get_workflow_performance_report` — pre-fix this surface
    /// hardcoded `None` for both fields with a "not available via repo"
    /// comment, which made the response misleading (the docstring
    /// promised the fields, the handler always returned null).
    pub async fn get_extreme_executions(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
        days: i64,
    ) -> Result<(Option<ExtremeExecution>, Option<ExtremeExecution>)> {
        // `EXTRACT(EPOCH FROM (interval))` returns `numeric` in Postgres,
        // and sqlx can't coerce `numeric` directly into `f64` — try_get
        // fails silently and the fallback is 0.0, which made every
        // extreme-execution row report `duration_ms: 0`. Explicit
        // `::float8` cast matches the M-F fuel-report fix
        // (talos-analytics-repository::lib.rs ~line 3138).
        let interval = format!("{} days", days);
        let rows = sqlx::query(
            "(SELECT id, started_at, \
                     (EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000)::float8 AS duration_ms, \
                     'slowest' AS bucket \
              FROM workflow_executions \
              WHERE workflow_id = $1 AND user_id = $2 \
                AND status = 'completed' \
                AND started_at > NOW() - $3::interval \
                AND completed_at IS NOT NULL \
              ORDER BY (completed_at - started_at) DESC LIMIT 1) \
             UNION ALL \
             (SELECT id, started_at, \
                     (EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000)::float8 AS duration_ms, \
                     'fastest' AS bucket \
              FROM workflow_executions \
              WHERE workflow_id = $1 AND user_id = $2 \
                AND status = 'completed' \
                AND started_at > NOW() - $3::interval \
                AND completed_at IS NOT NULL \
              ORDER BY (completed_at - started_at) ASC LIMIT 1)",
        )
        .bind(wf_id)
        .bind(user_id)
        .bind(&interval)
        .fetch_all(&self.db_pool)
        .await?;
        let mut slowest: Option<ExtremeExecution> = None;
        let mut fastest: Option<ExtremeExecution> = None;
        for r in &rows {
            let bucket: String = r.try_get::<Option<_>, _>("bucket")?.unwrap_or_default();
            let item = ExtremeExecution {
                id: r.get("id"),
                started_at: r.try_get::<Option<_>, _>("started_at")?.unwrap_or_default(),
                duration_ms: r.try_get::<Option<_>, _>("duration_ms")?.unwrap_or(0.0),
            };
            match bucket.as_str() {
                "slowest" => slowest = Some(item),
                "fastest" => fastest = Some(item),
                _ => {}
            }
        }
        Ok((slowest, fastest))
    }

    // -- Daily digest -----------------------------------------------------

    pub async fn get_daily_exec_summary(&self, user_id: Uuid) -> Result<DailyExecSummary> {
        // RFC 0005 S3: self-scope (workflow_executions backstop).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let row = sqlx::query(
            "SELECT COUNT(*)::bigint AS total, \
                    COUNT(*) FILTER (WHERE status = 'completed')::bigint AS succeeded, \
                    COUNT(*) FILTER (WHERE status = 'failed')::bigint AS failed, \
                    COUNT(*) FILTER (WHERE status = 'cancelled')::bigint AS cancelled, \
                    COUNT(*) FILTER (WHERE status = 'running')::bigint AS running \
             FROM workflow_executions WHERE user_id = $1 AND started_at > NOW() - INTERVAL '24 hours'",
        )
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(DailyExecSummary {
            total: row.try_get::<Option<_>, _>("total")?.unwrap_or(0),
            succeeded: row.try_get::<Option<_>, _>("succeeded")?.unwrap_or(0),
            failed: row.try_get::<Option<_>, _>("failed")?.unwrap_or(0),
            cancelled: row.try_get::<Option<_>, _>("cancelled")?.unwrap_or(0),
            running: row.try_get::<Option<_>, _>("running")?.unwrap_or(0),
        })
    }

    pub async fn get_top_active_workflows_24h(&self, user_id: Uuid) -> Result<Vec<TopWorkflowRow>> {
        // RFC 0005 S3: self-scope (workflow_executions + workflows backstop).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let rows = sqlx::query(
            "SELECT w.id, w.name, COUNT(*)::bigint AS exec_count \
             FROM workflow_executions we \
             JOIN workflows w ON we.workflow_id = w.id \
             WHERE we.user_id = $1 AND we.started_at > NOW() - INTERVAL '24 hours' \
             GROUP BY w.id, w.name \
             ORDER BY exec_count DESC LIMIT 3",
        )
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.into_iter()
            .map(|r| -> Result<TopWorkflowRow> {
                Ok(TopWorkflowRow {
                    id: r.get("id"),
                    name: r.get("name"),
                    exec_count: r.try_get::<Option<_>, _>("exec_count")?.unwrap_or(0),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    pub async fn get_top_failing_workflows_24h(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<FailingWorkflowRow>> {
        let rows = sqlx::query(
            "SELECT w.id, w.name, \
                    COUNT(*) FILTER (WHERE we.status = 'failed')::bigint AS fail_count, \
                    COUNT(*)::bigint AS total_count \
             FROM workflow_executions we \
             JOIN workflows w ON we.workflow_id = w.id \
             WHERE we.user_id = $1 AND we.started_at > NOW() - INTERVAL '24 hours' \
             GROUP BY w.id, w.name \
             HAVING COUNT(*) FILTER (WHERE we.status = 'failed') > 0 \
             ORDER BY fail_count DESC LIMIT 3",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<FailingWorkflowRow> {
                Ok(FailingWorkflowRow {
                    id: r.get("id"),
                    name: r.get("name"),
                    fail_count: r.try_get::<Option<_>, _>("fail_count")?.unwrap_or(0),
                    total_count: r.try_get::<Option<_>, _>("total_count")?.unwrap_or(0),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    pub async fn get_upcoming_schedules_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<ScheduleUpcomingRow>> {
        // workflow_schedules column is `is_enabled`. Pre-fix this query
        // referenced `enabled` (no such column on this table — webhook_triggers
        // uses `enabled`, schedules use `is_enabled`); Postgres errored at
        // every call, the daily-digest handler's unwrap_or_default()
        // swallowed it, and "Upcoming schedules (next 24h)" silently showed
        // zero entries.
        let rows = sqlx::query(
            "SELECT ws.id, ws.cron_expression, ws.timezone, w.name AS workflow_name, w.id AS workflow_id \
             FROM workflow_schedules ws \
             JOIN workflows w ON ws.workflow_id = w.id \
             WHERE w.user_id = $1 AND ws.is_enabled = true \
             ORDER BY ws.created_at DESC LIMIT 10",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<ScheduleUpcomingRow> {
                Ok(ScheduleUpcomingRow {
                    id: r.get("id"),
                    cron_expression: r.get("cron_expression"),
                    timezone: r.try_get::<Option<_>, _>("timezone")?,
                    workflow_name: r.get("workflow_name"),
                    workflow_id: r.get("workflow_id"),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    // -- Retry config data ------------------------------------------------

    pub async fn get_retry_config_executions(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<(String, Option<String>)>> {
        let rows = sqlx::query(
            "SELECT status, error_message FROM workflow_executions \
             WHERE workflow_id = $1 AND user_id = $2 \
               AND started_at > NOW() - INTERVAL '30 days' \
             ORDER BY started_at DESC LIMIT 200",
        )
        .bind(wf_id)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<(String, Option<String>)> {
                let status: String = r.get("status");
                let error_message: Option<String> = r.try_get::<Option<_>, _>("error_message")?;
                Ok((status, error_message))
            })
            .collect::<Result<Vec<_>>>()
    }

    // -- Risk assessment data ---------------------------------------------

    /// Batched 7-day exec-count summary keyed by `workflow_id`. Used by
    /// `handle_get_workflow_risk_assessment` to flag sub-workflows with
    /// high failure rates without paying a round-trip per node.
    ///
    /// Returns a sparse map: workflows with no executions in the window
    /// (or that don't belong to `user_id`) simply don't appear. Callers
    /// reading "total executions" should use `.get(id).copied()
    /// .unwrap_or((0, 0))` and treat absence as zero.
    ///
    /// Security: scoped by `user_id` (defense in depth — pre-batch
    /// version ran without user filtering, so a user who managed to
    /// embed another user's workflow_id in their graph could indirectly
    /// learn execution-count statistics about it. The structural
    /// sub-workflow validator already rejects cross-tenant references
    /// at create time; this closes the lookup-side gap if a stale
    /// reference predates that validator).
    pub async fn get_risk_exec_counts_for_ids(
        &self,
        wf_ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<std::collections::HashMap<Uuid, (i64, i64)>> {
        if wf_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let rows: Vec<(Uuid, i64, i64)> = sqlx::query_as(
            "SELECT workflow_id, \
                    COUNT(*) FILTER (WHERE status = 'failed')::bigint AS failed, \
                    COUNT(*)::bigint AS total \
             FROM workflow_executions \
             WHERE workflow_id = ANY($1) AND user_id = $2 \
               AND started_at > NOW() - INTERVAL '7 days' \
             GROUP BY workflow_id",
        )
        .bind(wf_ids)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows.into_iter().map(|(id, f, t)| (id, (f, t))).collect())
    }

    pub async fn get_risk_module_categories(
        &self,
        module_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, String, Option<String>)>> {
        // Phase 5.1: canonical id match on modules. Category prefers
        // persisted Phase 1.5 column, falls back to kind so sandbox/extracted
        // rows still surface sensibly.
        let rows = sqlx::query(
            "SELECT id, name, COALESCE(category, kind) AS category FROM modules \
             WHERE id = ANY($1) \
             ORDER BY id",
        )
        .bind(module_ids)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<(Uuid, String, Option<String>)> {
                let id: Uuid = r.get("id");
                let name: String = r.get("name");
                let category: Option<String> = r.try_get::<Option<_>, _>("category")?;
                Ok((id, name, category))
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Returns (id, name) for any module_id that is a user-authored sandbox
    /// (compiled via compile_custom_sandbox). Used by
    /// get_workflow_risk_assessment to flag sandbox nodes as higher risk.
    ///
    /// Phase 5: filters the unified `modules` table by `kind='sandbox'`
    /// (the Phase-3.2 classification for user-compiled sandboxes), with
    /// 3-shape id matching.
    pub async fn get_risk_sandbox_modules(
        &self,
        module_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, String)>> {
        let rows = sqlx::query(
            "SELECT id, name FROM modules \
             WHERE kind = 'sandbox' AND id = ANY($1) \
             ORDER BY id",
        )
        .bind(module_ids)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let id: Uuid = r.get("id");
                let name: String = r.get("name");
                (id, name)
            })
            .collect())
    }

    pub async fn get_risk_stale_templates(&self, module_ids: &[Uuid]) -> Result<Vec<Uuid>> {
        // Phase 5.1: reads the unified `modules` table by canonical id.
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM modules \
             WHERE id = ANY($1) \
               AND updated_at < NOW() - INTERVAL '90 days'",
        )
        .bind(module_ids)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(ids)
    }

    pub async fn get_risk_expiring_secrets(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(String, DateTime<Utc>)>> {
        let rows = sqlx::query(
            "SELECT name, expires_at FROM secrets \
             WHERE created_by = $1 AND expires_at IS NOT NULL \
               AND expires_at < NOW() + INTERVAL '30 days' AND expires_at > NOW() \
             ORDER BY expires_at ASC LIMIT 10",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let name: String = r.get("name");
                let expires_at: DateTime<Utc> = r.get("expires_at");
                (name, expires_at)
            })
            .collect())
    }

    pub async fn get_risk_no_expiry_secrets(&self, user_id: Uuid) -> Result<Vec<String>> {
        let names: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT s.name FROM secrets s \
             WHERE s.created_by = $1 AND s.expires_at IS NULL \
             ORDER BY s.name LIMIT 20",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(names)
    }

    // -- Hygiene report ---------------------------------------------------

    pub async fn get_hygiene_report(&self, user_id: Uuid) -> Result<HygieneReport> {
        // P5 perf: the ~16 queries below are user_id-scoped and (with one
        // exception) data-independent. They were previously `.await`ed one
        // at a time — 80-300ms of serialized round-trips on managed
        // Postgres. `db_pool` is a `PgPool` (a cloneable shared handle), so
        // each future inside a `tokio::join!` acquires its OWN pooled
        // connection and they run concurrently. We batch in groups of ~6 to
        // stay well under the pool's max connections (~30).
        //
        // `tokio::join!` (NOT `try_join!`) is deliberate: every query below
        // collapses its own errors into a default (`.unwrap_or_default()` /
        // `.unwrap_or(0)`), so there is no `Result` to short-circuit on and
        // the swallow-into-default semantics are byte-for-byte preserved.
        //
        // The ONLY data dependency is `orphaned_secrets` (#12), which is
        // gated on `has_wildcard_module` (#11). #11 lives in Batch B, which
        // completes before #12 runs in Batch C — so the dependency is
        // honored while everything else parallelizes.

        // 1. Undescribed workflows
        let undescribed_fut = async {
            let rows: Vec<HygieneWorkflowRow> = sqlx::query(
                "SELECT id, name, readiness_score, NULL::text AS description, created_at \
             FROM workflows \
             WHERE user_id = $1 AND is_enabled = true \
               AND (status IS NULL OR status != 'archived') \
               AND workflow_type IN ('production', 'template') \
               AND (description IS NULL OR description = '') \
               AND (readiness_score IS NULL OR readiness_score >= 10) \
             ORDER BY readiness_score DESC NULLS LAST LIMIT 25",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|r| -> Result<HygieneWorkflowRow> {
                Ok(HygieneWorkflowRow {
                    id: r.get("id"),
                    name: r.get("name"),
                    readiness_score: r.try_get::<Option<_>, _>("readiness_score")?,
                    description: r.try_get::<Option<_>, _>("description")?,
                    created_at: r.get("created_at"),
                })
            })
            .collect::<Result<Vec<_>>>()?;
            Ok(rows)
        };

        // 2. Uncapabilized workflows
        let uncapabilized_fut = async {
            let rows: Vec<HygieneWorkflowRow> = sqlx::query(
                "SELECT id, name, readiness_score, description, created_at \
             FROM workflows \
             WHERE user_id = $1 AND is_enabled = true \
               AND (status IS NULL OR status != 'archived') \
               AND workflow_type IN ('production', 'template') \
               AND (capabilities IS NULL OR array_length(capabilities, 1) IS NULL) \
               AND (readiness_score IS NULL OR readiness_score >= 10) \
             ORDER BY readiness_score DESC NULLS LAST LIMIT 25",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|r| -> Result<HygieneWorkflowRow> {
                Ok(HygieneWorkflowRow {
                    id: r.get("id"),
                    name: r.get("name"),
                    readiness_score: r.try_get::<Option<_>, _>("readiness_score")?,
                    description: r.try_get::<Option<_>, _>("description")?,
                    created_at: r.get("created_at"),
                })
            })
            .collect::<Result<Vec<_>>>()?;
            Ok(rows)
        };

        // 3. Suppressed count (internal/test workflow types)
        let suppressed_count_fut = async {
            let v: i64 = sqlx::query_scalar(
                "SELECT COUNT(*)::bigint FROM workflows \
             WHERE user_id = $1 AND is_enabled = true \
               AND (status IS NULL OR status != 'archived') \
               AND workflow_type IN ('internal', 'test')",
            )
            .bind(user_id)
            .fetch_one(&self.db_pool)
            .await
            .unwrap_or(0);
            v
        };

        // 3b. Suppressed low-score count (drafts with readiness_score < 10 excluded from hygiene)
        let suppressed_low_score_count_fut = async {
            let v: i64 = sqlx::query_scalar(
                "SELECT COUNT(*)::bigint FROM workflows \
             WHERE user_id = $1 AND is_enabled = true \
               AND (status IS NULL OR status != 'archived') \
               AND workflow_type IN ('production', 'template') \
               AND readiness_score < 10",
            )
            .bind(user_id)
            .fetch_one(&self.db_pool)
            .await
            .unwrap_or(0);
            v
        };

        // 4. Unembedded count
        let unembedded_count_fut = async {
            let v: i64 = sqlx::query_scalar(
                "SELECT COUNT(*)::bigint FROM workflows WHERE user_id = $1 AND embedding IS NULL",
            )
            .bind(user_id)
            .fetch_one(&self.db_pool)
            .await
            .unwrap_or(0);
            v
        };

        // 5. Total workflow count
        let total_workflow_count_fut = async {
            let v: i64 =
                sqlx::query_scalar("SELECT COUNT(*)::bigint FROM workflows WHERE user_id = $1")
                    .bind(user_id)
                    .fetch_one(&self.db_pool)
                    .await
                    .unwrap_or(0);
            v
        };

        // Batch A — 6 independent count/list queries.
        let (
            undescribed,
            uncapabilized,
            suppressed_count,
            suppressed_low_score_count,
            unembedded_count,
            total_workflow_count,
        ): (
            anyhow::Result<Vec<HygieneWorkflowRow>>,
            anyhow::Result<Vec<HygieneWorkflowRow>>,
            i64,
            i64,
            i64,
            i64,
        ) = tokio::join!(
            undescribed_fut,
            uncapabilized_fut,
            suppressed_count_fut,
            suppressed_low_score_count_fut,
            unembedded_count_fut,
            total_workflow_count_fut,
        );
        let undescribed = undescribed?;
        let uncapabilized = uncapabilized?;

        // 6. Orphaned modules — Phase 4 prep: query the unified `modules`
        // table and treat a module as orphan when no workflow graph_json
        // mentions any of its three id shapes (canonical id, legacy
        // template id, legacy wasm-module id). The 3-shape LIKE check
        // matters during the transition window: a graph compiled before
        // Phase 3.2 stores `legacy_template_id`, while graphs created
        // after store the canonical id. Once Phase 4 graph rewrite runs,
        // every reference is canonical and the legacy-alias clauses
        // become structurally redundant — they remain here as a
        // belt-and-suspenders until the column drop in Phase 4 final.
        let orphaned_modules_fut = async {
            let rows: Vec<OrphanedModuleRow> = sqlx::query(
                "SELECT m.id, m.name, m.compiled_at, m.size_bytes \
             FROM modules m \
             WHERE m.user_id = $1 \
               AND m.compiled_at IS NOT NULL \
               AND NOT EXISTS ( \
                   SELECT 1 FROM workflows w \
                    WHERE w.user_id = $1 \
                      AND w.graph_json LIKE '%' || m.id::text || '%' \
               ) \
             ORDER BY m.compiled_at DESC LIMIT 25",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|r| -> Result<OrphanedModuleRow> {
                Ok(OrphanedModuleRow {
                    id: r.get("id"),
                    name: r.get("name"),
                    size_bytes: r.try_get::<Option<_>, _>("size_bytes")?,
                    compiled_at: r.get("compiled_at"),
                })
            })
            .collect::<Result<Vec<_>>>()?;
            Ok(rows)
        };

        // 7. Stale executions
        let stale_executions_fut = async {
            let rows: Vec<StaleExecutionRow> = sqlx::query(
                "SELECT we.id, we.workflow_id, w.name AS workflow_name, we.started_at, we.status \
             FROM workflow_executions we \
             JOIN workflows w ON w.id = we.workflow_id \
             WHERE we.user_id = $1 AND we.status IN ('running', 'queued', 'resuming') \
               AND we.started_at < NOW() - INTERVAL '2 hours' \
             ORDER BY we.started_at ASC LIMIT 25",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|r| StaleExecutionRow {
                id: r.get("id"),
                workflow_id: r.get("workflow_id"),
                workflow_name: r.get("workflow_name"),
                started_at: r.get("started_at"),
                status: r.get("status"),
            })
            .collect();
            rows
        };

        // 8. Dormant workflows
        let dormant_workflows_fut = async {
            let rows: Vec<DormantWorkflowRow> = sqlx::query(
                "SELECT w.id, w.name, w.created_at, MAX(we.started_at) AS last_execution \
             FROM workflows w \
             LEFT JOIN workflow_executions we ON we.workflow_id = w.id AND we.user_id = w.user_id \
             WHERE w.user_id = $1 AND w.is_enabled = true AND w.created_at < NOW() - INTERVAL '30 days' \
             GROUP BY w.id, w.name, w.created_at \
             HAVING MAX(we.started_at) IS NULL OR MAX(we.started_at) < NOW() - INTERVAL '30 days' \
             ORDER BY w.created_at ASC LIMIT 25",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|r| -> Result<DormantWorkflowRow> { Ok(DormantWorkflowRow {
                id: r.get("id"),
                name: r.get("name"),
                created_at: r.get("created_at"),
                last_execution: r.try_get::<Option<_>, _>("last_execution")?,
            }) })
            .collect::<Result<Vec<_>>>()?;
            Ok(rows)
        };

        // 9. Stale draft workflows.
        // M-I: project graph_json so fix_all can run the
        // substantive-draft predicate before recommending deletion.
        let stale_draft_workflows_fut = async {
            let rows: Vec<StaleDraftRow> = sqlx::query(
                "SELECT w.id, w.name, w.created_at, w.graph_json::text AS graph_json \
             FROM workflows w \
             WHERE w.user_id = $1 AND w.status = 'draft' \
               AND NOT EXISTS (SELECT 1 FROM workflow_executions we WHERE we.workflow_id = w.id) \
               AND w.created_at < NOW() - INTERVAL '7 days' \
             ORDER BY w.created_at ASC LIMIT 25",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|r| -> Result<StaleDraftRow> {
                Ok(StaleDraftRow {
                    id: r.get("id"),
                    name: r.get("name"),
                    created_at: r.get("created_at"),
                    graph_json: r.try_get::<Option<_>, _>("graph_json")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
            Ok(rows)
        };

        // 10. Idle actors
        //
        // An actor is "idle" only if it's truly unused — no recent executions
        // AND no actor_memory rows AND no workflows wired to it. Pre-fix the
        // query checked execution recency only, which mis-flagged
        // memory-holder personas (aegix-vps with 11 memories, aegix-vpp with
        // 10) and workflow-target actors as "should terminate" — a misleading
        // recommendation that would destroy the actor's memory if followed.
        //
        // The two NOT EXISTS guards are read-only existence checks against
        // actor_memory + workflows; no decryption happens and the lint rule
        // (raw INSERT/UPDATE/DELETE on actor_memory) does not apply.
        let idle_actors_fut = async {
            let rows: Vec<IdleActorRow> = sqlx::query(
                "SELECT a.id, a.name, a.status, MAX(e.started_at) AS last_active, COUNT(DISTINCT e.id) AS total_executions \
             FROM actors a \
             LEFT JOIN workflow_executions e ON e.actor_id = a.id \
             WHERE a.user_id = $1 AND a.status = 'active' \
               AND NOT EXISTS (SELECT 1 FROM actor_memory am WHERE am.actor_id = a.id) \
               AND NOT EXISTS (SELECT 1 FROM workflows w WHERE w.actor_id = a.id AND w.user_id = $1) \
             GROUP BY a.id, a.name, a.status \
             HAVING MAX(e.started_at) < now() - interval '30 days' \
                OR (MAX(e.started_at) IS NULL AND a.created_at < now() - interval '7 days') \
             ORDER BY last_active ASC NULLS FIRST",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|r| -> Result<IdleActorRow> { Ok(IdleActorRow {
                id: r.get("id"),
                name: r.get("name"),
                status: r.get("status"),
                last_active: r.try_get::<Option<_>, _>("last_active")?,
                total_executions: r.try_get::<Option<_>, _>("total_executions")?.unwrap_or(0),
            }) })
            .collect::<Result<Vec<_>>>()?;
            Ok(rows)
        };

        // 11. Wildcard module check + attribution
        // Phase 5: single SELECT on the unified `modules` table.
        let wildcard_module_names_fut = async {
            let names: Vec<String> = sqlx::query(
                "SELECT DISTINCT name FROM modules \
             WHERE user_id = $1 AND '*' = ANY(allowed_secrets) \
             ORDER BY name",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await
            .unwrap_or_default()
            .iter()
            .filter_map(|r| r.try_get::<String, _>("name").ok())
            .collect();
            names
        };

        // Batch B — 6 independent list queries (orphaned modules, stale
        // executions, dormant/draft workflows, idle actors, wildcard
        // modules). #11 (wildcard) finishes here so its result gates #12
        // (orphaned_secrets) in Batch C below.
        let (
            orphaned_modules,
            stale_executions,
            dormant_workflows,
            stale_draft_workflows,
            idle_actors,
            wildcard_module_names,
        ): (
            anyhow::Result<Vec<OrphanedModuleRow>>,
            Vec<StaleExecutionRow>,
            anyhow::Result<Vec<DormantWorkflowRow>>,
            anyhow::Result<Vec<StaleDraftRow>>,
            anyhow::Result<Vec<IdleActorRow>>,
            Vec<String>,
        ) = tokio::join!(
            orphaned_modules_fut,
            stale_executions_fut,
            dormant_workflows_fut,
            stale_draft_workflows_fut,
            idle_actors_fut,
            wildcard_module_names_fut,
        );
        let orphaned_modules = orphaned_modules?;
        let dormant_workflows = dormant_workflows?;
        let stale_draft_workflows = stale_draft_workflows?;
        let idle_actors = idle_actors?;
        let has_wildcard_module = !wildcard_module_names.is_empty();

        // 12. Orphaned secrets (only when no wildcard module).
        //
        // A secret is orphaned when NO grant in `modules.allowed_secrets`
        // (Phase 5: single unified source) can resolve its key_path. Grants are
        // glob/prefix-aware (see worker/src/host_impl.rs::vault_path_allowed):
        //   - "*"            → matches anything
        //   - exact "a/b"    → matches key_path == "a/b"
        //   - prefix "a/b"   → matches any key_path starting with "a/b/"
        //   - glob "a/b/*"   → equivalent prefix form
        //
        // Previous bug: compared s.name (human label) against allowed_secrets
        // (which store key_paths) AND used strict equality, so any prefix grant
        // like "oauth/gmail/*" produced false positives on every gmail token.
        //
        // Correct implementation in pure SQL is ugly; instead we fetch all of
        // the user's secrets + the union of their grant entries, then filter
        // in Rust using a matcher that mirrors the host-side logic exactly.
        let orphaned_secrets_fut = async {
            Ok(if !has_wildcard_module {
                // The secrets list and the grants union are independent of
                // each other — run them concurrently (still gated on
                // !has_wildcard_module so behavior is unchanged).
                let secrets_rows_fut = sqlx::query(
                    "SELECT s.name, s.key_path, s.namespace, s.created_at, s.expires_at \
                 FROM secrets s \
                 WHERE s.created_by = $1 \
                 ORDER BY s.created_at ASC LIMIT 200",
                )
                .bind(user_id)
                .fetch_all(&self.db_pool);

                // Phase 5: union of grant entries from the unified `modules`
                // table — every row lives exactly once, so a single SELECT
                // DISTINCT replaces the old node_templates ∪ wasm_modules UNION.
                let grants_fut = sqlx::query_scalar::<_, String>(
                    "SELECT DISTINCT unnest(allowed_secrets) AS g \
                 FROM modules WHERE user_id = $1",
                )
                .bind(user_id)
                .fetch_all(&self.db_pool);

                let (secrets_rows_res, grants_res) = tokio::join!(secrets_rows_fut, grants_fut);
                let secrets_rows = secrets_rows_res.unwrap_or_default();
                let grants: Vec<String> = grants_res.unwrap_or_default();

                secrets_rows
                    .into_iter()
                    .map(|r| -> anyhow::Result<Option<OrphanedSecretRow>> {
                        let key_path: String = r.get("key_path");
                        // Suppress controller-internal paths (LLM provider keys, OAuth
                        // refresh tokens) — these are by-design absent from every
                        // module's allowed_secrets grant. Flagging them as orphan
                        // would suggest an operator delete them and silently break
                        // the LLM cache or the next OAuth refresh cycle.
                        if talos_workflow_job_protocol::is_controller_internal_vault_path(&key_path)
                        {
                            return Ok(None);
                        }
                        if secret_path_in_any_grant(&grants, &key_path) {
                            Ok(None)
                        } else {
                            Ok(Some(OrphanedSecretRow {
                                name: r.get("name"),
                                key_path,
                                namespace: r.try_get::<Option<_>, _>("namespace")?,
                                created_at: r.get("created_at"),
                                expires_at: r.try_get::<Option<_>, _>("expires_at")?,
                            }))
                        }
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?
                    .into_iter()
                    .flatten()
                    .take(25)
                    .collect()
            } else {
                Vec::new()
            })
        };

        // 13. Secrets without expiry
        let secrets_without_expiry_fut = async {
            let rows: Vec<SecretWithoutExpiryRow> = sqlx::query(
                "SELECT name, key_path, created_at FROM secrets \
             WHERE created_by = $1 AND expires_at IS NULL \
               AND (key_path ILIKE '%key%' OR key_path ILIKE '%token%' OR key_path ILIKE '%api%' \
                    OR key_path ILIKE '%pat%' OR key_path ILIKE '%secret%') \
             ORDER BY created_at ASC LIMIT 25",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|r| SecretWithoutExpiryRow {
                name: r.get("name"),
                key_path: r.get("key_path"),
                created_at: r.get("created_at"),
            })
            .collect();
            rows
        };

        // 14. Expiring actor memories
        let expiring_actor_memories_fut = async {
            let rows: Vec<ExpiringMemoryRow> = sqlx::query(
                "SELECT m.actor_id, m.key, m.memory_type, m.expires_at, a.name AS actor_name \
             FROM actor_memory m \
             JOIN actors a ON a.id = m.actor_id \
             WHERE a.user_id = $1 AND m.expires_at IS NOT NULL \
               AND m.expires_at > now() AND m.expires_at <= now() + interval '24 hours' \
             ORDER BY m.expires_at ASC LIMIT 50",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|r| -> Result<ExpiringMemoryRow> {
                Ok(ExpiringMemoryRow {
                    actor_id: r.get("actor_id"),
                    key: r.get("key"),
                    memory_type: r.try_get::<Option<_>, _>("memory_type")?,
                    expires_at: r.get("expires_at"),
                    actor_name: r.get("actor_name"),
                })
            })
            .collect::<Result<Vec<_>>>()?;
            Ok(rows)
        };

        // 15. Workflows needing schema
        let workflows_needing_schema_fut = async {
            let rows: Vec<NeedsSchemaRow> = sqlx::query(
                "SELECT w.id, w.name, COUNT(e.id)::bigint AS execution_count, MAX(e.started_at) AS last_run \
             FROM workflows w \
             JOIN workflow_executions e ON e.workflow_id = w.id AND e.status = 'completed' \
             WHERE w.user_id = $1 AND w.status = 'published' \
               AND (w.workflow_type IS NULL OR w.workflow_type NOT IN ('test', 'internal')) \
               AND w.input_schema IS NULL \
             GROUP BY w.id, w.name \
             HAVING COUNT(e.id) >= 1 \
             ORDER BY COUNT(e.id) DESC LIMIT 20",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|r| -> Result<NeedsSchemaRow> { Ok(NeedsSchemaRow {
                id: r.get("id"),
                name: r.get("name"),
                execution_count: r.try_get::<Option<_>, _>("execution_count")?.unwrap_or(0),
                last_run: r.try_get::<Option<_>, _>("last_run")?,
            }) })
            .collect::<Result<Vec<_>>>()?;
            Ok(rows)
        };

        // 16. Untyped serde_json::Value parser lint — performance anti-pattern.
        //
        // Modules that parse their input directly into `serde_json::Value` pay
        // HashMap<String, Value> allocation cost for every JSON object, which
        // dominates wasmtime fuel on large payloads. Typed #[derive(Deserialize)]
        // structs are 3–10× cheaper and only allocate fields the caller reads.
        // Incident reference: smart-email-drafts `fetch-threads` exhausted 30M
        // fuel on Value parsing; a typed rewrite dropped it below 1M.
        //
        // Detection regex catches only the actual anti-pattern — a top-level
        // typed bind from from_str into Value. Explicitly ignores narrow uses
        // like `Option<serde_json::Value>` (valid escape hatch for "number OR
        // string" config fields) and `Vec<serde_json::Value>` (passthrough
        // arrays), which legitimately need Value. Scoped to the caller's
        // user_id; catalog-compiled modules without source_code are excluded.
        //
        // Suppression: modules that genuinely need Value (e.g. arbitrary
        // schema passthrough, upstream payload envelopes) can include the
        // literal comment `// lint-allow: value-parser` anywhere in their
        // source to opt out of this lint. The author is expected to add a
        // brief rationale after the marker for reviewers.
        // Note: `$2::text` and `$3::text` are dollar-sign placeholders for
        // sqlx bind params, not Postgres dollar-quoted strings. The regex
        // patterns are plain string literals — backslash escapes in them
        // would be eaten by Rust's own string rules AND by Postgres's
        // backslash handling if we used E-strings. Plain string args avoid
        // both problems and are matched via Postgres's `~` operator.
        // Fetch id + name so the MCP layer can build a ready-to-paste
        // generate_typed_scaffold fix command per flagged module. The extra
        // column is free (modules has a btree on id).
        // Phase 5: reads the unified `modules` table; filters to
        // user-authored rows with source available (kind = sandbox|extracted
        // — catalog rows generally lack source_code and would produce
        // noise). Projects `legacy_wasm_module_id` when present so
        // existing graph_json callers keep resolving.
        // Suppression refinements:
        //   * `lint-allow: value-parser` — explicit author opt-out
        //   * `from_str(&input)` / `from_str(input.as_str())` — the documented
        //     envelope pattern (parsing the `fn run(input: String)` arg as
        //     Value to read dynamic `config`/`input` keys). Modules whose ONLY
        //     Value-parse is the envelope shouldn't be flagged. False
        //     negatives possible if a module mixes envelope + separate
        //     anti-pattern; the per-line compile-time lint
        //     (`compilation::analyze::lint_source_code`) covers that case
        //     accurately.
        let untyped_value_modules_fut = async {
            let rows: Vec<UntypedValueModuleRow> = sqlx::query_as::<_, (Uuid, String)>(
                "SELECT id, name FROM modules \
             WHERE user_id = $1 \
               AND kind IN ('sandbox', 'extracted') \
               AND source_code IS NOT NULL \
               AND (source_code ~ $2 OR source_code ~ $3) \
               AND position('lint-allow: value-parser' in source_code) = 0 \
               AND position('from_str(&input)' in source_code) = 0 \
               AND position('from_str(input.as_str())' in source_code) = 0 \
             ORDER BY name",
            )
            .bind(user_id)
            .bind(r":\s*serde_json::Value\s*=\s*serde_json::from_str")
            .bind(r"serde_json::from_str::<serde_json::Value>")
            .fetch_all(&self.db_pool)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(id, name)| UntypedValueModuleRow { id, name })
            .collect();
            rows
        };

        // Batch C — #12 (orphaned_secrets, gated on has_wildcard_module from
        // Batch B) plus 4 remaining independent queries (#13-#16). Five
        // futures, still well under the pool ceiling.
        let (
            orphaned_secrets,
            secrets_without_expiry,
            expiring_actor_memories,
            workflows_needing_schema,
            untyped_value_modules,
        ): (
            anyhow::Result<Vec<OrphanedSecretRow>>,
            Vec<SecretWithoutExpiryRow>,
            anyhow::Result<Vec<ExpiringMemoryRow>>,
            anyhow::Result<Vec<NeedsSchemaRow>>,
            Vec<UntypedValueModuleRow>,
        ) = tokio::join!(
            orphaned_secrets_fut,
            secrets_without_expiry_fut,
            expiring_actor_memories_fut,
            workflows_needing_schema_fut,
            untyped_value_modules_fut,
        );
        let orphaned_secrets = orphaned_secrets?;
        let expiring_actor_memories = expiring_actor_memories?;
        let workflows_needing_schema = workflows_needing_schema?;

        Ok(HygieneReport {
            undescribed,
            uncapabilized,
            suppressed_count,
            suppressed_low_score_count,
            unembedded_count,
            total_workflow_count,
            orphaned_modules,
            stale_executions,
            dormant_workflows,
            stale_draft_workflows,
            idle_actors,
            has_wildcard_module,
            wildcard_module_names,
            orphaned_secrets,
            secrets_without_expiry,
            expiring_actor_memories,
            workflows_needing_schema,
            untyped_value_modules,
        })
    }

    /// Per-module fuel usage stats over the last `days` days, scoped to a
    /// user (via the workflow that produced the rollup row).
    ///
    /// Source: `execution_cost_rollup` joined to `modules` for the current
    /// `max_fuel` ceiling. Rows with `module_id IS NULL` (raw rust_code
    /// nodes that never landed in the modules table) are skipped — they
    /// don't have a tunable budget to recommend against.
    ///
    /// `min_executions` filters out modules with too few samples for a
    /// reliable percentile (default 3 in callers). Top-N by p95 fuel.
    pub async fn get_per_module_fuel_stats(
        &self,
        user_id: Uuid,
        days: i32,
        min_executions: i64,
        limit: i32,
    ) -> Result<Vec<ModuleFuelStats>> {
        let rows = sqlx::query_as::<_, (
            Uuid,
            String,
            String,
            Option<i64>,
            i64,
            Option<f64>,
            Option<f64>,
            Option<i64>,
            Option<f64>,
            Option<f64>,
            Option<f64>,
        )>(
            // M-F (2026-05-06): cast `AVG(BIGINT)` to FLOAT8. Postgres
            // returns `numeric` for `avg(bigint)`, which sqlx decodes into
            // `BigDecimal` — NOT `f64`. The tuple type below expected
            // `Option<f64>`, so every invocation of this query failed at
            // decode time with the generic "Failed to fetch fuel stats"
            // wrapper hiding the actual mismatch error. The cast brings
            // the runtime type back into agreement with the tuple shape.
            // (`PERCENTILE_CONT` already returns `double precision`, so
            // those columns don't need the cast.)
            "SELECT \
                m.id, \
                m.name, \
                m.kind, \
                m.max_fuel, \
                COUNT(*) AS executions, \
                PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY r.fuel_consumed) AS fuel_p50, \
                PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY r.fuel_consumed) AS fuel_p95, \
                MAX(r.fuel_consumed) AS fuel_max, \
                AVG(r.fuel_consumed)::float8 AS fuel_avg, \
                PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY r.wall_time_ms) AS wall_p50, \
                PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY r.wall_time_ms) AS wall_p95 \
             FROM execution_cost_rollup r \
             JOIN modules m ON m.id = r.module_id \
             JOIN workflows w ON w.id = r.workflow_id \
             WHERE w.user_id = $1 \
               AND r.recorded_at > NOW() - make_interval(days => $2::int) \
               AND r.module_id IS NOT NULL \
             GROUP BY m.id, m.name, m.kind, m.max_fuel \
             HAVING COUNT(*) >= $3 \
             ORDER BY PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY r.fuel_consumed) DESC NULLS LAST \
             LIMIT $4",
        )
        .bind(user_id)
        .bind(days)
        .bind(min_executions)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, name, kind, max_fuel, execs, p50, p95, fmax, favg, wp50, wp95)| {
                    ModuleFuelStats {
                        module_id: id,
                        module_name: name,
                        kind,
                        current_max_fuel: max_fuel.unwrap_or(0),
                        executions: execs,
                        fuel_p50: p50.unwrap_or(0.0) as i64,
                        fuel_p95: p95.unwrap_or(0.0) as i64,
                        fuel_max: fmax.unwrap_or(0),
                        fuel_avg: favg.unwrap_or(0.0) as i64,
                        wall_time_p50_ms: wp50.unwrap_or(0.0) as i64,
                        wall_time_p95_ms: wp95.unwrap_or(0.0) as i64,
                    }
                },
            )
            .collect())
    }

    /// Per-node fuel breakdown for a single execution, scoped to the user
    /// via the owning workflow. Used by `get_execution_trace` to surface
    /// fuel consumption + ceiling utilization per node.
    ///
    /// Returns `(node_id, module_id, fuel_consumed, wall_time_ms,
    /// current_max_fuel)` per row. Rows with `module_id IS NULL` (raw
    /// rust_code, system nodes) are returned with `current_max_fuel: 0`
    /// so the caller can render fuel without a ceiling.
    pub async fn get_execution_node_fuel(
        &self,
        execution_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<(String, Option<Uuid>, i64, i64, Option<i64>)>> {
        let rows = sqlx::query_as::<_, (String, Option<Uuid>, i64, i64, Option<i64>)>(
            "SELECT r.node_id, r.module_id, r.fuel_consumed, r.wall_time_ms, \
                    /* Effective per-node limit: prefer the limit the worker \
                       actually enforced (r.max_fuel, stamped from \
                       __fuel_limit__); fall back to the module row for rows \
                       written before the stamp existed. */ \
                    COALESCE(r.max_fuel, m.max_fuel) \
             FROM execution_cost_rollup r \
             JOIN workflows w ON w.id = r.workflow_id \
             LEFT JOIN modules m ON m.id = r.module_id \
             WHERE r.execution_id = $1 AND w.user_id = $2 \
             ORDER BY r.recorded_at",
        )
        .bind(execution_id)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    /// MCP-50 (2026-05-07): aggregate per-node wall-time across all
    /// executions of a workflow in the period. Replaces the
    /// `output_data.__node_timings__` projection in
    /// `get_workflow_performance_report` which returned empty results
    /// when the engine wasn't stamping `__node_timings__` on
    /// output_data (the daily-brief case — no `__node_timings__`
    /// key in any of the 7 successful runs even though the
    /// underlying execution_cost_rollup rows are populated).
    ///
    /// Returns `Vec<(node_label, avg_wall_time_ms, sample_count)>`
    /// sorted by avg-time descending so the slowest nodes surface
    /// first. Note `node_id` in execution_cost_rollup is the human
    /// label (compute-context, synthesize), not the per-execution
    /// UUID hash — the engine writes the label there at rollup time
    /// for direct readability.
    pub async fn get_workflow_node_timing_breakdown(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
        days: i32,
    ) -> Result<Vec<(String, f64, i64)>> {
        let rows = sqlx::query_as::<_, (String, f64, i64)>(
            "SELECT r.node_id, AVG(r.wall_time_ms)::float8 AS avg_wall_ms, COUNT(*)::bigint AS sample_count \
             FROM execution_cost_rollup r \
             JOIN workflows w ON w.id = r.workflow_id \
             WHERE r.workflow_id = $1 AND w.user_id = $2 \
               AND r.recorded_at > NOW() - make_interval(days => $3::int) \
             GROUP BY r.node_id \
             ORDER BY AVG(r.wall_time_ms) DESC NULLS LAST",
        )
        .bind(wf_id)
        .bind(user_id)
        .bind(days)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }
}
