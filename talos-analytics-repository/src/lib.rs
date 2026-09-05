/// AnalyticsRepository -- centralises all SQL for the analytics domain.
///
/// Follows the ExecutionRepository pattern: plain struct, `new(db_pool)`,
/// all methods `pub async fn`, return `anyhow::Result<T>` so callers can `?`.
/// Handlers in `mcp/analytics.rs` should be thin wrappers that call these
/// methods and format the JSON-RPC response.
use anyhow::Result;
use chrono::{DateTime, Utc};
/// A read's own outcome, kept SEPARATE from [`Result`] (which is
/// `anyhow::Result` here). The hygiene sweep's futures return a nested
/// `Result<SqlxResult<T>>` so the two error classes stay distinguishable:
/// the outer one is row-mapping / schema drift and propagates loudly (check
/// 52); the inner one is the QUERY failing and is recorded in the report's
/// ledger instead of being defaulted away.
type SqlxResult<T> = std::result::Result<T, sqlx::Error>;
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
/// Six substitutions:
///   * UUIDs → `<UUID>`
///   * ISO-8601 timestamps → `<TIMESTAMP>`
///   * `(after|attempt|retry|timeout|took|elapsed) <N>` → `$1 N`
///   * Bare durations (`173s`, `250ms`) → `Ns` / `Nms`
///   * Per-run tallies (`4 nodes completed`, `+7 more`) → `N …`
///   * Long double-quoted strings (≥16 chars between the quotes) → `"<QUOTED>"`
///
/// The bare-duration and tally collapses exist for the engine's timeout
/// ATTRIBUTION clause — `"… timed out after 420 seconds (in flight:
/// synthesize 411s; 4 nodes completed)"`. Every one of those numbers
/// moves run to run, so without them each occurrence of the *same*
/// recurring timeout hashes to its own fingerprint and top-K aggregation
/// degrades to a list of singletons — the opposite of what an operator
/// staring at a repeatedly-failing workflow needs. Node LABELS stay
/// verbatim on purpose: "which node held the clock" is the signal worth
/// grouping BY, not grouping away.
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
    // Bare durations, as emitted by the timeout attribution's per-node
    // elapsed rendering. Anchored on both sides so it can't eat the tail
    // of an identifier (`v2s`, `qwen3.6:q4s`).
    static RE_BARE_DURATION: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"\b\d+(ms|s)\b").expect("valid bare-duration regex")
    });
    // Per-run tallies: `4 nodes completed` / `1 node completed` and the
    // in-flight overflow marker `+7 more`.
    static RE_TALLY: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"\b\d+ nodes? completed").expect("valid node-tally regex")
    });
    static RE_OVERFLOW: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"\+\d+ more").expect("valid overflow-marker regex")
    });
    let result = RE_UUID.replace_all(msg, "<UUID>");
    let result = RE_TS.replace_all(&result, "<TIMESTAMP>");
    let result = RE_NUM.replace_all(&result, "$1 N");
    let result = RE_BARE_DURATION.replace_all(&result, "N$1");
    let result = RE_TALLY.replace_all(&result, "N nodes completed");
    let result = RE_OVERFLOW.replace_all(&result, "+N more");
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

/// Everything `get_workflow_risk_assessment` needs to know about one module.
///
/// `capability_world` + `allowed_methods` are the AUTHORITATIVE inputs to
/// `talos_workflow_engine_core::default_max_retries_for_module`; `name` and
/// `category` are display labels only and must never be used to infer what a
/// module does.
#[derive(Debug, Clone)]
pub struct RiskModuleFacts {
    pub id: Uuid,
    pub name: String,
    pub category: Option<String>,
    pub capability_world: Option<String>,
    pub allowed_methods: Vec<String>,
}

/// One secret a workflow actually references, with its expiry.
#[derive(Debug, Clone)]
pub struct RiskSecretExpiry {
    pub name: String,
    pub key_path: String,
    pub expires_at: Option<DateTime<Utc>>,
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
/// Source of truth for `get_fuel_usage_report`.
///
/// ## Utilisation is measured against the ENFORCED ceiling, not the module row
///
/// `modules.max_fuel` is NOT the limit a run is killed at. The dispatch
/// enforces `node config max_fuel override > module default, engine-clamped`
/// (`engine_dispatch_single`), and the worker stamps what it actually enforced
/// into `execution_cost_rollup.max_fuel` (migration
/// `20260707190000_cost_rollup_max_fuel.sql`, added for exactly this reason).
///
/// Dividing `fuel_p95` by `modules.max_fuel` therefore produced utilisation
/// figures above 100 % for completed runs — impossible against a real ceiling,
/// since the run would have been killed. Measured on the live database
/// 2026-08-18 over a 7-day window: `cos_groundedness` 566.5 %,
/// `LLM Inference` 425.5 %, and **11 of 12 `at_risk` verdicts were false**
/// (only `gmail-organize`, at 75.8 %, was genuinely at risk). The
/// false-NEGATIVE direction is live too and is the one worth naming first:
/// `Gmail: Get Message` carries a 24 460 000 module row against a 6 000 000
/// enforced ceiling, understating its utilisation by 4×; a module row above
/// the enforced ceiling hides risk without bound.
///
/// [`Self::utilisation_p95`] is therefore a p95 of the PER-ROW ratio
/// `fuel_consumed / COALESCE(r.max_fuel, m.max_fuel)`, not a ratio of
/// aggregates. Two reasons, and the second is the load-bearing one:
///
/// 1. A module runs across many nodes with DIFFERENT enforced ceilings
///    (`LLM Inference`: 2 003 782 … 14 000 000 in one window), so any single
///    per-module denominator is a mixture of unlike things.
/// 2. It makes ">100 % is impossible for a completed run" true BY
///    CONSTRUCTION rather than by documentation — each row's ratio is ≤ 1, so
///    the percentile is ≤ 1. Taking the LATEST enforced ceiling as a single
///    denominator does not have this property and would still print 286 % for
///    `LLM Inference`.
///
/// `COALESCE` back to `modules.max_fuel` preserves the pre-migration
/// behaviour for rows written by older workers (`r.max_fuel IS NULL`), which
/// is correct for a module with no node-level override.
#[derive(Debug)]
pub struct ModuleFuelStats {
    pub module_id: Uuid,
    pub module_name: String,
    pub kind: String,
    /// The `modules.max_fuel` row value. **Not** the limit that is enforced
    /// when a node overrides it, and deliberately NOT the utilisation
    /// denominator — see the type docs. Retained because it is the number
    /// `hot_update_module(fuel_budget=…)` actually writes.
    pub current_max_fuel: i64,
    /// p95 of the per-execution ratio `fuel_consumed / enforced ceiling`,
    /// as a fraction (0.0–1.0). The basis for the handler's verdict.
    pub utilisation_p95: f64,
    /// Range of ceilings actually enforced for this module in the window.
    /// A wide spread means the module row governs only some of its nodes.
    pub enforced_ceiling_min: i64,
    pub enforced_ceiling_max: i64,
    /// Executions whose enforced ceiling came from the worker's own
    /// `__fuel_limit__` stamp rather than the `COALESCE` fallback. Provenance:
    /// if this is 0, every ratio fell back to the module row.
    pub rows_with_enforced_ceiling: i64,
    pub executions: i64,
    pub fuel_p50: i64,
    pub fuel_p95: i64,
    pub fuel_max: i64,
    pub fuel_avg: i64,
    pub wall_time_p50_ms: i64,
    pub wall_time_p95_ms: i64,
}

/// Per-node fuel-consumption statistics for one workflow, aggregated across
/// executions. Feeds the adaptive-fuel learned ceiling (Phase 2): a node's
/// effective `max_fuel` is raised to `max(configured, adaptive_ceiling(p95, max))`
/// so it never silently under-provisions. `node_label` matches the label the
/// engine dispatches under (the `execution_cost_rollup.node_id` column, which
/// stores the human label, not a UUID).
#[derive(Debug, Clone)]
pub struct NodeFuelStat {
    pub node_label: String,
    pub executions: i64,
    pub fuel_p95: u64,
    pub fuel_max: u64,
}

/// One `(workflow, node)` pair's fuel-headroom picture: the worst consumption
/// observed in the window against the ceiling a worker MOST RECENTLY enforced
/// for it.
///
/// THIS IS NOT `NodeFuelStat` AND MUST NOT BE MERGED WITH IT. `NodeFuelStat`
/// feeds the adaptive-fuel LEARNER — it is gated on `MIN_SAMPLES = 5` and
/// aggregates a percentile so a learned ceiling is not moved by one outlier.
/// This one feeds a DETECTOR, and its whole reason to exist is that it has **no
/// sample floor at all**: the node that motivated it
/// (`pa-read-later-digest/digest`) sat at 96.9% of budget for 16 days on **two**
/// samples, structurally invisible to every percentile-and-floor surface the
/// platform already had, and then failed. A floor here would reinstate exactly
/// the blindness it removes.
#[derive(Debug, Clone)]
pub struct NodeFuelHeadroom {
    pub workflow_id: Uuid,
    /// Workflow name at query time — for the operator-facing log line only.
    /// Never a metric label (see `talos_fuel_high_utilisation_nodes`).
    pub workflow_name: String,
    /// The engine's node label, i.e. `execution_cost_rollup.node_id`.
    pub node_label: String,
    /// Rows in the window. Reported so an operator can weigh the evidence;
    /// **never used to suppress a row**.
    pub samples: i64,
    /// `MAX(fuel_consumed)` over the window — the peak demand actually observed.
    pub peak_fuel: i64,
    /// `max_fuel` from the node's MOST RECENT row in the window: the last limit
    /// a worker genuinely enforced (the `__fuel_limit__` stamp), not a
    /// configured value that may never have reached a dispatch.
    pub current_ceiling: i64,
}

impl NodeFuelHeadroom {
    /// Peak consumption as a fraction of the ceiling now in force. `>= 1.0` is
    /// possible in principle (a ceiling that has since been LOWERED), so callers
    /// must not assume the value is bounded by 1.
    pub fn utilisation(&self) -> f64 {
        if self.current_ceiling <= 0 {
            return 0.0;
        }
        self.peak_fuel as f64 / self.current_ceiling as f64
    }
}

/// The classifier's verdict string for a fuel-meter kill.
///
/// `talos_retry_intelligence::classify_error` is the single authority on what a
/// fuel death is; this is only the token it answers with. Pinned by
/// `the_sql_prefilter_is_a_superset_of_the_classifier` so an upstream rename
/// fails a test here instead of silently emptying the deaths section.
pub const FUEL_EXHAUSTION_CLASS: &str = "fuel_exhaustion";

/// The one token the SQL pre-filter matches on before the Rust classifier runs.
///
/// It exists to keep the scan cheap, NOT to decide anything: it must be a
/// substring of every phrase the classifier maps to [`FUEL_EXHAUSTION_CLASS`],
/// so widening the classifier can never leave this behind. Re-stating the
/// classifier's phrase list here is what would make the two drift.
pub const FUEL_MESSAGE_PREFILTER: &str = "fuel";

/// Row cap for the node-budget graph scan. Mirrors [`TWIN_SCAN_GRAPH_LIMIT`]'s
/// reasoning on the same population (the fleet is a few dozen active graphs);
/// kept as its own constant so tuning one scan does not silently retune the
/// other. Hitting it is disclosed through the returned `Coverage`.
pub const NODE_BUDGET_GRAPH_LIMIT: i64 = 100;

/// Per-graph node cap for the same scan. A graph with more nodes than this is
/// read partially rather than unboundedly; 200 is ~4x the largest live graph.
pub const NODE_BUDGET_NODES_PER_GRAPH: usize = 200;

/// A node that was KILLED by the fuel meter.
///
/// Distinct from every other type in this file in one decisive way: it does not
/// come from `execution_cost_rollup`. Nothing in that table can represent this
/// event — see [`AnalyticsRepository::get_fuel_exhaustion_deaths`].
#[derive(Debug, Clone)]
pub struct FuelExhaustionDeath {
    /// The workflow the engine attributed the failing node to. For a
    /// sub-workflow run recorded before the engine began stamping the
    /// sub-workflow's own id this is a synthetic per-run uuid that resolves to
    /// no workflow row — which is why `workflow_name` is optional.
    pub workflow_id: Uuid,
    pub workflow_name: Option<String>,
    /// `engine_node_uuid(node label)` — the derived id the engine writes. The
    /// label is recoverable only from the owning graph, so a caller that wants
    /// one must resolve it through
    /// `talos_workflow_engine_core::engine_node_uuid`; deriving it a second way
    /// is what structural lint check 71 forbids.
    pub node_uuid: Uuid,
    pub execution_id: Uuid,
    pub occurred_at: DateTime<Utc>,
    /// The ceiling the worker enforced, parsed out of the failure text.
    /// `None` when the message did not carry one — absence of the number is
    /// not evidence about the number.
    pub enforced_limit: Option<i64>,
}

/// One module-backed graph node and the fuel ceiling it would run under.
///
/// Derived from the workflow GRAPH, not from execution history, so it can
/// describe a node that has never run — including one whose first run will be
/// its last.
#[derive(Debug, Clone)]
pub struct NodeBudgetRow {
    pub workflow_id: Uuid,
    pub workflow_name: String,
    /// The graph node id, which is also the label the engine dispatches under
    /// and stores in `execution_cost_rollup.node_id`.
    pub node_id: String,
    pub module_id: Uuid,
    pub module_name: String,
    /// The node's `data.max_fuel` override, when it has one.
    pub node_max_fuel: Option<i64>,
    /// `modules.max_fuel` — what the node inherits when it has no override.
    pub module_max_fuel: Option<i64>,
}

impl NodeBudgetRow {
    /// The ceiling this node is CONFIGURED with: its own override, else the
    /// module row. `None` when neither is set, i.e. the node falls back to the
    /// worker's own default and nothing in this database says what that is.
    ///
    /// # This is NOT necessarily the ceiling a dispatch enforces
    ///
    /// It was called `effective_max_fuel` until 2026-09-03, and that name
    /// asserted a finality it reads only two of the three inputs for.
    /// `ParallelWorkflowEngine::resolve_node_max_fuel` computes
    /// `baseline.max(learned).min(max_fuel_per_node)`, so the enforced value
    /// diverges from this one in BOTH directions:
    ///
    /// * **UP** — adaptive fuel (`talos_engine::adaptive_fuel`) applies a
    ///   learned p95/max-derived ceiling as a FLOOR. Measured on the live
    ///   database: `pa-daily-brief/gmail` is configured at 2_020_000 and ran
    ///   under enforced ceilings up to 4_264_652.
    /// * **DOWN** — the engine-wide `max_fuel_per_node` clamp (default 50M)
    ///   caps a larger configured value.
    ///
    /// Neither input is derivable from configuration: the learned floor is a
    /// function of a sliding 30-day history and DECAYS as big runs age out (the
    /// same node's enforced ceiling fell back to its configured 2_020_000 on
    /// 2026-08-21), and it is absent entirely below `MIN_SAMPLES`. So a caller
    /// that wants what actually ran must read `execution_cost_rollup.max_fuel`
    /// — the worker's own `__fuel_limit__` stamp — and treat THIS value as the
    /// configured baseline it is. See `AnalyticsRepository::get_node_fuel_headroom`.
    #[must_use]
    pub fn configured_max_fuel(&self) -> Option<i64> {
        self.node_max_fuel.or(self.module_max_fuel)
    }

    /// True when this node takes the module default rather than declaring its
    /// own budget. CLAUDE.md: "ALWAYS set explicit `max_fuel` on every workflow
    /// node. Default fuel (1M-5M) is rarely correct."
    #[must_use]
    pub fn inherits_module_default(&self) -> bool {
        self.node_max_fuel.is_none()
    }
}

/// Extract the enforced fuel ceiling from a worker failure message.
///
/// Best-effort by design: the worker has emitted three phrasings over time and
/// will emit more. Returning `None` is always correct-and-honest; guessing is
/// not, so there is no fallback constant here.
#[must_use]
pub fn parse_enforced_fuel_limit(msg: &str) -> Option<i64> {
    static RE_LIMIT: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        // Three worker phrasings, oldest last. A raw string with no line
        // continuations on purpose: `r"..\<newline>"` keeps the backslash
        // LITERAL, which silently changes the pattern.
        regex::Regex::new(
            r"(?i)current fuel limit:\s*(\d+)|of a (\d+)-instruction budget|fuel exhausted after (\d+)",
        )
        .expect("valid fuel limit regex")
    });
    let caps = RE_LIMIT.captures(msg)?;
    (1..=3)
        .filter_map(|i| caps.get(i))
        .find_map(|m| m.as_str().parse::<i64>().ok())
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

/// One row of the health-dashboard `top_failures_24h` rollup: a workflow
/// with at least one failed execution in the last 24 hours, plus the most
/// recent failure's error message as a representative sample.
///
/// Motivating incident (2026-07-24): a 3-hour network outage produced 125
/// failed vs 245 completed executions in 24h, but the dashboard's
/// `failing_workflow_count` heuristic (currently-failing only) showed 0 —
/// mass transient failure was invisible. This row type backs the grouped
/// failure view that makes such outages show up.
#[derive(Debug)]
pub struct TopFailureRow {
    pub workflow_id: Uuid,
    pub workflow_name: String,
    pub failed_count: i64,
    pub last_failed_at: Option<DateTime<Utc>>,
    /// Most recent non-null `error_message` among the failed runs.
    pub latest_error_message: Option<String>,
}

/// Pure: failure rate as failed/(failed+completed) percent, rounded to
/// 1 decimal. `None` (serialize as JSON null) when the window has no
/// terminal executions at all — a rate over zero runs is meaningless and
/// `0.0` would falsely read as "healthy". Negative inputs (impossible
/// from COUNT(*), defensive against future delta-fed callers) are also
/// `None`.
///
/// 2026-07-24: authoritative shared home for the computation, hoisted
/// here (next to [`HealthSummaryCounts`], which produces its inputs) so
/// the health dashboard (`talos-mcp-handlers::analytics`) and the
/// operator digest (`talos-operator-digest`) agree on one definition.
/// The mcp-handlers private copy predates this and should delegate here
/// on its next touch.
pub fn failure_rate_pct(failed: i64, completed: i64) -> Option<f64> {
    let total = failed + completed;
    if total <= 0 || failed < 0 || completed < 0 {
        return None;
    }
    Some(((failed as f64 / total as f64) * 1000.0).round() / 10.0)
}

#[cfg(test)]
mod failure_rate_tests {
    use super::failure_rate_pct;

    #[test]
    fn none_when_no_terminal_executions() {
        assert_eq!(failure_rate_pct(0, 0), None);
    }

    #[test]
    fn zero_when_all_completed_hundred_when_all_failed() {
        assert_eq!(failure_rate_pct(0, 245), Some(0.0));
        assert_eq!(failure_rate_pct(125, 0), Some(100.0));
    }

    #[test]
    fn rounds_to_one_decimal() {
        // The motivating incident: 125 failed / 245 completed → 33.8%.
        assert_eq!(failure_rate_pct(125, 245), Some(33.8));
        assert_eq!(failure_rate_pct(1, 2), Some(33.3));
        assert_eq!(failure_rate_pct(2, 1), Some(66.7));
    }

    #[test]
    fn negative_counts_are_null_not_garbage() {
        assert_eq!(failure_rate_pct(-1, 10), None);
        assert_eq!(failure_rate_pct(10, -1), None);
    }
}

/// One row of the global error report's per-workflow failure breakdown.
#[derive(Debug)]
pub struct WorkflowFailureCountRow {
    pub workflow_id: Uuid,
    pub workflow_name: String,
    pub failed_count: i64,
    pub last_failed_at: Option<DateTime<Utc>>,
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
    /// The DENOMINATOR of `success_rate` — executions whose `started_at`
    /// falls in the trailing 30 days, in ANY status.
    ///
    /// Added 2026-07-28 (measurement envelope, S1). `success_rate` alone
    /// renders 1-for-1 identically to 400-for-400, and this row feeds
    /// capability ROUTING — which workflow gets picked. Never emit the rate
    /// without this count beside it.
    pub runs_30d: i64,
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

/// A user-compiled (DB-resident) module referenced by many workflows — a
/// candidate for promotion to a versioned catalog template. High fan-out
/// compiled modules are unmaintainable black boxes: no version control, no
/// shared fix (the delivery-pattern send module's RFC 2047 bug was un-fixable
/// in place for exactly this reason).
#[derive(Debug)]
pub struct PromotableModuleRow {
    pub id: Uuid,
    pub name: String,
    pub dependent_count: i64,
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

/// One active workflow graph, fed to the hygiene report's twin-divergence
/// scan. `graph_json` is the raw TEXT column — parsing is the analyzer's
/// job (and is fail-soft there), so a malformed graph can never sink the
/// surrounding report. Distinct from the metadata-rich
/// [`WorkflowGraphRow`] above: this row carries a NON-optional body
/// (oversized graphs are dropped before construction) and nothing else.
#[derive(Debug, Clone)]
pub struct TwinScanGraphRow {
    pub id: Uuid,
    pub name: String,
    pub graph_json: String,
}

/// Row cap for the twin-divergence graph scan. The fleet is ~22 active
/// graphs today; 100 leaves headroom while keeping the payload bounded.
/// Hitting the cap sets `workflow_graphs_truncated`, which the report
/// surfaces so an empty finding list is never read as "nothing diverged".
pub const TWIN_SCAN_GRAPH_LIMIT: i64 = 100;

/// Row cap on the per-check hygiene finding lists.
///
/// **This constant does not drive the SQL** — the queries below carry a literal
/// `LIMIT 25`, and changing this value alone changes nothing. It exists so the
/// cap can TRAVEL to the reporting layer, which is in a different crate
/// (`talos-hygiene-service`) and previously had no way to know what bound the
/// vectors it was counting. `hygiene_finding_limit_matches_the_sql_literals`
/// pins the two together, in the style of
/// `the_hygiene_cuts_have_a_unique_tiebreaker` above.
///
/// The defect it addresses: `HygieneService` sums eleven of these `.len()`s into
/// a single `total_issues`, so an operator's headline "you have N issues" is a
/// sum of eleven independent truncations that saturates near 270 — a platform
/// with 5 000 real issues and one with 300 print an indistinguishable number.
/// A count cannot disclose its own ceiling if the ceiling is a literal in
/// another crate's SQL.
pub const HYGIENE_FINDING_LIMIT: i64 = 25;

/// The wildcard-secret verdict: `Some(true)` at least one module can read the
/// whole vault, `Some(false)` the scan ran and none can, `None` the scan
/// itself could not be read.
///
/// A pure function rather than an inline `map` because the collapse it exists
/// to prevent — `!names.is_empty()` over a defaulted `[]`, i.e. an unread scan
/// reporting "no module can read your whole vault" — is a SECURITY claim, and
/// an expression inside a 900-line DB-bound sweep cannot be unit-tested. This
/// can. `the_wildcard_verdict_has_one_implementation` pins the sweep to it.
#[must_use]
pub fn wildcard_verdict(names: Option<&[String]>) -> Option<bool> {
    names.map(|n| !n.is_empty())
}

/// Row cap on the `get_all_readiness_scores` page.
///
/// As with [`HYGIENE_FINDING_LIMIT`], this does NOT drive the SQL — the query
/// carries a literal `LIMIT 50` — it exists so the cap can travel to the
/// handler, which is in another crate and otherwise had no way to disclose the
/// bound on the list it renders. `readiness_page_limit_matches_the_sql_literal`
/// pins the two together.
pub const READINESS_PAGE_LIMIT: i64 = 50;

/// Population summary for `get_all_readiness_scores`, over the WHOLE filtered
/// set rather than the capped page.
///
/// Exists because the four summary numbers were previously accumulated over the
/// `LIMIT 50` page returned by [`AnalyticsRepository::list_readiness_scores`],
/// whose `ORDER BY COALESCE(readiness_score, 0) ASC` selects the 50 LOWEST
/// scorers. That is not a truncated population statistic — it is a BIASED SAMPLE
/// presented as one, and it fails in the direction that matters:
///
/// * `avg_score` is pinned to the worst tail, so it is monotonically
///   non-increasing in fleet quality once the cap binds. Adding good workflows
///   cannot raise it (they never enter the window); adding bad ones lowers it.
///   **A fleet that improves reports a falling average.**
/// * `below_50_count` counts, among the 50 worst, how many are below 50 — it
///   saturates at 50 and then never moves again.
/// * unscored rows `COALESCE` to 0 and therefore sort FIRST, so at >=50 unscored
///   workflows the page is entirely unscored and every scored workflow in the
///   fleet becomes invisible.
///
/// No disclosure flag fixes an inverted statistic, so this is computed over the
/// population instead. The capped list stays exactly as it is — an
/// `ORDER BY ... ASC LIMIT 50` is a good "worst offenders, fix these first"
/// list, and it is only the SUMMARY that was claiming to be about the fleet.
#[derive(Debug, Clone, Copy)]
pub struct ReadinessPopulation {
    /// Workflows matching the filters, uncapped.
    pub total: i64,
    /// Mean of `COALESCE(readiness_score, 0)` over all of them. `None` when
    /// there are no matching rows — a mean over zero rows has no value, and
    /// emitting `0` there would render "no workflows" as "everything is broken".
    pub avg_score: Option<f64>,
    /// How many score below 50, over all of them.
    pub below_50: i64,
    /// How many have never been scored, over all of them. Anchored on
    /// `readiness_scored_at IS NULL` to match `classify_readiness_state`'s
    /// authoritative predicate — the two columns can drift.
    pub unscored: i64,
}

/// Per-graph payload guard. Graphs above this are counted in
/// `workflow_graphs_skipped` and their text is never transferred (the
/// projection nulls it out server-side). Defensive: the largest graph
/// observed is ~8KB.
pub const TWIN_SCAN_MAX_GRAPH_BYTES: i64 = 262_144;

/// Aggregate payload guard across the whole scan. The per-graph cap alone
/// admits 100 × 256 KB = 25 MB of JSON, all of which the analyzer parses
/// into `serde_json::Value`s AT ONCE (they must coexist to be diffed) —
/// several hundred MB of controller RSS for one on-demand report. Graphs
/// past this budget are counted in `workflow_graphs_skipped` exactly like
/// oversized ones, so the report's coverage disclosure covers both.
/// 4 MB is ~65× the current whole-fleet total (62 KB).
pub const TWIN_SCAN_TOTAL_BYTES: i64 = 4_194_304;

/// One hygiene check, named by the report key its rows land under and by the
/// row cap the SQL behind it actually runs with.
///
/// # Why the name is the REPORT key and not the struct field
///
/// The disclosure this table drives is read by an operator (or a model)
/// holding the tool output, and its only job is to let them find the field
/// that is null. A name they cannot locate in the response — `undescribed`
/// when the JSON says `undescribed_workflows` — is a disclosure that names
/// nothing. `hygiene_check_names_are_report_keys` in `talos-hygiene-service`
/// resolves every name in this table against the JSON the service really
/// emits, so the two cannot drift.
///
/// # Why the cap travels here
///
/// Same reason [`HYGIENE_FINDING_LIMIT`] exists, generalised: the caps are
/// SQL literals in this crate and the counting happens in another one. There
/// are **three** distinct caps plus two genuinely uncapped checks, so a single
/// exported constant would misstate five of the thirteen list checks — which is
/// the disclosure defect one level up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HygieneCheck {
    /// The key the check's findings are rendered under in the report JSON. A
    /// `.`-separated path when the check lands inside a nested object.
    pub field: &'static str,
    /// Row cap the SQL runs under. `0` means the read is genuinely uncapped —
    /// [`talos_measurement::Coverage::complete`] territory, not "unknown".
    pub cap: i64,
    /// True when the check produces a LIST of findings (so a cap can bind).
    /// A scalar `COUNT(*)` sees the whole population by construction.
    pub is_list: bool,
}

impl HygieneCheck {
    const fn list(field: &'static str, cap: i64) -> Self {
        Self {
            field,
            cap,
            is_list: true,
        }
    }
    const fn count(field: &'static str) -> Self {
        Self {
            field,
            cap: 0,
            is_list: false,
        }
    }
}

/// Every check [`AnalyticsRepository::get_hygiene_report`] runs, with the
/// report key it is disclosed under and the cap in force.
///
/// This is the ONE list. The repository records read failures against these
/// names, the service renders coverage from these caps, and
/// `hygiene_check_caps_match_the_sql_literals` pins each cap to the literal in
/// the query beside it. Adding a check without adding it here leaves its
/// failure invisible — which is the entire defect this table exists to close.
pub const HYGIENE_CHECKS: &[HygieneCheck] = &[
    HygieneCheck::list("undescribed_workflows", HYGIENE_FINDING_LIMIT),
    HygieneCheck::list("uncapabilized_workflows", HYGIENE_FINDING_LIMIT),
    HygieneCheck::count("summary.suppressed_internal_test_workflows"),
    HygieneCheck::count("summary.suppressed_low_score_count"),
    HygieneCheck::count("unembedded_workflow_count"),
    HygieneCheck::count("summary.total_workflows"),
    HygieneCheck::list("orphaned_modules", HYGIENE_FINDING_LIMIT),
    HygieneCheck::list("promotable_modules", HYGIENE_FINDING_LIMIT),
    HygieneCheck::list("stale_executions", HYGIENE_FINDING_LIMIT),
    HygieneCheck::list("dormant_workflows", HYGIENE_FINDING_LIMIT),
    HygieneCheck::list("stale_draft_workflows", HYGIENE_FINDING_LIMIT),
    // No LIMIT: the idle-actor query is already narrowed by three NOT EXISTS
    // guards and returns single digits in practice.
    HygieneCheck::list("idle_actors", 0),
    HygieneCheck::count("summary.wildcard_secret_grant"),
    HygieneCheck::list("orphaned_secrets", HYGIENE_FINDING_LIMIT),
    HygieneCheck::list("secrets_without_expiry", HYGIENE_FINDING_LIMIT),
    HygieneCheck::list("expiring_actor_memories", EXPIRING_MEMORY_LIMIT),
    HygieneCheck::list("workflows_needing_schema", NEEDS_SCHEMA_LIMIT),
    // No LIMIT: the untyped-Value scan is a source-code regex over the
    // caller's own sandbox modules.
    HygieneCheck::list("untyped_value_modules", 0),
    HygieneCheck::list("workflow_twins", TWIN_SCAN_GRAPH_LIMIT),
];

/// Report key for the twin-divergence scan, which is the one check whose
/// finding list is not named after its own query.
pub const HYGIENE_FIELD_TWINS: &str = "workflow_twins";

/// Row cap on the expiring-actor-memory check. Distinct from
/// [`HYGIENE_FINDING_LIMIT`]: this list is a 24-hour TTL horizon, not a
/// finding sample, so it runs deeper.
pub const EXPIRING_MEMORY_LIMIT: i64 = 50;

/// Row cap on the workflows-needing-input-schema check.
pub const NEEDS_SCHEMA_LIMIT: i64 = 20;

/// Cap on the secrets scanned before the orphan predicate is applied in Rust.
///
/// A SECOND ceiling on `orphaned_secrets`, upstream of its
/// [`HYGIENE_FINDING_LIMIT`] output cap: the SQL reads at most this many of the
/// user's secrets, and only those are ever tested for orphanhood. A vault
/// larger than this has secrets that were never examined, and no `take(25)`
/// disclosure can see that.
pub const ORPHAN_SECRET_SCAN_LIMIT: i64 = 200;

/// The result of one hygiene sweep, plus the ledger saying which of its
/// checks actually ran.
///
/// # Why `readings` is not optional
///
/// Every list below is a `Vec`, and an empty `Vec` is what BOTH "this check
/// found nothing" and "this check's query failed" produced before #726. The
/// report is assembled with `tokio::join!` rather than `try_join!` on purpose
/// — one dead query must not destroy fifteen live ones, and a partial report
/// genuinely beats no report. The defect was never the concurrency; it was
/// that the partial-ness was invisible, so a database outage rendered as
/// `total_issues: 0` and an empty `recommendations` list: "your platform is
/// clean", from zero measurements.
///
/// [`talos_measurement::Readings`] is the ledger. Every check that could not
/// be read is recorded against the REPORT key it would have been rendered
/// under (see [`HYGIENE_CHECKS`]), the upstream error is logged server-side
/// and never travels, and the consumer can tell an empty list from an unasked
/// question.
#[derive(Debug)]
pub struct HygieneReport {
    pub undescribed: Vec<HygieneWorkflowRow>,
    pub uncapabilized: Vec<HygieneWorkflowRow>,
    /// `None` when the count could not be read. NEVER `0` — see `readings`.
    pub suppressed_count: Option<i64>,
    /// `None` when the count could not be read.
    pub suppressed_low_score_count: Option<i64>,
    /// `None` when the count could not be read.
    pub unembedded_count: Option<i64>,
    /// `None` when the count could not be read. This is the denominator of
    /// `embedding_coverage_percent`, so a defaulted `0` here did not merely
    /// misstate a total — it silently changed a coverage share into a share
    /// of nothing.
    pub total_workflow_count: Option<i64>,
    pub orphaned_modules: Vec<OrphanedModuleRow>,
    /// User-compiled modules with >=3 workflow dependents — promote-to-template
    /// candidates.
    pub promotable_modules: Vec<PromotableModuleRow>,
    pub stale_executions: Vec<StaleExecutionRow>,
    pub dormant_workflows: Vec<DormantWorkflowRow>,
    pub stale_draft_workflows: Vec<StaleDraftRow>,
    pub idle_actors: Vec<IdleActorRow>,
    /// `None` when the wildcard scan could not be read — distinct from
    /// `Some(false)`, which means the scan ran and found no wildcard grant.
    pub has_wildcard_module: Option<bool>,
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
    /// Active workflow graphs for the twin-divergence scan (bounded by
    /// [`TWIN_SCAN_GRAPH_LIMIT`]; oversized graphs excluded).
    pub workflow_graphs: Vec<TwinScanGraphRow>,
    /// True when the graph scan hit [`TWIN_SCAN_GRAPH_LIMIT`] — some
    /// workflows were not examined, so absence of findings proves nothing.
    pub workflow_graphs_truncated: bool,
    /// Graphs inside the scan window dropped before analysis: individually
    /// over [`TWIN_SCAN_MAX_GRAPH_BYTES`], or past the scan's aggregate
    /// [`TWIN_SCAN_TOTAL_BYTES`] budget.
    pub workflow_graphs_skipped: i64,
    /// True when the scan QUERY failed. Every other hygiene query treats a
    /// failure as "no rows" (best-effort report), which for the twin scan
    /// would render as a complete-looking, clean "0 pairs" section — so
    /// this one flag travels to the report and the note owns the gap.
    ///
    /// Kept alongside `readings` rather than folded into it: this bool feeds
    /// the `workflow_twins.scan_failed` field an operator already reads and
    /// tests already pin. The ledger is the INDEX of what did not run; this is
    /// the one section that renders its own gap inline.
    pub workflow_graphs_scan_failed: bool,
    /// Which checks could not be measured, keyed by the report field they
    /// would have appeared under. Empty means every check ran.
    pub readings: talos_measurement::Readings,
}

impl HygieneReport {
    /// A report in which every check ran and found nothing, EXCEPT those
    /// `readings` records as unmeasured.
    ///
    /// The ledger is a required argument, deliberately: there is no way to
    /// construct an all-clear hygiene report without stating whether it is
    /// clear because nothing was found or clear because nothing was looked at.
    /// Same move as [`talos_measurement::Coverage::new`] requiring the cap and
    /// `EncryptedSecrets` losing its `Default` (structural lint check 17) — a
    /// type beats a lint, because a lint has to find you.
    #[must_use]
    pub fn empty(readings: talos_measurement::Readings) -> Self {
        let missing = |field: &str| readings.not_measured().contains(&field);
        Self {
            undescribed: Vec::new(),
            uncapabilized: Vec::new(),
            suppressed_count: (!missing("summary.suppressed_internal_test_workflows")).then_some(0),
            suppressed_low_score_count: (!missing("summary.suppressed_low_score_count"))
                .then_some(0),
            unembedded_count: (!missing("unembedded_workflow_count")).then_some(0),
            total_workflow_count: (!missing("summary.total_workflows")).then_some(0),
            orphaned_modules: Vec::new(),
            promotable_modules: Vec::new(),
            stale_executions: Vec::new(),
            dormant_workflows: Vec::new(),
            stale_draft_workflows: Vec::new(),
            idle_actors: Vec::new(),
            has_wildcard_module: (!missing("summary.wildcard_secret_grant")).then_some(false),
            wildcard_module_names: Vec::new(),
            orphaned_secrets: Vec::new(),
            secrets_without_expiry: Vec::new(),
            expiring_actor_memories: Vec::new(),
            workflows_needing_schema: Vec::new(),
            untyped_value_modules: Vec::new(),
            workflow_graphs: Vec::new(),
            workflow_graphs_truncated: false,
            workflow_graphs_skipped: 0,
            workflow_graphs_scan_failed: missing(HYGIENE_FIELD_TWINS),
            readings,
        }
    }
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

/// The reliability points a workflow would gain by executing up to the
/// 10-run saturation point, assuming EVERY added run succeeds.
///
/// Derived from [`compute_reliability_score`] rather than restated, so the
/// advice can never drift from the score it claims to move: the score is
/// `s · min(n/10, 1) · 50`, so after `10 − n` further all-successful runs the
/// window holds `s·n + (10 − n)` completions out of 10 and the score is
/// `50 − 5n(1 − s)`. The gain is therefore `50 − 5n`, independent of `s`.
///
/// The `s`-independence is the whole point of splitting this out. The pre-fix
/// advice said "Run N more times to reach **full** reliability credit", which
/// is FALSE for any `s < 1.0` — at `n = 5, s = 0.6` the caller who follows it
/// exactly lands on 40/50, not 50, and `5n(1 − s)` points stay unreachable by
/// running more. The number was right; the destination was not. Callers must
/// pair this with [`reliability_gain_from_success_rate`], which accounts for
/// exactly the remainder — the two are additive and sum to the full gap.
#[must_use]
pub fn reliability_gain_from_more_runs(exec_count: i64) -> f64 {
    if exec_count >= 10 {
        return 0.0;
    }
    50.0 * (1.0 - exec_count.max(0) as f64 / 10.0)
}

/// The reliability points currently forfeited to failures, at the CURRENT run
/// count.
///
/// `50 · (1 − s) · min(n/10, 1)`. Unlike the pre-fix `50 · (1 − s)`, this
/// carries the run-count ramp, so below the saturation point it does not claim
/// points the ramp is withholding anyway — at `n ≥ 10` the two are identical.
#[must_use]
pub fn reliability_gain_from_success_rate(success_rate: Option<f64>, exec_count: i64) -> f64 {
    let s = success_rate.unwrap_or(0.0).clamp(0.0, 1.0);
    50.0 * (1.0 - s) * (exec_count.max(0) as f64 / 10.0).min(1.0)
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
    fn groups_repeated_attributed_timeouts_of_the_same_node() {
        // The engine's wall-clock timeout now appends a node-attribution
        // clause whose numbers all move between runs. Two occurrences of
        // the SAME recurring failure must still land in one top-K bucket.
        let a = fingerprint_error_message(
            "workflow execution timed out after 420 seconds \
             (in flight: synthesize 411s; 4 nodes completed)",
        );
        let b = fingerprint_error_message(
            "workflow execution timed out after 420 seconds \
             (in flight: synthesize 409s; 5 nodes completed)",
        );
        assert_eq!(a, b, "same node, same failure — must share a fingerprint");
        // The node label is the diagnostic payload and must SURVIVE.
        assert!(a.contains("synthesize"), "{a}");
    }

    #[test]
    fn keeps_timeouts_on_different_nodes_in_different_buckets() {
        // The collapse must not over-group: "synthesize is slow" and
        // "fetch is slow" are different problems with different fixes.
        let a = fingerprint_error_message(
            "workflow execution timed out after 420 seconds \
             (in flight: synthesize 411s; 4 nodes completed)",
        );
        let b = fingerprint_error_message(
            "workflow execution timed out after 420 seconds \
             (in flight: fetch 411s; 4 nodes completed)",
        );
        assert_ne!(a, b);
    }

    #[test]
    fn collapses_the_in_flight_overflow_marker() {
        let a = fingerprint_error_message("(in flight: a 9s, +7 more; 3 nodes completed)");
        let b = fingerprint_error_message("(in flight: a 8s, +9 more; 4 nodes completed)");
        assert_eq!(a, b);
        assert!(a.contains("+N more"), "{a}");
    }

    #[test]
    fn bare_duration_collapse_does_not_eat_identifier_tails() {
        // `\b\d+(ms|s)\b` must not chew the end of a model/module name.
        let out = fingerprint_error_message("node 'qwen3.6-q4s' failed: boom");
        assert!(out.contains("qwen3.6-q4s"), "{out}");
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
                id: r.try_get("id")?,
                name: r.try_get("name")?,
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
        // `intent` is a JSONB column and `WorkflowFullRow::intent` is an
        // `Option<String>`, so it MUST be cast to text here exactly as
        // `graph_json` is two columns earlier. Without the cast, sqlx 0.8's
        // `Row::try_get` skips its type-compatibility check only when the
        // value is NULL (sqlx-core `row.rs`: `if !value.is_null() { … }`), so
        // every workflow with a still-NULL intent decoded fine and the
        // mismatch stayed invisible — while the FIRST workflow to register an
        // intent returned `ColumnDecode` and took the whole row read with it.
        // That surfaces as `get_workflow_risk_assessment` and
        // `get_readiness_breakdown` answering "Failed to fetch workflow", and
        // it made the risk tool's `no_intent` finding unfalsifiable: it could
        // only ever report "no intent registered", because registering one
        // broke the call that would have reported otherwise. Every other
        // crate reads this column as `Option<serde_json::Value>`; this row
        // type is the lone `Option<String>`, which is why only it needs the
        // cast.
        let row = sqlx::query(
            "SELECT id, name, graph_json::text AS graph_json, tags, description, \
                    max_concurrent_executions, capabilities, intent::text AS intent \
             FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(wf_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        row.map(|r| -> Result<WorkflowFullRow> {
            Ok(WorkflowFullRow {
                id: r.try_get("id")?,
                name: r.try_get("name")?,
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
             ORDER BY updated_at DESC, id DESC",
        )
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.into_iter()
            .map(|r| -> Result<WorkflowBasicRow> {
                Ok(WorkflowBasicRow {
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
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
             ORDER BY updated_at DESC, id DESC \
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
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
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
        rows.into_iter()
            .map(|r| -> Result<(Uuid, String)> { Ok((r.try_get("id")?, r.try_get("name")?)) })
            .collect::<Result<Vec<_>>>()
    }

    // -- Module/template lookups ------------------------------------------

    /// Phase 5.1: queries the unified modules table; canonical id only.
    pub async fn list_module_and_template_names(&self, ids: &[Uuid]) -> Result<Vec<ModuleNameRow>> {
        let rows = sqlx::query("SELECT id, name FROM modules WHERE id = ANY($1)")
            .bind(ids)
            .fetch_all(&self.db_pool)
            .await?;
        rows.into_iter()
            .map(|r| -> Result<ModuleNameRow> {
                Ok(ModuleNameRow {
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    // `check_template_ids_exist` / `check_module_ids_exist` were DELETED here
    // (2026-09-01) with the fleet-validator convergence. They were
    // BYTE-IDENTICAL to each other — both `SELECT id FROM modules WHERE id =
    // ANY($1)`, a survival of the pre-Phase-5.1 split between `node_templates`
    // and `wasm_modules` — and the fleet sweep, their only caller, ran BOTH on
    // every invocation, issuing the same query twice and unioning the two
    // identical results. It now uses `WorkflowRepository::modules_exist`, which
    // is a third copy of the same statement and is the one the shared validator
    // already used. Three spellings of one query is how a checker starts
    // disagreeing with itself; one is the point.

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
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
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
                    id: r.try_get("id")?,
                    workflow_id: r.try_get("workflow_id")?,
                    name: r.try_get("name")?,
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

    /// Workflows with failed executions in the last 24 hours, grouped by
    /// workflow, ordered by failure count. Unlike `get_failing_workflows`
    /// (which feeds the "currently failing" heuristic), this is a raw
    /// grouped rollup so a mass transient outage — many workflows each
    /// failing a few times — is visible on the dashboard.
    ///
    /// `latest_error_message` is the most recent non-null error among the
    /// group's failed runs (`ARRAY_AGG ... ORDER BY started_at DESC` with a
    /// NULL filter). Archived workflows are excluded — same predicate
    /// rationale as `get_failing_workflows` (only `archived` suppresses
    /// observability; `draft` does not).
    ///
    /// ORDER BY carries `w.id` as the deterministic tiebreaker (lint
    /// check 28 discipline). Capped at 10 rows.
    pub async fn get_top_failures_24h(&self, user_id: Uuid) -> Result<Vec<TopFailureRow>> {
        // RFC 0005 S3: self-scope (workflows + workflow_executions backstop).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let rows = sqlx::query(
            "SELECT w.id, w.name, \
                    COUNT(*)::bigint AS failed_count, \
                    MAX(we.started_at) AS last_failed_at, \
                    (ARRAY_AGG(we.error_message ORDER BY we.started_at DESC) \
                        FILTER (WHERE we.error_message IS NOT NULL))[1] AS latest_error_message \
             FROM workflows w \
             JOIN workflow_executions we ON we.workflow_id = w.id \
             WHERE w.user_id = $1 AND we.status = 'failed' \
               AND we.started_at > NOW() - INTERVAL '24 hours' \
               AND (w.status IS NULL OR w.status != 'archived') \
             GROUP BY w.id, w.name \
             ORDER BY failed_count DESC, w.id \
             LIMIT 10",
        )
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.into_iter()
            .map(|r| -> Result<TopFailureRow> {
                Ok(TopFailureRow {
                    workflow_id: r.try_get("id")?,
                    workflow_name: r.try_get("name")?,
                    failed_count: r.try_get::<Option<_>, _>("failed_count")?.unwrap_or(0),
                    last_failed_at: r.try_get::<Option<_>, _>("last_failed_at")?,
                    latest_error_message: r.try_get::<Option<_>, _>("latest_error_message")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    // -- Latency ----------------------------------------------------------

    /// Compact stats for SLA threshold evaluation: total execution count,
    /// completed count, and p95 latency over a time window. Used by the
    /// background SLA task in `main.rs` (formerly an inline query that
    /// duplicated the latency percentile logic from
    /// `get_latency_percentiles_ms`).
    ///
    /// **`None` means the query FAILED, not "no executions."** The docstring
    /// used to claim the opposite, and it was wrong for a structural reason:
    /// this is an UNGROUPED aggregate, so Postgres always returns exactly one
    /// row and `fetch_optional`'s `None` was unreachable. The empty window is
    /// `Some(SlaWindowStats { total: 0, .. })` — `total == 0` is the "no
    /// executions" signal. `fetch_one` makes that structural fact visible
    /// instead of leaving a `None` arm that reads as a handled case.
    ///
    /// `p95_ms` stays `Option<f64>`: a percentile over zero completed runs is
    /// genuinely absent and has no meaningful zero.
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
        .fetch_one(&self.db_pool)
        .await
        .ok();
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
                    id: r.try_get("id")?,
                    cron_expression: r.try_get("cron_expression")?,
                    is_enabled: r.try_get::<Option<_>, _>("is_enabled")?.unwrap_or(false),
                    // NOT NULL. A silent None was rendered as "UTC" by
                    // handle_get_schedule_health (analytics.rs:4776) — #661's
                    // exported-cron defect, one spelling over.
                    timezone: r.try_get::<Option<_>, _>("timezone")?,
                    last_triggered_at: r.try_get::<Option<_>, _>("last_triggered_at")?,
                    next_trigger_at: r.try_get::<Option<_>, _>("next_trigger_at")?,
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
                    id: r.try_get("id")?,
                    endpoint_path: r.try_get("endpoint_path")?,
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
                    id: r.try_get("id")?,
                    endpoint_path: r.try_get("endpoint_path")?,
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
                    id: r.try_get("id")?,
                    event_type: r.try_get("event_type")?,
                    description: r.try_get::<Option<_>, _>("description")?,
                    created_at: r.try_get("created_at")?,
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
                    id: r.try_get("id")?,
                    status: r.try_get("status")?,
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

    /// Global sibling of `get_error_messages_with_started_at`: failed-run
    /// error messages across ALL of the user's workflows in the window,
    /// most recent first. Feeds the platform-wide fingerprint rollup in
    /// `get_error_report` when no `workflow_id` is given.
    ///
    /// `id DESC` tiebreaker keeps ordering deterministic when many rows
    /// share a `started_at` (lint check 28 discipline).
    pub async fn get_error_messages_with_started_at_global(
        &self,
        user_id: Uuid,
        days: i32,
        limit: i64,
    ) -> Result<Vec<(String, DateTime<Utc>)>> {
        // RFC 0005 S3: self-scope (workflow_executions backstop).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let rows = sqlx::query(
            "SELECT error_message, started_at FROM workflow_executions \
             WHERE user_id = $1 AND status = 'failed' \
               AND error_message IS NOT NULL \
               AND started_at IS NOT NULL \
               AND started_at > NOW() - make_interval(days => $2::int) \
             ORDER BY started_at DESC, id DESC LIMIT $3",
        )
        .bind(user_id)
        .bind(days)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
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

    /// Per-workflow failure counts across ALL of the user's workflows in
    /// the window — the "which workflows are failing and how much" leg of
    /// the global error report. Ordered by failure count with `w.id` as
    /// the deterministic tiebreaker; caller-supplied `limit` must already
    /// be clamped at the handler boundary.
    pub async fn get_per_workflow_failure_counts(
        &self,
        user_id: Uuid,
        days: i32,
        limit: i64,
    ) -> Result<Vec<WorkflowFailureCountRow>> {
        // RFC 0005 S3: self-scope (workflows + workflow_executions backstop).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let rows = sqlx::query(
            "SELECT w.id, w.name, \
                    COUNT(*)::bigint AS failed_count, \
                    MAX(we.started_at) AS last_failed_at \
             FROM workflows w \
             JOIN workflow_executions we ON we.workflow_id = w.id \
             WHERE w.user_id = $1 AND we.status = 'failed' \
               AND we.started_at > NOW() - make_interval(days => $2::int) \
             GROUP BY w.id, w.name \
             ORDER BY failed_count DESC, w.id \
             LIMIT $3",
        )
        .bind(user_id)
        .bind(days)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.into_iter()
            .map(|r| -> Result<WorkflowFailureCountRow> {
                Ok(WorkflowFailureCountRow {
                    workflow_id: r.try_get("id")?,
                    workflow_name: r.try_get("name")?,
                    failed_count: r.try_get::<Option<_>, _>("failed_count")?.unwrap_or(0),
                    last_failed_at: r.try_get::<Option<_>, _>("last_failed_at")?,
                })
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
                    node_id: r.try_get("node_id")?,
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
                    node_id: r.try_get("node_id")?,
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
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
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
                    name: r.try_get("name")?,
                    key_path: r.try_get("key_path")?,
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
                name: r.try_get("name")?,
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
        // 2026-07-28 (measurement envelope, S1): the rate now ships with its
        // denominator. The scalar sub-SELECT became a LATERAL so BOTH the
        // rate and the count come from ONE pass over the same rows — a second
        // scalar subquery would have re-scanned, and a per-row follow-up query
        // would have been an N+1. The rate expression is copied UNCHANGED, so
        // `runs_30d` is exactly the denominator it divides by: rows of
        // `workflow_executions` whose `started_at` is inside the window, in
        // every status. (`started_at` is NOT NULL DEFAULT NOW(), i.e. stamped
        // at row creation, so queued-and-never-run executions are in the
        // denominator too — the population note on the handler says so.)
        //
        // Phase-2 review, same date, two structural fixes:
        //   * the candidate set is picked and LIMITed in a derived table, so
        //     the LATERAL is evaluated for at most the 20 rows that are
        //     actually returned rather than for every capability match. The
        //     old scalar subquery sat in the target list where the planner
        //     could defer it past the Limit; a join cannot be deferred, so
        //     without the derived table this would have been a per-candidate
        //     index scan on `workflow_executions`.
        //   * `readiness_score` ties (NULL is the common case) previously left
        //     the top-20 cut to heap order, so two identical calls could
        //     return DIFFERENT workflows on a surface that decides which
        //     workflow gets picked. `id` is the unique tiebreaker, applied to
        //     the LIMIT and to the final ordering (checks 28/60's principle).
        let rows = sqlx::query(
            "SELECT w.id, w.name, w.description, w.capabilities, w.readiness_score, \
                    e.success_rate, e.runs_30d \
             FROM ( \
                 SELECT id, name, description, capabilities, readiness_score \
                 FROM workflows \
                 WHERE user_id = $1 AND capabilities @> $2 \
                 ORDER BY readiness_score DESC NULLS LAST, id \
                 LIMIT 20 \
             ) w \
             LEFT JOIN LATERAL ( \
                 SELECT COUNT(*) FILTER (WHERE status = 'completed')::float / NULLIF(COUNT(*), 0) AS success_rate, \
                        COUNT(*)::bigint AS runs_30d \
                 FROM workflow_executions \
                 WHERE workflow_id = w.id AND started_at > NOW() - interval '30 days' \
             ) e ON TRUE \
             ORDER BY w.readiness_score DESC NULLS LAST, w.id",
        )
        .bind(user_id)
        .bind(capabilities)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<WorkflowCapabilityRow> {
                Ok(WorkflowCapabilityRow {
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
                    description: r.try_get::<Option<_>, _>("description")?,
                    capabilities: r.try_get::<Option<_>, _>("capabilities")?,
                    readiness_score: r.try_get::<Option<_>, _>("readiness_score")?,
                    success_rate: r.try_get::<Option<_>, _>("success_rate")?,
                    // A workflow with no executions in the window still gets
                    // a row from the LEFT JOIN LATERAL; COUNT(*) is 0 there,
                    // never NULL. Read as Option anyway so a schema drift
                    // surfaces as an error rather than a silent 0 (check 52).
                    runs_30d: r.try_get::<Option<i64>, _>("runs_30d")?.unwrap_or(0),
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
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
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
                    workflow_id: r.try_get("workflow_id")?,
                    name: r.try_get("name")?,
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
    ///
    /// **An aggregate over nothing is NULL, not 0.** Two shapes were wrong
    /// here until 2026-08-31, and both only bit on the COMMON case — a
    /// workflow with no auth failures:
    ///
    ///  * `MAX(started_at)` over zero matching rows returns NULL, but the
    ///    tuple decoded column 1 as `String`. So the query FAILED with
    ///    `unexpected null; try decoding as an Option` exactly when the answer
    ///    was "no auth failures" — measured on the live DB 2026-08-31 as 30 of
    ///    30 workflows. Before #704 the error was swallowed into `0`, which
    ///    was accidentally the RIGHT answer, so the break was invisible in
    ///    both directions: correct output, broken query. #704 made report
    ///    handlers disclose a failed read, which turned the latent bug into a
    ///    `report_field_not_measured` disclosure on nearly every
    ///    `get_workflow_risk_assessment` call. `last_failure` is now
    ///    `Option<String>`: a MAX has no meaningful zero, so the empty set has
    ///    to stay representable rather than be COALESCEd into a fake
    ///    timestamp.
    ///  * An UNGROUPED aggregate always returns exactly one row, so
    ///    `fetch_optional`'s `None` was unreachable and the caller's
    ///    `Some(Some(..))` match read as a handled case that could never fire.
    ///    `fetch_one` is the honest call; the real "no data" signal is
    ///    `count == 0` (the same idiom as
    ///    `ExecutionRepository::node_fuel_history`).
    ///
    /// Caller-visible behaviour is preserved: an empty window still means "0
    /// auth failures", now by a route that actually runs.
    pub async fn count_recent_auth_failures(
        &self,
        workflow_id: Uuid,
        days: i32,
    ) -> Result<(i64, Option<String>)> {
        let row: (i64, Option<String>) = sqlx::query_as(
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
        .fetch_one(&self.db_pool)
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

    /// Population-wide readiness aggregate, over the SAME filter predicate as
    /// [`Self::list_readiness_scores`] and deliberately WITHOUT its
    /// `ORDER BY`/`LIMIT`.
    ///
    /// The predicate is duplicated rather than shared because the two queries
    /// differ only in the clause that makes one of them a sample; keeping them
    /// textually adjacent is what makes a future divergence visible in review.
    /// `readiness_population_predicate_matches_the_list_query` pins them.
    ///
    /// Cost, measured on the reference deployment: 0.042 ms / 19 buffer hits,
    /// all cache hits. This is an interactive MCP operator tool, not a
    /// request-path query.
    pub async fn readiness_population(
        &self,
        user_id: Uuid,
        filter_ids: Option<&[Uuid]>,
        max_score: Option<i32>,
        include_archived: bool,
    ) -> Result<ReadinessPopulation> {
        let row = sqlx::query(
            "SELECT COUNT(*)::bigint AS total, \
                    AVG(COALESCE(readiness_score, 0))::float8 AS avg_score, \
                    COUNT(*) FILTER (WHERE COALESCE(readiness_score, 0) < 50)::bigint AS below_50, \
                    COUNT(*) FILTER (WHERE readiness_scored_at IS NULL)::bigint AS unscored \
             FROM workflows \
             WHERE user_id = $1 \
               AND ($2::uuid[] IS NULL OR id = ANY($2::uuid[])) \
               AND ($3::int IS NULL OR COALESCE(readiness_score, 0) <= $3) \
               AND ($4 OR status != 'archived')",
        )
        .bind(user_id)
        .bind(filter_ids)
        .bind(max_score)
        .bind(include_archived)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(ReadinessPopulation {
            total: row.try_get::<Option<i64>, _>("total")?.unwrap_or(0),
            // AVG() is NULL over zero rows — kept as None rather than
            // COALESCEd, per this crate's "unknown is not zero" doctrine.
            avg_score: row.try_get::<Option<f64>, _>("avg_score")?,
            below_50: row.try_get::<Option<i64>, _>("below_50")?.unwrap_or(0),
            unscored: row.try_get::<Option<i64>, _>("unscored")?.unwrap_or(0),
        })
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
        rows.iter()
            .map(|r| -> Result<RecentAlertSummaryRow> {
                Ok(RecentAlertSummaryRow {
                    workflow_name: r.try_get("workflow_name")?,
                    message: r.try_get("message")?,
                    occurrence_count: r.try_get("occurrence_count")?,
                    last_occurred_at: r.try_get("last_occurred_at")?,
                    acknowledged: r.try_get("acknowledged")?,
                })
            })
            .collect::<Result<Vec<_>>>()
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
                status: r.try_get("status")?,
                started_at: r.try_get::<Option<_>, _>("started_at")?,
                completed_at: r.try_get::<Option<_>, _>("completed_at")?,
                output_data: r.try_get::<Option<_>, _>("output_data")?,
                workflow_id: r.try_get("workflow_id")?,
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
                    event_type: r.try_get("event_type")?,
                    node_id: r.try_get::<Option<_>, _>("node_id")?,
                    created_at: r.try_get("created_at")?,
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
                id: r.try_get("id")?,
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
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
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
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
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
                    id: r.try_get("id")?,
                    cron_expression: r.try_get("cron_expression")?,
                    timezone: r.try_get::<Option<_>, _>("timezone")?,
                    workflow_name: r.try_get("workflow_name")?,
                    workflow_id: r.try_get("workflow_id")?,
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
                let status: String = r.try_get("status")?;
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

    /// Per-module facts the risk assessment needs, keyed by canonical id.
    ///
    /// Supersedes the older `get_risk_module_categories`, which returned only
    /// `(id, name, category)`. `category` is a display label (`"Network"`,
    /// `"Security"`, `"Communication"`) chosen by whoever authored the module
    /// row; it is NOT a statement about what the module may do. The retry
    /// check that consumed it was matching substrings of that label and of
    /// the module NAME to guess "is this an HTTP module", which is a proxy for
    /// `capability_world` + `allowed_methods` — the two columns
    /// `talos_workflow_engine_core::default_max_retries_for_module` actually
    /// reads. Both are returned here so the caller can ask the engine's own
    /// function instead of guessing. `name` and `category` stay for the
    /// findings that legitimately render a human label.
    pub async fn get_risk_module_facts(&self, module_ids: &[Uuid]) -> Result<Vec<RiskModuleFacts>> {
        // Phase 5.1: canonical id match on modules. Category prefers
        // persisted Phase 1.5 column, falls back to kind so sandbox/extracted
        // rows still surface sensibly.
        let rows = sqlx::query(
            "SELECT id, name, COALESCE(category, kind) AS category, \
                    capability_world, allowed_methods \
             FROM modules \
             WHERE id = ANY($1) \
             ORDER BY id",
        )
        .bind(module_ids)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<RiskModuleFacts> {
                Ok(RiskModuleFacts {
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
                    category: r.try_get::<Option<_>, _>("category")?,
                    capability_world: r.try_get::<Option<_>, _>("capability_world")?,
                    // NULL `allowed_methods` and `{}` are the SAME thing to
                    // `default_max_retries_for_module`: an empty slice is
                    // "declares no method restriction", which that function
                    // deliberately treats as NOT read-only.
                    allowed_methods: r
                        .try_get::<Option<Vec<String>>, _>("allowed_methods")?
                        .unwrap_or_default(),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Expiry facts for the secrets a workflow actually references, matched on
    /// `secrets.key_path` — the exact string a `vault://<path>` reference
    /// resolves against at dispatch and in the worker.
    ///
    /// The two secret-expiry risk findings previously answered a different
    /// question than the one they reported. `expiring_secret` listed EVERY
    /// secret of the caller's expiring inside 30 days and attributed all of
    /// them to whichever workflow was being assessed, with no link between the
    /// two; `secret_no_expiry` tested whether a secret's display NAME appeared
    /// as a case-insensitive substring anywhere in the raw `graph_json` text,
    /// which matches node labels, descriptions and URLs as readily as an
    /// actual reference. Both are answerable exactly, because the vault path
    /// carried in a node's config IS `secrets.key_path`.
    pub async fn get_risk_secret_expiry_for_paths(
        &self,
        user_id: Uuid,
        key_paths: &[String],
    ) -> Result<Vec<RiskSecretExpiry>> {
        if key_paths.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            "SELECT name, key_path, expires_at FROM secrets \
             WHERE created_by = $1 AND key_path = ANY($2) \
             ORDER BY key_path",
        )
        .bind(user_id)
        .bind(key_paths)
        .fetch_all(&self.db_pool)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<RiskSecretExpiry> {
                Ok(RiskSecretExpiry {
                    name: r.try_get("name")?,
                    key_path: r.try_get("key_path")?,
                    expires_at: r.try_get::<Option<_>, _>("expires_at")?,
                })
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
        rows.into_iter()
            .map(|r| -> Result<(Uuid, String)> {
                let id: Uuid = r.try_get("id")?;
                let name: String = r.try_get("name")?;
                Ok((id, name))
            })
            .collect::<Result<Vec<_>>>()
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

    // `get_risk_expiring_secrets` and `get_risk_no_expiry_secrets` were removed
    // in the 2026-08 risk-assessment audit. Both selected across ALL of a
    // user's secrets with no link to the workflow being assessed — the caller
    // then attributed the whole list to that workflow, or guessed at the link
    // by substring-matching a secret's display name against the raw graph
    // document. `get_risk_secret_expiry_for_paths` replaces both by joining on
    // `secrets.key_path`, which is exactly the string a `vault://` reference
    // resolves against.

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
        //
        // D6 (2026-07-29): the `, id` tiebreaker on this LIMIT 25 (and on the
        // uncapabilized twin below) is load-bearing, not tidiness. An
        // UNDESCRIBED workflow very often has a NULL readiness_score, so the
        // sort key is tied across most of the candidate set and Postgres
        // breaks the tie by heap order — two consecutive hygiene reports over
        // an unchanged database can list a DIFFERENT 25 workflows, and a
        // "fixed it" that only changed which rows made the cut is
        // indistinguishable from one that did. Same check-28/60 principle as
        // the readiness-routing cut at ~:2419.
        let undescribed_fut = async {
            let fetched = sqlx::query(
                "SELECT id, name, readiness_score, NULL::text AS description, created_at \
             FROM workflows \
             WHERE user_id = $1 AND is_enabled = true \
               AND (status IS NULL OR status != 'archived') \
               AND workflow_type IN ('production', 'template') \
               AND (description IS NULL OR description = '') \
               AND (readiness_score IS NULL OR readiness_score >= 10) \
             ORDER BY readiness_score DESC NULLS LAST, id LIMIT 25",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await;
            // The QUERY error is disclosed, not defaulted: an empty list must not
            // be able to mean "nobody asked". The ROW-MAPPING error below still
            // propagates with `?` (schema drift is loud, per check 52).
            let raw = match fetched {
                Ok(raw) => raw,
                Err(e) => return Ok(Err(e)),
            };
            let rows: Vec<HygieneWorkflowRow> = raw
                .into_iter()
                .map(|r| -> Result<HygieneWorkflowRow> {
                    Ok(HygieneWorkflowRow {
                        id: r.try_get("id")?,
                        name: r.try_get("name")?,
                        readiness_score: r.try_get::<Option<_>, _>("readiness_score")?,
                        description: r.try_get::<Option<_>, _>("description")?,
                        created_at: r.try_get("created_at")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Ok(rows))
        };

        // 2. Uncapabilized workflows (same `, id` tiebreaker rationale as #1).
        let uncapabilized_fut = async {
            let fetched = sqlx::query(
                "SELECT id, name, readiness_score, description, created_at \
             FROM workflows \
             WHERE user_id = $1 AND is_enabled = true \
               AND (status IS NULL OR status != 'archived') \
               AND workflow_type IN ('production', 'template') \
               AND (capabilities IS NULL OR array_length(capabilities, 1) IS NULL) \
               AND (readiness_score IS NULL OR readiness_score >= 10) \
             ORDER BY readiness_score DESC NULLS LAST, id LIMIT 25",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await;
            // The QUERY error is disclosed, not defaulted: an empty list must not
            // be able to mean "nobody asked". The ROW-MAPPING error below still
            // propagates with `?` (schema drift is loud, per check 52).
            let raw = match fetched {
                Ok(raw) => raw,
                Err(e) => return Ok(Err(e)),
            };
            let rows: Vec<HygieneWorkflowRow> = raw
                .into_iter()
                .map(|r| -> Result<HygieneWorkflowRow> {
                    Ok(HygieneWorkflowRow {
                        id: r.try_get("id")?,
                        name: r.try_get("name")?,
                        readiness_score: r.try_get::<Option<_>, _>("readiness_score")?,
                        description: r.try_get::<Option<_>, _>("description")?,
                        created_at: r.try_get("created_at")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Ok(rows))
        };

        // 3. Suppressed count (internal/test workflow types)
        let suppressed_count_fut = async {
            let v: Result<i64, sqlx::Error> = sqlx::query_scalar(
                "SELECT COUNT(*)::bigint FROM workflows \
             WHERE user_id = $1 AND is_enabled = true \
               AND (status IS NULL OR status != 'archived') \
               AND workflow_type IN ('internal', 'test')",
            )
            .bind(user_id)
            .fetch_one(&self.db_pool)
            .await;
            v
        };

        // 3b. Suppressed low-score count (drafts with readiness_score < 10 excluded from hygiene)
        let suppressed_low_score_count_fut = async {
            let v: Result<i64, sqlx::Error> = sqlx::query_scalar(
                "SELECT COUNT(*)::bigint FROM workflows \
             WHERE user_id = $1 AND is_enabled = true \
               AND (status IS NULL OR status != 'archived') \
               AND workflow_type IN ('production', 'template') \
               AND readiness_score < 10",
            )
            .bind(user_id)
            .fetch_one(&self.db_pool)
            .await;
            v
        };

        // 4. Unembedded count
        let unembedded_count_fut = async {
            let v: Result<i64, sqlx::Error> = sqlx::query_scalar(
                "SELECT COUNT(*)::bigint FROM workflows WHERE user_id = $1 AND embedding IS NULL",
            )
            .bind(user_id)
            .fetch_one(&self.db_pool)
            .await;
            v
        };

        // 5. Total workflow count
        let total_workflow_count_fut = async {
            let v: Result<i64, sqlx::Error> =
                sqlx::query_scalar("SELECT COUNT(*)::bigint FROM workflows WHERE user_id = $1")
                    .bind(user_id)
                    .fetch_one(&self.db_pool)
                    .await;
            v
        };

        // The ledger. Every check that could not be READ is recorded here
        // against the report key it would have been rendered under, so the
        // consumer can tell an empty list from an unasked question. The
        // upstream error is logged server-side by `Readings::record` and never
        // travels — a `sqlx::Error` routinely embeds the failing SQL, and a
        // connection error embeds the DSN.
        //
        // It is built HERE rather than passed in because the caller has
        // nothing to contribute to it and because this is the only layer that
        // ever sees the errors: the service downstream cannot leak what it was
        // never handed.
        let mut readings = talos_measurement::Readings::new();

        // Batch A — 6 independent count/list queries.
        #[allow(clippy::type_complexity)]
        let (
            undescribed,
            uncapabilized,
            suppressed_count,
            suppressed_low_score_count,
            unembedded_count,
            total_workflow_count,
        ): (
            anyhow::Result<SqlxResult<Vec<HygieneWorkflowRow>>>,
            anyhow::Result<SqlxResult<Vec<HygieneWorkflowRow>>>,
            SqlxResult<i64>,
            SqlxResult<i64>,
            SqlxResult<i64>,
            SqlxResult<i64>,
        ) = tokio::join!(
            undescribed_fut,
            uncapabilized_fut,
            suppressed_count_fut,
            suppressed_low_score_count_fut,
            unembedded_count_fut,
            total_workflow_count_fut,
        );
        let undescribed = readings.record_rows("undescribed_workflows", undescribed?);
        let uncapabilized = readings.record_rows("uncapabilized_workflows", uncapabilized?);
        let suppressed_count = readings.record(
            "summary.suppressed_internal_test_workflows",
            suppressed_count,
        );
        let suppressed_low_score_count = readings.record(
            "summary.suppressed_low_score_count",
            suppressed_low_score_count,
        );
        let unembedded_count = readings.record("unembedded_workflow_count", unembedded_count);
        let total_workflow_count = readings.record("summary.total_workflows", total_workflow_count);

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
            let fetched = sqlx::query(
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
            .await;
            // The QUERY error is disclosed, not defaulted: an empty list must not
            // be able to mean "nobody asked". The ROW-MAPPING error below still
            // propagates with `?` (schema drift is loud, per check 52).
            let raw = match fetched {
                Ok(raw) => raw,
                Err(e) => return Ok(Err(e)),
            };
            let rows: Vec<OrphanedModuleRow> = raw
                .into_iter()
                .map(|r| -> Result<OrphanedModuleRow> {
                    Ok(OrphanedModuleRow {
                        id: r.try_get("id")?,
                        name: r.try_get("name")?,
                        size_bytes: r.try_get::<Option<_>, _>("size_bytes")?,
                        compiled_at: r.try_get("compiled_at")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Ok(rows))
        };

        // 6b. Promotable modules — user-compiled (kind sandbox/extracted)
        // modules referenced by >=3 non-archived workflows. The inverse of the
        // orphaned query: high fan-out DB-resident modules are unmaintainable
        // black boxes (no version control, no shared fix), so surface them as
        // promote-to-template candidates. The correlated `graph_json LIKE` count
        // is a full scan like the orphaned query; capped + bounded by the user
        // scope. The alias can't be filtered in WHERE (Postgres), so the count
        // is computed in a subselect and filtered in the outer query.
        let promotable_modules_fut = async {
            let fetched = sqlx::query(
                "SELECT id, name, dependent_count FROM ( \
                     SELECT m.id, m.name, \
                            (SELECT COUNT(*) FROM workflows w \
                              WHERE w.user_id = $1 \
                                AND (w.status IS NULL OR w.status != 'archived') \
                                AND w.graph_json LIKE '%' || m.id::text || '%') AS dependent_count \
                       FROM modules m \
                      WHERE m.user_id = $1 \
                        AND m.kind IN ('sandbox', 'extracted') \
                        AND m.compiled_at IS NOT NULL \
                 ) sub \
                 WHERE dependent_count >= 3 \
                 ORDER BY dependent_count DESC LIMIT 25",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await;
            // The QUERY error is disclosed, not defaulted: an empty list must not
            // be able to mean "nobody asked". The ROW-MAPPING error below still
            // propagates with `?` (schema drift is loud, per check 52).
            let raw = match fetched {
                Ok(raw) => raw,
                Err(e) => return Ok(Err(e)),
            };
            let rows: Vec<PromotableModuleRow> = raw
                .into_iter()
                .map(|r| -> Result<PromotableModuleRow> {
                    Ok(PromotableModuleRow {
                        id: r.try_get("id")?,
                        name: r.try_get("name")?,
                        dependent_count: r.try_get("dependent_count")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Ok(rows))
        };

        // 7. Stale executions
        let stale_executions_fut = async {
            let fetched = sqlx::query(
                "SELECT we.id, we.workflow_id, w.name AS workflow_name, we.started_at, we.status \
             FROM workflow_executions we \
             JOIN workflows w ON w.id = we.workflow_id \
             WHERE we.user_id = $1 AND we.status IN ('running', 'queued', 'resuming') \
               AND we.started_at < NOW() - INTERVAL '2 hours' \
             ORDER BY we.started_at ASC LIMIT 25",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await;
            // The QUERY error is disclosed, not defaulted: an empty list must not
            // be able to mean "nobody asked". The ROW-MAPPING error below still
            // propagates with `?` (schema drift is loud, per check 52).
            let raw = match fetched {
                Ok(raw) => raw,
                Err(e) => return Ok(Err(e)),
            };
            let rows: Vec<StaleExecutionRow> = raw
                .into_iter()
                .map(|r| -> Result<StaleExecutionRow> {
                    Ok(StaleExecutionRow {
                        id: r.try_get("id")?,
                        workflow_id: r.try_get("workflow_id")?,
                        workflow_name: r.try_get("workflow_name")?,
                        started_at: r.try_get("started_at")?,
                        status: r.try_get("status")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Ok(rows))
        };

        // 8. Dormant workflows
        let dormant_workflows_fut = async {
            let fetched = sqlx::query(
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
            .await;
            // The QUERY error is disclosed, not defaulted: an empty list must not
            // be able to mean "nobody asked". The ROW-MAPPING error below still
            // propagates with `?` (schema drift is loud, per check 52).
            let raw = match fetched {
                Ok(raw) => raw,
                Err(e) => return Ok(Err(e)),
            };
            let rows: Vec<DormantWorkflowRow> = raw
                .into_iter()
                .map(|r| -> Result<DormantWorkflowRow> {
                    Ok(DormantWorkflowRow {
                        id: r.try_get("id")?,
                        name: r.try_get("name")?,
                        created_at: r.try_get("created_at")?,
                        last_execution: r.try_get::<Option<_>, _>("last_execution")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Ok(rows))
        };

        // 9. Stale draft workflows.
        // M-I: project graph_json so fix_all can run the
        // substantive-draft predicate before recommending deletion.
        let stale_draft_workflows_fut = async {
            let fetched = sqlx::query(
                "SELECT w.id, w.name, w.created_at, w.graph_json::text AS graph_json \
             FROM workflows w \
             WHERE w.user_id = $1 AND w.status = 'draft' \
               AND NOT EXISTS (SELECT 1 FROM workflow_executions we WHERE we.workflow_id = w.id) \
               AND w.created_at < NOW() - INTERVAL '7 days' \
             ORDER BY w.created_at ASC LIMIT 25",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await;
            // The QUERY error is disclosed, not defaulted: an empty list must not
            // be able to mean "nobody asked". The ROW-MAPPING error below still
            // propagates with `?` (schema drift is loud, per check 52).
            let raw = match fetched {
                Ok(raw) => raw,
                Err(e) => return Ok(Err(e)),
            };
            let rows: Vec<StaleDraftRow> = raw
                .into_iter()
                .map(|r| -> Result<StaleDraftRow> {
                    Ok(StaleDraftRow {
                        id: r.try_get("id")?,
                        name: r.try_get("name")?,
                        created_at: r.try_get("created_at")?,
                        graph_json: r.try_get::<Option<_>, _>("graph_json")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Ok(rows))
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
            let fetched = sqlx::query(
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
            .await;
            // The QUERY error is disclosed, not defaulted: an empty list must not
            // be able to mean "nobody asked". The ROW-MAPPING error below still
            // propagates with `?` (schema drift is loud, per check 52).
            let raw = match fetched {
                Ok(raw) => raw,
                Err(e) => return Ok(Err(e)),
            };
            let rows: Vec<IdleActorRow> = raw
                .into_iter()
                .map(|r| -> Result<IdleActorRow> {
                    Ok(IdleActorRow {
                        id: r.try_get("id")?,
                        name: r.try_get("name")?,
                        status: r.try_get("status")?,
                        last_active: r.try_get::<Option<_>, _>("last_active")?,
                        total_executions: r
                            .try_get::<Option<_>, _>("total_executions")?
                            .unwrap_or(0),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Ok(rows))
        };

        // 11. Wildcard module check + attribution
        // Phase 5: single SELECT on the unified `modules` table.
        let wildcard_module_names_fut = async {
            // BOTH failure modes — the query and the per-row `name` read — now
            // yield `Err`, which the join site records as unmeasured. Before,
            // the query error defaulted to `[]` and the drift error was logged
            // and then ALSO defaulted to `[]`: the loudest signal this check
            // could produce was a log line nobody holding the tool output can
            // see, under a response that said "no wildcard grants".
            let names: Result<Vec<String>, sqlx::Error> = async {
                sqlx::query(
                    "SELECT DISTINCT name FROM modules \
             WHERE user_id = $1 AND '*' = ANY(allowed_secrets) \
             ORDER BY name",
                )
                .bind(user_id)
                .fetch_all(&self.db_pool)
                .await?
                .iter()
                .map(|r| r.try_get::<String, _>("name"))
                .collect::<std::result::Result<Vec<String>, _>>()
            }
            .await;
            names
        };

        // Batch B — 6 independent list queries (orphaned modules, stale
        // executions, dormant/draft workflows, idle actors, wildcard
        // modules). #11 (wildcard) finishes here so its result gates #12
        // (orphaned_secrets) in Batch C below.
        let (
            orphaned_modules,
            promotable_modules,
            stale_executions,
            dormant_workflows,
            stale_draft_workflows,
            idle_actors,
            wildcard_module_names,
        ): (
            anyhow::Result<SqlxResult<Vec<OrphanedModuleRow>>>,
            anyhow::Result<SqlxResult<Vec<PromotableModuleRow>>>,
            anyhow::Result<SqlxResult<Vec<StaleExecutionRow>>>,
            anyhow::Result<SqlxResult<Vec<DormantWorkflowRow>>>,
            anyhow::Result<SqlxResult<Vec<StaleDraftRow>>>,
            anyhow::Result<SqlxResult<Vec<IdleActorRow>>>,
            SqlxResult<Vec<String>>,
        ) = tokio::join!(
            orphaned_modules_fut,
            promotable_modules_fut,
            stale_executions_fut,
            dormant_workflows_fut,
            stale_draft_workflows_fut,
            idle_actors_fut,
            wildcard_module_names_fut,
        );
        let orphaned_modules = readings.record_rows("orphaned_modules", orphaned_modules?);
        let promotable_modules = readings.record_rows("promotable_modules", promotable_modules?);
        let stale_executions = readings.record_rows("stale_executions", stale_executions?);
        let dormant_workflows = readings.record_rows("dormant_workflows", dormant_workflows?);
        let stale_draft_workflows =
            readings.record_rows("stale_draft_workflows", stale_draft_workflows?);
        let idle_actors = readings.record_rows("idle_actors", idle_actors?);
        // `None` (scan unreadable) is NOT `Some(false)` (scan ran, no wildcard
        // grant). Collapsing the two with `!names.is_empty()` is what let a
        // failed scan report "no module can read your whole vault".
        let wildcard_module_names =
            readings.record("summary.wildcard_secret_grant", wildcard_module_names);
        let has_wildcard_module = wildcard_verdict(wildcard_module_names.as_deref());
        let wildcard_module_names = wildcard_module_names.unwrap_or_default();

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
        //
        // A `None` wildcard verdict (the scan itself was unreadable) suppresses
        // the orphan list exactly like a `Some(true)` would, because an
        // unsuppressed list under an unknown wildcard grant is a list of
        // possible false positives pointed at a DELETE button. The suppression
        // is disclosed via `mark_derived` below rather than rendering as a
        // clean `[]`.
        let orphaned_secrets_fut = async {
            Ok(if has_wildcard_module == Some(false) {
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
                // FAIL CLOSED: a transient error on EITHER query must propagate,
                // never default to empty. An empty `grants` makes
                // `secret_path_in_any_grant` report EVERY secret as orphaned/
                // unused (the `empty_grants_means_orphan` semantics) — feeding
                // get_unused_secrets, an operator could then delete an in-use
                // secret during a DB hiccup. `[]` must mean "genuinely no
                // grants", not "the query failed".
                let secrets_rows = secrets_rows_res?;
                let grants: Vec<String> = grants_res?;

                secrets_rows
                    .into_iter()
                    .map(|r| -> anyhow::Result<Option<OrphanedSecretRow>> {
                        let key_path: String = r.try_get("key_path")?;
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
                                name: r.try_get("name")?,
                                key_path,
                                namespace: r.try_get::<Option<_>, _>("namespace")?,
                                created_at: r.try_get("created_at")?,
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
            // `oauth/%` is EXCLUDED deliberately (2026-07-26). The `%token%`
            // predicate matches every `oauth/<provider>/<user>/<acct>/
            // {access,refresh}_token` — precisely the credentials the platform
            // rotates ITSELF via `refresh_oauth_token`. Advising an operator to
            // hand-set an expiry on those is wrong twice over: the rotation
            // cadence this check exists to enforce is already automated, and a
            // manually-expired OAuth access token breaks the integration until
            // the next refresh. Before this exclusion the finding was 100%
            // OAuth on the reference deployment (14/14) — a check that can only
            // fire on the one credential class it does not apply to trains the
            // operator to ignore it, and takes the real signal (a static,
            // never-rotated API key / PAT) down with it.
            let fetched = sqlx::query(
                "SELECT name, key_path, created_at FROM secrets \
             WHERE created_by = $1 AND expires_at IS NULL \
               AND key_path NOT ILIKE 'oauth/%' \
               AND (key_path ILIKE '%key%' OR key_path ILIKE '%token%' OR key_path ILIKE '%api%' \
                    OR key_path ILIKE '%pat%' OR key_path ILIKE '%secret%') \
             ORDER BY created_at ASC LIMIT 25",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await;
            // The QUERY error is disclosed, not defaulted: an empty list must not
            // be able to mean "nobody asked". The ROW-MAPPING error below still
            // propagates with `?` (schema drift is loud, per check 52).
            let raw = match fetched {
                Ok(raw) => raw,
                Err(e) => return Ok(Err(e)),
            };
            let rows: Vec<SecretWithoutExpiryRow> = raw
                .into_iter()
                .map(|r| -> Result<SecretWithoutExpiryRow> {
                    Ok(SecretWithoutExpiryRow {
                        name: r.try_get("name")?,
                        key_path: r.try_get("key_path")?,
                        created_at: r.try_get("created_at")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Ok(rows))
        };

        // 14. Expiring actor memories
        let expiring_actor_memories_fut = async {
            let fetched = sqlx::query(
                "SELECT m.actor_id, m.key, m.memory_type, m.expires_at, a.name AS actor_name \
             FROM actor_memory m \
             JOIN actors a ON a.id = m.actor_id \
             WHERE a.user_id = $1 AND m.expires_at IS NOT NULL \
               AND m.expires_at > now() AND m.expires_at <= now() + interval '24 hours' \
             ORDER BY m.expires_at ASC LIMIT 50",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await;
            // The QUERY error is disclosed, not defaulted: an empty list must not
            // be able to mean "nobody asked". The ROW-MAPPING error below still
            // propagates with `?` (schema drift is loud, per check 52).
            let raw = match fetched {
                Ok(raw) => raw,
                Err(e) => return Ok(Err(e)),
            };
            let rows: Vec<ExpiringMemoryRow> = raw
                .into_iter()
                .map(|r| -> Result<ExpiringMemoryRow> {
                    Ok(ExpiringMemoryRow {
                        actor_id: r.try_get("actor_id")?,
                        key: r.try_get("key")?,
                        memory_type: r.try_get::<Option<_>, _>("memory_type")?,
                        expires_at: r.try_get("expires_at")?,
                        actor_name: r.try_get("actor_name")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Ok(rows))
        };

        // 15. Workflows needing schema
        let workflows_needing_schema_fut = async {
            let fetched = sqlx::query(
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
            .await;
            // The QUERY error is disclosed, not defaulted: an empty list must not
            // be able to mean "nobody asked". The ROW-MAPPING error below still
            // propagates with `?` (schema drift is loud, per check 52).
            let raw = match fetched {
                Ok(raw) => raw,
                Err(e) => return Ok(Err(e)),
            };
            let rows: Vec<NeedsSchemaRow> = raw
                .into_iter()
                .map(|r| -> Result<NeedsSchemaRow> {
                    Ok(NeedsSchemaRow {
                        id: r.try_get("id")?,
                        name: r.try_get("name")?,
                        execution_count: r.try_get::<Option<_>, _>("execution_count")?.unwrap_or(0),
                        last_run: r.try_get::<Option<_>, _>("last_run")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Ok(rows))
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
            let rows: Result<Vec<UntypedValueModuleRow>, sqlx::Error> =
                sqlx::query_as::<_, (Uuid, String)>(
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
                .map(|raw| {
                    raw.into_iter()
                        .map(|(id, name)| UntypedValueModuleRow { id, name })
                        .collect()
                });
            rows
        };

        // 17. Active workflow graphs — input to the twin-divergence scan
        // (`talos_hygiene_service::twin_divergence`). A defect fixed on one
        // instance of a duplicated workflow and not its twin is a real,
        // twice-observed incident class; the analyzer needs the graphs to
        // diff them, so this is the only hygiene query that pulls
        // `graph_json` bodies.
        //
        // Bounded four ways: user-scoped, LIMIT $2 rows (cap-hit reported
        // as `workflow_graphs_truncated`), a server-side per-graph size
        // guard — the CASE nulls out any graph over $3 bytes so an
        // oversized payload is COUNTED but never transferred or parsed —
        // and a client-side aggregate byte budget (the analyzer holds every
        // graph parsed at once, so 100 × the per-graph cap is the number
        // that matters for controller memory). Both drops land in the same
        // `workflow_graphs_skipped` counter the report discloses.
        // `ORDER BY name, id` is a total order (id breaks name ties), so
        // the cap window is stable across runs.
        let workflow_graphs_fut = async {
            let fetched = sqlx::query(
                "SELECT id, name, \
                        CASE WHEN octet_length(graph_json) <= $3 THEN graph_json END AS graph_json \
                   FROM workflows \
                  WHERE user_id = $1 \
                    AND (status IS NULL OR status != 'archived') \
                    AND graph_json IS NOT NULL \
                  ORDER BY name, id LIMIT $2",
            )
            .bind(user_id)
            .bind(TWIN_SCAN_GRAPH_LIMIT)
            .bind(TWIN_SCAN_MAX_GRAPH_BYTES)
            .fetch_all(&self.db_pool)
            .await;
            // The scan's own failure now travels TWICE, on purpose: as an
            // `Err` the join site records in the ledger (so the check appears
            // in `measurement.not_measured` alongside its siblings), and — via
            // the caller deriving `workflow_graphs_scan_failed` from it — as
            // the inline `workflow_twins.scan_failed` an operator already
            // reads. One mechanism, two renderings; not two mechanisms.
            let rows = match fetched {
                Ok(rows) => rows,
                Err(e) => return Ok(Err(e)),
            };
            let truncated = rows.len() as i64 >= TWIN_SCAN_GRAPH_LIMIT;
            let mut skipped: i64 = 0;
            let mut budget_remaining: i64 = TWIN_SCAN_TOTAL_BYTES;
            let mut graphs: Vec<TwinScanGraphRow> = Vec::with_capacity(rows.len());
            for r in rows {
                let graph_json: Option<String> = r.try_get::<Option<_>, _>("graph_json")?;
                let Some(graph_json) = graph_json else {
                    skipped += 1;
                    continue;
                };
                let len = graph_json.len() as i64;
                if len > budget_remaining {
                    skipped += 1;
                    continue;
                }
                budget_remaining -= len;
                graphs.push(TwinScanGraphRow {
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
                    graph_json,
                });
            }
            Ok(Ok((graphs, truncated, skipped)))
        };

        // Batch C — #12 (orphaned_secrets, gated on has_wildcard_module from
        // Batch B) plus 5 remaining independent queries (#13-#17). Six
        // futures, still well under the pool ceiling.
        let (
            orphaned_secrets,
            secrets_without_expiry,
            expiring_actor_memories,
            workflows_needing_schema,
            untyped_value_modules,
            workflow_graphs,
        ): (
            anyhow::Result<Vec<OrphanedSecretRow>>,
            anyhow::Result<SqlxResult<Vec<SecretWithoutExpiryRow>>>,
            anyhow::Result<SqlxResult<Vec<ExpiringMemoryRow>>>,
            anyhow::Result<SqlxResult<Vec<NeedsSchemaRow>>>,
            SqlxResult<Vec<UntypedValueModuleRow>>,
            anyhow::Result<SqlxResult<(Vec<TwinScanGraphRow>, bool, i64)>>,
        ) = tokio::join!(
            orphaned_secrets_fut,
            secrets_without_expiry_fut,
            expiring_actor_memories_fut,
            workflows_needing_schema_fut,
            untyped_value_modules_fut,
            workflow_graphs_fut,
        );
        // #12 stays FAIL-CLOSED and is deliberately NOT routed through the
        // ledger. Its documented hazard runs the other way: an empty `grants`
        // union makes `secret_path_in_any_grant` report EVERY secret as
        // orphaned, so `[]` must never be able to mean "the query failed". A
        // hard error is already distinguishable from an empty result here —
        // the caller gets an error, not a clean report — which is the property
        // this change is about. Left as it is, on purpose.
        let orphaned_secrets = orphaned_secrets?;
        if has_wildcard_module != Some(false) {
            // Suppressed, not measured: either a wildcard grant makes the
            // orphan predicate meaningless, or the wildcard scan itself could
            // not be read. Both render as `[]`, so both must be disclosed.
            readings.mark_derived("orphaned_secrets");
        }
        let secrets_without_expiry =
            readings.record_rows("secrets_without_expiry", secrets_without_expiry?);
        let expiring_actor_memories =
            readings.record_rows("expiring_actor_memories", expiring_actor_memories?);
        let workflows_needing_schema =
            readings.record_rows("workflows_needing_schema", workflows_needing_schema?);
        let untyped_value_modules =
            readings.record_rows("untyped_value_modules", untyped_value_modules);
        // Same fail-loud posture as the sibling futs: a `try_get` error here
        // is schema drift on `workflows.id/name/graph_json`, which every
        // other hygiene query reads too — surfacing it beats a silent
        // default (check 52).
        let workflow_graphs_scan = workflow_graphs?;
        let workflow_graphs_scan_failed = workflow_graphs_scan.is_err();
        let (workflow_graphs, workflow_graphs_truncated, workflow_graphs_skipped) = readings
            .record(HYGIENE_FIELD_TWINS, workflow_graphs_scan)
            .unwrap_or((Vec::new(), false, 0));

        Ok(HygieneReport {
            undescribed,
            uncapabilized,
            suppressed_count,
            suppressed_low_score_count,
            unembedded_count,
            total_workflow_count,
            orphaned_modules,
            promotable_modules,
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
            workflow_graphs,
            workflow_graphs_truncated,
            workflow_graphs_skipped,
            workflow_graphs_scan_failed,
            readings,
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
            Option<f64>,
            Option<i64>,
            Option<i64>,
            i64,
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
                PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY r.wall_time_ms) AS wall_p95, \
                PERCENTILE_CONT(0.95) WITHIN GROUP ( \
                    ORDER BY r.fuel_consumed::float8 \
                             / GREATEST(COALESCE(r.max_fuel, m.max_fuel), 1)::float8 \
                ) AS util_p95, \
                MIN(COALESCE(r.max_fuel, m.max_fuel)) AS ceil_min, \
                MAX(COALESCE(r.max_fuel, m.max_fuel)) AS ceil_max, \
                COUNT(*) FILTER (WHERE r.max_fuel IS NOT NULL) AS enforced_rows \
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
                |(
                    id,
                    name,
                    kind,
                    max_fuel,
                    execs,
                    p50,
                    p95,
                    fmax,
                    favg,
                    wp50,
                    wp95,
                    util,
                    cmin,
                    cmax,
                    enforced_rows,
                )| {
                    let row_fuel = max_fuel.unwrap_or(0);
                    ModuleFuelStats {
                        module_id: id,
                        module_name: name,
                        kind,
                        current_max_fuel: row_fuel,
                        // Clamped to [0, 1]: a completed run cannot consume more
                        // than the ceiling enforced FOR IT, so a value above 1
                        // means a NULL-ceiling row fell back to a module row
                        // smaller than the limit actually enforced. Clamping
                        // keeps the ">100% is impossible" invariant true at the
                        // API boundary instead of leaking the old symptom back.
                        utilisation_p95: util.unwrap_or(0.0).clamp(0.0, 1.0),
                        enforced_ceiling_min: cmin.unwrap_or(row_fuel),
                        enforced_ceiling_max: cmax.unwrap_or(row_fuel),
                        rows_with_enforced_ceiling: enforced_rows,
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

    /// Per-`(workflow, node)` fuel headroom over `days`, for the high-utilisation
    /// DETECTOR. Fleet-wide when `user_id` is `None` (the controller's gauge
    /// sweep), owner-scoped when `Some` (the MCP report).
    ///
    /// **No sample floor, deliberately** — see [`NodeFuelHeadroom`]. Every
    /// existing fuel surface in this platform hides a node that has run once or
    /// twice, and the node that motivated this had two samples.
    ///
    /// ## What the two numbers are, and why they come from different rows
    ///
    /// * `peak_fuel` = `MAX(fuel_consumed)` across the whole window — the worst
    ///   demand actually observed.
    /// * `current_ceiling` = `max_fuel` from the node's **most recent** row.
    ///
    /// Taking the ceiling from the latest row rather than maxing it, or taking a
    /// per-row `consumed/limit` ratio and maxing that, is the difference between
    /// a detector that clears when you fix it and one that stays red for a full
    /// window. Adaptive fuel raises ceilings over time, so a per-row max ratio
    /// keeps reporting a node's worst historical squeeze long after the squeeze
    /// is gone: measured on the live database 2026-08-17, per-row max ratio
    /// flagged three nodes at ≥80% of which two (`ops-critical-notifier/
    /// critical_notify_compose` 92.8%, `pa-weekly-report/send` 83.1%) were
    /// already fixed by a raised ceiling. A permanently-firing alert trains
    /// operators to ignore red, which is the same defect one level up.
    ///
    /// It also means **a config change alone does not clear this**. The ceiling
    /// read here is the limit a worker ENFORCED (the `__fuel_limit__` stamp), so
    /// raising `data.max_fuel` in the graph shows up only after the node next
    /// runs. That is the honest reading: an unexercised budget is not evidence.
    /// For a weekly workflow it means up to a week of continued firing.
    ///
    /// ## Test executions are EXCLUDED
    ///
    /// `test_workflow` writes rollup rows (`is_test_execution = true`), and a
    /// hand-crafted probe payload is traffic that never happened — counting it
    /// lets an author trip a production alert with a deliberate experiment. On
    /// the live database 34 of 77 qualifying pairs carry at least one test row,
    /// so this is not a rounding correction. The cost is a real false negative:
    /// a node that has ONLY ever run under test (1 pair of the 77) is invisible
    /// here — acceptable, because it has no production traffic to protect.
    ///
    /// The `workflow_executions` join is a LEFT join and the test predicate is
    /// `NOT COALESCE(we.is_test_execution, false)`, deliberately. A SUB-workflow
    /// run has no `workflow_executions` row at all (`execute_subworkflow_graph`
    /// seeds a synthetic execution id and detaches the event sink for exactly
    /// that reason), so an inner join silently deleted every sub-workflow node
    /// from the DETECTOR — 86 rollup rows over the last 30 days when this was
    /// measured, topped by a node sitting at 99.2% of its ceiling the day before
    /// it died of fuel exhaustion. A missing row now reads as "not a test",
    /// which is the correct reading for a sub-workflow and is the LOUD
    /// direction: the only way it can be wrong is by counting a sub-workflow
    /// dispatched from a `test_workflow` run as production traffic, which adds a
    /// warning rather than hiding one. (`is_test_execution` is not propagated
    /// into sub-engines; propagating it would be the way to close that, and is
    /// not worth a wire change to suppress a louder warning.)
    ///
    /// ## Bounds
    ///
    /// `LIMIT $N` on the aggregate (one row per pair). At 24k rollup rows the
    /// query plans as a seq scan over the window and measures ~33 ms; it runs
    /// once per sweep interval (300 s), so it is deliberately NOT given its own
    /// index — the fleet-wide form has no `workflow_id` predicate for
    /// `idx_cost_rollup_workflow` to serve, and an index earned by one caller
    /// every five minutes is not worth the write amplification on a hot
    /// insert path.
    pub async fn get_node_fuel_headroom(
        &self,
        user_id: Option<Uuid>,
        days: i32,
        limit: i64,
    ) -> Result<Vec<NodeFuelHeadroom>> {
        let rows = sqlx::query_as::<_, (Uuid, String, String, i64, i64, i64)>(
            "WITH scoped AS ( \
                SELECT r.workflow_id, r.node_id, r.fuel_consumed, r.max_fuel, r.recorded_at \
                FROM execution_cost_rollup r \
                LEFT JOIN workflow_executions we ON we.id = r.execution_id \
                JOIN workflows w ON w.id = r.workflow_id \
                WHERE r.recorded_at > NOW() - make_interval(days => $1::int) \
                  AND r.max_fuel > 0 \
                  AND r.fuel_consumed > 0 \
                  AND NOT COALESCE(we.is_test_execution, false) \
                  AND ($2::uuid IS NULL OR w.user_id = $2) \
             ), latest AS ( \
                SELECT DISTINCT ON (workflow_id, node_id) \
                       workflow_id, node_id, max_fuel AS current_ceiling \
                FROM scoped \
                ORDER BY workflow_id, node_id, recorded_at DESC, max_fuel DESC \
             ) \
             SELECT s.workflow_id, w.name, s.node_id, \
                    COUNT(*) AS samples, \
                    MAX(s.fuel_consumed) AS peak_fuel, \
                    l.current_ceiling \
             FROM scoped s \
             JOIN latest l ON l.workflow_id = s.workflow_id AND l.node_id = s.node_id \
             JOIN workflows w ON w.id = s.workflow_id \
             GROUP BY s.workflow_id, w.name, s.node_id, l.current_ceiling \
             ORDER BY MAX(s.fuel_consumed)::numeric / l.current_ceiling DESC, \
                      s.workflow_id, s.node_id \
             LIMIT $3",
        )
        .bind(days)
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(workflow_id, workflow_name, node_label, samples, peak_fuel, current_ceiling)| {
                    NodeFuelHeadroom {
                        workflow_id,
                        workflow_name,
                        node_label,
                        samples,
                        peak_fuel,
                        current_ceiling,
                    }
                },
            )
            .collect())
    }

    /// Nodes that DIED of fuel exhaustion in the last `days` days.
    ///
    /// # Why this is a second source and not another rollup query
    ///
    /// `execution_cost_rollup` is written from `on_node_completed` only, and
    /// only when the node's output carries `__fuel_consumed__ > 0`. A node
    /// killed by the fuel meter never completes and never produces that output,
    /// so **the exact event a fuel report exists to warn about is structurally
    /// absent from the table every other section of that report reads.** Adding
    /// a sample floor, a percentile, or a threshold to a rollup query cannot
    /// reach it; only a different source can.
    ///
    /// `dead_letter_queue` is that source. The engine's `on_node_failed` hook
    /// writes one row per terminal node failure carrying `(workflow_id,
    /// execution_id, node_id, error_message)` — the `(workflow, node)` unit that
    /// matters, and the error text is already DLP-scrubbed on the way in.
    /// `module_executions` was evaluated and rejected: measured on the live
    /// database, 84 fuel deaths were recorded in `dead_letter_queue` and only 2
    /// of them had a `module_executions` row saying `failed` — the rest were
    /// left `running` and later swept to `status = 'timeout'`, so a
    /// module-execution query reports 2 deaths where 84 happened.
    ///
    /// # Tenancy
    ///
    /// `dead_letter_queue` carries no owner column, so ownership is proved two
    /// ways and a row needs either: the DLQ row's `workflow_id` resolves to a
    /// workflow this user owns, OR a `module_executions` row for the same
    /// execution belongs to this user. The second arm is not redundant — a
    /// sub-workflow run stamped its rows with a synthetic id before the engine
    /// began setting one (`execute_subworkflow_graph`), so historical rows have
    /// a `workflow_id` that resolves to nothing at all. Dropping them for want
    /// of a join would mean the surface reported "no deaths" on the very
    /// incident that motivated it.
    ///
    /// # What is deliberately NOT returned
    ///
    /// The raw `error_message` never leaves this function. Only the parsed
    /// integer ceiling does. DLQ text is scrubbed, but it is still a
    /// worker-authored string, and a fuel report has no need of prose.
    pub async fn get_fuel_exhaustion_deaths(
        &self,
        user_id: Uuid,
        days: i32,
        limit: i64,
    ) -> Result<Vec<FuelExhaustionDeath>> {
        // The SQL predicate is a deliberate SUPERSET of the classifier's, not a
        // copy of it: `FUEL_MESSAGE_PREFILTER` is one token that every phrase
        // the canonical classifier maps to `fuel_exhaustion` contains, and the
        // authority on whether a row IS a fuel death remains
        // `talos_retry_intelligence::classify_error` below. Duplicating the
        // classifier's phrase list in SQL is how the two drift apart;
        // `the_sql_prefilter_is_a_superset_of_the_classifier` pins the
        // relationship.
        let rows = sqlx::query(
            "SELECT d.workflow_id, w.name AS workflow_name, d.node_id, d.execution_id, \
                    d.created_at, d.error_message \
               FROM dead_letter_queue d \
               LEFT JOIN workflows w ON w.id = d.workflow_id \
              WHERE d.created_at > NOW() - make_interval(days => $2::int) \
                AND d.error_message ILIKE $4 \
                AND ( w.user_id = $1 \
                      OR EXISTS ( SELECT 1 FROM module_executions me \
                                   WHERE me.workflow_execution_id = d.execution_id \
                                     AND me.user_id = $1 ) ) \
              ORDER BY d.created_at DESC, d.id \
              LIMIT $3",
        )
        .bind(user_id)
        .bind(days)
        .bind(limit)
        .bind(format!("%{FUEL_MESSAGE_PREFILTER}%"))
        .fetch_all(&self.db_pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let error_message: String = r.try_get("error_message")?;
            if talos_retry_intelligence::classify_error(&error_message) != FUEL_EXHAUSTION_CLASS {
                continue;
            }
            out.push(FuelExhaustionDeath {
                workflow_id: r.try_get("workflow_id")?,
                workflow_name: r.try_get::<Option<String>, _>("workflow_name")?,
                node_uuid: r.try_get("node_id")?,
                execution_id: r.try_get("execution_id")?,
                occurred_at: r.try_get("created_at")?,
                enforced_limit: parse_enforced_fuel_limit(&error_message),
            });
        }
        Ok(out)
    }

    /// Every module-backed node in the caller's workflow graphs, with the fuel
    /// ceiling it would run under.
    ///
    /// This is the only fuel surface that does not depend on execution history,
    /// which is the point: it can name a node that is about to die instead of
    /// one that already has. A node inherits `modules.max_fuel` unless its
    /// graph `data.max_fuel` overrides it, so a module shared by several
    /// workflows can be correctly sized in one and starved in another — and the
    /// per-MODULE half of the fuel report, which groups by `modules.id`, cannot
    /// express that as anything but one averaged number.
    ///
    /// Both fuel deaths on the live database when this was written were exactly
    /// that shape: the dead node was the one running at the module default
    /// while its siblings carried a large per-node override.
    ///
    /// Bounded the same four ways as the hygiene twin scan (user-scoped,
    /// [`NODE_BUDGET_GRAPH_LIMIT`] rows, a server-side per-graph byte guard, and
    /// a client-side aggregate budget); the returned [`Coverage`] carries the
    /// cap so a short answer can never read as a complete one.
    pub async fn get_node_budgets(
        &self,
        user_id: Uuid,
    ) -> Result<(Vec<NodeBudgetRow>, talos_measurement::Coverage)> {
        let graph_rows = sqlx::query(
            "SELECT id, name, \
                    CASE WHEN octet_length(graph_json) <= $3 THEN graph_json END AS graph_json \
               FROM workflows \
              WHERE user_id = $1 \
                AND (status IS NULL OR status != 'archived') \
                AND graph_json IS NOT NULL \
              ORDER BY name, id LIMIT $2",
        )
        .bind(user_id)
        .bind(NODE_BUDGET_GRAPH_LIMIT)
        .bind(TWIN_SCAN_MAX_GRAPH_BYTES)
        .fetch_all(&self.db_pool)
        .await?;

        let coverage =
            talos_measurement::Coverage::new(graph_rows.len() as i64, NODE_BUDGET_GRAPH_LIMIT);

        // (workflow_id, workflow_name, node graph id, module id, node override)
        let mut pending: Vec<(Uuid, String, String, Uuid, Option<i64>)> = Vec::new();
        let mut module_ids: Vec<Uuid> = Vec::new();
        let mut budget_remaining: i64 = TWIN_SCAN_TOTAL_BYTES;
        for r in graph_rows {
            let Some(graph_json) = r.try_get::<Option<String>, _>("graph_json")? else {
                continue;
            };
            let len = graph_json.len() as i64;
            if len > budget_remaining {
                continue;
            }
            budget_remaining -= len;
            let wf_id: Uuid = r.try_get("id")?;
            let wf_name: String = r.try_get("name")?;
            // Fail-soft per graph: a malformed body must not sink the report.
            let Ok(graph) = serde_json::from_str::<serde_json::Value>(&graph_json) else {
                continue;
            };
            let Some(nodes) = graph.get("nodes").and_then(serde_json::Value::as_array) else {
                continue;
            };
            for node in nodes.iter().take(NODE_BUDGET_NODES_PER_GRAPH) {
                let Some(node_id) = node.get("id").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                // A graph node's `type` is the module uuid for module-backed
                // nodes and a system-node keyword otherwise; the parse is the
                // discriminator, and a system node has no tunable budget.
                let Some(module_id) = node
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|t| Uuid::parse_str(t).ok())
                else {
                    continue;
                };
                let node_max_fuel = node
                    .get("data")
                    .and_then(|d| d.get("max_fuel"))
                    .and_then(serde_json::Value::as_i64)
                    .filter(|v| *v > 0);
                if !module_ids.contains(&module_id) {
                    module_ids.push(module_id);
                }
                pending.push((
                    wf_id,
                    wf_name.clone(),
                    node_id.to_string(),
                    module_id,
                    node_max_fuel,
                ));
            }
        }

        // One batched read for every referenced module — never one per node.
        let mut modules: std::collections::HashMap<Uuid, (String, Option<i64>)> =
            std::collections::HashMap::new();
        if !module_ids.is_empty() {
            let module_rows =
                sqlx::query("SELECT id, name, max_fuel FROM modules WHERE id = ANY($1)")
                    .bind(&module_ids)
                    .fetch_all(&self.db_pool)
                    .await?;
            for r in module_rows {
                let id: Uuid = r.try_get("id")?;
                let name: String = r.try_get("name")?;
                let max_fuel: Option<i64> = r.try_get("max_fuel")?;
                modules.insert(id, (name, max_fuel));
            }
        }

        let out = pending
            .into_iter()
            .filter_map(
                |(workflow_id, workflow_name, node_id, module_id, node_max_fuel)| {
                    // A node whose module row is gone is not a budget we can reason
                    // about — it cannot run at all.
                    let (module_name, module_max_fuel) = modules.get(&module_id)?.clone();
                    Some(NodeBudgetRow {
                        workflow_id,
                        workflow_name,
                        node_id,
                        module_id,
                        module_name,
                        node_max_fuel,
                        module_max_fuel,
                    })
                },
            )
            .collect();
        Ok((out, coverage))
    }

    /// Per-node fuel-consumption stats for ONE workflow, aggregated across its
    /// recent executions. Powers the adaptive-fuel learned ceiling (Phase 2).
    ///
    /// Scoped by `workflow_id` (the tenant boundary — a workflow belongs to one
    /// owner) with the `workflows` join kept as the RLS backstop for when the
    /// per-tenant policy lands. `min_executions` gates out nodes with too few
    /// samples to trust a percentile; zero-fuel structural nodes (collect/loop
    /// scaffolding) are excluded. Returns at most one row per distinct node
    /// label — small and index-served via `idx_cost_rollup_workflow`.
    pub async fn get_workflow_node_fuel_stats(
        &self,
        workflow_id: Uuid,
        days: i32,
        min_executions: i64,
    ) -> Result<Vec<NodeFuelStat>> {
        let rows = sqlx::query_as::<_, (String, i64, Option<f64>, Option<i64>)>(
            "SELECT \
                r.node_id, \
                COUNT(*) AS executions, \
                PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY r.fuel_consumed) AS fuel_p95, \
                MAX(r.fuel_consumed) AS fuel_max \
             FROM execution_cost_rollup r \
             JOIN workflows w ON w.id = r.workflow_id \
             WHERE r.workflow_id = $1 \
               AND r.recorded_at > NOW() - make_interval(days => $2::int) \
               AND r.fuel_consumed > 0 \
             GROUP BY r.node_id \
             HAVING COUNT(*) >= $3",
        )
        .bind(workflow_id)
        .bind(days)
        .bind(min_executions)
        .fetch_all(&self.db_pool)
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(|(node_label, executions, p95, fmax)| {
                // PERCENTILE_CONT / MAX are non-negative here (fuel_consumed > 0),
                // but clamp defensively before the u64 cast.
                let fuel_p95 = p95.unwrap_or(0.0).max(0.0) as u64;
                let fuel_max = i64::max(fmax.unwrap_or(0), 0) as u64;
                if fuel_max == 0 {
                    return None;
                }
                Some(NodeFuelStat {
                    node_label,
                    executions,
                    fuel_p95,
                    fuel_max,
                })
            })
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

    /// When migration `20260905120000_updated_at_is_not_a_maintenance_clock` was
    /// APPLIED to this database — the instant after which `workflows.updated_at`
    /// means "a user edited this row" rather than "a background job touched it".
    ///
    /// `Ok(None)` means the migration is not applied here (a genuine answer, not
    /// a failure). An `Err` is propagated rather than flattened: the caller
    /// treats "cannot determine" as "assume pre-cutover", and it must be able to
    /// tell that apart from "definitely not applied".
    pub async fn maintenance_clock_cutover(
        &self,
        migration_version: i64,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
        Ok(sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
            "SELECT installed_on FROM _sqlx_migrations WHERE version = $1",
        )
        .bind(migration_version)
        .fetch_optional(&self.db_pool)
        .await?)
    }
}

/// Structural pin on the capability-routing query (Phase-2 review, 2026-07-28).
///
/// `get_workflows_by_capability` has no unit coverage — the only tests are on
/// the pure JSON renderer in `talos-mcp-handlers`, which takes the row as a
/// given. So the two properties that make `runs_30d` HONEST live only in the
/// SQL text: it must be the SAME `COUNT(*)` the rate divides by, over the SAME
/// predicate, in the SAME subquery. Silently changing either one (a status
/// filter on the count, a different window on the rate) would leave every test
/// green while the row started claiming a denominator it does not have.
/// #726: the hygiene sweep's read outcomes must be DISCLOSED, not defaulted.
///
/// The pre-fix function collapsed every query error into `.unwrap_or_default()`
/// / `.unwrap_or(0)` and said so in its own comment, so a database outage
/// produced fifteen empty lists, `total_issues: 0` and an empty
/// `recommendations` — "your platform is clean", from zero measurements. The
/// `tokio::join!` (not `try_join!`) design is correct and is preserved; what
/// was missing is that the partial-ness was invisible.
///
/// These are SOURCE pins because `get_hygiene_report` needs Postgres. The
/// BEHAVIOUR of the disclosure is driven end-to-end against the real
/// production assembly function in `talos_hygiene_service::build_report`'s
/// test module, which is pure. The division is deliberate: a pin can prove the
/// swallow is gone from the wiring, and only a behavioural test can prove the
/// report then says the right thing.
#[cfg(test)]
mod hygiene_disclosure_pins {
    use super::{
        HygieneCheck, HygieneReport, EXPIRING_MEMORY_LIMIT, HYGIENE_CHECKS, HYGIENE_FIELD_TWINS,
        HYGIENE_FINDING_LIMIT, NEEDS_SCHEMA_LIMIT, ORPHAN_SECRET_SCAN_LIMIT, TWIN_SCAN_GRAPH_LIMIT,
    };

    /// The body of `get_hygiene_report`, from its signature to the next
    /// `pub async fn`. Scoping matters: this file has ~180 other queries and a
    /// whole-file grep would be answering a different question.
    fn sweep_body() -> &'static str {
        let src = include_str!("lib.rs");
        let start = src
            .find(concat!("pub async fn ", "get_hygiene_report"))
            .expect("the hygiene sweep still exists");
        let rest = &src[start + 20..];
        let end = rest
            .find("\n    pub async fn ")
            .expect("the sweep is followed by another method");
        &rest[..end]
    }

    /// The defect, stated as a shape: an awaited read followed by a benign
    /// default. This is structural lint check 74's regex, applied to the crate
    /// the lint cannot see (74/74b are scoped to `talos-mcp-handlers/src` and
    /// `talos-api/src`, so neither leg has ever looked at this function).
    ///
    /// FAILS on the pre-#726 tree at 15 sites; passes here at 0.
    #[test]
    fn the_sweep_never_defaults_a_failed_query() {
        let body = sweep_body();
        let mut offenders: Vec<String> = Vec::new();
        let lines: Vec<&str> = body.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            // Same-line form, and the split form the house style actually uses
            // (`.await` at the end of one line, `.unwrap_or*` opening the next).
            let same_line = t.contains(".await.unwrap_or");
            let split = t.ends_with(".await")
                && lines
                    .get(i + 1)
                    .is_some_and(|n| n.trim_start().starts_with(".unwrap_or"));
            if same_line || split {
                offenders.push(format!("line {}: {t}", i + 1));
            }
        }
        assert!(
            offenders.is_empty(),
            "a hygiene query is defaulting its own failure again — an empty list would once more \
             be indistinguishable from an unasked question:\n{}",
            offenders.join("\n")
        );
    }

    /// Every check the sweep records must be in [`HYGIENE_CHECKS`], and every
    /// entry in the table must be recorded by the sweep.
    ///
    /// This is the anti-drift guard that matters: a check added without a table
    /// entry has a cap nobody discloses, and a table entry nothing records is a
    /// name the report will never use. Both directions fail.
    #[test]
    fn the_check_table_matches_what_the_sweep_records() {
        let body = sweep_body();
        let mut recorded: Vec<String> = Vec::new();
        // The `readings.` receiver is deliberately NOT part of the needle:
        // rustfmt breaks the chain onto its own line for the longer calls, and
        // a needle that assumes one formatting is a pin that a `cargo fmt` can
        // silently disarm.
        for marker in [
            concat!(".", "record_rows("),
            concat!(".", "record("),
            concat!(".", "mark_derived("),
        ] {
            let mut from = 0usize;
            while let Some(i) = body[from..].find(marker) {
                let at = from + i + marker.len();
                // rustfmt breaks a long call across lines, so the first
                // argument may start on the next one.
                let arg = body[at..].trim_start();
                from = at;
                let Some(rest) = arg.strip_prefix('"') else {
                    continue; // a non-literal first argument (HYGIENE_FIELD_TWINS)
                };
                let end = rest.find('"').expect("a closing quote");
                recorded.push(rest[..end].to_string());
            }
        }
        // The twin scan is recorded under the exported constant rather than a
        // literal, precisely so the one check whose finding list is not named
        // after its own query cannot drift.
        assert!(
            body.contains(concat!(".", "record(HYGIENE_FIELD_TWINS")),
            "the twin scan must be recorded under HYGIENE_FIELD_TWINS"
        );
        recorded.push(HYGIENE_FIELD_TWINS.to_string());

        let table: Vec<&str> = HYGIENE_CHECKS.iter().map(|c| c.field).collect();
        for r in &recorded {
            assert!(
                table.contains(&r.as_str()),
                "the sweep records `{r}` but HYGIENE_CHECKS does not list it, so its cap is \
                 undisclosed and the coverage block cannot see it"
            );
        }
        for t in &table {
            assert!(
                recorded.iter().any(|r| r == t),
                "HYGIENE_CHECKS lists `{t}` but nothing in the sweep records it, so a failure \
                 of that check would still be invisible"
            );
        }
        assert_eq!(
            recorded.len(),
            HYGIENE_CHECKS.len(),
            "one check is recorded twice, or the table has a duplicate"
        );
    }

    /// A cap that is not the cap in force is a disclosure that names the wrong
    /// ceiling — this bug class one level up, which is exactly what
    /// `hygiene_finding_limit_matches_the_sql_literals` already says about the
    /// one constant that existed before. There are THREE distinct caps plus
    /// two uncapped reads, so each is anchored to the query that owns it.
    #[test]
    fn hygiene_check_caps_match_the_sql_literals() {
        let body = sweep_body();
        // Needles are `concat!`-assembled so this test's own text is not a match.
        for (anchor, cap) in [
            (
                concat!("ORDER BY readiness_score DESC NULLS LAST, id", " LIMIT "),
                HYGIENE_FINDING_LIMIT,
            ),
            (
                concat!("ORDER BY m.compiled_at DESC", " LIMIT "),
                HYGIENE_FINDING_LIMIT,
            ),
            (
                concat!("ORDER BY dependent_count DESC", " LIMIT "),
                HYGIENE_FINDING_LIMIT,
            ),
            (
                concat!("ORDER BY we.started_at ASC", " LIMIT "),
                HYGIENE_FINDING_LIMIT,
            ),
            (
                concat!("ORDER BY m.expires_at ASC", " LIMIT "),
                EXPIRING_MEMORY_LIMIT,
            ),
            (
                concat!("ORDER BY COUNT(e.id) DESC", " LIMIT "),
                NEEDS_SCHEMA_LIMIT,
            ),
            (
                concat!("ORDER BY s.created_at ASC", " LIMIT "),
                ORPHAN_SECRET_SCAN_LIMIT,
            ),
        ] {
            let needle = format!("{anchor}{cap}");
            assert!(
                body.contains(&needle),
                "no hygiene query runs `{needle}` any more; a cap constant and its SQL literal \
                 have drifted, so summary.coverage.caps now names a ceiling that is not in force"
            );
        }
        // The twin scan binds its cap rather than inlining it.
        assert!(
            body.contains(concat!(".bind(", "TWIN_SCAN_GRAPH_LIMIT)")),
            "the twin scan must bind TWIN_SCAN_GRAPH_LIMIT"
        );
        assert_eq!(
            HYGIENE_CHECKS
                .iter()
                .find(|c| c.field == HYGIENE_FIELD_TWINS)
                .map(|c| c.cap),
            Some(TWIN_SCAN_GRAPH_LIMIT)
        );
        // And the orphaned-secrets OUTPUT cap is a Rust `take`, not SQL — the
        // 200 above is a second, upstream ceiling on what is even examined.
        assert!(
            body.contains(&format!(".take({HYGIENE_FINDING_LIMIT})")),
            "the orphaned-secrets list no longer takes HYGIENE_FINDING_LIMIT"
        );
    }

    /// A cap of `0` in the table is a CLAIM that the read is unbounded. If one
    /// of those queries grows a LIMIT, the coverage block will report
    /// `complete` over a truncated list — absence reading as completeness,
    /// which is the whole defect class.
    #[test]
    fn the_uncapped_checks_really_are_uncapped() {
        let body = sweep_body();
        for (name, anchor) in [
            ("idle_actors", "ORDER BY last_active ASC NULLS FIRST"),
            ("untyped_value_modules", "position('from_str(&input)'"),
        ] {
            assert_eq!(
                HYGIENE_CHECKS
                    .iter()
                    .find(|c| c.field == name)
                    .map(|c| c.cap),
                Some(0),
                "{name} is declared capped but the table says otherwise"
            );
            let at = body.find(anchor).unwrap_or_else(|| {
                panic!("the {name} query no longer contains its anchor `{anchor}`")
            });
            // The query text ends at the closing `",` of the SQL literal.
            let tail_end = body[at..].find("\",").expect("the SQL literal is closed");
            assert!(
                !body[at..at + tail_end].contains("LIMIT"),
                "the {name} query grew a LIMIT but HYGIENE_CHECKS still declares it uncapped, so \
                 summary.coverage would call a truncated list complete"
            );
        }
    }

    /// [`HygieneReport::empty`] must not be able to manufacture an all-clear
    /// report: the ledger is a required argument, and the fields it names come
    /// back as `None`/`true` rather than as reassuring defaults.
    #[test]
    fn an_empty_report_inherits_its_ledger() {
        let clean = HygieneReport::empty(talos_measurement::Readings::new());
        assert_eq!(clean.total_workflow_count, Some(0));
        assert_eq!(clean.has_wildcard_module, Some(false));
        assert!(!clean.workflow_graphs_scan_failed);
        assert!(clean.readings.complete());

        let mut degraded = talos_measurement::Readings::new();
        degraded.mark_derived("summary.total_workflows");
        degraded.mark_derived("summary.wildcard_secret_grant");
        degraded.mark_derived(HYGIENE_FIELD_TWINS);
        let r = HygieneReport::empty(degraded);
        assert_eq!(
            r.total_workflow_count, None,
            "an unread workflow count must be null, never 0 — 0 is a denominator"
        );
        assert_eq!(
            r.has_wildcard_module, None,
            "an unread wildcard scan must not report `no wildcard grant`"
        );
        assert!(r.workflow_graphs_scan_failed);
        assert_eq!(
            r.suppressed_count,
            Some(0),
            "unrelated checks are unaffected"
        );
    }

    /// The ledger the sweep FILLS must be the ledger the report CARRIES.
    ///
    /// Written because the obvious mutation — `readings: Readings::new()` in
    /// the returned struct literal — left every other test in this change
    /// green: the behavioural tests construct a `HygieneReport` directly, so
    /// none of them can see the wiring. A guard that cannot fail on the wiring
    /// it guards is the class this whole change is about, one level up.
    #[test]
    fn the_returned_report_carries_the_ledger_the_sweep_filled() {
        let body = sweep_body();
        assert_eq!(
            body.matches(concat!("Readings", "::new()")).count(),
            1,
            "the sweep constructs more than one ledger, so at least one of them is being \
             discarded — the report would then claim every check ran"
        );
        // Field-init shorthand: anything else is a different value.
        assert!(
            body.contains("\n            readings,\n"),
            "the returned HygieneReport no longer uses the field-init shorthand for `readings`, \
             so it may be carrying a ledger other than the one the sweep filled"
        );
    }

    /// The wildcard collapse must go through the one pure function that is
    /// actually unit-tested. Same reason: the sweep is DB-bound, so an inline
    /// `map(|n| !n.is_empty())` here is unreachable by any test.
    #[test]
    fn the_wildcard_verdict_has_one_implementation() {
        let body = sweep_body();
        assert!(
            body.contains(concat!("wildcard_verdict", "(wildcard_module_names")),
            "the sweep stopped routing the wildcard scan through `wildcard_verdict`; an inline \
             collapse there cannot be tested and turns an unread scan into a security all-clear"
        );
        assert!(
            !body.contains(concat!("map(|n| !n.", "is_empty())")),
            "an inline wildcard collapse is back in the sweep"
        );
    }

    /// The three states, exhaustively. `Some(false)` and `None` are the pair
    /// that must never merge: one says "no module can read your whole vault",
    /// the other says "nobody checked".
    #[test]
    fn the_wildcard_verdict_keeps_unknown_apart_from_none_found() {
        use super::wildcard_verdict;
        assert_eq!(wildcard_verdict(None), None);
        assert_eq!(wildcard_verdict(Some(&[])), Some(false));
        assert_eq!(
            wildcard_verdict(Some(&["some-module".to_string()])),
            Some(true)
        );
    }

    /// END-TO-END, against the REAL `get_hygiene_report`, with every query
    /// failing — and without touching a live database.
    ///
    /// The trick is a lazily-connected pool pointed at a closed port, in the
    /// spirit of `SecretsManager::test_stub_for_cache`: nothing connects until
    /// a query runs, and then every one of them fails with a connection error.
    /// That is exactly the "Postgres blip" this whole change is about, and it
    /// is the only test here that exercises the WIRING rather than the
    /// renderer.
    ///
    /// It exists because a call-site mutation — returning a fresh
    /// `Readings::new()` from the struct literal instead of the ledger the
    /// sweep filled — left every other test in this change GREEN. A source pin
    /// now guards that too, but a pin proves the text and this proves the
    /// behaviour.
    ///
    /// Note what it also demonstrates: under a TOTAL outage the sweep still
    /// returns `Ok`, not `Err`. That is the `join!`-over-`try_join!` design
    /// working as intended — a partial report beats no report — and it is only
    /// safe because the ledger comes back full.
    #[tokio::test]
    async fn a_total_outage_returns_a_fully_disclosed_report_not_a_clean_one() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_millis(400))
            .connect_lazy("postgres://nobody:nobody@127.0.0.1:1/nothing")
            .expect("a lazy pool never connects at construction");
        let repo = super::AnalyticsRepository::new(pool);
        let report = repo.get_hygiene_report(uuid::Uuid::nil()).await.expect(
            "a dead database must still yield a report — that is why the sweep uses \
                     tokio::join! rather than try_join!",
        );

        assert!(
            !report.readings.complete(),
            "every query failed and the report claims every check was measured"
        );
        let missing = report.readings.not_measured();
        for check in HYGIENE_CHECKS {
            assert!(
                missing.contains(&check.field),
                "`{}` failed to read and was not disclosed; its empty result is \
                 indistinguishable from a clean one",
                check.field
            );
        }
        // And the defaults that used to be published as findings are gone.
        assert_eq!(report.total_workflow_count, None);
        assert_eq!(report.unembedded_count, None);
        assert_eq!(report.suppressed_count, None);
        assert_eq!(report.has_wildcard_module, None);
        assert!(report.workflow_graphs_scan_failed);
        assert!(report.stale_executions.is_empty());
    }

    /// The list/count split drives whether a `Coverage` is even meaningful: a
    /// scalar `COUNT(*)` sees its whole population by construction.
    #[test]
    fn only_list_checks_carry_a_cap() {
        for c in HYGIENE_CHECKS {
            let HygieneCheck {
                field,
                cap,
                is_list,
            } = *c;
            if !is_list {
                assert_eq!(cap, 0, "the scalar check `{field}` declares a row cap");
            }
        }
        assert_eq!(
            HYGIENE_CHECKS.iter().filter(|c| c.is_list).count(),
            14,
            "the number of list checks changed; summary.coverage.caps changed shape with it"
        );
    }
}

#[cfg(test)]
mod capability_query_pins {
    use super::{HYGIENE_FINDING_LIMIT, READINESS_PAGE_LIMIT};

    /// The rate expression and the count must come from one subquery with one
    /// window predicate.
    #[test]
    fn runs_30d_is_the_denominator_of_success_rate() {
        let src = include_str!("lib.rs");
        let start = src
            .find("LEFT JOIN LATERAL")
            .expect("the capability query still uses a LATERAL");
        let end = src[start..].find(") e ON TRUE").expect("LATERAL is closed") + start;
        let lateral = &src[start..end];
        // Numerator: completed only. Denominator: NULLIF(COUNT(*), 0).
        assert!(
            lateral.contains(
                "COUNT(*) FILTER (WHERE status = 'completed')::float / NULLIF(COUNT(*), 0) AS success_rate"
            ),
            "the rate expression changed; runs_30d may no longer be its denominator:\n{lateral}"
        );
        // The count is the same unfiltered COUNT(*) — NOT a second FILTER.
        assert!(
            lateral.contains("COUNT(*)::bigint AS runs_30d"),
            "runs_30d must be the bare COUNT(*):\n{lateral}"
        );
        // Exactly one window predicate governs both.
        assert_eq!(
            lateral
                .matches("started_at > NOW() - interval '30 days'")
                .count(),
            1,
            "rate and count must share ONE 30-day predicate:\n{lateral}"
        );
        assert_eq!(
            lateral.matches("FROM workflow_executions").count(),
            1,
            "one pass over workflow_executions, not two:\n{lateral}"
        );
    }

    /// The readiness page cap must equal the literal its query runs under, for
    /// the same reason as the hygiene one: a disclosure naming a ceiling that is
    /// not in force is this bug class one level up.
    #[test]
    fn readiness_page_limit_matches_the_sql_literal() {
        let src = include_str!("lib.rs");
        let needle = format!(
            "{} {}",
            concat!("ORDER BY COALESCE(readiness_score, 0) ASC \\\n             LIMIT"),
            READINESS_PAGE_LIMIT
        );
        assert!(
            src.contains(&needle),
            "the readiness page query no longer runs under \
             READINESS_PAGE_LIMIT={READINESS_PAGE_LIMIT}"
        );
    }

    /// The exported cap must equal the literal the hygiene queries actually
    /// run under. A disclosure that names the wrong ceiling is worse than no
    /// disclosure — it is this bug class one level up.
    #[test]
    fn hygiene_finding_limit_matches_the_sql_literals() {
        // Needle is `concat!`-assembled so this test's own text is not a match.
        let src = include_str!("lib.rs");
        let needle = format!(
            "{} {}",
            concat!("ORDER BY we.started_at ASC", " LIMIT"),
            HYGIENE_FINDING_LIMIT
        );
        assert!(
            src.contains(&needle),
            "the stale-executions hygiene query no longer runs under \
             HYGIENE_FINDING_LIMIT={HYGIENE_FINDING_LIMIT}; the exported cap and the SQL \
             literal have drifted, so every disclosure derived from the const now names a \
             ceiling that is not in force"
        );
    }

    /// D6 (2026-07-29): the two hygiene-report LIMIT 25 cuts must be
    /// deterministic for the same reason the routing cut is — an undescribed
    /// or uncapabilized workflow usually has a NULL readiness_score, so
    /// almost the whole candidate set is tied and the survivors of the cut
    /// were chosen by heap order.
    #[test]
    fn the_hygiene_cuts_have_a_unique_tiebreaker() {
        // Needles are `concat!`-assembled so this test's own source text is
        // not a match — a self-scanning `include_str!` that matches itself is
        // a test that can never fail.
        let src = include_str!("lib.rs");
        assert_eq!(
            src.matches(concat!(
                "ORDER BY readiness_score DESC",
                " NULLS LAST, id LIMIT 25"
            ))
            .count(),
            2,
            "both hygiene LIMIT 25 cuts must carry the `, id` tiebreaker"
        );
        assert!(
            !src.contains(concat!(
                "ORDER BY readiness_score DESC",
                " NULLS LAST LIMIT 25"
            )),
            "an untiebroken hygiene cut reappeared"
        );
    }

    /// The top-20 cut of a routing surface must be deterministic: readiness
    /// ties (NULL is the common case) would otherwise be broken by heap order.
    #[test]
    fn the_candidate_cut_has_a_unique_tiebreaker() {
        // The needles are assembled with `concat!` so this test's own source
        // text is not a match for them — an `include_str!` self-scan that
        // matches itself is a test that can never fail (or never pass).
        let src = include_str!("lib.rs");
        assert!(
            src.contains(concat!("ORDER BY readiness_score DESC", " NULLS LAST, id")),
            "the LIMIT 20 must be ordered by a unique tiebreaker"
        );
        assert!(
            !src.contains(concat!(
                "ORDER BY w.readiness_score DESC",
                " NULLS LAST LIMIT 20"
            )),
            "the untiebroken cut reappeared"
        );
    }
}

#[cfg(test)]
mod reliability_gain_tests {
    use super::{
        compute_reliability_score, reliability_gain_from_more_runs,
        reliability_gain_from_success_rate,
    };

    /// THE regression, stated as arithmetic. `get_readiness_breakdown` told the
    /// caller "Run N more times to reach FULL reliability credit". The score is
    /// a PRODUCT — `s · min(n/10, 1) · 50` — so at any `s < 1.0` the run-count
    /// lever alone cannot reach 50, and the shortfall `50·(1−s)·n/10` is exactly
    /// what the second lever accounts for.
    ///
    /// Driven against the REAL `compute_reliability_score`, not a restated
    /// formula, so a change to the scoring rule fails this rather than silently
    /// making the advice wrong again.
    #[test]
    fn running_more_does_not_reach_full_credit_below_a_perfect_success_rate() {
        // The worked case from the report: 5 runs at 60%.
        let (n, s) = (5i64, Some(0.6));
        let now = compute_reliability_score(s, n);
        let gain = reliability_gain_from_more_runs(n);

        // After 10-n further ALL-SUCCESSFUL runs the window holds s·n + (10−n)
        // completions out of 10 — that is the destination the advice promises.
        let after_all_success =
            compute_reliability_score(Some((s.unwrap() * n as f64 + (10 - n) as f64) / 10.0), 10);
        assert!(
            (now + gain - after_all_success).abs() < 1e-9,
            "gain must be exact: {now} + {gain} != {after_all_success}"
        );
        assert!(
            after_all_success < 50.0 - 1e-9,
            "the pre-fix advice claimed FULL credit ({after_all_success} is not 50)"
        );
        // And the shortfall is exactly the other lever's value.
        let forfeit = reliability_gain_from_success_rate(s, n);
        assert!(
            (50.0 - after_all_success - forfeit).abs() < 1e-9,
            "shortfall {} must equal the success-rate lever {forfeit}",
            50.0 - after_all_success
        );
    }

    /// The two levers are ADDITIVE and together close the whole gap, which is
    /// why they must both fire rather than sit in an `else if` chain — pre-fix
    /// `total_points_available` understated the real gap by `5n(1−s)`.
    #[test]
    fn the_two_levers_sum_to_the_whole_gap_at_every_n_and_s() {
        for n in [0i64, 1, 3, 5, 9, 10, 25, 400] {
            for s in [0.0f64, 0.25, 0.6, 0.95, 1.0] {
                let gap = 50.0 - compute_reliability_score(Some(s), n);
                let sum = reliability_gain_from_more_runs(n)
                    + reliability_gain_from_success_rate(Some(s), n);
                assert!(
                    (gap - sum).abs() < 1e-9,
                    "n={n} s={s}: gap {gap} != levers {sum}"
                );
            }
        }
    }

    /// At and above saturation the run lever is spent and the success-rate
    /// lever is the pre-fix `50·(1−s)` unchanged — the fix must not move the
    /// numbers where they were already right.
    #[test]
    fn at_saturation_the_success_rate_lever_is_byte_identical_to_the_old_formula() {
        for n in [10i64, 11, 999] {
            for s in [0.0f64, 0.5, 0.94, 1.0] {
                assert_eq!(reliability_gain_from_more_runs(n), 0.0, "n={n}");
                assert!(
                    (reliability_gain_from_success_rate(Some(s), n) - 50.0 * (1.0 - s)).abs()
                        < 1e-12,
                    "n={n} s={s}"
                );
            }
        }
    }

    /// A missing success rate is 0.0 in the score, so it must be 0.0 here too —
    /// the advice may not disagree with the number it is advising about. And a
    /// negative run count (schema drift) must not produce a gain above the
    /// component's own 50-point ceiling.
    #[test]
    fn absent_and_out_of_range_inputs_track_the_score() {
        assert_eq!(
            reliability_gain_from_success_rate(None, 10),
            reliability_gain_from_success_rate(Some(0.0), 10)
        );
        assert_eq!(reliability_gain_from_more_runs(-5), 50.0);
        assert_eq!(reliability_gain_from_success_rate(Some(0.0), -5), 0.0);
        // Out-of-range rates are clamped rather than producing negative points.
        assert_eq!(reliability_gain_from_success_rate(Some(1.5), 10), 0.0);
    }
}

#[cfg(test)]
mod fuel_blindspot_tests {
    use super::{
        parse_enforced_fuel_limit, NodeBudgetRow, FUEL_EXHAUSTION_CLASS, FUEL_MESSAGE_PREFILTER,
    };
    use uuid::Uuid;

    /// The two failure texts observed on the live database, verbatim (module
    /// and workflow names removed — this repository is public). Both are real
    /// worker output, not invented shapes: one from the 2026-08-17 death, one
    /// from the 2026-09-03 death that motivated this work.
    const LIVE_MESSAGES: [&str; 2] = [
        "Job failed after 1 attempts: execution failure: WASM fuel exhausted after 1404000 \
         instructions. Your module ran out of computation budget. Split into smaller modules \
         or reduce payload size. Current fuel limit: 1404000 (configurable via WASM_FUEL_LIMIT \
         or per-node max_fuel config).",
        "Job failed (non-transient: fuel_exhaustion): execution failure: WASM fuel exhausted: \
         the module consumed 1000000 instructions of a 1000000-instruction budget",
    ];

    /// The relationship the deaths query depends on, stated as an assertion
    /// rather than as a comment: the SQL pre-filter must be a SUPERSET of the
    /// classifier, so the cheap scan can never exclude a row the authority
    /// would have accepted.
    ///
    /// This is also the tripwire for an upstream rename of the verdict token —
    /// which would otherwise empty the section silently, since "no fuel deaths"
    /// and "no row matched the token" render identically.
    #[test]
    fn the_sql_prefilter_is_a_superset_of_the_classifier() {
        for msg in LIVE_MESSAGES {
            assert_eq!(
                talos_retry_intelligence::classify_error(msg),
                FUEL_EXHAUSTION_CLASS,
                "the canonical classifier no longer calls this a fuel death: {msg}"
            );
            assert!(
                msg.to_ascii_lowercase().contains(FUEL_MESSAGE_PREFILTER),
                "the SQL pre-filter would have excluded a row the classifier accepts: {msg}"
            );
        }
        // The classifier's other trigger phrase, which the pre-filter must also
        // survive even though no live row has carried it yet.
        assert_eq!(
            talos_retry_intelligence::classify_error("the module ran out of fuel"),
            FUEL_EXHAUSTION_CLASS
        );
        assert!("the module ran out of fuel".contains(FUEL_MESSAGE_PREFILTER));
    }

    /// A non-fuel failure must not be counted as one. The deaths section is a
    /// claim an operator acts on; inflating it trains them to ignore it.
    #[test]
    fn an_unrelated_failure_is_not_a_fuel_death() {
        let msg = "Job failed after 1 attempts: execution failure: Component returned error: \
                   list fetch: networkerror";
        assert_ne!(
            talos_retry_intelligence::classify_error(msg),
            FUEL_EXHAUSTION_CLASS
        );
    }

    #[test]
    fn the_enforced_limit_is_parsed_from_every_live_phrasing() {
        assert_eq!(parse_enforced_fuel_limit(LIVE_MESSAGES[0]), Some(1_404_000));
        assert_eq!(parse_enforced_fuel_limit(LIVE_MESSAGES[1]), Some(1_000_000));
    }

    /// Absence of the number is reported as absence, never as a zero — a `0`
    /// ceiling would render as "this node had no budget", which is a different
    /// and false claim.
    #[test]
    fn an_unparseable_message_yields_none_not_zero() {
        assert_eq!(parse_enforced_fuel_limit("WASM fuel exhausted"), None);
        assert_eq!(parse_enforced_fuel_limit(""), None);
    }

    fn budget(node: Option<i64>, module: Option<i64>) -> NodeBudgetRow {
        NodeBudgetRow {
            workflow_id: Uuid::nil(),
            workflow_name: "wf".into(),
            node_id: "n".into(),
            module_id: Uuid::nil(),
            module_name: "m".into(),
            node_max_fuel: node,
            module_max_fuel: module,
        }
    }

    /// The precedence the engine actually applies: a node override wins, and
    /// only its ABSENCE falls back to the module row. Getting this backwards is
    /// the bug the divergence section exists to find, so it is pinned here.
    #[test]
    fn the_node_override_wins_and_only_its_absence_inherits() {
        assert_eq!(
            budget(Some(12_000_000), Some(1_000_000)).configured_max_fuel(),
            Some(12_000_000)
        );
        assert!(!budget(Some(12_000_000), Some(1_000_000)).inherits_module_default());
        assert_eq!(
            budget(None, Some(1_000_000)).configured_max_fuel(),
            Some(1_000_000)
        );
        assert!(budget(None, Some(1_000_000)).inherits_module_default());
        assert_eq!(budget(None, None).configured_max_fuel(), None);
    }

    /// SOURCE pin: the headroom DETECTOR must not require a
    /// `workflow_executions` row.
    ///
    /// A sub-workflow run has none — `execute_subworkflow_graph` seeds a
    /// synthetic execution id — so an inner join deletes every sub-workflow
    /// node from the detector. Measured on the live database before the fix: 86
    /// rollup rows over 30 days were dropped this way, topped by a node at
    /// 99.2% of its ceiling the day before it died. This needs Postgres to
    /// exercise behaviourally, so the shape is pinned in the text instead.
    #[test]
    fn the_headroom_detector_does_not_require_a_workflow_execution_row() {
        let src = include_str!("lib.rs");
        let start = src
            .find(concat!("pub async fn ", "get_node_fuel_headroom"))
            .expect("the headroom query still exists");
        let body = &src[start..];
        let end = body[1..]
            .find("pub async fn ")
            .map_or(body.len(), |i| i + 1);
        let body = &body[..end];
        assert!(
            body.contains("LEFT JOIN workflow_executions we"),
            "the workflow_executions join must be a LEFT join"
        );
        assert!(
            body.contains("NOT COALESCE(we.is_test_execution, false)"),
            "a missing workflow_executions row must read as NOT a test execution"
        );
        // The exact pre-fix text, which would silently restore the blindness.
        assert!(
            !body.contains("AND NOT we.is_test_execution \\"),
            "the inner-join test predicate reappeared"
        );
    }
}
