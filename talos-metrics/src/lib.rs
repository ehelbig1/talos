//! Prometheus metrics instrumentation for Talos controller.
//!
//! This module provides metrics for:
//! - Webhook request counts and latencies
//! - Authentication success/failure rates
//! - Module execution counts and duration
//! - Rate limiter hits
//! - Cache hit/miss rates
//! - DLQ metrics

use prometheus::{
    exponential_buckets, Counter, CounterVec, Gauge, HistogramVec, IntGauge, IntGaugeVec, Registry,
};
use std::sync::{Arc, OnceLock};

pub mod actor_budget;
pub mod execution;
pub mod execution_pause;
pub mod google_push;
pub mod mcp;
pub mod outcome_class;
pub mod rpc;
pub mod security;
pub mod vault_token;
pub mod webhook;
pub use actor_budget::{BudgetCap, BudgetMode};
pub use execution::ModuleExecutionOutcome;
pub use execution_pause::{PauseGatePath, PauseRefusal};
pub use google_push::{JwkRefreshOutcome, PushDeferReason, PushIntegration, PushRefusalReason};
pub use mcp::McpToolOutcome;
pub use outcome_class::OutcomeClass;
pub use rpc::{seeded_pairs as rpc_seeded_pairs, RpcOutcome, RpcSubject};
pub use security::{
    ApiKeyValidation, McpAuthOutcome, PasswordChangeOutcome, PlatformAdminOutcome,
    PrivilegedOpOutcome, RateLimitKind, RotationAuditArmOutcome, TokenReuseOutcome,
    TwoFactorOutcome, WsHandshakeOutcome, WsOperationOutcome, WsSessionEnd,
};
pub use vault_token::{VaultTokenLifetimeLabel, VaultTokenRenewalOutcome};
pub mod advisory_db;
pub use advisory_db::{AdvisoryDbCopy, AdvisoryDbSampleOutcome};
pub use webhook::WebhookAuthFormat;

/// The complete, closed set of `subject` label values on
/// `talos_rpc_write_ceiling_refusals_total` — the NATS subjects on which the
/// controller serves a ceiling-gated mutation.
///
/// Must equal the distinct subjects in
/// `talos_rpc_subscribers::write_ceiling::CONTROLLER_SERVED_WRITE_OPS`. The
/// list is duplicated rather than imported because that crate DEPENDS on this
/// one, so importing would be a cycle; `every_gated_subject_is_seeded_in_the_metrics_crate`
/// (in that crate, where both are visible) pins the agreement. A gated subject
/// missing here has an ABSENT series until its first refusal, and
/// `increase(...) > 0` over an absent series matches nothing.
pub const RPC_WRITE_CEILING_SUBJECTS: [&str; 3] = [
    "talos.memory.op",
    "talos.integration_state.op",
    "talos.database.query",
];

/// The complete, closed set of `phase` label values on
/// `talos_scheduler_dispatches_total`.
///
/// Shared by the pre-seed loop in [`TalosMetrics::new`] and by every emitting
/// site in `talos_scheduler`, so a new value cannot be emitted without also
/// being seeded — the drift that makes an `increase(...) > 0` alert
/// unfireable on the one series that matters.
///
/// The three values PARTITION every poll's batch: `startup` and `catchup`
/// are the two BACKLOG shapes (both drain under the tighter startup
/// ceiling), `steady` is everything else.
pub const SCHEDULER_DISPATCH_PHASES: [&str; 3] = [
    SCHEDULER_PHASE_STARTUP,
    SCHEDULER_PHASE_CATCHUP,
    SCHEDULER_PHASE_STEADY,
];

/// The complete, closed set of `coverage` label values on
/// `talos_rank_training_fetches_total`.
///
/// The two values PARTITION every per-actor training fetch: the fetch either
/// reached the end of the configured lookback window or it hit its row cap
/// first. Shared by the pre-seed loop in [`TalosMetrics::new`] and by the one
/// emitting site in `talos_memory_ranking`, so a value cannot be emitted
/// without also being seeded.
pub const RANK_TRAINING_FETCH_COVERAGES: [&str; 2] = [
    RANK_TRAINING_COVERAGE_COMPLETE,
    RANK_TRAINING_COVERAGE_TRUNCATED,
];

/// The fetch read every row in the configured lookback window.
pub const RANK_TRAINING_COVERAGE_COMPLETE: &str = "complete";
/// The fetch hit its per-actor row cap, so the OLDEST part of the configured
/// window was never read.
pub const RANK_TRAINING_COVERAGE_TRUNCATED: &str = "truncated";

/// The startup backlog: schedules found due by the FIRST poll after boot.
pub const SCHEDULER_PHASE_STARTUP: &str = "startup";
/// A catch-up backlog: a LATER poll whose batch holds a schedule overdue by
/// more than `talos_scheduler::CATCHUP_OVERDUE_SECS`, i.e. the scheduler
/// missed several consecutive polls without the process restarting. Measured
/// live 2026-09-10: the host was suspended 10:56–12:06 UTC, the controller
/// resumed with `first_poll_done` already spent, and 10 schedules came due in
/// one poll — the boot-herd shape, labelled `steady` and drained under the
/// 16-wide steady ceiling, invisible to the herd alert. A host resume, a
/// long DB outage and a paused-then-resumed scheduler all produce this
/// batch; only a boot produces `startup`.
pub const SCHEDULER_PHASE_CATCHUP: &str = "catchup";
/// A poll whose batch is neither the boot backlog nor a catch-up backlog:
/// the schedules that came due since the previous poll, at most one poll
/// interval late.
pub const SCHEDULER_PHASE_STEADY: &str = "steady";

/// The complete, closed set of `outcome` label values on
/// `talos_scheduler_dispatches_total`. See [`SCHEDULER_DISPATCH_PHASES`].
///
/// **These five values PARTITION the scheduler's dispatch attempts**, and that
/// is a load-bearing property rather than a tidiness one: the alert runbook
/// tells operators to reconcile this counter against the boot backlog size
/// logged by `event_kind="scheduler_startup_backlog"`, and a counter with
/// uncounted terminal paths cannot reconcile against anything. Every task
/// spawned by `talos_scheduler::SchedulerService::spawn_workflow_execution`
/// records exactly one of these before it returns. When adding a terminal
/// `return` to that path, add its `record_dispatch` in the same edit — the
/// crate's `every_terminal_path_records_an_outcome` test documents the
/// enumeration, but only a human keeps it true.
pub const SCHEDULER_DISPATCH_OUTCOMES: [&str; 5] = [
    SCHEDULER_OUTCOME_COMPLETED,
    SCHEDULER_OUTCOME_FAILED,
    SCHEDULER_OUTCOME_SKIPPED,
    SCHEDULER_OUTCOME_DENIED,
    SCHEDULER_OUTCOME_FENCED,
];

/// The execution reached a terminal success.
pub const SCHEDULER_OUTCOME_COMPLETED: &str = "completed";
/// The run errored — engine failure, engine-build failure, or a DB error on
/// any of the pre-dispatch loads (workflow row, graph, execution-row INSERT,
/// fail-closed auth-gate lookup).
pub const SCHEDULER_OUTCOME_FAILED: &str = "failed";
/// The fire was refused before it ran because CAPACITY was exhausted — the
/// per-workflow concurrency cap, the actor-budget pre-check, or the atomic
/// actor-budget backstop. Visibly skipped, not silently dropped: for a daily
/// cron this means the run is lost until tomorrow. This is the herd-shaped
/// refusal, which is why the startup-herd alert selects it alongside `failed`.
pub const SCHEDULER_OUTCOME_SKIPPED: &str = "skipped";
/// The fire was refused by POLICY — the bound actor is archived/terminated/
/// not-runnable, or a node exceeds the actor's capability ceiling. Deliberately
/// NOT `skipped`: these are chronic configuration states that are unchanged by
/// how many schedules came due at once, so folding them into the herd alert
/// would make it fire on every deploy with a cause it cannot support.
pub const SCHEDULER_OUTCOME_DENIED: &str = "denied";
/// The run was superseded mid-flight by a crash-recovery reclaim (the execution
/// row's epoch advanced under it). Neither a success nor a failure of THIS
/// dispatch — the row now belongs to the resumer — but it is a terminal path,
/// and an uncounted terminal path is what stops the counter being a partition.
pub const SCHEDULER_OUTCOME_FENCED: &str = "fenced";

/// Process-global metrics registry.
///
/// Initialised once in `main.rs` after [`TalosMetrics::new`] succeeds.
/// Subsystems use [`global()`] to emit metrics without threading an
/// `Arc<TalosMetrics>` through every constructor. Safe concurrent reads;
/// writes are one-shot at startup.
static METRICS: OnceLock<Arc<TalosMetrics>> = OnceLock::new();

/// Install the process-global metrics registry. Idempotent —
/// subsequent calls return the already-installed value.
pub fn set_global(metrics: Arc<TalosMetrics>) {
    let _ = METRICS.set(metrics);
}

/// Access the process-global metrics registry. Returns `None` when
/// called before [`set_global`] (e.g. from a unit test). Callers MUST
/// use `.map(|m| m.counter.inc())` idiom — never unwrap.
pub fn global() -> Option<&'static Arc<TalosMetrics>> {
    METRICS.get()
}

/// Record one per-actor adaptive-rank training fetch on the process-global
/// registry, classified by whether it read the whole configured lookback window.
///
/// ONE increment site for the counter, so a new classification point cannot be
/// added without going through the closed label set. `coverage` is
/// `&'static str` DELIBERATELY and the only values a caller can pass are the two
/// [`RANK_TRAINING_FETCH_COVERAGES`] constants — the actor id must NOT appear
/// here (caller-influenced, unbounded cardinality) and stays a log field.
///
/// Inert when metrics are not wired (unit tests, any process without
/// [`set_global`]) — never unwraps, mirroring [`global`]'s contract.
pub fn record_rank_training_fetch(coverage: &'static str) {
    if let Some(m) = global() {
        m.rank_training_fetches_total
            .with_label_values(&[coverage])
            .inc();
    }
}

/// Publish the worst rank-training lookback shortfall observed in one completed
/// training tick, in days. `0.0` when every fetch read its whole configured
/// window.
///
/// A `set`, not an `inc`: this is the state as of the last tick, and it must
/// fall back to 0 when a previously-truncating actor stops truncating. Call it
/// ONCE per tick, after the whole fleet has been classified — a value published
/// mid-loop would report a partial maximum as a completed measurement.
pub fn set_rank_training_lookback_shortfall_days(days: f64) {
    if let Some(m) = global() {
        // A non-finite gauge renders as `NaN` and every comparison against it is
        // false, so a corrupt reading would silence rather than alarm. Refuse it
        // and leave the previous tick's value standing.
        if days.is_finite() {
            m.rank_training_lookback_shortfall_days.set(days.max(0.0));
        }
    }
}

/// Record one MCP `tools/call` on the process-global registry.
///
/// ONE increment site for both series, so a new observation point cannot
/// move one and forget the other. Inert when metrics are not wired (unit
/// tests, any process without [`set_global`]) — never unwraps, mirroring
/// [`global`]'s contract.
///
/// `tool` is `&'static str` DELIBERATELY. The only values the chokepoint can
/// pass are borrowed from the process-lifetime tool-schema registry or are
/// one of two `const` sentinels; a `String` parameter would accept the
/// request's own `params.name` and make the label set unbounded. The type is
/// not a proof on its own (`Box::leak` also yields `&'static str`), so the
/// rule is pinned by `talos_mcp_handlers::tool_labels`' tests.
pub fn record_mcp_tool_call(
    tool: &'static str,
    outcome: McpToolOutcome,
    elapsed: std::time::Duration,
) {
    if let Some(m) = global() {
        record_mcp_tool_call_on(m, tool, outcome, elapsed);
    }
}

/// Record one signed-RPC call on the process-global registry.
///
/// ONE increment site for both series, so a new observation point cannot move
/// one and forget the other. Inert when metrics are not wired (unit tests, any
/// process without [`set_global`]) — never unwraps, mirroring [`global`]'s
/// contract.
///
/// Both parameters are ENUMS, not `&'static str`. The `subject` label is the
/// NATS subject and the `outcome` label is the subscriber's own classification
/// of its reply; `actor_id` is a LOG FIELD on the caller and must NEVER become
/// a label — it is caller-supplied and unbounded, i.e. a cardinality DoS
/// surface reachable by anything that can publish to the subject. With the
/// enums, a caller-derived label value is not expressible.
///
/// `queue` and `exec` are passed as `Duration`s rather than pre-rounded
/// milliseconds: every call site used to round to `as_millis()`, and every
/// `queue_ms`/`exec_ms` this fleet has ever logged is `0`, so a histogram fed
/// the rounded value would put every observation in its bottom bucket.
pub fn record_rpc_call(
    subject: RpcSubject,
    outcome: RpcOutcome,
    queue: std::time::Duration,
    exec: std::time::Duration,
) {
    if let Some(m) = global() {
        record_rpc_call_on(m, subject, outcome, queue, exec);
    }
}

/// The recording itself, against an EXPLICIT registry.
///
/// Split out from [`record_mcp_tool_call`] so a test can drive the real
/// recording without racing `set_global` (a process-wide `OnceLock` that
/// sibling tests in one binary share). The 2026-09-08 scheduler-readiness
/// entry records what happens without this split: the publish site is
/// unreachable from a unit test and survives its own deletion.
pub fn record_mcp_tool_call_on(
    metrics: &TalosMetrics,
    tool: &'static str,
    outcome: McpToolOutcome,
    elapsed: std::time::Duration,
) {
    let labels = [tool, outcome.as_str(), outcome.class().as_str()];
    metrics
        .mcp_tool_calls_total
        .with_label_values(&labels)
        .inc();
    metrics
        .mcp_tool_duration_seconds
        .with_label_values(&labels)
        .observe(elapsed.as_secs_f64());
}

/// The recording itself, against an EXPLICIT registry.
///
/// Split out from [`record_rpc_call`] so a test can drive the real recording
/// without racing `set_global` (a process-wide `OnceLock` that sibling tests in
/// one binary share — CLAUDE.md's 2026-09-08 entry records the flake and its
/// `installed_test_metrics()` fix).
pub fn record_rpc_call_on(
    metrics: &TalosMetrics,
    subject: RpcSubject,
    outcome: RpcOutcome,
    queue: std::time::Duration,
    exec: std::time::Duration,
) {
    let labels = [subject.as_str(), outcome.as_str(), outcome.class().as_str()];
    metrics.rpc_calls_total.with_label_values(&labels).inc();
    metrics
        .rpc_duration_seconds
        .with_label_values(&labels)
        .observe((queue + exec).as_secs_f64());
}

/// Record an archived-workflow dispatch refusal on the process-global
/// `talos_dispatch_refused_total{path,reason}` counter.
///
/// ONE increment site for the whole narrow gate: every path that classifies a
/// workflow's lifecycle in Rust calls this, and the `path` label is a typed
/// [`talos_workflow_liveness::dispatch::DispatchPath`] rather than a string, so
/// a new dispatch surface cannot spell a label the constructor never seeded.
/// Inert when metrics are not wired (unit tests, any process without
/// `set_global`) — never unwraps, mirroring [`global`]'s contract.
pub fn record_dispatch_refusal(path: talos_workflow_liveness::dispatch::DispatchPath) {
    if let Some(m) = global() {
        m.dispatch_refused_total
            .with_label_values(&[
                path.as_str(),
                talos_workflow_liveness::dispatch::REFUSAL_REASON_ARCHIVED,
            ])
            .inc();
    }
}

/// Record a terminal workflow-execution outcome on the process-global
/// `talos_workflow_executions_total{status}` counter. Inert when metrics
/// aren't wired (unit tests, any process without `set_global`) — never
/// unwraps, mirroring [`global`]'s contract.
///
/// Called from the two terminal-write chokepoints
/// (`mark_execution_completed` → `"success"`, `mark_execution_failed` →
/// `"failure"`) so every finalizing caller (trigger / retry / replay /
/// crash-recovery / GraphQL / MCP) feeds the counter without each site
/// remembering to. This is the metric the TalosWorkflowFailureRateHigh
/// alert fires on — before this wiring the counter was registered but
/// never incremented (dead), so any alert on it would never have fired.
/// Count one terminal workflow outcome and, when the finalizer could
/// compute it, observe the run's wall-clock duration.
///
/// `duration_secs` is `completed_at - started_at` as the DATABASE computed it
/// in the same UPDATE that moved the status (`RETURNING EXTRACT(EPOCH FROM
/// (completed_at - started_at))`), so the two series describe the same row
/// and the same clock. `None` when the finalizer did not stamp
/// `completed_at` (the `set_completed_at = false` arm of
/// `fail_execution_unless_terminal`) — the count still moves, the histogram
/// does not: an unknown duration is not a zero-second one. The histogram is
/// deliberately NOT pre-seeded (a quantile needs no first observation; the
/// seeded COUNTER carries the volume — the MCP-instrument decision).
pub fn record_workflow_outcome(status: &str, duration_secs: Option<f64>) {
    if let Some(m) = global() {
        record_workflow_outcome_on(m, status, duration_secs);
    }
}

/// The recording itself, against an EXPLICIT registry.
pub fn record_workflow_outcome_on(
    metrics: &TalosMetrics,
    status: &str,
    duration_secs: Option<f64>,
) {
    metrics
        .workflow_executions_total
        .with_label_values(&[status])
        .inc();
    if let Some(secs) = duration_secs {
        metrics
            .workflow_execution_duration_seconds
            .with_label_values(&[status])
            .observe(secs.max(0.0));
    }
}

/// Count one terminal module-execution outcome and, when known, observe its
/// duration. Same contract as [`record_workflow_outcome`]: the duration comes
/// from the finalizing UPDATE's own `RETURNING`, `None` means unknown (the
/// engine's born-`cancelled` row never ran), and only the counter is seeded.
pub fn record_module_execution(outcome: ModuleExecutionOutcome, duration_secs: Option<f64>) {
    if let Some(m) = global() {
        record_module_execution_on(m, outcome, duration_secs);
    }
}

/// The recording itself, against an EXPLICIT registry.
pub fn record_module_execution_on(
    metrics: &TalosMetrics,
    outcome: ModuleExecutionOutcome,
    duration_secs: Option<f64>,
) {
    metrics
        .module_executions_total
        .with_label_values(&[outcome.as_str()])
        .inc();
    if let Some(secs) = duration_secs {
        metrics
            .module_execution_duration_seconds
            .with_label_values(&[outcome.as_str()])
            .observe(secs.max(0.0));
    }
}

/// Count one interactive 2FA verification. Inert without [`set_global`].
pub fn record_2fa_attempt(outcome: TwoFactorOutcome) {
    if let Some(m) = global() {
        record_2fa_attempt_on(m, outcome);
    }
}

/// The recording itself, against an EXPLICIT registry (testable without
/// racing `set_global`).
pub fn record_2fa_attempt_on(metrics: &TalosMetrics, outcome: TwoFactorOutcome) {
    metrics
        .auth_2fa_attempts_total
        .with_label_values(&[outcome.as_str()])
        .inc();
}

/// Count one API-key validation verdict. Inert without [`set_global`].
pub fn record_api_key_validation(verdict: ApiKeyValidation) {
    if let Some(m) = global() {
        record_api_key_validation_on(m, verdict);
    }
}

/// The recording itself, against an EXPLICIT registry.
pub fn record_api_key_validation_on(metrics: &TalosMetrics, verdict: ApiKeyValidation) {
    metrics
        .api_key_validations_total
        .with_label_values(&[verdict.as_str()])
        .inc();
}

/// Count one request a limiter refused. Inert without [`set_global`].
pub fn record_rate_limit_hit(kind: RateLimitKind) {
    if let Some(m) = global() {
        record_rate_limit_hit_on(m, kind);
    }
}

/// The recording itself, against an EXPLICIT registry.
pub fn record_rate_limit_hit_on(metrics: &TalosMetrics, kind: RateLimitKind) {
    metrics
        .rate_limit_hits_total
        .with_label_values(&[kind.as_str()])
        .inc();
}

/// Count one privileged-operation gate outcome. Inert without [`set_global`].
///
/// Called from the ONE site in `talos_api::schema::require_second_factor` that
/// knows the verdict — permitted and refused alike, because a refusal rate
/// needs its denominator and "the gate ran and admitted" is what separates a
/// quiet deployment from an unwired one.
pub fn record_privileged_op(outcome: PrivilegedOpOutcome) {
    if let Some(m) = global() {
        record_privileged_op_on(m, outcome);
    }
}

/// The recording itself, against an EXPLICIT registry.
pub fn record_privileged_op_on(metrics: &TalosMetrics, outcome: PrivilegedOpOutcome) {
    metrics
        .privileged_op_total
        .with_label_values(&[outcome.as_str()])
        .inc();
}

/// Count one platform-admin gate outcome. Inert without [`set_global`].
pub fn record_platform_admin_check(outcome: PlatformAdminOutcome) {
    if let Some(m) = global() {
        record_platform_admin_check_on(m, outcome);
    }
}

/// The recording itself, against an EXPLICIT registry.
pub fn record_platform_admin_check_on(metrics: &TalosMetrics, outcome: PlatformAdminOutcome) {
    metrics
        .platform_admin_checks_total
        .with_label_values(&[outcome.as_str()])
        .inc();
}

/// Count one MCP agent-token authentication outcome. Inert without
/// [`set_global`].
pub fn record_mcp_auth(outcome: McpAuthOutcome) {
    if let Some(m) = global() {
        record_mcp_auth_on(m, outcome);
    }
}

/// The recording itself, against an EXPLICIT registry.
pub fn record_mcp_auth_on(metrics: &TalosMetrics, outcome: McpAuthOutcome) {
    metrics
        .mcp_auth_total
        .with_label_values(&[outcome.as_str()])
        .inc();
}

/// Count one WebSocket handshake outcome. Inert without [`set_global`].
pub fn record_ws_handshake(outcome: WsHandshakeOutcome) {
    if let Some(m) = global() {
        record_ws_handshake_on(m, outcome);
    }
}

/// The recording itself, against an EXPLICIT registry.
pub fn record_ws_handshake_on(metrics: &TalosMetrics, outcome: WsHandshakeOutcome) {
    metrics
        .ws_handshakes_total
        .with_label_values(&[outcome.as_str()])
        .inc();
}

/// Count how an authenticated WebSocket session ended. Inert without
/// [`set_global`].
pub fn record_ws_session_end(reason: WsSessionEnd) {
    if let Some(m) = global() {
        record_ws_session_end_on(m, reason);
    }
}

pub fn record_ws_session_end_on(metrics: &TalosMetrics, reason: WsSessionEnd) {
    metrics
        .ws_session_ends_total
        .with_label_values(&[reason.as_str()])
        .inc();
}

/// Count one start/subscribe frame's outcome. Inert without [`set_global`].
pub fn record_ws_operation(outcome: WsOperationOutcome) {
    if let Some(m) = global() {
        record_ws_operation_on(m, outcome);
    }
}

pub fn record_ws_operation_on(metrics: &TalosMetrics, outcome: WsOperationOutcome) {
    metrics
        .ws_operations_total
        .with_label_values(&[outcome.as_str()])
        .inc();
}

/// One open, authenticated WebSocket session on this controller: the gauge
/// is incremented when the guard is created and decremented when it is
/// dropped, so a session that ends by deadline, transport error, client
/// close or a panic unwinding through the handler all release it. Holding
/// the guard IS the session's presence in `talos_ws_active_sessions`.
#[must_use = "dropping the guard immediately ends the session's presence in the gauge"]
pub struct WsActiveSession {
    gauge: IntGauge,
}

impl WsActiveSession {
    /// Register an open session against the GLOBAL registry; `None` when no
    /// registry is installed (tests, the worker), in which case there is
    /// nothing to hold.
    pub fn open() -> Option<Self> {
        global().map(|m| Self::open_on(m))
    }

    /// Register an open session against an EXPLICIT registry.
    pub fn open_on(metrics: &TalosMetrics) -> Self {
        metrics.ws_active_sessions.inc();
        Self {
            gauge: metrics.ws_active_sessions.clone(),
        }
    }
}

impl Drop for WsActiveSession {
    fn drop(&mut self) {
        self.gauge.dec();
    }
}

/// Count one password-change outcome. Inert without [`set_global`].
pub fn record_password_change(outcome: PasswordChangeOutcome) {
    if let Some(m) = global() {
        record_password_change_on(m, outcome);
    }
}

/// The recording itself, against an EXPLICIT registry.
pub fn record_password_change_on(metrics: &TalosMetrics, outcome: PasswordChangeOutcome) {
    metrics
        .password_changes_total
        .with_label_values(&[outcome.as_str()])
        .inc();
}

/// Count one refresh-token reuse-detector verdict. Inert without
/// [`set_global`].
///
/// Called exactly once per failed refresh that reaches the detector, from
/// the single `match` over `talos_auth::classify_token_reuse`'s finding, so
/// a new verdict cannot be added without landing here.
pub fn record_token_reuse(outcome: TokenReuseOutcome) {
    if let Some(m) = global() {
        record_token_reuse_on(m, outcome);
    }
}

/// The recording itself, against an EXPLICIT registry.
pub fn record_token_reuse_on(metrics: &TalosMetrics, outcome: TokenReuseOutcome) {
    metrics
        .token_reuse_total
        .with_label_values(&[outcome.as_str()])
        .inc();
}

/// Count one rotation by whether it armed the reuse detector. Inert without
/// [`set_global`]. One per rotation, on BOTH outcomes — the failure series
/// is only readable against this denominator.
pub fn record_rotation_audit_arm(outcome: RotationAuditArmOutcome) {
    if let Some(m) = global() {
        record_rotation_audit_arm_on(m, outcome);
    }
}

/// The recording itself, against an EXPLICIT registry.
pub fn record_rotation_audit_arm_on(metrics: &TalosMetrics, outcome: RotationAuditArmOutcome) {
    metrics
        .rotation_audit_arm_total
        .with_label_values(&[outcome.as_str()])
        .inc();
}

/// Count one start the deployment-wide execution pause refused. Inert without
/// [`set_global`].
pub fn record_actor_budget_refusal(cap: BudgetCap, mode: BudgetMode) {
    if let Some(m) = global() {
        record_actor_budget_refusal_on(m, cap, mode);
    }
}

/// The recording itself, against an EXPLICIT registry.
pub fn record_actor_budget_refusal_on(metrics: &TalosMetrics, cap: BudgetCap, mode: BudgetMode) {
    metrics
        .actor_budget_refusals_total
        .with_label_values(&[cap.as_str(), mode.as_str()])
        .inc();
}

/// Count one start refused by the deployment-wide execution pause. Inert
/// without [`set_global`].
pub fn record_execution_pause_refusal(path: PauseGatePath, reason: PauseRefusal) {
    if let Some(m) = global() {
        record_execution_pause_refusal_on(m, path, reason);
    }
}

/// The recording itself, against an EXPLICIT registry.
pub fn record_execution_pause_refusal_on(
    metrics: &TalosMetrics,
    path: PauseGatePath,
    reason: PauseRefusal,
) {
    metrics
        .execution_pause_refusals_total
        .with_label_values(&[path.as_str(), reason.as_str()])
        .inc();
}

/// Count one inbound webhook delivery suppressed as a duplicate. Inert without
/// [`set_global`].
pub fn record_webhook_duplicate_suppressed(format: WebhookAuthFormat) {
    if let Some(m) = global() {
        record_webhook_duplicate_suppressed_on(m, format);
    }
}

/// The recording itself, against an EXPLICIT registry.
pub fn record_webhook_duplicate_suppressed_on(metrics: &TalosMetrics, format: WebhookAuthFormat) {
    metrics
        .webhook_duplicate_suppressed_total
        .with_label_values(&[format.as_str()])
        .inc();
}

/// Count one Google push delivery refused at the HTTP boundary. Inert
/// without [`set_global`].
pub fn record_google_push_refusal(integration: PushIntegration, reason: PushRefusalReason) {
    if let Some(m) = global() {
        record_google_push_refusal_on(m, integration, reason);
    }
}

/// The recording itself, against an EXPLICIT registry.
pub fn record_google_push_refusal_on(
    metrics: &TalosMetrics,
    integration: PushIntegration,
    reason: PushRefusalReason,
) {
    metrics
        .google_push_refusals_total
        .with_label_values(&[integration.as_str(), reason.as_str()])
        .inc();
}

/// Count one Google push delivery that passed authentication. Inert without
/// [`set_global`].
pub fn record_google_push_accepted(integration: PushIntegration) {
    if let Some(m) = global() {
        record_google_push_accepted_on(m, integration);
    }
}

/// The recording itself, against an EXPLICIT registry.
pub fn record_google_push_accepted_on(metrics: &TalosMetrics, integration: PushIntegration) {
    metrics
        .google_push_accepted_total
        .with_label_values(&[integration.as_str()])
        .inc();
}

/// Count one push DEFERRED for redelivery. Not a refusal: see
/// [`PushDeferReason`]. The transport retries, so this series climbing means
/// work is being delayed — and, if it keeps climbing past the subscription's
/// retention, eventually lost.
pub fn record_google_push_deferred(integration: PushIntegration, reason: PushDeferReason) {
    if let Some(m) = global() {
        record_google_push_deferred_on(m, integration, reason);
    }
}

/// [`record_google_push_deferred`] against an explicit registry (tests).
pub fn record_google_push_deferred_on(
    metrics: &TalosMetrics,
    integration: PushIntegration,
    reason: PushDeferReason,
) {
    metrics
        .google_push_deferred_total
        .with_label_values(&[integration.as_str(), reason.as_str()])
        .inc();
}

/// Seed every `talos_vault_token_renewals_total` outcome at 0. Called by the
/// Vault token renewal loop when it starts — NOT by [`TalosMetrics::new`],
/// because only a process running a Vault KEK provider can move the series.
/// Inert without [`set_global`].
pub fn seed_vault_token_renewals() {
    if let Some(m) = global() {
        seed_vault_token_renewals_on(m);
    }
}

/// The seeding itself, against an EXPLICIT registry.
pub fn seed_vault_token_renewals_on(metrics: &TalosMetrics) {
    for outcome in VaultTokenRenewalOutcome::ALL {
        metrics
            .vault_token_renewals_total
            .with_label_values(&[outcome.as_str()])
            .inc_by(0.0);
    }
}

/// Count one Vault token renewal attempt. Inert without [`set_global`].
pub fn record_vault_token_renewal(outcome: VaultTokenRenewalOutcome) {
    if let Some(m) = global() {
        record_vault_token_renewal_on(m, outcome);
    }
}

/// The recording itself, against an EXPLICIT registry.
pub fn record_vault_token_renewal_on(metrics: &TalosMetrics, outcome: VaultTokenRenewalOutcome) {
    metrics
        .vault_token_renewals_total
        .with_label_values(&[outcome.as_str()])
        .inc();
}

/// Publish the Vault token's remaining TTL under its lifetime class, removing
/// every other class so exactly one series is present. Inert without
/// [`set_global`].
pub fn publish_vault_token_ttl(lifetime: VaultTokenLifetimeLabel, ttl_secs: u64) {
    if let Some(m) = global() {
        publish_vault_token_ttl_on(m, lifetime, ttl_secs);
    }
}

/// The publication itself, against an EXPLICIT registry.
pub fn publish_vault_token_ttl_on(
    metrics: &TalosMetrics,
    lifetime: VaultTokenLifetimeLabel,
    ttl_secs: u64,
) {
    for other in VaultTokenLifetimeLabel::ALL {
        if *other != lifetime {
            // Absent is the only honest reading for a class the token is not.
            let _ = metrics
                .vault_token_ttl_seconds
                .remove_label_values(&[other.as_str()]);
        }
    }
    metrics
        .vault_token_ttl_seconds
        .with_label_values(&[lifetime.as_str()])
        .set(i64::try_from(ttl_secs).unwrap_or(i64::MAX));
}

/// Publish one MEASURED advisory-database age for `copy`.
pub fn publish_advisory_db_age_on(metrics: &TalosMetrics, copy: AdvisoryDbCopy, age_days: u64) {
    metrics
        .advisory_db_age_days
        .with_label_values(&[copy.as_str()])
        .set(i64::try_from(age_days).unwrap_or(i64::MAX));
}

/// Publish the limit the compile gate applies to `copy` and whether it
/// refuses (1) or only warns (0) on this controller.
pub fn publish_advisory_db_limits_on(
    metrics: &TalosMetrics,
    copy: AdvisoryDbCopy,
    max_age_days: u64,
    enforced: bool,
) {
    metrics
        .advisory_db_max_age_days
        .with_label_values(&[copy.as_str()])
        .set(i64::try_from(max_age_days).unwrap_or(i64::MAX));
    metrics
        .advisory_db_age_enforced
        .with_label_values(&[copy.as_str()])
        .set(i64::from(enforced));
}

/// Count one advisory-database age sample.
pub fn record_advisory_db_sample_on(
    metrics: &TalosMetrics,
    copy: AdvisoryDbCopy,
    outcome: AdvisoryDbSampleOutcome,
) {
    metrics
        .advisory_db_age_samples_total
        .with_label_values(&[copy.as_str(), outcome.as_str()])
        .inc();
}

/// Count one attempt to fetch Google's JWK set. Inert without [`set_global`].
pub fn record_google_jwk_refresh(outcome: JwkRefreshOutcome) {
    if let Some(m) = global() {
        record_google_jwk_refresh_on(m, outcome);
    }
}

/// The recording itself, against an EXPLICIT registry.
pub fn record_google_jwk_refresh_on(metrics: &TalosMetrics, outcome: JwkRefreshOutcome) {
    metrics
        .google_jwk_refresh_total
        .with_label_values(&[outcome.as_str()])
        .inc();
}

/// The closed set of `kind` label values on
/// `talos_condition_eval_failures_total`, in the order they are pre-seeded.
///
/// Lives HERE rather than beside the enum that produces it
/// (`talos_workflow_engine::ConditionKind`) for one reason: the pre-seed
/// loop in [`TalosMetrics::new`] and the increment sites must agree, and
/// this crate is the only one both of them already depend on. The engine's
/// `ConditionKind::label()` returns these `&'static str`s and a unit test
/// there asserts every variant's label is a member — so a new variant that
/// forgets to seed fails the engine's tests rather than silently exporting
/// a series that only appears after the first failure.
///
/// **Every value must be a compile-time constant.** These are label values
/// on a `CounterVec`; a caller-derived string here is unbounded cardinality.
pub const CONDITION_EVAL_KINDS: &[&str] = &[
    CONDITION_EVAL_KIND_SKIP,
    CONDITION_EVAL_KIND_EDGE,
    CONDITION_EVAL_KIND_WHILE_LOOP,
    CONDITION_EVAL_KIND_LOOP,
    CONDITION_EVAL_KIND_FAN_IN,
    CONDITION_EVAL_KIND_VERIFY,
];

/// A node's `skip_condition`. **The only FAIL-OPEN kind**: `false` means
/// "do not skip", so a broken expression RUNS the node the author gated.
pub const CONDITION_EVAL_KIND_SKIP: &str = "skip_condition";
/// An edge `condition`. `false` means "do not traverse" — the child is
/// skipped, so a broken expression silently drops a branch.
pub const CONDITION_EVAL_KIND_EDGE: &str = "edge_condition";
/// A `WhileLoop` system node's condition. `false` breaks the loop.
pub const CONDITION_EVAL_KIND_WHILE_LOOP: &str = "while_loop";
/// A `Loop` system node's per-iteration condition. `false` breaks the loop.
pub const CONDITION_EVAL_KIND_LOOP: &str = "loop";
/// A `FanIn` node's `aggregation_expr`. `false` marks the aggregation failed.
pub const CONDITION_EVAL_KIND_FAN_IN: &str = "fan_in_aggregation";
/// A `Verify` node's condition. `false` fails the check — loudly.
pub const CONDITION_EVAL_KIND_VERIFY: &str = "verify";

/// Global metrics registry and collectors
pub struct TalosMetrics {
    pub registry: Registry,

    // Webhook metrics. `talos_webhook_requests_total{trigger_id,status}` and
    // `talos_webhook_request_duration_seconds{trigger_id}` were DELETED
    // 2026-09-11: registered since 2026-05, never incremented (check 58's
    // burn-down baseline), referenced by no alert or dashboard, and keyed on
    // `trigger_id` — a per-row label this file otherwise forbids. The
    // per-request record is `webhook_request_log`.
    pub webhook_dlq_drops_total: Counter,

    // Authentication metrics.
    //
    // `auth_attempts_total` / `auth_failures_total` are the denominator and
    // numerator of the `TalosControllerHighErrorRate` alert. Emitted for
    // INTERACTIVE logins only — `method=password` (`talos_auth::AuthService::
    // login`) and `method=oauth` (the controller's `oauth_callback_handler`).
    // API-key validation is deliberately excluded: it runs on every GraphQL
    // request, so folding it into the same `sum(rate(...))` would swamp the
    // interactive population and leave a credential-stuffing burst unable to
    // move the ratio — an alert that is technically live but still cannot
    // fire. `api_key_validations_total` below is that surface's own series —
    // wired 2026-09-11 at `ApiKeyService::validate_key`, seeded over
    // `ApiKeyValidation::ALL`; no alert references it yet. Both it and
    // `auth_2fa_attempts_total` sat in check 58's dead-metric baseline for
    // four months before that.
    pub auth_attempts_total: CounterVec,
    pub auth_failures_total: CounterVec,
    pub auth_2fa_attempts_total: CounterVec,
    pub api_key_validations_total: CounterVec,
    // The third bearer credential — the MCP agent token — was the one whose
    // refusals reached no series and no log line until 2026-09-13: a guessed
    // token got a bare 401 from `mcp_auth_middleware` and nothing else
    // happened. One value per `/mcp` request, from the middleware's single
    // exit; the per-IP limiter in front of it also counts on
    // `rate_limit_hits_total{type="mcp_auth"}`. No alert yet, deliberately:
    // like the two above, a threshold needs a baseline this series has never
    // produced. Seeded over `McpAuthOutcome::ALL`.
    pub mcp_auth_total: CounterVec,
    // The fourth bearer surface — the access-token cookie on the /ws upgrade
    // (2026-09-22, package DU): nine refusal / close arms in talos-ws-auth and
    // not one series, so a Cross-Site-WebSocket-Hijacking probe, a cookie
    // guessing burst or a client that never completes connection_init were
    // all invisible below the WARN log. One value per socket at the
    // handshake's single exit. Seeded over `WsHandshakeOutcome::ALL`.
    pub ws_handshakes_total: CounterVec,
    // How an authenticated session ended; `token_expired` is the
    // stolen-cookie exposure bound firing. Seeded over `WsSessionEnd::ALL`.
    pub ws_session_ends_total: CounterVec,
    // Subscription starts and the lane's two per-operation refusals (the
    // subscriptions-only gate and the pre-2FA gate), both previously
    // `talos_audit` log lines only. Seeded over `WsOperationOutcome::ALL`.
    pub ws_operations_total: CounterVec,
    // Authenticated sessions currently open on THIS controller (a Drop guard
    // decrements, so a session that ends by timeout, error or client close
    // all release it). Not seeded: a gauge reads 0 at registration.
    pub ws_active_sessions: IntGauge,
    // A user changing their own password (2026-09-18): the one recovery a
    // user has after a password leak, and — through `wrong_current_password`
    // — the signal that someone holding a session is guessing the password.
    // No alert yet, for the reason given above. Seeded over
    // `PasswordChangeOutcome::ALL`.
    pub password_changes_total: CounterVec,
    // What the refresh-token REUSE DETECTOR concluded, one per failed
    // refresh that reaches it. Label set closed by
    // `TokenReuseOutcome::ALL`; every value pre-seeded.
    pub token_reuse_total: CounterVec,
    // Did a successful rotation ARM that detector? The denominator the
    // failure series needs, closed by `RotationAuditArmOutcome::ALL`.
    pub rotation_audit_arm_total: CounterVec,

    // Execution metrics
    pub module_executions_total: CounterVec,
    pub module_execution_duration_seconds: HistogramVec,
    pub workflow_executions_total: CounterVec,
    pub workflow_execution_duration_seconds: HistogramVec,

    // Crash-recovery metrics (durable execution, RFC 0003). Labeled by
    // `outcome`: resumed | failed | reclaimed. Lets operators alert on a
    // restart-resume sweep that silently does nothing or whose resumes fail.
    pub crash_recovery_total: CounterVec,

    /// Rhai expressions that FAILED TO EVALUATE and were replaced by the
    /// call site's silent default. Labelled by [`CONDITION_EVAL_KINDS`].
    ///
    /// This is the counter `talos-engine`'s `rhai_helpers` L-30 comment asked
    /// for and nobody built: *"Operators need a metric to alert on the rate so
    /// a regression after a refactor surfaces."* Until 2026-09 the only trace
    /// of a broken condition was one WARN line, and a WARN line is not a
    /// signal anything on this platform can alert on.
    ///
    /// **The `kind` label is the whole point, and it is worth its
    /// cardinality** (six values, all `&'static str`). `false` is the
    /// conservative default for a ROUTING condition — "do not take this
    /// branch" — and the PERMISSIVE default for a SKIP condition, where
    /// `false` means "do not skip" and therefore RUNS the node the author
    /// gated. One primitive, two semantics, opposite safe defaults. Collapsed
    /// into a single unlabelled counter the two are indistinguishable, and
    /// they call for opposite remediations: a fail-open skip gate means work
    /// happened that should not have (a send fired on a dry run), a
    /// fail-closed edge condition means a branch was silently not taken. That
    /// is the "dimension collapsed by aggregation" trap — the label is
    /// cheaper than the ambiguity.
    ///
    /// A NON-ZERO value on `kind="skip_condition"` should be treated as an
    /// incident, not a warning: every increment is one node that ran despite
    /// a gate its author wrote to stop it.
    pub condition_eval_failures_total: CounterVec,

    // ---- Detector metrics (2026-08) ----
    //
    // Each of the five below existed as a WARN/ERROR log line ONLY. Every
    // alert this platform ships is metric-based, so a log-only detector is a
    // signal nothing can consume — the same defect as a signal never emitted.
    // Adding the counter is what makes the detector page-able.
    //
    // DO NOT collapse these into a shared `warn_and_count!` macro. A macro
    // body would contain the literal `.field….inc()` for every metric it can
    // touch, so all of them would read as LIVE to structural check 58 from one
    // definition site — re-blinding the lint in exactly the way #620 just
    // fixed. If a future author does build such a helper, check 58 must first
    // be taught to require an INVOCATION naming the field rather than a
    // textual match.
    /// WASM log lines discarded because they could not be routed to any
    /// execution row. Labels: `kind=no_execution_row|unparseable_id`, a
    /// closed set of `&'static str` — never the guest-authored message body,
    /// never the execution id (an orphaned line may carry module output, and
    /// a per-execution label would be unbounded cardinality).
    pub wasm_log_orphaned_total: CounterVec,
    /// `module_executions` start-row INSERT failures at the single
    /// `PostgresModuleExecutionStore::record_started` chokepoint. The upstream
    /// CAUSE of `wasm_log_orphaned_total{kind="no_execution_row"}`, and
    /// independently it means `get_execution_logs` / `get_node_io` / cost
    /// attribution are quietly missing rows.
    pub module_execution_record_started_failures_total: Counter,
    /// `module_executions` rows the stuck-execution sweep had to convert to
    /// `'timeout'` because nothing ever finalized them.
    ///
    /// A HEALTHY fleet increments this rarely — a genuinely dead worker, a
    /// controller killed mid-execution. Sustained non-zero means rows are
    /// being opened and never closed, which is a broken LEDGER rather than a
    /// broken fleet, and it is the shape that hid for over a month: from the
    /// table's first row until 2026-08-12 every single-node workflow dispatch
    /// landed here (21,065 rows, zero `completed` rows ever), silently
    /// emptying `replay_module_regression`'s `WHERE status='completed'`
    /// corpus. Nothing observed the sweep's return value except a WARN log.
    ///
    /// Unlabelled deliberately. The sweep's `UPDATE … LIMIT 100` returns a
    /// row count and nothing else — it does not know which module, user or
    /// workflow the rows belonged to, and any of those would be unbounded
    /// cardinality. An unlabelled `Counter` is also exported at 0 from
    /// process start (unlike a `CounterVec`, which emits nothing until a
    /// label set is touched), so an alert on it is never silenced by the
    /// absent-is-not-zero trap.
    pub module_executions_swept_stuck_total: Counter,
    /// `module_executions` rows DELETEd by the opt-in row-retention sweep.
    /// Each one also removed its CASCADEd `module_execution_logs` children.
    ///
    /// This is the observability half of an IRREVERSIBLE operation: once the
    /// row is gone there is no tombstone to count after the fact (unlike the
    /// payload sweep, whose `payload_pruned_at` can be queried), so if this
    /// counter does not move, nothing anywhere records that the sweep ran.
    ///
    /// **Do not confuse this with `module_execution_orphaned_rows`.** That
    /// gauge counts rows whose `payload_enc_key_id` references a MISSING DEK
    /// — a crypto data-loss detector with a `critical` alert behind it. This
    /// counter counts deliberate retention deletions. They share the word
    /// "orphan" in prose and nothing else.
    ///
    /// Unlabelled deliberately, for the two reasons its `swept_stuck` sibling
    /// directly above is: the sweep's `DELETE … RETURNING` knows only a row
    /// count, and `module_id` / `user_id` / `actor_id` would each be unbounded
    /// cardinality. An unlabelled `Counter` also exports at 0 from process
    /// start (a `CounterVec` emits nothing until a label set is touched), so
    /// "the sweep is enabled and deleting nothing" and "the series does not
    /// exist" stay distinguishable — the absent-is-not-zero trap.
    ///
    /// A fleet with `MODULE_EXECUTION_RETENTION_ENABLED` unset leaves this
    /// flat at 0 forever, which is the correct reading: nothing was deleted.
    pub module_executions_retention_deleted_total: Counter,
    /// Job results discarded by the fire-and-forget `talos.results.*`
    /// subscriber because the payload would not deserialize into a
    /// `JobResult`.
    ///
    /// That subject is single-producer and single-type — only the worker
    /// publishes there (`worker/src/main.rs::publish_result_with_retry`, the
    /// no-reply-topic branch), pipeline results go to a different subject,
    /// and guest WASM is denied the whole `talos.` prefix. So a message that
    /// does not parse is an anomaly, never routine traffic, and the drop is
    /// not free: that subscriber is the ONLY finalizer for the four
    /// fire-and-forget dispatch paths that publish with no reply inbox (Gmail
    /// push, Google-Calendar push, GCP Monitoring Pub/Sub, and the webhook
    /// DLQ replay `talos_webhooks::router::dispatch_replay`). The live
    /// webhook path uses `nats.request()` and is NOT one of them. One dropped
    /// message loses the
    /// terminal `module_executions` status write, the `output_data` payload,
    /// and the `__ops_alert__` ingest that hangs off
    /// `complete_execution_from_worker` — after which the 30-minute sweep
    /// rewrites the row to `'timeout'`. Pre-metric this was a
    /// `tracing::debug!`, a level not enabled by default, so the loss left no
    /// operator-visible trace at all.
    ///
    /// UNLABELLED on purpose, for two independent reasons. The serde error
    /// text is derived from an attacker-influenceable payload, so it is an
    /// unbounded-cardinality surface on a scrapeable endpoint; and `job_id`
    /// is unavailable by construction (the parse that would have produced it
    /// is the thing that failed). Registration alone exports an unlabelled
    /// `Counter` at 0 from process start, so `> 0` cannot be silenced by the
    /// series being absent (a `CounterVec` emits nothing until a label set is
    /// first touched).
    pub job_results_dropped_unparseable_total: Counter,
    /// WORM audit-ledger verification failures. Labels:
    /// `stage=event|chain` — `event` is the inline per-message
    /// authenticity/integrity check at ingest (the message is quarantined,
    /// never persisted); `chain` is the offline hash-chain sweep over a
    /// completed execution's full ordered record set. Either means the
    /// compliance artifact is void for that execution.
    pub audit_verification_failures_total: CounterVec,
    /// Executions whose audit chain could NOT BE READ, by classified reason.
    ///
    /// The read-side twin of `audit_verification_failures_total`, and
    /// deliberately a SEPARATE series: "the chain is broken" and "I could not
    /// look" are different findings with different severities (#578), and
    /// folding an object-store blip into the CRITICAL tamper alert would train
    /// operators to ignore it. Before this existed the `Err` arm of the sweep
    /// incremented NOTHING, so a verifier that had never once succeeded — the
    /// live state of the dev stack on 2026-09-06, 37 unverifiable executions
    /// an hour since 2026-07-08 — was indistinguishable, on every
    /// machine-readable surface, from a ledger verified clean.
    ///
    /// Labels: `reason` over the CLOSED set in
    /// `talos_audit_ledger::ChainVerifyErrorKind` (access_denied,
    /// no_such_bucket, not_found, transport, other, no_credentials). Every
    /// value is pre-seeded — an `increase(...) > 0` alert over an absent
    /// series matches nothing, which is precisely how this control stayed
    /// quiet. No execution id, workflow id or object key is ever a label.
    pub audit_chain_unverifiable_total: CounterVec,
    /// Job chains the audit-chain verification sweep CLASSIFIED, by outcome
    /// (`verified_ok`, `empty`, `failed`, `errored` — the closed set
    /// `talos_audit_ledger::JobChainOutcome`), one increment per job at the
    /// sweep's single classification site. The DENOMINATOR
    /// `TalosAuditChainJobsUnverifiable` divides by: a per-job unverifiable
    /// reason (an empty prefix, one failed read) is a finding only as a SHARE
    /// of the jobs swept — one job whose worker died mid-flight is expected,
    /// a quarter of the population is not. Pre-seeded over the closed set so
    /// the ratio is defined the moment the sweep runs; 0/0 on an idle fleet is
    /// NaN and matches nothing, which is the intended silence.
    pub audit_chain_jobs_swept_total: CounterVec,
    /// EXACT duplicate audit events dropped by the WORM LEDGER WRITER before
    /// persistence, by scope. `scope="batch"` is the only value with a live
    /// increment site (`talos_audit_ledger::batch_dedupe`), because the writer
    /// can only see the copies that share one batch — its S3 identity is
    /// write-only by design, so it cannot read the prefix back to find a
    /// cross-batch copy.
    ///
    /// Deliberately NOT alerted on and deliberately NOT folded into
    /// `talos_audit_verification_failures_total`: at-least-once delivery is
    /// the transport working as designed, and the tamper counter's whole value
    /// is that its steady state is 0.
    pub audit_ledger_duplicate_deliveries_total: CounterVec,
    /// Audit events the JetStream broker holds that the WORM-ledger consumer
    /// has not yet been delivered (`num_pending` on the durable consumer),
    /// sampled every 5 s by `talos-audit-ledger`'s batch loop. This is the
    /// buffer's FILL LEVEL: the `AUDIT_LEDGER` stream is bounded by age (30 d,
    /// `AUDIT_LEDGER_STREAM_MAX_AGE`), so a backlog that keeps climbing is a
    /// subscriber that is not shipping to S3, and past the bound its oldest
    /// events expire unshipped. Steady state on a healthy fleet is 0 to a few
    /// (one batch). Not alerted yet — the series comes first; the loud signal
    /// for a dead subscriber today is `TalosAuditChainJobsUnverifiable`.
    pub audit_ledger_consumer_pending: IntGauge,
    /// Job chains the offline sweep found carrying a BYTE-IDENTICAL redelivery
    /// (`talos_audit_event::ChainBreak::DuplicateDelivery`) — the copies the
    /// writer could not see because they arrived in different batches.
    ///
    /// A chain whose only finding is this still verifies (`ok == true`) and is
    /// counted in `jobs_verified_ok`, never in `jobs_failed`. Reported so the
    /// redundancy is visible; not alerted on, for the same reason as the
    /// writer-side counter above.
    pub audit_chain_duplicate_deliveries_total: Counter,
    /// Job chains the offline sweep found holding MORE THAN ONE controller
    /// dispatch attempt — a re-dispatched `job_id`, whose second dispatch
    /// necessarily opened a fresh hash chain at `sequence_num` 1.
    ///
    /// A retry, not a finding: such a chain verifies (`ok == true`), is counted
    /// in `jobs_verified_ok`, and NOTHING alerts on this series. It exists
    /// because before `dispatch_attempt` reached the wire this shape was
    /// reported as `DuplicateSequence` — CRITICAL tamper evidence — and an
    /// operator asking "how often does the fleet re-dispatch?" had no number to
    /// read. Registration alone exports it at 0 so absent and zero do not
    /// render alike.
    pub audit_chain_multi_attempt_jobs_total: Counter,
    /// Unix seconds at which an audit chain last verified CLEAN.
    ///
    /// A gauge, and deliberately NOT pre-seeded: absent means "no chain has
    /// verified in this process", which is the true state of a controller that
    /// has just booted AND of one whose verifier cannot read the bucket. A
    /// zero seed would render as 1970 and make every staleness rule fire on a
    /// healthy cold start, so the alert on this carries an explicit
    /// `absent()` arm instead.
    pub audit_chain_last_verified_ok_timestamp_seconds: Gauge,
    /// Unix seconds at which the chain-verification sweep last COMPLETED a
    /// pass, whatever it found.
    ///
    /// Separate from the gauge above because the two questions have different
    /// answers on the deployment this instrument was added for: the sweep ran
    /// hourly for two months and verified nothing. One series cannot say both
    /// "the loop is alive" and "the control works", and collapsing them is how
    /// a dead control reads as a healthy one.
    pub audit_chain_sweep_timestamp_seconds: Gauge,
    /// Worker-key trust-on-first-use conflicts at the self-registration
    /// endpoint: a `worker_id` presented a key that is not its bound
    /// identity. In-fleet impersonation, or an operator rotating off the
    /// managed path. UNLABELLED on purpose — `worker_id` and the submitted
    /// key are both caller-supplied at a network endpoint, so neither may
    /// become a label (unbounded cardinality, attacker-driven).
    pub worker_key_tofu_conflicts_total: Counter,
    /// Responses in which a mounted route asked for an axum `Extension` its
    /// router never layered (`talos_http_utils::missing_extension`). A wiring
    /// defect, never a caller error: `GET /metrics` and `GET /graphql/schema`
    /// answered this way from the day they were mounted until package BZ
    /// deleted them. UNLABELLED — the route template is in the ERROR log line.
    pub http_missing_extension_total: Counter,
    /// Number of distinct `worker_id`s with an ACTIVE `worker_identities` row
    /// whose reported build provably differs from this controller's. A GAUGE,
    /// recomputed from a query each sweep (always `set`, never `inc`/`dec`) so a
    /// worker catching up, or having its key deactivated, lowers it. A counter
    /// would be wrong at both ends: it would fire on every rolling deploy AND go
    /// quiet while a fleet stayed skewed.
    ///
    /// ACTIVE means "row not deactivated", NOT "process running", and
    /// `last_seen_at` is boot-only so no age filter can tell the two apart. A
    /// reaper DOES exist (`reap_departed_identities`, added #631/#632) but it
    /// is OFF by default, and its automatic arm only matches rows with a
    /// non-NULL `last_liveness_at`; a worker that never ran the liveness
    /// pinger needs the separately-gated `reap_pre_protocol_identities`. So on
    /// a fleet whose `worker_id` is the pod name (the chart default), retired
    /// pods keep this above zero after a controller upgrade until an operator
    /// deactivates their keys or enables BOTH reaper arms. See
    /// `controller::bootstrap::background::publish_worker_build_skew`.
    ///
    /// "Unverifiable" workers are NOT counted here (absence of evidence is
    /// not evidence of skew — #578).
    pub worker_build_skew_workers: IntGauge,

    /// Catalog templates (`kind='catalog' AND user_id IS NULL`) whose
    /// `wasm_bytes` is NULL or empty **and which carry no `oci_url`** — i.e.
    /// templates with neither local bytes nor a registry reference, which
    /// therefore **cannot run at all**.
    ///
    /// The `oci_url` half of that predicate is not defensive trimming. In OCI
    /// mode `talos_registry::sync` inserts every catalog row with
    /// `source_code = ''` and no `wasm_bytes` BY DESIGN — the worker pulls the
    /// bytes from the registry at execution time — so a count without it
    /// equals the entire healthy catalog and this gauge's alert pages on a
    /// working cluster.
    ///
    /// A GAUGE, recomputed from one query after each boot's background
    /// compiles settle (always `set`, never `inc`), because the condition is
    /// durable state rather than an event: a template with no WASM stays
    /// broken until someone fixes it, and a counter would go quiet exactly
    /// while the fleet stayed broken.
    ///
    /// This exists because the failure it detects was, for its whole
    /// lifetime, visible ONLY as a boot-time WARN whose text
    /// ("keeping existing wasm_bytes") actively implied there were bytes to
    /// keep. Three shipped templates sat at NULL for months.
    ///
    /// UNLABELLED on purpose. In OCI mode the template name is
    /// registry-supplied, so a per-template label is an unbounded-cardinality
    /// surface; the names live in `get_catalog_status` → `never_compiled`,
    /// which is a queried surface rather than a scraped one.
    ///
    /// Published at boot on every exit of the seeding pass (disk seed, OCI
    /// early return, missing-`module-templates/` early return) so the alert is
    /// fireable in every supported mode, AND re-measured every 300 s by
    /// `spawn_metrics_gauge_tasks` so it tracks current state rather than the
    /// state at the last restart.
    ///
    /// **Until 2026-08-26 the boot publish was the ONLY writer**, which broke
    /// the gauge in both directions: a row that lost its bytes after boot left
    /// it at 0 and the alert could never fire, and a row repaired after boot
    /// left it above 0 and the alert fired until the next restart. The
    /// periodic sweep is what makes `> 0` mean "right now".
    ///
    /// **Holds its last value when the query fails; it is NOT zeroed and no
    /// sentinel is folded in** — `get_catalog_status` and the alert's
    /// `{{ $value }}` both read this as a row count, and a synthetic value
    /// would make it untrustworthy to them. Telling a held value from a
    /// measured one is the job of the SEPARATE series below.
    pub catalog_templates_missing_wasm: IntGauge,

    /// Unix time of the last sweep in which `talos_catalog_templates_missing_wasm`
    /// was successfully measured.
    ///
    /// **This is the companion "the detector could not measure" signal**, in
    /// the same form and for the same reason as
    /// `crypto_orphan_scan_last_success_timestamp_seconds` (#667). An
    /// `IntGauge` exports 0 from registration, so
    /// `talos_catalog_templates_missing_wasm == 0` covers BOTH "measured, every
    /// catalog template can run" and "the `SELECT COUNT(*)` errored and nothing
    /// was ever measured". Before the periodic sweep those two readings were
    /// not merely ambiguous but PERMANENTLY so: the boot publish never retried,
    /// so one failed query at boot switched the detector off for the life of
    /// the process while it read as a clean bill of health.
    ///
    /// **Why a freshness timestamp rather than a `blind`/`failed` gauge.** A
    /// `blind == 0` gauge is itself an unmeasured zero: if the sweep task never
    /// spawns, panics, or is dropped in a refactor, nothing sets it and it
    /// reads "not blind" forever — this exact defect one level up. A timestamp
    /// degrades the right way in all four cases: query error, task death, task
    /// never spawned, and a controller build predating the sweep (0 from
    /// registration, which reads as maximally stale).
    ///
    /// `TalosCatalogMissingWasmDetectorBlind` is the alert that consumes it.
    pub catalog_missing_wasm_scan_last_success_timestamp_seconds: Gauge,

    // ---- Worker-identity liveness + reaper (2026-08) ----
    //
    // Before these, the entire proof-of-possession liveness path and the
    // reaper that consumes it were UNINSTRUMENTED: no metric, no alert. That
    // is not a gap like an ordinary missing counter, because the reaper's
    // worst failure — deactivating the signing key of a LIVE worker — is
    // silent for a whole trust window (24h by default) and then presents as
    // fleet-wide signature-verification failure with nothing pointing at the
    // cause. The five series below exist so that failure is visible BEFORE
    // it happens, which is the precondition for turning the reaper on at all.
    /// Liveness pings received at `POST /internal/worker-liveness`.
    /// Labels: `outcome=accepted|rejected_request|rejected_proof|
    /// inactive_identity|error` — a closed set of `&'static str` DERIVED FROM
    /// THE RESPONSE STATUS the endpoint already returns
    /// (`controller::bootstrap::router::liveness_outcome_label`).
    ///
    /// TWO PROPERTIES THAT MUST NOT BE WEAKENED, both because this endpoint
    /// is unauthenticated and reachable by any caller that can open a socket
    /// to the controller:
    ///  * NO caller-derived label. Not `worker_id`, not the presented public
    ///    key, not an error string — each would hand an unauthenticated
    ///    caller control of series cardinality (an OOM DoS on the scrape
    ///    path). The identifying detail lives in the `talos_security` log,
    ///    which is rate-limited and DLP-scrubbed; a metric label is neither.
    ///  * NO new distinction. Deriving the label from the HTTP status makes
    ///    it STRUCTURALLY impossible for this counter to tell an observer
    ///    anything the endpoint's own response does not already — so it can
    ///    never become an existence oracle for "is this worker registered".
    ///    (The endpoint already answers 401 for a bad proof and 404 for a key
    ///    that is not an active identity, and 404 is only reachable AFTER a
    ///    valid proof-of-possession, i.e. by someone who already holds the
    ///    private key.) Do not "improve" this by labelling from inside the
    ///    handler's branches.
    pub worker_liveness_pings_total: CounterVec,
    /// Worker signing keys deactivated by the reaper. Labels:
    /// `arm=departed|pre_protocol` — `departed` is the automatic arm keyed on
    /// liveness silence, `pre_protocol` the opt-in arm keyed on registration
    /// age for rows that never participated. Counts KEYS, not workers (a
    /// worker mid-rotation holds two rows).
    ///
    /// This is the "what just happened" pointer for the failure this whole
    /// area exists to survive: a false reap manifests as signature failures
    /// across the fleet, and without this counter there is nothing in the
    /// metrics tying that to a trust-boundary write. UNLABELLED by worker —
    /// same cardinality rule as above, and the reaper's own WARN already
    /// carries the count.
    pub worker_identity_reaps_total: CounterVec,
    /// Reactive OAuth credential repairs — one increment per credential per
    /// repair attempt, fired only after a dispatched job has ALREADY failed
    /// with an authentication error on a Talos-held OAuth credential.
    ///
    /// Labels: `outcome=repaired|not_refreshed|refresh_failed`, a closed set
    /// of three `&'static str`. **Deliberately not labelled by provider,
    /// user, or vault path**: the provider segment comes from a
    /// workflow-authored `vault://oauth/<provider>/…` string (unbounded
    /// cardinality from caller data), and the remaining segments are the
    /// user id and — for gmail/google_calendar — the user's e-mail address.
    ///
    /// This counter is what makes the two failure MODES distinguishable,
    /// which is the whole operator-facing point of the reactive path:
    ///
    /// * `repaired` — the credential was dead, a new token was obtained, and
    ///   the node was re-dispatched. Self-healed; no action. A rising rate
    ///   means the PREDICTIVE refresh is losing races and is worth a look,
    ///   because each one costs a doubled dispatch.
    /// * `refresh_failed` — the token endpoint refused. For Google and
    ///   Atlassian that is what a REVOKED or expired grant looks like
    ///   (`HTTP 400 invalid_grant`). The node failed and **will keep failing
    ///   until a human re-consents** — this is the arm that needs a person.
    /// * `not_refreshed` — nothing to refresh (no refresh endpoint for the
    ///   provider, e.g. non-expiring Slack bot tokens). The 401 was not a
    ///   staleness problem and the node was NOT retried.
    ///
    /// All three are pre-seeded at 0: the healthy steady state is that none
    /// of them ever moves, which is exactly the case where an absent series
    /// silently unfires an `increase(...) > 0` alert.
    pub oauth_reactive_refresh_total: CounterVec,
    /// Distinct `worker_id`s with an ACTIVE `worker_identities` row that have
    /// proved liveness at least once — i.e. **the automatic reaper's
    /// population**. A row enters it on its first ping and never leaves
    /// (nothing clears `last_liveness_at`) until the row is deactivated, so
    /// this is exactly the set of identities the reaper is able to act on.
    ///
    /// A GAUGE recomputed from the fleet query each sweep (always `set`), for
    /// the same reason as `worker_build_skew_workers`: it must be able to
    /// fall as well as rise.
    pub worker_liveness_participants: IntGauge,
    /// The subset of [`Self::worker_liveness_participants`] whose most recent
    /// liveness proof is inside the participation horizon — i.e. **the set
    /// still actively pinging**.
    ///
    /// THE PAIR IS THE POINT, and neither number is useful alone. The
    /// difference `participants - recent_participants` is the count of keys
    /// that are in the reaper's population and have STOPPED proving liveness:
    /// the pre-reap signature of a false reap, visible for the whole gap
    /// between the horizon and the trust window (~22h at defaults) BEFORE any
    /// key is deactivated. Publishing only the difference would have hidden
    /// the denominator — "3 silent" reads very differently at 3 participants
    /// than at 300 — so both are exported and the alert does the subtraction.
    ///
    /// On a fleet that has NEVER participated both are 0 and the difference
    /// is 0, which is why the alert cannot fire on a fleet that legitimately
    /// does not ping (the chart default: the liveness ping is blocked at the
    /// network layer unless two opt-in NetworkPolicy rules are enabled).
    pub worker_liveness_recent_participants: IntGauge,
    /// 1 when the liveness DETECTOR can no longer see the whole population the
    /// REAPER can act on, 0 otherwise.
    ///
    /// **This closes the one gap that would have reintroduced the exact silent
    /// false reap the pair above exists to prevent.** The two participation
    /// gauges are computed from
    /// `WorkerIdentityRepository::list_active_builds`, which is bounded
    /// (`ORDER BY worker_id, public_key LIMIT MAX_FLEET_BUILD_ROWS`, 200). The
    /// reaper's `UPDATE` is NOT bounded. So above 200 active rows a worker
    /// whose row sorts after the 200th was invisible to both gauges and fully
    /// reapable — `TalosWorkerLivenessParticipationDropped` could not warn
    /// about it, and the runbook's "participants must equal your worker count"
    /// gate silently became uncheckable.
    ///
    /// The fix is FAIL-SAFE rather than cosmetic: while this gauge is 1 the
    /// reaper SKIPS its sweep entirely and deactivates nothing (see
    /// `controller::bootstrap::background`). This series is what makes that
    /// refusal visible — a fail-safe you cannot see is just a silent state,
    /// which is the defect one level up. `TalosWorkerIdentityReapBlinded`
    /// alerts on it.
    ///
    /// SATURATING, not a count: the bounded SELECT returning exactly 200 rows
    /// means "at least 200 active rows, possibly more". Knowing HOW many are
    /// unobserved would need a second query, and the number does not change
    /// the response — drain the ghost rows with `deactivate-worker-identity`
    /// until the detector is whole again.
    pub worker_liveness_population_truncated: IntGauge,

    // ---- NATS fleet heartbeat (2026-08) ----
    //
    // A THIRD, INDEPENDENT view of the fleet, and the only one that works in
    // the chart's DEFAULT posture. The two series above describe registered
    // `worker_identities` rows and are structurally silent on a fleet pinned
    // through the static `TALOS_WORKER_PUBLIC_KEYS` ring (no registration
    // endpoint, no rows); the liveness ping needs worker→controller HTTP,
    // which `networkPolicy.workerControllerEgress` blocks unless enabled.
    // The heartbeat needs neither — every worker already speaks NATS.
    //
    // WHAT THE EVIDENCE IS WORTH, because it is weaker than it looks: a
    // heartbeat is HMAC-signed under the FLEET-SHARED `WORKER_SHARED_KEY`, so
    // any process holding that key can mint one naming any worker. These are
    // liveness HINTS for observability. Nothing here may gate trust, and
    // `worker_id` is caller-supplied so it is NOT a label on any of them.
    /// Distinct `worker_id`s that published a fleet heartbeat within the
    /// staleness window. A GAUGE recomputed from the fleet view each sweep
    /// (always `set`), so an id that stops heartbeating lowers it within
    /// `STALE_AFTER + PRUNE_INTERVAL`.
    ///
    /// **WHETHER THIS IS A REPLICA COUNT DEPENDS ON THE POSTURE, so establish
    /// the posture before reading the number.** The fleet view is a map keyed
    /// on `worker_id`, and the two shipped postures differ:
    ///
    /// * **DISTINCT ids — the chart DEFAULT.** Nothing in
    ///   `deploy/helm/talos/templates/worker/deployment.yaml` renders
    ///   `TALOS_WORKER_ID`; the `values.yaml` line offering it is COMMENTED
    ///   OUT inside the opt-in RFC-0010 worker-trust block. So a default
    ///   `helm install` falls through to `worker_identity()`'s step 2,
    ///   `HOSTNAME` → the pod name, and every replica carries its own id.
    ///   Here the gauge IS a replica count: five replicas report 5, and
    ///   scaling 5→1 lowers it to 1.
    /// * **ONE SHARED id.** The dev compose stack sets a single
    ///   `TALOS_WORKER_ID` for every replica (`.env`), and the RFC-0010
    ///   single-key Ed25519 block does the same once an operator uncomments
    ///   it. Every replica then writes the SAME entry: a fleet of any size
    ///   reports 1, and scaling 5→1 still reports 1.
    ///
    /// The earlier wording here ("so a scaled-down worker lowers it") was true
    /// of the first posture and silently false of the second; it is corrected
    /// rather than renamed, per the misleading-report-field rule (#579/#580).
    /// Where a shared id is deliberate, do NOT "fix" it to make this gauge
    /// nicer: the static `TALOS_WORKER_PUBLIC_KEYS` ring looks a worker's
    /// public key up BY `worker_id`, so varying it alone breaks dispatch
    /// verification.
    ///
    /// What it answers in EVERY posture is "how many distinct heartbeating
    /// identities?", which is the honest denominator for
    /// [`Self::worker_fleet_build_skew_workers`] and
    /// [`Self::worker_fleet_unverifiable_workers`] (all three are derived from
    /// this same map). It is an answer to "are all my replicas up?" only under
    /// distinct ids, and under a shared id nothing in this file can answer
    /// that — see the fleet crate's module header for why replica-loss
    /// detection is a separate problem.
    ///
    /// 0 is AMBIGUOUS and must be read as "no heartbeat observed": it covers
    /// a genuinely empty fleet, a fleet on a build too old to publish, and a
    /// broken subscription. It is not evidence that workers are absent.
    pub worker_fleet_live_workers: IntGauge,
    /// DISTINCT builds observed within the staleness window — **the
    /// denominator for the two gauges below, and the one to read beside them.**
    ///
    /// This is a different population from
    /// [`Self::worker_fleet_live_workers`], which counts heartbeating
    /// IDENTITIES. Reading a builds numerator against an ids denominator is
    /// how "1 skewed build of 1 live worker" comes to read as 100% of a fleet
    /// that is in fact 1 pod in 10 — the misleading-report-field defect
    /// (#579/#580) this pair exists to avoid. The two skew gauges are computed
    /// over THIS population, so:
    /// `live_builds == build_skew_builds + unverifiable_builds + agreeing`.
    ///
    /// A healthy fleet reads 1. A fleet mid-roll reads 2, steadily, for as
    /// long as both builds keep heartbeating — which is the property that lets
    /// an alert hold a `for:` duration.
    ///
    /// 0 is AMBIGUOUS in exactly the same way as `live_workers`: nothing has
    /// been observed, which is not the same as nothing running.
    pub worker_fleet_live_builds: IntGauge,
    /// Of [`Self::worker_fleet_live_builds`], those that PROVABLY differ from
    /// this controller's build.
    ///
    /// **COUNTS BUILDS, NOT PROCESSES.** Five workers stuck on one old build
    /// report 1 here, not 5. The magnitude is not lost from the export —
    /// [`Self::worker_fleet_build_skew_workers`] carries it — but it is not
    /// recoverable from THIS number, and it is this number the alert is built
    /// on, because it is the only one that survives every posture.
    ///
    /// **Why the ALERT lives here and not on the `_workers` gauge.** The fleet
    /// view is keyed on `worker_id`. Where replicas share one id — the dev
    /// compose stack, and the RFC-0010 single-key block once uncommented — a
    /// per-worker skew count ALTERNATES on a mixed-build fleet (the map is
    /// last-write-wins, so the retained build is whichever replica spoke
    /// last), and no `for:` duration can ever elapse. This build-keyed count
    /// is steady in BOTH postures, so the detector holds in both.
    ///
    /// **State the old defect precisely.** The `_workers` gauge could not
    /// hold a `for:` on a MIXED-build SHARED-id fleet — a roll stuck partway.
    /// It was steady and alerted correctly on a uniformly skewed shared-id
    /// fleet, and it is steady and correct in ALL cases under distinct ids
    /// (the chart default), which is why it is exported again beside this one
    /// rather than deleted. "It could not fire" is the overstatement; this is
    /// the claim.
    ///
    /// Still the live-process twin of `worker_build_skew_workers`, which counts
    /// REGISTERED ROWS. Neither subsumes the other — a ghost row appears only
    /// in the former, a static-key worker with no registry row only here.
    pub worker_fleet_build_skew_builds: IntGauge,
    /// Of [`Self::worker_fleet_live_builds`], those that cannot be compared
    /// with the controller's.
    ///
    /// TWO CAUSES, and the second is easy to misread off the number alone:
    /// the WORKER reported no usable sha (none, `unknown`, or a value refused
    /// by `talos_worker_fleet::well_formed_build_key`, all of which collapse
    /// onto one bucket), **or the CONTROLLER's own build has no usable sha** —
    /// in which case nothing is comparable and every observed build lands here
    /// regardless of what was reported. So this gauge equalling `live_builds`
    /// says "no comparison was possible", not "no worker reported a build".
    ///
    /// Exported so a 0 on the skew gauge is readable: 0 skewed out of 0
    /// comparable builds is not "the fleet agrees" (#578). Same deliberate
    /// under-count as the registry-backed gauge, made visible.
    ///
    /// Its population moved from workers to builds in 2026-08 alongside the
    /// gauge above; the NAME did not have to change because it already said
    /// `builds`, which is now accurate rather than merely plausible. The
    /// per-identity companion is [`Self::worker_fleet_unverifiable_workers`].
    ///
    /// **WHEN THIS EQUALS [`Self::worker_fleet_live_builds`] THE SKEW
    /// DETECTOR CANNOT FIRE AT ALL** — nothing was comparable, so
    /// `build_skew_builds` is pinned at 0 by construction rather than by
    /// agreement. `TalosWorkerFleetBuildSkewUndetectable` is the alert that
    /// says so, and it exists because the "read this gauge first" mitigation
    /// otherwise lives only in the annotation of an alert that requires
    /// `build_skew_builds > 0` — i.e. it would be delivered in every state
    /// EXCEPT the one it warns about.
    pub worker_fleet_unverifiable_builds: IntGauge,
    /// Of [`Self::worker_fleet_live_workers`], the heartbeating IDENTITIES
    /// whose reported build PROVABLY differs from this controller's — the
    /// MAGNITUDE that [`Self::worker_fleet_build_skew_builds`] cannot carry.
    ///
    /// **INFORMATIONAL. NO ALERT IS BUILT ON THIS, and one must not be**, for
    /// the reason spelled out on the builds gauge: under a shared `worker_id`
    /// the underlying map is last-write-wins, so on a MIXED-build fleet this
    /// alternates 1/0 across sweeps and no `for:` duration can elapse.
    ///
    /// **The posture decides whether the number means anything:**
    ///
    /// * **DISTINCT ids (the chart DEFAULT — `HOSTNAME` → pod name, because
    ///   nothing renders `TALOS_WORKER_ID`)**: every replica holds its own map
    ///   entry, so this is exactly "how many running pods are on a build that
    ///   differs from mine". Steady, and the honest magnitude.
    /// * **ONE SHARED id (dev compose; the RFC-0010 single-key block once
    ///   uncommented)**: the map holds ONE entry for the whole fleet, so this
    ///   is 0 or 1 regardless of fleet size, and it FLAPS whenever the fleet
    ///   is mid-roll. Read `talos_worker_fleet_build_skew_builds` there, and
    ///   `get_platform_info.fleet` for per-worker detail.
    ///
    /// It was briefly dropped while the ALERT was moved to the build-keyed
    /// population (#644 review) and kept on purpose: dropping it would have
    /// lost the magnitude on the DEFAULT posture, where the per-identity view
    /// was never broken, in order to fix a defect only shared-id installs
    /// have. It is not a dead metric — `publish_worker_fleet_gauges` `set`s it
    /// every sweep from `WorkerManager::live_build_versions`.
    ///
    /// Its denominator is [`Self::worker_fleet_live_workers`], NOT
    /// `live_builds`, and the identity population decomposes exactly the same
    /// way the build one does: `live_workers == build_skew_workers +
    /// unverifiable_workers + agreeing`.
    pub worker_fleet_build_skew_workers: IntGauge,
    /// Of [`Self::worker_fleet_live_workers`], the heartbeating identities
    /// whose build could not be compared with this controller's.
    ///
    /// Exists so that [`Self::worker_fleet_build_skew_workers`] has a
    /// published denominator decomposition and a 0 on it is readable: 0 skewed
    /// of 5 live identities means something quite different when 4 of them
    /// were never comparable. Shipping the numerator without this would repeat,
    /// one population over, the exact defect the builds trio was built to
    /// avoid — an absence rendered as a negative result (#578).
    ///
    /// Same two causes as [`Self::worker_fleet_unverifiable_builds`]: the
    /// WORKER reported no usable sha, or THIS CONTROLLER's own build has none,
    /// in which case every identity lands here at once. Same posture caveat as
    /// its sibling above: under a shared `worker_id` this counts map entries,
    /// of which there is one.
    pub worker_fleet_unverifiable_workers: IntGauge,
    /// Heartbeats refused because the fleet view was at its hard cap
    /// (`talos_worker_fleet::MAX_TRACKED_WORKERS`), cumulative since process
    /// start.
    ///
    /// An IntGauge rather than a Counter because it is republished from the
    /// subscriber's own running total each sweep rather than incremented here;
    /// it is monotonic within a process and resets on restart. Non-zero means
    /// either a misconfigured fleet or someone using the shared key to flood
    /// distinct worker ids — the bound held, but say so out loud.
    ///
    /// **TRAP FOR ANY ALERT WRITTEN ON THIS.** It has COUNTER semantics
    /// but a GAUGE type and no `_total` suffix, so `rate()` / `increase()`
    /// will not apply counter reset handling and will misread every
    /// controller restart. Alert on the level (`> 0`) or on
    /// `delta(...[1h]) > 0`, not on a rate.
    ///
    /// **IT SUPPRESSES THE BUILD-SKEW DETECTOR, not just the fleet census.**
    /// `handle_heartbeat` refuses an untracked id at the cap and returns
    /// BEFORE `record_build_observation`, so a heartbeat dropped here never
    /// reaches the build map either — a straggling worker that boots during a
    /// flood is invisible to `worker_fleet_build_skew_builds` as well as to
    /// `worker_fleet_live_workers`. `TalosWorkerFleetWorkerViewSaturated` consumes
    /// this counter, and `TalosWorkerFleetBuildViewSaturated` its build-map
    /// sibling, for that reason.
    pub worker_fleet_capacity_dropped_heartbeats: IntGauge,
    /// Build observations refused because the BUILD map was at its hard cap
    /// (`talos_worker_fleet::MAX_TRACKED_BUILDS`), cumulative since process
    /// start.
    ///
    /// Separate from [`Self::worker_fleet_capacity_dropped_heartbeats`] on
    /// purpose: they are different refusal causes over different key spaces,
    /// and a single number covering both would be unreadable. The build map
    /// saturates on a shape the worker cap cannot see — ONE `worker_id`
    /// publishing many distinct build strings — because the worker map has a
    /// single entry throughout.
    ///
    /// Non-zero means the bound held while something published more distinct
    /// builds than a fleet can have. `build_version` is signed, so only a
    /// holder of the fleet-shared key can do it; signing bounds WHO, never HOW
    /// MUCH, which is what the cap is for.
    ///
    /// **NAME THE SUPPRESSION DIRECTION FIRST, because it is the one the skew
    /// alert exists for and an earlier version of this comment gave only the
    /// other one.** At the cap a NEW key is REFUSED (`record_build_observation`
    /// returns early); tracked keys keep refreshing. `builds_match` compares
    /// only the `+sha` suffix, so `v0+<sha>` … `v63+<sha>` are 64 distinct keys
    /// that all classify as AGREEING. A shared-key holder can therefore fill
    /// the map with agreeing-but-distinct builds, after which a genuinely
    /// straggling worker's build is a new key, is refused, and is INVISIBLE:
    /// `build_skew_builds` reads 0, `TalosWorkerFleetBuildSkew` stays silent,
    /// and every published number looks healthy. That is a FALSE NEGATIVE on
    /// the detector, not a nuisance. Inflation (fabricated builds landing in
    /// the skew or unverifiable counts before the cap is reached) is the other
    /// direction and is the milder one — it is loud.
    ///
    /// The same suppression reaches this map through the WORKER cap too:
    /// `handle_heartbeat` returns early at
    /// `talos_worker_fleet::MAX_TRACKED_WORKERS` BEFORE recording the build,
    /// so a flood of distinct ids hides a straggler's build as effectively as
    /// a flood of distinct builds does. `TalosWorkerFleetBuildViewSaturated` and
    /// `TalosWorkerFleetWorkerViewSaturated` alert on the two counters for
    /// exactly that reason.
    ///
    /// Same COUNTER-semantics-with-GAUGE-type trap as its sibling: alert on
    /// the level (`> 0`) or `delta(...[1h]) > 0`, never on a `rate()`.
    pub worker_fleet_capacity_dropped_builds: IntGauge,

    /// Terminal outcomes of scheduler-driven workflow dispatches, split by
    /// whether the dispatch belonged to the **startup backlog** or to steady
    /// state.
    ///
    /// `phase=startup` is the set of schedules found due by the FIRST poll
    /// after a controller boot — i.e. the runs that accumulated while the
    /// process was down. That set is dispatched under a tighter concurrency
    /// ceiling than steady state precisely because releasing it all at once
    /// self-inflicts an outage: on 2026-08-10 fifteen schedules fired within
    /// 20 ms of each other, their WASM jobs opened ~16 simultaneous TLS
    /// connects to Google hosts, five consecutive connect failures tripped
    /// the worker's per-host circuit breaker, and the remaining eight
    /// workflows then failed instantly against an OPEN breaker. Nothing
    /// alerted, and the platform looked healthy minutes later.
    ///
    /// Splitting on `phase` is the whole point: a steady-state failure and a
    /// startup-window failure have completely different causes, and pooling
    /// them hides a defect that fires on EVERY deploy inside a background
    /// failure rate. `outcome=skipped` is the visibly-refused branch (the
    /// per-workflow concurrency cap and the actor budget) — it is NOT a
    /// success, and it is how a dropped daily cron becomes observable rather
    /// than a WARN nobody reads.
    ///
    /// The five outcomes are a PARTITION of dispatch attempts, not a sample:
    /// see [`SCHEDULER_DISPATCH_OUTCOMES`]. Fifteen closed series, all pre-seeded.
    /// Deliberately carries NO workflow name, schedule id or user id — those
    /// are unbounded cardinality.
    pub scheduler_dispatches_total: CounterVec,

    // ---- Adaptive rank-training window (2026-09) ----
    //
    // `ADAPTIVE_RANK_LOOKBACK_DAYS` is documented as a training window clamped
    // to [1, 3650] days, and a hardcoded per-actor row cap binds first. On the
    // reference fleet the configured 30 days is a fitted 6.6, and EVERY value
    // from 7 to 3650 produces a bit-identical model. Until these two series
    // there was no machine-readable signal at all: the only disclosure was a
    // WARN, plus row counts on the stored artifact and in the operator digest
    // — and row counts MOVE when the inert knob is turned, which reads as the
    // change taking effect.
    /// Per-actor training fetches by whether they read the whole configured
    /// lookback window. Labels: `coverage=complete|truncated`
    /// ([`RANK_TRAINING_FETCH_COVERAGES`]) — a PARTITION of every fetch, so the
    /// two reconcile against the actors examined per tick.
    ///
    /// Both series are PRE-SEEDED, and the zero is meaningful in both
    /// directions: `complete=0 AND truncated=0` means no tick has fit anything
    /// yet (training off, or no active actor), which is a different state from
    /// "nothing truncates".
    ///
    /// Deliberately carries NO `actor_id` — it is caller-influenced and stays a
    /// log FIELD. **Nothing alerts on this**: on a fleet with one busy actor the
    /// cap binds on every tick forever, so an alert here would fire
    /// permanently and train operators to ignore it (check 69's trap). It is a
    /// dashboard/questions series, not a page.
    pub rank_training_fetches_total: CounterVec,

    /// Days of the CONFIGURED rank-training window that the NARROWEST fit in
    /// the last completed tick could not reach — `ADAPTIVE_RANK_LOOKBACK_DAYS`
    /// minus the widest window that fit actually saw. `0` when every fetch read
    /// its whole window.
    ///
    /// WORST CASE across the tick, not a per-actor value, because `actor_id`
    /// cannot be a label. One actor whose window is short pulls this up while
    /// every other actor's fit is complete; the counter above is what says how
    /// MANY were affected.
    ///
    /// **Its zero is ambiguous and the counter beside it resolves that**: a
    /// gauge at 0 means either "no fit fell short" or "no tick has run".
    /// `talos_rank_training_fetches_total` summing to 0 distinguishes them.
    pub rank_training_lookback_shortfall_days: Gauge,

    // ---- Fuel-headroom detector (2026-08) ----
    //
    // WHY THIS EXISTS, because it is not another "we had a log, add a
    // counter" case. The number these two publish — peak `fuel_consumed`
    // against the ceiling a worker actually enforced — was **already in the
    // database and had never been compared to anything**.
    // `pa-read-later-digest/digest` sat at 96.9% of its budget for 16 days,
    // ACROSS A SUCCESSFUL RUN, and then failed two of its four scheduled
    // runs. Every fuel surface the platform had was structurally unable to
    // see it: `get_fuel_usage_report` aggregates per MODULE, behind a
    // `min_executions` default of 3, and the adaptive-fuel learner needs
    // `MIN_SAMPLES = 5`. The node had two samples.
    //
    // That report ALSO divided by the shared `modules.max_fuel` rather than
    // the ceiling a worker enforced, so a node-scoped override read against
    // the wrong denominator. **That half is fixed** (2026-08-18): both the
    // per-module and per-node surfaces now measure against the enforced
    // ceiling, so the report no longer contradicts this gauge. The reason
    // THIS pair still has to exist is the OTHER half, which is unchanged and
    // unfixable there — the per-module surface aggregates away the node, uses
    // a percentile rather than a peak, and hides anything under
    // `min_executions`. A node with two runs remains invisible to it.
    //
    // So the defining property of this pair is that it has **NO SAMPLE
    // FLOOR**. It fires at n=1. Adding one back — for smoothing, for
    // noise, for any reason — deletes the only case it was built for.
    /// `(workflow, node)` pairs whose peak observed `fuel_consumed` is at or
    /// above [`crate`-external] threshold × the ceiling most recently enforced
    /// for them, over the detector's window.
    ///
    /// A GAUGE, recomputed from one query each sweep (always `set`, never
    /// `inc`), because the condition is durable state: an under-provisioned
    /// node stays under-provisioned until someone changes the number, and a
    /// counter would go quiet exactly while the fleet stayed exposed.
    ///
    /// UNLABELLED. `workflow_id` and the node label are both author-supplied
    /// and unbounded — a per-node label is an unbounded-cardinality surface on
    /// the scrape path. The names go to a WARN log
    /// (`controller::bootstrap::background::publish_fuel_utilisation`) and to
    /// `get_fuel_usage_report`'s `high_utilisation_nodes`, which are queried
    /// surfaces rather than scraped ones. Same rule and same escape hatch as
    /// `catalog_templates_missing_wasm`.
    ///
    /// TEST EXECUTIONS ARE EXCLUDED from the population. `test_workflow`
    /// writes rollup rows, and a hand-crafted probe payload is traffic that
    /// never happened.
    pub fuel_high_utilisation_nodes: IntGauge,
    /// The DENOMINATOR of [`Self::fuel_high_utilisation_nodes`]: every
    /// `(workflow, node)` pair the detector could evaluate in the window.
    ///
    /// **Published because otherwise a 0 above is unreadable**, and unreadable
    /// in the specific direction that matters. `high = 0` covers both "77 pairs
    /// examined, all healthy" and "the sweep is broken / the rollup is empty /
    /// nothing has run", and an IntGauge exports 0 from registration — so a
    /// detector that never ran looks exactly like a healthy fleet. That is the
    /// blindness this whole change exists to remove, one level up. Same
    /// argument as `worker_fleet_unverifiable_builds`, and
    /// `TalosFuelHeadroomDetectorBlind` is the alert that consumes it.
    pub fuel_utilisation_observed_nodes: IntGauge,

    /// Scheduler poll iterations HELD by the fleet-readiness barrier because
    /// the controller's NATS heartbeat view contained no live worker.
    ///
    /// A hold advances nothing: the barrier runs before the poll's
    /// transaction opens, so `next_trigger_at` is untouched and every due
    /// schedule is still due on the next tick.
    ///
    /// The ORDINARY boot case does not appear here. A worker that booted
    /// before the controller subscribed loses its first heartbeat outright
    /// (NATS core delivery is not retained), so the controller typically waits
    /// most of one heartbeat interval to see it — measured at ~50 s on
    /// 2026-08-10. That wait is absorbed by the scheduler's ONE bounded
    /// pre-loop wait, which deliberately does not count a hold, so a healthy
    /// boot leaves this at 0. It only starts moving once that bound has
    /// already elapsed, i.e. the fleet has been invisible far longer than the
    /// protocol can explain.
    pub scheduler_readiness_holds_total: Counter,

    /// 1 when the scheduler has GIVEN UP waiting for the fleet to become
    /// visible and is dispatching without that evidence; 0 while the barrier
    /// is functioning normally.
    ///
    /// This exists because an empty fleet view is **ambiguous, not proof of
    /// absence** — the same reading covers a genuinely empty fleet, a fleet on
    /// a build too old to publish heartbeats, a broken subscription, and an
    /// operator who set `TALOS_WORKER_HEARTBEAT_INTERVAL_SECS=0` (a supported
    /// configuration that disables heartbeat publishing outright). A barrier
    /// that treated 0 as "known cold" and refused forever would therefore
    /// silently stop ALL scheduled work on a perfectly healthy fleet — strictly
    /// worse than the boot herd it was added to prevent. So the barrier gives
    /// up after a bounded number of consecutive holds and says so here, rather
    /// than blocking indefinitely on a signal it cannot fully trust.
    ///
    /// 1 means: schedules ARE running, but the readiness guarantee is not in
    /// force, so a boot herd could recur.
    ///
    /// **This is a level, not a latch.** It returns to 0 the moment any
    /// heartbeat is seen. As a one-way latch it pinned at 1 on a healthy fleet
    /// — a slow worker image pull outlasts the give-up bound, the worker then
    /// arrives, and the alert fires until the controller restarts. On a
    /// deployment that publishes no heartbeats at all (worker-side
    /// `TALOS_WORKER_HEARTBEAT_INTERVAL_SECS=0`, which the controller cannot
    /// detect) the barrier is switched off wholesale with
    /// `SCHEDULER_FLEET_READINESS_BARRIER=false` and this stays 0, rather than
    /// documenting an alert as expected-to-fire-forever.
    pub scheduler_readiness_degraded: IntGauge,

    // Rate limiting metrics — wired 2026-09-11 at all four limiters
    // (`RateLimitKind::ALL`), seeded at 0. The two per-USER GraphQL throttles
    // joined the family 2026-09-23 (package DY).
    pub rate_limit_hits_total: CounterVec,

    /// `talos_privileged_op_total{outcome}` — every `require_second_factor`
    /// check on the privileged tier. `PrivilegedOpOutcome::ALL`, seeded at 0.
    /// Package DY: this was the LAST bearer/auth surface with no series, so a
    /// deployment that had never refused a key rotation and one whose gate was
    /// not wired rendered identically. No alert — no baseline yet, and a
    /// refusal is the gate working.
    pub privileged_op_total: CounterVec,
    /// `talos_platform_admin_checks_total{outcome}` — every
    /// `require_platform_admin` check. `PlatformAdminOutcome::ALL`, seeded at 0.
    pub platform_admin_checks_total: CounterVec,

    // Google push authentication (Gmail + GCP Pub/Sub) — added 2026-09-12
    // after one JWK fetch failure produced 94 WARN lines and no series. Both
    // seeded over their closed sets (`google_push`).
    pub google_push_refusals_total: CounterVec,
    pub google_push_accepted_total: CounterVec,
    /// `talos_google_push_deferred_total{integration,reason}` — pushes handed
    /// back to the transport for redelivery because Talos could not answer.
    /// `PushIntegration::ALL` x `PushDeferReason::ALL`, seeded at 0. Package ES.
    pub google_push_deferred_total: CounterVec,

    // Deployment-wide execution pause — added 2026-09-14 (package BF) when the
    // pause turned out never to have taken effect. `PauseGatePath::ALL` ×
    // `PauseRefusal::ALL`, seeded at 0; no alert (a refusal is the operator's
    // pause working).
    pub execution_pause_refusals_total: CounterVec,
    /// `talos_webhook_duplicate_suppressed_total{format}` — inbound webhook
    /// deliveries answered 200 and dispatched nothing because the dedup store
    /// had already seen this event. Package CI.
    pub webhook_duplicate_suppressed_total: CounterVec,
    // Actor budget refusals — added 2026-09-17 (package CD). `BudgetCap::ALL`
    // × `BudgetMode::ALL`, seeded at 0; no alert (a refusal is the budget
    // working; `on_budget_exceeded = 'alert'` raises an ops alert instead).
    pub actor_budget_refusals_total: CounterVec,
    pub google_jwk_refresh_total: CounterVec,

    // Vault KEK-token renewal — added 2026-09-14 after the controller's transit
    // token was found to be minted periodic and renewed by nothing
    // (`vault_token`). The counter is seeded by the renewal loop, not here:
    // only a process running a Vault KEK provider can move it.
    pub vault_token_renewals_total: CounterVec,
    pub vault_token_ttl_seconds: IntGaugeVec,

    // RustSec advisory-database age (2026-09-22). The compile gate refuses
    // every Rust compile in production once the baked DB passes
    // TALOS_ADVISORY_DB_MAX_AGE_DAYS, and until these existed the age was
    // computed only when somebody compiled. Three READINGS keyed on `copy`
    // (absent until the hourly sampler's first tick — a seeded 0 would say
    // "built today") and one pre-seeded sample counter, whose `unreadable`
    // value is what says the age reading is stale.
    pub advisory_db_age_days: IntGaugeVec,
    pub advisory_db_max_age_days: IntGaugeVec,
    pub advisory_db_age_enforced: IntGaugeVec,
    pub advisory_db_age_samples_total: CounterVec,

    // `talos_cache_hits_total{cache_type}` / `talos_cache_misses_total` were
    // DELETED 2026-09-11: registered since 2026-05 with a comment naming three
    // caches (wasm, secret, dek), incremented by none of them in four months,
    // referenced by nothing. Re-add WITH a live site when a cache needs it.

    // NOTE — no circuit-breaker metrics here, deliberately.
    //
    // `talos_circuit_breaker_opens_total` / `_blocks_total` were declared and
    // registered on THIS registry from the day this crate was written, and
    // could never have been incremented: the breaker they name is a
    // per-process `OnceLock<HttpCircuitBreaker>` inside `talos-worker-runtime`,
    // running in the WORKER. Both exported a flat 0 forever while the breaker
    // was, in fact, failing scheduled workflows. They now live with their
    // producer (`talos-worker-runtime/src/circuit_breaker.rs`) and are exported
    // under the SAME names by the worker's already-scraped `/metrics`
    // (`job="talos-worker"`). Do not re-declare them here: two producers for
    // one series name, one of them permanently zero, is the false-negative
    // this move removed.

    // DLQ metrics
    pub dlq_entries_total: Counter,
    pub dlq_drops_total: Counter,
    pub dlq_db_errors_total: Counter,

    // Crypto-invariant metrics. These are the highest-blast-radius
    // signals the platform exposes — a Vault outage or KEK / DEK
    // drift causes silent encrypted-at-rest data loss.
    // See deploy/observability/alerts.yaml for the SLOs built on top.
    pub kek_decrypt_failures_total: CounterVec,
    pub memory_write_failures_total: CounterVec,
    /// Child-run ledger writes that produced no row (RFC 0012). Labels:
    /// `reason=acquire|insert`. A sub-workflow leaves no `workflow_executions`
    /// row, so this ledger is the ONLY record that a child ran — a dropped
    /// write is a run that, to every reader, never happened. The write is
    /// best-effort by design (it must never fail the workflow), which is
    /// exactly why the failure needs a series of its own.
    pub child_run_record_failures_total: CounterVec,
    /// Signed-RPC mutations the CONTROLLER refused on the per-actor write
    /// ceiling (#757). Labels: `subject` (the NATS subject) × `reason`
    /// (`policy` | `unreadable`).
    ///
    /// **This is a FLEET-CONFIGURATION signal, not a routine policy event**,
    /// and that is why it is its own series rather than another `reason` on
    /// `talos_memory_write_failures_total`. A worker gates these ops itself;
    /// reaching the controller's gate means the sender did NOT — its
    /// `TALOS_WRITE_CEILING_ENFORCED` is unset, or its build predates the
    /// gate, or it is not a Talos worker at all (the request is signed under
    /// the FLEET-SHARED `WORKER_SHARED_KEY`, which proves possession of a key,
    /// not that a gate ran).
    ///
    /// #757 stated that distinction and routed it to
    /// `event_kind = "rpc_write_ceiling_refused"` plus the per-subject
    /// `talos_rpc` outcome tag. Measured on the live controller 2026-09-05:
    /// `talos_rpc` is a TRACING TARGET ONLY — no `talos_rpc*` Prometheus
    /// series exists — and the memory routes folded into
    /// `talos_memory_write_failures_total{reason="write_ceiling"}`, whose own
    /// HELP text tells operators not to alert on it, while the
    /// integration-state and database routes incremented nothing at all. So
    /// the signal existed as prose and not as a series, and no alert could
    /// select it.
    ///
    /// `reason="unreadable"` is the fail-closed arm (absent actor row, or an
    /// unreadable one). It is an operator problem — a dangling actor id, or a
    /// database the enforcement path cannot reach — not a policy working as
    /// configured, which is why it is a separate label rather than folded in.
    pub rpc_write_ceiling_refusals_total: CounterVec,

    /// Signed-RPC calls the controller served for credential-free workers, by
    /// `subject` × `outcome` × `class`. THE instrument for the whole data
    /// plane: every actor-memory read and write, every graph-RAG search, every
    /// sandbox SQL statement and every model inference crosses one of these
    /// seven subjects.
    ///
    /// Until 2026-09-09 there was none. `record_rpc_metric`'s name asserted a
    /// metric and its body was one `tracing` call, so `curl /metrics/prometheus
    /// | grep '^talos_rpc'` returned only #760's six write-ceiling series —
    /// "how many memory RPCs did we serve, and how fast" was unanswerable in
    /// every channel at once, because the SUCCESS arm logged at `debug!` and
    /// nothing counted it.
    ///
    /// **Cardinality is the design.** All three labels are closed
    /// compile-time sets: `subject` is [`RpcSubject`], `outcome` is
    /// [`RpcOutcome`], and `class` is a pure FUNCTION of `outcome`
    /// ([`OutcomeClass`]) so it adds no series. `actor_id` is a log field
    /// on `record_rpc_metric` and must never be added here — it is
    /// caller-supplied and unbounded.
    ///
    /// **Pre-seeded, and only over the reachable pairs.** All 64 pairs a call
    /// site can pass are seeded at 0 from `rpc::seeded_pairs()`, which IS the
    /// per-subject table; the cross product would be 7 × 18 = 126 and would
    /// seed 62 combinations nothing can increment (check 58's defect). Seeding
    /// matters because `TalosRPCSubjectFailing` selects on this counter and
    /// `increase(...) > 0` over an ABSENT series matches nothing — the
    /// detector silenced by exactly the condition it detects.
    ///
    /// Useful queries: failure share of a subject is
    /// `sum by (subject) (rate(…{class="finding"}[15m])) / sum by (subject)
    /// (rate(…[15m]))`; a signature-failure burst — deliberately NOT alerted
    /// on, because this fleet has produced zero and any threshold would be a
    /// guess that fires on a rolling deploy's clock skew — is
    /// `sum by (subject) (increase(…{outcome="unauthorized"}[15m]))`;
    /// backpressure on a subject is `{outcome="stale_deadline"}`, the queue
    /// outrunning the caller's own deadline.
    pub rpc_calls_total: CounterVec,
    /// Wall-clock duration (semaphore queue + execution) of one signed-RPC
    /// call, same labels and same closed-set rule as [`Self::rpc_calls_total`].
    ///
    /// **Deliberately NOT pre-seeded**, and the reason is narrower than "it is
    /// expensive": the absent-≠-zero rule is a rule about COUNTS. A seeded
    /// histogram over zero observations renders every bucket 0, `_sum` 0 and
    /// `_count` 0 — exactly what the seeded counter at 0 already says — and
    /// `histogram_quantile` over it is NaN either way. It costs 21 lines per
    /// pair against the counter's 1. If an alert is ever written on this
    /// histogram, seed the pairs THAT alert selects, not the table.
    pub rpc_duration_seconds: HistogramVec,

    /// Dispatches refused because the workflow is ARCHIVED — the narrow
    /// lifecycle gate (2026-09-07). Labels: `path` (which dispatch surface
    /// refused, from `talos_workflow_liveness::dispatch::DispatchPath`) ×
    /// `reason` (`archived` today, and only that value has an emitter).
    ///
    /// A non-zero value is the policy WORKING, not a fault: an operator
    /// archived a workflow and something still tried to run it. Nothing alerts
    /// on it, deliberately — an alert here would train operators to ignore the
    /// series, which is the defect the gate exists to remove. What it answers
    /// is the question a silently-filtered dispatch cannot: *a schedule stopped
    /// firing — is the platform refusing it, or is the scheduler broken?*
    ///
    /// Pre-seeded at 0 for every `(path, archived)` pair, because the healthy
    /// steady state is zero forever and `increase(...) > 0` over an ABSENT
    /// series matches nothing.
    ///
    /// It does NOT count the four sites that enforce the gate in SQL (the chain
    /// fan-out, `resolve_by_capabilities`, `resolve_by_name`, the sub-workflow
    /// cache prefetch). Those choose among candidates rather than refusing a
    /// named workflow, so there is no per-request refusal to count — see
    /// `DispatchPath`'s own doc, and CLAUDE.md's stated limit.
    pub dispatch_refused_total: CounterVec,
    /// `ops_alerts` ingest failures from the `__ops_alert__` hook.
    /// Labels: reason=validation|db|tenancy. Sustained bump means alert
    /// envelopes emitted by parser modules are being lost.
    pub ops_alert_ingest_failures_total: CounterVec,
    /// Alerts auto-resolved by a source-signaled recovery
    /// (`status_event: "resolved"` in the __ops_alert__ envelope).
    pub ops_alert_auto_resolved_total: Counter,
    pub module_payload_encryption_failures_total: CounterVec,
    /// Per-row secret-decrypt failures from `SecretsManager::get_module_secrets`.
    /// Labels: reason=missing_dek|cipher_init|aead|invalid_utf8|too_short.
    /// Sustained bump means a module is missing some of its expected
    /// secrets at runtime — `vault://` substitutions will fail with
    /// `Notfound` and HTTP calls will be unauthenticated.
    pub secret_decrypt_failures_total: CounterVec,
    pub actor_memory_orphaned_rows: IntGauge,
    pub module_execution_orphaned_rows: IntGauge,
    pub workflow_execution_orphaned_rows: IntGauge,
    /// Unix time of the last crypto-orphan sweep in which **all three** of the
    /// gauges above were successfully measured.
    ///
    /// **This is the companion "the detector could not measure" signal for the
    /// three `critical` / data-loss orphan alerts**, and it exists for exactly
    /// the reason `fuel_utilisation_observed_nodes` exists for
    /// `fuel_high_utilisation_nodes`: an `IntGauge` exports 0 from
    /// registration, so `talos_actor_memory_orphaned_rows == 0` covers BOTH
    /// "measured, and there are no orphans" and "the `SELECT COUNT(*)` errored
    /// and nothing was ever measured". Those two readings are the same number,
    /// and one of them means the only automated notice that at-rest ciphertext
    /// has become unrecoverable is switched off.
    ///
    /// **Deliberately NOT folded into the orphan counts.** Publishing a
    /// sentinel (`-1`, or a synthetic large value) on failure would make the
    /// counts untrustworthy to every other consumer — `get_health_dashboard`,
    /// the runbook's psql cross-check, and the `{{ $value }}` in the alert
    /// summary all read them as row counts. The blind signal is a separate
    /// series; the counts keep their meaning and simply stop advancing.
    ///
    /// **Why a freshness timestamp rather than a `blind`/`failed` counter.**
    /// A `blind == 0` gauge is itself an unmeasured zero: if the sweep task
    /// never spawns, panics, or is removed in a refactor, nothing sets it and
    /// it reads "not blind" forever — the same defect one level up, which is
    /// the failure mode this whole change exists to remove. A timestamp that
    /// only ever advances on a fully successful sweep degrades the right way
    /// in all four cases: query error, task death, task never spawned, and
    /// controller build predating the sweep (0 from registration, which reads
    /// as maximally stale). The form is the same one
    /// `talos_backup_drill_last_success_timestamp_seconds` already uses.
    ///
    /// **PARTIAL failure counts as blind, on purpose.** Only a sweep in which
    /// all three probes returned advances this. One broken probe leaves two
    /// trustworthy gauges and still raises the alert; for a data-loss detector
    /// that is the right side to err on, and the WARN log
    /// (`target: "talos_crypto"`) names which table failed.
    ///
    /// `TalosCryptoOrphanDetectorBlind` is the alert that consumes it.
    pub crypto_orphan_scan_last_success_timestamp_seconds: Gauge,
    pub dek_cache_size: IntGauge,
    /// Total connections currently held by the controller's sqlx
    /// Postgres pool (idle + in-use). Sampled periodically by a
    /// controller sweep task. Bounded above by `DB_MAX_CONNECTIONS`.
    pub db_pool_connections: IntGauge,
    /// Connections in the pool that are idle (available to hand out).
    pub db_pool_idle_connections: IntGauge,
    /// Connections currently checked out and in use
    /// (`connections - idle`). When this sits at `DB_MAX_CONNECTIONS`,
    /// new acquisitions block on the 10 s acquire timeout — the pool is
    /// saturated and request latency climbs across the whole process.
    pub db_pool_in_use_connections: IntGauge,
    /// The configured max pool size (`DB_MAX_CONNECTIONS`), exported as
    /// a gauge so alerts can compute a saturation RATIO
    /// (`in_use / max`) without hardcoding the limit in PromQL.
    pub db_pool_max_connections: IntGauge,

    /// Per-tool latency of the ONE MCP `tools/call` chokepoint
    /// (`talos_mcp_handlers::handle_tools_call`), labelled
    /// `tool` × `outcome` × `class`.
    ///
    /// `outcome` is a [`McpToolOutcome`] and `class` is a pure function of it
    /// ([`OutcomeClass`]) so the third label adds NO series — verified by
    /// `mcp::tests::the_class_label_adds_no_series`, not assumed. It exists
    /// so a dashboard or an alert can ask "is the platform declining, or
    /// failing?" of this surface in the SAME words it asks the signed-RPC one
    /// ([`rpc_calls_total`](Self::rpc_calls_total)), and so that a future
    /// seventh outcome does not silently fall outside a selector spelled as
    /// an outcome alternation.
    ///
    /// **Cardinality is the design.** `tool` is NEVER the request's own
    /// string: the chokepoint resolves it against the static tool-schema
    /// registry and passes a `&'static str` borrowed from that registry, or
    /// one of two fixed sentinels. A caller-derived label value here would be
    /// an unbounded-cardinality DoS surface reachable by anyone who can reach
    /// `/mcp` — check 58's rule, and the reason
    /// [`record_mcp_tool_call`] takes `&'static str` and an ENUM rather than
    /// two strings.
    ///
    /// **Deliberately NOT pre-seeded, and the number is why.** The label
    /// product is ~320 tools × 6 outcomes, and a 16-bucket histogram series
    /// renders 19 lines, so seeding the product would add ~24 000 lines
    /// (~1.9 MB) to a `/metrics/prometheus` body measured at 567 lines /
    /// 61 128 bytes — a 30× scrape. Seeding only the pairs a live call site
    /// can reach is still ~960 series. Nothing alerts on these two, so the
    /// absent-≠-zero argument that seeds `dispatch_refused_total` does not
    /// apply: an absent `(tool, outcome)` here means "this tool has not been
    /// called since boot", which is what a seeded 0 would have said anyway.
    /// If an alert is ever written on these, seed the pairs THAT alert
    /// selects, not the product.
    pub mcp_tool_duration_seconds: HistogramVec,
    /// Call count for the same chokepoint, same labels, same cardinality
    /// rule. The histogram's `_count` carries the same number; this exists
    /// so a dashboard or alert can rate the calls without depending on the
    /// histogram's bucket layout.
    pub mcp_tool_calls_total: CounterVec,
}

impl TalosMetrics {
    /// Create and register all metrics
    pub fn new() -> anyhow::Result<Arc<Self>> {
        let registry = Registry::new();

        // The process itself: `process_resident_memory_bytes`,
        // `process_virtual_memory_bytes`, `process_open_fds`, `process_max_fds`,
        // `process_threads`, `process_cpu_seconds_total`,
        // `process_start_time_seconds`. Measured 2026-09-11: this registry
        // exported 66 families and NOT ONE of them was about the process — a
        // controller leaking memory or file descriptors had no series anywhere
        // (every `process_*` in the dev Prometheus came from Prometheus,
        // Grafana, Jaeger and node-exporter), so a 26-hour RSS trend could not
        // be read and `docker stats` was the only view. The collector reads
        // procfs, so it is Linux-only by the crate's own cfg; a macOS dev
        // build exports the same 66 families it always did. Not a
        // `TalosMetrics` field on purpose: check 58 audits fields for a live
        // increment site, and a collector is sampled by the registry, never
        // incremented.
        #[cfg(target_os = "linux")]
        registry.register(Box::new(
            prometheus::process_collector::ProcessCollector::for_self(),
        ))?;

        // Webhook metrics (the per-trigger request pair was deleted 2026-09-11;
        // see the struct field comment).
        let webhook_dlq_drops_total = Counter::new(
            "talos_webhook_dlq_drops_total",
            "Total number of webhook requests dropped to DLQ",
        )?;
        registry.register(Box::new(webhook_dlq_drops_total.clone()))?;

        // Authentication metrics
        let auth_attempts_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_auth_attempts_total",
                "Total number of authentication attempts",
            ),
            // Emitted values: password | oauth. See the struct-field comment
            // for why api_key is deliberately not in this population.
            &["method"],
        )?;
        registry.register(Box::new(auth_attempts_total.clone()))?;
        // Pre-seed the two `method` values that are actually emitted
        // (`talos_auth::AUTH_METHOD_PASSWORD` / `_OAUTH`), so a controller
        // that has served no interactive login still EXPORTS the series at 0
        // instead of omitting it. A `CounterVec` emits nothing at all until a
        // label set is first touched, which makes "detector present and
        // quiet" indistinguishable from "detector deleted" on a healthy
        // stack — the exact ambiguity that let five alerted CounterVecs here
        // sit unexercised. `api_key` is deliberately NOT seeded: it is not in
        // this population (see the talos-auth header for why folding it in
        // would make TalosControllerHighErrorRate unfireable in practice).
        //
        // Note precisely what this proves and what it does not: a present
        // denominator shows the auth counters were registered in THIS
        // process. It does not show the failure leg is still wired — that is
        // what the talos-auth unit tests driving the production login path
        // are for.
        for method in ["password", "oauth"] {
            auth_attempts_total.with_label_values(&[method]).inc_by(0.0);
        }

        let auth_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_auth_failures_total",
                "Total number of authentication failures",
            ),
            // Emitted reasons are a closed literal set owned by the emitting
            // crate — see the `AUTH_REASON_*` constants in `talos-auth`.
            // Never a username, IP, or key id: this endpoint is scrapeable
            // and the label set must stay bounded.
            &["method", "reason"],
        )?;
        registry.register(Box::new(auth_failures_total.clone()))?;
        // DELIBERATELY NOT PRE-SEEDED, unlike its denominator above. The
        // `reason` values are a closed set of `&'static str` constants, but
        // the (method, reason) PRODUCT is not a valid population: only 9 of
        // the 16 pairs have an emitting call site (`unknown_user`, `locked`,
        // `lockout_triggered`, `invalid_password` are password-only;
        // `provider_error`, `csrf_state`, `link_failed` are oauth-only), and
        // seeding a pair nothing writes would imply a wired signal that does
        // not exist. Encoding the real pairing here would also mean copying
        // talos-auth's constants across a dependency edge that only points
        // the other way (talos-auth depends on this crate), so the two could
        // drift silently. Absence of a failure series is the correct
        // non-alerting answer anyway — see the TalosControllerHighErrorRate
        // comment in deploy/helm/talos/files/alerts.yaml.

        let auth_2fa_attempts_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_auth_2fa_attempts_total",
                "Interactive 2FA verifications (TOTP or backup code), by outcome. \
                 status=success|failure (talos_metrics::TwoFactorOutcome, a closed \
                 set); recorded at TotpService's success/failure recorders, so every \
                 verification branch is counted. Both values pre-seeded at 0 — a \
                 counter born at 1 loses its first increment to increase()/rate(). \
                 Registered 2026-05, first incremented 2026-09-11.",
            ),
            &["status"],
        )?;
        registry.register(Box::new(auth_2fa_attempts_total.clone()))?;
        for outcome in TwoFactorOutcome::ALL {
            auth_2fa_attempts_total
                .with_label_values(&[outcome.as_str()])
                .inc_by(0.0);
        }

        let api_key_validations_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_api_key_validations_total",
                "API-key validation verdicts (ApiKeyService::validate_key), by outcome. \
                 status=valid|invalid|expired|rate_limited (talos_metrics::ApiKeyValidation, \
                 a closed set); expired means EVERY candidate for the prefix was past its \
                 expiry; a DB failure mid-validation is not a verdict and records nothing. \
                 Deliberately NOT part of the interactive-login ratio alert (see the field \
                 comment). All four values pre-seeded at 0. Registered 2026-05, first \
                 incremented 2026-09-11.",
            ),
            &["status"],
        )?;
        registry.register(Box::new(api_key_validations_total.clone()))?;
        for verdict in ApiKeyValidation::ALL {
            api_key_validations_total
                .with_label_values(&[verdict.as_str()])
                .inc_by(0.0);
        }

        let mcp_auth_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_mcp_auth_total",
                "MCP agent-token authentication outcomes (mcp_auth_middleware), one per \
                 /mcp request. outcome=ok | missing_token (no bearer header and no ?token=) \
                 | unknown_token (no active mcp_agents row carries the token's lookup hash \
                 — a guessed, mistyped or REVOKED token; the guessing signal) | \
                 invalid_token (a row's lookup hash matches and its bcrypt hash does not — \
                 a corrupted or hand-edited row, not a guess) | unscoped_agent (authenticated, \
                 mcp_agents.user_id IS NULL, 403) | rate_limited (the per-IP limiter, also \
                 rate_limit_hits_total{type=mcp_auth}) | error (lookup failed / bcrypt worker \
                 panicked / stored hash malformed — counted, so a surface failing every \
                 request is not quiet). talos_metrics::McpAuthOutcome, a closed set, all \
                 seven pre-seeded at 0. The caller sees one 401 for the three token \
                 outcomes; the split is for the operator. Registered and first incremented \
                 2026-09-13.",
            ),
            &["outcome"],
        )?;
        registry.register(Box::new(mcp_auth_total.clone()))?;
        for outcome in McpAuthOutcome::ALL {
            mcp_auth_total
                .with_label_values(&[outcome.as_str()])
                .inc_by(0.0);
        }

        let ws_handshakes_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_ws_handshakes_total",
                "WebSocket (/ws) handshake outcomes, one per socket, recorded at the \
                 handshake's single exit in talos-ws-auth. outcome=authenticated | \
                 origin_missing / origin_malformed / origin_not_allowed (the Cross-Site \
                 WebSocket Hijacking signal; missing is refused in production only) | \
                 no_token / invalid_token / invalid_user_id (connection_init completed \
                 without a usable access-token cookie; the caller sees one \
                 connection_error for all three) | protocol_violation (first frame was \
                 not connection_init) | init_not_received (no connection_init within \
                 30 s or the client left first). talos_metrics::WsHandshakeOutcome, a \
                 closed set, all nine pre-seeded at 0. No alert yet: no baseline. \
                 Registered and first incremented 2026-09-22.",
            ),
            &["outcome"],
        )?;
        registry.register(Box::new(ws_handshakes_total.clone()))?;
        for outcome in WsHandshakeOutcome::ALL {
            ws_handshakes_total
                .with_label_values(&[outcome.as_str()])
                .inc_by(0.0);
        }

        let ws_session_ends_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_ws_session_ends_total",
                "How an AUTHENTICATED WebSocket session ended. reason=token_expired (the \
                 session's hard deadline — the access token's remaining life — fired: \
                 the stolen-cookie exposure bound working) | client_terminated \
                 (connection_terminate or a Close frame) | stream_ended (the transport \
                 went away). talos_metrics::WsSessionEnd, closed, all three pre-seeded \
                 at 0. Registered 2026-09-22.",
            ),
            &["reason"],
        )?;
        registry.register(Box::new(ws_session_ends_total.clone()))?;
        for reason in WsSessionEnd::ALL {
            ws_session_ends_total
                .with_label_values(&[reason.as_str()])
                .inc_by(0.0);
        }

        let ws_operations_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_ws_operations_total",
                "start/subscribe frames on authenticated WebSocket sessions. \
                 outcome=started (a subscription stream was opened) | \
                 refused_non_subscription (the lane executes subscriptions only — a query \
                 or mutation sent over /ws is refused, 2026-09-10) | \
                 refused_pre_second_factor (a password-only session may not subscribe, \
                 2026-07-19 P3) | refused_too_many (the per-socket subscription cap, \
                 MAX_SUBSCRIPTIONS_PER_SOCKET) | refused_duplicate_id (a start reusing a \
                 live id). The first two refusals were talos_audit log lines only until \
                 2026-09-22; the last two exist since the lane multiplexes (package DV). \
                 talos_metrics::WsOperationOutcome, closed, all five pre-seeded at 0.",
            ),
            &["outcome"],
        )?;
        registry.register(Box::new(ws_operations_total.clone()))?;
        for outcome in WsOperationOutcome::ALL {
            ws_operations_total
                .with_label_values(&[outcome.as_str()])
                .inc_by(0.0);
        }

        let ws_active_sessions = IntGauge::new(
            "talos_ws_active_sessions",
            "Authenticated WebSocket sessions currently open on this controller \
             (per process — sum across replicas for the fleet). Incremented when the \
             connection_ack is sent, decremented by a Drop guard however the session \
             ends. The frontend opens one socket per subscription, so one dashboard \
             load is several sessions (3 measured on 2026-09-22).",
        )?;
        registry.register(Box::new(ws_active_sessions.clone()))?;

        let password_changes_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_password_changes_total",
                "Password changes a signed-in user requested (AuthService::change_password), \
                 one per request. outcome=changed | wrong_current_password (the current \
                 password did not match — the guessing signal; shares the login lockout \
                 counter) | locked (the account is locked after repeated wrong passwords) | \
                 policy_rejected (the new password fails the policy; not counted toward the \
                 lockout) | unchanged (the new password is the current one) | conflict \
                 (another request changed the password first) | error (could not decide — \
                 counted, so a surface failing every request is not quiet). \
                 talos_metrics::PasswordChangeOutcome, a closed set, all seven pre-seeded \
                 at 0. Registered 2026-09-18.",
            ),
            &["outcome"],
        )?;
        registry.register(Box::new(password_changes_total.clone()))?;
        for outcome in PasswordChangeOutcome::ALL {
            password_changes_total
                .with_label_values(&[outcome.as_str()])
                .inc_by(0.0);
        }

        // The refresh-token REUSE DETECTOR. Refresh rotation makes a stolen
        // token self-announcing, `rotated_session_audit` turns the resulting
        // miss into evidence, and `revoke_all_sessions` is the response — the
        // platform's ONLY automated stolen-credential response. Until
        // 2026-09-21 it produced NO machine-readable output: one
        // `target: "talos_security_alert"` line, the sole emitter of that
        // target in the workspace, with no layer, rule, scrape or script
        // subscribing to it, so a detection and a non-detection rendered
        // identically everywhere an operator looks.
        let token_reuse_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_auth_token_reuse_total",
                "Refresh-token reuse-detector verdicts, one per failed refresh that \
                 reaches the detector. outcome=not_reused (no audit row — a stale \
                 bookmark or a logged-out session; the common case) | within_grace (an \
                 audit row younger than the grace window: two tabs raced one rotation, \
                 deliberately not revoked) | detected (a stolen token was replayed AND \
                 every session for that user was revoked) | revoke_failed (replay \
                 detected and the revoke FAILED — the detection is real, the response \
                 did not happen) | detector_unreadable (the audit read itself failed: \
                 the control did not run, and this says NOTHING about whether the token \
                 was reused). Alert on reuse must select detected AND revoke_failed. \
                 The caller cannot tell any of these apart — every path answers the same \
                 generic refusal, so a thief learns nothing. \
                 talos_metrics::TokenReuseOutcome, a closed set, all five pre-seeded at \
                 0. Registered 2026-09-21.",
            ),
            &["outcome"],
        )?;
        registry.register(Box::new(token_reuse_total.clone()))?;
        for outcome in TokenReuseOutcome::ALL {
            token_reuse_total
                .with_label_values(&[outcome.as_str()])
                .inc_by(0.0);
        }

        // The ARM side of the same control: the detector can only recognise a
        // replayed token if the rotation that retired it wrote the audit row.
        // That INSERT is best-effort by design (it must never fail a
        // legitimate refresh), so a PERSISTENT failure disarms the detector
        // fleet-wide while every verdict reads `not_reused` — a green
        // detector over a dead control, check 58's class. Counted on BOTH
        // outcomes so the failure series has a denominator.
        let rotation_audit_arm_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_auth_rotation_audit_arm_total",
                "Refresh-token rotations by whether they ARMED the reuse detector, one \
                 per rotation. outcome=armed (the rotated_session_audit row was written, \
                 so a later replay of the retired token is detectable) | failed (the \
                 INSERT failed; the rotation still succeeded and the user got their new \
                 token, but a replay of the retired token will read as not_reused). \
                 This is also the controller's only volume series for the refresh path. \
                 talos_metrics::RotationAuditArmOutcome, a closed set, both pre-seeded \
                 at 0. Registered 2026-09-21.",
            ),
            &["outcome"],
        )?;
        registry.register(Box::new(rotation_audit_arm_total.clone()))?;
        for outcome in RotationAuditArmOutcome::ALL {
            rotation_audit_arm_total
                .with_label_values(&[outcome.as_str()])
                .inc_by(0.0);
        }

        // Execution metrics. Both module families sat in check 58's dead-metric
        // baseline from 2026-05 to 2026-09-11; they are now moved by every
        // module_executions finalizer (talos-module-executions: complete /
        // fail / timeout, the two worker-result paths, the stuck sweep; the
        // engine's race-safe INSERT for born-cancelled rows). `trigger_type`
        // was dropped from the counter while it was still dead — the column
        // reads `webhook` on all 55 279 rows of the reference fleet.
        let module_executions_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_module_executions_total",
                "Terminal module-execution outcomes, by status. \
                 status=completed|failed|timeout|cancelled — the module_executions.status \
                 terminal states spelled as the column spells them \
                 (talos_metrics::ModuleExecutionOutcome, a closed set, all four pre-seeded \
                 at 0). timeout covers BOTH the per-execution finalizer and the \
                 stuck-execution sweep; cancelled is the engine's born-terminal row. \
                 Registered 2026-05, first incremented 2026-09-11.",
            ),
            &["status"],
        )?;
        registry.register(Box::new(module_executions_total.clone()))?;
        for outcome in ModuleExecutionOutcome::ALL {
            module_executions_total
                .with_label_values(&[outcome.as_str()])
                .inc_by(0.0);
        }

        let module_execution_duration_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "talos_module_execution_duration_seconds",
                "Wall-clock duration of one module execution, completed_at - started_at as \
                 the finalizing UPDATE's RETURNING computed it (database clock). Same \
                 status label as talos_module_executions_total; NOT pre-seeded (a \
                 quantile needs no first observation — read volume from the counter). \
                 A born-cancelled row has no duration and is absent here.",
            )
            .buckets(exponential_buckets(0.01, 2.0, 15).expect("valid exponential buckets")),
            &["status"],
        )?;
        registry.register(Box::new(module_execution_duration_seconds.clone()))?;

        let workflow_executions_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_workflow_executions_total",
                "Total number of workflow executions",
            ),
            &["status"], // success, failure, timeout, cancelled
        )?;
        registry.register(Box::new(workflow_executions_total.clone()))?;
        // Pre-seed the two terminal outcomes the finalizers write (success /
        // failure) at 0 — same reasoning as crash_recovery_total below: the
        // series must exist in steady state so `rate()` in the
        // TalosWorkflowFailureRateHigh alert (deploy/helm files/alerts.yaml)
        // has something to reference before the first failure. `timeout` /
        // `cancelled` are deliberately NOT seeded: nothing increments them yet
        // (the scheduler writes those states via a raw UPDATE), so seeding
        // them would imply a wired signal that doesn't exist.
        for outcome in ["success", "failure"] {
            workflow_executions_total
                .with_label_values(&[outcome])
                .inc_by(0.0);
        }

        let workflow_execution_duration_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "talos_workflow_execution_duration_seconds",
                "Wall-clock duration of one workflow execution, completed_at - started_at \
                 as the finalizing UPDATE's RETURNING computed it (database clock), \
                 observed at the same five finalizers that move \
                 talos_workflow_executions_total and with the same status label \
                 (success|failure). NOT pre-seeded (read volume from the counter). \
                 Registered 2026-05, first observed 2026-09-11.",
            )
            .buckets(exponential_buckets(0.1, 2.0, 15).expect("valid exponential buckets")),
            &["status"],
        )?;
        registry.register(Box::new(workflow_execution_duration_seconds.clone()))?;

        let crash_recovery_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_crash_recovery_total",
                "Total crash-recovery resume outcomes since process start",
            ),
            &["outcome"], // resumed, failed, reclaimed
        )?;
        registry.register(Box::new(crash_recovery_total.clone()))?;
        // Pre-seed the outcome series to 0. Unlike the high-frequency execution
        // counters above, crash-recovery only fires on a restart-with-orphans,
        // so without seeding these series would be absent in steady state and
        // `rate()` / absence alerts + dashboard panels would have nothing to
        // reference. A counter seeded at 0 is correct and always present.
        for outcome in ["resumed", "failed", "reclaimed"] {
            crash_recovery_total
                .with_label_values(&[outcome])
                .inc_by(0.0);
        }

        let condition_eval_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_condition_eval_failures_total",
                "Rhai condition expressions that failed to evaluate and were \
                 replaced by the call site's silent default. \
                 kind=skip_condition is FAIL-OPEN — the node the author gated \
                 RAN. Every other kind fails conservatively (branch not taken, \
                 loop broken, check failed).",
            ),
            &["kind"],
        )?;
        registry.register(Box::new(condition_eval_failures_total.clone()))?;
        // Pre-seed every kind at 0. The expected steady state is zero, so
        // without seeding the series is ABSENT and `increase(...[15m]) > 0`
        // has nothing to reference until the first failure — the detector
        // silenced by exactly the condition it detects. Seeding also keeps
        // "gate present and quiet" distinguishable from "gate deleted".
        //
        // The list is closed and compile-time-known (see CONDITION_EVAL_KINDS)
        // — seeding a caller-derived value would be unbounded cardinality, and
        // seeding a kind nothing increments would imply a wired signal that
        // does not exist.
        for kind in CONDITION_EVAL_KINDS {
            condition_eval_failures_total
                .with_label_values(&[kind])
                .inc_by(0.0);
        }

        // ---- Detector metrics (2026-08) ----
        let wasm_log_orphaned_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_wasm_log_orphaned_total",
                "WASM log lines discarded because they could not be routed to \
                 any execution row. Labels: kind=no_execution_row|unparseable_id. \
                 Non-zero means a dispatch path is minting execution ids without \
                 recording a row — those executions' logs are lost.",
            ),
            &["kind"],
        )?;
        registry.register(Box::new(wasm_log_orphaned_total.clone()))?;
        // Pre-seed both kinds at 0, same reasoning as crash_recovery_total: the
        // expected steady state is zero, so without seeding the series would be
        // ABSENT and `increase(...[15m]) > 0` would have nothing to reference
        // until the first incident. Seeding at 0 also lets a dashboard show
        // "detector present and quiet" rather than "detector missing".
        for kind in ["no_execution_row", "unparseable_id"] {
            wasm_log_orphaned_total
                .with_label_values(&[kind])
                .inc_by(0.0);
        }

        let module_execution_record_started_failures_total = Counter::new(
            "talos_module_execution_record_started_failures_total",
            "Failures writing the module_executions start row at the \
             PostgresModuleExecutionStore::record_started chokepoint. Non-fatal \
             by design, so the execution proceeds — but its row is missing, its \
             WASM logs orphan, and get_execution_logs / get_node_io / cost \
             attribution silently under-report.",
        )?;
        registry.register(Box::new(
            module_execution_record_started_failures_total.clone(),
        ))?;

        let module_executions_swept_stuck_total = Counter::new(
            "talos_module_executions_swept_stuck_total",
            "module_executions rows the stuck-execution sweep converted to \
             'timeout' because nothing ever finalized them. Sustained non-zero \
             means rows are opened and never closed — a broken ledger, not a \
             broken fleet. Registration alone exports it at 0, so an alert on \
             it cannot be silenced by the series being absent.",
        )?;
        registry.register(Box::new(module_executions_swept_stuck_total.clone()))?;

        let module_executions_retention_deleted_total = Counter::new(
            "talos_module_executions_retention_deleted_total",
            "module_executions rows DELETEd by the opt-in row-retention sweep \
             (MODULE_EXECUTION_RETENTION_ENABLED), each cascading its \
             module_execution_logs children. Deletion is irreversible and \
             leaves no tombstone, so this counter is the only record that the \
             sweep ran. Distinct from talos_module_execution_orphaned_rows, \
             which counts rows referencing a MISSING DEK. Registration alone \
             exports it at 0, so an alert on it cannot be silenced by the \
             series being absent.",
        )?;
        registry.register(Box::new(module_executions_retention_deleted_total.clone()))?;

        let job_results_dropped_unparseable_total = Counter::new(
            "talos_job_results_dropped_unparseable_total",
            "Job results discarded by the talos.results.* subscriber because \
             the payload would not deserialize into a JobResult. That \
             subscriber is the only finalizer for the fire-and-forget \
             module-bound dispatch paths, so each drop loses a terminal \
             module_executions status write, its output_data, and its \
             __ops_alert__ ingest. Registration alone exports it at 0, so an \
             alert on it cannot be silenced by the series being absent.",
        )?;
        registry.register(Box::new(job_results_dropped_unparseable_total.clone()))?;

        let audit_verification_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_audit_verification_failures_total",
                "WORM audit-ledger verification failures. Labels: \
                 stage=event|chain. stage=event is the inline per-message check \
                 at ingest (message quarantined, not persisted); stage=chain is \
                 the offline hash-chain sweep over a completed execution. Either \
                 is positive tamper/corruption evidence.",
            ),
            &["stage"],
        )?;
        registry.register(Box::new(audit_verification_failures_total.clone()))?;
        // Seeded for the same reason as the orphan counter above — the CRITICAL
        // alert on this series must have something to reference in steady state.
        for stage in ["event", "chain"] {
            audit_verification_failures_total
                .with_label_values(&[stage])
                .inc_by(0.0);
        }

        let audit_chain_unverifiable_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_audit_chain_unverifiable_total",
                "Executions whose WORM audit chain could not be READ, by classified \
                 reason (access_denied, no_such_bucket, not_found, transport, other, \
                 no_credentials, empty_chain). Distinct from \
                 talos_audit_verification_failures_total: unverifiable is not \
                 verified-bad, so a store outage must not page as a tamper incident. \
                 access_denied on this platform means the verifier is running as the \
                 WRITE-ONLY writer identity, which cannot list or get by design.",
            ),
            &["reason"],
        )?;
        registry.register(Box::new(audit_chain_unverifiable_total.clone()))?;
        // The reason set is closed and every value has a live increment site in
        // `talos-audit-ledger`, so seeding all six implies no signal that is not
        // wired. Absent ≠ zero: `increase(...[2h]) > 0` over an untouched series
        // matches nothing.
        for reason in [
            "access_denied",
            "no_such_bucket",
            "not_found",
            "transport",
            "other",
            "no_credentials",
            "empty_chain",
        ] {
            audit_chain_unverifiable_total
                .with_label_values(&[reason])
                .inc_by(0.0);
        }

        let audit_chain_jobs_swept_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_audit_chain_jobs_swept_total",
                "Job chains the audit-chain verification sweep classified, by outcome \
                 (verified_ok, unanchored, empty, failed, errored). `unanchored` is NOT a \
                 failure — the chain verified, but a dispatch sealed no terminal anchor, so \
                 its tail is unprovable; every prefix this fleet wrote since 2026-08-01 is \
                 anchored, so a climbing unanchored means the producer stopped sealing them. \
                 The DENOMINATOR \
                 TalosAuditChainJobsUnverifiable divides talos_audit_chain_unverifiable_total's \
                 per-job reasons by: one empty prefix is a worker that died mid-flight, \
                 a quarter of the population is the audit-ledger subscriber. Pre-seeded \
                 over the closed set; 0/0 on an idle fleet is NaN and matches nothing.",
            ),
            &["outcome"],
        )?;
        registry.register(Box::new(audit_chain_jobs_swept_total.clone()))?;
        // The outcome set is `talos_audit_ledger::JobChainOutcome::ALL`, pinned
        // equal to this list by `job_chain_outcome_labels_are_the_seeded_set`
        // in that crate (it cannot be imported here without inverting the
        // layering — #760's `RPC_WRITE_CEILING_SUBJECTS` precedent).
        for outcome in ["verified_ok", "unanchored", "empty", "failed", "errored"] {
            audit_chain_jobs_swept_total
                .with_label_values(&[outcome])
                .inc_by(0.0);
        }

        let audit_ledger_duplicate_deliveries_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_audit_ledger_duplicate_deliveries_total",
                "EXACT duplicate audit events dropped by the WORM ledger writer before \
                 persistence, by scope (batch). At-least-once delivery is the transport \
                 working as designed, so this is NOT tamper evidence and NOTHING alerts \
                 on it — it is kept off talos_audit_verification_failures_total precisely \
                 so that counter's steady state stays 0 and its CRITICAL alert stays \
                 meaningful.",
            ),
            &["scope"],
        )?;
        registry.register(Box::new(audit_ledger_duplicate_deliveries_total.clone()))?;

        let audit_ledger_consumer_pending = IntGauge::new(
            "talos_audit_ledger_consumer_pending",
            "Audit events the JetStream AUDIT_LEDGER stream holds that the WORM-ledger \
             consumer has not yet been delivered (consumer num_pending), sampled every \
             5 s. The buffer's fill level: the stream is age-bounded (30 d), so a climbing \
             backlog is a subscriber not shipping to S3, and events older than the bound \
             expire unshipped. Healthy steady state is 0 to one batch.",
        )?;
        registry.register(Box::new(audit_ledger_consumer_pending.clone()))?;
        // `batch` is the ONLY scope with a live increment site — the writer is
        // write-only and cannot see a cross-batch copy. Seeding a second value
        // would imply a signal that is not wired (check 58's own rule read
        // from the label side).
        audit_ledger_duplicate_deliveries_total
            .with_label_values(&["batch"])
            .inc_by(0.0);

        let audit_chain_duplicate_deliveries_total = Counter::new(
            "talos_audit_chain_duplicate_deliveries_total",
            "Job chains the offline audit-chain sweep found carrying a BYTE-IDENTICAL \
             redelivery — the copies the write-only ledger writer could not dedupe \
             because they arrived in different batches. Such a chain still VERIFIES: it \
             is counted in jobs_verified_ok, never in jobs_failed, and nothing alerts on \
             this series. Registration alone exports it at 0 so absent and zero do not \
             render alike.",
        )?;
        registry.register(Box::new(audit_chain_duplicate_deliveries_total.clone()))?;

        let audit_chain_multi_attempt_jobs_total = Counter::new(
            "talos_audit_chain_multi_attempt_jobs_total",
            "Job chains the offline audit-chain sweep found holding more than one \
             CONTROLLER DISPATCH ATTEMPT. A re-dispatch re-uses the job_id and the \
             credential-free worker cannot read the prior dispatch's ledger, so it \
             opens a fresh chain at sequence 1 — a retry, not tamper evidence. Such \
             a chain VERIFIES and is counted in jobs_verified_ok; nothing alerts on \
             this series. Registration alone exports it at 0 so absent and zero do \
             not render alike.",
        )?;
        registry.register(Box::new(audit_chain_multi_attempt_jobs_total.clone()))?;

        let audit_chain_last_verified_ok_timestamp_seconds = Gauge::new(
            "talos_audit_chain_last_verified_ok_timestamp_seconds",
            "Unix time at which an execution's WORM audit chain last verified CLEAN. \
             ABSENT until the first success in this process — a zero seed would read \
             as 1970 and fire every staleness rule on a healthy cold boot, so the \
             alert carries an explicit absent() arm instead.",
        )?;
        registry.register(Box::new(
            audit_chain_last_verified_ok_timestamp_seconds.clone(),
        ))?;

        let audit_chain_sweep_timestamp_seconds = Gauge::new(
            "talos_audit_chain_sweep_timestamp_seconds",
            "Unix time at which the audit-chain verification sweep last completed a \
             pass, whatever it found. Paired with \
             talos_audit_chain_last_verified_ok_timestamp_seconds: the sweep being \
             alive and the control working are different facts, and on the deployment \
             this was added for they disagreed for two months.",
        )?;
        registry.register(Box::new(audit_chain_sweep_timestamp_seconds.clone()))?;

        let worker_key_tofu_conflicts_total = Counter::new(
            "talos_worker_key_tofu_conflicts_total",
            "Worker self-registration refusals where the presented key is not \
             the worker_id's bound trust-on-first-use identity. Possible \
             in-fleet impersonation; legitimate rotation goes through the \
             operator CLI or a worker_id-bound provisioning token.",
        )?;
        registry.register(Box::new(worker_key_tofu_conflicts_total.clone()))?;

        let http_missing_extension_total = Counter::new(
            "talos_http_missing_extension_total",
            "Responses where a mounted route extracted an axum Extension its \
             router does not provide (a wiring defect, answered 500 with the \
             body replaced). Zero on a correctly wired controller; the route \
             is named in the route_missing_extension ERROR log line.",
        )?;
        registry.register(Box::new(http_missing_extension_total.clone()))?;

        let worker_build_skew_workers = IntGauge::new(
            "talos_worker_build_skew_workers",
            "Distinct worker_ids with an ACTIVE worker_identities row whose \
             build PROVABLY differs from this controller's (different commit \
             sha, or -dirty on one side only). Recomputed each sweep, so it \
             falls back to 0 once the fleet converges OR the stale rows are \
             deactivated — ACTIVE means 'row not deactivated', not 'process \
             running'. A departed pod's row is reaped only if the identity \
             reaper is enabled (OFF by default), and a row that never sent a \
             liveness ping needs its second, separately-gated arm; otherwise \
             it must be deactivated by an operator. Workers \
             that report no usable sha are 'unverifiable' and are NOT counted.",
        )?;
        registry.register(Box::new(worker_build_skew_workers.clone()))?;

        let catalog_templates_missing_wasm = IntGauge::new(
            "talos_catalog_templates_missing_wasm",
            "Catalog templates whose wasm_bytes is NULL/empty AND which carry no \
             oci_url — they have neither local bytes nor a registry reference and \
             cannot run at all. Published at boot after that boot's background \
             compiles settle, then re-measured every 300s, so it falls back to 0 \
             once the templates build and rises again if a row loses its bytes \
             mid-life. HOLDS its last value if the query fails rather than \
             zeroing; talos_catalog_missing_wasm_scan_last_success_timestamp_seconds \
             is how a held value is told from a measured one. Names are in \
             get_catalog_status → never_compiled (deliberately not a label: \
             template names are registry-supplied in OCI mode).",
        )?;
        registry.register(Box::new(catalog_templates_missing_wasm.clone()))?;

        let catalog_missing_wasm_scan_last_success_timestamp_seconds = Gauge::new(
            "talos_catalog_missing_wasm_scan_last_success_timestamp_seconds",
            "Unix time of the last sweep that successfully measured \
             talos_catalog_templates_missing_wasm. Not seeded and not reset: it \
             reads 0 until the first successful measurement, which is maximally \
             stale, so a controller that never ran the sweep is loud rather than \
             silent. The missing-wasm gauge reads 0 both when every template can \
             run and when the query never returned; this is how those cases are \
             told apart. TalosCatalogMissingWasmDetectorBlind alerts on it.",
        )?;
        registry.register(Box::new(
            catalog_missing_wasm_scan_last_success_timestamp_seconds.clone(),
        ))?;

        // ---- Worker-identity liveness + reaper ----
        let worker_liveness_pings_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_worker_liveness_pings_total",
                "Proof-of-possession liveness pings received at \
                 POST /internal/worker-liveness. Labels: outcome=accepted|\
                 rejected_request|rejected_proof|inactive_identity|error, \
                 derived from the response status so the counter can never \
                 distinguish more than the endpoint's own reply. Never \
                 labelled by worker_id or key — the endpoint is \
                 unauthenticated and a caller-derived label is unbounded \
                 cardinality.",
            ),
            &["outcome"],
        )?;
        registry.register(Box::new(worker_liveness_pings_total.clone()))?;
        // Seed ALL FIVE: every value has a live emitting site, because the
        // label is derived from the status and each status class is reachable
        // (`liveness_outcome_label` maps 2xx/400/401/404/5xx). Seeding matters
        // more here than for most detectors: the steady state of the two
        // failure-shaped values is 0, and at the enablement runbook's step 0
        // (does the instrumentation exist at all) and step 4 (THE GATE) an
        // operator reads these series to decide whether the fleet is pinging
        // at all. An ABSENT series and a 0 one answer that question
        // differently, and absent is the answer that gets a fleet reaped.
        for outcome in [
            "accepted",
            "rejected_request",
            "rejected_proof",
            "inactive_identity",
            "error",
        ] {
            worker_liveness_pings_total
                .with_label_values(&[outcome])
                .inc_by(0.0);
        }

        let worker_identity_reaps_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_worker_identity_reaps_total",
                "Worker signing keys deactivated by the worker-identity \
                 reaper. Labels: arm=departed|pre_protocol. `departed` is the \
                 automatic arm (liveness silence past \
                 TALOS_WORKER_IDENTITY_REAP_HOURS); `pre_protocol` is the \
                 opt-in arm for rows that never participated. A reaped key \
                 cannot re-register itself — every count here needs an \
                 operator if the worker is still alive.",
            ),
            &["arm"],
        )?;
        registry.register(Box::new(worker_identity_reaps_total.clone()))?;
        // Both arms seeded: both have a live emitting site in the reaper
        // sweep. `pre_protocol` only ever moves when an operator sets its env
        // var, but the code path exists unconditionally — same case as
        // crash_recovery_total's `reclaimed`. The expected steady state of
        // BOTH is 0 forever, which is precisely why they must be present
        // rather than absent: `increase(...) > 0` over an absent series
        // matches nothing, so an un-seeded counter would leave the reap alert
        // unfireable until the first reap it was supposed to warn about.
        for arm in ["departed", "pre_protocol"] {
            worker_identity_reaps_total
                .with_label_values(&[arm])
                .inc_by(0.0);
        }

        let oauth_reactive_refresh_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_oauth_reactive_refresh_total",
                "Reactive OAuth credential repairs attempted after a job \
                 failed with an authentication error on a Talos-held OAuth \
                 credential. Labels: \
                 outcome=repaired|not_refreshed|refresh_failed. \
                 `refresh_failed` is the arm that needs a human — the token \
                 endpoint refused, which for Google/Atlassian means the grant \
                 is revoked or expired and the integration must be \
                 re-consented.",
            ),
            &["outcome"],
        )?;
        registry.register(Box::new(oauth_reactive_refresh_total.clone()))?;
        // Seed all three: the healthy steady state is that NONE of them ever
        // moves, so without seeding the whole family is absent and
        // `increase(...) > 0` — the shape the re-auth alert uses — matches
        // nothing. Every one of the three has a live emitting site in
        // `OAuthCredentialService::force_refresh_oauth_tokens_in_batch`.
        for outcome in ["repaired", "not_refreshed", "refresh_failed"] {
            oauth_reactive_refresh_total
                .with_label_values(&[outcome])
                .inc_by(0.0);
        }

        let worker_liveness_participants = IntGauge::new(
            "talos_worker_liveness_participants",
            "Distinct worker_ids with an ACTIVE worker_identities row that \
             have proved liveness at least once — the automatic reaper's \
             population. Recomputed each sweep. Rows that never pinged \
             (last_liveness_at IS NULL) are NOT counted: the automatic reaper \
             cannot act on them.",
        )?;
        registry.register(Box::new(worker_liveness_participants.clone()))?;

        let worker_liveness_recent_participants = IntGauge::new(
            "talos_worker_liveness_recent_participants",
            "The subset of talos_worker_liveness_participants whose last \
             liveness proof is inside the participation horizon (2h, or the \
             configured trust window if shorter) — i.e. still actively \
             pinging. participants MINUS this is the number of trusted keys \
             that have stopped proving liveness and are heading for a reap.",
        )?;
        registry.register(Box::new(worker_liveness_recent_participants.clone()))?;

        let worker_liveness_population_truncated = IntGauge::new(
            "talos_worker_liveness_population_truncated",
            "1 when the ACTIVE worker_identities population exceeds the bound \
             on the query the participation gauges are computed from \
             (MAX_FLEET_BUILD_ROWS = 200), i.e. the liveness detector can no \
             longer see every row the reaper could act on. The reaper REFUSES \
             to sweep while this is 1, so nothing is deactivated blind. Drain \
             ghost rows with deactivate-worker-identity to clear it.",
        )?;
        registry.register(Box::new(worker_liveness_population_truncated.clone()))?;

        // ---- NATS fleet heartbeat ----
        let worker_fleet_live_workers = IntGauge::new(
            "talos_worker_fleet_live_workers",
            "Distinct worker_ids that published a NATS fleet heartbeat within \
             the staleness window. Recomputed each sweep. WHETHER IT IS A \
             REPLICA COUNT DEPENDS ON THE POSTURE: with distinct ids (the \
             chart DEFAULT — nothing renders TALOS_WORKER_ID, so the worker \
             falls back to HOSTNAME/pod name) it IS one, and checking it \
             against your replica count is valid; where every replica shares \
             one TALOS_WORKER_ID (the dev compose stack, and the commented-out \
             RFC-0010 single-key block once enabled) a fleet of any size \
             reports 1. 0 is AMBIGUOUS in both — it \
             covers an empty fleet, a fleet on a build too old to publish \
             heartbeats, and a broken subscription alike, so it is not \
             evidence that workers are absent. Heartbeats are HMAC-signed \
             under the FLEET-SHARED key, so this is a liveness hint for \
             observability and never a trust signal.",
        )?;
        registry.register(Box::new(worker_fleet_live_workers.clone()))?;

        let worker_fleet_live_builds = IntGauge::new(
            "talos_worker_fleet_live_builds",
            "DISTINCT builds observed in NATS fleet heartbeats within the \
             staleness window. THE DENOMINATOR for the two gauges below, which \
             are computed over this same population — read it beside them, NOT \
             talos_worker_fleet_live_workers, which counts heartbeating \
             IDENTITIES and is a different population. A healthy fleet reads \
             1; a fleet mid-roll reads 2 steadily. 0 is AMBIGUOUS in the same \
             way as live_workers: nothing observed is not nothing running.",
        )?;
        registry.register(Box::new(worker_fleet_live_builds.clone()))?;

        let worker_fleet_build_skew_builds = IntGauge::new(
            "talos_worker_fleet_build_skew_builds",
            "DISTINCT observed builds that PROVABLY differ from this \
             controller's, over the denominator talos_worker_fleet_live_builds. \
             THE ALERTABLE ONE, because it is steady in every posture. COUNTS \
             BUILDS, NOT PROCESSES: five workers stuck on one old build report \
             1, not 5 — for the magnitude read \
             talos_worker_fleet_build_skew_workers (meaningful under distinct \
             worker_ids, which is the chart default) or get_platform_info.fleet \
             for per-worker detail. The alert is here rather than on that gauge \
             because where replicas share one worker_id the fleet map is \
             last-write-wins, so a per-worker count alternates on a MIXED-build \
             fleet and no for: duration can elapse (a uniformly skewed shared-id \
             fleet was always steady). Still the live-process twin of \
             talos_worker_build_skew_workers, which counts REGISTERED ROWS; \
             neither subsumes the other.",
        )?;
        registry.register(Box::new(worker_fleet_build_skew_builds.clone()))?;

        let worker_fleet_unverifiable_builds = IntGauge::new(
            "talos_worker_fleet_unverifiable_builds",
            "DISTINCT observed builds that cannot be compared with the \
             controller's. Covers a worker reporting no usable commit sha AND \
             — for every observed build at once — the case where the \
             CONTROLLER's own build has no usable sha, since nothing can be \
             compared then. Exported so a 0 on \
             talos_worker_fleet_build_skew_builds is readable: 0 skewed out \
             of 0 comparable builds is not 'the fleet agrees'.",
        )?;
        registry.register(Box::new(worker_fleet_unverifiable_builds.clone()))?;

        let worker_fleet_build_skew_workers = IntGauge::new(
            "talos_worker_fleet_build_skew_workers",
            "Heartbeating worker_ids whose reported build PROVABLY differs \
             from this controller's, over the denominator \
             talos_worker_fleet_live_workers. INFORMATIONAL MAGNITUDE — do NOT \
             build an alert on it. Under distinct worker_ids (the chart \
             DEFAULT: nothing renders TALOS_WORKER_ID, so each pod is its own \
             id) it is steady and answers 'how many running pods are on the \
             wrong build'. Where replicas share one worker_id the fleet map \
             holds a single entry, so it is 0 or 1 at any fleet size and \
             ALTERNATES while the fleet is mid-roll — which is why the alert \
             is on talos_worker_fleet_build_skew_builds, whose population is \
             steady in both postures.",
        )?;
        registry.register(Box::new(worker_fleet_build_skew_workers.clone()))?;

        let worker_fleet_unverifiable_workers = IntGauge::new(
            "talos_worker_fleet_unverifiable_workers",
            "Heartbeating worker_ids whose build cannot be compared with the \
             controller's — same two causes as \
             talos_worker_fleet_unverifiable_builds (the worker reported no \
             usable sha, or THIS CONTROLLER has none, in which case every \
             identity lands here at once). Published so \
             talos_worker_fleet_build_skew_workers has its decomposition \
             beside it: live_workers == build_skew_workers + \
             unverifiable_workers + agreeing. Same posture caveat as that \
             gauge.",
        )?;
        registry.register(Box::new(worker_fleet_unverifiable_workers.clone()))?;

        let worker_fleet_capacity_dropped_heartbeats = IntGauge::new(
            "talos_worker_fleet_capacity_dropped_heartbeats",
            "Heartbeats refused because the controller's fleet view was at its \
             hard cap (MAX_TRACKED_WORKERS). Cumulative within a controller \
             process; resets on restart. Non-zero means the bound held but \
             something is publishing under more distinct worker ids than the \
             fleet has. IT ALSO SUPPRESSES THE SKEW DETECTOR: a heartbeat \
             refused here never reaches the build map, so a straggling worker \
             that boots during a flood is invisible to \
             talos_worker_fleet_build_skew_builds too. Counter semantics on a \
             gauge type: alert on the level, never on rate().",
        )?;
        registry.register(Box::new(worker_fleet_capacity_dropped_heartbeats.clone()))?;

        let worker_fleet_capacity_dropped_builds = IntGauge::new(
            "talos_worker_fleet_capacity_dropped_builds",
            "Build observations refused because the controller's BUILD view \
             was at its hard cap (MAX_TRACKED_BUILDS). Cumulative within a \
             controller process; resets on restart. Saturates on a shape the \
             worker cap cannot see — one worker_id publishing many distinct \
             build strings. THE SUPPRESSION DIRECTION MATTERS MOST: at the \
             cap a NEW key is refused, and builds_match compares only the \
             +sha suffix, so a shared-key holder can fill the map with 64 \
             agreeing-but-distinct builds after which a genuinely straggling \
             worker's build is refused and talos_worker_fleet_build_skew_builds \
             reads 0 while looking healthy. Inflation by fabricated builds is \
             the milder, louder direction. Only a holder of the fleet-shared \
             key can do either, and the cap is what bounds how much. Counter \
             semantics on a gauge type: alert on the level, never on rate().",
        )?;
        registry.register(Box::new(worker_fleet_capacity_dropped_builds.clone()))?;

        // Seed all eight at 0. A gauge that has never been `set` is ABSENT, not
        // zero, and every common PromQL idiom reads absent as "no match" — so
        // an alert on a fleet that has never heartbeated could not fire on the
        // cold-dead case, which is the one that matters (#625). These are
        // closed, label-free series with live `set` sites in
        // `controller::bootstrap::background::publish_worker_fleet_gauges`, so
        // seeding them asserts nothing that is not wired.
        worker_fleet_live_workers.set(0);
        worker_fleet_live_builds.set(0);
        worker_fleet_build_skew_builds.set(0);
        worker_fleet_unverifiable_builds.set(0);
        worker_fleet_build_skew_workers.set(0);
        worker_fleet_unverifiable_workers.set(0);
        worker_fleet_capacity_dropped_heartbeats.set(0);
        worker_fleet_capacity_dropped_builds.set(0);

        // ---- Fuel-headroom detector ----
        let fuel_high_utilisation_nodes = IntGauge::new(
            "talos_fuel_high_utilisation_nodes",
            "(workflow, node) pairs whose PEAK observed fuel_consumed is at or \
             above the detector threshold (default 80%) of the ceiling a worker \
             most recently ENFORCED for them. Recomputed each sweep from \
             execution_cost_rollup. NO SAMPLE FLOOR — it fires at n=1, which is \
             the point: the node it was built for sat at 96.9% on two samples, \
             below every percentile-and-floor surface the platform had. Test \
             executions are excluded. Names are in the controller WARN log and \
             get_fuel_usage_report.high_utilisation_nodes, deliberately not \
             labels (node labels are author-supplied and unbounded).",
        )?;
        registry.register(Box::new(fuel_high_utilisation_nodes.clone()))?;

        let fuel_utilisation_observed_nodes = IntGauge::new(
            "talos_fuel_utilisation_observed_nodes",
            "The DENOMINATOR of talos_fuel_high_utilisation_nodes: every \
             (workflow, node) pair the detector could evaluate in the window. \
             Exported so a 0 on the numerator is readable — 0 of 77 examined is \
             a healthy fleet, 0 of 0 is a detector that measured nothing, and an \
             IntGauge reads 0 in both cases. TalosFuelHeadroomDetectorBlind \
             alerts on the second.",
        )?;
        registry.register(Box::new(fuel_utilisation_observed_nodes.clone()))?;

        // Seed the pair at 0. Same rule as the fleet gauges above: a gauge that
        // has never been `set` is ABSENT, and `absent >= 1` matches nothing —
        // so before the first sweep the detector would be silent for the reason
        // it exists to make loud. Both have live `set` sites in
        // `controller::bootstrap::background::publish_fuel_utilisation`.
        fuel_high_utilisation_nodes.set(0);
        fuel_utilisation_observed_nodes.set(0);

        // ---- Scheduler startup-herd detection ----
        let scheduler_dispatches_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_scheduler_dispatches_total",
                "Terminal outcomes of scheduler-driven workflow dispatches. \
                 Labels: phase=startup|catchup|steady (startup = the backlog \
                 found due by the first poll after a controller boot; catchup \
                 = a later poll holding a schedule overdue by more than the \
                 catch-up threshold, e.g. after a host suspend/resume — both \
                 are BACKLOGS and drain under the startup ceiling), \
                 outcome=completed|failed|skipped|denied|fenced. skipped = \
                 refused for CAPACITY (concurrency cap or actor budget), \
                 which for a daily cron means the run is lost until tomorrow; \
                 denied = refused by POLICY (actor not runnable, capability \
                 ceiling); fenced = superseded by a crash-recovery reclaim. \
                 The five outcomes PARTITION every dispatch attempt, so the \
                 total reconciles against the boot backlog size. Fifteen closed \
                 series; never labelled by workflow, schedule or user — \
                 unbounded cardinality.",
            ),
            &["phase", "outcome"],
        )?;
        registry.register(Box::new(scheduler_dispatches_total.clone()))?;

        let rank_training_fetches_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_rank_training_fetches_total",
                "Per-actor adaptive-rank training fetches by whether they read \
                 the WHOLE configured lookback window. Labels: \
                 coverage=complete|truncated. truncated = the per-actor row cap \
                 (TRAINING_FETCH_CAP) bound first, so the OLDEST part of \
                 ADAPTIVE_RANK_LOOKBACK_DAYS was never read and raising that \
                 knob will not widen the fit. The two values PARTITION every \
                 fetch. Both pre-seeded: a sum of 0 means no tick has fit \
                 anything, which is NOT the same as nothing truncating. Never \
                 labelled by actor — unbounded cardinality, and the actor id is \
                 caller-influenced. NOT alerted on: on a fleet with one busy \
                 actor this truncates every tick forever.",
            ),
            &["coverage"],
        )?;
        registry.register(Box::new(rank_training_fetches_total.clone()))?;
        // Seed both. Absent and zero diverge here in the usual way — an absent
        // `truncated` series reads as "nothing has ever been truncated" to
        // every `increase(...) > 0` expression — and, more sharply, the PAIR is
        // what makes the gauge below legible: without seeded counters a gauge
        // of 0 cannot be told apart from a controller that has not ticked yet.
        for coverage in RANK_TRAINING_FETCH_COVERAGES {
            rank_training_fetches_total
                .with_label_values(&[coverage])
                .inc_by(0.0);
        }

        let rank_training_lookback_shortfall_days = Gauge::new(
            "talos_rank_training_lookback_shortfall_days",
            "ADAPTIVE_RANK_LOOKBACK_DAYS minus the widest window any single \
             adaptive-rank fit actually saw in the last completed training \
             tick, i.e. how many days of the CONFIGURED window the worst-off \
             actor's model could not reach. 0 when every fetch read its whole \
             window. WORST CASE across the tick (actor_id cannot be a label); \
             talos_rank_training_fetches_total says how many fits were \
             affected, and also disambiguates this gauge's zero, which means \
             'no shortfall' OR 'no tick yet'. NOT alerted on — a chronic \
             shortfall is the row cap working as designed.",
        )?;
        registry.register(Box::new(rank_training_lookback_shortfall_days.clone()))?;
        // Seed all ten. The healthy steady state of every startup-phase
        // series is 0 forever, which is exactly the case where absent and
        // zero diverge: the herd alert is built on `increase(...)` — a
        // threshold arm and a ratio arm — and an absent counter matches
        // nothing, so the detector would be silenced by precisely the
        // condition it exists to catch (#625). The ratio arm needs the
        // seeding twice over: an absent denominator term does not make the
        // ratio absent, it makes it WRONG. Every (phase,
        // outcome) pair is reachable from a live site in
        // `talos_scheduler::SchedulerService`, so seeding asserts nothing
        // that is not wired.
        for phase in SCHEDULER_DISPATCH_PHASES {
            for outcome in SCHEDULER_DISPATCH_OUTCOMES {
                scheduler_dispatches_total
                    .with_label_values(&[phase, outcome])
                    .inc_by(0.0);
            }
        }

        let scheduler_readiness_holds_total = Counter::new(
            "talos_scheduler_readiness_holds_total",
            "Scheduler poll iterations held because the controller's NATS \
             fleet heartbeat view contained no live worker. A hold advances \
             no schedule state, so nothing is lost — the same schedules are \
             still due on the next tick. Non-zero at boot is normal (a \
             worker that booted first loses its unretained first heartbeat); \
             sustained growth means the fleet is genuinely absent.",
        )?;
        registry.register(Box::new(scheduler_readiness_holds_total.clone()))?;
        // Same reasoning as above: on a healthy single-node stack this is 0
        // forever, and an absent counter cannot be distinguished from a
        // scheduler that never started.
        scheduler_readiness_holds_total.inc_by(0.0);

        let scheduler_readiness_degraded = IntGauge::new(
            "talos_scheduler_readiness_degraded",
            "1 when the scheduler has given up waiting for the worker fleet to \
             become visible and is dispatching without that evidence. An empty \
             fleet view is ambiguous (empty fleet / old build / broken \
             subscription / heartbeats deliberately disabled), so the barrier \
             degrades after a bounded number of holds instead of stopping all \
             scheduled work forever on a signal it cannot fully trust.",
        )?;
        registry.register(Box::new(scheduler_readiness_degraded.clone()))?;
        // 0 is the healthy value AND the value this sits at forever on a
        // working fleet, so it must be exported rather than absent — an alert
        // on `== 1` over an absent series can never fire.
        scheduler_readiness_degraded.set(0);

        // Rate limiting metrics
        let rate_limit_hits_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_rate_limit_hits_total",
                "Requests a limiter refused, by limiter. type=ip (per-IP middleware: the \
                 429, and the GraphQL 200-with-RATE_LIMITED variant) | global (the \
                 controller-wide limiter's 503) | api_key (the per-prefix limiter inside \
                 validate_key; also counted as api_key_validations_total{status=\
                 rate_limited}) | webhook (the per-trigger limiter in the webhook \
                 router) | mcp_auth (the per-IP limiter in front of MCP agent-token \
                 authentication; also counted as mcp_auth_total{outcome=rate_limited}). \
                 talos_metrics::RateLimitKind, a closed set, all five pre-seeded at 0. \
                 The webhook IP circuit breaker is not a rate limit and is not here. \
                 Registered 2026-05, first incremented 2026-09-11; mcp_auth added \
                 2026-09-13.",
            ),
            &["type"],
        )?;
        registry.register(Box::new(rate_limit_hits_total.clone()))?;
        for kind in RateLimitKind::ALL {
            rate_limit_hits_total
                .with_label_values(&[kind.as_str()])
                .inc_by(0.0);
        }

        // Privileged-operation gate (package DY). Seeded over the CLOSED set:
        // an absent series and a zero are different claims, and `increase()`
        // over an absent one matches nothing.
        let privileged_op_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_privileged_op_total",
                "Outcomes of the GraphQL privileged-operation gate \
                 (require_second_factor): key-material rotation, the \
                 re-encryption sweeps, API-key lifecycle, MCP-agent \
                 registration, capability grants, audit settings, ownership \
                 transfer. `outcome=permitted` admitted the call; every other \
                 value refused it. `unreadable` means the enrolment rule could \
                 not be READ and the call was refused anyway (fail closed) — \
                 a fault to fix, not a policy decision.",
            ),
            &["outcome"],
        )?;
        registry.register(Box::new(privileged_op_total.clone()))?;
        for outcome in PrivilegedOpOutcome::ALL {
            privileged_op_total
                .with_label_values(&[outcome.as_str()])
                .inc_by(0.0);
        }

        let platform_admin_checks_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_platform_admin_checks_total",
                "Outcomes of the GraphQL platform-admin gate \
                 (require_platform_admin) on cross-tenant and system-wide \
                 operations. `unreadable` means the is_platform_admin read \
                 failed and the call was refused anyway. `unauthenticated` \
                 reads 0 on every deployment and is NOT evidence that no \
                 anonymous caller reached a platform-admin operation: every \
                 current call site runs require_scope(Admin) first, and that \
                 gate refuses a caller with neither an API key nor a session, \
                 so the platform-admin gate is never reached without one. It \
                 is seeded anyway because a future call site placed ahead of \
                 the scope gate would otherwise be born at 1 and read 0 \
                 forever under increase(). Read `unauthenticated` on \
                 talos_privileged_op_total instead, which IS reachable.",
            ),
            &["outcome"],
        )?;
        registry.register(Box::new(platform_admin_checks_total.clone()))?;
        for outcome in PlatformAdminOutcome::ALL {
            platform_admin_checks_total
                .with_label_values(&[outcome.as_str()])
                .inc_by(0.0);
        }

        // Deployment-wide execution pause
        let execution_pause_refusals_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_execution_pause_refusals_total",
                "Workflow starts refused because the deployment-wide execution pause \
                 (pause_executions) is set, by the surface that refused and why. \
                 path=scheduler_poll counts deferred POLLS, not schedules (the due rows \
                 are never claimed, so they fire on resume); webhook and gmail_push \
                 requests answered 503 so the sender redelivers (gcal_push and gcp_push \
                 likewise, since package BG); trigger / retry / replay / mcp_entry / \
                 graphql_test / handoff the operator-invoked entry gates; continuation an \
                 approval or suspension resume refused BEFORE the gate is resolved or the \
                 suspension claimed, so it can be repeated; row_creation the \
                 in-transaction backstop behind them (including a scheduled fire claimed \
                 just before the pause, whose schedule is re-armed). One refusal is one \
                 increment on exactly one path, so the family sums. reason=paused | \
                 unreadable (a stored value that is not a JSON boolean — refused, never \
                 read as running). talos_metrics::{PauseGatePath, PauseRefusal}, closed \
                 sets, every pair pre-seeded at 0. A refusal is the pause working: do \
                 NOT alert on it.",
            ),
            &["path", "reason"],
        )?;
        registry.register(Box::new(execution_pause_refusals_total.clone()))?;
        for path in PauseGatePath::ALL {
            for reason in PauseRefusal::ALL {
                execution_pause_refusals_total
                    .with_label_values(&[path.as_str(), reason.as_str()])
                    .inc_by(0.0);
            }
        }

        // Webhook duplicate suppression (package CI)
        let webhook_duplicate_suppressed_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_webhook_duplicate_suppressed_total",
                "Inbound webhook deliveries answered 200 and dispatched NOTHING because \
                 the deduplication store had already seen this event, by the scheme that \
                 authenticated the request. format=github is the one to read: the GitHub \
                 HMAC signs the body alone, so its dedup fingerprint is deterministic in \
                 the body and a legitimate GitHub 'Redeliver' of an unchanged payload is \
                 indistinguishable from a replay — this series is how often that horizon \
                 (24 h since package CI, 1 h for every other format) suppressed a \
                 delivery someone meant to send. talos_metrics::WebhookAuthFormat, a \
                 closed set, every value pre-seeded at 0. A suppression is deduplication \
                 working: do NOT alert on it.",
            ),
            &["format"],
        )?;
        registry.register(Box::new(webhook_duplicate_suppressed_total.clone()))?;
        for format in WebhookAuthFormat::ALL {
            webhook_duplicate_suppressed_total
                .with_label_values(&[format.as_str()])
                .inc_by(0.0);
        }

        // Actor budget refusals
        let actor_budget_refusals_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_actor_budget_refusals_total",
                "Workflow starts refused by an actor budget cap, by the cap and the \
                 policy's on_budget_exceeded mode. cap=per_minute | per_hour | total | \
                 fuel_per_hour | llm_tokens_per_day; mode=suspend | alert | block. Recorded \
                 where the refusal is decided (the pre-checks and the atomic backstop at \
                 row creation), once per refused start. mode=alert also raises an ops \
                 alert keyed per actor and cap. talos_metrics::{BudgetCap, BudgetMode}, \
                 closed sets, every pair pre-seeded at 0. A refusal is the budget \
                 working: do NOT alert on this series.",
            ),
            &["cap", "mode"],
        )?;
        registry.register(Box::new(actor_budget_refusals_total.clone()))?;
        for cap in BudgetCap::ALL {
            for mode in BudgetMode::ALL {
                actor_budget_refusals_total
                    .with_label_values(&[cap.as_str(), mode.as_str()])
                    .inc_by(0.0);
            }
        }

        // Google push authentication
        let google_push_refusals_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_google_push_refusals_total",
                "Google Pub/Sub push deliveries refused at the HTTP boundary (401), by \
                 integration (gmail | gcp) and reason. reason=missing_bearer (no \
                 Authorization header) | malformed_header | wrong_algorithm | missing_kid | \
                 unknown_key (the JWT's kid is not in the cached JWK set — during a JWK \
                 backoff window EVERY push with a rotated key lands here; read beside \
                 talos_google_jwk_refresh_total) | invalid (signature / iss / aud / exp) | \
                 wrong_email | email_not_verified (service-account check) | \
                 jwk_fetch_failed. Closed sets (talos_metrics::{PushIntegration, \
                 PushRefusalReason}), all 18 pairs pre-seeded at 0. A refusal is the \
                 fail-closed control working; Pub/Sub retries a 401. Not alerted.",
            ),
            &["integration", "reason"],
        )?;
        registry.register(Box::new(google_push_refusals_total.clone()))?;
        for integration in PushIntegration::ALL {
            for reason in PushRefusalReason::ALL {
                google_push_refusals_total
                    .with_label_values(&[integration.as_str(), reason.as_str()])
                    .inc_by(0.0);
            }
        }
        let google_push_accepted_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_google_push_accepted_total",
                "Google Pub/Sub push deliveries that PASSED authentication, by integration \
                 (gmail | gcp) — counted the moment the push's JWT verifies, before any \
                 payload decode or dispatch. The positive twin of \
                 talos_google_push_refusals_total: a push stream that stops (a deleted \
                 subscription, a moved push endpoint, a revoked publisher grant) refuses \
                 nothing, so only this series can say it went quiet. Closed set \
                 (talos_metrics::PushIntegration), both values pre-seeded at 0. Alerted by \
                 TalosGooglePushSilent (pushes in the last 7 d, none in the last 12 h).",
            ),
            &["integration"],
        )?;
        registry.register(Box::new(google_push_accepted_total.clone()))?;
        for integration in PushIntegration::ALL {
            google_push_accepted_total
                .with_label_values(&[integration.as_str()])
                .inc_by(0.0);
        }
        let google_push_deferred_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_google_push_deferred_total",
                "Google push deliveries handed BACK to the transport for redelivery \
                 (503), by integration (gmail | gcp) and reason. Not a refusal: \
                 talos_google_push_refusals_total counts pushes we REJECTED, this counts \
                 pushes we could not ANSWER. reason=watch_lookup_unreadable (the \
                 watch/channel lookup returned Err, so the row's existence is unknown — \
                 an ABSENT row is a determinate answer and is acked instead). Closed sets \
                 (talos_metrics::{PushIntegration, PushDeferReason}), both pairs \
                 pre-seeded at 0. Deferral is the safe direction, but a deferral that \
                 repeats past the subscription's retention (7 d by default) becomes real \
                 loss, which is why it is counted rather than only logged. Not alerted: no \
                 baseline — this arm has never fired on the reference fleet.",
            ),
            &["integration", "reason"],
        )?;
        registry.register(Box::new(google_push_deferred_total.clone()))?;
        for integration in PushIntegration::ALL {
            for reason in PushDeferReason::ALL {
                google_push_deferred_total
                    .with_label_values(&[integration.as_str(), reason.as_str()])
                    .inc_by(0.0);
            }
        }
        let google_jwk_refresh_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_google_jwk_refresh_total",
                "Attempts by the shared GoogleOidcVerifier to fetch Google's JWK set, by \
                 outcome (ok | failed). A fetch runs on an unknown kid or a stale (1 h) \
                 cache; `failed` opens a 60 s backoff during which every unknown-kid push \
                 is refused (talos_google_push_refusals_total{reason=unknown_key}), so a \
                 sustained outage yields at most one `failed` per minute per controller \
                 and only while pushes arrive. Alerted by TalosGoogleJwkRefreshFailing \
                 (>= 5 failures in 15 m). Both values pre-seeded at 0.",
            ),
            &["outcome"],
        )?;
        registry.register(Box::new(google_jwk_refresh_total.clone()))?;
        for outcome in JwkRefreshOutcome::ALL {
            google_jwk_refresh_total
                .with_label_values(&[outcome.as_str()])
                .inc_by(0.0);
        }

        // Vault KEK-token renewal
        let vault_token_renewals_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_vault_token_renewals_total",
                "auth/token/renew-self attempts on the controller's Vault KEK token \
                 (KEK_PROVIDER=vault), by outcome: renewed (full increment granted) | capped \
                 (Vault granted less, or the token stopped being renewable: it has reached \
                 its maximum TTL and WILL expire) | failed (no successful answer). A healthy \
                 renewable token renews at least once an hour. ABSENT on a deployment with \
                 no Vault KEK provider (seeded at 0 by the renewal loop, not at \
                 registration). Alerted by TalosVaultTokenRenewalFailing and \
                 TalosVaultTokenCapped.",
            ),
            &["outcome"],
        )?;
        registry.register(Box::new(vault_token_renewals_total.clone()))?;
        let vault_token_ttl_seconds = IntGaugeVec::new(
            prometheus::Opts::new(
                "talos_vault_token_ttl_seconds",
                "Seconds until the controller's Vault KEK token expires, as Vault last \
                 reported it (boot lookup-self, then every renewal), labelled by the \
                 token's lifetime class: periodic | renewable_bounded | expiring | \
                 non_expiring (value 0 = no TTL). Exactly one lifetime is present at a \
                 time; ABSENT when no Vault KEK provider runs. Not seeded (a reading, not a \
                 count) and not alerted directly — read it beside \
                 talos_vault_token_renewals_total to see how long a capped token has left.",
            ),
            &["lifetime"],
        )?;
        registry.register(Box::new(vault_token_ttl_seconds.clone()))?;

        // RustSec advisory-database age
        let advisory_db_age_days = IntGaugeVec::new(
            prometheus::Opts::new(
                "talos_advisory_db_age_days",
                "Age in whole days of the baked RustSec advisory database that the compile \
                 gate (check_advisory_db_age) consults, sampled hourly from the freshest of \
                 three filesystem signals (directory mtime, .git/refs/heads/main|master mtime, \
                 newest crates/ entry). `copy` names which baked copy was sampled; only the \
                 controller's is today, and in container mode `cargo audit` reads the BUILDER \
                 image's copy, which this series does not see. A reading, not a count: ABSENT \
                 until the first sample, and left at its last value when a sample is \
                 unreadable — read talos_advisory_db_age_samples_total{outcome=\"unreadable\"} \
                 beside it. Alerted by TalosAdvisoryDbAging and TalosAdvisoryDbExpired.",
            ),
            &["copy"],
        )?;
        registry.register(Box::new(advisory_db_age_days.clone()))?;
        let advisory_db_max_age_days = IntGaugeVec::new(
            prometheus::Opts::new(
                "talos_advisory_db_max_age_days",
                "The age at which check_advisory_db_age refuses (TALOS_ADVISORY_DB_MAX_AGE_DAYS, \
                 default 90), as this controller resolved it. Exported so the expiry alert's \
                 threshold is the process's own limit rather than a copy of the default. \
                 Absent until the first sample.",
            ),
            &["copy"],
        )?;
        registry.register(Box::new(advisory_db_max_age_days.clone()))?;
        let advisory_db_age_enforced = IntGaugeVec::new(
            prometheus::Opts::new(
                "talos_advisory_db_age_enforced",
                "1 when a stale advisory database REFUSES compilation on this controller \
                 (RUST_ENV=production), 0 when it only warns. TalosAdvisoryDbExpired is \
                 critical only where this is 1; outside production an expired copy is \
                 TalosAdvisoryDbAging's warning. Absent until the first sample.",
            ),
            &["copy"],
        )?;
        registry.register(Box::new(advisory_db_age_enforced.clone()))?;
        let advisory_db_age_samples_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_advisory_db_age_samples_total",
                "Hourly samples of the baked advisory database's age, by outcome: measured \
                 (the age gauge was set) | unreadable (the database is missing, unreadable or \
                 dated in the future — the gauge was NOT touched, and cargo audit --no-fetch \
                 fails in every environment while this persists). Pre-seeded at 0 for every \
                 (copy, outcome). Alerted by TalosAdvisoryDbUnreadable.",
            ),
            &["copy", "outcome"],
        )?;
        registry.register(Box::new(advisory_db_age_samples_total.clone()))?;
        for copy in AdvisoryDbCopy::ALL {
            for outcome in AdvisoryDbSampleOutcome::ALL {
                advisory_db_age_samples_total
                    .with_label_values(&[copy.as_str(), outcome.as_str()])
                    .inc_by(0.0);
            }
        }

        // (cache_hits_total / cache_misses_total were deleted 2026-09-11 — see
        // the struct field comment.)

        // (circuit-breaker metrics moved to talos-worker-runtime — see the
        // note on the struct definition above.)

        // DLQ metrics
        let dlq_entries_total = Counter::new(
            "talos_dlq_entries_total",
            "Total number of DLQ entries created",
        )?;
        registry.register(Box::new(dlq_entries_total.clone()))?;

        let dlq_drops_total = Counter::new(
            "talos_dlq_drops_total",
            "Total number of DLQ entries dropped (channel full)",
        )?;
        registry.register(Box::new(dlq_drops_total.clone()))?;

        let dlq_db_errors_total = Counter::new(
            "talos_dlq_db_errors_total",
            "Total number of DLQ database write errors",
        )?;
        registry.register(Box::new(dlq_db_errors_total.clone()))?;

        // ---- Crypto-invariant metrics ----
        let kek_decrypt_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_kek_decrypt_failures_total",
                "DEK unwrap failures. Labels: provider=active|legacy|both. \
                 Any bump here means encrypted-at-rest data is currently \
                 unreadable — page operator immediately.",
            ),
            &["provider"],
        )?;
        registry.register(Box::new(kek_decrypt_failures_total.clone()))?;
        // Seed only the two `provider` values with a live emitting site:
        // `active` and `both`, both in `SecretsManager::decrypt_dek`. The
        // description's third value, `legacy`, has NO emitter anywhere in the
        // workspace — a total legacy-provider failure is reported as `both`.
        // Seeding `legacy` would put a permanent flat 0 on a dashboard for a
        // condition nothing can ever report, which reads as "watched and
        // healthy" rather than "not watched".
        for provider in ["active", "both"] {
            kek_decrypt_failures_total
                .with_label_values(&[provider])
                .inc_by(0.0);
        }

        let memory_write_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_memory_write_failures_total",
                "actor_memory writes that produced no row. Labels: \
                 reason=crypto|db|validation|other|quota|write_ceiling. The \
                 first four are PERSISTENCE FAILURES of a __memory_write__ \
                 envelope (a sustained bump means node outputs are being lost \
                 to disk); quota is the per-actor row cap refusing a NEW key \
                 (the actor already holds MAX_MEMORIES_PER_ACTOR rows, e.g. a \
                 module writing a fresh key per run and never deleting); \
                 write_ceiling is a POLICY REFUSAL working as designed, \
                 expected to be non-zero wherever TALOS_WRITE_CEILING_ENFORCED \
                 is set and readonly actors run, and do not alert on it. \
                 write_ceiling has TWO producers: the __memory_write__ \
                 envelope gate (#750) and the signed-RPC memory gate (#757). \
                 For the RPC route — which is a FLEET-CONFIGURATION signal and \
                 IS worth alerting on — select \
                 talos_rpc_write_ceiling_refusals_total instead.",
            ),
            &["reason"],
        )?;
        registry.register(Box::new(memory_write_failures_total.clone()))?;
        // Closed set, and every value has a live emitter. Five come from
        // `MemoryWriteError::metric_label()` (`quota` since 2026-09-25: the
        // per-actor row cap enforced inside the persist statement), emitted
        // at the `__memory_write__` hook site in talos-engine. This crate
        // cannot depend on talos-memory, so the five below are a COPY of
        // `MemoryWriteError::METRIC_LABELS`, pinned by
        // `every_metric_label_is_pre_seeded_at_zero` in talos-memory.
        //
        // `write_ceiling` is the fifth and is NOT from that enum: it is the
        // literal stamped by `ControllerNodeHook::record_memory_write_refusal`
        // when the actor's `max_write_ceiling` declines a returned envelope
        // (#750) AND by `talos_rpc_subscribers::write_ceiling::record_refusal`
        // when the signed-RPC memory gate refuses one (#757) — TWO live sites,
        // not one, which is exactly why the RPC route needed a series of its
        // own: folded here, a fleet-configuration defect is indistinguishable
        // from a routine policy refusal. It qualifies for seeding on the same
        // rule as the others — a compile-time-known label with a live `.inc()` —
        // and it was MISSING, which was measured rather than assumed: on the
        // dev controller 2026-09-05 the four seeded reasons rendered `0` and
        // `write_ceiling` was simply ABSENT until a refusal happened, after
        // which it read `1`. So before the first refusal of a process's life
        // (i.e. after every restart) the series that says "policy declined a
        // memory write" was indistinguishable from the wiring not existing.
        // Absent is not zero — the same rule that motivated this whole seed
        // loop, applied to the label the loop had not been told about.
        for reason in [
            "crypto",
            "db",
            "validation",
            "other",
            "quota",
            "write_ceiling",
        ] {
            memory_write_failures_total
                .with_label_values(&[reason])
                .inc_by(0.0);
        }

        let child_run_record_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_child_run_record_failures_total",
                "Child-run ledger writes that produced no row. Labels: \
                 reason=acquire (no pooled connection) | insert (the INSERT \
                 itself failed). RFC 0012: a sub-workflow runs in-process and \
                 records no workflow_executions row, so sub_workflow_runs is \
                 the only evidence a child ran; a dropped write is silence \
                 that reads exactly like 'this child never ran'. The write is \
                 deliberately best-effort — it must never fail a workflow — so \
                 this counter is the only thing that can say it failed.",
            ),
            &["reason"],
        )?;
        registry.register(Box::new(child_run_record_failures_total.clone()))?;
        // Closed set with a live emitter for each: `PostgresChildRunRecorder`
        // has exactly two failure arms and stamps one label at each. Seeded
        // because the healthy steady state is zero forever, and an ABSENT
        // series makes `increase(...) > 0` match nothing — the detector
        // silenced by exactly the condition it detects.
        for reason in ["acquire", "insert"] {
            child_run_record_failures_total
                .with_label_values(&[reason])
                .inc_by(0.0);
        }

        let rpc_write_ceiling_refusals_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_rpc_write_ceiling_refusals_total",
                "Signed-RPC mutations the CONTROLLER refused on the per-actor \
                 write ceiling. Labels: subject (NATS subject) × \
                 reason=policy|unreadable. A non-zero value is a FLEET \
                 CONFIGURATION signal: the sending worker did not run its own \
                 write-ceiling gate, so its TALOS_WRITE_CEILING_ENFORCED is \
                 unset or its build predates the gate. reason=unreadable is \
                 the fail-closed arm (absent or unreadable actor row) and \
                 names an operator problem, not a policy working as \
                 configured.",
            ),
            &["subject", "reason"],
        )?;
        registry.register(Box::new(rpc_write_ceiling_refusals_total.clone()))?;
        // Closed set, every combination has a live emitter: `write_ceiling::gate`
        // is the ONE chokepoint, it is called on all three subjects, and both
        // reasons are reachable at each of them (`decide` returns
        // `Unreadable` for any subject whose actor row is absent or
        // unreadable). Seeded because the healthy steady state is zero
        // forever, and `increase(...) > 0` over an ABSENT series matches
        // nothing — the detector silenced by exactly the condition it detects.
        for subject in RPC_WRITE_CEILING_SUBJECTS {
            for reason in ["policy", "unreadable"] {
                rpc_write_ceiling_refusals_total
                    .with_label_values(&[subject, reason])
                    .inc_by(0.0);
            }
        }

        // ── The signed-RPC data-plane instrument (2026-09-09) ────────────
        //
        // Labels are `subject` × `outcome` × `class`, all three closed
        // compile-time sets from `crate::rpc`. `class` is a pure function of
        // `outcome`, so it costs no series and buys the one thing a PromQL
        // selector cannot do for itself: rest the alert on the SAME decision
        // the log level rests on, instead of a hand-maintained
        // `outcome=~"internal|timeout|…"` alternation that a nineteenth
        // outcome would silently fall outside of.
        let rpc_calls_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_rpc_calls_total",
                "Signed-NATS-RPC calls the controller served for credential-free \
                 workers. Labels: subject (one of seven NATS subjects) × outcome \
                 (the subscriber's own classification of its reply) × class \
                 (served | declined | finding — a pure function of outcome). \
                 `declined` is the platform answering CORRECTLY by declining: a \
                 policy refusal, a designed lifecycle state such as \
                 outcome=not_promoted, a configured cap, or a caller error the \
                 caller was told about — do NOT alert on it. `finding` means \
                 someone should look: the platform could not serve the call, or \
                 the call should not have arrived in the shape it did. All 64 \
                 reachable (subject, outcome) pairs are pre-seeded at 0; a pair \
                 outside the per-subject table cannot be emitted.",
            ),
            &["subject", "outcome", "class"],
        )?;
        registry.register(Box::new(rpc_calls_total.clone()))?;
        // The pre-seed loop IS the table (`rpc::seeded_pairs`), so a pair the
        // loop misses is not expressible — there is no parallel list to rot
        // (#778's `BackgroundTask` shape). Seeded because
        // `TalosRPCSubjectFailing` selects on this counter, and the healthy
        // steady state of the `finding` class is zero forever.
        for (subject, outcome) in rpc::seeded_pairs() {
            rpc_calls_total
                .with_label_values(&[subject.as_str(), outcome.as_str(), outcome.class().as_str()])
                .inc_by(0.0);
        }

        // Buckets: 0.5 ms … 65.5 s, doubling (18 finite buckets). The bottom
        // is 0.5 ms because the sub-millisecond end is where this subsystem
        // actually lives — every `exec_ms` on the reference fleet is 0. The
        // top is chosen against the real ceiling rather than the house
        // default: `kernel::PERMIT_GUARD_TIMEOUT_SECS` is 30 s and the
        // semaphore queue wait sits OUTSIDE it, so one call can exceed the
        // 16-bucket 32.768 s top and would then be unmeasurable above it.
        let rpc_duration_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "talos_rpc_duration_seconds",
                "Wall-clock duration (semaphore queue + execution) of one signed-RPC \
                 call. Same labels and same closed-set rule as talos_rpc_calls_total. \
                 NOT pre-seeded: an absent (subject, outcome) here means that pair has \
                 not occurred since process start, which is what the pre-seeded 0 on \
                 talos_rpc_calls_total already says.",
            )
            .buckets(exponential_buckets(0.0005, 2.0, 18).expect("valid exponential buckets")),
            &["subject", "outcome", "class"],
        )?;
        registry.register(Box::new(rpc_duration_seconds.clone()))?;

        let dispatch_refused_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_dispatch_refused_total",
                "Workflow dispatches refused because the workflow is ARCHIVED. \
                 Labels: path (which dispatch surface refused) × reason \
                 (archived). A non-zero value is the lifecycle gate working as \
                 configured, NOT a fault — do NOT alert on it. It exists so a \
                 schedule that stopped firing can be told apart from a \
                 scheduler that stopped working. Sites that enforce the gate in \
                 SQL (chain fan-out, capability/name resolution, the \
                 sub-workflow cache prefetch) are NOT counted here: they choose \
                 among candidates rather than refusing a named workflow.",
            ),
            &["path", "reason"],
        )?;
        registry.register(Box::new(dispatch_refused_total.clone()))?;
        // Closed set, every combination has a live emitter: each `DispatchPath`
        // variant names a site that classifies in Rust and calls
        // `record_dispatch_refusal`, and `archived` is the only reason with an
        // emitter. Seeded for the same reason as the ceiling counter above.
        for path in talos_workflow_liveness::dispatch::DispatchPath::ALL {
            dispatch_refused_total
                .with_label_values(&[
                    path.as_str(),
                    talos_workflow_liveness::dispatch::REFUSAL_REASON_ARCHIVED,
                ])
                .inc_by(0.0);
        }

        let ops_alert_ingest_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_ops_alert_ingest_failures_total",
                "ops_alerts persistence failures from the __ops_alert__ \
                 hook. Labels: reason=validation|db|tenancy. Sustained bump \
                 means parser-module alert envelopes are being lost.",
            ),
            &["reason"],
        )?;
        registry.register(Box::new(ops_alert_ingest_failures_total.clone()))?;

        let ops_alert_auto_resolved_total = Counter::new(
            "talos_ops_alert_auto_resolved_total",
            "ops_alerts rows resolved by a status_event: 'resolved' signal \
             from the ingest pipeline (source-reported recovery, e.g. a \
             Cloud Monitoring incident closing).",
        )?;
        registry.register(Box::new(ops_alert_auto_resolved_total.clone()))?;

        let module_payload_encryption_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_module_payload_encryption_failures_total",
                "module_executions payload encrypt/decrypt failures. \
                 Labels: op=encrypt|decrypt, stage=input|output|trigger_metadata.",
            ),
            &["op", "stage"],
        )?;
        registry.register(Box::new(module_payload_encryption_failures_total.clone()))?;
        // All six combinations are reachable, so all six are seeded:
        // `encrypt_payload_bundle` loops over all three `PayloadSlot`s and
        // `decrypt_payload_slot` is called for each of them, and both wrap
        // their failures through `inc_payload_crypto_failure`. Cardinality is
        // fixed at 6 by construction (both labels are `&'static str` from
        // closed sets) — the same bound that crate's own doc comment states.
        for op in ["encrypt", "decrypt"] {
            for stage in ["input", "output", "trigger_metadata"] {
                module_payload_encryption_failures_total
                    .with_label_values(&[op, stage])
                    .inc_by(0.0);
            }
        }

        let secret_decrypt_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_secret_decrypt_failures_total",
                "Per-row secret decrypt failures inside get_module_secrets. \
                 Labels: reason=missing_dek|cipher_init|aead|invalid_utf8|too_short.",
            ),
            &["reason"],
        )?;
        registry.register(Box::new(secret_decrypt_failures_total.clone()))?;

        let actor_memory_orphaned_rows = IntGauge::new(
            "talos_actor_memory_orphaned_rows",
            "Rows in actor_memory whose value_key_id points at a DEK that \
             no longer exists in encryption_keys. Should be 0. Non-zero = \
             data loss already occurred, investigate immediately.",
        )?;
        registry.register(Box::new(actor_memory_orphaned_rows.clone()))?;

        let module_execution_orphaned_rows = IntGauge::new(
            "talos_module_execution_orphaned_rows",
            "Rows in module_executions whose payload_enc_key_id points at a \
             missing DEK. Should be 0.",
        )?;
        registry.register(Box::new(module_execution_orphaned_rows.clone()))?;

        let workflow_execution_orphaned_rows = IntGauge::new(
            "talos_workflow_execution_orphaned_rows",
            "Rows in workflow_executions whose output_enc_key_id points at a \
             missing DEK. Should be 0.",
        )?;
        registry.register(Box::new(workflow_execution_orphaned_rows.clone()))?;

        let crypto_orphan_scan_last_success_timestamp_seconds = Gauge::new(
            "talos_crypto_orphan_scan_last_success_timestamp_seconds",
            "Unix time of the last crypto-orphan sweep in which ALL THREE \
             talos_*_orphaned_rows gauges were measured. Not seeded and not \
             reset: it reads 0 until the first fully successful sweep, which \
             is maximally stale, so a controller that never ran the sweep is \
             loud rather than silent. The three orphan gauges read 0 both when \
             clean and when unmeasured; this is how those cases are told \
             apart. TalosCryptoOrphanDetectorBlind alerts on it.",
        )?;
        registry.register(Box::new(
            crypto_orphan_scan_last_success_timestamp_seconds.clone(),
        ))?;

        let dek_cache_size = IntGauge::new(
            "talos_dek_cache_size",
            "Current number of DEKs held in the in-memory decryption cache. \
             Bounded by TTL eviction + write-path invalidation.",
        )?;
        registry.register(Box::new(dek_cache_size.clone()))?;

        let db_pool_connections = IntGauge::new(
            "talos_db_pool_connections",
            "Total connections held by the controller's Postgres pool (idle + in-use).",
        )?;
        registry.register(Box::new(db_pool_connections.clone()))?;

        let db_pool_idle_connections = IntGauge::new(
            "talos_db_pool_idle_connections",
            "Idle connections in the controller's Postgres pool (available to hand out).",
        )?;
        registry.register(Box::new(db_pool_idle_connections.clone()))?;

        let db_pool_in_use_connections = IntGauge::new(
            "talos_db_pool_in_use_connections",
            "Connections currently checked out of the controller's Postgres pool. \
             At DB_MAX_CONNECTIONS the pool is saturated and acquisitions block.",
        )?;
        registry.register(Box::new(db_pool_in_use_connections.clone()))?;

        let db_pool_max_connections = IntGauge::new(
            "talos_db_pool_max_connections",
            "Configured maximum size of the controller's Postgres pool (DB_MAX_CONNECTIONS).",
        )?;
        registry.register(Box::new(db_pool_max_connections.clone()))?;

        // ── MCP tools/call instrument (2026-09-08) ───────────────────────
        //
        // Buckets: 1 ms … 32.768 s, doubling (16 finite buckets). The brief's
        // target range is 1 ms … 30 s and the house style elsewhere in this
        // file is `exponential_buckets(0.001, 2.0, 15)` — 15 tops out at
        // 16.384 s, BELOW 30 s, so every call slower than 16 s would land in
        // `+Inf` and its latency would be unmeasurable above the top bucket.
        // 16 puts the top finite bucket at 32.768 s, above the range, so a
        // 30-second report is still bounded from above. The bottom bucket is
        // 1 ms because the fastest tools here (`whoami`, `describe_capability_world`)
        // are pure in-process work and would otherwise all pile into one bucket.
        let mcp_tool_duration_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "talos_mcp_tool_duration_seconds",
                "Wall-clock duration of one MCP tools/call, measured at the single \
                 dispatch chokepoint. Labels: tool (a value from the static tool-schema \
                 registry, or the fixed sentinels 'catalog_template' / 'unknown' — NEVER \
                 the caller's own string) × outcome (ok | error | refused | unknown_tool | \
                 denied | not_found) × class (served | declined | finding, a pure function \
                 of outcome, so it adds no series). NOT pre-seeded: an absent \
                 (tool, outcome) means that tool has not been called since process start \
                 — and its _count is therefore born at 1, so increase()/rate() drop the \
                 FIRST call of every pair per process lifetime. Read call VOLUME from \
                 talos_mcp_tool_calls_total, which IS pre-seeded; read latency here.",
            )
            .buckets(exponential_buckets(0.001, 2.0, 16).expect("valid exponential buckets")),
            &["tool", "outcome", "class"],
        )?;
        registry.register(Box::new(mcp_tool_duration_seconds.clone()))?;

        let mcp_tool_calls_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_mcp_tool_calls_total",
                "MCP tools/call invocations, by tool, outcome and class. Same labels and \
                 same closed-set rule as talos_mcp_tool_duration_seconds. class is served \
                 | declined | finding: a REFUSAL the platform issued correctly is declined, \
                 not finding, so a client looping on a tool it lacks the capability for no \
                 longer moves the same series as an outage. PRE-SEEDED at 0 over every \
                 declared tool × outcome by talos_mcp_handlers::tool_labels::\
                 seed_tool_call_series at controller boot (2026-09-11): a counter born at \
                 1 loses its first increment to increase()/rate(), and on a fleet that \
                 restarts often a tool called once per lifetime read 0 forever \
                 (measured: session_start 15 calls / 7 d rendered as 0). One line per \
                 pair; the HISTOGRAM stays unseeded.",
            ),
            &["tool", "outcome", "class"],
        )?;
        registry.register(Box::new(mcp_tool_calls_total.clone()))?;

        Ok(Arc::new(Self {
            registry,
            mcp_tool_duration_seconds,
            mcp_tool_calls_total,
            rpc_calls_total,
            rpc_duration_seconds,
            webhook_dlq_drops_total,
            auth_attempts_total,
            auth_failures_total,
            auth_2fa_attempts_total,
            api_key_validations_total,
            mcp_auth_total,
            ws_handshakes_total,
            ws_session_ends_total,
            ws_operations_total,
            ws_active_sessions,
            password_changes_total,
            token_reuse_total,
            rotation_audit_arm_total,
            module_executions_total,
            module_execution_duration_seconds,
            workflow_executions_total,
            workflow_execution_duration_seconds,
            crash_recovery_total,
            condition_eval_failures_total,
            wasm_log_orphaned_total,
            module_execution_record_started_failures_total,
            module_executions_swept_stuck_total,
            module_executions_retention_deleted_total,
            job_results_dropped_unparseable_total,
            audit_verification_failures_total,
            audit_ledger_duplicate_deliveries_total,
            audit_ledger_consumer_pending,
            audit_chain_duplicate_deliveries_total,
            audit_chain_multi_attempt_jobs_total,
            audit_chain_unverifiable_total,
            audit_chain_jobs_swept_total,
            audit_chain_last_verified_ok_timestamp_seconds,
            audit_chain_sweep_timestamp_seconds,
            worker_key_tofu_conflicts_total,
            http_missing_extension_total,
            worker_build_skew_workers,
            catalog_templates_missing_wasm,
            catalog_missing_wasm_scan_last_success_timestamp_seconds,
            worker_liveness_pings_total,
            worker_identity_reaps_total,
            oauth_reactive_refresh_total,
            worker_liveness_participants,
            worker_liveness_recent_participants,
            worker_liveness_population_truncated,
            worker_fleet_live_workers,
            worker_fleet_live_builds,
            worker_fleet_build_skew_builds,
            worker_fleet_unverifiable_builds,
            worker_fleet_build_skew_workers,
            worker_fleet_unverifiable_workers,
            worker_fleet_capacity_dropped_heartbeats,
            worker_fleet_capacity_dropped_builds,
            fuel_high_utilisation_nodes,
            fuel_utilisation_observed_nodes,
            scheduler_dispatches_total,
            rank_training_fetches_total,
            rank_training_lookback_shortfall_days,
            scheduler_readiness_holds_total,
            scheduler_readiness_degraded,
            rate_limit_hits_total,
            privileged_op_total,
            platform_admin_checks_total,
            google_push_refusals_total,
            google_push_accepted_total,
            google_push_deferred_total,
            execution_pause_refusals_total,
            webhook_duplicate_suppressed_total,
            actor_budget_refusals_total,
            google_jwk_refresh_total,
            vault_token_renewals_total,
            vault_token_ttl_seconds,
            advisory_db_age_days,
            advisory_db_max_age_days,
            advisory_db_age_enforced,
            advisory_db_age_samples_total,
            dlq_entries_total,
            dlq_drops_total,
            dlq_db_errors_total,
            kek_decrypt_failures_total,
            memory_write_failures_total,
            child_run_record_failures_total,
            rpc_write_ceiling_refusals_total,
            dispatch_refused_total,
            ops_alert_ingest_failures_total,
            ops_alert_auto_resolved_total,
            module_payload_encryption_failures_total,
            secret_decrypt_failures_total,
            actor_memory_orphaned_rows,
            module_execution_orphaned_rows,
            workflow_execution_orphaned_rows,
            crypto_orphan_scan_last_success_timestamp_seconds,
            dek_cache_size,
            db_pool_connections,
            db_pool_idle_connections,
            db_pool_in_use_connections,
            db_pool_max_connections,
        }))
    }

    /// Export metrics in Prometheus text format
    pub fn gather(&self) -> Vec<prometheus::proto::MetricFamily> {
        self.registry.gather()
    }

    /// Render the gathered registry into the Prometheus text exposition
    /// format. Returned string is UTF-8 and safe to drop into a
    /// `text/plain; version=0.0.4` HTTP response body.
    pub fn render_prometheus(&self) -> Result<String, prometheus::Error> {
        use prometheus::Encoder as _;
        let encoder = prometheus::TextEncoder::new();
        let mut buf = Vec::with_capacity(8192);
        encoder.encode(&self.gather(), &mut buf)?;
        String::from_utf8(buf).map_err(|e| prometheus::Error::Msg(format!("utf-8: {e}")))
    }
}

/// The platform-admin counter must keep DISCLOSING that its
/// `unauthenticated` label is unreachable.
///
/// `talos-api`'s `platform_admin_reachability_pins` proves the fact (every
/// `require_platform_admin` call site sits behind `require_scope`, which
/// refuses an anonymous caller first). This asserts the counter still SAYS
/// so: a correct pin beside a deleted disclosure leaves an operator reading a
/// permanent 0 as evidence that no anonymous caller reached a platform-admin
/// operation, which is exactly the reading the disclosure removes.
#[cfg(test)]
mod platform_admin_help_disclosure_tests {
    use super::TalosMetrics;
    use prometheus::Encoder;

    #[test]
    fn the_help_text_names_the_unreachable_label_and_why() {
        let m = TalosMetrics::new().expect("registry");
        let mut buf = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&m.registry.gather(), &mut buf)
            .expect("encode");
        let text = String::from_utf8(buf).expect("utf-8");
        let help = text
            .lines()
            .find(|l| l.starts_with("# HELP talos_platform_admin_checks_total"))
            .expect("the counter must be registered with a HELP line");
        assert!(
            help.contains("unauthenticated"),
            "HELP must name the unreachable label: {help}"
        );
        assert!(
            help.contains("require_scope"),
            "HELP must say WHY it is unreachable, not merely that it is: {help}"
        );
        assert!(
            help.contains("talos_privileged_op_total"),
            "HELP must point at the counter whose unauthenticated IS reachable: {help}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// The premise of the "do NOT pre-seed the MCP instrument" decision,
    /// pinned so it cannot silently stop being true.
    ///
    /// Both series are documented as unseeded because the label PRODUCT is
    /// large and a histogram series is expensive to render. This measures the
    /// per-series cost rather than asserting it from memory: if someone
    /// halves the bucket count, or adds a third series to the pair, the
    /// numbers in the field docs and in CLAUDE.md are wrong and this test
    /// says so.
    ///
    /// The numbers moved once, deliberately: package 35 added the `class`
    /// label, which adds no SERIES (it is a pure function of `outcome`) but
    /// does add ~19 bytes to each of the 20 rendered lines — 2356/1656 →
    /// 2941/1996 bytes, i.e. the no-pre-seed argument gets ~24 % stronger
    /// rather than weaker. And once more on 2026-09-11, on the FIRST-pair
    /// number only: both HELP texts grew (they now say which series to read
    /// for call volume and why the counter is seeded and the histogram is
    /// not), so the one-time preamble is 3459 bytes; the MARGINAL 1996 — the
    /// per-pair cost the histogram decision actually rests on — is unchanged.
    #[test]
    fn the_mcp_instrument_costs_the_lines_the_no_preseed_decision_assumes() {
        let m = TalosMetrics::new().expect("metrics");

        // Nothing before the first call: an absent (tool, outcome) is the
        // documented meaning of "not called since boot".
        let cold = m.render_prometheus().expect("render");
        assert!(
            !cold.contains("talos_mcp_tool_duration_seconds{"),
            "the instrument must export no per-tool series before any call"
        );
        assert!(
            !cold.contains("talos_mcp_tool_calls_total{"),
            "the instrument must export no per-tool series before any call"
        );

        record_mcp_tool_call_on(&m, "whoami", McpToolOutcome::Ok, Duration::from_millis(3));
        let warm = m.render_prometheus().expect("render");
        let lines = |needle: &str| {
            warm.lines()
                .filter(|l| !l.starts_with('#') && l.starts_with(needle))
                .count()
        };
        // 16 finite buckets + `le="+Inf"` + `_sum` + `_count` = 19 lines.
        assert_eq!(
            lines("talos_mcp_tool_duration_seconds"),
            19,
            "bucket layout changed; the pre-seed cost argument is stale"
        );
        assert_eq!(lines("talos_mcp_tool_calls_total"), 1);
        // First pair also pays the two families' HELP/TYPE preamble once.
        let first_pair_bytes = warm.len() - cold.len();
        record_mcp_tool_call_on(
            &m,
            "whoami",
            McpToolOutcome::Refused,
            Duration::from_millis(3),
        );
        let two = m.render_prometheus().expect("render");
        let marginal_bytes = two.len() - warm.len();
        assert_eq!(
            (first_pair_bytes, marginal_bytes),
            (3459, 1996),
            "per-(tool, outcome) scrape cost changed; the numbers in the field \
             docs and in CLAUDE.md's no-pre-seed argument are now stale"
        );
    }

    /// A second pair adds a second set of series — i.e. the label product is
    /// what it looks like, which is the other half of the same premise.
    #[test]
    fn each_tool_outcome_pair_is_its_own_series() {
        let m = TalosMetrics::new().expect("metrics");
        record_mcp_tool_call_on(&m, "whoami", McpToolOutcome::Ok, Duration::from_millis(1));
        let one = m.render_prometheus().expect("render").len();
        record_mcp_tool_call_on(
            &m,
            "whoami",
            McpToolOutcome::Refused,
            Duration::from_millis(1),
        );
        let two = m.render_prometheus().expect("render").len();
        assert!(
            two > one,
            "a second outcome on the same tool must add series, not fold in"
        );
    }

    #[test]
    fn test_metrics_creation() {
        let metrics = TalosMetrics::new();
        assert!(metrics.is_ok());
    }

    #[test]
    fn test_metrics_increment() {
        let metrics = TalosMetrics::new().unwrap();

        // Increment a counter
        metrics.dlq_entries_total.inc();

        // Verify it was incremented
        let families = metrics.gather();
        let dlq_metric = families
            .iter()
            .find(|f| f.name() == "talos_dlq_entries_total");
        assert!(dlq_metric.is_some());
    }

    /// The process collector is registered on Linux and its seven families
    /// render. Deleting the `register` call in `new()` fails this on every CI
    /// runner; on macOS the collector does not exist and the test is skipped
    /// rather than passed vacuously — a green tick over a cfg'd-out body
    /// would be the gate-that-doesn't-gate shape.
    #[cfg(target_os = "linux")]
    #[test]
    fn process_metrics_are_exported_on_linux() {
        let m = TalosMetrics::new().unwrap();
        let text = m.render_prometheus().unwrap();
        for series in [
            "process_resident_memory_bytes",
            "process_virtual_memory_bytes",
            "process_open_fds",
            "process_max_fds",
            "process_threads",
            "process_cpu_seconds_total",
            "process_start_time_seconds",
        ] {
            assert!(
                text.contains(&format!("\n{series} ")),
                "{series} must render from the registered ProcessCollector"
            );
        }
    }

    /// `#[test]` restored 2026-09-12: f27db68d inserted the process-metrics
    /// test above this fn and took this attribute with it, so the guard on the
    /// crypto series (incl. the blind-detector stamp rendering 0) had not run
    /// since 2026-09-11 while `cargo check --all-targets` called it dead code.
    /// The advisory-database age series (2026-09-22): the three readings are
    /// ABSENT on a cold registry — a seeded 0 would say "built today" — while
    /// both sample outcomes are seeded, and each recorder moves exactly the
    /// series it names.
    #[test]
    fn advisory_db_readings_are_absent_until_sampled_and_the_counter_is_seeded() {
        let m = TalosMetrics::new().unwrap();
        let cold = m.render_prometheus().expect("render");
        for reading in [
            "talos_advisory_db_age_days{",
            "talos_advisory_db_max_age_days{",
            "talos_advisory_db_age_enforced{",
        ] {
            assert!(
                !cold.contains(reading),
                "{reading} must be absent before the first sample"
            );
        }
        assert!(cold.contains(
            r#"talos_advisory_db_age_samples_total{copy="controller",outcome="measured"} 0"#
        ));
        assert!(cold.contains(
            r#"talos_advisory_db_age_samples_total{copy="controller",outcome="unreadable"} 0"#
        ));

        super::publish_advisory_db_age_on(&m, AdvisoryDbCopy::Controller, 75);
        super::publish_advisory_db_limits_on(&m, AdvisoryDbCopy::Controller, 90, true);
        super::record_advisory_db_sample_on(
            &m,
            AdvisoryDbCopy::Controller,
            AdvisoryDbSampleOutcome::Measured,
        );
        let warm = m.render_prometheus().expect("render");
        assert!(warm.contains(r#"talos_advisory_db_age_days{copy="controller"} 75"#));
        assert!(warm.contains(r#"talos_advisory_db_max_age_days{copy="controller"} 90"#));
        assert!(warm.contains(r#"talos_advisory_db_age_enforced{copy="controller"} 1"#));
        assert!(warm.contains(
            r#"talos_advisory_db_age_samples_total{copy="controller",outcome="measured"} 1"#
        ));
        assert!(warm.contains(
            r#"talos_advisory_db_age_samples_total{copy="controller",outcome="unreadable"} 0"#
        ));

        // A later sample that only warns flips the enforced reading; the age
        // it did not remeasure stands.
        super::publish_advisory_db_limits_on(&m, AdvisoryDbCopy::Controller, 120, false);
        let later = m.render_prometheus().expect("render");
        assert!(later.contains(r#"talos_advisory_db_max_age_days{copy="controller"} 120"#));
        assert!(later.contains(r#"talos_advisory_db_age_enforced{copy="controller"} 0"#));
        assert!(later.contains(r#"talos_advisory_db_age_days{copy="controller"} 75"#));
    }

    // Sanity-check that every crypto-invariant metric is actually
    // registered AND surfaces in the rendered Prometheus text format.
    // Catches typos in registry.register / series-name drift — a regression
    // here means the alerts in deploy/observability/alerts.yaml would
    // silently never fire. (Its `#[test]` sat orphaned above the Linux-only
    // process test from f27db68d until 2026-09-22: on Linux that made a
    // DUPLICATED `#[test]` there, which macOS — where the cfg removes the
    // item — could never compile; the first `--all-targets` CI clippy run
    // found it.)
    #[test]
    fn crypto_invariant_metrics_render() {
        let m = TalosMetrics::new().unwrap();

        m.kek_decrypt_failures_total
            .with_label_values(&["active"])
            .inc();
        m.kek_decrypt_failures_total
            .with_label_values(&["both"])
            .inc_by(2.0);
        m.memory_write_failures_total
            .with_label_values(&["crypto"])
            .inc();
        m.module_payload_encryption_failures_total
            .with_label_values(&["encrypt", "output"])
            .inc();
        m.actor_memory_orphaned_rows.set(3);
        m.module_execution_orphaned_rows.set(0);
        m.workflow_execution_orphaned_rows.set(0);
        m.dek_cache_size.set(42);

        let rendered = m.render_prometheus().expect("render");
        for name in [
            "talos_kek_decrypt_failures_total",
            "talos_memory_write_failures_total",
            "talos_module_payload_encryption_failures_total",
            "talos_actor_memory_orphaned_rows",
            "talos_module_execution_orphaned_rows",
            "talos_workflow_execution_orphaned_rows",
            // The meta-detector's series. It is registered but deliberately
            // NOT set above: the assertion below is that it renders as 0 on a
            // registry nothing has stamped, because `time() - 0` is what makes
            // TalosCryptoOrphanDetectorBlind fire for a controller whose sweep
            // never completed.
            "talos_crypto_orphan_scan_last_success_timestamp_seconds",
            "talos_dek_cache_size",
        ] {
            assert!(
                rendered.contains(name),
                "rendered output missing metric {name}\n--- output ---\n{rendered}"
            );
        }
        // Spot-check values land correctly.
        assert!(rendered.contains(r#"talos_kek_decrypt_failures_total{provider="active"} 1"#));
        assert!(rendered.contains(r#"talos_kek_decrypt_failures_total{provider="both"} 2"#));
        assert!(rendered.contains("talos_actor_memory_orphaned_rows 3"));
        assert!(rendered.contains("talos_dek_cache_size 42"));
        assert!(
            rendered.contains("talos_crypto_orphan_scan_last_success_timestamp_seconds 0"),
            "an unstamped freshness gauge must EXPORT 0, not be absent — an \
             absent series makes `time() - x > 600` an empty vector, which is \
             the detector silenced by its own condition (#625)"
        );
    }

    /// Absence is not zero. A `CounterVec` emits NOTHING until some label set
    /// is first touched, so on a healthy controller that has had no auth
    /// traffic and no crypto failure, ALL FIVE alerted CounterVecs were
    /// simply missing from `/metrics/prometheus` (verified 2026-08-02 against
    /// the live endpoint) — indistinguishable from the wiring having been
    /// deleted. Pre-seeding the combinations that have a live emitter makes
    /// idle read `0` instead; that fixes FOUR of the five, and
    /// `talos_auth_failures_total` deliberately stays absent (asserted
    /// below), because only 9 of its 16 (method, reason) pairs have an
    /// emitting call site.
    ///
    /// This test asserts the seeds on a FRESH registry with nothing recorded,
    /// which is the state that matters (`crypto_invariant_metrics_render`
    /// above increments first, so it cannot see this).
    /// The pre-seed, in BOTH directions.
    ///
    /// #778's worker regression was seeded pairs nothing in that process could
    /// increment, and the `absent != zero` rule is the mirror of it, so this
    /// asserts (a) every pair the table declares is present at exactly 0 on a
    /// cold registry, and (b) NO pair outside the table exists. Direction (b)
    /// is the one that catches a widening to the 7 x 18 cross product.
    #[test]
    fn the_rpc_instrument_seeds_exactly_the_reachable_pairs() {
        let m = TalosMetrics::new().unwrap();
        let rendered = m.render_prometheus().expect("render");

        // (a) every declared pair is present, at zero.
        let mut declared = std::collections::HashSet::new();
        for (subject, outcome) in rpc::seeded_pairs() {
            let line = format!(
                r#"talos_rpc_calls_total{{class="{}",outcome="{}",subject="{}"}} 0"#,
                outcome.class().as_str(),
                outcome.as_str(),
                subject.as_str()
            );
            assert!(
                rendered.contains(&line),
                "reachable pair not seeded: {line}\n\
                 An absent series is not a zero: `increase(...) > 0` over it matches \
                 nothing, which is how the RPC plane stayed uninstrumented for a year."
            );
            declared.insert(line);
        }
        assert_eq!(declared.len(), 64, "the table changed; re-derive it");

        // (b) nothing outside the table. A seeded combination nothing can
        // increment reads as a wired signal that does not exist (check 58).
        let exported: Vec<&str> = rendered
            .lines()
            .filter(|l| l.starts_with("talos_rpc_calls_total{"))
            .collect();
        assert_eq!(
            exported.len(),
            64,
            "expected exactly the 64 reachable pairs, got {}:\n{}",
            exported.len(),
            exported.join("\n")
        );
        for line in exported {
            assert!(
                declared.contains(line),
                "exported a pair the table does not declare: {line}"
            );
        }

        // The histogram is deliberately unseeded — see its field docs. A
        // seeded histogram over zero observations says nothing the seeded
        // counter at 0 does not, at 21 lines per pair instead of 1.
        assert!(
            !rendered.contains("talos_rpc_duration_seconds{"),
            "the duration histogram must export no series before the first call"
        );
    }

    /// The histogram observes the WHOLE call, queue wait included.
    ///
    /// This is a measured SURVIVOR closed. `record_rpc_call_on`'s observed
    /// VALUE is not visible to the wiring test in
    /// `controller/tests/rpc_instrument_tests` — that one proves the series
    /// MOVED, and on the reference fleet every `queue_ms`/`exec_ms` is 0, so a
    /// mutation dropping the queue wait would leave it green. The queue is the
    /// per-subject semaphore wait, i.e. the only part of an RPC that grows
    /// under backpressure; observing `exec` alone would make a saturated
    /// subject look fast.
    #[test]
    fn the_duration_histogram_observes_queue_plus_exec() {
        let m = TalosMetrics::new().unwrap();
        record_rpc_call_on(
            &m,
            RpcSubject::MemoryOp,
            RpcOutcome::Ok,
            Duration::from_millis(1500),
            Duration::from_millis(2500),
        );
        let rendered = m.render_prometheus().expect("render");
        let sum_line = rendered
            .lines()
            .find(|l| l.starts_with("talos_rpc_duration_seconds_sum{"))
            .expect("the histogram exported a _sum after one observation");
        let sum: f64 = sum_line
            .rsplit(' ')
            .next()
            .and_then(|v| v.parse().ok())
            .expect("parse _sum");
        assert!(
            (sum - 4.0).abs() < 1e-9,
            "expected 1.5s queue + 2.5s exec = 4s, got {sum} from `{sum_line}`"
        );
        // Sub-millisecond resolution survives, which is why the call sites
        // pass `Duration` rather than the pre-rounded `as_millis()` they used
        // to: every exec time on the reference fleet rounds to 0 ms.
        let m2 = TalosMetrics::new().unwrap();
        record_rpc_call_on(
            &m2,
            RpcSubject::MemoryOp,
            RpcOutcome::Ok,
            Duration::ZERO,
            Duration::from_micros(700),
        );
        let sum2: f64 = m2
            .render_prometheus()
            .expect("render")
            .lines()
            .find(|l| l.starts_with("talos_rpc_duration_seconds_sum{"))
            .and_then(|l| l.rsplit(' ').next().and_then(|v| v.parse().ok()))
            .expect("parse _sum");
        assert!(
            sum2 > 0.0,
            "a 700 microsecond call must be observable; it rounds to 0 ms, which \
             is what the pre-2026-09-09 signature would have recorded"
        );
    }

    /// The measured per-pair scrape cost, which is the premise of the
    /// seed-the-counter / do-not-seed-the-histogram split. Measured rather
    /// than asserted from memory: if the bucket count changes, the numbers in
    /// the field docs and in CLAUDE.md are stale and this says so.
    #[test]
    fn the_rpc_instrument_costs_the_lines_the_seed_decision_assumes() {
        let m = TalosMetrics::new().unwrap();
        let cold = m.render_prometheus().expect("render");
        record_rpc_call_on(
            &m,
            RpcSubject::MemoryOp,
            RpcOutcome::Ok,
            std::time::Duration::from_millis(1),
            std::time::Duration::from_millis(2),
        );
        let warm = m.render_prometheus().expect("render");
        let lines = |body: &str, needle: &str| {
            body.lines()
                .filter(|l| !l.starts_with('#') && l.starts_with(needle))
                .count()
        };
        // 18 finite buckets + le="+Inf" + _sum + _count = 21 lines per pair.
        assert_eq!(
            lines(&warm, "talos_rpc_duration_seconds"),
            21,
            "bucket layout changed; the no-seed cost argument is stale"
        );
        // The counter is seeded, so its line count does not move.
        assert_eq!(lines(&cold, "talos_rpc_calls_total"), 64);
        assert_eq!(lines(&warm, "talos_rpc_calls_total"), 64);
    }

    /// The DEFERRED-push counter (package ES) is seeded over its whole closed
    /// product and moved by exactly the integration it was given.
    ///
    /// The seeding is the load-bearing half: this arm has never fired on the
    /// reference fleet, so on any controller that has not deferred a push the
    /// series would be ABSENT, and `increase()` over an absent series matches
    /// nothing — "no push has ever been deferred" and "the deferral is not
    /// wired" would render identically. The counter is also asserted to be
    /// SEPARATE from the refusal counter: a refusal means we rejected a sender,
    /// a deferral means we could not answer one, and folding them would put a
    /// platform failure behind a counter whose every other value is the
    /// fail-closed control working as designed.
    #[test]
    fn google_push_deferred_is_seeded_over_its_closed_product() {
        let m = TalosMetrics::new().unwrap();
        let cold = m.render_prometheus().expect("render");
        for integration in PushIntegration::ALL {
            for reason in PushDeferReason::ALL {
                assert!(
                    cold.contains(&format!(
                        "talos_google_push_deferred_total{{integration=\"{}\",reason=\"{}\"}} 0",
                        integration.as_str(),
                        reason.as_str()
                    )),
                    "unseeded pair {}/{} reads as absent, not zero",
                    integration.as_str(),
                    reason.as_str()
                );
            }
        }
        record_google_push_deferred_on(
            &m,
            PushIntegration::Gmail,
            PushDeferReason::WatchLookupUnreadable,
        );
        let warm = m.render_prometheus().expect("render");
        assert!(warm.contains(
            "talos_google_push_deferred_total{integration=\"gmail\",reason=\"watch_lookup_unreadable\"} 1"
        ));
        assert!(
            warm.contains(
                "talos_google_push_deferred_total{integration=\"gcp\",reason=\"watch_lookup_unreadable\"} 0"
            ),
            "one integration's deferral must not move another's"
        );
        // A deferral is NOT a refusal.
        assert!(
            warm.contains(
                "talos_google_push_refusals_total{integration=\"gmail\",reason=\"invalid\"} 0"
            ),
            "the refusal counter must be untouched by a deferral"
        );
    }

    /// The accepted-push counter (2026-09-18) is seeded for every
    /// integration and moved by exactly the integration it was given.
    #[test]
    fn google_push_accepted_is_seeded_and_moved_by_integration() {
        let m = TalosMetrics::new().unwrap();
        let cold = m.render_prometheus().expect("render");
        for i in PushIntegration::ALL {
            assert!(cold.contains(&format!(
                "talos_google_push_accepted_total{{integration=\"{}\"}} 0",
                i.as_str()
            )));
        }
        record_google_push_accepted_on(&m, PushIntegration::Gmail);
        let warm = m.render_prometheus().expect("render");
        assert!(warm.contains("talos_google_push_accepted_total{integration=\"gmail\"} 1"));
        assert!(warm.contains("talos_google_push_accepted_total{integration=\"gcp\"} 0"));
    }

    /// The Google push counters (2026-09-12) are seeded over the FULL
    /// integration × reason product — every pair is reachable from a live
    /// handler — and both recorders move exactly the pair they were given.
    #[test]
    fn google_push_counters_are_seeded_over_the_product_and_moved_by_pair() {
        let m = TalosMetrics::new().unwrap();
        let cold = m.render_prometheus().expect("render");
        let mut seeded = 0;
        for i in PushIntegration::ALL {
            for r in PushRefusalReason::ALL {
                assert!(cold.contains(&format!(
                    "talos_google_push_refusals_total{{integration=\"{}\",reason=\"{}\"}} 0",
                    i.as_str(),
                    r.as_str()
                )));
                seeded += 1;
            }
        }
        assert_eq!(seeded, 18, "the HELP text claims 18 pre-seeded pairs");
        for o in JwkRefreshOutcome::ALL {
            assert!(cold.contains(&format!(
                "talos_google_jwk_refresh_total{{outcome=\"{}\"}} 0",
                o.as_str()
            )));
        }
        record_google_push_refusal_on(&m, PushIntegration::Gmail, PushRefusalReason::UnknownKey);
        record_google_jwk_refresh_on(&m, JwkRefreshOutcome::Failed);
        let warm = m.render_prometheus().expect("render");
        assert!(warm.contains(
            "talos_google_push_refusals_total{integration=\"gmail\",reason=\"unknown_key\"} 1"
        ));
        // The sibling integration's same reason did NOT move — the label is
        // not aggregated away by the recorder.
        assert!(warm.contains(
            "talos_google_push_refusals_total{integration=\"gcp\",reason=\"unknown_key\"} 0"
        ));
        assert!(warm.contains("talos_google_jwk_refresh_total{outcome=\"failed\"} 1"));
        assert!(warm.contains("talos_google_jwk_refresh_total{outcome=\"ok\"} 0"));
    }

    /// The Vault token instruments (2026-09-14) are ABSENT on a cold registry —
    /// no Vault KEK provider has started — the seed brings all three outcomes
    /// to 0, each recorder moves exactly its outcome, and the TTL gauge carries
    /// exactly ONE lifetime class at a time.
    #[test]
    fn vault_token_instruments_are_absent_until_seeded_and_one_lifetime_at_a_time() {
        let m = TalosMetrics::new().unwrap();
        let cold = m.render_prometheus().expect("render");
        assert!(
            !cold.contains("talos_vault_token_renewals_total{"),
            "an env-KEK process must not expose renewal series nothing can move"
        );
        assert!(!cold.contains("talos_vault_token_ttl_seconds{"));

        seed_vault_token_renewals_on(&m);
        let seeded = m.render_prometheus().expect("render");
        for o in VaultTokenRenewalOutcome::ALL {
            assert!(seeded.contains(&format!(
                "talos_vault_token_renewals_total{{outcome=\"{}\"}} 0",
                o.as_str()
            )));
        }

        record_vault_token_renewal_on(&m, VaultTokenRenewalOutcome::Capped);
        publish_vault_token_ttl_on(&m, VaultTokenLifetimeLabel::Periodic, 2_764_800);
        publish_vault_token_ttl_on(&m, VaultTokenLifetimeLabel::RenewableBounded, 3600);
        let warm = m.render_prometheus().expect("render");
        assert!(warm.contains("talos_vault_token_renewals_total{outcome=\"capped\"} 1"));
        assert!(warm.contains("talos_vault_token_renewals_total{outcome=\"renewed\"} 0"));
        assert!(warm.contains("talos_vault_token_renewals_total{outcome=\"failed\"} 0"));
        assert!(warm.contains("talos_vault_token_ttl_seconds{lifetime=\"renewable_bounded\"} 3600"));
        assert!(
            !warm.contains("talos_vault_token_ttl_seconds{lifetime=\"periodic\"}"),
            "a class the token is no longer must be removed, not left stale"
        );
    }

    /// Every `(cap, mode)` pair of the actor-budget counter is seeded at 0 and
    /// moved by the recorder; the cap strings are the backstop's `kind`s and the
    /// mode parse is exactly the column's CHECK set.
    #[test]
    fn actor_budget_refusals_are_seeded_and_the_recorder_moves_them() {
        let m = TalosMetrics::new().unwrap();
        let cold = m.render_prometheus().expect("render");
        for cap in BudgetCap::ALL {
            for mode in BudgetMode::ALL {
                assert!(
                    cold.contains(&format!(
                        "talos_actor_budget_refusals_total{{cap=\"{}\",mode=\"{}\"}} 0",
                        cap.as_str(),
                        mode.as_str()
                    )),
                    "unseeded pair {cap:?}/{mode:?}"
                );
                record_actor_budget_refusal_on(&m, *cap, *mode);
            }
        }
        let warm = m.render_prometheus().expect("render");
        for cap in BudgetCap::ALL {
            for mode in BudgetMode::ALL {
                assert!(warm.contains(&format!(
                    "talos_actor_budget_refusals_total{{cap=\"{}\",mode=\"{}\"}} 1",
                    cap.as_str(),
                    mode.as_str()
                )));
            }
        }
        for mode in BudgetMode::ALL {
            assert_eq!(BudgetMode::parse(mode.as_str()), Some(*mode));
        }
        assert_eq!(BudgetMode::parse("notify"), None);
    }

    /// Every format of the webhook duplicate-suppression counter is seeded at
    /// 0 and moved by the recorder. Exhaustive over `ALL`, so a sixth
    /// authentication scheme cannot ship without a seeded series.
    #[test]
    fn webhook_duplicate_suppressions_are_seeded_and_the_recorder_moves_them() {
        let m = TalosMetrics::new().unwrap();
        let cold = m.render_prometheus().expect("render");
        for format in WebhookAuthFormat::ALL {
            assert!(
                cold.contains(&format!(
                    "talos_webhook_duplicate_suppressed_total{{format=\"{}\"}} 0",
                    format.as_str()
                )),
                "unseeded format {format:?}"
            );
            record_webhook_duplicate_suppressed_on(&m, *format);
        }
        let warm = m.render_prometheus().expect("render");
        for format in WebhookAuthFormat::ALL {
            assert!(warm.contains(&format!(
                "talos_webhook_duplicate_suppressed_total{{format=\"{}\"}} 1",
                format.as_str()
            )));
        }
        // The label values are distinct — a collision would merge two schemes
        // into one series and make the github reading unreadable.
        let mut seen = std::collections::HashSet::new();
        for format in WebhookAuthFormat::ALL {
            assert!(seen.insert(format.as_str()), "duplicate label {format:?}");
        }
    }

    /// Every `(path, reason)` pair of the execution-pause counter is seeded at
    /// 0 and moved by the recorder. Exhaustive over both `ALL`s.
    #[test]
    fn execution_pause_refusals_are_seeded_and_the_recorder_moves_them() {
        let m = TalosMetrics::new().unwrap();
        let cold = m.render_prometheus().expect("render");
        for path in PauseGatePath::ALL {
            for reason in PauseRefusal::ALL {
                assert!(
                    cold.contains(&format!(
                        "talos_execution_pause_refusals_total{{path=\"{}\",reason=\"{}\"}} 0",
                        path.as_str(),
                        reason.as_str()
                    )),
                    "unseeded pair {path:?}/{reason:?}"
                );
            }
        }
        for path in PauseGatePath::ALL {
            for reason in PauseRefusal::ALL {
                record_execution_pause_refusal_on(&m, *path, *reason);
            }
        }
        let warm = m.render_prometheus().expect("render");
        for path in PauseGatePath::ALL {
            for reason in PauseRefusal::ALL {
                assert!(warm.contains(&format!(
                    "talos_execution_pause_refusals_total{{path=\"{}\",reason=\"{}\"}} 1",
                    path.as_str(),
                    reason.as_str()
                )));
            }
        }
    }

    /// The three security counters that sat DEAD in check 58's baseline for
    /// four months are now seeded over their closed sets and moved by their
    /// recorders. Exhaustive over `ALL`, so a new variant is covered the
    /// moment it is declared.
    #[test]
    fn security_counters_are_seeded_and_their_recorders_move_them() {
        let m = TalosMetrics::new().unwrap();
        let cold = m.render_prometheus().expect("render");
        for o in TwoFactorOutcome::ALL {
            assert!(cold.contains(&format!(
                "talos_auth_2fa_attempts_total{{status=\"{}\"}} 0",
                o.as_str()
            )));
        }
        for v in ApiKeyValidation::ALL {
            assert!(cold.contains(&format!(
                "talos_api_key_validations_total{{status=\"{}\"}} 0",
                v.as_str()
            )));
        }
        for k in RateLimitKind::ALL {
            assert!(cold.contains(&format!(
                "talos_rate_limit_hits_total{{type=\"{}\"}} 0",
                k.as_str()
            )));
        }
        for o in McpAuthOutcome::ALL {
            assert!(cold.contains(&format!(
                "talos_mcp_auth_total{{outcome=\"{}\"}} 0",
                o.as_str()
            )));
        }
        for o in TwoFactorOutcome::ALL {
            record_2fa_attempt_on(&m, *o);
        }
        for v in ApiKeyValidation::ALL {
            record_api_key_validation_on(&m, *v);
        }
        for k in RateLimitKind::ALL {
            record_rate_limit_hit_on(&m, *k);
        }
        for o in McpAuthOutcome::ALL {
            record_mcp_auth_on(&m, *o);
        }
        for o in PasswordChangeOutcome::ALL {
            assert!(cold.contains(&format!(
                "talos_password_changes_total{{outcome=\"{}\"}} 0",
                o.as_str()
            )));
            record_password_change_on(&m, *o);
        }
        // The refresh-token reuse detector and its arm side. Both are
        // security counters whose FIRST event is the one that matters, so
        // absent-vs-zero is not acceptable for either: a cold registry must
        // already export every value at 0.
        for o in TokenReuseOutcome::ALL {
            assert!(cold.contains(&format!(
                "talos_auth_token_reuse_total{{outcome=\"{}\"}} 0",
                o.as_str()
            )));
            record_token_reuse_on(&m, *o);
        }
        for o in RotationAuditArmOutcome::ALL {
            assert!(cold.contains(&format!(
                "talos_auth_rotation_audit_arm_total{{outcome=\"{}\"}} 0",
                o.as_str()
            )));
            record_rotation_audit_arm_on(&m, *o);
        }
        // The WebSocket lane (package DU): three closed sets, every value
        // exported at 0 on a cold registry; the gauge reads 0 and follows the
        // guard both ways.
        for o in WsHandshakeOutcome::ALL {
            assert!(cold.contains(&format!(
                "talos_ws_handshakes_total{{outcome=\"{}\"}} 0",
                o.as_str()
            )));
            record_ws_handshake_on(&m, *o);
        }
        for r in WsSessionEnd::ALL {
            assert!(cold.contains(&format!(
                "talos_ws_session_ends_total{{reason=\"{}\"}} 0",
                r.as_str()
            )));
            record_ws_session_end_on(&m, *r);
        }
        for o in WsOperationOutcome::ALL {
            assert!(cold.contains(&format!(
                "talos_ws_operations_total{{outcome=\"{}\"}} 0",
                o.as_str()
            )));
            record_ws_operation_on(&m, *o);
        }
        assert!(cold.contains("talos_ws_active_sessions 0"));
        {
            let _a = WsActiveSession::open_on(&m);
            let _b = WsActiveSession::open_on(&m);
            assert!(m
                .render_prometheus()
                .expect("render")
                .contains("talos_ws_active_sessions 2"));
            drop(_a);
            assert!(m
                .render_prometheus()
                .expect("render")
                .contains("talos_ws_active_sessions 1"));
        }
        // The GraphQL privileged and platform-admin gates (package DY). The
        // LAST bearer/auth surfaces on this platform with no series, and the
        // first refusal is the one an operator wants, so a cold registry must
        // already export every value at 0 — including `permitted`, without
        // which a refusal rate has no denominator and a quiet deployment is
        // indistinguishable from an unwired gate.
        for o in PrivilegedOpOutcome::ALL {
            assert!(cold.contains(&format!(
                "talos_privileged_op_total{{outcome=\"{}\"}} 0",
                o.as_str()
            )));
            record_privileged_op_on(&m, *o);
        }
        for o in PlatformAdminOutcome::ALL {
            assert!(cold.contains(&format!(
                "talos_platform_admin_checks_total{{outcome=\"{}\"}} 0",
                o.as_str()
            )));
            record_platform_admin_check_on(&m, *o);
        }
        let warm = m.render_prometheus().expect("render");
        assert!(warm.contains("talos_ws_active_sessions 0"));
        for o in WsHandshakeOutcome::ALL {
            assert!(warm.contains(&format!(
                "talos_ws_handshakes_total{{outcome=\"{}\"}} 1",
                o.as_str()
            )));
        }
        assert_eq!(WsHandshakeOutcome::ALL.len(), 10);
        assert_eq!(
            warm.matches("talos_ws_handshakes_total{outcome=").count(),
            10
        );
        for r in WsSessionEnd::ALL {
            assert!(warm.contains(&format!(
                "talos_ws_session_ends_total{{reason=\"{}\"}} 1",
                r.as_str()
            )));
        }
        for o in WsOperationOutcome::ALL {
            assert!(warm.contains(&format!(
                "talos_ws_operations_total{{outcome=\"{}\"}} 1",
                o.as_str()
            )));
        }
        for o in TwoFactorOutcome::ALL {
            assert!(warm.contains(&format!(
                "talos_auth_2fa_attempts_total{{status=\"{}\"}} 1",
                o.as_str()
            )));
        }
        for v in ApiKeyValidation::ALL {
            assert!(warm.contains(&format!(
                "talos_api_key_validations_total{{status=\"{}\"}} 1",
                v.as_str()
            )));
        }
        for k in RateLimitKind::ALL {
            assert!(warm.contains(&format!(
                "talos_rate_limit_hits_total{{type=\"{}\"}} 1",
                k.as_str()
            )));
        }
        for o in McpAuthOutcome::ALL {
            assert!(warm.contains(&format!(
                "talos_mcp_auth_total{{outcome=\"{}\"}} 1",
                o.as_str()
            )));
        }
        // Seven distinct label values, seven distinct series — the recorder
        // does not aggregate outcomes away.
        assert_eq!(McpAuthOutcome::ALL.len(), 7);
        assert_eq!(warm.matches("talos_mcp_auth_total{outcome=").count(), 7);
        // Package DY's two gates: every value moved exactly once, and the
        // series count equals the enum arity — a recorder that collapsed two
        // refusal reasons into one label would pass the per-value loop above
        // and fail here.
        for o in PrivilegedOpOutcome::ALL {
            assert!(warm.contains(&format!(
                "talos_privileged_op_total{{outcome=\"{}\"}} 1",
                o.as_str()
            )));
        }
        assert_eq!(PrivilegedOpOutcome::ALL.len(), 7);
        assert_eq!(
            warm.matches("talos_privileged_op_total{outcome=").count(),
            PrivilegedOpOutcome::ALL.len()
        );
        for o in PlatformAdminOutcome::ALL {
            assert!(warm.contains(&format!(
                "talos_platform_admin_checks_total{{outcome=\"{}\"}} 1",
                o.as_str()
            )));
        }
        assert_eq!(PlatformAdminOutcome::ALL.len(), 4);
        assert_eq!(
            warm.matches("talos_platform_admin_checks_total{outcome=")
                .count(),
            PlatformAdminOutcome::ALL.len()
        );
        // The two per-USER GraphQL throttles joined the limiter family; the
        // loop above already moved every kind, so this pins that the family
        // GREW rather than that a name was swapped.
        assert_eq!(RateLimitKind::ALL.len(), 7);
        for k in [
            RateLimitKind::GraphqlHeavyMutation,
            RateLimitKind::GraphqlRhai,
        ] {
            assert!(warm.contains(&format!(
                "talos_rate_limit_hits_total{{type=\"{}\"}} 1",
                k.as_str()
            )));
        }
        for o in PasswordChangeOutcome::ALL {
            assert!(warm.contains(&format!(
                "talos_password_changes_total{{outcome=\"{}\"}} 1",
                o.as_str()
            )));
        }
        assert_eq!(
            warm.matches("talos_password_changes_total{outcome=")
                .count(),
            PasswordChangeOutcome::ALL.len()
        );
        for o in TokenReuseOutcome::ALL {
            assert!(warm.contains(&format!(
                "talos_auth_token_reuse_total{{outcome=\"{}\"}} 1",
                o.as_str()
            )));
        }
        // Five distinct verdicts, five distinct series — the recorder does
        // not aggregate `detector_unreadable` into `not_reused`, which is
        // the whole point of the split.
        assert_eq!(TokenReuseOutcome::ALL.len(), 5);
        assert_eq!(
            warm.matches("talos_auth_token_reuse_total{outcome=")
                .count(),
            TokenReuseOutcome::ALL.len()
        );
        for o in RotationAuditArmOutcome::ALL {
            assert!(warm.contains(&format!(
                "talos_auth_rotation_audit_arm_total{{outcome=\"{}\"}} 1",
                o.as_str()
            )));
        }
        assert_eq!(
            warm.matches("talos_auth_rotation_audit_arm_total{outcome=")
                .count(),
            RotationAuditArmOutcome::ALL.len()
        );
        // The two execution families that closed the baseline: the counter is
        // seeded over ALL and both recorders move counter + histogram, the
        // histogram only when a duration is known.
        for o in ModuleExecutionOutcome::ALL {
            assert!(warm.contains(&format!(
                "talos_module_executions_total{{status=\"{}\"}} 0",
                o.as_str()
            )));
        }
        record_module_execution_on(&m, ModuleExecutionOutcome::Completed, Some(2.5));
        record_module_execution_on(&m, ModuleExecutionOutcome::Cancelled, None);
        record_workflow_outcome_on(&m, "success", Some(4.0));
        record_workflow_outcome_on(&m, "failure", None);
        let after = m.render_prometheus().expect("render");
        assert!(after.contains("talos_module_executions_total{status=\"completed\"} 1"));
        assert!(after.contains("talos_module_executions_total{status=\"cancelled\"} 1"));
        assert!(
            after.contains("talos_module_execution_duration_seconds_count{status=\"completed\"} 1")
        );
        assert!(
            !after.contains("talos_module_execution_duration_seconds_count{status=\"cancelled\"}"),
            "an unknown duration must not be observed as zero seconds"
        );
        assert!(
            after.contains("talos_workflow_execution_duration_seconds_count{status=\"success\"} 1")
        );
        assert!(
            !after.contains("talos_workflow_execution_duration_seconds_count{status=\"failure\"}")
        );
        // And the four deleted families are gone — a registry that still
        // exported them would be the dead-metric defect back under a comment.
        for gone in [
            "talos_webhook_requests_total",
            "talos_webhook_request_duration_seconds",
            "talos_cache_hits_total",
            "talos_cache_misses_total",
        ] {
            assert!(
                !warm.contains(gone),
                "{gone} was deleted and must not render"
            );
        }
    }

    #[test]
    fn alerted_counter_vecs_are_seeded_at_zero_on_a_cold_registry() {
        let m = TalosMetrics::new().unwrap();
        let rendered = m.render_prometheus().expect("render");

        // `talos_rpc_calls_total` is alerted (`TalosRPCSubjectFailing`) and
        // seeded too, but its 64 pairs are asserted EXHAUSTIVELY and in BOTH
        // directions by `the_rpc_instrument_seeds_exactly_the_reachable_pairs`
        // below — listing them here would be a second, hand-maintained copy of
        // the table, which is the drift the table exists to remove.
        for expected in [
            r#"talos_auth_attempts_total{method="password"} 0"#,
            r#"talos_auth_attempts_total{method="oauth"} 0"#,
            r#"talos_kek_decrypt_failures_total{provider="active"} 0"#,
            r#"talos_kek_decrypt_failures_total{provider="both"} 0"#,
            r#"talos_memory_write_failures_total{reason="crypto"} 0"#,
            r#"talos_memory_write_failures_total{reason="db"} 0"#,
            r#"talos_memory_write_failures_total{reason="validation"} 0"#,
            r#"talos_memory_write_failures_total{reason="other"} 0"#,
            // The per-actor row cap (2026-09-25), a `MemoryWriteError`
            // variant like the four above.
            r#"talos_memory_write_failures_total{reason="quota"} 0"#,
            // #750's policy refusal. Not a `MemoryWriteError` variant — the
            // one emitter is `ControllerNodeHook::record_memory_write_refusal`
            // — and it was unseeded until 2026-09-05, so the series only
            // existed on a controller that had already refused something.
            r#"talos_memory_write_failures_total{reason="write_ceiling"} 0"#,
            // RFC 0012's child-run ledger. Its healthy steady state is zero
            // forever, which is exactly the case where ABSENT and ZERO
            // diverge. Both reasons have a live emitter in
            // `PostgresChildRunRecorder`.
            r#"talos_child_run_record_failures_total{reason="acquire"} 0"#,
            r#"talos_child_run_record_failures_total{reason="insert"} 0"#,
            // #757's fleet-configuration signal. Its healthy steady state is
            // zero forever, which is exactly the case where ABSENT and ZERO
            // diverge: the alert on it is an `increase(...) > 0`, and an
            // absent counter matches nothing. All six combinations are seeded
            // because `write_ceiling::gate` is one chokepoint reached on all
            // three subjects, and both reasons are reachable at each.
            r#"talos_rpc_write_ceiling_refusals_total{reason="policy",subject="talos.memory.op"} 0"#,
            r#"talos_rpc_write_ceiling_refusals_total{reason="unreadable",subject="talos.memory.op"} 0"#,
            r#"talos_rpc_write_ceiling_refusals_total{reason="policy",subject="talos.integration_state.op"} 0"#,
            r#"talos_rpc_write_ceiling_refusals_total{reason="unreadable",subject="talos.integration_state.op"} 0"#,
            r#"talos_rpc_write_ceiling_refusals_total{reason="policy",subject="talos.database.query"} 0"#,
            r#"talos_dispatch_refused_total{path="scheduler",reason="archived"} 0"#,
            r#"talos_dispatch_refused_total{path="webhook",reason="archived"} 0"#,
            r#"talos_dispatch_refused_total{path="trigger",reason="archived"} 0"#,
            r#"talos_dispatch_refused_total{path="call_workflow",reason="archived"} 0"#,
            r#"talos_dispatch_refused_total{path="bulk_trigger",reason="archived"} 0"#,
            r#"talos_dispatch_refused_total{path="trigger_as_actors",reason="archived"} 0"#,
            r#"talos_dispatch_refused_total{path="enqueue",reason="archived"} 0"#,
            r#"talos_dispatch_refused_total{path="continuation",reason="archived"} 0"#,
            r#"talos_dispatch_refused_total{path="sub_workflow",reason="archived"} 0"#,
            r#"talos_dispatch_refused_total{path="retry",reason="archived"} 0"#,
            r#"talos_dispatch_refused_total{path="replay",reason="archived"} 0"#,
            r#"talos_dispatch_refused_total{path="handoff",reason="archived"} 0"#,
            // The refresh-token reuse detector (2026-09-21). Its healthy
            // steady state is zero FOREVER on `detected` / `revoke_failed`,
            // which is exactly where ABSENT and ZERO diverge: the alert on
            // them is an `increase(...) > 0`, and an absent counter matches
            // nothing. The arm pair carries the denominator of the ratio
            // alert, so both of ITS values are seeded too — a ratio over an
            // absent denominator is NaN, not 0. The other three verdicts are
            // asserted, in both directions, by the exhaustive security-counter
            // test above.
            r#"talos_auth_token_reuse_total{outcome="detected"} 0"#,
            r#"talos_auth_token_reuse_total{outcome="revoke_failed"} 0"#,
            r#"talos_auth_rotation_audit_arm_total{outcome="armed"} 0"#,
            r#"talos_auth_rotation_audit_arm_total{outcome="failed"} 0"#,
            r#"talos_rpc_write_ceiling_refusals_total{reason="unreadable",subject="talos.database.query"} 0"#,
            // #767's audit-chain read-side detector. ABSENT and ZERO diverge
            // here in the sharpest possible way: the control this counts had
            // NEVER functioned on the reference deployment, and the reason
            // nothing said so is that its `Err` arm incremented nothing at
            // all. All SEVEN reasons are seeded because every one has a live
            // emitter — six through `inc_chain_unverifiable` at the sweep's
            // one classification site, and `no_credentials` at the
            // client-build refusal.
            r#"talos_audit_chain_unverifiable_total{reason="access_denied"} 0"#,
            r#"talos_audit_chain_unverifiable_total{reason="no_such_bucket"} 0"#,
            r#"talos_audit_chain_unverifiable_total{reason="not_found"} 0"#,
            r#"talos_audit_chain_unverifiable_total{reason="transport"} 0"#,
            r#"talos_audit_chain_unverifiable_total{reason="other"} 0"#,
            r#"talos_audit_chain_unverifiable_total{reason="no_credentials"} 0"#,
            r#"talos_audit_chain_unverifiable_total{reason="empty_chain"} 0"#,
            // Package AV's denominator: the per-job half of the unverifiable
            // alert is a RATIO over this, so the ratio must be defined from
            // the first sweep, not from the first job that happened to fail.
            r#"talos_audit_chain_jobs_swept_total{outcome="verified_ok"} 0"#,
            r#"talos_audit_chain_jobs_swept_total{outcome="unanchored"} 0"#,
            r#"talos_audit_chain_jobs_swept_total{outcome="empty"} 0"#,
            r#"talos_audit_chain_jobs_swept_total{outcome="failed"} 0"#,
            r#"talos_audit_chain_jobs_swept_total{outcome="errored"} 0"#,
            // The advisory-database age sampler (2026-09-22). Its `unreadable`
            // value is alerted with an `increase(...) > 0`, and on a correctly
            // built image it is zero FOREVER — exactly where ABSENT and ZERO
            // diverge. Both outcomes are seeded because one sampler reaches
            // both.
            r#"talos_advisory_db_age_samples_total{copy="controller",outcome="measured"} 0"#,
            r#"talos_advisory_db_age_samples_total{copy="controller",outcome="unreadable"} 0"#,
            // The duplicate-delivery pair. Neither is alerted on — that is the
            // point of them — but both are read by an operator asking "is this
            // ledger carrying redundant copies?", and an ABSENT series answers
            // that question "no" when the truth is "nothing has looked". Only
            // `scope="batch"` is seeded: the writer is write-only and cannot
            // see a cross-batch copy, so a second scope value would be a label
            // with no increment site.
            r#"talos_audit_ledger_duplicate_deliveries_total{scope="batch"} 0"#,
            "talos_audit_chain_duplicate_deliveries_total 0",
            // Same reasoning as the pair above: a re-dispatch is a routine
            // fleet fact, nothing alerts on it, and an absent series answers
            // "how often does the controller re-dispatch?" with "never" when
            // the truth is "nothing has looked".
            "talos_audit_chain_multi_attempt_jobs_total 0",
            // The adaptive-rank training-window pair. Neither is alerted on
            // (a cap that binds every tick on a busy fleet is a permanent
            // state, and an alert on it would fire forever), but the SEEDING
            // is what makes the gauge beside them legible: a shortfall gauge
            // of 0 means "no fit fell short" OR "no tick has run", and only a
            // seeded pair of counters summing to 0 tells those apart. An
            // absent `truncated` series answers "has the training window ever
            // been cut short?" with "no" when the truth is "nothing has
            // looked".
            r#"talos_rank_training_fetches_total{coverage="complete"} 0"#,
            r#"talos_rank_training_fetches_total{coverage="truncated"} 0"#,
            r#"talos_module_payload_encryption_failures_total{op="encrypt",stage="input"} 0"#,
            r#"talos_module_payload_encryption_failures_total{op="encrypt",stage="output"} 0"#,
            r#"talos_module_payload_encryption_failures_total{op="encrypt",stage="trigger_metadata"} 0"#,
            r#"talos_module_payload_encryption_failures_total{op="decrypt",stage="input"} 0"#,
            r#"talos_module_payload_encryption_failures_total{op="decrypt",stage="output"} 0"#,
            r#"talos_module_payload_encryption_failures_total{op="decrypt",stage="trigger_metadata"} 0"#,
            // Worker-identity liveness + reaper. The steady state of every
            // one of these is 0 forever on a healthy fleet, which is exactly
            // the case where "absent" and "zero" diverge: the reap alert is
            // an `increase(...) > 0`, and an absent counter matches nothing.
            r#"talos_worker_liveness_pings_total{outcome="accepted"} 0"#,
            r#"talos_worker_liveness_pings_total{outcome="rejected_request"} 0"#,
            r#"talos_worker_liveness_pings_total{outcome="rejected_proof"} 0"#,
            r#"talos_worker_liveness_pings_total{outcome="inactive_identity"} 0"#,
            r#"talos_worker_liveness_pings_total{outcome="error"} 0"#,
            r#"talos_worker_identity_reaps_total{arm="departed"} 0"#,
            r#"talos_worker_identity_reaps_total{arm="pre_protocol"} 0"#,
            // Reactive OAuth repair. Same absent-is-not-zero reasoning: the
            // healthy steady state is that no arm ever moves, and the re-auth
            // alert is an `increase(...) > 0`.
            r#"talos_oauth_reactive_refresh_total{outcome="repaired"} 0"#,
            r#"talos_oauth_reactive_refresh_total{outcome="not_refreshed"} 0"#,
            r#"talos_oauth_reactive_refresh_total{outcome="refresh_failed"} 0"#,
            // The D2 pair. Plain IntGauges, so they are exported from
            // registration — asserted anyway because the alert subtracts one
            // from the other and a vector match against a missing series
            // silently yields NO RESULT, i.e. a detector that cannot fire.
            "talos_worker_liveness_participants 0",
            "talos_worker_liveness_recent_participants 0",
            // The detector-completeness flag. 0 = the participation pair
            // above describes the WHOLE reapable population; the reaper only
            // sweeps in that state.
            "talos_worker_liveness_population_truncated 0",
            // The NATS fleet-heartbeat view. Same reasoning one step further:
            // the state these sit in on a fleet that has never published a
            // heartbeat is precisely the state an operator most needs to be
            // able to distinguish from "the controller stopped publishing",
            // and `absent()` cannot tell them apart if the series never
            // existed.
            "talos_worker_fleet_live_workers 0",
            "talos_worker_fleet_live_builds 0",
            "talos_worker_fleet_build_skew_builds 0",
            "talos_worker_fleet_unverifiable_builds 0",
            "talos_worker_fleet_build_skew_workers 0",
            "talos_worker_fleet_unverifiable_workers 0",
            "talos_worker_fleet_capacity_dropped_heartbeats 0",
            "talos_worker_fleet_capacity_dropped_builds 0",
            // The fuel-headroom pair. The numerator's healthy steady state is
            // 0 forever, and it is read by a `>= 1` alert — absent would
            // match nothing. The DENOMINATOR is asserted for the opposite
            // reason: its alert fires on `== 0`, and an absent series makes
            // `== 0` match nothing too, so the meta-detector that catches a
            // dead sweep would itself be silenced by a dead sweep.
            "talos_fuel_high_utilisation_nodes 0",
            "talos_fuel_utilisation_observed_nodes 0",
            // The scheduler startup-herd detector. On a healthy fleet the
            // startup-phase series sit at 0 forever, and the alert on them is
            // built on `increase(...)` — so an absent series is a
            // detector that cannot fire on the very condition it exists to
            // catch. All fifteen are asserted, not just the alerted ones: an
            // operator comparing a backlog phase against steady needs both
            // halves to exist before either number means anything, and the
            // herd alert's ratio arm divides by the sum over ALL outcomes — an
            // absent denominator term makes the ratio silently wrong rather
            // than absent. The `catchup` five matter most: on a fleet that
            // never suspends they sit at 0 forever, which is exactly the
            // series an unseeded registry would omit.
            r#"talos_scheduler_dispatches_total{outcome="completed",phase="startup"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="failed",phase="startup"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="skipped",phase="startup"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="denied",phase="startup"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="fenced",phase="startup"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="completed",phase="catchup"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="failed",phase="catchup"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="skipped",phase="catchup"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="denied",phase="catchup"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="fenced",phase="catchup"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="completed",phase="steady"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="failed",phase="steady"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="skipped",phase="steady"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="denied",phase="steady"} 0"#,
            r#"talos_scheduler_dispatches_total{outcome="fenced",phase="steady"} 0"#,
            "talos_scheduler_readiness_holds_total 0",
            "talos_scheduler_readiness_degraded 0",
        ] {
            assert!(
                rendered.contains(expected),
                "cold registry must EXPORT `{expected}` — an absent series is \
                 not a zero one, and every alert built on these reads absence \
                 as 'no match'\n--- output ---\n{rendered}"
            );
        }

        // The two deliberate non-seeds, asserted so a later "tidy-up" that
        // seeds them has to argue with a test rather than slip through.
        assert!(
            !rendered.contains("talos_auth_failures_total{"),
            "talos_auth_failures_total is deliberately unseeded: only 9 of its \
             16 (method, reason) pairs have an emitter, and seeding a pair \
             nothing writes implies a signal that does not exist\n{rendered}"
        );
        assert!(
            !rendered.contains(r#"provider="legacy""#),
            "provider=\"legacy\" has no emitting site anywhere in the \
             workspace; a flat 0 there would read as 'watched' when it is \
             not\n{rendered}"
        );
    }

    // Crash-recovery outcome counter (durable execution, RFC 0003) must be
    // registered, pre-seeded at 0 for all three outcomes (so dashboards/alerts
    // have a series in steady state), and increment correctly. A regression
    // here means the crash-recovery observability surface silently disappears.
    #[test]
    fn crash_recovery_metric_seeded_and_increments() {
        let m = TalosMetrics::new().unwrap();

        // Pre-seeded at 0 from new() — present before any recovery runs.
        let rendered = m.render_prometheus().expect("render");
        for outcome in ["resumed", "failed", "reclaimed"] {
            assert!(
                rendered.contains(&format!(
                    "talos_crash_recovery_total{{outcome=\"{outcome}\"}} 0"
                )),
                "crash_recovery_total[{outcome}] not pre-seeded at 0\n{rendered}"
            );
        }

        // Increment behaves: counts accumulate per outcome label.
        m.crash_recovery_total.with_label_values(&["resumed"]).inc();
        m.crash_recovery_total
            .with_label_values(&["reclaimed"])
            .inc_by(3.0);
        let rendered = m.render_prometheus().expect("render");
        assert!(rendered.contains(r#"talos_crash_recovery_total{outcome="resumed"} 1"#));
        assert!(rendered.contains(r#"talos_crash_recovery_total{outcome="reclaimed"} 3"#));
        assert!(rendered.contains(r#"talos_crash_recovery_total{outcome="failed"} 0"#));
    }

    // workflow_executions_total must be pre-seeded at 0 for success+failure
    // (so the TalosWorkflowFailureRateHigh alert's rate() has a series in
    // steady state) and increment per status label. Before this wiring the
    // counter was registered but never incremented — a dead metric that made
    // any alert on it silently un-fireable.
    #[test]
    fn workflow_executions_metric_seeded_and_increments() {
        let m = TalosMetrics::new().unwrap();
        let rendered = m.render_prometheus().expect("render");
        for status in ["success", "failure"] {
            assert!(
                rendered.contains(&format!(
                    "talos_workflow_executions_total{{status=\"{status}\"}} 0"
                )),
                "workflow_executions_total[{status}] not pre-seeded at 0\n{rendered}"
            );
        }
        m.workflow_executions_total
            .with_label_values(&["failure"])
            .inc();
        m.workflow_executions_total
            .with_label_values(&["success"])
            .inc_by(3.0);
        let rendered = m.render_prometheus().expect("render");
        assert!(rendered.contains(r#"talos_workflow_executions_total{status="failure"} 1"#));
        assert!(rendered.contains(r#"talos_workflow_executions_total{status="success"} 3"#));
    }

    // record_workflow_outcome is inert (no panic) when metrics aren't wired —
    // the finalizers call it unconditionally, and unit tests / any process
    // without set_global must not blow up.
    #[test]
    fn record_workflow_outcome_is_inert_without_global() {
        // Does not panic even though set_global may not have run in this test
        // binary. (If a sibling test already set the global, this still just
        // increments harmlessly.)
        super::record_workflow_outcome("failure", None);
        super::record_workflow_outcome("success", Some(1.5));
    }

    // set_global / global round-trip. One-shot semantics: subsequent
    // sets are no-ops (and crucially must not panic).
    #[test]
    fn global_metrics_oncelock_round_trip() {
        // If another test already initialised the global, the value will
        // reflect that — this test is side-effect-tolerant. We care that
        // global() returns Some AFTER set_global.
        let m = TalosMetrics::new().unwrap();
        set_global(m.clone());
        let fetched = global().expect("global registry installed");
        // Increment via global; verify via the local Arc.
        fetched.dek_cache_size.set(7);
        // Both references share the same underlying prometheus collectors.
        assert_eq!(m.dek_cache_size.get(), 7);
    }
}
