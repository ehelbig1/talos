//! Self-monitoring bridge — Talos's own execution failures as ops
//! alerts (`source = "talos"`).
//!
//! The weekly assistant report made a week of silent scheduled
//! failures visible only retroactively (83 failures discovered days
//! late, 2026-07-20). This module closes that loop: when an UNATTENDED
//! execution finalizes `failed`, a deduped alert flows through the same
//! [`crate::OpsAlertRepository::ingest`] path external sources use —
//! so dedup-bump, reopen-on-regression, severity corrections, digest
//! ranking, and the correction-training moat all apply to the
//! platform's own health for free. When a later unattended run of the
//! same workflow completes, every active `talos/`-alert for that
//! workflow auto-resolves (`resolved_source = 'signal'`); a recurrence
//! then REOPENS the row — exactly the regression signal the store
//! already models.
//!
//! # Why a cursor reconciler, not finalizer hooks
//!
//! Terminal `workflow_executions.status` writes happen in 8 repository
//! helpers plus ~7 inline UPDATEs (scheduler ×3, stale sweep, webhook
//! router ×3, crash recovery…), and the existing caller-side
//! failure-notify precedent (`publish_execution_failure_alert`)
//! already rotted by missing the scheduler arms entirely — the exact
//! unattended paths that matter most. Instead of wiring (and forever
//! re-wiring) N call sites, a background tick scans
//! `(completed_at, id) > cursor` over terminal rows: every finalizer
//! is captured by construction, including ones that don't exist yet.
//!
//! Cursor correctness: `completed_at` is stamped exactly once by every
//! terminal writer (25/25 sites audited 2026-07-20) and never bumped
//! again — unlike `updated_at`, which the table's BEFORE UPDATE
//! trigger bumps on pin/acknowledge of already-terminal rows and would
//! re-enter processed executions into the window (double
//! occurrence-bumps). Rows are processed in `(completed_at, id)` order
//! so a fail→success sequence lands as ingest→resolve, and the cursor
//! is a `(timestamp, id)` pair compared as a row value, so same-moment
//! finalizations split across batches are never skipped.
//!
//! # Concurrency, idempotency, failure isolation
//!
//! Each tick takes the cursor row `FOR UPDATE SKIP LOCKED` inside one
//! transaction and commits the advanced cursor only after the batch is
//! processed — a second controller instance skips the tick instead of
//! double-processing, and a crash mid-batch rolls the cursor back
//! (at-least-once; the only artifact of a replay is a benign extra
//! occurrence-bump on already-open alerts). Per-row alert writes go
//! through the pool so one bad row can't poison the cursor
//! transaction; row-level errors are logged + counted, never fatal to
//! the tick.
//!
//! # Scope rules (all enforced by the tick's WHERE clause)
//!
//! * **Unattended only** — `provenance->>'trigger_type'` ∈
//!   {`scheduled`, `webhook`, `actor_dispatch`, `agent_dispatch`}.
//!   Manual / MCP / replay / retry runs have a human watching them;
//!   alerting those is noise.
//! * **Root executions only** (`parent_execution_id IS NULL`) — a
//!   sub-workflow failure surfaces through its parent.
//! * **Never test executions** (`is_test_execution`).
//!
//! Security posture: tenancy comes from `workflow_executions.user_id`
//! / `org_id` — the identity the execution row was created under, not
//! caller input. Free text (error excerpt, workflow name) is
//! DLP-redacted before persistence (error_message is already redacted
//! by the finalizers; this is defense in depth) and bounded by the
//! repository's char-truncation. Kill switch:
//! `TALOS_SELF_ALERTS=0|false|off`.

use sqlx::{Pool, Postgres, Row};
use uuid::Uuid;

use crate::{NewOpsAlert, OpsAlertRepository};

/// `ops_alerts.source` value for platform-emitted alerts. Also the
/// dedup-key namespace prefix — see [`workflow_dedup_prefix`].
pub const SELF_ALERT_SOURCE: &str = "talos";

/// Reserved dedup-key namespace. The `__ops_alert__` envelope boundary
/// ([`crate::envelope::classify_entry`]) refuses module-emitted entries
/// under this prefix (or claiming [`SELF_ALERT_SOURCE`]) so sandboxed
/// code can never bump, retitle, or resolve self-monitoring rows.
pub const RESERVED_DEDUP_PREFIX: &str = "talos/";

/// Trigger types considered unattended (nobody is watching a terminal
/// or editor when these fail). `agent_dispatch` is the legacy alias of
/// `actor_dispatch`; `api` is a caller script, not a human at a
/// keyboard. A cross-crate test below pins this list against
/// `talos_workflow_authorization::VALID_TRIGGER_TYPES` so a new
/// trigger type cannot land silently unmonitored (review 2026-07-20 —
/// the original list omitted `api`, replaying the exact vocabulary-rot
/// mode this module's own design doc criticizes).
const UNATTENDED_TRIGGER_TYPES: [&str; 5] = [
    "scheduled",
    "webhook",
    "actor_dispatch",
    "agent_dispatch",
    "api",
];

/// The complement: trigger types where a human IS watching (manual /
/// MCP runs). Together with [`UNATTENDED_TRIGGER_TYPES`] this must
/// cover the full ingress vocabulary — enforced by test.
#[cfg(test)]
const ATTENDED_TRIGGER_TYPES: [&str; 1] = ["manual"];

/// Max terminal rows drained per tick (multiple batches per tick until
/// dry). Bounds transaction size, not throughput.
const TICK_BATCH_LIMIT: i64 = 200;

/// Safety valve on batches per tick so a pathological backlog can't
/// pin a controller task forever; the remainder drains next tick.
const MAX_BATCHES_PER_TICK: usize = 20;

/// Cap on the redacted error excerpt stored in `raw` (chars — the
/// repository bounds the whole `raw` payload separately).
const MAX_ERROR_EXCERPT_CHARS: usize = 2000;

/// Only process rows finalized at least this long ago. `completed_at`
/// is stamped `NOW()` INSIDE the finalizer's transaction; one that
/// commits after our snapshot would otherwise carry a timestamp the
/// cursor already passed (classic timestamp-watermark read skew).
/// Finalizer transactions live milliseconds — 30 s is a deep margin,
/// and worst-case alert latency is lag + one interval.
const CURSOR_SAFETY_LAG_SECS: f64 = 30.0;

/// Default seconds between reconciler ticks.
pub const DEFAULT_TICK_INTERVAL_SECS: u64 = 60;

/// Stable classification of an execution error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorClass {
    /// Stable dedup-key segment (`[a-z0-9_]`, never changes for a
    /// given failure mode — occurrence counts depend on it).
    pub class: &'static str,
    /// Human label for titles.
    pub label: &'static str,
    /// Initial severity for NEWLY created rows (repository semantics:
    /// ignored on dedup-bump, never overwrites corrections).
    pub severity_hint: &'static str,
}

/// Classify an execution error message into a stable class.
///
/// Deterministic failure modes that need an operator (config, fuel,
/// contract, egress policy, signature) hint `high`; auth and backend
/// wobbles hint `medium`; known-transient classes hint `low`.
/// Corrections refine from there — hints only seed NEW rows.
#[must_use]
pub fn classify_execution_error(msg: &str) -> ErrorClass {
    // Cap before lowercasing (the MCP-1135 class: error strings can
    // embed large quoted response bodies; finalizers truncate, but this
    // layer should not trust that). 4 KiB matches the retry
    // classifier's cap.
    let m: String = msg.chars().take(4096).collect::<String>().to_lowercase();
    let has = |needle: &str| m.contains(needle);

    if has("approval was denied") || has("approval denied") {
        // FIRST branch, deliberately: a human rejecting a
        // confidence-gate / approval pause fails the execution with the
        // gate's stable "… approval was denied" reason
        // (`PostgresApprovalGate` / the Human_Approval_Gate node). That
        // reason can be wrapped by a finalizer prefix and can carry a
        // node UUID whose digits could otherwise trip the `401` auth
        // branch, so this unambiguous phrase is matched before anything
        // else. The class is NON-ALERTING (see `NON_ALERTING_CLASSES`):
        // a legitimate "no" is the system working as designed, not a
        // fault to page on.
        ErrorClass {
            class: "approval_denied",
            label: "human approval denied",
            severity_hint: "low",
        }
    } else if has("fuel exhausted") {
        ErrorClass {
            class: "fuel_exhausted",
            label: "WASM fuel exhausted",
            severity_hint: "high",
        }
    } else if has("missing") && has("config") {
        ErrorClass {
            class: "missing_config",
            label: "missing node config",
            severity_hint: "high",
        }
    } else if has("forbiddenhost") {
        ErrorClass {
            class: "egress_denied",
            label: "HTTP egress denied (host not allowed)",
            severity_hint: "high",
        }
    } else if has("signature verification failed") {
        ErrorClass {
            class: "signature",
            label: "signature verification failed",
            severity_hint: "high",
        }
    } else if has("no upstream") {
        ErrorClass {
            class: "contract",
            label: "inter-node contract violation",
            severity_hint: "high",
        }
    } else if has("timed out") || has("timeout") {
        // BEFORE the auth branch: a timeout message can contain an
        // incidental "401" digit run ("timed out after 40100 ms"),
        // and class is a dedup-key segment — a misclass forks
        // occurrence history (review 2026-07-20).
        ErrorClass {
            class: "timeout",
            label: "execution timeout",
            severity_hint: "medium",
        }
    } else if has("401") || has("access_token invalid") || has("unauthorized") {
        ErrorClass {
            class: "auth",
            label: "upstream auth failure",
            severity_hint: "medium",
        }
    } else if has("networkerror") {
        ErrorClass {
            class: "network",
            label: "transient network error",
            severity_hint: "low",
        }
    } else if has("llm") || has("model served nothing") {
        ErrorClass {
            class: "llm",
            label: "LLM backend failure",
            severity_hint: "medium",
        }
    } else if has("execution stale") {
        ErrorClass {
            class: "stale",
            label: "execution stale (auto-cleaned)",
            severity_hint: "low",
        }
    } else {
        ErrorClass {
            class: "other",
            label: "unclassified failure",
            severity_hint: "medium",
        }
    }
}

/// Error classes that represent an EXPECTED, human-driven terminal
/// outcome rather than a platform fault — never surfaced as an ops
/// alert. This is the error-class analogue of the attended-trigger skip
/// in [`reconcile_tick`]: the run technically finalized `failed`, but
/// nobody should be paged.
///
/// Currently one member — `approval_denied` (a human clicking "reject"
/// on a confidence-gate / approval pause). Kept as a list (mirroring
/// `UNATTENDED_TRIGGER_TYPES`) so future expected outcomes are a
/// one-line, self-documenting addition.
const NON_ALERTING_CLASSES: [&str; 1] = ["approval_denied"];

impl ErrorClass {
    /// Whether a failure of this class should raise an ops alert.
    /// `false` for expected human-driven outcomes (see
    /// [`NON_ALERTING_CLASSES`]).
    #[must_use]
    pub fn is_alerting(&self) -> bool {
        !NON_ALERTING_CLASSES.contains(&self.class)
    }
}

/// Extract the failing node id from the engine's standard error shape
/// (`… node 'NAME' failed …`). Bounded to the repository's key-segment
/// budget; returns `None` for workflow-level failures.
#[must_use]
pub fn extract_failed_node(msg: &str) -> Option<String> {
    let start = msg.find("node '")? + "node '".len();
    let rest = &msg[start..];
    let end = rest.find('\'')?;
    let node: String = rest[..end].chars().take(100).collect();
    if node.is_empty() {
        None
    } else {
        Some(node)
    }
}

/// FNV-1a 64 over a digit-collapsed, lowercased prefix of the message —
/// disambiguates `other` classes so distinct unknown failure modes
/// don't merge into one occurrence-bumping row. No crypto claim needed
/// (dedup bucketing only), so a tiny inline hash beats a sha2 dep.
#[must_use]
fn normalized_fingerprint(msg: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut prev_digit = false;
    for c in msg.chars().take(200) {
        let c = if c.is_ascii_digit() {
            if prev_digit {
                continue; // collapse digit runs: "after 1380000" == "after 42"
            }
            prev_digit = true;
            '#'
        } else {
            prev_digit = false;
            c.to_ascii_lowercase()
        };
        let mut buf = [0u8; 4];
        for b in c.encode_utf8(&mut buf).bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    h
}

/// Dedup-key namespace for one workflow's self-alerts. Success-side
/// auto-resolve matches on this prefix.
#[must_use]
pub fn workflow_dedup_prefix(workflow_id: Uuid) -> String {
    format!("talos/{workflow_id}/")
}

/// Full dedup key for a failure: `talos/{workflow}/{node|-}/{class}`,
/// with an `other` fingerprint suffix so unrelated unknown errors keep
/// separate occurrence counts.
#[must_use]
pub fn failure_dedup_key(workflow_id: Uuid, node: Option<&str>, error_message: &str) -> String {
    let ec = classify_execution_error(error_message);
    let class_seg = if ec.class == "other" {
        format!("other_{:016x}", normalized_fingerprint(error_message))
    } else {
        ec.class.to_string()
    };
    format!(
        "{}{}/{}",
        workflow_dedup_prefix(workflow_id),
        node.unwrap_or("-"),
        class_seg
    )
}

/// Bridge kill switch — enabled unless `TALOS_SELF_ALERTS` is
/// explicitly `0` / `false` / `off` (any case). Read once per process.
#[must_use]
pub fn self_alerts_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        !matches!(
            std::env::var("TALOS_SELF_ALERTS")
                .ok()
                .map(|v| v.trim().to_ascii_lowercase())
                .as_deref(),
            Some("0" | "false" | "off")
        )
    })
}

/// Outcome counters for one reconciler tick (log/metric fodder).
#[derive(Debug, Default, Clone, Copy)]
pub struct TickStats {
    pub scanned: u64,
    pub ingested: u64,
    /// Failed rows deliberately NOT alerted because their error class is
    /// an expected human-driven outcome (see [`NON_ALERTING_CLASSES`]) —
    /// e.g. a rejected approval gate. Cursor still advances past them.
    pub skipped_expected: u64,
    pub resolved_alerts: u64,
    pub row_errors: u64,
    /// Another instance held the cursor — tick skipped.
    pub skipped_lock: bool,
}

/// Run one reconciler tick: drain terminal executions past the cursor,
/// ingest failures / resolve on successes, advance the cursor.
///
/// Never returns Err for per-row problems — only for cursor-level
/// failures (the caller logs and retries next interval).
pub async fn reconcile_tick(pool: &Pool<Postgres>) -> anyhow::Result<TickStats> {
    let mut stats = TickStats::default();
    let repo = OpsAlertRepository::new(pool.clone());

    for _ in 0..MAX_BATCHES_PER_TICK {
        let mut tx = pool.begin().await?;

        // Single-instance guard: whoever holds the row runs the tick;
        // everyone else skips (SKIP LOCKED, no waiting).
        let Some(cursor) = sqlx::query(
            "SELECT cursor_completed_at, cursor_execution_id \
             FROM ops_alerts_self_monitor_cursor \
             WHERE singleton FOR UPDATE SKIP LOCKED",
        )
        .fetch_optional(&mut *tx)
        .await?
        else {
            // SKIP LOCKED returns None for BOTH contention and a
            // missing seed row — and a missing row would otherwise
            // disable the bridge silently forever (the exact failure
            // class this module exists to close). A plain MVCC read
            // distinguishes them: it sees a locked row just fine.
            let row_exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM ops_alerts_self_monitor_cursor WHERE singleton)",
            )
            .fetch_one(&mut *tx)
            .await?;
            if row_exists {
                stats.skipped_lock = true;
                tracing::debug!(
                    target: "talos_self_alerts",
                    "cursor held by another instance — tick skipped"
                );
            } else {
                tracing::error!(
                    target: "talos_self_alerts",
                    "self-monitor cursor row MISSING — re-seeding at NOW() \
                     (no backfill; the bridge was inert until this tick)"
                );
                sqlx::query(
                    "INSERT INTO ops_alerts_self_monitor_cursor (singleton, cursor_completed_at) \
                     VALUES (true, NOW()) ON CONFLICT (singleton) DO NOTHING",
                )
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
            }
            return Ok(stats);
        };
        let cur_ts: chrono::DateTime<chrono::Utc> = cursor.try_get("cursor_completed_at")?;
        let cur_id: Uuid = cursor.try_get("cursor_execution_id")?;

        // Row-value comparison keeps same-timestamp finalizations safe
        // across batch boundaries. The trigger-type filter is the
        // unattended-only scope rule; identity/name come off the row +
        // one join (workflow name is display-only).
        let rows = sqlx::query(
            "SELECT e.id, e.completed_at, e.status, e.user_id, e.org_id, \
                    e.workflow_id, e.error_message, \
                    e.provenance->>'trigger_type' AS trigger_type, \
                    w.name AS workflow_name \
             FROM workflow_executions e \
             LEFT JOIN workflows w ON w.id = e.workflow_id \
             WHERE e.status IN ('completed','failed') \
               AND e.completed_at IS NOT NULL \
               AND (e.completed_at, e.id) > ($1, $2) \
               AND e.completed_at < NOW() - make_interval(secs => $5) \
               AND e.is_test_execution = false \
               AND e.parent_execution_id IS NULL \
               AND e.provenance->>'trigger_type' = ANY($3) \
             ORDER BY e.completed_at ASC, e.id ASC \
             LIMIT $4",
        )
        .bind(cur_ts)
        .bind(cur_id)
        .bind(&UNATTENDED_TRIGGER_TYPES[..])
        .bind(TICK_BATCH_LIMIT)
        .bind(CURSOR_SAFETY_LAG_SECS)
        .fetch_all(&mut *tx)
        .await?;

        if rows.is_empty() {
            // Advance the cursor past ineligible terminal rows too, so
            // the range scan doesn't re-walk them forever: jump to the
            // newest terminal completed_at when nothing eligible is
            // ahead of the cursor. (Safe: eligibility is row-immutable.)
            let max_terminal: Option<(chrono::DateTime<chrono::Utc>, Uuid)> = sqlx::query_as(
                "SELECT completed_at, id FROM workflow_executions \
                 WHERE status IN ('completed','failed') AND completed_at IS NOT NULL \
                   AND completed_at < NOW() - make_interval(secs => $1) \
                 ORDER BY completed_at DESC, id DESC LIMIT 1",
            )
            .bind(CURSOR_SAFETY_LAG_SECS)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some((ts, id)) = max_terminal {
                if (ts, id) > (cur_ts, cur_id) {
                    sqlx::query(
                        "UPDATE ops_alerts_self_monitor_cursor \
                         SET cursor_completed_at = $1, cursor_execution_id = $2, \
                             updated_at = NOW() \
                         WHERE singleton",
                    )
                    .bind(ts)
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
                    tx.commit().await?;
                    // No re-loop: max_terminal is the newest terminal
                    // row inside the lag horizon and the batch query
                    // just proved nothing eligible exists at or below
                    // it — the next iteration would provably find
                    // nothing (review 2026-07-20: the `continue` here
                    // doubled every quiet tick's transactions).
                }
            }
            return Ok(stats); // fully drained
        }

        let batch_len = rows.len();
        let mut last: Option<(chrono::DateTime<chrono::Utc>, Uuid)> = None;
        // Successes are the overwhelmingly common case — collect their
        // (user, workflow) pairs and resolve in ONE batched UPDATE
        // after the loop instead of one round-trip per green row (the
        // N+1 the review flagged). Failures stay per-row: each does
        // multi-statement work and needs individual error isolation.
        let mut green: Vec<(Uuid, Uuid)> = Vec::new();
        let mut green_seen: std::collections::HashSet<(Uuid, Uuid)> =
            std::collections::HashSet::new();
        for row in rows {
            stats.scanned += 1;
            let exec_id: Uuid = row.try_get("id")?;
            let ts: chrono::DateTime<chrono::Utc> = row.try_get("completed_at")?;
            last = Some((ts, exec_id));
            let status: String = row.try_get("status")?;
            if status == "completed" {
                let pair = (row.try_get("user_id")?, row.try_get("workflow_id")?);
                if green_seen.insert(pair) {
                    green.push(pair);
                }
                continue;
            }
            // A human rejecting an approval/confidence gate finalizes the
            // run `failed`, but it's an EXPECTED outcome — skip it the
            // same way an attended trigger type is skipped, so a
            // legitimate "no" never pages. `last` is already set above,
            // so the cursor advances past this row and it's never
            // revisited. (`error_message` is read again inside
            // `process_failed_row`; the double read keeps that helper
            // self-contained and the rows are already in memory.)
            let err_for_class: Option<String> = row.try_get("error_message")?;
            if let Some(ref m) = err_for_class {
                if !classify_execution_error(m).is_alerting() {
                    stats.skipped_expected += 1;
                    tracing::info!(
                        target: "talos_self_alerts",
                        execution_id = %exec_id,
                        error_class = classify_execution_error(m).class,
                        "self-monitor: expected human-driven outcome — not alerting"
                    );
                    continue;
                }
            }
            match process_failed_row(&repo, &row, exec_id).await {
                Ok(()) => stats.ingested += 1,
                Err(e) => {
                    stats.row_errors += 1;
                    bump_failure_metric("db");
                    tracing::warn!(
                        target: "talos_self_alerts",
                        execution_id = %exec_id,
                        error = %e,
                        "self-monitor: row processing failed — continuing (row is \
                         past the cursor and will not retry; occurrence data only)"
                    );
                }
            }
        }
        match repo.resolve_self_alerts_for_workflows(&green).await {
            Ok(0) => {}
            Ok(n) => {
                stats.resolved_alerts += n;
                if let Some(m) = talos_metrics::global() {
                    m.ops_alert_auto_resolved_total.inc();
                }
                tracing::info!(
                    target: "talos_self_alerts",
                    resolved = n,
                    workflows = green.len(),
                    "self-alerts auto-resolved by successful unattended runs"
                );
            }
            Err(e) => {
                stats.row_errors += 1;
                bump_failure_metric("db");
                tracing::warn!(
                    target: "talos_self_alerts",
                    error = %e,
                    "self-monitor: batched auto-resolve failed — continuing"
                );
            }
        }

        let (ts, id) = last.expect("non-empty batch has a last row");
        sqlx::query(
            "UPDATE ops_alerts_self_monitor_cursor \
             SET cursor_completed_at = $1, cursor_execution_id = $2, updated_at = NOW() \
             WHERE singleton",
        )
        .bind(ts)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        if (batch_len as i64) < TICK_BATCH_LIMIT {
            break; // drained
        }
    }
    Ok(stats)
}

/// Ingest one FAILED execution row as an ops alert (the tick's success
/// rows resolve in a single batched UPDATE — see the tick loop).
async fn process_failed_row(
    repo: &OpsAlertRepository,
    row: &sqlx::postgres::PgRow,
    execution_id: Uuid,
) -> anyhow::Result<()> {
    let user_id: Uuid = row.try_get("user_id")?;
    let org_id: Option<Uuid> = row.try_get("org_id")?;
    let workflow_id: Uuid = row.try_get("workflow_id")?;
    // LEFT-joined: a workflow deleted right after its last failure must
    // still alert (review 2026-07-20 — the INNER JOIN silently swallowed
    // those rows and the cursor jumped past them).
    let workflow_name: String = row
        .try_get::<Option<String>, _>("workflow_name")?
        .unwrap_or_else(|| "(deleted workflow)".to_string());

    let error_message: Option<String> = row.try_get("error_message")?;
    let error_message = error_message.unwrap_or_else(|| "unknown failure".to_string());
    let trigger_type: Option<String> = row.try_get("trigger_type")?;
    let ec = classify_execution_error(&error_message);
    let node = extract_failed_node(&error_message);

    // DLP-redact all free text BEFORE persistence — the finalizers
    // already redact error_message, this is defense in depth (and the
    // workflow name has never passed through DLP).
    let name_red = talos_dlp_provider::redact_str(&workflow_name);
    let excerpt: String = error_message
        .chars()
        .take(MAX_ERROR_EXCERPT_CHARS)
        .collect();
    let excerpt_red = talos_dlp_provider::redact_str(&excerpt);

    let node_red = node.as_deref().map(talos_dlp_provider::redact_str);
    let title = match &node_red {
        Some(n) => format!("workflow '{name_red}' failed: {} (node '{n}')", ec.label),
        None => format!("workflow '{name_red}' failed: {}", ec.label),
    };

    let alert = NewOpsAlert {
        source: SELF_ALERT_SOURCE.to_string(),
        external_id: Some(execution_id.to_string()),
        dedup_key: failure_dedup_key(workflow_id, node.as_deref(), &error_message),
        title,
        resource: Some(name_red),
        severity_raw: Some(ec.class.to_string()),
        severity_hint: Some(ec.severity_hint.to_string()),
        raw: Some(serde_json::json!({
            "execution_id": execution_id,
            "workflow_id": workflow_id,
            "node": node,
            "error_class": ec.class,
            "trigger_type": trigger_type,
            "error_message": excerpt_red,
        })),
    };
    let outcome = repo.ingest(user_id, org_id, alert).await?;
    tracing::info!(
        target: "talos_self_alerts",
        %workflow_id,
        error_class = ec.class,
        ?outcome,
        "execution failure ingested as ops alert"
    );
    Ok(())
}

/// One loggable tick invocation for callers that own the interval loop
/// (the controller spawns this on the same shutdown-aware pattern as
/// its cache sweeps). Never propagates errors — logs + counts them.
pub async fn tick_and_log(pool: &Pool<Postgres>) {
    match reconcile_tick(pool).await {
        Ok(s) if s.scanned > 0 || s.row_errors > 0 => {
            tracing::info!(
                target: "talos_self_alerts",
                scanned = s.scanned,
                ingested = s.ingested,
                skipped_expected = s.skipped_expected,
                resolved = s.resolved_alerts,
                row_errors = s.row_errors,
                "self-monitor tick"
            );
        }
        Ok(_) => {}
        Err(e) => {
            bump_failure_metric("db");
            tracing::warn!(
                target: "talos_self_alerts",
                error = %e,
                "self-monitor tick failed — will retry next interval"
            );
        }
    }
}

fn bump_failure_metric(reason: &'static str) {
    if let Some(m) = talos_metrics::global() {
        m.ops_alert_ingest_failures_total
            .with_label_values(&[reason])
            .inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_the_observed_corpus() {
        // Real messages from the 2026-07 failure post-mortem.
        let cases = [
            (
                "Scheduled workflow failed: workflow execution failed: node 'compose' failed: \
                 Job failed after 1 attempts: execution failure: WASM fuel exhausted after \
                 1380000 instructions.",
                "fuel_exhausted",
                "high",
            ),
            (
                "Execution failed: {\"error\":\"execution failure: Component returned error: \
                 Missing AUTH_HEADER config\"}",
                "missing_config",
                "high",
            ),
            (
                "node 'gmail' failed: Component returned error: Gmail 401: access_token \
                 invalid or expired.",
                "auth",
                "medium",
            ),
            (
                "node 'gmail_work' failed: Component returned error: list fetch: \
                 Error { code: 2, name: \"networkerror\", message: \"\" }",
                "network",
                "low",
            ),
            (
                "node 'mint_smoke' failed: Component returned error: fetch: \
                 Error { code: 3, name: \"forbiddenhost\", message: \"\" }",
                "egress_denied",
                "high",
            ),
            (
                "node 'classify_work' failed: Job failed after 1 attempts: execution timed \
                 out after 30 seconds",
                "timeout",
                "medium",
            ),
            (
                "node 'organize' failed: Component returned error: no upstream \
                 classifications; input keys = []",
                "contract",
                "high",
            ),
            (
                "node 'gmail' failed: Job failed after 1 attempts: signature verification failed",
                "signature",
                "high",
            ),
            (
                "node 'classify' failed: Component returned error: LLM classify failed and \
                 model served nothing",
                "llm",
                "medium",
            ),
            (
                "Auto-cleaned: execution stale (running > configured threshold)",
                "stale",
                "low",
            ),
            // Human rejected a confidence-gate / approval pause. The
            // engine-wrapped form the resume finalizer produces.
            (
                "approval-resume: resume dispatch failed: workflow execution failed: \
                 node 'gate' failed: Execution denied: module \
                 40111111-2222-3333-4444-555555555555 approval was denied",
                "approval_denied",
                "low",
            ),
            ("something entirely novel exploded", "other", "medium"),
        ];
        for (msg, class, sev) in cases {
            let ec = classify_execution_error(msg);
            assert_eq!(ec.class, class, "message: {msg}");
            assert_eq!(ec.severity_hint, sev, "message: {msg}");
        }
    }

    #[test]
    fn approval_denial_is_recognized_and_non_alerting() {
        // The gate's stable phrasing, and the wrapped form.
        for msg in [
            "Execution denied: module 6f1a approval was denied",
            "node 'gate' failed: Execution denied: module x approval was denied",
            "APPROVAL DENIED by reviewer",
        ] {
            let ec = classify_execution_error(msg);
            assert_eq!(ec.class, "approval_denied", "message: {msg}");
            assert!(!ec.is_alerting(), "denial must not alert: {msg}");
        }

        // The denial branch wins even when the (UUID) node id embeds a
        // digit run that would otherwise trip the `401` auth branch.
        let with_401 = "node 'gate' failed: Execution denied: module 401abc approval was denied";
        assert_eq!(classify_execution_error(with_401).class, "approval_denied");
    }

    #[test]
    fn genuine_faults_still_alert() {
        // Every non-expected class must keep alerting — the skip is
        // scoped to human-driven outcomes only.
        for msg in [
            "WASM fuel exhausted after 42 instructions",
            "Missing AUTH_HEADER config",
            "signature verification failed",
            "something entirely novel exploded",
        ] {
            assert!(
                classify_execution_error(msg).is_alerting(),
                "fault must alert: {msg}"
            );
        }
    }

    #[test]
    fn non_alerting_classes_are_a_subset_of_known_classes() {
        // Guard against a typo drifting NON_ALERTING_CLASSES away from a
        // class classify_execution_error can actually emit — otherwise
        // the skip would silently never fire.
        let known = [
            "approval_denied",
            "fuel_exhausted",
            "missing_config",
            "egress_denied",
            "signature",
            "contract",
            "timeout",
            "auth",
            "network",
            "llm",
            "stale",
            "other",
        ];
        for c in NON_ALERTING_CLASSES {
            assert!(
                known.contains(&c),
                "NON_ALERTING_CLASSES member '{c}' is not a class classify_execution_error emits"
            );
        }
    }

    #[test]
    fn node_extraction_handles_shapes() {
        assert_eq!(
            extract_failed_node("workflow execution failed: node 'gmail_work' failed: x"),
            Some("gmail_work".to_string())
        );
        assert_eq!(extract_failed_node("Auto-cleaned: execution stale"), None);
        assert_eq!(extract_failed_node("node '' failed"), None);
        // Unterminated quote — must not panic.
        assert_eq!(extract_failed_node("node 'unterminated"), None);
    }

    #[test]
    fn dedup_keys_are_stable_across_volatile_details() {
        let wf = Uuid::nil();
        // Same class, different fuel numbers → same key.
        let a = failure_dedup_key(wf, Some("compose"), "WASM fuel exhausted after 1380000");
        let b = failure_dedup_key(wf, Some("compose"), "WASM fuel exhausted after 8000000");
        assert_eq!(a, b);
        assert_eq!(a, format!("talos/{wf}/compose/fuel_exhausted"));

        // `other` fingerprint collapses digit runs but separates
        // genuinely different messages.
        let c = failure_dedup_key(wf, None, "weird failure at offset 17");
        let d = failure_dedup_key(wf, None, "weird failure at offset 9912");
        let e = failure_dedup_key(wf, None, "a totally different weird failure");
        assert_eq!(c, d);
        assert_ne!(c, e);
        assert!(c.starts_with(&format!("talos/{wf}/-/other_")));
    }

    #[test]
    fn trigger_vocabulary_is_fully_classified() {
        // Every ingress trigger type must be explicitly attended or
        // unattended — a new type landing in the vocabulary without a
        // decision here is exactly how the caller-side failure-notify
        // precedent rotted. Fails compilation-adjacent (this test) the
        // moment VALID_TRIGGER_TYPES grows.
        for t in talos_workflow_authorization::VALID_TRIGGER_TYPES {
            assert!(
                UNATTENDED_TRIGGER_TYPES.contains(t) || ATTENDED_TRIGGER_TYPES.contains(t),
                "trigger type '{t}' is not classified attended/unattended in self_monitor — \
                 decide whether the bridge should monitor it"
            );
        }
    }

    #[test]
    fn prefix_matches_all_keys_for_workflow() {
        let wf = Uuid::nil();
        let key = failure_dedup_key(wf, Some("send"), "networkerror");
        assert!(key.starts_with(&workflow_dedup_prefix(wf)));
    }
}
