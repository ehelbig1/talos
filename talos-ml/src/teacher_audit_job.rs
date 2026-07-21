//! RFC 0011 R3 — the scheduled teacher-audit cadence.
//!
//! A bounded background job (same integration_state-sweeper shape as
//! [`crate::lifecycle_job`] / [`crate::digest`]: interval +
//! `MissedTickBehavior::Delay` + `select!`-on-shutdown) that keeps every
//! correction-bearing model's teacher-vs-gold ceiling FRESH without a
//! human running `ml_teacher_audit` by hand — so the weekly assistant
//! report can always cite a current ceiling.
//!
//! ## Why a SIBLING task, not an extension of the policy tick
//!
//! [`crate::lifecycle_job::run_policy_tick`] is deliberately NOT the host
//! for this:
//! - **Different candidate set.** The policy tick scans models with a
//!   non-empty `policy_json`; the audit must cover EVERY model with ≥1
//!   correction row, policy or not.
//! - **Different cadence semantics.** Policy re-eval is dataset-change
//!   driven (debounced on `ml_datasets.updated_at`); the audit is a flat
//!   per-model weekly clock (`TALOS_TEACHER_AUDIT_INTERVAL_DAYS`).
//! - **Different rate discipline.** One audit is ~100 local LLM calls
//!   (~75 s). The policy tick evaluates up to `MODELS_PER_TICK` models per
//!   run; folding a ~100-call audit into that per-model loop would let a
//!   single tick stampede the local LLM over many models. This job starts
//!   AT MOST ONE audit per tick — the next tick catches the next model.
//!
//! ## Transport
//!
//! [`crate::teacher_audit::start_teacher_audit`] stays transport-agnostic
//! (caller supplies the classify closure). Here the closure is the SAME
//! one the MCP handler builds — `OllamaClient::complete_structured`
//! (`think:false`, `format:"json"`) — reusing the one process-wide
//! `Arc<OllamaClient>` threaded in from the controller wiring. Ollama not
//! configured → the tick skips with a DEBUG log; it never errors.
//!
//! ## DLP
//!
//! One INFO log per STARTED audit carrying the model id + name only (model
//! names are user-chosen labels, not email-derived content — same posture
//! as [`crate::lifecycle_job::audit_transition`]); everything else is
//! DEBUG. No gold-row text or teacher reply is ever logged.

use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::dataset::DatasetService;
use crate::teacher_audit::{
    start_teacher_audit, TeacherAuditError, TeacherRequest, MAX_AUDIT_ROWS,
};
use talos_llm::OllamaClient;

/// Weekly cadence default (days) — the max age of a stored audit before
/// the model is re-audited.
const DEFAULT_INTERVAL_DAYS: i64 = 7;
const MIN_INTERVAL_DAYS: i64 = 1;
const MAX_INTERVAL_DAYS: i64 = 90;

/// A `status:"running"` stamp older than this is treated as a CRASHED
/// process's leftover and made eligible again. The in-flight guard in
/// `start_teacher_audit` prevents a true double WITHIN a live process; a
/// crash clears that guard but strands the JSONB status, so the age check
/// is the only cross-process recovery signal.
const STALE_RUNNING_SECS: i64 = 2 * 60 * 60;

/// Per-tick candidate scan cap. ML models are low-cardinality per
/// deployment; the stalest-first ORDER BY keeps the most-overdue models in
/// the window and the LIMIT just bounds the scan.
const CANDIDATES_PER_TICK: i64 = 50;

/// How often the scheduler WAKES to check (not how often a given model is
/// audited — that's the interval-days cadence). Hourly is plenty; the
/// per-model 7-day gate does the real rate-limiting.
const DEFAULT_CHECK_INTERVAL_SECS: u64 = 3600;
const MIN_CHECK_INTERVAL_SECS: u64 = 60;

/// The per-model weekly cadence, from `TALOS_TEACHER_AUDIT_INTERVAL_DAYS`
/// (default 7, clamped 1..=90). Mirrors the inline positive-env idiom
/// `crate::lifecycle_job` / `crate::digest` use (talos-ml keeps no
/// talos-config dep); the clamp is the `positive_env_or_default` spirit.
pub fn interval_days() -> i64 {
    std::env::var("TALOS_TEACHER_AUDIT_INTERVAL_DAYS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_INTERVAL_DAYS)
        .clamp(MIN_INTERVAL_DAYS, MAX_INTERVAL_DAYS)
}

fn check_interval_secs() -> u64 {
    std::env::var("TALOS_TEACHER_AUDIT_CHECK_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v >= MIN_CHECK_INTERVAL_SECS)
        .unwrap_or(DEFAULT_CHECK_INTERVAL_SECS)
}

/// Parse an RFC3339 timestamp out of a stored JSONB field (the form
/// `chrono::DateTime<Utc>` serializes to in the audit stamps).
fn parse_ts(v: &serde_json::Value) -> Option<DateTime<Utc>> {
    v.as_str()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
}

/// Is a fresh bare-prompt teacher audit due for this model? PURE —
/// unit-tested without a DB or wall clock.
///
/// - `has_corrections` — the model's dataset has ≥1 `source='correction'`
///   row (the audit's gold slice). No corrections → never eligible.
/// - `stored` — the `ml_models.teacher_audit` JSONB (`None` when the
///   column is NULL, i.e. never audited).
///
/// Reads the exact status/timestamp shape written by
/// [`crate::teacher_audit`] (`running`+`started_at`, `complete`+`audited_at`,
/// `failed`+`failed_at`): keep the two in sync.
pub(crate) fn teacher_audit_due(
    has_corrections: bool,
    stored: Option<&serde_json::Value>,
    now: DateTime<Utc>,
    interval_days: i64,
) -> bool {
    if !has_corrections {
        return false;
    }
    // Never audited (NULL column / JSON null) → due.
    let Some(v) = stored.filter(|v| !v.is_null()) else {
        return true;
    };
    let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("");
    if status == "running" {
        // Live audit → not due (the in-flight guard owns it). A `running`
        // stamp older than STALE_RUNNING_SECS is a crashed process's
        // leftover → due. Missing/unparsable `started_at` on a `running`
        // stamp is malformed (start always stamps one) — treat as stale so
        // the model isn't stranded forever; start's own guard + the fresh
        // stamp supersede it.
        return match v.get("started_at").and_then(parse_ts) {
            Some(started) => (now - started).num_seconds() > STALE_RUNNING_SECS,
            None => true,
        };
    }
    // complete / failed / anything else: gate on the last-attempt age so a
    // failed audit respects the same cadence instead of retrying every
    // check. `audited_at` (complete) or `failed_at` (failed); absent both →
    // due.
    let last = v
        .get("audited_at")
        .and_then(parse_ts)
        .or_else(|| v.get("failed_at").and_then(parse_ts));
    match last {
        Some(t) => (now - t) > Duration::days(interval_days),
        None => true,
    }
}

/// One eligible candidate from the scan.
struct AuditCandidate {
    model_id: Uuid,
    user_id: Uuid,
    name: String,
    has_corrections: bool,
    stored: Option<serde_json::Value>,
}

/// Scan correction-eligible, non-archived models, STALEST-audit-first.
/// `has_corrections` is selected (not WHERE-filtered) so the pure
/// predicate stays authoritative — the ORDER BY + LIMIT bound the work.
async fn scan_candidates(pool: &PgPool) -> Result<Vec<AuditCandidate>> {
    let rows = sqlx::query(
        "SELECT m.id, m.user_id, m.name, m.teacher_audit, \
                EXISTS(SELECT 1 FROM ml_examples e \
                       WHERE e.dataset_id = m.dataset_id \
                         AND e.source = 'correction') AS has_corrections \
         FROM ml_models m \
         WHERE m.dataset_id IS NOT NULL \
           AND m.lifecycle_state NOT IN ('archived', 'deleted') \
         ORDER BY (m.teacher_audit->>'audited_at') ASC NULLS FIRST, m.id \
         LIMIT $1",
    )
    .bind(CANDIDATES_PER_TICK)
    .fetch_all(pool)
    .await
    .context("scan teacher-audit candidates")?;

    rows.into_iter()
        .map(|r| {
            Ok(AuditCandidate {
                model_id: r.try_get("id")?,
                user_id: r.try_get("user_id")?,
                name: r.try_get("name")?,
                has_corrections: r
                    .try_get::<Option<bool>, _>("has_corrections")?
                    .unwrap_or(false),
                stored: r.try_get::<Option<serde_json::Value>, _>("teacher_audit")?,
            })
        })
        .collect()
}

/// One bounded tick: find the stalest eligible model and start AT MOST ONE
/// audit. Returns the started model id (if any). Public so an integration
/// test / operator tool can drive it deterministically.
///
/// `ollama` absent (not configured) → skip with a DEBUG log, never error.
pub async fn run_teacher_audit_tick(
    pool: &PgPool,
    dataset: &DatasetService,
    ollama: Option<&Arc<OllamaClient>>,
    interval_days: i64,
) -> Result<Option<Uuid>> {
    let Some(ollama) = ollama else {
        tracing::debug!(
            target: "talos_ml",
            "teacher-audit scheduler: local LLM (ollama) not configured — skipping tick"
        );
        return Ok(None);
    };

    let now = Utc::now();
    let candidates = scan_candidates(pool).await?;

    for c in candidates {
        if !teacher_audit_due(c.has_corrections, c.stored.as_ref(), now, interval_days) {
            continue;
        }

        // Same transport the MCP handler builds — think:false / format:json,
        // reusing the one process-wide Arc<OllamaClient>. Rebuilt per
        // attempt so a data-level skip can move on to the next candidate.
        let ollama = ollama.clone();
        let classify = move |r: TeacherRequest| {
            let ollama = ollama.clone();
            async move {
                ollama
                    .complete_structured(
                        &r.llm_model,
                        &r.system_prompt,
                        &r.user_content,
                        r.max_tokens,
                    )
                    .await
            }
        };

        // Bare-label contract: system_prompt = None (the canonical
        // unattended measurement — no node prompt to bias the teacher).
        match start_teacher_audit(
            pool,
            dataset,
            c.user_id,
            c.model_id,
            MAX_AUDIT_ROWS,
            None,
            classify,
        )
        .await
        {
            Ok(_) => {
                // DLP: model id + name only (name is a user label, not
                // content). One INFO per started audit.
                tracing::info!(
                    target: "talos_ml",
                    model_id = %c.model_id,
                    model_name = %c.name,
                    "automatic teacher audit started (weekly cadence)"
                );
                return Ok(Some(c.model_id));
            }
            Err(TeacherAuditError::AlreadyRunning) => {
                // Another tick/replica owns it — that's a covered model, but
                // not a start WE made, so keep looking for one to progress.
                tracing::debug!(target: "talos_ml", model_id = %c.model_id, "teacher audit already running; skipping");
            }
            Err(TeacherAuditError::InvalidConfig(reason)) => {
                // e.g. corrections exist but none carry a usable label yet.
                // Not a start — move on rather than stalling the whole tick
                // behind one un-auditable model.
                tracing::debug!(target: "talos_ml", model_id = %c.model_id, %reason, "teacher audit not startable; skipping");
            }
            Err(TeacherAuditError::NotFound | TeacherAuditError::NoDataset) => {
                tracing::debug!(target: "talos_ml", model_id = %c.model_id, "teacher audit target vanished; skipping");
            }
            Err(TeacherAuditError::Internal(e)) => {
                tracing::warn!(target: "talos_ml", model_id = %c.model_id, error = ?e, "teacher audit start failed; skipping");
            }
        }
    }

    Ok(None)
}

/// Spawn the scheduler loop. Wakes every
/// `TALOS_TEACHER_AUDIT_CHECK_INTERVAL_SECS` (default 3600 s); the per-model
/// cadence is `TALOS_TEACHER_AUDIT_INTERVAL_DAYS`. Observes the shared
/// background-shutdown watch. `ollama = None` → the loop still runs but
/// every tick skips (presence-only).
pub fn spawn_teacher_audit_scheduler(
    pool: PgPool,
    dataset: DatasetService,
    ollama: Option<Arc<OllamaClient>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let check_secs = check_interval_secs();
    let days = interval_days();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(check_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tracing::info!(
            check_interval_secs = check_secs,
            interval_days = days,
            ollama_configured = ollama.is_some(),
            "ml teacher-audit scheduler active"
        );
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    tracing::info!("ml teacher-audit scheduler shutting down");
                    break;
                }
                _ = interval.tick() => {
                    match run_teacher_audit_tick(&pool, &dataset, ollama.as_ref(), days).await {
                        Ok(Some(_)) => {}
                        Ok(None) => {}
                        Err(e) => tracing::warn!(error = %e, "ml teacher-audit tick failed; retrying next interval"),
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    #[test]
    fn fresh_complete_audit_is_skipped() {
        let n = now();
        let stored = serde_json::json!({
            "status": "complete",
            "audited_at": (n - Duration::days(1)),
            "accuracy": 0.9,
        });
        assert!(
            !teacher_audit_due(true, Some(&stored), n, 7),
            "an audit 1 day old under a 7-day cadence is fresh → skip"
        );
    }

    #[test]
    fn stale_complete_audit_is_eligible() {
        let n = now();
        let stored = serde_json::json!({
            "status": "complete",
            "audited_at": (n - Duration::days(8)),
        });
        assert!(
            teacher_audit_due(true, Some(&stored), n, 7),
            "an audit 8 days old under a 7-day cadence is stale → eligible"
        );
    }

    #[test]
    fn absent_audit_is_eligible() {
        let n = now();
        assert!(
            teacher_audit_due(true, None, n, 7),
            "never audited (NULL column) → eligible"
        );
        assert!(
            teacher_audit_due(true, Some(&serde_json::Value::Null), n, 7),
            "JSON null → eligible"
        );
    }

    #[test]
    fn live_running_audit_is_skipped() {
        let n = now();
        let stored = serde_json::json!({
            "status": "running",
            "started_at": (n - Duration::minutes(5)),
            "gold_rows": 100,
        });
        assert!(
            !teacher_audit_due(true, Some(&stored), n, 7),
            "a running audit started 5 min ago is live → skip (in-flight guard owns it)"
        );
    }

    #[test]
    fn stale_running_audit_is_eligible() {
        let n = now();
        let stored = serde_json::json!({
            "status": "running",
            "started_at": (n - Duration::hours(3)),
        });
        assert!(
            teacher_audit_due(true, Some(&stored), n, 7),
            "a running stamp 3 h old is a crashed-process leftover → eligible"
        );
    }

    #[test]
    fn running_without_started_at_is_eligible() {
        let n = now();
        let stored = serde_json::json!({ "status": "running" });
        assert!(
            teacher_audit_due(true, Some(&stored), n, 7),
            "a malformed running stamp with no started_at must not strand the model"
        );
    }

    #[test]
    fn no_corrections_is_skipped() {
        let n = now();
        // Even a never-audited model is ineligible without a gold slice.
        assert!(
            !teacher_audit_due(false, None, n, 7),
            "no correction rows → nothing to audit against → skip"
        );
        let stale = serde_json::json!({
            "status": "complete",
            "audited_at": (n - Duration::days(30)),
        });
        assert!(
            !teacher_audit_due(false, Some(&stale), n, 7),
            "no corrections overrides staleness → skip"
        );
    }

    #[test]
    fn recently_failed_audit_respects_cadence() {
        let n = now();
        let recent = serde_json::json!({
            "status": "failed",
            "failed_at": (n - Duration::hours(1)),
            "error": "teacher unavailable (repeated call failures)",
        });
        assert!(
            !teacher_audit_due(true, Some(&recent), n, 7),
            "a failure 1 h ago must not hammer a down teacher every check"
        );
        let old = serde_json::json!({
            "status": "failed",
            "failed_at": (n - Duration::days(8)),
        });
        assert!(
            teacher_audit_due(true, Some(&old), n, 7),
            "a week-old failure is eligible to retry"
        );
    }

    #[test]
    fn interval_days_clamps() {
        // Defaults + clamp are env-driven; assert the pure clamp bounds via
        // the constants the reader relies on.
        assert_eq!(
            DEFAULT_INTERVAL_DAYS.clamp(MIN_INTERVAL_DAYS, MAX_INTERVAL_DAYS),
            7
        );
        assert_eq!(
            0i64.max(MIN_INTERVAL_DAYS)
                .clamp(MIN_INTERVAL_DAYS, MAX_INTERVAL_DAYS),
            1
        );
        assert_eq!(1000i64.clamp(MIN_INTERVAL_DAYS, MAX_INTERVAL_DAYS), 90);
    }
}
