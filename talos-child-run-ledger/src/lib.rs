//! The child-run ledger — RFC 0012 P1.
//!
//! `ParallelWorkflowEngine::execute_subworkflow_graph` runs a child workflow
//! IN-PROCESS and records no `workflow_executions` row. Measured platform-wide
//! 2026-09-05 and re-measured 2026-09-06: ZERO rows carry a
//! `parent_execution_id`, live table AND archive, against an estimated ~225
//! child runs per day. Every reader that answers *"did this workflow run, how
//! often, how reliably, how recently?"* reads `workflow_executions` — 163
//! occurrences across 28 non-test files — so a child is structurally invisible
//! to all of them. #758 / #760 / #762 / #763 taught the DESTRUCTIVE and
//! SCORING readers to say *"no evidence"* instead of *"never ran"*. This crate
//! is the first thing that can ANSWER the question.
//!
//! # Two rules a future change must not quietly drop
//!
//! **A child run is NOT charged to the actor's hourly execution budget.**
//! `talos_actor_repository::budget_precheck` counts `workflow_executions` rows
//! (`count_executions_last_hour`, `count_total_executions`), and this crate
//! writes to `sub_workflow_runs`. The parent's run was budgeted when it was
//! created; charging its children again would bill one run twice.
//!
//! **UNKNOWN is not zero.** The table has a first row. A count of 0 for a
//! period BEFORE [`ChildRunLedger::since`] is *nobody was recording*, not
//! *nothing ran* — the same rule #758 applies to `child_workflow_ids_checked`.
//! Every consumer renders `since()` beside its count, and renders `null` with
//! a reason (never `0`) when `since()` is unknown or the window predates it.
//!
//! # What this ledger does NOT see
//!
//! [`UNRECORDED_DISPATCH_KINDS`]. Four node kinds run a child through a
//! DIFFERENT engine-hydration site and are not recorded in P1. That is
//! disclosed by every consumer rather than left to look like silence.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use talos_workflow_engine_core::{ChildDispatchKind, ChildRunRecord};
use uuid::Uuid;

/// Node kinds that dispatch a child workflow but are **not** recorded by P1.
///
/// Measured, not assumed: every `AdapterSet::into_engine_with_graph` site in
/// the workspace was enumerated (2026-09-06). Three exist — the chokepoint
/// `execute_subworkflow_graph`, `run_dispatched_subworkflow`
/// (`DynamicDispatch` + `CapabilityDispatch`) and the agent-loop body's
/// per-iteration hydration — and only the first routes through the recorder.
///
/// On the reference fleet these kinds are LATENT: of 36 workflows, the only
/// child-dispatching node kinds present are `sub_workflow` (3) and `judge`
/// (3), both recorded. "Latent is not live" cuts both ways, so the gap is
/// NAMED here and disclosed by every consumer instead of being left to read as
/// "this child never ran".
pub const UNRECORDED_DISPATCH_KINDS: &[&str] = &[
    "agent_loop",
    "react_loop",
    "dispatch",
    "capability_dispatch",
];

/// The disclosure every consumer renders beside a ledger count, so a reader can
/// tell "no runs" from "this dispatch kind is not recorded yet".
pub const UNRECORDED_DISPATCH_KINDS_NOTE: &str =
    "The ledger records the five node kinds that dispatch through \
     execute_subworkflow_graph (sub_workflow, judge, ensemble, reflective_retry, \
     llm_dispatch). A child dispatched ONLY by agent_loop, react_loop, dispatch or \
     capability_dispatch hydrates its engine at a different site and is not recorded \
     in RFC 0012 P1, so a zero count for such a workflow says nothing about it.";

/// How long [`ChildRunLedger::since`] is cached per process.
///
/// The ledger's start moves exactly once in the table's life (the first
/// INSERT) and then never again, so the only thing this TTL bounds is how long
/// a brand-new deployment renders UNKNOWN after its first child run.
pub const SINCE_CACHE_TTL: Duration = Duration::from_secs(60);

/// Rows deleted per retention batch. Matches
/// `talos_advanced_repository::RETENTION_BATCH`'s shape: bounded work per
/// statement, `SKIP LOCKED` so a concurrent purge never blocks.
pub const LEDGER_PURGE_BATCH: i64 = 1_000;

/// The largest page any ledger read will return, whatever a caller asks for.
pub const MAX_LIST_LIMIT: i64 = 500;

/// One recorded child run, as a reader sees it.
#[derive(Debug, Clone)]
pub struct ChildRunRow {
    /// The ledger row's own id.
    pub id: Uuid,
    /// The parent's graph node id, as authored.
    pub parent_node_id: String,
    /// Which node kind dispatched it.
    pub dispatch_kind: String,
    /// The workflow that ran as the child.
    pub child_workflow_id: Uuid,
    /// The child workflow's name, when the row still exists.
    pub child_workflow_name: Option<String>,
    /// The effective actor the child ran as.
    pub actor_id: Option<Uuid>,
    /// Nesting depth; 1 = a direct child.
    pub depth: i16,
    /// When the child started.
    pub started_at: DateTime<Utc>,
    /// When it settled.
    pub completed_at: DateTime<Utc>,
    /// `completed` or `failed`.
    pub status: String,
    /// A redacted, capped error summary. Never a payload.
    pub error_class: Option<String>,
    /// Wall time of the run.
    pub duration_ms: i64,
}

/// Postgres-backed child-run ledger.
#[derive(Clone)]
pub struct ChildRunLedger {
    pool: PgPool,
}

/// Process-wide cache for [`ChildRunLedger::since`].
///
/// Deliberately process-wide rather than per-instance: `since()` is a
/// DEPLOYMENT fact ("from when does this table hold data"), not a per-request
/// one, and several consumers construct their own `ChildRunLedger` from the
/// shared pool.
static SINCE_CACHE: OnceLock<Mutex<Option<(Instant, Option<DateTime<Utc>>)>>> = OnceLock::new();

fn since_cache() -> &'static Mutex<Option<(Instant, Option<DateTime<Utc>>)>> {
    SINCE_CACHE.get_or_init(|| Mutex::new(None))
}

impl ChildRunLedger {
    /// Bind a ledger to a pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Persist one child run.
    ///
    /// The record is [`sanitized`](ChildRunRecord::sanitized) HERE, immediately
    /// before the bind, rather than by the engine that built it — so no future
    /// caller can forget, and the table's `char_length` CHECKs are a second
    /// belt rather than the only one.
    ///
    /// Runs on the bare pool: the writer is the engine's dispatch path, which
    /// sets no tenant GUC, and the RLS policy's `current_setting(...) IS NULL`
    /// transition clause is what makes that legal — the same posture the
    /// retention sweep and the archival move already have.
    ///
    /// # Errors
    /// Any database failure. The CALLER (the `ChildRunRecorder` adapter) must
    /// swallow it: a ledger is not a routing dependency.
    pub async fn record(&self, record: ChildRunRecord) -> Result<()> {
        let record = record.sanitized();
        let started_at = DateTime::from_timestamp_millis(record.started_at_unix_ms)
            .context("child-run record: started_at_unix_ms out of range")?;
        let completed_at = started_at
            + chrono::Duration::try_milliseconds(record.duration_ms)
                .context("child-run record: duration_ms out of range")?;
        sqlx::query(
            "INSERT INTO sub_workflow_runs \
                 (parent_execution_id, parent_workflow_id, parent_node_id, dispatch_kind, \
                  child_workflow_id, user_id, actor_id, depth, started_at, completed_at, \
                  status, error_class, duration_ms) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(record.parent_execution_id)
        .bind(record.parent_workflow_id)
        .bind(&record.parent_node_id)
        .bind(record.dispatch_kind.as_str())
        .bind(record.child_workflow_id)
        .bind(record.user_id)
        .bind(record.actor_id)
        .bind(record.depth)
        .bind(started_at)
        .bind(completed_at)
        .bind(record.status.as_str())
        .bind(record.error_class.as_deref())
        .bind(record.duration_ms)
        .execute(&self.pool)
        .await
        .context("record_child_run")?;
        Ok(())
    }

    /// When the ledger's earliest surviving row started — the answer to *"is a
    /// zero here evidence, or is it silence?"*.
    ///
    /// `Ok(None)` means the table is EMPTY, which is not "the ledger started
    /// now": a consumer must render UNKNOWN, never 0. Cached per process for
    /// [`SINCE_CACHE_TTL`].
    ///
    /// **Deliberately NOT user-scoped**, and this is the one place the ledger
    /// reads across tenants. The question is "from when was anything being
    /// recorded", which is a deployment fact; a per-user `MIN` answers a
    /// different question and would render UNKNOWN forever for a user who has
    /// legitimately never dispatched a child, i.e. it would turn a real zero
    /// into a permanent "we cannot tell". The value crossing that boundary is
    /// ONE timestamp with no tenant attached.
    ///
    /// Note what it cannot say: after retention purges the oldest rows this
    /// floor RISES, so it is *"the earliest run the ledger still holds"* and
    /// not *"the day the table was created"*. That is the conservative
    /// direction — it can only widen the UNKNOWN region, never claim coverage
    /// the rows do not support.
    ///
    /// # Errors
    /// Any database failure. A failure is NOT cached.
    pub async fn since(&self) -> Result<Option<DateTime<Utc>>> {
        if let Some((at, cached)) = *since_cache().lock().unwrap_or_else(|e| e.into_inner()) {
            if at.elapsed() < SINCE_CACHE_TTL {
                return Ok(cached);
            }
        }
        let row = sqlx::query("SELECT MIN(started_at) AS since FROM sub_workflow_runs")
            .fetch_one(&self.pool)
            .await
            .context("child_run_ledger_since")?;
        let since: Option<DateTime<Utc>> = row.try_get("since")?;
        *since_cache().lock().unwrap_or_else(|e| e.into_inner()) = Some((Instant::now(), since));
        Ok(since)
    }

    /// Forget the cached [`Self::since`] value.
    ///
    /// For tests that seed a row and then read the floor back inside one
    /// process. It exists because the cache is process-wide: in production one
    /// process talks to one database, but a test binary drives several
    /// isolated databases from the same process and would otherwise read a
    /// sibling's floor.
    pub fn reset_since_cache() {
        *since_cache().lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Every child run one parent EXECUTION dispatched, newest first.
    ///
    /// Tenant-scoped twice: `WHERE user_id = $2` at the app layer, on a
    /// `begin_user_scoped` transaction so the RLS policy is the backstop.
    /// Bounded by `limit`, itself clamped to [`MAX_LIST_LIMIT`].
    ///
    /// # Errors
    /// Any database failure.
    pub async fn list_for_parent(
        &self,
        parent_execution_id: Uuid,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<ChildRunRow>> {
        let limit = limit.clamp(1, MAX_LIST_LIMIT);
        let mut tx = talos_db::begin_user_scoped(&self.pool, user_id).await?;
        let rows = sqlx::query(
            "SELECT s.id, s.parent_node_id, s.dispatch_kind, s.child_workflow_id, \
                    w.name AS child_workflow_name, s.actor_id, s.depth, s.started_at, \
                    s.completed_at, s.status, s.error_class, s.duration_ms \
             FROM sub_workflow_runs s \
             LEFT JOIN workflows w ON w.id = s.child_workflow_id \
             WHERE s.parent_execution_id = $1 AND s.user_id = $2 \
             ORDER BY s.started_at DESC, s.id \
             LIMIT $3",
        )
        .bind(parent_execution_id)
        .bind(user_id)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .context("list_child_runs_for_parent")?;
        tx.commit().await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(ChildRunRow {
                id: r.try_get("id")?,
                parent_node_id: r
                    .try_get::<Option<String>, _>("parent_node_id")?
                    .unwrap_or_default(),
                dispatch_kind: r
                    .try_get::<Option<String>, _>("dispatch_kind")?
                    .unwrap_or_default(),
                child_workflow_id: r.try_get("child_workflow_id")?,
                child_workflow_name: r.try_get("child_workflow_name")?,
                actor_id: r.try_get("actor_id")?,
                depth: r.try_get::<Option<i16>, _>("depth")?.unwrap_or_default(),
                started_at: r.try_get("started_at")?,
                completed_at: r.try_get("completed_at")?,
                status: r
                    .try_get::<Option<String>, _>("status")?
                    .unwrap_or_default(),
                error_class: r.try_get("error_class")?,
                duration_ms: r
                    .try_get::<Option<i64>, _>("duration_ms")?
                    .unwrap_or_default(),
            });
        }
        Ok(out)
    }

    /// How many recorded runs each of `child_workflow_ids` has had since
    /// `since`, as one batched query.
    ///
    /// `= ANY($1)` and not one query per id — this is called from a list
    /// renderer, which is exactly where an N+1 is born. A child with no rows
    /// is ABSENT from the map, never present as 0: the caller decides what an
    /// absence means, and before `ledger_since` it means UNKNOWN.
    ///
    /// # Errors
    /// Any database failure.
    pub async fn count_for_children_since(
        &self,
        child_workflow_ids: &[Uuid],
        user_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<HashMap<Uuid, i64>> {
        if child_workflow_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let mut tx = talos_db::begin_user_scoped(&self.pool, user_id).await?;
        let rows = sqlx::query(
            "SELECT child_workflow_id, COUNT(*) AS runs \
             FROM sub_workflow_runs \
             WHERE child_workflow_id = ANY($1) AND user_id = $2 AND started_at >= $3 \
             GROUP BY child_workflow_id",
        )
        .bind(child_workflow_ids)
        .bind(user_id)
        .bind(since)
        .fetch_all(&mut *tx)
        .await
        .context("count_child_runs_since")?;
        tx.commit().await?;

        let mut out = HashMap::with_capacity(rows.len());
        for r in &rows {
            let id: Uuid = r.try_get("child_workflow_id")?;
            let n: i64 = r.try_get::<Option<i64>, _>("runs")?.unwrap_or_default();
            out.insert(id, n);
        }
        Ok(out)
    }

    /// Delete ledger rows older than `days`, in `SKIP LOCKED` batches,
    /// EXEMPTING any row whose parent execution is pinned in EITHER tier.
    ///
    /// `days` is the TOTAL execution lifetime (`archive_after_days +
    /// purge_after_days`), because the ledger has no FK to
    /// `workflow_executions` and therefore no archival move of its own: a
    /// shorter window would delete the evidence while the parent is still
    /// readable in the archive.
    ///
    /// Three belts, deliberately the same three
    /// `purge_archived_executions` carries:
    ///
    /// * a POSITIVE-days guard, refusing loudly — `make_interval(days => 0)`
    ///   selects everything;
    /// * the pinned-parent exemption, checked against `workflow_executions`
    ///   AND `workflow_executions_archive`, because `pin_execution`'s promise
    ///   must survive the parent's own archival move;
    /// * `ORDER BY … LIMIT … FOR UPDATE SKIP LOCKED`, so a concurrent purge
    ///   never blocks and no statement is unbounded.
    ///
    /// # Errors
    /// Any database failure. Returns the number of rows deleted.
    pub async fn purge_older_than(&self, days: i32) -> Result<u64> {
        if days <= 0 {
            tracing::warn!(
                target: "talos_audit",
                days,
                "child-run ledger purge refused: days must be positive (would delete the whole ledger)"
            );
            return Ok(0);
        }
        let sql = format!(
            "DELETE FROM sub_workflow_runs WHERE id IN ( \
                 SELECT s.id FROM sub_workflow_runs s \
                 WHERE s.started_at < NOW() - make_interval(days => $1::int) \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM workflow_executions e \
                       WHERE e.id = s.parent_execution_id AND e.is_pinned \
                   ) \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM workflow_executions_archive a \
                       WHERE a.id = s.parent_execution_id AND a.is_pinned \
                   ) \
                 ORDER BY s.started_at, s.id \
                 LIMIT {LEDGER_PURGE_BATCH} \
                 FOR UPDATE SKIP LOCKED \
             )"
        );
        let mut total = 0u64;
        loop {
            let deleted = sqlx::query(&sql)
                .bind(days)
                .execute(&self.pool)
                .await
                .map(|r| r.rows_affected())
                .context("purge_child_run_ledger")?;
            total += deleted;
            if deleted < LEDGER_PURGE_BATCH as u64 {
                break;
            }
            // Yield between batches so a large first sweep does not monopolise
            // the pool — same courtesy the execution purge extends.
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok(total)
    }
}

/// Every dispatch kind the ledger DOES record, as the DB spells them. Derived
/// from the taxonomy rather than re-listed, so a sixth kind cannot be added to
/// one and forgotten in the other.
#[must_use]
pub fn recorded_dispatch_kinds() -> Vec<&'static str> {
    ChildDispatchKind::ALL.iter().map(|k| k.as_str()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_and_unrecorded_kinds_do_not_overlap() {
        for recorded in recorded_dispatch_kinds() {
            assert!(
                !UNRECORDED_DISPATCH_KINDS.contains(&recorded),
                "{recorded} is claimed both recorded and unrecorded"
            );
        }
    }

    /// The disclosure must NAME every kind it claims is unrecorded. A note
    /// that drifts from the constant is a disclosure that misleads.
    #[test]
    fn the_disclosure_names_every_unrecorded_kind() {
        for kind in UNRECORDED_DISPATCH_KINDS {
            assert!(
                UNRECORDED_DISPATCH_KINDS_NOTE.contains(kind),
                "the operator-facing note does not name {kind}"
            );
        }
        for kind in recorded_dispatch_kinds() {
            assert!(
                UNRECORDED_DISPATCH_KINDS_NOTE.contains(kind),
                "the operator-facing note does not name the recorded kind {kind}"
            );
        }
    }
}
