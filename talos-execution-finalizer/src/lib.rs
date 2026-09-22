//! The ONE home for the `workflow_executions` terminal writes that more than
//! one crate performs.
//!
//! Measured 2026-09-12 on the #828 deploy: the database held two `failed`
//! workflow rows since boot and `talos_workflow_executions_total{status=
//! "failure"}` read 0. The scheduler's failure path was one of EIGHT raw
//! single-line `status = 'failed'` UPDATE statements outside the
//! two counted repositories — `talos-scheduler` ×3, `talos-webhooks` ×3,
//! `talos-actor-repository` ×2 — and none recorded the outcome; the actor
//! repository's `complete_execution` was a third copy of the completion
//! statement, uncounted and guarded on `status = 'running'` alone (check 46's
//! class, out of that check's then two-crate scope). The 2026-09-11 burn-down
//! had said "every finalizer" and enumerated five. This crate is the
//! workflow-side twin of `cancel_running_module_executions`: every path calls
//! in, the statement RETURNS the row's own duration by the database clock, and
//! the recorder is called once per finalized row.
//!
//! It is a LEAF because the two repositories that need it cannot see each
//! other: `talos-workflow-repository → talos-graph-rag → talos-actor-repository`
//! is already an edge, so the actor repository cannot depend on the workflow
//! repository.

use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

/// A DISPATCHER lost or refused a run: the scheduler, the webhook router, the
/// continuation / handoff paths. Guard: never clobber a terminal row, and never
/// touch a `resuming` row — that one is OWNED by crash recovery
/// (`reclaim_orphaned_resuming` fails it out). The ENGINE's own failure
/// finalizer (`WorkflowRepository::mark_execution_failed`, `IN ('running',
/// 'resuming')`) is deliberately a different guard: it may finalize the run it
/// resumed. Returns the rows finalized (0 or 1).
pub async fn fail_workflow_execution_unless_terminal(
    pool: &PgPool,
    execution_id: Uuid,
    error_message: &str,
) -> Result<u64> {
    let row = sqlx::query(
        "UPDATE workflow_executions \
         SET status = 'failed', completed_at = NOW(), error_message = $2 \
         WHERE id = $1 AND status NOT IN ('completed', 'failed', 'cancelled', 'resuming') \
         RETURNING EXTRACT(EPOCH FROM (completed_at - started_at))::float8",
    )
    .bind(execution_id)
    .bind(error_message)
    .fetch_optional(pool)
    .await?;
    record("failure", row)
}

/// The same dispatcher-side guard, for a failure that is NOT a terminal-time
/// write: the GraphQL resume / test setup paths fail a run BEFORE it ever
/// started, so the row has no meaningful duration and `completed_at` stays
/// NULL. Records the outcome with `None` — unknown is not zero seconds.
///
/// It lives here, beside its twin, because the GUARD is the rule and the
/// rule has one home. Until 2026-09-22 this statement was inlined in
/// `talos-execution-repository::fail_execution_unless_terminal`, so the
/// `NOT IN ('completed', 'failed', 'cancelled', 'resuming')` predicate
/// existed in two places — and the source pin that claimed otherwise could
/// not see either of them, because its needle was one contiguous string and
/// both are written across lines.
pub async fn fail_workflow_execution_unless_terminal_without_completed_at(
    pool: &PgPool,
    execution_id: Uuid,
    error_message: &str,
) -> Result<u64> {
    let row = sqlx::query(
        "UPDATE workflow_executions \
         SET status = 'failed', error_message = $2 \
         WHERE id = $1 AND status NOT IN ('completed', 'failed', 'cancelled', 'resuming') \
         RETURNING NULL::float8",
    )
    .bind(execution_id)
    .bind(error_message)
    .fetch_optional(pool)
    .await?;
    record("failure", row)
}

/// The STALE SWEEP closes a run nothing is driving any more (typically one a
/// controller restart orphaned). Guard: `running` ONLY. A `resuming` row is
/// owned by crash recovery and a `queued` one has not started, so the janitor
/// leaves both; a row that finalized itself between the sweep's read and this
/// write keeps its real outcome. Until 2026-09-21 this statement lived in
/// `talos-execution-repository::stale_sweep` and recorded nothing, so every
/// run a restart killed was a `failed` row the failure counter never saw.
/// Returns the rows finalized (0 or 1).
pub async fn fail_stale_running_workflow_execution(
    pool: &PgPool,
    execution_id: Uuid,
    error_message: &str,
) -> Result<u64> {
    // The janitor must not take a `resuming` row from crash recovery — see
    // the doc comment above.
    // allow-running-only-finalize: a `resuming` row is crash recovery's.
    let row = sqlx::query(
        "UPDATE workflow_executions \
         SET status = 'failed', completed_at = NOW(), error_message = $2 \
         WHERE id = $1 AND status = 'running' \
         RETURNING EXTRACT(EPOCH FROM (completed_at - started_at))::float8",
    )
    .bind(execution_id)
    .bind(error_message)
    .fetch_optional(pool)
    .await?;
    record("failure", row)
}

/// A controller is SHUTTING DOWN and these are the runs IT was driving that
/// did not finish inside the drain's grace period (`talos_shutdown::inflight`).
/// They are failed at once with the real reason, instead of sitting `running`
/// until the stale sweep closes them an hour later.
///
/// `ids` must be the caller's OWN in-flight set — never a query over the
/// table: `workflow_executions` records no owning controller, so at two
/// replicas any table-wide predicate would fail a sibling's live runs.
/// Guard: `running` or `resuming` (a run this process resumed is its own);
/// a run that finalized itself in the last instant keeps its real outcome.
/// One statement for the whole set. Returns the rows finalized.
pub async fn fail_runs_interrupted_by_shutdown(
    pool: &PgPool,
    ids: &[Uuid],
    error_message: &str,
) -> Result<u64> {
    if ids.is_empty() {
        return Ok(0);
    }
    let rows = sqlx::query(
        "UPDATE workflow_executions \
         SET status = 'failed', completed_at = NOW(), error_message = $2 \
         WHERE id = ANY($1) AND status IN ('running', 'resuming') \
         RETURNING EXTRACT(EPOCH FROM (completed_at - started_at))::float8",
    )
    .bind(ids)
    .bind(error_message)
    .fetch_all(pool)
    .await?;
    let mut finalized = 0;
    for row in rows {
        finalized += record("failure", Some(row))?;
    }
    Ok(finalized)
}

/// CRASH RECOVERY could not dispatch the run it claimed (decrypt failure,
/// engine build failure, NATS down, deleted workflow). Guard: `resuming` ONLY —
/// the claim's own state — so it never clobbers a row the engine moved on.
/// Until 2026-09-21 this statement lived in `talos-execution-repository` and
/// recorded nothing. Returns the rows finalized (0 or 1).
pub async fn fail_resuming_workflow_execution(
    pool: &PgPool,
    execution_id: Uuid,
    error_message: &str,
) -> Result<u64> {
    let row = sqlx::query(
        "UPDATE workflow_executions \
         SET status = 'failed', error_message = $2, completed_at = NOW() \
         WHERE id = $1 AND status = 'resuming' \
         RETURNING EXTRACT(EPOCH FROM (completed_at - started_at))::float8",
    )
    .bind(execution_id)
    .bind(error_message)
    .fetch_optional(pool)
    .await?;
    record("failure", row)
}

/// Runs wedged in `resuming` — a replica crashed DURING recovery, before the
/// engine took over — older than `grace_minutes`. `epoch = epoch + 1` fences a
/// resumer that merely went slow: its heartbeat sees the mismatch and aborts
/// rather than drive a now-`failed` row. The caller refuses a non-positive
/// grace. One statement; recorded once per row. Returns the rows finalized.
pub async fn reclaim_orphaned_resuming_workflow_executions(
    pool: &PgPool,
    grace_minutes: i64,
) -> Result<u64> {
    let rows = sqlx::query(
        "UPDATE workflow_executions \
         SET status = 'failed', \
             error_message = 'resume interrupted (controller restarted during recovery)', \
             completed_at = NOW(), epoch = epoch + 1 \
         WHERE status = 'resuming' \
           AND updated_at < NOW() - make_interval(mins => $1::int) \
         RETURNING EXTRACT(EPOCH FROM (completed_at - started_at))::float8",
    )
    .bind(grace_minutes)
    .fetch_all(pool)
    .await?;
    let mut finalized = 0;
    for row in rows {
        finalized += record("failure", Some(row))?;
    }
    Ok(finalized)
}

/// Runs an OPERATOR's cleanup failed inside the caller's transaction, not yet
/// counted. The caller commits and THEN calls [`Self::record_after_commit`]:
/// counting inside a transaction that then rolls back would count failures
/// that never happened. `#[must_use]`, so dropping it (never counting) is a
/// `-D warnings` error rather than a silent gap.
#[must_use = "call record_after_commit() once the transaction has committed"]
#[derive(Debug)]
pub struct PendingFailures(Vec<(Uuid, Option<f64>)>);

impl PendingFailures {
    pub fn ids(&self) -> Vec<Uuid> {
        self.0.iter().map(|(id, _)| *id).collect()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Count every run on the failure counter and duration histogram.
    pub fn record_after_commit(self) -> u64 {
        for (_, duration_secs) in &self.0 {
            talos_metrics::record_workflow_outcome("failure", *duration_secs);
        }
        self.0.len() as u64
    }
}

/// An operator's stale-execution cleanup (`cleanup_stale_executions`, hygiene
/// `fix_all`): ONE user's runs `running` for longer than `timeout_minutes`,
/// optionally bounded to an explicit id list (the hygiene preview). Guard:
/// `running` ONLY, like the janitor — a `resuming` row is crash recovery's.
/// Runs on the caller's connection so the cleanup and its `admin_event_log`
/// record are one transaction. The caller refuses a non-positive timeout.
/// Until 2026-09-21 both statements lived in `talos-execution-repository` and
/// recorded nothing.
pub async fn fail_stale_running_for_user_on_conn(
    conn: &mut sqlx::PgConnection,
    user_id: Uuid,
    timeout_minutes: i64,
    only_ids: Option<&[Uuid]>,
) -> Result<PendingFailures> {
    use sqlx::Row as _;
    // allow-running-only-finalize: a `resuming` row is crash recovery's.
    let rows = sqlx::query(
        "UPDATE workflow_executions \
         SET status = 'failed', \
             error_message = CONCAT('Cleaned up: execution was stale (running for over ', $1::text, ' minutes)'), \
             completed_at = NOW() \
         WHERE status = 'running' AND user_id = $2 \
           AND ($3::uuid[] IS NULL OR id = ANY($3)) \
           AND started_at < NOW() - make_interval(mins => $1::int) \
         RETURNING id, EXTRACT(EPOCH FROM (completed_at - started_at))::float8",
    )
    .bind(timeout_minutes)
    .bind(user_id)
    .bind(only_ids)
    .fetch_all(conn)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push((
            row.try_get::<Uuid, _>(0)?,
            row.try_get::<Option<f64>, _>(1)?,
        ));
    }
    Ok(PendingFailures(out))
}

/// Completion with the output already encrypted at rest by the caller
/// (`output_data` cleared, ciphertext + DEK id + format bound). Guard
/// `IN ('running', 'resuming')`: the engine may complete the run it resumed.
pub async fn complete_workflow_execution_encrypted(
    pool: &PgPool,
    execution_id: Uuid,
    enc_bytes: &[u8],
    key_id: Uuid,
    format_version: i16,
) -> Result<u64> {
    let row = sqlx::query(
        "UPDATE workflow_executions \
         SET status = 'completed', output_data = NULL, \
             output_data_enc = $1, output_enc_key_id = $2, \
             output_data_format = $3, completed_at = NOW() \
         WHERE id = $4 AND status IN ('running', 'resuming') \
         RETURNING EXTRACT(EPOCH FROM (completed_at - started_at))::float8",
    )
    .bind(enc_bytes)
    .bind(key_id)
    .bind(format_version)
    .bind(execution_id)
    .fetch_optional(pool)
    .await?;
    record("success", row)
}

/// Completion with a plaintext (already DLP-redacted and payload-bounded)
/// output — the no-encryption configuration.
pub async fn complete_workflow_execution_plain(
    pool: &PgPool,
    execution_id: Uuid,
    redacted_output: &serde_json::Value,
) -> Result<u64> {
    let row = sqlx::query(
        "UPDATE workflow_executions \
         SET status = 'completed', output_data = $1, \
             output_data_enc = NULL, output_enc_key_id = NULL, \
             completed_at = NOW() \
         WHERE id = $2 AND status IN ('running', 'resuming') \
         RETURNING EXTRACT(EPOCH FROM (completed_at - started_at))::float8",
    )
    .bind(redacted_output)
    .bind(execution_id)
    .fetch_optional(pool)
    .await?;
    record("success", row)
}

fn record(status: &str, row: Option<sqlx::postgres::PgRow>) -> Result<u64> {
    match row {
        Some(row) => {
            use sqlx::Row as _;
            let duration_secs = row.try_get::<Option<f64>, _>(0)?;
            talos_metrics::record_workflow_outcome(status, duration_secs);
            Ok(1)
        }
        None => Ok(0),
    }
}

#[cfg(test)]
mod pins {
    /// Every former raw copy must call in and must not re-inline either
    /// statement. Single-line needles: the eight raw failure sites were
    /// single-line, and this crate's statements are written across lines, so
    /// each needle appears in this file exactly once — here.
    const FORMER_COPIES: &[(&str, &str)] = &[
        (
            "talos-scheduler/src/lib.rs",
            include_str!("../../talos-scheduler/src/lib.rs"),
        ),
        (
            "talos-webhooks/src/router.rs",
            include_str!("../../talos-webhooks/src/router.rs"),
        ),
        (
            "talos-actor-repository/src/lib.rs",
            include_str!("../../talos-actor-repository/src/lib.rs"),
        ),
        (
            "talos-execution-repository/src/lib.rs",
            include_str!("../../talos-execution-repository/src/lib.rs"),
        ),
        (
            "talos-workflow-repository/src/executions.rs",
            include_str!("../../talos-workflow-repository/src/executions.rs"),
        ),
    ];

    /// The POSITIVE half: every former copy still calls the home.
    ///
    /// The NEGATIVE half — "no former copy re-inlines the statement" — was
    /// deleted on 2026-09-22 because it was PROVABLY UNFIREABLE, and the
    /// measurement is worth keeping. It read
    /// `!src.contains("UPDATE workflow_executions SET status = 'failed'")`;
    /// that needle is one contiguous string and every such statement in this
    /// workspace is written across lines with `\` continuations, so it
    /// matched **zero** of the five statements that existed in two of the
    /// five pinned files. Its companion
    /// `assert_eq!(include_str!("lib.rs").matches(needle).count(), 1)` was
    /// worse: the single match it counted was the `let needle = …` line
    /// declaring it. A pin whose only evidence is itself.
    ///
    /// That half now lives in `scripts/lint-terminal-write-recorded.py`
    /// leg (b), which reads the statements STATEMENT-AWARE through the
    /// shared `scripts/lint_lib/ruststmt.py`, and keys on the dispatcher
    /// GUARD rather than the columns — because the guard is what makes it
    /// this finalizer rather than the engine's.
    #[test]
    fn the_workflow_failure_finalizer_has_one_home() {
        for (name, src) in &FORMER_COPIES[..4] {
            assert!(
                src.contains("fail_workflow_execution_unless_terminal("),
                "{name} no longer calls the failure home"
            );
        }
    }

    /// The stale sweep was the eighteenth terminal writer: its own UPDATE,
    /// no outcome recorded. TEXTUAL, stated as such — the behaviour is driven
    /// by `controller/tests/workflow_failure_finalizer_tests`.
    #[test]
    fn the_stale_sweep_fails_runs_through_the_home() {
        let src = include_str!("../../talos-execution-repository/src/stale_sweep.rs");
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            code.contains("fail_stale_running_workflow_execution("),
            "the stale sweep no longer calls the failure home"
        );
        assert!(
            !code.contains("SET status = 'failed'"),
            "the stale sweep re-inlines its failure UPDATE"
        );
    }

    /// The POSITIVE half, as above. The negative half moved to the lint on
    /// 2026-09-22 as well — not because it was unfireable (this needle sits
    /// on ONE line in the house style, so it did match real statements) but
    /// because it was fireable by the LUCK of where the author wrapped the
    /// SQL, and a rule that depends on that is one reflow from silent.
    #[test]
    fn the_completion_finalizer_has_one_home() {
        for name in [
            "talos-actor-repository/src/lib.rs",
            "talos-workflow-repository/src/executions.rs",
        ] {
            let src = FORMER_COPIES.iter().find(|(n, _)| *n == name).unwrap().1;
            assert!(
                src.contains("complete_workflow_execution_encrypted(")
                    && src.contains("complete_workflow_execution_plain("),
                "{name} no longer calls both completion homes"
            );
        }
    }
}
