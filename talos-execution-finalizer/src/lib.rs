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

    #[test]
    fn the_workflow_failure_finalizer_has_one_home() {
        let needle = "UPDATE workflow_executions SET status = 'failed'";
        for (name, src) in FORMER_COPIES {
            assert!(
                !src.contains(needle),
                "{name} re-inlines the dispatcher-side failure UPDATE"
            );
        }
        for (name, src) in &FORMER_COPIES[..4] {
            assert!(
                src.contains("fail_workflow_execution_unless_terminal("),
                "{name} no longer calls the failure home"
            );
        }
        assert_eq!(include_str!("lib.rs").matches(needle).count(), 1);
    }

    #[test]
    fn the_completion_finalizer_has_one_home() {
        let needle = "SET status = 'completed', output_data";
        for (name, src) in FORMER_COPIES {
            assert!(
                !src.contains(needle),
                "{name} re-inlines a completion UPDATE"
            );
        }
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
        assert_eq!(
            include_str!("lib.rs").matches(needle).count(),
            3,
            "two statements plus this needle"
        );
    }
}
