//! The ONE in-transaction actor-budget check (package CK, 2026-09-18).
//!
//! Until this package the five per-actor caps — executions per minute, per
//! hour and in total, fuel per hour, LLM tokens per day — were enforced
//! atomically in exactly one place, `create_execution_under_concurrency_limit`,
//! which the scheduler, webhooks and the operator trigger surfaces go through.
//! Measured by statement, `workflow_executions` has thirteen INSERT sites, and
//! the other start paths had only a lock-free pre-check covering some caps:
//! the approval/suspension/push CONTINUATION path — 3 104 runs in 30 days on
//! the reference fleet, every one `pa-ask-email`, 28% of all runs — checked
//! actor status, per-hour and total, and never per-minute, fuel or tokens;
//! replay and retry the same; handoff skipped per-minute and fuel; the two MCP
//! test paths checked nothing. A spend ceiling that holds on part of the
//! population is not a ceiling.
//!
//! [`admit_actor_budget`] is that backstop's actor half, lifted out so every
//! start path runs the SAME check inside ITS OWN row-creation transaction,
//! under the SAME per-actor advisory lock, atomic with its INSERT. The caller
//! owns the transaction: on [`BudgetAdmission::Refused`] it rolls back and
//! THEN calls [`BudgetRefusal::record`], so no ops-alert write runs while the
//! advisory lock is held (package CD's rule).
//!
//! Deliberately NOT here: the per-workflow concurrency cap, the archived gate
//! and the execution pause. Those are workflow- and deployment-level decisions
//! each path already makes (or deliberately does not) for its own reasons;
//! this is the actor's spend ceiling only.

use sqlx::PgConnection;
use talos_metrics::BudgetCap;
use uuid::Uuid;

/// Derive a stable per-actor key for `pg_advisory_xact_lock(bigint)` from the
/// actor UUID. ONE home, because two start paths taking DIFFERENT keys for the
/// same actor would not serialise against each other and the atomicity would
/// be decorative. A 64-bit collision merely serialises two unrelated actors
/// together occasionally — correctness-safe, perf-only.
#[must_use]
pub fn actor_advisory_lock_key(actor_id: Uuid) -> i64 {
    let b = actor_id.as_bytes();
    i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// The human-facing sentence for a refused start, shared by every path so the
/// fuel cap (a fuel sum) and the token cap (a token sum) never get the
/// execution-count wording.
#[must_use]
pub fn actor_budget_exceeded_message(kind: &str, limit: i64, count: i64) -> String {
    match kind {
        "fuel_per_hour" => format!(
            "Actor fuel budget exceeded: {count} fuel consumed in the last hour (limit: {limit})"
        ),
        "per_minute" => {
            format!("Actor budget exceeded: {count} executions in the last minute (limit: {limit})")
        }
        "per_hour" => {
            format!("Actor budget exceeded: {count} executions in the last hour (limit: {limit})")
        }
        // Package CD: this cap fell into the `_` arm and was worded
        // "executions total" — a token count reported as an execution count.
        "llm_tokens_per_day" => format!(
            "Actor LLM token budget exceeded: {count} tokens in the last 24 hours (limit: {limit})"
        ),
        _ => format!("Actor budget exceeded: {count} executions total (limit: {limit})"),
    }
}

/// A start the actor's budget refused. Nothing was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetRefusal {
    pub actor_id: Uuid,
    pub cap: BudgetCap,
    /// The configured cap.
    pub limit: i64,
    /// The value observed inside the transaction (always `>= limit`) — an
    /// execution count, or a fuel / token sum for those caps.
    pub used: i64,
    /// The policy's stored `on_budget_exceeded`, passed to the recorder.
    pub mode: String,
}

impl BudgetRefusal {
    /// The caller-facing sentence.
    #[must_use]
    pub fn message(&self) -> String {
        actor_budget_exceeded_message(self.cap.as_str(), self.limit, self.used)
    }

    /// Count the refusal and, in `alert` mode, raise the ops alert. Call it
    /// AFTER the row-creation transaction has rolled back.
    pub async fn record(&self, pool: &sqlx::PgPool) {
        crate::record_actor_budget_refusal(
            pool,
            self.actor_id,
            self.cap,
            self.limit,
            self.used,
            &self.mode,
        )
        .await;
    }
}

/// The answer to "may this actor start another execution now?".
///
/// `#[must_use]` and a two-armed enum rather than a `bool`, for
/// `ConcurrencyAdmission`'s reason: a forgotten refusal would dispatch.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetAdmission {
    /// No cap refuses, or the actor has no budget policy. The per-actor
    /// advisory lock is HELD until the caller's transaction ends, so the
    /// caller's INSERT is atomic with this check.
    Admitted,
    /// A cap refuses. The caller must roll back, then [`BudgetRefusal::record`].
    Refused(BudgetRefusal),
}

/// Take the per-actor advisory lock and evaluate all five caps inside the
/// caller's transaction.
///
/// `conn` MUST be a transaction the caller will INSERT the execution row on
/// (or, for retry, reset the row on): the lock is transaction-scoped, and
/// the counts are only atomic with a write made before that transaction ends.
///
/// The caps run in the order the backstop always ran them — per-minute,
/// per-hour, total, fuel per hour, tokens per day — so the refused cap a
/// caller reports is the same whichever path refused it.
pub async fn admit_actor_budget(
    conn: &mut PgConnection,
    actor_id: Uuid,
) -> sqlx::Result<BudgetAdmission> {
    admit_actor_budget_for(conn, actor_id, 1).await
}

/// [`admit_actor_budget`] for a BATCH of `starts` executions admitted
/// together (`enqueue_workflow`). The three COUNT caps refuse when
/// `count + starts > limit` — for one start exactly the single rule
/// `count >= limit` — so a batch cannot carry an actor past its cap in one
/// statement; the whole batch is refused, matching the batch-aware pre-check
/// (MCP-566). The fuel and token caps measure spend already RECORDED, which a
/// batch has not incurred yet, so they refuse on `used >= limit` whatever
/// `starts` is.
pub async fn admit_actor_budget_for(
    conn: &mut PgConnection,
    actor_id: Uuid,
    starts: i64,
) -> sqlx::Result<BudgetAdmission> {
    let starts = starts.max(1);
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(actor_advisory_lock_key(actor_id))
        .execute(&mut *conn)
        .await?;

    // `max_executions_total` is BIGINT: decoding it as i32 made every start of
    // an actor with a lifetime cap fail with a decode error (package CD).
    let policy: Option<(
        Option<i32>,
        Option<i64>,
        Option<i32>,
        Option<i64>,
        Option<i64>,
        String,
    )> = sqlx::query_as(
        "SELECT max_executions_per_hour, max_executions_total, \
             max_workflows_per_minute, max_fuel_per_hour, max_llm_tokens_per_day, \
             on_budget_exceeded \
             FROM actor_budget_policies WHERE actor_id = $1",
    )
    .bind(actor_id)
    .fetch_optional(&mut *conn)
    .await?;

    let Some((per_hour, total, per_minute, fuel_per_hour, llm_tokens_per_day, mode)) = policy
    else {
        return Ok(BudgetAdmission::Admitted);
    };
    let refuse = |cap: BudgetCap, limit: i64, used: i64| {
        BudgetAdmission::Refused(BudgetRefusal {
            actor_id,
            cap,
            limit,
            used,
            mode: mode.clone(),
        })
    };

    // Per-minute trigger-rate cap. Counts only rows that carry this actor_id.
    // In-process sub-workflow dispatch creates no execution rows. Chain rows
    // DO count: since Phase D2 `insert_chain_execution_row` stamps the
    // gate-resolved actor, and since package CK it runs this check too (the
    // comment this replaced said chain rows carried no actor — stale for
    // months, and the reason the first CK survey missed that path).
    if let Some(limit) = per_minute {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM workflow_executions \
             WHERE actor_id = $1 AND started_at > now() - INTERVAL '1 minute'",
        )
        .bind(actor_id)
        .fetch_one(&mut *conn)
        .await?;
        if count + starts > i64::from(limit) {
            return Ok(refuse(BudgetCap::PerMinute, i64::from(limit), count));
        }
    }
    if let Some(limit) = per_hour {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM workflow_executions \
             WHERE actor_id = $1 AND started_at > now() - INTERVAL '1 hour'",
        )
        .bind(actor_id)
        .fetch_one(&mut *conn)
        .await?;
        if count + starts > i64::from(limit) {
            return Ok(refuse(BudgetCap::PerHour, i64::from(limit), count));
        }
    }
    if let Some(limit) = total {
        // LIFETIME cap, so it counts the archive tier too (#746): a live-only
        // count reset this budget every archive window.
        let count: i64 = sqlx::query_scalar(
            "SELECT (SELECT COUNT(*) FROM workflow_executions WHERE actor_id = $1) \
                  + (SELECT COUNT(*) FROM workflow_executions_archive WHERE actor_id = $1)",
        )
        .bind(actor_id)
        .fetch_one(&mut *conn)
        .await?;
        if count + starts > limit {
            return Ok(refuse(BudgetCap::Total, limit, count));
        }
    }
    // Rolling per-hour FUEL cap over execution_cost_rollup. `::bigint` is
    // required: SUM(bigint) returns NUMERIC, which sqlx cannot decode as i64.
    if let Some(limit) = fuel_per_hour {
        let used: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(fuel_consumed), 0)::bigint FROM execution_cost_rollup \
             WHERE actor_id = $1 AND recorded_at > now() - INTERVAL '1 hour'",
        )
        .bind(actor_id)
        .fetch_one(&mut *conn)
        .await?;
        if used >= limit {
            return Ok(refuse(BudgetCap::FuelPerHour, limit, used));
        }
    }
    // Rolling daily LLM token ceiling over the `llm_usage` ledger.
    if let Some(limit) = llm_tokens_per_day {
        let used: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(prompt_tokens + completion_tokens), 0)::bigint \
             FROM llm_usage \
             WHERE actor_id = $1 AND recorded_at > now() - INTERVAL '24 hours'",
        )
        .bind(actor_id)
        .fetch_one(&mut *conn)
        .await?;
        if used >= limit {
            return Ok(refuse(BudgetCap::LlmTokensPerDay, limit, used));
        }
    }
    Ok(BudgetAdmission::Admitted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_key_is_deterministic_and_distinct() {
        let a = Uuid::parse_str("d8aaa59a-bab7-4a7e-9c21-8ba041543403").unwrap();
        let b = Uuid::parse_str("cd4ac0f1-9a4b-425b-9434-c0dda50e0049").unwrap();
        assert_eq!(actor_advisory_lock_key(a), actor_advisory_lock_key(a));
        assert_ne!(actor_advisory_lock_key(a), actor_advisory_lock_key(b));
        assert_eq!(actor_advisory_lock_key(Uuid::nil()), 0);
    }

    #[test]
    fn every_cap_has_its_own_wording() {
        for cap in BudgetCap::ALL {
            let r = BudgetRefusal {
                actor_id: Uuid::nil(),
                cap: *cap,
                limit: 10,
                used: 12,
                mode: "block".into(),
            };
            let m = r.message();
            assert!(m.contains("12") && m.contains("10"), "{cap:?}: {m}");
            match cap {
                BudgetCap::FuelPerHour => assert!(m.contains("fuel")),
                BudgetCap::LlmTokensPerDay => assert!(m.contains("tokens")),
                BudgetCap::PerMinute => assert!(m.contains("last minute")),
                BudgetCap::PerHour => assert!(m.contains("last hour")),
                BudgetCap::Total => assert!(m.contains("total")),
            }
        }
    }
}
