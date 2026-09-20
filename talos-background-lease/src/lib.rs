//! A fleet-wide lease for PERIODIC background loops.
//!
//! Every controller replica runs every background loop. For a loop whose
//! tick only tidies per-process state, or whose writes are idempotent, that
//! is harmless. For a loop whose tick has an OUTWARD effect it is not: both
//! SLA monitors POST a customer's webhook, so N replicas deliver N copies of
//! every breach notification.
//!
//! **A lock is the wrong tool.** Replicas tick at different phases, so an
//! advisory lock — which only excludes concurrent holders — is free again
//! when the second replica ticks. What a periodic loop needs is "this period
//! has been handled": a lease on the DATABASE clock, claimed with one atomic
//! upsert ([`CLAIM_SQL`]). No connection is held while the loop works, and a
//! replica that dies holding a lease simply lets it run out.
//!
//! The lease is shorter than the period by [`lease_secs`]'s slack, so the
//! replica that claimed at tick `T` can claim again at `T + period` despite
//! the round trip the first claim cost. The guarantee is therefore: **at most
//! one claim per `period - slack`**, fleet-wide.
//!
//! **Fail direction:** a claim that cannot be read is NOT a claim
//! ([`claim_tick`] returns `false`), so the loop skips that tick. Acting on
//! an unreadable lease would be every replica acting at once — the defect
//! this exists to remove, during exactly the incident that produces it.
//!
//! Not for concurrent races over one external resource (a token refresh, a
//! watch create): those need mutual exclusion for the duration of the call,
//! not once-per-period.

use prometheus::{CounterVec, Opts, Registry};
use std::sync::OnceLock;
use std::time::Duration;
use talos_task_supervision::BackgroundTask;

/// THE claim. Inserts the lease, or takes it over only if it has run out.
/// A returned row means this caller holds the period; no row means another
/// replica does. `now()` is the database's clock on both sides of the
/// comparison, so replica clock skew cannot produce two holders.
pub const CLAIM_SQL: &str = "\
    INSERT INTO background_task_leases (task, leased_until) \
    VALUES ($1, now() + make_interval(secs => $2::float8)) \
    ON CONFLICT (task) DO UPDATE \
        SET leased_until = EXCLUDED.leased_until, claimed_at = now() \
        WHERE background_task_leases.leased_until <= now() \
    RETURNING task";

/// What one claim attempt found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum LeaseOutcome {
    /// This replica holds the period: do the work.
    Claimed,
    /// Another replica holds it: skip this tick.
    HeldElsewhere,
}

/// How long a lease lasts for a loop ticking every `period`: the period minus
/// a slack of 10 %, clamped to `[1, 30]` seconds, and never below one second.
///
/// The slack is what lets the SAME replica re-claim on its next tick: it
/// claimed a round trip after tick `T`, so a full-period lease would still be
/// live at `T + period` and it would lose its own lease to nobody, halving
/// the loop's cadence on a single-replica fleet.
#[must_use]
pub fn lease_secs(period: Duration) -> f64 {
    let p = period.as_secs_f64();
    let slack = (p * 0.10).clamp(1.0, 30.0);
    (p - slack).max(1.0)
}

/// One claim attempt for `task`, whose loop ticks every `period`.
pub async fn try_claim(
    pool: &sqlx::Pool<sqlx::Postgres>,
    task: BackgroundTask,
    period: Duration,
) -> Result<LeaseOutcome, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as(CLAIM_SQL)
        .bind(task.as_str())
        .bind(lease_secs(period))
        .fetch_optional(pool)
        .await?;
    Ok(if row.is_some() {
        LeaseOutcome::Claimed
    } else {
        LeaseOutcome::HeldElsewhere
    })
}

/// The loop-side form: `true` means run this tick. Counts every attempt and
/// treats an unreadable lease as NOT claimed (see the crate docs).
pub async fn claim_tick(
    pool: &sqlx::Pool<sqlx::Postgres>,
    task: BackgroundTask,
    period: Duration,
) -> bool {
    match try_claim(pool, task, period).await {
        Ok(LeaseOutcome::Claimed) => {
            record(task, OUTCOME_CLAIMED);
            true
        }
        Ok(LeaseOutcome::HeldElsewhere) => {
            record(task, OUTCOME_HELD);
            tracing::debug!(
                task = task.as_str(),
                "background lease held by another replica; skipping this tick"
            );
            false
        }
        Err(e) => {
            record(task, OUTCOME_ERROR);
            tracing::warn!(
                target: "talos_controller",
                event_kind = "background_lease_unreadable",
                task = task.as_str(),
                error = %e,
                "background lease could not be claimed; skipping this tick rather than \
                 acting on every replica at once"
            );
            false
        }
    }
}

pub const OUTCOME_CLAIMED: &str = "claimed";
pub const OUTCOME_HELD: &str = "held";
pub const OUTCOME_ERROR: &str = "error";
/// The closed outcome set, in seeding order.
pub const OUTCOMES: [&str; 3] = [OUTCOME_CLAIMED, OUTCOME_HELD, OUTCOME_ERROR];

static CLAIMS: OnceLock<CounterVec> = OnceLock::new();

fn claims_collector() -> CounterVec {
    CounterVec::new(
        Opts::new(
            "talos_background_lease_claims_total",
            "Fleet-lease claim attempts by periodic background loops, by task and \
             outcome. 'claimed' = this replica ran the tick; 'held' = another \
             replica holds the period (the lease working; on a one-replica fleet \
             it stays 0); 'error' = the lease could not be read and the tick was \
             SKIPPED. Sum 'claimed' across replicas for the fleet's tick rate.",
        ),
        &["task", "outcome"],
    )
    .expect("static metric opts")
}

fn record(task: BackgroundTask, outcome: &'static str) {
    CLAIMS
        .get_or_init(claims_collector)
        .with_label_values(&[task.as_str(), outcome])
        .inc();
}

/// Register the claim counter and pre-seed `leased × OUTCOMES` at 0. `leased`
/// is the set of loops THIS process actually leases — seeding a task that
/// never claims would imply a signal that does not exist.
pub fn register_metrics(registry: &Registry, leased: &[BackgroundTask]) -> prometheus::Result<()> {
    let claims = CLAIMS.get_or_init(claims_collector);
    registry.register(Box::new(claims.clone()))?;
    for task in leased {
        for outcome in OUTCOMES {
            claims
                .with_label_values(&[task.as_str(), outcome])
                .inc_by(0.0);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lease_is_shorter_than_the_period_so_the_holder_can_reclaim() {
        // 5-minute loop: 10 % = 30 s slack.
        assert!((lease_secs(Duration::from_secs(300)) - 270.0).abs() < 1e-9);
        // 15-minute loop: 10 % would be 90 s; the slack is capped at 30 s.
        assert!((lease_secs(Duration::from_secs(900)) - 870.0).abs() < 1e-9);
        // Short loop: the slack floor is 1 s.
        assert!((lease_secs(Duration::from_secs(5)) - 4.0).abs() < 1e-9);
        // Never zero or negative, whatever the period.
        assert!((lease_secs(Duration::from_millis(200)) - 1.0).abs() < 1e-9);
        for secs in [1_u64, 2, 60, 300, 900, 86_400] {
            let p = Duration::from_secs(secs);
            assert!(lease_secs(p) >= 1.0);
            assert!(secs < 2 || lease_secs(p) < p.as_secs_f64(), "period {secs}");
        }
    }

    #[test]
    fn seeding_covers_exactly_the_leased_tasks() {
        let registry = Registry::new();
        register_metrics(&registry, &[BackgroundTask::SlaBreachMonitor]).expect("register");
        let families = registry.gather();
        let family = families
            .iter()
            .find(|f| f.name() == "talos_background_lease_claims_total")
            .expect("family present");
        let mut pairs: Vec<(String, String)> = family
            .get_metric()
            .iter()
            .map(|m| {
                let get = |k: &str| {
                    m.get_label()
                        .iter()
                        .find(|l| l.name() == k)
                        .map(|l| l.value().to_string())
                        .unwrap_or_default()
                };
                (get("task"), get("outcome"))
            })
            .filter(|(t, _)| t == "sla_breach_monitor")
            .collect();
        pairs.sort();
        assert_eq!(
            pairs,
            vec![
                ("sla_breach_monitor".to_string(), "claimed".to_string()),
                ("sla_breach_monitor".to_string(), "error".to_string()),
                ("sla_breach_monitor".to_string(), "held".to_string()),
            ]
        );
    }
}
