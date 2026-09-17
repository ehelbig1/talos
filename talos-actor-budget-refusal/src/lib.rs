//! The one recorder for an actor-budget refusal (package CD, 2026-09-17).
//!
//! `actor_budget_policies.on_budget_exceeded` admits `suspend`, `alert` and
//! `block`. Until this package `alert` raised no alert: every mode refused the
//! start, `suspend` also suspended the actor (hourly cap only), and `alert`
//! behaved exactly as `block`. A refusal was a returned error string and
//! nothing else — no series, no record.
//!
//! Every site that DECIDES a refusal now calls [`record_actor_budget_refusal`]:
//! the atomic backstop at execution-row creation and the two pre-checks. It
//! increments `talos_actor_budget_refusals_total{cap, mode}` for every mode,
//! and for `alert` it upserts one ops alert per actor and cap
//! (`talos/actor/<id>/budget/<cap>` — a repeat bumps `occurrence_count`, a
//! resolved alert reopens). Hard limits are unchanged: the start is refused
//! in every mode, and this function never decides anything.
//!
//! **A refusal loop must not become a write storm.** An actor at its cap can be
//! refused many times a second, so the alert write is throttled in-process to
//! one per actor and cap per [`ALERT_REPEAT_WINDOW`]; the counter still moves
//! on every refusal. The throttle is per PROCESS (a fleet of N controllers may
//! write N times per window) and its map is bounded.
//!
//! **Recording must not change the refusal.** An unreadable actor or a failed
//! write logs a WARN and returns; the caller refuses regardless.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use sqlx::PgPool;
use talos_ops_alert_store::NewOpsAlert;
use uuid::Uuid;

pub use talos_metrics::{BudgetCap, BudgetMode};

/// Minimum interval between two alert writes for one actor and cap.
pub const ALERT_REPEAT_WINDOW: Duration = Duration::from_secs(60);

/// Entries kept by the throttle before it is cleared.
const THROTTLE_MAX_ENTRIES: usize = 10_000;

/// The ops-alert dedup key for an actor's cap — under the reserved `talos/`
/// prefix modules cannot write into.
#[must_use]
pub fn budget_alert_dedup_key(actor_id: Uuid, cap: BudgetCap) -> String {
    format!("talos/actor/{actor_id}/budget/{}", cap.as_str())
}

/// The ops alert raised for one refusal. Carries identifiers and counts only.
#[must_use]
pub fn budget_alert(actor_id: Uuid, cap: BudgetCap, limit: i64, count: i64) -> NewOpsAlert {
    let what = match cap {
        BudgetCap::PerMinute => "executions in the last minute",
        BudgetCap::PerHour => "executions in the last hour",
        BudgetCap::Total => "executions in total",
        BudgetCap::FuelPerHour => "fuel in the last hour",
        BudgetCap::LlmTokensPerDay => "LLM tokens in the last 24 hours",
    };
    NewOpsAlert {
        source: "talos".to_string(),
        external_id: None,
        dedup_key: budget_alert_dedup_key(actor_id, cap),
        title: format!(
            "Actor budget exceeded ({}): {count} {what}, limit {limit}",
            cap.as_str()
        ),
        resource: Some(format!("actor:{actor_id}")),
        severity_raw: None,
        severity_hint: Some("medium".to_string()),
        raw: Some(serde_json::json!({
            "actor_id": actor_id,
            "cap": cap.as_str(),
            "limit": limit,
            "count": count,
            "on_budget_exceeded": "alert",
        })),
    }
}

/// Whether an alert write for `key` is admitted at `now`, recording it if so.
/// Pure over the map so the window and the bound are unit-tested.
fn throttle_admits(
    map: &mut HashMap<(Uuid, BudgetCap), Instant>,
    key: (Uuid, BudgetCap),
    now: Instant,
    window: Duration,
    max_entries: usize,
) -> bool {
    if let Some(last) = map.get(&key) {
        if now.saturating_duration_since(*last) < window {
            return false;
        }
    }
    if map.len() >= max_entries && !map.contains_key(&key) {
        map.clear();
    }
    map.insert(key, now);
    true
}

fn throttle() -> &'static Mutex<HashMap<(Uuid, BudgetCap), Instant>> {
    static T: OnceLock<Mutex<HashMap<(Uuid, BudgetCap), Instant>>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Record one refused start. `mode_raw` is the policy's stored
/// `on_budget_exceeded`. Never fails: see the crate docs.
pub async fn record_actor_budget_refusal(
    pool: &PgPool,
    actor_id: Uuid,
    cap: BudgetCap,
    limit: i64,
    count: i64,
    mode_raw: &str,
) {
    let Some(mode) = BudgetMode::parse(mode_raw) else {
        tracing::warn!(
            target: "talos_audit",
            event_kind = "actor_budget_mode_unrecognised",
            %actor_id,
            cap = cap.as_str(),
            mode = mode_raw,
            "actor budget refused a start under an on_budget_exceeded value the column CHECK \
             should not admit; the refusal stands and nothing else is recorded"
        );
        return;
    };
    talos_metrics::record_actor_budget_refusal(cap, mode);
    if mode != BudgetMode::Alert {
        return;
    }
    let admitted = {
        let mut map = throttle()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        throttle_admits(
            &mut map,
            (actor_id, cap),
            Instant::now(),
            ALERT_REPEAT_WINDOW,
            THROTTLE_MAX_ENTRIES,
        )
    };
    if !admitted {
        return;
    }
    let tenancy = match talos_ops_alert_store::actor_tenancy(pool, actor_id).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            tracing::warn!(
                target: "talos_audit",
                event_kind = "actor_budget_alert_not_raised",
                %actor_id,
                cap = cap.as_str(),
                reason = "no_such_actor",
                "budget alert not raised: the actor row is gone"
            );
            return;
        }
        Err(e) => {
            tracing::warn!(
                target: "talos_audit",
                event_kind = "actor_budget_alert_not_raised",
                %actor_id,
                cap = cap.as_str(),
                reason = "tenancy_unreadable",
                error = %e,
                "budget alert not raised: the actor's tenancy could not be read"
            );
            return;
        }
    };
    let (user_id, org_id) = tenancy;
    if let Err(e) = talos_ops_alert_store::ingest(
        pool,
        user_id,
        org_id,
        budget_alert(actor_id, cap, limit, count),
    )
    .await
    {
        tracing::warn!(
            target: "talos_audit",
            event_kind = "actor_budget_alert_not_raised",
            %actor_id,
            cap = cap.as_str(),
            reason = e.metric_label(),
            error = %e,
            "budget alert not raised: the ops_alerts write failed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throttle_admits_once_per_window_per_actor_and_cap() {
        let mut map = HashMap::new();
        let t0 = Instant::now();
        let a = Uuid::new_v4();
        let w = Duration::from_secs(60);
        assert!(throttle_admits(
            &mut map,
            (a, BudgetCap::PerHour),
            t0,
            w,
            100
        ));
        assert!(!throttle_admits(
            &mut map,
            (a, BudgetCap::PerHour),
            t0 + Duration::from_secs(59),
            w,
            100
        ));
        // another cap and another actor are independent
        assert!(throttle_admits(&mut map, (a, BudgetCap::Total), t0, w, 100));
        assert!(throttle_admits(
            &mut map,
            (Uuid::new_v4(), BudgetCap::PerHour),
            t0,
            w,
            100
        ));
        assert!(throttle_admits(
            &mut map,
            (a, BudgetCap::PerHour),
            t0 + w,
            w,
            100
        ));
    }

    #[test]
    fn throttle_map_is_bounded() {
        let mut map = HashMap::new();
        let t0 = Instant::now();
        for _ in 0..5 {
            assert!(throttle_admits(
                &mut map,
                (Uuid::new_v4(), BudgetCap::Total),
                t0,
                Duration::from_secs(60),
                5
            ));
        }
        assert_eq!(map.len(), 5);
        assert!(throttle_admits(
            &mut map,
            (Uuid::new_v4(), BudgetCap::Total),
            t0,
            Duration::from_secs(60),
            5
        ));
        assert_eq!(map.len(), 1, "a full map is cleared, never grown");
    }

    #[test]
    fn the_alert_names_the_cap_and_counts_and_is_keyed_per_actor_and_cap() {
        let a = Uuid::new_v4();
        let alert = budget_alert(a, BudgetCap::LlmTokensPerDay, 1000, 1200);
        assert_eq!(
            alert.dedup_key,
            format!("talos/actor/{a}/budget/llm_tokens_per_day")
        );
        assert!(alert.title.contains("1200 LLM tokens"), "{}", alert.title);
        assert!(alert.title.contains("limit 1000"), "{}", alert.title);
        assert_ne!(
            budget_alert_dedup_key(a, BudgetCap::PerHour),
            budget_alert_dedup_key(a, BudgetCap::Total)
        );
        assert!(
            talos_ops_alert_store::sanitize(alert).is_ok(),
            "the alert passes ingest validation"
        );
    }
}
