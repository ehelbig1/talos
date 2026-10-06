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

mod admission;
pub use admission::{
    actor_advisory_lock_key, actor_budget_exceeded_message, actor_budget_headroom,
    admit_actor_budget, admit_actor_budget_for, executions_last_hour, executions_last_minute,
    fuel_last_hour, lifetime_executions, llm_tokens_last_24h, BudgetAdmission, BudgetHeadroom,
    BudgetRefusal, CapUse,
};

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

/// The ops-alert dedup key for "this actor was suspended by its budget" —
/// one per actor, under the reserved `talos/` prefix, and NOT under
/// `…/budget/`: it is a state the actor is in, not one more refusal.
#[must_use]
pub fn suspension_alert_dedup_key(actor_id: Uuid) -> String {
    format!("talos/actor/{actor_id}/suspended")
}

/// The ops alert raised when a budget SUSPENDS an actor. Identifiers and
/// counts only. `high`: from this moment every start on the actor is refused
/// until a person resumes it.
#[must_use]
pub fn suspension_alert(actor_id: Uuid, cap: BudgetCap, limit: i64, count: i64) -> NewOpsAlert {
    NewOpsAlert {
        source: "talos".to_string(),
        external_id: None,
        dedup_key: suspension_alert_dedup_key(actor_id),
        title: format!(
            "Actor suspended by its budget ({}): {count} against a limit of {limit}. \
             Every start on it is refused until it is resumed",
            cap.as_str()
        ),
        resource: Some(format!("actor:{actor_id}")),
        severity_raw: None,
        severity_hint: Some("high".to_string()),
        raw: Some(serde_json::json!({
            "actor_id": actor_id,
            "cap": cap.as_str(),
            "limit": limit,
            "count": count,
            "on_budget_exceeded": "suspend",
            "resume_with": "update_actor_status(actor_id, \"active\")",
        })),
    }
}

/// Record that a budget has just SUSPENDED `actor_id` — call it only when the
/// suspension is this call's doing (the row went `active` → `suspended`).
///
/// Measured 2026-10-05: an actor reached its hourly cap under
/// `on_budget_exceeded = suspend`, was suspended, and every workflow bound to
/// it was refused for 1 h 45 min. Nothing said so — a suspension was a status
/// column and, on each refused start, a WARN in the controller log. The
/// refusals were counted (`talos_actor_budget_refusals_total`), but a refusal
/// counter cannot tell "one start too many" from "nothing runs any more".
///
/// Not throttled: a suspended actor is refused by its status before any
/// budget is read, so this is reached once per suspension. Like the refusal
/// recorder it never fails — an unreadable actor or a failed write logs a
/// WARN and the suspension stands.
pub async fn record_actor_budget_suspension(
    pool: &PgPool,
    actor_id: Uuid,
    cap: BudgetCap,
    limit: i64,
    count: i64,
) {
    let (user_id, org_id) = match talos_ops_alert_store::actor_tenancy(pool, actor_id).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            tracing::warn!(
                target: "talos_audit",
                event_kind = "actor_suspension_alert_not_raised",
                %actor_id,
                reason = "no_such_actor",
                "suspension alert not raised: the actor row is gone"
            );
            return;
        }
        Err(e) => {
            tracing::warn!(
                target: "talos_audit",
                event_kind = "actor_suspension_alert_not_raised",
                %actor_id,
                reason = "tenancy_unreadable",
                error = %e,
                "suspension alert not raised: the actor's tenancy could not be read"
            );
            return;
        }
    };
    if let Err(e) = talos_ops_alert_store::ingest(
        pool,
        user_id,
        org_id,
        suspension_alert(actor_id, cap, limit, count),
    )
    .await
    {
        tracing::warn!(
            target: "talos_audit",
            event_kind = "actor_suspension_alert_not_raised",
            %actor_id,
            reason = e.metric_label(),
            error = %e,
            "suspension alert not raised: the ops_alerts write failed"
        );
    }
}

/// Close the suspension alert of an actor that has just been RESUMED. Takes
/// the caller's executor so it can run inside the same tenant-scoped
/// transaction as the status change. Returns whether an alert was open.
pub async fn resolve_actor_suspension_alert<'e, E>(
    executor: E,
    user_id: Uuid,
    actor_id: Uuid,
) -> sqlx::Result<bool>
where
    E: sqlx::PgExecutor<'e>,
{
    talos_ops_alert_store::resolve_by_dedup_key(
        executor,
        user_id,
        &suspension_alert_dedup_key(actor_id),
    )
    .await
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
    fn the_suspension_alert_is_one_reserved_key_per_actor_outside_the_refusal_keys() {
        let actor = Uuid::new_v4();
        let alert = suspension_alert(actor, BudgetCap::PerHour, 40, 41);
        assert_eq!(alert.source, "talos");
        assert_eq!(alert.dedup_key, format!("talos/actor/{actor}/suspended"));
        assert_eq!(alert.dedup_key, suspension_alert_dedup_key(actor));
        // A refusal alert of the same actor is a different row.
        assert_ne!(
            alert.dedup_key,
            budget_alert(actor, BudgetCap::PerHour, 40, 41).dedup_key
        );
        assert_ne!(
            suspension_alert_dedup_key(actor),
            suspension_alert_dedup_key(Uuid::new_v4())
        );
        assert_eq!(alert.severity_hint.as_deref(), Some("high"));
        assert_eq!(alert.resource.as_deref(), Some(&*format!("actor:{actor}")));
        assert!(
            alert.title.contains("41 against a limit of 40"),
            "{}",
            alert.title
        );
        assert!(alert.title.contains("per_hour"), "{}", alert.title);
        // Identifiers and counts only.
        let raw = alert.raw.expect("raw");
        let mut keys: Vec<_> = raw.as_object().expect("object").keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "actor_id",
                "cap",
                "count",
                "limit",
                "on_budget_exceeded",
                "resume_with"
            ]
        );
    }

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
