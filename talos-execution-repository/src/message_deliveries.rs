//! `message_deliveries`: one row per send node that delivered a message.
//!
//! Written by the engine's node hook from the adapter's verdict
//! (`talos_workflow_engine_core::delivery_verdict`), read by the
//! message-engagement report (`talos_analytics_repository`). The row carries
//! identifiers and counts only; see the table's migration
//! (`20261016130000_message_deliveries.sql`) for what is deliberately not in
//! it.

use anyhow::Result;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

/// One send to record. The counts are the adapter's, already bounded by the
/// reader that produced them.
#[derive(Debug, Clone, Copy)]
pub struct MessageDelivery<'a> {
    pub workflow_id: Uuid,
    pub execution_id: Uuid,
    pub node_id: Uuid,
    pub provider: &'a str,
    pub parts_total: u32,
    pub parts_sent: u32,
    pub actions_sent: u32,
    pub one_tap_actions: u32,
    pub kept_actions: u32,
    /// How the run was started, the engine's word; `None` when unknown.
    pub started_by_kind: Option<&'a str>,
}

/// Record one delivery. Returns `false` when `workflow_id` names no workflow:
/// a run outside a workflow (the engine then passes its execution id in the
/// workflow's place) has nothing to attribute a send to, and that is not an
/// error.
pub async fn record_message_delivery(
    pool: &Pool<Postgres>,
    delivery: MessageDelivery<'_>,
) -> Result<bool> {
    let started_by_kind = delivery.started_by_kind.map(|k| {
        // The column admits 32 characters; the engine's words are far shorter.
        k.chars().take(32).collect::<String>()
    });
    let result = sqlx::query(
        "INSERT INTO message_deliveries \
             (workflow_id, execution_id, node_id, provider, parts_total, parts_sent, \
              actions_sent, one_tap_actions, kept_actions, started_by_kind) \
         SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10 \
         WHERE EXISTS (SELECT 1 FROM workflows WHERE id = $1)",
    )
    .bind(delivery.workflow_id)
    .bind(delivery.execution_id)
    .bind(delivery.node_id)
    .bind(delivery.provider)
    .bind(i32::try_from(delivery.parts_total)?)
    .bind(i32::try_from(delivery.parts_sent)?)
    .bind(i32::try_from(delivery.actions_sent)?)
    .bind(i32::try_from(delivery.one_tap_actions)?)
    .bind(i32::try_from(delivery.kept_actions)?)
    .bind(started_by_kind)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}
