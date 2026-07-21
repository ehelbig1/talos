//! Ops-alert corrections → dataset bridge (alert-triage brain Phase 2).
//!
//! When a human corrects an ops-alert's severity (MCP `correct_ops_alert_severity`,
//! the GraphQL mutation, or the one-click email link), that label is the
//! distillation GOLD signal. This module fans that correction into any ML
//! dataset that is ALREADY tracking the alert — i.e. any dataset owned by the
//! same user that already holds an `ml_examples` row whose `example_key`
//! equals the alert's `dedup_key`. The linkage is generic containment: no
//! classifier model-name is hardcoded, so the same code bridges the
//! `ops-severity` classifier and any future dataset that adopts the same
//! `example_key = dedup_key` convention.
//!
//! Design (mirrors [`crate::distill::spawn_distill_from_output`]):
//! * **Fire-and-forget.** The entry point is sync + cheap: read the shared
//!   context, `tokio::spawn`, return. A bridge failure is a WARN + metric,
//!   NEVER a failure of the correction that triggered it (the correction has
//!   already committed by the time the caller reaches here).
//! * **Reuses [`crate::distill::DISTILL_CONTEXT`].** That OnceLock is installed
//!   unconditionally at controller boot and already carries exactly what the
//!   bridge needs — the `db_pool` and the `DatasetService` (the ONLY writer, so
//!   AEAD encryption + local embedding + growth-cap eviction ride along). Until
//!   it is installed the bridge drops with a WARN (never a panic).
//! * **DLP.** The `features_text` carries the alert TITLE. Logs record counts,
//!   the user id, and error kinds ONLY — never the features text or title.
//!
//! Upsert semantics: the append is `source='correction'`, so
//! `DatasetService::insert_prepared`'s conflict rule
//! (`... WHERE ml_examples.source <> 'correction' OR EXCLUDED.source = 'correction'`)
//! lets a human correction beat a bootstrap/production label on the same key.

use anyhow::{Context, Result};
use uuid::Uuid;

use crate::dataset::{AppendExample, ExampleSource};
use crate::distill::DISTILL_CONTEXT;

/// Concurrency bound on in-flight bridge flows. Corrections are human-paced
/// (one per click) so saturation is unlikely, but each flow costs an embed +
/// AEAD round-trip; a modest cap keeps a burst of corrections from stampeding
/// the embedder. Saturation SHEDS (WARN + drop) — the correction is already
/// durable, and the bridge is best-effort enrichment.
const MAX_CONCURRENT_BRIDGE_FLOWS: usize = 4;
static BRIDGE_PERMITS: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
    std::sync::OnceLock::new();

/// The six assignable severity labels — the fixed vocabulary the bridge will
/// accept. Kept in lockstep with `talos_ops_alerts_repository::ASSIGNABLE_SEVERITIES`
/// (both derive from the same triage design); an out-of-set label is dropped
/// so a junk value can never enter a dataset via the bridge.
const ASSIGNABLE_SEVERITIES: [&str; 6] = ["critical", "high", "medium", "low", "info", "noise"];

/// Cheap, pure input guard — split out so the drop rules are unit-testable
/// without a runtime or a DB. A blank key/text or an out-of-set label is a
/// no-op (the caller already validated severity, but the bridge fails closed
/// on its own inputs rather than trusting the call site).
#[must_use]
pub(crate) fn bridge_inputs_valid(example_key: &str, features_text: &str, label: &str) -> bool {
    !example_key.trim().is_empty()
        && !features_text.trim().is_empty()
        && ASSIGNABLE_SEVERITIES.contains(&label.trim())
}

/// Entry point for the correction surfaces (MCP / GraphQL / webhook). Sync +
/// cheap: validate, read the shared context, `tokio::spawn`, return.
///
/// `example_key` is the alert's `dedup_key`; `features_text` is the canonical
/// classifier feature text (built by
/// `talos_ops_alerts_repository::canonical_features_text`); `label` is the
/// corrected severity.
pub fn spawn_ops_correction_bridge(
    user_id: Uuid,
    example_key: String,
    features_text: String,
    label: String,
) {
    if !bridge_inputs_valid(&example_key, &features_text, &label) {
        // Not an error — nothing to bridge (e.g. a caller passed a blank key).
        return;
    }
    let Some(ctx) = DISTILL_CONTEXT.get() else {
        tracing::warn!(
            target: "talos_ml",
            %user_id,
            "ops-alert correction bridge dropped: distill context not installed"
        );
        return;
    };
    let permits = BRIDGE_PERMITS.get_or_init(|| {
        std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_BRIDGE_FLOWS))
    });
    let Ok(permit) = permits.clone().try_acquire_owned() else {
        tracing::warn!(
            target: "talos_ml",
            %user_id,
            cap = MAX_CONCURRENT_BRIDGE_FLOWS,
            "ops-alert correction bridge shed: concurrent flows saturated"
        );
        return;
    };
    tokio::spawn(async move {
        let _permit = permit;
        match process_bridge(ctx, user_id, &example_key, &features_text, &label).await {
            // No dataset tracks this alert — the common case for alerts that
            // aren't wired to a classifier. Silent (not even a WARN).
            Ok(0) => {}
            Ok(datasets) => tracing::info!(
                target: "talos_ml",
                %user_id,
                datasets,
                "ops-alert correction bridged into dataset(s)"
            ),
            // Best-effort: the correction is already durable. Presence-only
            // log — NO features_text / title (DLP).
            Err(e) => tracing::warn!(
                target: "talos_ml",
                %user_id,
                error = %e,
                "ops-alert correction bridge failed (correction unaffected)"
            ),
        }
    });
}

/// The spawned flow: find datasets tracking this alert → upsert the
/// `source=correction` gold example into each. Returns the number of datasets
/// updated. Mirrors the distill append discipline: resolve under a tenant tx,
/// `prepare_examples` with NO connection held, then a short write tx per
/// dataset.
async fn process_bridge(
    ctx: &'static crate::distill::DistillContext,
    user_id: Uuid,
    example_key: &str,
    features_text: &str,
    label: &str,
) -> Result<usize> {
    // 1. Resolve candidate datasets (owner-scoped tx = RLS backstop + the
    // explicit `user_id` predicate). Containment linkage: a dataset "tracks"
    // this alert iff it already holds a row with this example_key.
    let mut tx = talos_db::begin_tenant_read_scoped(
        &ctx.db_pool,
        &talos_tenancy::TenantReadScope::new(user_id, Vec::new()),
    )
    .await
    .context("open ops-bridge resolve tx")?;
    let dataset_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT dataset_id FROM ml_examples \
         WHERE user_id = $1 AND example_key = $2",
    )
    .bind(user_id)
    .bind(example_key)
    .fetch_all(&mut *tx)
    .await
    .context("find datasets tracking the alert")?;
    // Re-confirm each dataset's ownership before writing into it (belt: the
    // example rows are user-scoped, but the write targets the DATASET).
    let mut targets: Vec<(Uuid, crate::dataset::DatasetTenancy)> = Vec::new();
    for dataset_id in dataset_ids {
        let tenancy = ctx
            .dataset_service
            .dataset_tenancy(&mut tx, dataset_id)
            .await
            .context("ops-bridge dataset tenancy")?;
        if tenancy.user_id == user_id {
            targets.push((dataset_id, tenancy));
        }
    }
    tx.commit().await.context("commit ops-bridge resolve tx")?;
    if targets.is_empty() {
        return Ok(0);
    }

    // 2. Upsert the gold correction into each tracking dataset.
    let mut updated = 0usize;
    for (dataset_id, tenancy) in targets {
        // prepare (embed + encrypt) with NO connection held — the long pole.
        let prepared = ctx
            .dataset_service
            .prepare_examples(
                dataset_id,
                tenancy,
                vec![AppendExample {
                    features_text: features_text.to_string(),
                    label: label.to_string(),
                    source: ExampleSource::Correction,
                    example_key: Some(example_key.to_string()),
                }],
            )
            .await
            .context("prepare ops-bridge correction")?;
        let mut wtx = talos_db::begin_tenant_read_scoped(
            &ctx.db_pool,
            &talos_tenancy::TenantReadScope::new(user_id, Vec::new()),
        )
        .await
        .context("open ops-bridge write tx")?;
        ctx.dataset_service
            .insert_prepared(&mut wtx, dataset_id, tenancy, prepared)
            .await
            .context("insert ops-bridge correction")?;
        wtx.commit().await.context("commit ops-bridge write tx")?;
        updated += 1;
    }
    Ok(updated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_inputs_valid_accepts_good_and_rejects_bad() {
        assert!(bridge_inputs_valid(
            "gcpmon|policy|resource",
            "Title: Disk full\nSource: gcp-monitoring",
            "critical"
        ));
        // Blank key / text / whitespace all rejected.
        assert!(!bridge_inputs_valid("", "text", "high"));
        assert!(!bridge_inputs_valid("k", "   ", "high"));
        // Out-of-set label (incl. the unassignable ingest default) rejected.
        assert!(!bridge_inputs_valid("k", "text", "unclassified"));
        assert!(!bridge_inputs_valid("k", "text", "sev1"));
        // Surrounding whitespace on the label is tolerated.
        assert!(bridge_inputs_valid("k", "text", "  noise "));
    }

    #[tokio::test]
    async fn spawn_is_a_noop_without_context_and_never_panics() {
        // With no DISTILL_CONTEXT installed (the unit-test process never boots
        // the controller), the bridge must log-and-return — it must NEVER
        // panic or propagate, so a correction can call it unconditionally.
        spawn_ops_correction_bridge(
            Uuid::new_v4(),
            "gcpmon|p|r".to_string(),
            "Title: t\nSource: s".to_string(),
            "high".to_string(),
        );
        // Invalid inputs return before even touching the context.
        spawn_ops_correction_bridge(
            Uuid::new_v4(),
            String::new(),
            String::new(),
            "bogus".to_string(),
        );
    }
}
