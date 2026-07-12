//! RFC 0011 P2d — the scheduled policy evaluator.
//!
//! A bounded background job (integration_state-sweeper shape: interval
//! + `MissedTickBehavior::Delay` + `select!`-on-shutdown) that drives
//! the lifecycle state machine from data instead of manual runs:
//!
//! - **Drift guard (every tick, cheap)**: models in hybrid/fast_primary
//!   with `demote_below_agreement` configured are DEMOTED one step when
//!   rolling shadow agreement (at/above the serving-threshold band)
//!   falls below the floor — but only once `min_shadow_total`
//!   observations exist. Fail-safe direction: missing data can never
//!   promote; only PRESENT bad data demotes.
//! - **Policy re-eval (only on dataset change)**: when the dataset's
//!   `updated_at` has passed `last_policy_eval_at`, run the eval
//!   harness (records a version, same as `ml_eval_model`), judge the
//!   typed policy, and — only when `auto_advance: true` — promote the
//!   fresh version and advance ONE lifecycle step. `auto_advance:
//!   false` records the satisfied policy in the audit log and leaves
//!   the promote button to a human.
//!
//! Bounds: per-tick model scan is LIMIT-capped; each model's work runs
//! under a `pg_try_advisory_xact_lock` (skip-if-held, so two replicas
//! never double-eval); eval itself takes the dataset advisory lock.
//! Every transition is audit-logged to `admin_event_log` and surfaced
//! at WARN under `target: "talos_ml"` for ops dashboards.

use anyhow::{Context, Result};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::dataset::DatasetService;
use crate::lifecycle::{
    confidence_band, evaluate_policy, LifecycleService, LifecycleState, PolicyInputs, PolicyJson,
};
use crate::registry::ModelRegistry;
use crate::serve::{invalidate_serving_cache, DEFAULT_KNN_K};

const DEFAULT_INTERVAL_SECS: u64 = 600;
/// Per-tick model cap — backlog catches up over subsequent ticks.
const MODELS_PER_TICK: i64 = 25;
const DEFAULT_MIN_SHADOW_TOTAL: i64 = 50;
const EVAL_HOLDOUT_FRACTION: f64 = 0.2;

/// Audit-log helper. `admin_event_log` is append-only; summaries here
/// are BUILT from fixed strings + model names/states (no user content),
/// so no DLP pass is needed — do not interpolate example text into
/// them. WARN-level tracing doubles as the ops notification.
async fn audit_transition(
    pool: &PgPool,
    user_id: Uuid,
    model_id: Uuid,
    event_type: &str,
    summary: String,
    details: serde_json::Value,
) {
    tracing::warn!(target: "talos_ml", %model_id, event = event_type, "{summary}");
    if let Err(e) = sqlx::query(
        "INSERT INTO admin_event_log (user_id, event_type, resource_type, resource_id, \
         summary, details) VALUES ($1, $2, 'ml_model', $3, $4, $5)",
    )
    .bind(user_id)
    .bind(event_type)
    .bind(model_id)
    .bind(&summary)
    .bind(&details)
    .execute(pool)
    .await
    {
        tracing::warn!(error = %e, "failed to audit-log lifecycle event (non-fatal)");
    }
}

/// Spawn the evaluator loop. Interval from `ML_POLICY_EVAL_INTERVAL_SECS`
/// (default 600 s); observes the shared background-shutdown watch.
pub fn spawn_policy_evaluator(
    pool: PgPool,
    dataset_service: DatasetService,
    lifecycle_service: std::sync::Arc<LifecycleService>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let interval_secs = std::env::var("ML_POLICY_EVAL_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v >= 30)
        .unwrap_or(DEFAULT_INTERVAL_SECS);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tracing::info!(interval_secs, "ml policy evaluator active");
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    tracing::info!("ml policy evaluator shutting down");
                    break;
                }
                _ = interval.tick() => {
                    match run_policy_tick(&pool, &dataset_service, &lifecycle_service).await {
                        Ok(evaluated) if evaluated > 0 => {
                            tracing::info!(evaluated, "ml policy tick complete");
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(error = %e, "ml policy tick failed; retrying next interval");
                        }
                    }
                }
            }
        }
    });
}

/// One bounded tick. Public so an integration test (or an operator MCP
/// tool later) can drive it deterministically.
pub async fn run_policy_tick(
    pool: &PgPool,
    dataset_service: &DatasetService,
    lifecycle_service: &LifecycleService,
) -> Result<usize> {
    // Candidates: models with a non-empty policy and a dataset. The
    // drift guard applies every tick; the eval leg is gated per model
    // on dataset change (skip-if-unchanged).
    let rows = sqlx::query(
        "SELECT m.id, m.user_id, m.org_id, m.name, m.dataset_id, m.lifecycle_state, \
                m.policy_json, m.config_json, m.last_policy_eval_at, \
                d.updated_at AS dataset_updated_at \
         FROM ml_models m JOIN ml_datasets d ON d.id = m.dataset_id \
         WHERE m.policy_json <> '{}'::jsonb \
         ORDER BY d.updated_at DESC LIMIT $1",
    )
    .bind(MODELS_PER_TICK)
    .fetch_all(pool)
    .await
    .context("scan policy-bearing models")?;

    let mut evaluated = 0usize;
    for row in rows {
        let model_id: Uuid = row.try_get("id")?;
        match evaluate_one_model(pool, dataset_service, lifecycle_service, &row).await {
            Ok(true) => evaluated += 1,
            Ok(false) => {}
            Err(e) => {
                // One broken model must not starve the rest of the tick.
                tracing::warn!(%model_id, error = %e, "policy evaluation failed for model");
            }
        }
    }
    Ok(evaluated)
}

/// Returns Ok(true) when the model was actually evaluated (lock won and
/// work done), Ok(false) on clean skips.
async fn evaluate_one_model(
    pool: &PgPool,
    dataset_service: &DatasetService,
    lifecycle_service: &LifecycleService,
    row: &sqlx::postgres::PgRow,
) -> Result<bool> {
    let model_id: Uuid = row.try_get("id")?;
    let user_id: Uuid = row.try_get("user_id")?;
    let org_id: Option<Uuid> = row.try_get("org_id")?;
    let name: String = row.try_get("name")?;
    let dataset_id: Uuid = row.try_get("dataset_id")?;
    let state = LifecycleState::parse(&row.try_get::<String, _>("lifecycle_state")?)
        .unwrap_or(LifecycleState::LlmOnly);
    let policy_raw: serde_json::Value = row.try_get("policy_json")?;
    let config_json: serde_json::Value = row.try_get("config_json")?;
    let last_eval: Option<chrono::DateTime<chrono::Utc>> = row.try_get("last_policy_eval_at")?;
    let dataset_updated: chrono::DateTime<chrono::Utc> = row.try_get("dataset_updated_at")?;

    let policy = match PolicyJson::parse(&policy_raw) {
        Ok(p) => p,
        Err(e) => {
            // A malformed policy must be LOUD (it silently disables
            // governance otherwise) but not retried into log spam every
            // tick — WARN once per tick is acceptable at 25/tick.
            tracing::warn!(%model_id, error = %e, "unparseable policy_json; model skipped");
            return Ok(false);
        }
    };

    // All work for one model inside one tenant-scoped tx guarded by a
    // per-model try-lock: a replica already evaluating skips cleanly.
    let mut tx = talos_db::begin_tenant_read_scoped(
        pool,
        &talos_tenancy::TenantReadScope::new(user_id, Vec::new()),
    )
    .await
    .context("open evaluator tx")?;
    let locked: bool = sqlx::query_scalar(
        "SELECT pg_try_advisory_xact_lock(hashtextextended('ml_policy:' || $1::text, 0))",
    )
    .bind(model_id)
    .fetch_one(&mut *tx)
    .await
    .context("try policy advisory lock")?;
    if !locked {
        return Ok(false);
    }

    // ── Drift guard (fail-safe demote) ──────────────────────────────
    if matches!(state, LifecycleState::Hybrid | LifecycleState::FastPrimary) {
        if let Some(floor) = policy.demote_below_agreement {
            let min_total = policy.min_shadow_total.unwrap_or(DEFAULT_MIN_SHADOW_TOTAL);
            let serving_threshold = config_json
                .get("confidence_threshold")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0) as f32;
            let min_band = confidence_band(Some(serving_threshold));
            if let Some((agreement, total)) = lifecycle_service
                .shadow_agreement(&mut tx, model_id, min_band)
                .await?
            {
                if total >= min_total && agreement < floor {
                    let to = match state {
                        LifecycleState::FastPrimary => LifecycleState::Hybrid,
                        _ => LifecycleState::Shadow,
                    };
                    if lifecycle_service
                        .transition(&mut tx, model_id, user_id, state, to)
                        .await?
                    {
                        tx.commit().await?;
                        audit_transition(
                            pool,
                            user_id,
                            model_id,
                            "ml_lifecycle_auto_demoted",
                            format!(
                                "Model '{name}' auto-demoted {} -> {} (shadow agreement \
                                 {agreement:.3} < {floor} over {total} observations)",
                                state.as_str(),
                                to.as_str()
                            ),
                            serde_json::json!({
                                "agreement": agreement,
                                "floor": floor,
                                "observations": total,
                                "min_band": min_band,
                            }),
                        )
                        .await;
                        return Ok(true);
                    }
                }
            }
        }
    }

    // ── Policy re-eval — only on dataset change ─────────────────────
    if state == LifecycleState::FastPrimary
        || last_eval.map(|t| dataset_updated <= t).unwrap_or(false)
    {
        tx.commit().await.ok();
        return Ok(false);
    }

    let k = config_json
        .get("k")
        .and_then(|v| v.as_i64())
        .unwrap_or(DEFAULT_KNN_K)
        .clamp(1, 50);
    let report = match crate::eval::run_knn_eval(
        dataset_service,
        &mut tx,
        dataset_id,
        k,
        EVAL_HOLDOUT_FRACTION,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            // Not enough data / embedder down: stamp the attempt so
            // we don't hot-loop on the same broken dataset, then
            // surface. NEVER advances (fail-safe).
            stamp_last_eval(&mut tx, model_id).await?;
            tx.commit().await?;
            tracing::info!(%model_id, error = %e, "policy eval not runnable yet");
            return Ok(true);
        }
    };

    let class_counts = dataset_service.class_counts(&mut tx, dataset_id).await?;
    let total_examples: i64 = class_counts.values().sum();
    let dataset_classes: Vec<String> = class_counts.keys().cloned().collect();
    let corrections = dataset_service
        .corrections_per_class(&mut tx, dataset_id)
        .await?;
    let decision = evaluate_policy(
        &policy,
        &PolicyInputs {
            report: &report,
            total_examples,
            corrections_per_class: &corrections,
            dataset_classes: &dataset_classes,
        },
    );

    // Record the eval as a version (same shape as ml_eval_model) so the
    // model card carries the evidence either way.
    let metrics = serde_json::json!({
        "backend": "knn-pgvector",
        "voting": "balanced-sqrt",
        "k": k,
        "holdout_fraction": EVAL_HOLDOUT_FRACTION,
        "report": report,
        "policy_decision": {"satisfied": decision.satisfied, "unmet": decision.unmet},
        "evaluator": "scheduled",
    });
    let version = ModelRegistry::create_version(
        &mut tx,
        model_id,
        user_id,
        org_id,
        "knn-pgvector",
        None,
        &metrics,
    )
    .await
    .context("record evaluator version")?;
    stamp_last_eval(&mut tx, model_id).await?;

    let next = state.next();
    if decision.satisfied && policy.auto_advance {
        if let Some(to) = next {
            ModelRegistry::promote_version(&mut tx, model_id, version.id).await?;
            let swapped = lifecycle_service
                .transition(&mut tx, model_id, user_id, state, to)
                .await?;
            tx.commit().await?;
            if swapped {
                invalidate_serving_cache(user_id, &name);
                audit_transition(
                    pool,
                    user_id,
                    model_id,
                    "ml_lifecycle_auto_advanced",
                    format!(
                        "Model '{name}' auto-advanced {} -> {} (policy satisfied; \
                         version {} promoted)",
                        state.as_str(),
                        to.as_str(),
                        version.version
                    ),
                    serde_json::json!({
                        "version_id": version.id.to_string(),
                        "version": version.version,
                    }),
                )
                .await;
            }
            return Ok(true);
        }
    }
    tx.commit().await?;
    if decision.satisfied {
        // auto_advance: false — human keeps the promote button; say so
        // once per dataset change (the last_policy_eval_at stamp gates
        // repeats).
        audit_transition(
            pool,
            user_id,
            model_id,
            "ml_lifecycle_policy_satisfied",
            format!(
                "Model '{name}' policy satisfied at state {} — awaiting manual \
                 ml_promote_model / lifecycle advance (auto_advance=false); \
                 evidence on version {}",
                state.as_str(),
                version.version
            ),
            serde_json::json!({"version_id": version.id.to_string()}),
        )
        .await;
    } else {
        tracing::info!(
            target: "talos_ml",
            %model_id,
            unmet = ?decision.unmet,
            "policy evaluated: gates unmet"
        );
    }
    Ok(true)
}

async fn stamp_last_eval(conn: &mut sqlx::PgConnection, model_id: Uuid) -> Result<()> {
    sqlx::query("UPDATE ml_models SET last_policy_eval_at = NOW() WHERE id = $1")
        .bind(model_id)
        .execute(conn)
        .await
        .context("stamp last_policy_eval_at")?;
    Ok(())
}
