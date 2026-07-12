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
    evaluate_policy, LifecycleService, LifecycleState, PolicyInputs, PolicyJson,
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
    // Candidates: models with a non-empty policy and a dataset,
    // LEAST-recently-VISITED first (review 2026-07-11: ordering by
    // dataset heat let 25 hot DISTILL datasets permanently starve every
    // other model from its drift check). `last_policy_eval_at` is
    // stamped on EVERY completed visit — including drift-only and
    // skip-unchanged visits — so the LIMIT window rotates fairly.
    let rows = sqlx::query(
        "SELECT m.id, m.user_id, m.org_id, m.name, m.dataset_id, m.lifecycle_state, \
                m.policy_json, m.config_json, m.last_policy_eval_at, \
                d.updated_at AS dataset_updated_at \
         FROM ml_models m JOIN ml_datasets d ON d.id = m.dataset_id \
         WHERE m.policy_json <> '{}'::jsonb \
         ORDER BY m.last_policy_eval_at ASC NULLS FIRST, m.id LIMIT $1",
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
    // Visit stamp FIRST, on the POOL (autocommit, not this tx): it must
    // survive an eval that aborts the tx (review 2026-07-11: stamping
    // on the same tx after a SQL-level eval failure hits "current
    // transaction is aborted", losing the stamp and hot-looping the
    // full eval every tick). The stamp doubles as the rotation cursor;
    // the eval-decision below uses the PRE-visit value from the scan.
    stamp_last_eval_pool(pool, model_id).await;

    // ── Drift guard (fail-safe demote) ──────────────────────────────
    if matches!(state, LifecycleState::Hybrid | LifecycleState::FastPrimary) {
        if let Some(floor) = policy.demote_below_agreement {
            let min_total = policy.min_shadow_total.unwrap_or(DEFAULT_MIN_SHADOW_TOTAL);
            let serving_threshold = config_json
                .get("confidence_threshold")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            // Bands are tenths; CEIL the threshold to a band boundary
            // so the drift pool is a SUBSET of what production actually
            // serves — flooring would dilute the signal with
            // sub-threshold predictions users never see (review
            // 2026-07-11). 0.75 → band 8 ([0.8, ...)); a clean tenth
            // maps to its own band.
            let min_band = ((serving_threshold.clamp(0.0, 1.0) * 10.0).ceil() as i16).min(10);
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
                        // Drop THIS process's cached serving config so
                        // the demoted state takes effect on the local RPC
                        // path immediately rather than at the 15 s TTL —
                        // the serving gate keys on the cached
                        // lifecycle_state. Invalidation is process-local
                        // (same as promote/advance); on other controller
                        // replicas a drifted hybrid model can still serve
                        // for up to the 15 s TTL after this demote. That
                        // bound is acceptable for a fail-safe demote and
                        // matches every other transition path.
                        invalidate_serving_cache(user_id, &name);
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

    // ── Policy re-eval — only on dataset change, debounced ──────────
    // fast_primary is governed by the drift guard alone (RFC: LLM only
    // runs on fallback there; re-eval resumes if it demotes). The
    // debounce bounds eval churn for actively-distilling models: the
    // DISTILL hook touches ml_datasets.updated_at on every production
    // call, and each eval rewrites every row's split + scans the whole
    // holdout — once per ML_POLICY_EVAL_MIN_INTERVAL_SECS (default 1 h)
    // is governance-fresh without the per-tick full-dataset churn.
    let now = chrono::Utc::now();
    let min_eval_interval = chrono::Duration::seconds(
        std::env::var("ML_POLICY_EVAL_MIN_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|v| *v >= 0)
            .unwrap_or(3600),
    );
    let unchanged = last_eval.map(|t| dataset_updated <= t).unwrap_or(false);
    let debounced = last_eval
        .map(|t| now - t < min_eval_interval)
        .unwrap_or(false);
    if state == LifecycleState::FastPrimary || unchanged || debounced {
        tx.commit().await.ok();
        return Ok(true);
    }

    let k = config_json
        .get("k")
        .and_then(|v| v.as_i64())
        .unwrap_or(DEFAULT_KNN_K)
        .clamp(1, 50);
    // Evaluate EVERY backend on one shared split and take the highest
    // macro-F1 winner — the policy then gates on the BEST backend's report,
    // and an auto-advance promotes that backend's version (+ artifact).
    let candidates = match crate::eval::run_backend_selection_eval(
        dataset_service,
        &mut tx,
        dataset_id,
        k,
        EVAL_HOLDOUT_FRACTION,
        crate::linear::FitOpts::default(),
    )
    .await
    {
        Ok(c) if !c.is_empty() => c,
        Ok(_) => {
            drop(tx);
            tracing::info!(%model_id, "policy eval produced no backend candidates");
            return Ok(true);
        }
        Err(e) => {
            // Not enough data / embedder down / SQL failure. The visit
            // stamp already landed on the pool (pre-eval), so a
            // possibly-poisoned tx here can't hot-loop the model —
            // drop it and surface. NEVER advances (fail-safe).
            drop(tx);
            tracing::info!(%model_id, error = %e, "policy eval not runnable yet");
            return Ok(true);
        }
    };
    let winner = &candidates[0];
    let report = &winner.report;

    let class_counts = dataset_service.class_counts(&mut tx, dataset_id).await?;
    let total_examples: i64 = class_counts.values().sum();
    let dataset_classes: Vec<String> = class_counts.keys().cloned().collect();
    let corrections = dataset_service
        .corrections_per_class(&mut tx, dataset_id)
        .await?;
    let decision = evaluate_policy(
        &policy,
        &PolicyInputs {
            report,
            total_examples,
            corrections_per_class: &corrections,
            dataset_classes: &dataset_classes,
        },
    );

    // Record the winning backend as a version (same shape as ml_eval_model)
    // so the model card carries the evidence + the backend comparison.
    let mut metrics = serde_json::json!({
        "backend": winner.backend,
        "holdout_fraction": EVAL_HOLDOUT_FRACTION,
        "report": winner.report.clone(),
        "policy_decision": {"satisfied": decision.satisfied, "unmet": decision.unmet},
        "evaluator": "scheduled",
        "selected_backend": winner.backend,
        "backend_comparison": candidates
            .iter()
            .map(|c| serde_json::json!({
                "backend": c.backend,
                "macro_recall": c.macro_recall,
                "macro_f1": c.macro_f1,
            }))
            .collect::<Vec<_>>(),
    });
    if let (Some(obj), Some(p)) = (metrics.as_object_mut(), winner.params.as_object()) {
        for (kk, vv) in p {
            obj.insert(kk.clone(), vv.clone());
        }
    }
    let version = ModelRegistry::create_version(
        &mut tx,
        model_id,
        user_id,
        org_id,
        winner.backend,
        winner.artifact.as_deref(),
        &metrics,
    )
    .await
    .context("record evaluator version")?;

    let next = state.next();
    if decision.satisfied && policy.auto_advance {
        if let Some(to) = next {
            ModelRegistry::promote_version(&mut tx, model_id, version.id).await?;
            let swapped = lifecycle_service
                .transition(&mut tx, model_id, user_id, state, to)
                .await?;
            if !swapped {
                // Lost the CAS to a concurrent manual command: roll the
                // WHOLE tx back (promote included) — promote+advance is
                // one atomic decision, and committing half of it would
                // silently swap production_version_id under whatever
                // state the operator just chose (review 2026-07-11).
                // The eval version is re-recorded on the next visit.
                drop(tx);
                tracing::warn!(
                    target: "talos_ml",
                    %model_id,
                    "auto-advance lost the state CAS; promote rolled back"
                );
                return Ok(true);
            }
            tx.commit().await?;
            {
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

/// Visit stamp on the pool (autocommit): rotation cursor + hot-loop
/// guard. Failure is non-fatal (WARN) — worst case the model is
/// revisited next tick.
async fn stamp_last_eval_pool(pool: &PgPool, model_id: Uuid) {
    if let Err(e) = sqlx::query("UPDATE ml_models SET last_policy_eval_at = NOW() WHERE id = $1")
        .bind(model_id)
        .execute(pool)
        .await
    {
        tracing::warn!(%model_id, error = %e, "failed to stamp last_policy_eval_at");
    }
}
