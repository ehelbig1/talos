//! ML lifecycle GraphQL queries — model-review list + disagreement feed.

use async_graphql::{Context, Object, Result, SimpleObject};
use std::sync::Arc;
use uuid::Uuid;

use super::super::{require_scope, SafeErrorExtensions};

/// One model's review summary — enough to render a list with a
/// "needs review" badge and lifecycle status.
#[derive(SimpleObject, Clone)]
pub struct MlModelSummary {
    pub id: Uuid,
    pub name: String,
    pub task_type: String,
    /// `llm_only` | `shadow` | `hybrid` | `fast_primary`.
    pub lifecycle_state: String,
    pub promoted_version: Option<i32>,
    /// Holdout accuracy of the promoted version (0–1), if promoted.
    pub promoted_accuracy: Option<f64>,
    /// Count of `pending` disagreements awaiting human review.
    pub pending_disagreements: i32,
}

/// A single pending fast-vs-LLM divergence awaiting the user's verdict.
/// `features_text` is decrypted email-derived content — same egress
/// surface as the MCP `ml_disagreements` tool, owner-only.
#[derive(SimpleObject, Clone)]
pub struct MlDisagreement {
    pub id: Uuid,
    pub example_key: Option<String>,
    pub features_text: String,
    /// `divergence` (model disagreed with the LLM) or `low_confidence`
    /// (model abstained; the LLM answered).
    pub kind: String,
    pub fast_label: Option<String>,
    pub fast_confidence: Option<f64>,
    pub llm_label: String,
    /// RFC-3339 timestamp.
    pub created_at: String,
}

/// The disagreement feed for one model, plus the lifecycle context the
/// review page shows above the queue.
#[derive(SimpleObject, Clone)]
pub struct MlDisagreementFeed {
    pub model_id: Uuid,
    pub lifecycle_state: String,
    /// Rolling shadow agreement (fast-vs-LLM, all bands), 0–1, scoped to
    /// the CURRENT shadow era — the window rotates on every lifecycle
    /// transition, version promotion, or manual reset, so this reads only
    /// evidence about the current model/teacher combination. `None` when
    /// the era has no observations yet.
    pub shadow_agreement: Option<f64>,
    pub shadow_observations: i32,
    /// Current shadow era number (increments on each window rotation) —
    /// display context for the agreement figure.
    pub shadow_epoch: i32,
    pub pending: Vec<MlDisagreement>,
    /// The latest teacher-vs-gold audit report (RFC 0011 R3), `ml_models
    /// .teacher_audit` passed through verbatim — `null` until
    /// `ml_teacher_audit` has run at least once for this model. Polymorphic
    /// on `status`: `running` ({done, gold_rows}), `failed` ({error,
    /// failed_at}), or `complete` (accuracy/per_class/parse_failed/
    /// audited_at/mismatches — see `talos_ml::teacher_audit` for the exact
    /// shape). Raw JSON passthrough (like `outputData` elsewhere in this
    /// schema) rather than a fully-typed union, since the shape varies by
    /// status and this field is read-only / display-only.
    pub teacher_audit: Option<serde_json::Value>,
}

#[derive(Default)]
pub struct MlQueries;

#[Object]
impl MlQueries {
    /// The caller's models, owner-scoped, ordered so the ones with the
    /// most pending review float to the top.
    async fn ml_models(&self, ctx: &Context<'_>) -> Result<Vec<MlModelSummary>> {
        // Scope gate (lint check 22 — sibling mutation exists). Session
        // callers pass any scope; API keys need WorkflowsRead.
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;
        let user_id = session_user(ctx)?;
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        let mut tx = open_tx(db_pool, user_id).await?;
        let rows = talos_ml::ModelRegistry::list_models_for_review(&mut tx, user_id)
            .await
            .map_err(|e| {
                tracing::error!(target: "talos_ml", error = %e, "ml_models query failed");
                async_graphql::Error::new("Could not load models").extend_safe()
            })?;
        Ok(rows
            .into_iter()
            .map(|m| MlModelSummary {
                id: m.model_id,
                name: m.name,
                task_type: m.task_type,
                lifecycle_state: m.lifecycle_state,
                promoted_version: m.promoted_version,
                promoted_accuracy: m.promoted_accuracy,
                // Clamp to i32 for the wire; counts never realistically
                // exceed i32::MAX (per-model cap is a few hundred).
                pending_disagreements: m.pending_disagreements.min(i64::from(i32::MAX)) as i32,
            })
            .collect())
    }

    /// Pending disagreements for one model (owner-scoped, decrypted),
    /// plus lifecycle + shadow context for the review header.
    async fn ml_model_disagreements(
        &self,
        ctx: &Context<'_>,
        model_name: String,
        limit: Option<i32>,
    ) -> Result<MlDisagreementFeed> {
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsRead)?;
        let user_id = session_user(ctx)?;
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;
        let secrets = ctx.data::<Arc<talos_secrets_manager::SecretsManager>>()?;
        let lifecycle = talos_ml::LifecycleService::new(secrets.clone());

        let mut tx = open_tx(db_pool, user_id).await?;
        // Owner-predicated name resolution — a foreign/absent model is an
        // indistinguishable "not found" (no cross-tenant enumeration).
        let model = talos_ml::ModelRegistry::resolve_by_name(&mut tx, &model_name, user_id)
            .await
            .map_err(|e| {
                tracing::error!(target: "talos_ml", error = %e, "resolve model");
                async_graphql::Error::new("Model not found").extend_safe()
            })?
            .ok_or_else(|| async_graphql::Error::new("Model not found").extend_safe())?;

        let limit = i64::from(limit.unwrap_or(20)).clamp(1, 100);
        let pending = lifecycle
            .pending_disagreements(&mut tx, model.model_id, user_id, limit)
            .await
            .map_err(|e| {
                tracing::error!(target: "talos_ml", error = %e, "pending_disagreements");
                async_graphql::Error::new("Could not load disagreements").extend_safe()
            })?;
        // Single shadow-agreement read for the selected model (not N+1 —
        // one call, only on the model the user is actively reviewing).
        let shadow = lifecycle
            .shadow_agreement(&mut tx, model.model_id, 0)
            .await
            .map_err(|e| {
                tracing::error!(target: "talos_ml", error = %e, "shadow_agreement");
                async_graphql::Error::new("Could not load model status").extend_safe()
            })?;

        let shadow_epoch = talos_ml::shadow_epoch(&mut tx, model.model_id)
            .await
            .map_err(|e| {
                tracing::error!(target: "talos_ml", error = %e, "shadow_epoch");
                async_graphql::Error::new("Could not load model status").extend_safe()
            })?;

        // Owner-scoped read on the same tx — same primitive the MCP
        // `ml_get_model_card` handler uses, so the two protocol surfaces
        // can't drift on what "the audit" means.
        let teacher_audit = talos_ml::stored_teacher_audit(&mut tx, model.model_id, user_id)
            .await
            .map_err(|e| {
                tracing::error!(target: "talos_ml", error = %e, "stored_teacher_audit");
                async_graphql::Error::new("Could not load model status").extend_safe()
            })?;

        Ok(MlDisagreementFeed {
            model_id: model.model_id,
            lifecycle_state: model.lifecycle_state,
            shadow_agreement: shadow.map(|(a, _)| a),
            shadow_observations: shadow
                .map(|(_, n)| n.min(i64::from(i32::MAX)) as i32)
                .unwrap_or(0),
            shadow_epoch,
            teacher_audit,
            pending: pending
                .into_iter()
                .map(|d| MlDisagreement {
                    id: d.id,
                    example_key: d.example_key,
                    features_text: d.features_text,
                    kind: d.kind,
                    fast_label: d.fast_label,
                    fast_confidence: d.fast_confidence.map(f64::from),
                    llm_label: d.llm_label,
                    created_at: d.created_at.to_rfc3339(),
                })
                .collect(),
        })
    }
}

/// Session user_id from the auth context — never a query argument.
pub(super) fn session_user(ctx: &Context<'_>) -> Result<Uuid> {
    ctx.data_opt::<Uuid>()
        .copied()
        .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())
}

/// Tenant-scoped read tx (sets `app.current_user_id` so the ml_* RLS
/// policies enforce as a backstop under the app-layer owner predicates).
pub(super) async fn open_tx(
    db_pool: &sqlx::Pool<sqlx::Postgres>,
    user_id: Uuid,
) -> Result<sqlx::Transaction<'_, sqlx::Postgres>> {
    talos_db::begin_tenant_read_scoped(
        db_pool,
        &talos_tenancy::TenantReadScope::new(user_id, Vec::new()),
    )
    .await
    .map_err(|e| {
        tracing::error!(target: "talos_ml", error = %e, "open ml tenant tx");
        async_graphql::Error::new("Request scope error").extend_safe()
    })
}
