//! ML lifecycle GraphQL mutations — resolve a disagreement (correct or
//! dismiss).

use async_graphql::{Context, Object, Result, SimpleObject};
use std::sync::Arc;
use uuid::Uuid;

use super::super::{require_2fa, require_scope, SafeErrorExtensions};

/// Outcome of resolving one disagreement.
#[derive(SimpleObject, Clone)]
pub struct MlResolveResult {
    pub disagreement_id: Uuid,
    /// `"resolved"` (a gold correction was appended) or `"dismissed"`.
    pub status: String,
    pub correction_appended: bool,
}

/// Outcome of provisioning a classifier.
#[derive(SimpleObject, Clone)]
pub struct MlProvisionResult {
    pub model_name: String,
    pub model_id: Uuid,
    pub dataset_id: Uuid,
    /// Always `llm_only` for a fresh classifier (it serves via the LLM and
    /// distills into a fast model over time).
    pub lifecycle_state: String,
    /// True when a model of this name already existed and was reused.
    pub already_existed: bool,
    /// Set when `allowExternalLlm: false` is not backed by the runtime gate
    /// that actually enforces egress — the bound actor's `max_llm_tier`.
    /// Show it to the user: the local-only intent is advisory until the
    /// actor's tier ceiling is tier1.
    pub locality_warning: Option<String>,
}

#[derive(Default)]
pub struct MlMutations;

#[Object]
impl MlMutations {
    /// Resolve one pending disagreement. `correctLabel` present → append a
    /// `source=correction` gold example (built from the disagreement's own
    /// stored features; the caller supplies only the label) and mark it
    /// resolved. Omitted/blank → dismiss. Counts toward the model's
    /// promotion policy.
    async fn resolve_ml_disagreement(
        &self,
        ctx: &Context<'_>,
        disagreement_id: Uuid,
        correct_label: Option<String>,
    ) -> Result<MlResolveResult> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;
        let user_id = super::queries::session_user(ctx)?;
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;
        let secrets = ctx.data::<Arc<talos_secrets_manager::SecretsManager>>()?;
        let lifecycle = talos_ml::LifecycleService::new(secrets.clone());
        let dataset = talos_ml::DatasetService::new(secrets.clone());

        // The whole two-tx, owner-scoped, prepare-outside-tx flow (+ all
        // six tenancy checks) lives in `talos_ml::resolve_disagreement` —
        // the ONE implementation shared with the MCP handler. This
        // resolver only maps the typed outcome/error to GraphQL.
        match talos_ml::resolve_disagreement(
            db_pool,
            &lifecycle,
            &dataset,
            disagreement_id,
            user_id,
            correct_label.as_deref(),
        )
        .await
        {
            Ok(outcome) => Ok(MlResolveResult {
                disagreement_id,
                status: outcome.status.to_string(),
                correction_appended: outcome.correction_appended,
            }),
            Err(talos_ml::ResolveError::NotFound) => Err(async_graphql::Error::new(
                "Disagreement not found or already handled",
            )
            .extend_safe()),
            Err(talos_ml::ResolveError::NoDataset) => {
                Err(async_graphql::Error::new("Model has no dataset to correct into").extend_safe())
            }
            Err(talos_ml::ResolveError::Internal(e)) => {
                tracing::error!(target: "talos_ml", error = %e, "resolve_ml_disagreement failed");
                Err(async_graphql::Error::new("Could not resolve disagreement").extend_safe())
            }
        }
    }

    /// Provision (or idempotently reuse) a classifier for a workflow node:
    /// creates the dataset + model (born `llm_only`) + a safe default
    /// promotion policy under the actor's tenancy in one owner-scoped tx, and
    /// returns the model name to stamp into the node. Backed by the SAME
    /// `talos_ml::provision_classifier` the MCP tool calls.
    #[allow(clippy::too_many_arguments)]
    async fn provision_ml_classifier(
        &self,
        ctx: &Context<'_>,
        name: String,
        labels: Vec<String>,
        actor_id: Uuid,
        fallback_provider: Option<String>,
        fallback_model: Option<String>,
        allow_external_llm: Option<bool>,
        k: Option<i32>,
        confidence_threshold: Option<f64>,
        max_examples: Option<i32>,
    ) -> Result<MlProvisionResult> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;
        let user_id = super::queries::session_user(ctx)?;
        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;
        let secrets = ctx.data::<Arc<talos_secrets_manager::SecretsManager>>()?;
        let dataset = talos_ml::DatasetService::new(secrets.clone());

        let input = talos_ml::ProvisionInput {
            name,
            labels,
            actor_id,
            fallback_provider,
            fallback_model,
            allow_external_llm: allow_external_llm.unwrap_or(false),
            k: k.map(i64::from),
            confidence_threshold,
            max_examples: max_examples.map(i64::from),
            // The GraphQL surface uses the safe default policy; the MCP tool
            // carries the advanced override for expert flows.
            policy_override: None,
        };

        match talos_ml::provision_classifier(db_pool, &dataset, input, user_id).await {
            Ok(o) => Ok(MlProvisionResult {
                model_name: o.model_name,
                model_id: o.model_id,
                dataset_id: o.dataset_id,
                lifecycle_state: o.lifecycle_state,
                already_existed: o.already_existed,
                locality_warning: o.locality_warning,
            }),
            // The validation message is caller-authored (no schema/internal
            // detail) — safe to surface so the editor can show it inline.
            Err(talos_ml::ProvisionError::InvalidInput(m)) => {
                Err(async_graphql::Error::new(m).extend_safe())
            }
            Err(talos_ml::ProvisionError::InvalidActor) => {
                Err(async_graphql::Error::new("Actor not found or not owned by you").extend_safe())
            }
            Err(talos_ml::ProvisionError::Internal(e)) => {
                tracing::error!(target: "talos_ml", error = %e, "provision_ml_classifier failed");
                Err(async_graphql::Error::new("Could not provision classifier").extend_safe())
            }
        }
    }
}
