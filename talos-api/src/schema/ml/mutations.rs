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
}
