//! RFC 0011 — shared disagreement-resolution flow.
//!
//! One implementation of "resolve a pending disagreement" (append a gold
//! correction, or dismiss), called by BOTH the MCP handler
//! (`talos-mcp-handlers`) AND the GraphQL resolver (`talos-api`). The six
//! tenancy invariants (owner-scoped tx, owner-predicated model + dataset
//! resolution, correction provenance from the stored row) live here so the
//! two protocol surfaces can never drift — a missing check on one surface
//! would be a cross-tenant vulnerability, so there is exactly one copy.

use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

use crate::dataset::{AppendExample, DatasetService, ExampleSource};
use crate::lifecycle::LifecycleService;
use crate::registry::ModelRegistry;

/// Correction-label cap (mirrors the dataset label byte cap).
const MAX_LABEL_BYTES: usize = 256;

/// Resolve failure taxonomy — each protocol surface maps these to its own
/// code/message. `NotFound` deliberately covers absent AND already-handled
/// AND foreign rows so a caller can never enumerate another tenant's ids.
#[derive(Debug)]
pub enum ResolveError {
    /// Disagreement absent, already resolved/dismissed, or not owned by
    /// the caller; also a lost CAS between the two phases.
    NotFound,
    /// A correction was requested but the model has no dataset to write
    /// the gold example into.
    NoDataset,
    Internal(anyhow::Error),
}

#[derive(Debug)]
pub struct ResolveOutcome {
    /// `"resolved"` (a correction was appended) or `"dismissed"`.
    pub status: &'static str,
    pub correction_appended: bool,
}

/// Resolve one pending disagreement, owner-scoped end to end.
///
/// `correct_label = Some(non-blank, ≤256 bytes)` → append a
/// `source=correction` gold example built from the disagreement's OWN
/// stored `features_text` + `example_key` (the caller supplies ONLY the
/// label; provenance stays trusted) and mark the row `resolved`. A `None`,
/// blank, or oversized label → `dismissed`, no append.
///
/// Two-phase to honor the prepare-outside-tx discipline (the local
/// embedder must never pin an idle-in-transaction connection): tx#1 reads
/// the pending row + resolves the target dataset/ownership, `prepare_examples`
/// runs with NO connection held, tx#2 inserts + flips the status atomically.
///
/// Idempotent: a row handled by another caller between the phases loses the
/// status CAS and returns `NotFound` (its correction insert rolls back with
/// the uncommitted tx).
pub async fn resolve_disagreement(
    pool: &PgPool,
    lifecycle: &LifecycleService,
    dataset: &DatasetService,
    id: Uuid,
    user_id: Uuid,
    correct_label: Option<&str>,
) -> Result<ResolveOutcome, ResolveError> {
    let label = correct_label
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= MAX_LABEL_BYTES);

    // tx #1 (read-only): fetch the pending row (owner-scoped, decrypted);
    // for the correction path resolve the target dataset + re-check its
    // ownership independently (the correction writes into the DATASET, so
    // model ownership alone is not sufficient).
    let (features_text, example_key, correction) = {
        let mut tx = open_tx(pool, user_id).await?;
        let Some((model_id, pending)) = lifecycle
            .get_disagreement(&mut tx, id, user_id)
            .await
            .map_err(ResolveError::Internal)?
        else {
            return Err(ResolveError::NotFound);
        };
        let correction = match label {
            Some(label) => {
                let model = ModelRegistry::resolve_by_id(&mut tx, model_id, user_id)
                    .await
                    .map_err(ResolveError::Internal)?
                    .ok_or(ResolveError::NotFound)?;
                let dataset_id = model.dataset_id.ok_or(ResolveError::NoDataset)?;
                // Dataset-ownership belt: single NotFound for absent AND
                // foreign so the surface can't enumerate dataset ids.
                let tenancy = match dataset.dataset_tenancy(&mut tx, dataset_id).await {
                    Ok(t) if t.user_id == user_id => t,
                    _ => return Err(ResolveError::NotFound),
                };
                Some((dataset_id, tenancy, label.to_string()))
            }
            None => None,
        };
        (pending.features_text, pending.example_key, correction)
    };

    // prepare (embed + encrypt) with NO connection held.
    let prepared = match &correction {
        Some((dataset_id, tenancy, label)) => Some(
            dataset
                .prepare_examples(
                    *dataset_id,
                    *tenancy,
                    vec![AppendExample {
                        features_text,
                        label: label.clone(),
                        source: ExampleSource::Correction,
                        example_key,
                    }],
                )
                .await
                .map_err(ResolveError::Internal)?,
        ),
        None => None,
    };

    // tx #2 (write): insert the correction (if any) + flip the status,
    // atomically.
    let mut tx = open_tx(pool, user_id).await?;
    let appended = prepared.is_some();
    if let (Some(prepared), Some((dataset_id, tenancy, _))) = (prepared, &correction) {
        dataset
            .insert_prepared(&mut tx, *dataset_id, *tenancy, prepared)
            .await
            .map_err(ResolveError::Internal)?;
    }
    let status = if appended { "resolved" } else { "dismissed" };
    let handled = lifecycle
        .set_disagreement_status(&mut tx, id, user_id, status)
        .await
        .map_err(ResolveError::Internal)?;
    if !handled {
        // Lost the CAS (row handled between tx#1 and tx#2). Drop tx#2
        // without committing → the correction insert rolls back.
        return Err(ResolveError::NotFound);
    }
    tx.commit()
        .await
        .map_err(|e| ResolveError::Internal(e.into()))?;
    Ok(ResolveOutcome {
        status,
        correction_appended: appended,
    })
}

async fn open_tx(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, ResolveError> {
    talos_db::begin_tenant_read_scoped(
        pool,
        &talos_tenancy::TenantReadScope::new(user_id, Vec::new()),
    )
    .await
    .map_err(|e| ResolveError::Internal(anyhow::anyhow!("open user-scoped tx: {e}")))
}
