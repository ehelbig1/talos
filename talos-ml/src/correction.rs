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
    /// Exact-duplicate siblings closed by this same decision — copies of the
    /// SAME message carrying the SAME disagreement. Always 0 for a unique row.
    ///
    /// Exactly ONE gold correction is appended for the whole group. Appending
    /// one per copy would silently multiply a single human judgement in
    /// training and mint the duplicate embeddings that made the kNN neighbour
    /// vote tie-dependent (#582).
    pub siblings_resolved: usize,
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
    let (features_text, example_key, correction, siblings) = {
        let mut tx = open_tx(pool, user_id).await?;
        let Some((model_id, pending)) = lifecycle
            .get_disagreement(&mut tx, id, user_id)
            .await
            .map_err(ResolveError::Internal)?
        else {
            return Err(ResolveError::NotFound);
        };
        // Exact-duplicate siblings of this row, so ONE decision closes the
        // whole group and appends ONE correction. Read through the same
        // deduped queue view the operator saw, which is why the grouping key
        // cannot drift between what was displayed and what gets closed.
        // Best-effort: a read failure or a row outside the window simply
        // yields no siblings — degrading to the previous one-row behaviour is
        // always safe, whereas failing the resolve would lose the human's
        // decision.
        let siblings = sibling_ids(lifecycle, &mut tx, model_id, user_id, id).await;
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
        (
            pending.features_text,
            pending.example_key,
            correction,
            siblings,
        )
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
    // Close the duplicates under the SAME decision, in the SAME tx, with NO
    // further correction appended. A sibling that lost its own CAS (handled
    // concurrently) is skipped rather than failing the batch — the operator's
    // decision on the group still stands.
    let mut siblings_resolved = 0usize;
    for sibling in siblings {
        if lifecycle
            .set_disagreement_status(&mut tx, sibling, user_id, status)
            .await
            .map_err(ResolveError::Internal)?
        {
            siblings_resolved += 1;
        }
    }
    tx.commit()
        .await
        .map_err(|e| ResolveError::Internal(e.into()))?;
    Ok(ResolveOutcome {
        status,
        correction_appended: appended,
        siblings_resolved,
    })
}

/// Ids of the exact-duplicate siblings of `id` within the model's pending
/// queue — every other row in its deduped group, whether `id` is the group's
/// survivor or one of the collapsed copies.
///
/// Returns empty on ANY read failure or when `id` falls outside the queue
/// window: siblings are an optimisation of the operator's attention, never a
/// correctness precondition, so this must not be able to fail a resolve.
async fn sibling_ids(
    lifecycle: &LifecycleService,
    conn: &mut sqlx::PgConnection,
    model_id: Uuid,
    user_id: Uuid,
    id: Uuid,
) -> Vec<Uuid> {
    let Ok(groups) = lifecycle
        .pending_disagreements(conn, model_id, user_id, 100)
        .await
    else {
        return Vec::new();
    };
    siblings_from_groups(groups, id)
}

/// Pure selection half of [`sibling_ids`] — every other id in `id`'s deduped
/// group. Split out so the branch that matters (resolving a COLLAPSED copy
/// rather than the survivor) is exercised by tests without a database.
fn siblings_from_groups(groups: Vec<crate::lifecycle::PendingDisagreement>, id: Uuid) -> Vec<Uuid> {
    for g in groups {
        if g.id == id {
            return g.duplicate_ids;
        }
        if g.duplicate_ids.contains(&id) {
            // `id` is a collapsed copy: its siblings are the survivor plus
            // every other copy.
            let mut out: Vec<Uuid> = g.duplicate_ids.into_iter().filter(|d| *d != id).collect();
            out.push(g.id);
            return out;
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::PendingDisagreement;

    fn group(id: Uuid, dups: &[Uuid]) -> PendingDisagreement {
        PendingDisagreement {
            id,
            example_key: None,
            features_text: "Subject: [STALE DATA] Chief of Staff".to_string(),
            fast_label: Some("to_read".to_string()),
            fast_confidence: Some(0.43),
            llm_label: "follow_up".to_string(),
            kind: "divergence".to_string(),
            created_at: chrono::Utc::now(),
            duplicate_ids: dups.to_vec(),
        }
    }

    #[test]
    fn survivor_returns_its_collapsed_copies() {
        let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(siblings_from_groups(vec![group(a, &[b, c])], a), vec![b, c]);
    }

    /// The operator may resolve by an id that was COLLAPSED into another row
    /// (it is still a real, addressable row). Its siblings are the survivor
    /// plus the other copies — and must never include itself, which would
    /// double-flip the row it was called for.
    #[test]
    fn collapsed_copy_returns_survivor_and_other_copies() {
        let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let out = siblings_from_groups(vec![group(a, &[b, c])], b);
        assert_eq!(out.len(), 2);
        assert!(out.contains(&a) && out.contains(&c));
        assert!(!out.contains(&b), "must not return the row being resolved");
    }

    #[test]
    fn unique_row_has_no_siblings() {
        let a = Uuid::new_v4();
        assert!(siblings_from_groups(vec![group(a, &[])], a).is_empty());
    }

    /// A row outside the queue window degrades to the previous one-row
    /// behaviour rather than touching an unrelated group.
    #[test]
    fn unknown_id_yields_no_siblings() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(siblings_from_groups(vec![group(a, &[b])], Uuid::new_v4()).is_empty());
    }

    #[test]
    fn picks_the_right_group_among_several() {
        let (a, b, c, d) = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        let groups = vec![group(a, &[b]), group(c, &[d])];
        assert_eq!(siblings_from_groups(groups, c), vec![d]);
    }
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
