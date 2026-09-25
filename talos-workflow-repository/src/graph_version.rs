//! Optimistic concurrency for `workflows.graph_json` — the ONE home of the
//! versioned read and the compare-and-set write.
//!
//! Every graph mutation in this workspace is a read-modify-write of the whole
//! document. Until migration `20260925120000` the write was unconditional, so
//! two overlapping mutations (parallel MCP tool calls, or an MCP edit racing a
//! web-editor save) each wrote their own copy and the later one silently
//! discarded the earlier one's change while both reported success.
//!
//! `workflows.graph_version` is advanced by a trigger whenever `graph_json`
//! changes — on EVERY writer, including the deliberately unconditional ones —
//! and a read-modify-write passes back the version it read. The write matches
//! only if nothing changed in between; otherwise it reports
//! [`GraphWrite::Conflict`] and writes nothing.
//!
//! These are free functions over a `PgExecutor` so the two repositories that
//! own a graph write (`WorkflowRepository`, and `ExecutionRepository` for the
//! failure-analysis auto-fix) delegate to one statement instead of carrying
//! two.

use anyhow::Result;
use sqlx::Row;
use uuid::Uuid;

/// A workflow's draft graph together with the version it was read at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedGraph {
    pub graph_json: String,
    /// Pass this back to the write. It is only meaningful for the row it was
    /// read from.
    pub graph_version: i64,
}

/// Outcome of a compare-and-set graph write. Three-valued, because the two
/// ways a conditional UPDATE can match zero rows mean different things to the
/// caller: the workflow is gone (or not theirs), or somebody else changed the
/// graph since it was read.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphWrite {
    /// The graph was written. `graph_version` is the row's version AFTER the
    /// write (unchanged when the written text equals the stored text).
    Written { graph_version: i64 },
    /// The row exists and is the caller's, but its graph changed after it was
    /// read. NOTHING was written; the caller must re-read and re-apply.
    Conflict,
    /// No such workflow for this user.
    NotFound,
}

impl GraphWrite {
    /// Classify the two columns the CAS statement returns. Pure so the
    /// mapping is testable without a database.
    #[must_use]
    pub fn classify(written_version: Option<i64>, row_visible: bool) -> Self {
        match (written_version, row_visible) {
            (Some(graph_version), _) => Self::Written { graph_version },
            (None, true) => Self::Conflict,
            (None, false) => Self::NotFound,
        }
    }
}

/// Read `graph_json` + `graph_version` for `workflow_id`, owner-scoped.
/// `Ok(None)` = no such workflow for this user.
pub async fn read_workflow_graph_versioned<'e, E>(
    executor: E,
    workflow_id: Uuid,
    user_id: Uuid,
) -> Result<Option<VersionedGraph>>
where
    E: sqlx::PgExecutor<'e>,
{
    let row = sqlx::query(
        "SELECT graph_json::text AS graph_json, graph_version \
         FROM workflows WHERE id = $1 AND user_id = $2",
    )
    .bind(workflow_id)
    .bind(user_id)
    .fetch_optional(executor)
    .await?;
    row.map(|r| -> Result<VersionedGraph> {
        Ok(VersionedGraph {
            graph_json: r.try_get("graph_json")?,
            graph_version: r.try_get("graph_version")?,
        })
    })
    .transpose()
}

/// Write `graph_json` only if the row is still at `expected_version`.
///
/// One statement: the data-modifying CTE does the conditional UPDATE, and the
/// outer SELECT — which sees the statement's snapshot, i.e. the row as it was
/// BEFORE this UPDATE — answers whether the row exists at all, so a zero-row
/// UPDATE is classified without a second round trip. Under READ COMMITTED a
/// concurrent committed writer makes the UPDATE re-check `graph_version`
/// against the NEW row version and match nothing; the snapshot SELECT still
/// sees the row, so that race reads as `Conflict`, which is what it is.
pub async fn write_workflow_graph_if_unchanged<'e, E>(
    executor: E,
    workflow_id: Uuid,
    user_id: Uuid,
    graph_json: &str,
    expected_version: i64,
) -> Result<GraphWrite>
where
    E: sqlx::PgExecutor<'e>,
{
    let row = sqlx::query(
        "WITH written AS ( \
             UPDATE workflows SET graph_json = $1, updated_at = NOW() \
             WHERE id = $2 AND user_id = $3 AND graph_version = $4 \
             RETURNING graph_version \
         ) \
         SELECT (SELECT graph_version FROM written) AS written_version, \
                EXISTS (SELECT 1 FROM workflows WHERE id = $2 AND user_id = $3) AS row_visible",
    )
    .bind(graph_json)
    .bind(workflow_id)
    .bind(user_id)
    .bind(expected_version)
    .fetch_one(executor)
    .await?;
    Ok(GraphWrite::classify(
        row.try_get::<Option<i64>, _>("written_version")?,
        row.try_get::<bool, _>("row_visible")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::GraphWrite;

    #[test]
    fn a_returned_version_is_a_write_whatever_the_visibility_probe_says() {
        assert_eq!(
            GraphWrite::classify(Some(7), true),
            GraphWrite::Written { graph_version: 7 }
        );
        // The snapshot probe cannot see a row the UPDATE just wrote only in a
        // pathological case, but a returned version is proof of the write.
        assert_eq!(
            GraphWrite::classify(Some(7), false),
            GraphWrite::Written { graph_version: 7 }
        );
    }

    #[test]
    fn zero_rows_on_a_visible_row_is_a_conflict_not_a_missing_workflow() {
        assert_eq!(GraphWrite::classify(None, true), GraphWrite::Conflict);
        assert_eq!(GraphWrite::classify(None, false), GraphWrite::NotFound);
    }
}
