//! What an action link may start, checked where a graph is WRITTEN.
//!
//! An `action_links` node's `targets` names the only workflows a link minted
//! by that node may start (see `talos_workflow_engine_core::action_links`).
//! `add_action_links_node` checked the list; every other tool that writes or
//! copies a graph (`update_node_config`, the imports, the copies, the
//! GraphQL save) stored what it was given. The rule therefore sits here, in
//! front of every statement that writes `workflows.graph_json`: a tool
//! cannot reach the column without passing it, and a tool added later
//! inherits it. `scripts/check-graph-writers.py` refuses a statement that
//! writes the column from a function that does not call this module.
//!
//! # The rule
//!
//! * **Shape, on every write.** Each `action_links` node in the graph being
//!   written has 1 to 16 targets, each a usable name mapped to a workflow
//!   UUID ([`check_action_targets`]).
//! * **Ownership, of what the write introduces.** A target the stored graph
//!   of the workflow being written does not already name must be a workflow
//!   of the owner's. A target it already names is not asked about again: a
//!   workflow whose target was deleted since must stay editable. That is not
//!   a way around anything, because this check is the early, readable
//!   refusal and not the authority: the mint JOINs `workflows` on the running
//!   user every time a link is made (`ExecutionRepository::mint_action_tokens`).
//!
//! # What a refusal says
//!
//! The node and the entry, and for a workflow one answer for "does not
//! exist" and "is not yours" ([`TargetsFault::NotAccessible`]). It travels as
//! a typed error inside `anyhow`; a caller that can show it reads it with
//! [`action_targets_refusal`], and one that does not still refuses.
//!
//! [`check_action_targets`]: talos_workflow_engine_core::action_links::check_action_targets

use std::collections::HashSet;

use anyhow::Result;
use sqlx::{PgConnection, PgPool};
use talos_workflow_engine_core::action_links::{
    action_targets_in_graph, stored_action_target_ids, NodeActionTargets, TargetsFault,
};
use uuid::Uuid;

pub use talos_workflow_engine_core::action_links::ActionTargetsRefusal;

/// The refusal a graph write failed with, when that is why it failed.
#[must_use]
pub fn action_targets_refusal(error: &anyhow::Error) -> Option<&ActionTargetsRefusal> {
    error.downcast_ref::<ActionTargetsRefusal>()
}

/// The `action_links` nodes of the graph about to be written, read strictly.
/// Text that is not JSON has no nodes the engine could load.
fn written_targets(graph_json: &str) -> Result<Vec<NodeActionTargets>> {
    let Ok(graph) = serde_json::from_str::<serde_json::Value>(graph_json) else {
        return Ok(Vec::new());
    };
    action_targets_in_graph(&graph).map_err(anyhow::Error::new)
}

/// Whether the graph about to be written has an `action_links` node at all.
///
/// # Errors
/// The refusal, when it has one whose `targets` breaks the shape rule.
pub(crate) fn names_action_targets(graph_json: &str) -> Result<bool> {
    Ok(!written_targets(graph_json)?.is_empty())
}

/// Who a write is made for.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Writer<'a> {
    /// The user the workflow belongs to: the user a mint from it runs as.
    pub owner: Uuid,
    /// The user making the write. The owner, except on the organisation
    /// path, where an editor may save a workflow that is not theirs.
    pub accessor: Uuid,
    /// The organisations `accessor` may write in (empty off that path).
    pub writable_org_ids: &'a [Uuid],
}

impl Writer<'_> {
    /// The owner writing their own workflow.
    pub(crate) fn owner(user_id: Uuid) -> Writer<'static> {
        Writer {
            owner: user_id,
            accessor: user_id,
            writable_org_ids: &[],
        }
    }
}

/// Refuse `graph_json` when it would store targets the rule does not allow.
///
/// `existing_workflow` is the row being overwritten, or `None` for a new
/// row; its stored targets are the ones this write does not introduce.
///
/// Runs on the caller's connection, so a tenant-scoped transaction's row
/// security applies to the ownership read as it does to the write.
pub(crate) async fn refuse_unowned_targets(
    conn: &mut PgConnection,
    writer: Writer<'_>,
    existing_workflow: Option<Uuid>,
    graph_json: &str,
) -> Result<()> {
    let nodes = written_targets(graph_json)?;
    if nodes.is_empty() {
        return Ok(());
    }

    let already_named: HashSet<Uuid> = match existing_workflow {
        None => HashSet::new(),
        Some(workflow_id) => {
            let stored: Option<String> = sqlx::query_scalar(
                "SELECT graph_json::text FROM workflows WHERE id = $1 AND user_id = $2",
            )
            .bind(workflow_id)
            .bind(writer.owner)
            .fetch_optional(&mut *conn)
            .await?;
            stored
                .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
                .map(|graph| stored_action_target_ids(&graph))
                .unwrap_or_default()
        }
    };

    let introduced: Vec<Uuid> = nodes
        .iter()
        .flat_map(|node| node.targets.values().copied())
        .filter(|id| !already_named.contains(id))
        .collect::<HashSet<Uuid>>()
        .into_iter()
        .collect();
    if introduced.is_empty() {
        return Ok(());
    }

    // The mint's own predicate (`w.user_id = <the running user>`), plus, on
    // the organisation path, that the accessor could write the target too:
    // an editor must not point an owner's workflow at a workflow of the
    // owner's that the editor cannot reach.
    let owned: HashSet<Uuid> = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM workflows \
         WHERE id = ANY($1) AND user_id = $2 AND (user_id = $3 OR org_id = ANY($4))",
    )
    .bind(&introduced)
    .bind(writer.owner)
    .bind(writer.accessor)
    .bind(writer.writable_org_ids)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .collect();

    for node in &nodes {
        for (name, workflow_id) in &node.targets {
            if !already_named.contains(workflow_id) && !owned.contains(workflow_id) {
                return Err(anyhow::Error::new(ActionTargetsRefusal {
                    node: node.node.clone(),
                    fault: TargetsFault::NotAccessible {
                        name: name.clone(),
                        workflow_id: *workflow_id,
                    },
                }));
            }
        }
    }
    Ok(())
}

/// [`refuse_unowned_targets`] for the owner writing their own workflow on a
/// connection the caller holds (a tenant-scoped transaction).
pub async fn refuse_unowned_targets_on_conn(
    conn: &mut PgConnection,
    user_id: Uuid,
    existing_workflow: Option<Uuid>,
    graph_json: &str,
) -> Result<()> {
    refuse_unowned_targets(conn, Writer::owner(user_id), existing_workflow, graph_json).await
}

/// [`refuse_unowned_targets`] for a writer that holds only the pool: the
/// owner writing their own workflow. Opens a user-scoped transaction for the
/// reads, and none at all when the graph has no `action_links` node.
pub async fn refuse_unowned_targets_on_pool(
    pool: &PgPool,
    user_id: Uuid,
    existing_workflow: Option<Uuid>,
    graph_json: &str,
) -> Result<()> {
    if written_targets(graph_json)?.is_empty() {
        return Ok(());
    }
    let mut tx = talos_db::begin_user_scoped(pool, user_id).await?;
    refuse_unowned_targets(
        &mut tx,
        Writer::owner(user_id),
        existing_workflow,
        graph_json,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_malformed_list_is_refused_before_any_database_read_and_names_its_node() {
        let graph = serde_json::json!({ "nodes": [
            { "id": "links", "kind": "action_links", "data": { "targets": {} } }
        ]})
        .to_string();
        let error = written_targets(&graph).unwrap_err();
        let refusal = action_targets_refusal(&error).expect("typed refusal");
        assert_eq!(refusal.node, "links");
        assert_eq!(refusal.fault, TargetsFault::Count(0));
        // Any other failure is not mistaken for one.
        assert!(action_targets_refusal(&anyhow::anyhow!("connection reset")).is_none());
    }

    #[test]
    fn a_graph_without_the_node_and_text_that_is_not_json_have_nothing_to_check() {
        assert!(
            written_targets(r#"{"nodes":[{"id":"a","kind":"collect"}]}"#)
                .unwrap()
                .is_empty()
        );
        assert!(written_targets("{not json").unwrap().is_empty());
        // An escaped spelling of the kind is still the kind.
        let escaped = r#"{"nodes":[{"id":"a","kind":"action_links","data":{"targets":[]}}]}"#;
        assert!(written_targets(escaped).is_err());
    }
}
