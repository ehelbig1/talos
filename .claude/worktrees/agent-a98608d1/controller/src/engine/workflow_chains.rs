//! Shared workflow chaining logic for all trigger types.
//!
//! When any trigger fires (webhook, scheduled job, manual run), downstream
//! nodes in the same workflow are executed in-process via
//! [`ParallelWorkflowEngine::run_with_seed`].  The trigger module's output is
//! pre-seeded so that downstream nodes receive it as their `input`.
//!
//! Call [`run_workflow_chains`] from any trigger handler to automatically
//! extend execution to linked workflow nodes.

use crate::engine::parallel::ParallelWorkflowEngine;
use crate::registry::ModuleRegistry;
use crate::secrets::SecretsManager;
use crate::workflow_engine::EdgeLogic;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// Find all workflows that contain `trigger_module_id` and execute their
/// downstream nodes in-process, with `event_data` pre-seeded as the trigger
/// module's output.
///
/// `trigger_context_id` is an opaque identifier used only for log messages
/// (e.g., a webhook channel UUID or a scheduled job ID).
///
/// This function is best-effort — errors are logged as warnings and do not
/// propagate to the caller.
pub async fn run_workflow_chains(
    nats_client: Arc<async_nats::Client>,
    secrets_manager: Arc<SecretsManager>,
    db_pool: &sqlx::Pool<sqlx::Postgres>,
    worker_shared_key: Option<Arc<Vec<u8>>>,
    redis_client: Option<Arc<redis::Client>>,
    trigger_module_id: Uuid,
    user_id: Uuid,
    event_data: Value,
    trigger_context_id: Uuid,
    trigger_execution_id: Uuid,
    trigger_error: Option<String>,
) {
    let module_id_str = trigger_module_id.to_string();
    // Quick text search to avoid loading every workflow for the user.
    // Since UUIDs are unique the LIKE hit rate of false-positives is negligible.
    let search = format!("%{}%", module_id_str);

    let workflows = match sqlx::query_as::<_, (Uuid, String)>(
        "SELECT id, graph_json FROM workflows WHERE user_id = $1 AND graph_json LIKE $2",
    )
    .bind(user_id)
    .bind(&search)
    .fetch_all(db_pool)
    .await
    {
        Ok(ws) => ws,
        Err(e) => {
            tracing::warn!(
                "run_workflow_chains: failed to query workflows for module {}: {}",
                trigger_module_id,
                e
            );
            return;
        }
    };

    if workflows.is_empty() {
        tracing::debug!(
            "run_workflow_chains: no workflows found for module {} — single-node execution only",
            trigger_module_id
        );
        return;
    }

    for (workflow_id, graph_json) in workflows {
        if let Err(e) = run_single_workflow_chain(
            nats_client.clone(),
            secrets_manager.clone(),
            db_pool,
            worker_shared_key.clone(),
            redis_client.clone(),
            workflow_id,
            &graph_json,
            trigger_module_id,
            user_id,
            event_data.clone(),
            trigger_context_id,
            trigger_execution_id,
            trigger_error.clone(),
        )
        .await
        {
            tracing::warn!(
                "run_workflow_chains: workflow {} chain failed: {}",
                workflow_id,
                e
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_single_workflow_chain(
    nats_client: Arc<async_nats::Client>,
    secrets_manager: Arc<SecretsManager>,
    db_pool: &sqlx::Pool<sqlx::Postgres>,
    worker_shared_key: Option<Arc<Vec<u8>>>,
    redis_client: Option<Arc<redis::Client>>,
    workflow_id: Uuid,
    graph_json: &str,
    trigger_module_id: Uuid,
    user_id: Uuid,
    event_data: Value,
    trigger_context_id: Uuid,
    trigger_execution_id: Uuid,
    trigger_error: Option<String>,
) -> Result<(), String> {
    let graph: Value =
        serde_json::from_str(graph_json).map_err(|e| format!("Invalid graph_json: {}", e))?;

    let empty_vec = vec![];
    let nodes = graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .unwrap_or(&empty_vec);

    // Build React Flow node ID → module UUID mapping.
    let mut rf_to_module: HashMap<String, Uuid> = HashMap::new();
    let registry = Arc::new(ModuleRegistry::new(db_pool.clone(), redis_client.clone()));
    let mut engine = ParallelWorkflowEngine::with_services(registry, secrets_manager, user_id);
    let mut has_trigger = false;
    let mut has_downstream = false;

    for node in nodes {
        let rf_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("");
        // Module UUID may be stored under "type" (save v1) or "data.moduleId" (save v2).
        let module_id_str = node
            .get("type")
            .and_then(|v| v.as_str())
            .filter(|s| Uuid::parse_str(s).is_ok()) // skip non-UUID "type" values like "talosNode"
            .or_else(|| {
                node.get("data")
                    .and_then(|d| d.get("moduleId"))
                    .and_then(|v| v.as_str())
            });
        if let Some(module_id_str) = module_id_str {
            if let Ok(module_id) = Uuid::parse_str(module_id_str) {
                tracing::debug!(
                    rf_id,
                    module_id = %module_id,
                    "workflow_chains: mapped node"
                );
                rf_to_module.insert(rf_id.to_string(), module_id);
                engine.add_node(module_id);
                if module_id == trigger_module_id {
                    has_trigger = true;
                } else {
                    has_downstream = true;
                }
            }
        }
    }

    tracing::debug!(
        has_trigger,
        has_downstream,
        nodes_mapped = rf_to_module.len(),
        "workflow_chains: node mapping complete"
    );

    if !has_trigger {
        // Workflow contains the module but has no other nodes connected — nothing to chain.
        return Ok(());
    }

    // Add directed edges between nodes.
    let empty_edges = vec![];
    let edges = graph
        .get("edges")
        .and_then(|e| e.as_array())
        .unwrap_or(&empty_edges);

    let mut edges_added = 0usize;
    for edge in edges {
        let src_rf = edge.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let tgt_rf = edge.get("target").and_then(|v| v.as_str()).unwrap_or("");
        tracing::debug!(src_rf, tgt_rf, "workflow_chains: resolving edge");
        if let (Some(&src), Some(&tgt)) = (rf_to_module.get(src_rf), rf_to_module.get(tgt_rf)) {
            tracing::debug!(src = %src, tgt = %tgt, "workflow_chains: edge wired");
            engine.add_edge(
                src,
                tgt,
                EdgeLogic {
                    source_handle: "output".to_string(),
                    target_handle: "input".to_string(),
                },
            );
            edges_added += 1;
        } else {
            tracing::warn!(
                src_rf,
                tgt_rf,
                src_found = rf_to_module.contains_key(src_rf),
                tgt_found = rf_to_module.contains_key(tgt_rf),
                "workflow_chains: edge source/target not found in node map — edge skipped"
            );
        }
    }
    tracing::debug!(edges_added, "workflow_chains: edge wiring complete");

    // Pre-seed the trigger module's output so downstream nodes receive the event data.
    let seed = serde_json::json!({
        "trigger_module_id": trigger_module_id.to_string(),
        "trigger_context_id": trigger_context_id.to_string(),
        "event": event_data,
    });
    let mut initial_results = HashMap::new();
    initial_results.insert(trigger_module_id, seed);

    tracing::info!(
        "🔗 Chaining workflow {} from trigger module {} (context: {})",
        workflow_id,
        trigger_module_id,
        trigger_context_id
    );

    // Create a workflow execution record for this chain run
    let execution_id = Uuid::new_v4();
    if let Err(db_err) = sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, status, started_at) VALUES ($1, $2, $3, 'running', NOW()) ON CONFLICT DO NOTHING"
    )
    .bind(execution_id)
    .bind(workflow_id)
    .bind(user_id)
    .execute(db_pool)
    .await {
    tracing::error!("Database operation failed in engine: {}", db_err);
}

    // Link the trigger's module execution to this workflow execution
    if let Err(db_err) =
        sqlx::query("UPDATE module_executions SET workflow_execution_id = $1 WHERE id = $2")
            .bind(execution_id)
            .bind(trigger_execution_id)
            .execute(db_pool)
            .await
    {
        tracing::error!("Database operation failed in engine: {}", db_err);
    }

    if let Some(err_msg) = trigger_error {
        if let Err(db_err) = sqlx::query(
            "UPDATE workflow_executions SET status = 'failed', completed_at = NOW(), error_message = $1 WHERE id = $2"
        )
        .bind(&err_msg)
        .bind(execution_id)
        .execute(db_pool)
        .await {
            tracing::error!("Database operation failed in engine: {}", db_err);
        }
        return Ok(());
    }

    match engine
        .run_with_seed(
            nats_client.clone(),
            worker_shared_key.clone(),
            initial_results,
            execution_id,
        )
        .await
    {
        Ok(ctx) => {
            // Subtract 1 for the pre-seeded trigger node itself.
            let downstream_count = ctx.results.len().saturating_sub(1);
            tracing::info!(
                "✅ Workflow {} chain complete — {} downstream node(s) ran",
                workflow_id,
                downstream_count
            );
            let output_data = serde_json::to_value(&ctx.results).unwrap_or(serde_json::json!({}));
            if let Err(db_err) = sqlx::query(
                "UPDATE workflow_executions SET status = 'completed', completed_at = NOW(), output_data = $1 WHERE id = $2"
            )
            .bind(&output_data)
            .bind(execution_id)
            .execute(db_pool)
            .await {
    tracing::error!("Database operation failed in engine: {}", db_err);
}
            Ok(())
        }
        Err(e) => {
            if let Err(db_err) = sqlx::query(
                "UPDATE workflow_executions SET status = 'failed', completed_at = NOW(), error_message = $1 WHERE id = $2"
            )
            .bind(&e)
            .bind(execution_id)
            .execute(db_pool)
            .await {
    tracing::error!("Database operation failed in engine: {}", db_err);
}
            Err(e)
        }
    }
}
