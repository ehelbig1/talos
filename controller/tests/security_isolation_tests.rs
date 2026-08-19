mod common;

use common::{create_test_user, setup_test_context, AuthenticatedClient};
use controller::api_keys::ApiKeyScope;
use uuid::Uuid;

#[tokio::test]
async fn test_cross_user_workflow_access() {
    let ctx = setup_test_context().await;

    // 1. Create User A and User B
    let user_a_id = create_test_user(&ctx.auth_service, "user_a@example.com").await;
    let user_b_id = create_test_user(&ctx.auth_service, "user_b@example.com").await;

    // 2. User B creates a workflow
    let mutation = r#"
        mutation {
            createWorkflow(input: { name: "User B Workflow", graphJson: "{}" }) {
                id
            }
        }
    "#;

    let client_b = AuthenticatedClient::new(
        user_b_id,
        None,
        vec![ApiKeyScope::WorkflowsWrite, ApiKeyScope::WorkflowsRead],
        ctx.schema.clone(),
    );
    let res_b = client_b.execute(mutation).await;
    assert!(
        res_b.errors.is_empty(),
        "User B failed to create workflow: {:?}",
        res_b.errors
    );

    let workflow_id = res_b.data.into_json().unwrap()["createWorkflow"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // 3. User A attempts to fetch User B's workflow by ID
    let query = format!(
        r#"
        query {{
            workflow(id: "{}") {{
                id
                name
            }}
        }}
    "#,
        workflow_id
    );

    let client_a = AuthenticatedClient::new(
        user_a_id,
        None,
        vec![ApiKeyScope::WorkflowsRead],
        ctx.schema.clone(),
    );
    let res_a = client_a.execute(&query).await;

    // Correct isolation should return an error or null.
    // In current implementation, it returns "Workflow not found or access denied" error.
    assert!(
        !res_a.errors.is_empty(),
        "User A should not be able to see User B's workflow"
    );
    let msg = res_a.errors[0].message.to_lowercase();
    assert!(msg.contains("not found") || msg.contains("denied"));
}

#[tokio::test]
async fn test_dataloader_leakage_module_logs() {
    let ctx = setup_test_context().await;

    // 1. Create User A and User B
    let user_a_id = create_test_user(&ctx.auth_service, "user_a_logs@example.com").await;
    let user_b_id = create_test_user(&ctx.auth_service, "user_b_logs@example.com").await;

    // 2. User B has a module execution with logs
    let module_id = Uuid::new_v4();
    let execution_id = Uuid::new_v4();

    // Insert the module to satisfy module_executions' FK. Phase-5 unified the
    // old `node_templates` + `wasm_modules` pair into a single `modules` table;
    // a user-owned compiled module is `kind = 'sandbox'`.
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, kind, content_hash, wasm_bytes, size_bytes, max_fuel) \
         VALUES ($1, $2, 'Test', 'sandbox', 'hash', ''::bytea, 0, 0)",
    )
    .bind(module_id)
    .bind(user_b_id)
    .execute(&ctx.db_pool)
    .await
    .unwrap();

    // Phase E: module_executions.actor_id is NOT NULL. Give user B a default
    // actor so the trg_set_default_actor trigger stamps it onto the execution.
    sqlx::query(
        "INSERT INTO actors (id, user_id, name, max_capability_world, is_default) \
         VALUES (gen_random_uuid(), $1, 'Default', 'network-node', true)",
    )
    .bind(user_b_id)
    .execute(&ctx.db_pool)
    .await
    .unwrap();

    // Now insert the execution
    sqlx::query("INSERT INTO module_executions (id, module_id, user_id, status, trigger_type) VALUES ($1, $2, $3, 'completed', 'manual')")
        .bind(execution_id)
        .bind(module_id)
        .bind(user_b_id)
        .execute(&ctx.db_pool)
        .await.unwrap();

    sqlx::query("INSERT INTO module_execution_logs (execution_id, level, message) VALUES ($1, 'INFO', 'Secret log message from User B')")
        .bind(execution_id)
        .execute(&ctx.db_pool)
        .await.unwrap();

    // 3. User A attempts to fetch logs for User B's execution ID
    let query = format!(
        r#"
        query {{
            moduleExecutionLogs(executionId: "{}") {{
                message
            }}
        }}
    "#,
        execution_id
    );

    let client_a = AuthenticatedClient::new(
        user_a_id,
        None,
        vec![ApiKeyScope::WorkflowsRead],
        ctx.schema.clone(),
    );
    let res_a = client_a.execute(&query).await;

    // If it's correctly isolated, User A should get an error or empty logs.
    // In current implementation (schema.rs:834), it returns "Not found or permission denied".
    assert!(
        !res_a.errors.is_empty(),
        "User A should not see User B's logs"
    );
    let msg = res_a.errors[0].message.to_lowercase();
    assert!(msg.contains("not found") || msg.contains("denied"));
}

#[tokio::test]
async fn test_scope_escalation_api_key() {
    let ctx = setup_test_context().await;
    let user_id = create_test_user(&ctx.auth_service, "scope_test@example.com").await;

    // User has WorkflowsRead but NOT WorkflowsWrite
    let client = AuthenticatedClient::new(
        user_id,
        None,
        vec![ApiKeyScope::WorkflowsRead],
        ctx.schema.clone(),
    );

    let mutation = r#"
        mutation {
            createWorkflow(input: { name: "Forbidden", graphJson: "{}" }) {
                id
            }
        }
    "#;

    let res = client.execute(mutation).await;
    assert!(
        !res.errors.is_empty(),
        "Mutation should fail due to missing WorkflowsWrite scope"
    );
    assert!(res.errors[0]
        .message
        .contains("Insufficient API key permissions"));
}

/// #658: the graph_json write must refuse a workflow the caller does not own,
/// at the STATEMENT, not merely at a read the caller was trusted to have run.
///
/// Until this change there were two write paths: `update_workflow_graph`
/// (`… WHERE id = $2 AND user_id = $3`) and `update_workflow_graph_unchecked`
/// (`… WHERE id = $2`). The unscoped one was reached by six MCP handlers, each
/// of which did run an ownership-checked read first — an audit of all six
/// confirmed it — but the guarantee lived in handler convention, which is the
/// shape that failed in #656 (a user-scoped read feeding an unscoped write).
/// The unscoped variant is deleted; this test is the regression net.
///
/// Restore `WHERE id = $2` in `WorkflowRepository::update_workflow_graph` and
/// the first assertion pair below fails: user A's write lands on user B's row.
#[tokio::test]
async fn test_graph_json_write_refuses_foreign_workflow() {
    let ctx = setup_test_context().await;

    let user_a_id = create_test_user(&ctx.auth_service, "graph_a@example.com").await;
    let user_b_id = create_test_user(&ctx.auth_service, "graph_b@example.com").await;

    let repo = talos_workflow_repository::WorkflowRepository::new(ctx.db_pool.clone());

    let original = r#"{"nodes":[],"edges":[]}"#;
    let wf_id = repo
        .create_workflow(
            user_b_id,
            "B's workflow",
            original,
            None,
            &[],
            &[],
            None,
            None,
            None,
            None,
        )
        .await
        .expect("user B creates a workflow");

    // User A attempts to overwrite user B's graph.
    let attacker_graph = r#"{"nodes":[{"id":"pwned"}],"edges":[]}"#;
    let affected = repo
        .update_workflow_graph(wf_id, user_a_id, attacker_graph)
        .await
        .expect("query executes");
    assert!(
        !affected,
        "cross-tenant graph write reported a row affected — the statement lost its \
         `AND user_id = $3` predicate"
    );

    // …and the row is untouched. Read it back as the OWNER, since the
    // ownership-scoped read is the only one that can see it at all.
    let after = repo
        .get_workflow_graph(wf_id, user_b_id)
        .await
        .expect("owner reads back")
        .expect("row still exists");
    assert_eq!(
        after, original,
        "user B's graph_json was modified by user A"
    );

    // The owner's own write still works — this guards against "fixing" the
    // above by making the statement match nothing at all.
    let owner_graph = r#"{"nodes":[{"id":"mine"}],"edges":[]}"#;
    let affected_owner = repo
        .update_workflow_graph(wf_id, user_b_id, owner_graph)
        .await
        .expect("query executes");
    assert!(
        affected_owner,
        "owner's own graph write reported no rows affected"
    );
    let after_owner = repo
        .get_workflow_graph(wf_id, user_b_id)
        .await
        .expect("owner reads back")
        .expect("row still exists");
    assert_eq!(after_owner, owner_graph, "owner's write did not persist");
}
