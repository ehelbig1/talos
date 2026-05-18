mod common;

use common::{create_test_user, setup_test_context, AuthenticatedClient};
use controller::api_keys::ApiKeyScope;
use uuid::Uuid;

#[ignore = "references dropped wasm_modules/node_templates tables — port fixtures to unified `modules` table (Phase 5)"]
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

#[ignore = "references dropped wasm_modules/node_templates tables — port fixtures to unified `modules` table (Phase 5)"]
#[tokio::test]
async fn test_dataloader_leakage_module_logs() {
    let ctx = setup_test_context().await;

    // 1. Create User A and User B
    let user_a_id = create_test_user(&ctx.auth_service, "user_a_logs@example.com").await;
    let user_b_id = create_test_user(&ctx.auth_service, "user_b_logs@example.com").await;

    // 2. User B has a module execution with logs
    let template_id = Uuid::new_v4();
    let module_id = Uuid::new_v4();
    let execution_id = Uuid::new_v4();

    // Insert template and module first to satisfy foreign keys
    sqlx::query("INSERT INTO node_templates (id, name, category, config_schema, code_template) VALUES ($1, 'Test', 'test', '{}', '')")
        .bind(template_id)
        .execute(&ctx.db_pool)
        .await.unwrap();

    sqlx::query("INSERT INTO wasm_modules (id, name, content_hash, wasm_bytes, template_id, user_id, size_bytes, max_fuel, max_memory_mb) VALUES ($1, 'Test', 'hash', '', $2, $3, 0, 0, 0)")
        .bind(module_id)
        .bind(template_id)
        .bind(user_b_id)
        .execute(&ctx.db_pool)
        .await.unwrap();

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

#[ignore = "references dropped wasm_modules/node_templates tables — port fixtures to unified `modules` table (Phase 5)"]
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
