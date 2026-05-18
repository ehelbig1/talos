#[path = "common/mod.rs"]
mod common;

use crate::common::AuthenticatedClient;
use common::setup_test_context;
use controller::api_keys::ApiKeyScope;

#[tokio::test]
async fn test_graphql_api_key_auth_scopes() {
    let ctx = setup_test_context().await;

    // 1. Create a test user
    let user_id = ctx
        .auth_service
        .create_user(
            "test_api_auth@example.com",
            "password123456!", // Complexity met
            Some("Test User"),
            None,
            None,
        )
        .await
        .expect("Failed to create user");

    // 2. Create an API key with limited scopes (WorkflowsRead only)
    let (_full_key, _id, _) = ctx
        .api_key_service
        .create_api_key(
            user_id,
            "Read Only Key",
            vec![ApiKeyScope::WorkflowsRead],
            None,
        )
        .await
        .expect("Failed to create API key");

    // 3. Define a query that requires WorkflowsRead
    let query = r#"
        query {
            workflows {
                id
                name
            }
        }
    "#;

    // 4. Execute query WITH valid API key scope
    let client = AuthenticatedClient::new(
        user_id,
        None,
        vec![ApiKeyScope::WorkflowsRead],
        ctx.schema.clone(),
    );
    let res = client.execute(query).await;

    assert!(
        res.errors.is_empty(),
        "Query should succeed with correct scope: {:?}",
        res.errors
    );

    // 5. Define a mutation that requires WorkflowsWrite
    let mutation = r#"
        mutation {
            createWorkflow(input: { name: "New Workflow", graphJson: "{}" }) {
                id
                name
            }
        }
    "#;

    // 6. Execute mutation WITH Read-Only API key scope (should FAIL)
    let client_fail = AuthenticatedClient::new(
        user_id,
        None,
        vec![ApiKeyScope::WorkflowsRead],
        ctx.schema.clone(),
    );
    let res_fail = client_fail.execute(mutation).await;

    assert!(
        !res_fail.errors.is_empty(),
        "Mutation should fail with insufficient scope"
    );
    assert!(res_fail.errors[0]
        .message
        .contains("Insufficient API key permissions"));

    // 7. Create an API key with WorkflowsWrite scope
    let (_write_key, _id2, _) = ctx
        .api_key_service
        .create_api_key(
            user_id,
            "Write Key",
            vec![ApiKeyScope::WorkflowsWrite],
            None,
        )
        .await
        .expect("Failed to create write API key");

    // 8. Execute mutation WITH Write API key scope (should SUCCEED)
    let client_success = AuthenticatedClient::new(
        user_id,
        None,
        vec![ApiKeyScope::WorkflowsWrite, ApiKeyScope::WorkflowsRead],
        ctx.schema.clone(),
    );

    let res_success = client_success.execute(mutation).await;
    assert!(
        res_success.errors.is_empty(),
        "Mutation should succeed with correct scope: {:?}",
        res_success.errors
    );
}

#[tokio::test]
async fn test_graphql_unauthenticated_access() {
    let ctx = setup_test_context().await;

    // 1. Define a query that requires authentication
    let query = r#"
        query {
            workflows {
                id
                name
            }
        }
    "#;

    // 2. Execute query WITHOUT user_id in context
    let req = async_graphql::Request::new(query);
    let res = ctx.schema.execute(req).await;

    // 3. Verify it fails with authentication error
    assert!(
        !res.errors.is_empty(),
        "Query should fail without authentication"
    );
    let err_msg = &res.errors[0].message;
    assert!(
        err_msg.contains("Authentication required") || err_msg.contains("Not authenticated"),
        "Unexpected error message: {}",
        err_msg
    );
}
