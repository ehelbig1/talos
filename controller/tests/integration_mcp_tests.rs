use controller::api::schema::{MutationRoot, QueryRoot, SubscriptionRoot};
use controller::auth::AuthService;
use controller::db::init_pool;
use sqlx::{Pool, Postgres};
use std::sync::Arc;

type TalosSchema = async_graphql::Schema<QueryRoot, MutationRoot, SubscriptionRoot>;

async fn setup_test_context() -> (Pool<Postgres>, TalosSchema, Arc<AuthService>) {
    let _ = dotenvy::dotenv();
    let db_pool = init_pool()
        .await
        .expect("Failed to connect to test database");

    // Clean up test data
    let _ = sqlx::query("DELETE FROM mcp_agents")
        .execute(&db_pool)
        .await;
    let _ = sqlx::query("DELETE FROM agent_roles")
        .execute(&db_pool)
        .await;
    let _ = sqlx::query("DELETE FROM slack_integrations")
        .execute(&db_pool)
        .await;
    let _ = sqlx::query("DELETE FROM gmail_integrations")
        .execute(&db_pool)
        .await;
    let _ = sqlx::query("DELETE FROM google_calendar_integrations")
        .execute(&db_pool)
        .await;
    let _ = sqlx::query("DELETE FROM integration_credentials")
        .execute(&db_pool)
        .await;
    let _ = sqlx::query("DELETE FROM users").execute(&db_pool).await;

    let auth_service = Arc::new(
        AuthService::new(
            db_pool.clone(),
            "test_secret_must_be_at_least_32_chars_long".to_string(),
            12,
            None,
        )
        .unwrap(),
    );

    let schema = async_graphql::Schema::build(
        QueryRoot::default(),
        MutationRoot::default(),
        SubscriptionRoot,
    )
    .data(db_pool.clone())
    .data(auth_service.clone())
    .finish();

    (db_pool, schema, auth_service)
}

#[tokio::test]
async fn test_service_integrations_query_and_disconnect() {
    let (db_pool, schema, auth_service) = setup_test_context().await;

    let user_id = auth_service
        .create_user(
            "test_integrations@example.com",
            "password123456",
            Some("Integrations Tester"),
            None,
            None,
        )
        .await
        .expect("Failed to create user");

    // We don't have a generic service_integrations table, but the query joins several.
    // Let's test Slack specifically since it's one of the ones in queries.rs
    sqlx::query(
        "INSERT INTO slack_integrations (id, user_id, team_id, team_name, bot_user_id) VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(uuid::Uuid::new_v4())
    .bind(user_id)
    .bind("T123")
    .bind("TestTeam")
    .bind("U123")
    .execute(&db_pool)
    .await
    .unwrap();

    let query = r#"
        query {
            serviceIntegrations {
                service
                accountIdentifier
                status
            }
        }
    "#;

    let req = async_graphql::Request::new(query).data(user_id);
    let res = schema.execute(req).await;
    assert!(res.errors.is_empty(), "Query failed: {:?}", res.errors);

    let data = res.data.into_json().unwrap();
    let integrations = data["serviceIntegrations"].as_array().unwrap();
    assert_eq!(integrations.len(), 1);
    assert_eq!(integrations[0]["service"], "SLACK");

    // Test disconnect
    let integration_id =
        sqlx::query_scalar::<_, uuid::Uuid>("SELECT id FROM slack_integrations WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&db_pool)
            .await
            .unwrap();

    let mutation = format!(
        r#"
        mutation {{
            disconnectServiceIntegration(id: "{}", service: SLACK)
        }}
    "#,
        integration_id
    );

    let req = async_graphql::Request::new(&mutation).data(user_id);
    let res = schema.execute(req).await;
    assert!(res.errors.is_empty(), "Mutation failed: {:?}", res.errors);
    assert!(
        res.data.into_json().unwrap()["disconnectServiceIntegration"]
            .as_bool()
            .unwrap()
    );

    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM slack_integrations WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&db_pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn test_mcp_agents_query_and_revoke() {
    let (db_pool, schema, auth_service) = setup_test_context().await;

    let user_id = auth_service
        .create_user(
            "test_mcp@example.com",
            "password123456",
            Some("MCP Tester"),
            None,
            None,
        )
        .await
        .expect("Failed to create user");

    // Need a role first
    let role_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO agent_roles (id, name, allowed_capabilities) VALUES ($1, $2, $3)")
        .bind(role_id)
        .bind("Test Role")
        .bind(&vec!["minimal"])
        .execute(&db_pool)
        .await
        .unwrap();

    let agent_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO mcp_agents (id, user_id, name, role_id, token_hash, is_active, created_at) VALUES ($1, $2, $3, $4, $5, $6, NOW())"
    )
    .bind(agent_id)
    .bind(user_id)
    .bind("Test Agent")
    .bind(role_id)
    .bind("hashed_token")
    .bind(true)
    .execute(&db_pool)
    .await
    .unwrap();

    let query = r#"
        query {
            mcpAgents {
                id
                name
            }
        }
    "#;

    let req = async_graphql::Request::new(query).data(user_id);
    let res = schema.execute(req).await;
    assert!(res.errors.is_empty(), "Query failed: {:?}", res.errors);

    let data = res.data.into_json().unwrap();
    let agents = data["mcpAgents"].as_array().unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0]["name"], "Test Agent");

    let mutation = format!(
        r#"
        mutation {{
            revokeMcpAgent(id: "{}")
        }}
    "#,
        agent_id
    );

    let req = async_graphql::Request::new(&mutation).data(user_id);
    let res = schema.execute(req).await;
    assert!(res.errors.is_empty(), "Mutation failed: {:?}", res.errors);
    assert!(res.data.into_json().unwrap()["revokeMcpAgent"]
        .as_bool()
        .unwrap());

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM mcp_agents WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&db_pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}
