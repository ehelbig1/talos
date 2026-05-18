use async_graphql::Schema;
use controller::api::schema::{ApiKeyScopes, MutationRoot, QueryRoot, SubscriptionRoot};
use controller::api_keys::{ApiKeyScope, ApiKeyService};
use controller::auth::AuthService;
use controller::db::init_pool;
use controller::dlp::DlpService;
use controller::module_executions::ModuleExecutionService;
use controller::secrets::SecretsManager;
use controller::totp_2fa::TotpService;
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use uuid::Uuid;

#[allow(dead_code)]
pub type TalosSchema = Schema<QueryRoot, MutationRoot, SubscriptionRoot>;

#[allow(dead_code)]
pub struct TestContext {
    pub db_pool: Pool<Postgres>,
    pub schema: TalosSchema,
    pub auth_service: Arc<AuthService>,
    pub api_key_service: Arc<ApiKeyService>,
    pub execution_service: Arc<ModuleExecutionService>,
    pub totp_service: Arc<TotpService>,
    pub secrets_manager: Arc<SecretsManager>,
}

#[allow(dead_code)]
pub async fn setup_test_context() -> TestContext {
    let _ = dotenvy::dotenv();
    let db_pool = init_pool()
        .await
        .expect("Failed to connect to test database");

    // Clean up test data
    let _ = sqlx::query("DELETE FROM organization_members")
        .execute(&db_pool)
        .await;
    let _ = sqlx::query("DELETE FROM organizations")
        .execute(&db_pool)
        .await;
    let _ = sqlx::query("DELETE FROM execution_approvals")
        .execute(&db_pool)
        .await;
    let _ = sqlx::query("DELETE FROM dead_letter_queue")
        .execute(&db_pool)
        .await;
    let _ = sqlx::query("DELETE FROM webhook_dlq")
        .execute(&db_pool)
        .await;
    let _ = sqlx::query("DELETE FROM webhook_triggers")
        .execute(&db_pool)
        .await;
    let _ = sqlx::query("DELETE FROM api_keys").execute(&db_pool).await;
    let _ = sqlx::query("DELETE FROM user_sessions")
        .execute(&db_pool)
        .await;
    let _ = sqlx::query("DELETE FROM module_execution_logs")
        .execute(&db_pool)
        .await;
    let _ = sqlx::query("DELETE FROM module_executions")
        .execute(&db_pool)
        .await;
    let _ = sqlx::query("DELETE FROM modules").execute(&db_pool).await;
    let _ = sqlx::query("DELETE FROM workflows").execute(&db_pool).await;
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

    let api_key_service = Arc::new(ApiKeyService::new(db_pool.clone(), None));
    let secrets_manager =
        Arc::new(SecretsManager::new(db_pool.clone()).expect("Failed to create SecretsManager"));
    let totp_service = Arc::new(TotpService::new(
        db_pool.clone(),
        None,
        secrets_manager.clone(),
    ));
    let dlp_service = Arc::new(DlpService::from_env());
    let execution_service = Arc::new(ModuleExecutionService::new(db_pool.clone(), dlp_service));

    let schema = Schema::build(
        QueryRoot::default(),
        MutationRoot::default(),
        SubscriptionRoot,
    )
    .data(db_pool.clone())
    .data(auth_service.clone())
    .data(api_key_service.clone())
    .data(totp_service.clone())
    .data(execution_service.clone())
    .finish();

    TestContext {
        db_pool,
        schema,
        auth_service,
        api_key_service,
        execution_service,
        totp_service,
        secrets_manager,
    }
}

#[allow(dead_code)]
pub async fn create_test_user(auth_service: &AuthService, email: &str) -> Uuid {
    auth_service
        .create_user(
            email,
            "password123456!", // Must meet complexity requirements (12 chars)
            Some("Test User"),
            None,
            None,
        )
        .await
        .expect("Failed to create user")
}

#[allow(dead_code)]
pub async fn login_test_user(auth_service: &AuthService, email: &str) -> (String, String) {
    let (access, refresh, _user) = auth_service
        .login(email, "password123456!", None, None)
        .await
        .expect("Failed to login");
    (access, refresh)
}

#[allow(dead_code)]
pub async fn create_test_organization(db_pool: &Pool<Postgres>, name: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO organizations (name) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(db_pool)
        .await
        .expect("Failed to create organization")
}

#[allow(dead_code)]
pub async fn add_user_to_organization(
    db_pool: &Pool<Postgres>,
    user_id: Uuid,
    organization_id: Uuid,
    role: &str,
) {
    // MCP-595/596 sibling: `organization_members` column is `org_id`,
    // not `organization_id`. This test helper would fail at runtime
    // ("column 'organization_id' does not exist") the moment any test
    // exercised it. Currently the helper has zero callers but keep it
    // accurate so a future user of the harness doesn't get a confusing
    // surprise.
    sqlx::query(
        "INSERT INTO organization_members (user_id, org_id, role) VALUES ($1, $2, $3)",
    )
    .bind(user_id)
    .bind(organization_id)
    .bind(role)
    .execute(db_pool)
    .await
    .expect("Failed to add user to organization");
}

#[allow(dead_code)]
pub async fn create_authenticated_org_client(
    ctx: &TestContext,
    email: &str,
    org_name: &str,
    role: &str,
    scopes: Vec<ApiKeyScope>,
) -> AuthenticatedClient {
    let user_id = create_test_user(&ctx.auth_service, email).await;
    let organization_id = create_test_organization(&ctx.db_pool, org_name).await;
    add_user_to_organization(&ctx.db_pool, user_id, organization_id, role).await;

    AuthenticatedClient::new(user_id, Some(organization_id), scopes, ctx.schema.clone())
}

#[allow(dead_code)]
pub struct AuthenticatedClient {
    pub user_id: Uuid,
    pub organization_id: Option<Uuid>,
    pub scopes: Vec<ApiKeyScope>,
    pub schema: TalosSchema,
}

impl AuthenticatedClient {
    #[allow(dead_code)]
    pub fn new(
        user_id: Uuid,
        organization_id: Option<Uuid>,
        scopes: Vec<ApiKeyScope>,
        schema: TalosSchema,
    ) -> Self {
        Self {
            user_id,
            organization_id,
            scopes,
            schema,
        }
    }

    #[allow(dead_code)]
    pub async fn execute(&self, query: &str) -> async_graphql::Response {
        let mut req = async_graphql::Request::new(query)
            .data(self.user_id)
            .data(ApiKeyScopes(self.scopes.clone()));

        if let Some(org_id) = self.organization_id {
            req = req.data(org_id);
        }

        self.schema.execute(req).await
    }

    #[allow(dead_code)]
    pub async fn execute_with_variables(
        &self,
        query: &str,
        variables: serde_json::Value,
    ) -> async_graphql::Response {
        let vars = async_graphql::Variables::from_json(variables);
        let mut req = async_graphql::Request::new(query)
            .variables(vars)
            .data(self.user_id)
            .data(ApiKeyScopes(self.scopes.clone()));

        if let Some(org_id) = self.organization_id {
            req = req.data(org_id);
        }

        self.schema.execute(req).await
    }
}

#[allow(dead_code)]
pub async fn create_test_workflow(
    db_pool: &sqlx::Pool<sqlx::Postgres>,
    user_id: uuid::Uuid,
    name: &str,
) -> uuid::Uuid {
    let workflow_id = uuid::Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status, created_at, updated_at)
        VALUES ($1, $2, $3, '{}', 'talos://test-module', 'draft', NOW(), NOW())
        "#,
    )
    .bind(workflow_id)
    .bind(user_id)
    .bind(name)
    .execute(db_pool)
    .await
    .expect("Failed to create test workflow");
    workflow_id
}
