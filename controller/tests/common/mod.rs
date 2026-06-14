use async_graphql::Schema;
use controller::api::schema::{
    ApiKeyScopes, IsTwoFactorVerified, MutationRoot, QueryRoot, SubscriptionRoot,
};
use controller::api_keys::{ApiKeyScope, ApiKeyService};
use controller::auth::AuthService;
use controller::dlp::DlpService;
use controller::module_executions::ModuleExecutionService;
use controller::secrets::SecretsManager;
use controller::totp_2fa::TotpService;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, PgConnection, Pool, Postgres};
use std::str::FromStr;
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
    // Drops the per-test database when the context goes out of scope. MUST be
    // the last field so it drops AFTER `db_pool` (fields drop in declaration
    // order) — the pool's connections close first, then the DB is removed.
    _db: TestDb,
}

/// A throwaway per-test database, created as a fast file-copy of the migrated
/// template database (`DATABASE_URL`, e.g. `talos_ctl`). Each test gets its own
/// isolated database, so tests never see each other's rows. This retires the
/// global `DELETE FROM …` cleanup and the cross-binary serialization it forced
/// — see docs/backlog.md "Per-test DB isolation".
#[allow(dead_code)]
pub struct TestDb {
    /// The original `DATABASE_URL` (used to reconstruct an admin connection on
    /// the maintenance `postgres` db for the drop).
    template_url: String,
    db_name: String,
}

impl Drop for TestDb {
    fn drop(&mut self) {
        // Drop is synchronous but sqlx is async, and we are typically dropping
        // from inside the test's Tokio runtime — building a runtime inside a
        // runtime panics. Run the drop on a dedicated OS thread with its own
        // current-thread runtime. `DROP DATABASE … WITH (FORCE)` terminates any
        // backends the test's pool still holds. Best-effort: a failure here
        // only leaks one small (data-free) database, swept on the next run.
        let template_url = self.template_url.clone();
        let db_name = self.db_name.clone();
        let _ = std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => return,
            };
            rt.block_on(async move {
                let Ok(admin_opts) = PgConnectOptions::from_str(&template_url) else {
                    return;
                };
                let admin_opts = admin_opts.database("postgres");
                if let Ok(mut conn) = PgConnection::connect_with(&admin_opts).await {
                    let _ = sqlx::query(&format!(
                        "DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)"
                    ))
                    .execute(&mut conn)
                    .await;
                    let _ = conn.close().await;
                }
            });
        })
        .join();
    }
}

/// Create an isolated per-test database (a `TEMPLATE` clone of the migrated DB
/// `DATABASE_URL` points at) and return a pool bound to it plus a guard that
/// drops it on scope-exit. Used by `setup_test_context` and by other CTL test
/// binaries that need an isolated DB without the shared-state cleanup.
#[allow(dead_code)]
pub async fn isolated_db_pool() -> (Pool<Postgres>, TestDb) {
    let _ = dotenvy::dotenv();
    let db_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set to a migrated template database (e.g. talos_ctl)");
    let base = PgConnectOptions::from_str(&db_url)
        .expect("DATABASE_URL is not a valid Postgres connection string");
    let template = base.get_database().unwrap_or("postgres").to_string();
    let db_name = format!("test_{}", Uuid::new_v4().simple());

    // CREATE DATABASE … TEMPLATE must run from a connection NOT on the template
    // (and the template must be connection-free). Use the maintenance db.
    let admin_opts = base.clone().database("postgres");
    let mut admin = PgConnection::connect_with(&admin_opts)
        .await
        .expect("connect to maintenance 'postgres' db");

    // The template is connection-free in steady state, but a peer test cloning
    // the same template at the same instant can briefly hold it; retry the
    // "source database is being accessed by other users" race a few times.
    let create_sql = format!("CREATE DATABASE \"{db_name}\" TEMPLATE \"{template}\"");
    let mut attempt = 0;
    loop {
        match sqlx::query(&create_sql).execute(&mut admin).await {
            Ok(_) => break,
            Err(e) if attempt < 10 && e.to_string().contains("being accessed by other users") => {
                attempt += 1;
                tokio::time::sleep(std::time::Duration::from_millis(100 * attempt)).await;
            }
            Err(e) => panic!("failed to create test database from template '{template}': {e}"),
        }
    }
    let _ = admin.close().await;

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect_with(base.clone().database(&db_name))
        .await
        .expect("connect to isolated test database");

    (
        pool,
        TestDb {
            template_url: db_url,
            db_name,
        },
    )
}

#[allow(dead_code)]
pub async fn setup_test_context() -> TestContext {
    // Each test runs against its own isolated database (a template clone of the
    // migrated DB). No global `DELETE FROM …` cleanup is needed — the database
    // starts empty of test rows and is dropped when the context goes out of
    // scope. This is what lets these binaries run in parallel.
    let (db_pool, _db) = isolated_db_pool().await;

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
        _db,
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
    sqlx::query("INSERT INTO organization_members (user_id, org_id, role) VALUES ($1, $2, $3)")
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
            .data(ApiKeyScopes(self.scopes.clone()))
            // Mirror the real API-key auth path (controller/src/main.rs:5805):
            // API-key requests are 2FA-verified by construction. Without this,
            // every 2FA-gated mutation (`require_2fa`, MCP-616 fail-closed)
            // rejects with "Two-Factor Authentication required" before the
            // scope check runs.
            .data(IsTwoFactorVerified(true));

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
            .data(ApiKeyScopes(self.scopes.clone()))
            // See `execute` — replicate the API-key path's 2FA-verified context.
            .data(IsTwoFactorVerified(true));

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
