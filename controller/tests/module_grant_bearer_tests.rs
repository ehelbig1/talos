//! What an MCP bearer token may grant a module, and at which worlds a user
//! may compile and install (security review 2026-10-14, A-2, G-3, G-23,
//! G-24).
//!
//! * A-2 / G-23: `update_module_secrets(["*"])`, `update_module_hosts(["*"])`
//!   and a `*` in a compile or `run_sandbox` grant are refused for a bearer
//!   token; an edit of a stored module's grants passes the role and user
//!   ceiling gate for the module's world; the lists are bounded.
//! * G-3: the user's own capability ceiling bounds compile/install/run, and
//!   `registerMcpAgent` does not issue a role above it.
//! * G-24: a marketplace install takes no `*` and, from another publisher, no
//!   `/*` prefix; it counts against the per-user module quota.
//!
//! Every refusal here comes before a compile, so no toolchain runs.
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use std::sync::Arc;

use controller::api::schema::{IsTwoFactorVerified, SecondFactorVerified};
use controller::mcp::auth::AgentIdentity;
use talos_actor_repository::ActorRepository;
use talos_capability_world::WILDCARD_GRANT_NEEDS_SECOND_FACTOR;
use uuid::Uuid;

fn agent_with(user: Uuid, caps: &[&str]) -> Arc<AgentIdentity> {
    Arc::new(AgentIdentity {
        agent_id: Uuid::new_v4(),
        name: "grant-probe".to_string(),
        role_name: "probe".to_string(),
        allowed_capabilities: caps.iter().map(|c| (*c).to_string()).collect(),
        user_id: user,
    })
}

async fn seed_module(pool: &sqlx::PgPool, user: Uuid, world: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, kind, capability_world, allowed_secrets, \
                              allowed_hosts) \
         VALUES ($1, $2, $3, 'sandbox', $4, ARRAY['svc/a'], ARRAY['api.example.test'])",
    )
    .bind(id)
    .bind(user)
    .bind(format!("grant-module-{}", &id.to_string()[..8]))
    .bind(world)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn grants(pool: &sqlx::PgPool, module: Uuid) -> (Vec<String>, Vec<String>) {
    sqlx::query_as("SELECT allowed_secrets, allowed_hosts FROM modules WHERE id = $1")
        .bind(module)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn sandbox(
    state: &controller::mcp::McpState,
    agent: Arc<AgentIdentity>,
    tool: &str,
    args: serde_json::Value,
) -> controller::mcp::types::JsonRpcResponse {
    controller::mcp::sandbox::dispatch(tool, Some(serde_json::json!(1)), &args, state, agent)
        .await
        .expect("dispatched")
}

async fn grant(pool: &sqlx::PgPool, user: Uuid, world: &str) {
    ActorRepository::new(pool.clone())
        .upsert_capability_grant(user, world, user, None)
        .await
        .unwrap();
}

/// A-2 / G-23: no `*` from a bearer token, on any of the four writes; exact
/// entries are written; a role below the module's world edits nothing; a list
/// over the bounds is refused.
#[tokio::test]
async fn a_bearer_token_grants_exact_paths_and_hosts_only() {
    let ctx = common::setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = common::create_test_user(&ctx.auth_service, "grant-owner@example.com").await;
    grant(&pool, user, "automation-node").await;
    let module = seed_module(&pool, user, "http-node").await;
    let state = mcp_common::mcp_state(pool.clone()).await;
    let token = mcp_common::agent(user);
    let mid = module.to_string();

    for (tool, key) in [
        ("update_module_secrets", "allowed_secrets"),
        ("update_module_hosts", "allowed_hosts"),
    ] {
        let resp = sandbox(
            &state,
            token.clone(),
            tool,
            serde_json::json!({ "module_id": mid, key: ["*"] }),
        )
        .await;
        assert_eq!(
            mcp_common::error_message(&resp),
            WILDCARD_GRANT_NEEDS_SECOND_FACTOR
        );
    }
    assert_eq!(
        grants(&pool, module).await,
        (
            vec!["svc/a".to_string()],
            vec!["api.example.test".to_string()]
        )
    );

    // A compile and a sandbox run refuse a `*` before anything is compiled.
    for tool in ["compile_custom_sandbox", "run_sandbox"] {
        let resp = sandbox(
            &state,
            token.clone(),
            tool,
            serde_json::json!({
                "name": "grant-probe",
                "rust_code": "pub fn run(_input: String) -> String { String::new() }",
                "capability_world": "http-node",
                "allowed_hosts": ["*"],
            }),
        )
        .await;
        assert_eq!(
            mcp_common::error_message(&resp),
            WILDCARD_GRANT_NEEDS_SECOND_FACTOR,
            "{tool}"
        );
    }

    // Exact entries widen the grant.
    let resp = sandbox(
        &state,
        token.clone(),
        "update_module_secrets",
        serde_json::json!({ "module_id": mid, "allowed_secrets": ["svc/a", "svc/b"] }),
    )
    .await;
    assert!(resp.error.is_none(), "{resp:?}");
    assert_eq!(grants(&pool, module).await.0, vec!["svc/a", "svc/b"]);

    // Bounds: 51 entries.
    let many: Vec<String> = (0..51).map(|i| format!("svc/k{i}")).collect();
    let resp = sandbox(
        &state,
        token.clone(),
        "update_module_secrets",
        serde_json::json!({ "module_id": mid, "allowed_secrets": many }),
    )
    .await;
    assert!(mcp_common::error_message(&resp).contains("maximum of 50"));

    // G-23: a `minimal` role does not edit an http-node module's grants.
    let narrow = agent_with(user, &["minimal"]);
    let resp = sandbox(
        &state,
        narrow,
        "update_module_hosts",
        serde_json::json!({ "module_id": mid, "allowed_hosts": ["other.example.test"] }),
    )
    .await;
    assert!(
        mcp_common::error_message(&resp).contains("lacks capability"),
        "{resp:?}"
    );
    assert_eq!(grants(&pool, module).await.1, vec!["api.example.test"]);

    // The repository refuses a `*` for a bearer and writes one for a second
    // factor — the rule lives at the write, not only in the handler.
    let repo = talos_module_repository::ModuleRepository::new(pool.clone());
    let star = vec!["*".to_string()];
    let err = repo
        .update_module_allowed_hosts(
            module,
            user,
            &star,
            &|_: &[String], new: &[String]| new.to_vec(),
            talos_capability_world::ChangeAuthority::BearerCredential,
        )
        .await
        .expect_err("refused");
    assert!(err
        .downcast_ref::<talos_module_repository::WildcardGrantRefused>()
        .is_some());
    repo.update_module_allowed_hosts(
        module,
        user,
        &star,
        &|_: &[String], new: &[String]| new.to_vec(),
        talos_capability_world::ChangeAuthority::SecondFactorSession,
    )
    .await
    .unwrap()
    .expect("owned");
    assert_eq!(grants(&pool, module).await.1, vec!["*"]);
}

/// G-3: the user's ceiling bounds a compile even when the agent's role
/// permits the world, and an edit of a module above it.
#[tokio::test]
async fn the_users_ceiling_bounds_what_their_agent_compiles() {
    let ctx = common::setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = common::create_test_user(&ctx.auth_service, "ceiling-compiler@example.com").await;
    grant(&pool, user, "minimal-node").await;
    let state = mcp_common::mcp_state(pool.clone()).await;
    let token = mcp_common::agent(user); // role `*`

    for (tool, world) in [
        ("compile_custom_sandbox", "governance-node"),
        ("run_sandbox", "http-node"),
    ] {
        let resp = sandbox(
            &state,
            token.clone(),
            tool,
            serde_json::json!({
                "name": "ceiling-probe",
                "rust_code": "pub fn run(_input: String) -> String { String::new() }",
                "capability_world": world,
            }),
        )
        .await;
        let msg = mcp_common::error_message(&resp);
        assert!(
            msg.contains("your capability ceiling is 'minimal-node'"),
            "{tool}: {msg}"
        );
    }

    let module = seed_module(&pool, user, "http-node").await;
    let resp = sandbox(
        &state,
        token,
        "update_module_secrets",
        serde_json::json!({ "module_id": module.to_string(), "allowed_secrets": ["svc/b"] }),
    )
    .await;
    assert!(mcp_common::error_message(&resp).contains("your capability ceiling"));
    assert_eq!(grants(&pool, module).await.0, vec!["svc/a"]);
}

/// G-3: `registerMcpAgent` issues a role only within the caller's ceiling; a
/// platform admin issues any.
#[tokio::test]
async fn an_agent_role_is_issued_within_the_users_ceiling() {
    let ctx = common::setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = common::create_test_user(&ctx.auth_service, "role-issuer@example.com").await;
    grant(&pool, user, "minimal-node").await;
    // The `System Administrator` shape: every world.
    let role = format!("probe-wide-{}", &user.to_string()[..8]);
    sqlx::query(
        "INSERT INTO agent_roles (name, allowed_capabilities) \
         VALUES ($1, ARRAY['automation','secrets','governance','http','minimal'])",
    )
    .bind(&role)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("UPDATE users SET totp_enabled = true WHERE id = $1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    let register = |role: &str, name: &str| {
        async_graphql::Request::new(format!(
            r#"mutation {{ registerMcpAgent(name: "{name}", roleName: "{role}") {{ agentId }} }}"#
        ))
        .data(user)
        .data(IsTwoFactorVerified(true))
        .data(SecondFactorVerified(true))
    };
    let agents = |pool: sqlx::PgPool| async move {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM mcp_agents WHERE user_id = $1")
            .bind(user)
            .fetch_one(&pool)
            .await
            .unwrap()
    };

    let resp = ctx.schema.execute(register(&role, "too-wide")).await;
    assert!(
        resp.errors
            .first()
            .is_some_and(|e| e.message.contains("beyond your capability ceiling")),
        "{:?}",
        resp.errors
    );
    assert_eq!(agents(pool.clone()).await, 0);

    // Within the ceiling once it is wide enough.
    grant(&pool, user, "automation-node").await;
    let resp = ctx.schema.execute(register(&role, "fits")).await;
    assert!(resp.errors.is_empty(), "{:?}", resp.errors);
    assert_eq!(agents(pool.clone()).await, 1);

    // A platform admin issues a role above their own ceiling.
    grant(&pool, user, "minimal-node").await;
    sqlx::query("UPDATE users SET is_platform_admin = true WHERE id = $1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    let resp = ctx.schema.execute(register(&role, "admin-issued")).await;
    assert!(resp.errors.is_empty(), "{:?}", resp.errors);
    assert_eq!(agents(pool.clone()).await, 2);
}

/// G-24: a marketplace install takes exact secret paths, from another
/// publisher no `/*` prefix, and counts against the module quota.
#[tokio::test]
async fn a_marketplace_install_is_granted_exact_paths_within_the_quota() {
    let ctx = common::setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let publisher = common::create_test_user(&ctx.auth_service, "mk-publisher@example.com").await;
    let installer = common::create_test_user(&ctx.auth_service, "mk-installer@example.com").await;
    grant(&pool, installer, "automation-node").await;
    let source = seed_module(&pool, publisher, "minimal-node").await;
    let listing = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO module_marketplace \
             (id, module_id, name, publisher_id, description, capability_world, version, \
              is_public, downloads, tags, verified, star_count, snapshot_source_code, \
              snapshot_allowed_hosts, snapshot_allowed_methods, snapshot_taken_at) \
         VALUES ($1, $2, 'mk-listing', $3, 'd', 'minimal-node', '1.0.0', true, 0, \
                 ARRAY[]::text[], false, 0, 'pub fn run(_i: String) -> String { String::new() }', \
                 ARRAY[]::text[], ARRAY[]::text[], now())",
    )
    .bind(listing)
    .bind(source)
    .bind(publisher)
    .execute(&pool)
    .await
    .unwrap();
    let state = mcp_common::mcp_state(pool.clone()).await;
    let install = |secrets: serde_json::Value| {
        let state = state.clone();
        async move {
            controller::mcp::advanced::dispatch(
                "install_from_marketplace",
                Some(serde_json::json!(1)),
                &serde_json::json!({ "listing_id": listing.to_string(), "allowed_secrets": secrets }),
                &state,
                mcp_common::agent(installer),
            )
            .await
            .expect("dispatched")
        }
    };
    let installed = |pool: sqlx::PgPool| async move {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM modules WHERE user_id = $1 AND name LIKE '%(marketplace)'",
        )
        .bind(installer)
        .fetch_one(&pool)
        .await
        .unwrap()
    };

    let resp = install(serde_json::json!(["*"])).await;
    assert_eq!(
        mcp_common::error_message(&resp),
        WILDCARD_GRANT_NEEDS_SECOND_FACTOR
    );
    let resp = install(serde_json::json!(["svc/*"])).await;
    assert!(mcp_common::error_message(&resp).contains("exact secret paths only"));
    assert_eq!(installed(pool.clone()).await, 0);

    // The quota: 500 modules already held.
    sqlx::query(
        "INSERT INTO modules (user_id, name, kind, capability_world) \
         SELECT $1, 'quota-' || g, 'sandbox', 'minimal-node' FROM generate_series(1, 500) g",
    )
    .bind(installer)
    .execute(&pool)
    .await
    .unwrap();
    let resp = install(serde_json::json!(["svc/token"])).await;
    assert!(mcp_common::error_message(&resp).contains("Installed module limit reached"));
    assert_eq!(installed(pool.clone()).await, 0);

    // Control: under the quota, an exact path installs.
    sqlx::query("DELETE FROM modules WHERE user_id = $1 AND name LIKE 'quota-%'")
        .bind(installer)
        .execute(&pool)
        .await
        .unwrap();
    let resp = install(serde_json::json!(["svc/token"])).await;
    assert!(resp.error.is_none(), "{resp:?}");
    assert_eq!(installed(pool.clone()).await, 1, "{resp:?}");
}

/// G-3: the GraphQL `createModuleFromTemplate` makes a module at the
/// template's world only within the caller's ceiling.
#[tokio::test]
async fn a_dashboard_module_is_created_within_the_users_ceiling() {
    let ctx = common::setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = common::create_test_user(&ctx.auth_service, "dash-module@example.com").await;
    grant(&pool, user, "minimal-node").await;
    let template = seed_module(&pool, user, "governance-node").await;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM modules WHERE user_id = $1")
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
    let req = async_graphql::Request::new(format!(
        r#"mutation {{ createModuleFromTemplate(input: {{templateId: "{template}", name: "dash-probe", config: "{{}}"}}) {{ id }} }}"#
    ))
    .data(user)
    .data(IsTwoFactorVerified(true))
    .data(SecondFactorVerified(false))
    .data(Arc::new(talos_registry::ModuleRegistry::new(pool.clone(), None)))
    .data(Arc::new(controller::compilation::CompilationService::new(
        std::path::PathBuf::from("/tmp/talos-compilations-test"),
        tokio::sync::broadcast::channel::<controller::engine::events::CompilationEvent>(8).0,
    )))
    .data(ctx.secrets_manager.clone());
    let resp = ctx.schema.execute(req).await;
    assert!(
        resp.errors.first().is_some_and(|e| e
            .message
            .contains("Your capability ceiling is 'minimal-node'")),
        "{:?}",
        resp.errors
    );
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM modules WHERE user_id = $1")
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(before, after);
}
