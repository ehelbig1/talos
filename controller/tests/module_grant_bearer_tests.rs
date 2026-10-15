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
use talos_capability_world::{SECRET_WILDCARD_RETIRED, WILDCARD_GRANT_NEEDS_SECOND_FACTOR};
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
        // A `*` secret grant is refused for every authority (D2-D); a `*`
        // host grant needs a second factor.
        let expected = if key == "allowed_secrets" {
            SECRET_WILDCARD_RETIRED
        } else {
            WILDCARD_GRANT_NEEDS_SECOND_FACTOR
        };
        assert_eq!(mcp_common::error_message(&resp), expected, "{tool}");
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
    assert_eq!(mcp_common::error_message(&resp), SECRET_WILDCARD_RETIRED);
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

async fn seed_workflow(pool: &sqlx::PgPool, user: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status) \
         VALUES ($1, $2, $3, '{\"nodes\": [], \"edges\": []}', 'talos://test', 'draft')",
    )
    .bind(id)
    .bind(user)
    .bind(format!("grant-wf-{}", &id.to_string()[..8]))
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn workflow_tool(
    state: &Arc<controller::mcp::McpState>,
    agent: Arc<AgentIdentity>,
    tool: &str,
    args: serde_json::Value,
) -> controller::mcp::types::JsonRpcResponse {
    controller::mcp::workflows::dispatch(
        tool,
        Some(serde_json::json!(1)),
        &args,
        state.clone(),
        agent,
    )
    .await
    .expect("dispatched")
}

async fn module_count(pool: &sqlx::PgPool, user: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM modules WHERE user_id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn graph(pool: &sqlx::PgPool, workflow: Uuid) -> String {
    sqlx::query_scalar("SELECT graph_json::text FROM workflows WHERE id = $1")
        .bind(workflow)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// A2-1 (2026-10-15): `add_node_to_workflow`'s inline compile takes no
/// wildcard grant from a bearer — a `*` secret, a `<prefix>/*` secret glob,
/// a `*` host, nor the every-host default of a network world it used to hand
/// out when no hosts were named. Refused before anything is compiled; no
/// module row, no graph change.
#[tokio::test]
async fn an_inline_node_takes_no_wildcard_grant_from_a_bearer() {
    let ctx = common::setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = common::create_test_user(&ctx.auth_service, "inline-grant@example.com").await;
    grant(&pool, user, "automation-node").await;
    let wf = seed_workflow(&pool, user).await;
    let before = graph(&pool, wf).await;
    let state = Arc::new(mcp_common::mcp_state(pool.clone()).await);
    let token = mcp_common::agent(user);
    let node = |extra: serde_json::Value| {
        let mut args = serde_json::json!({
            "workflow_id": wf.to_string(),
            "node_id": "inline-probe",
            "rust_code": "pub fn run(_input: String) -> String { String::new() }",
            "capability_world": "http-node",
        });
        args.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        args
    };
    for extra in [
        serde_json::json!({ "allowed_secrets": ["*"], "allowed_hosts": ["api.example.test"] }),
        serde_json::json!({ "allowed_secrets": ["svc/*"], "allowed_hosts": ["api.example.test"] }),
        serde_json::json!({ "allowed_hosts": ["*"] }),
    ] {
        let resp = workflow_tool(
            &state,
            token.clone(),
            "add_node_to_workflow",
            node(extra.clone()),
        )
        .await;
        let expected = if extra["allowed_secrets"] == serde_json::json!(["*"]) {
            SECRET_WILDCARD_RETIRED
        } else {
            WILDCARD_GRANT_NEEDS_SECOND_FACTOR
        };
        assert_eq!(mcp_common::error_message(&resp), expected, "{extra}");
    }
    // A network world with no host list: the every-host default is a `*`.
    let resp = workflow_tool(
        &state,
        token.clone(),
        "add_node_to_workflow",
        node(serde_json::json!({})),
    )
    .await;
    assert_eq!(
        mcp_common::error_message(&resp),
        talos_workflow_creation_helpers::HOSTS_MUST_BE_NAMED
    );
    assert_eq!(module_count(&pool, user).await, 0, "no module row");
    assert_eq!(graph(&pool, wf).await, before, "no graph change");

    // create_workflow_from_spec: a spec grants secrets by path.
    let resp = workflow_tool(
        &state,
        token,
        "create_workflow_from_spec",
        serde_json::json!({
            "name": "spec-grant-probe",
            "nodes": [{
                "id": "spec-probe",
                "rust_code": "pub fn run(_input: String) -> String { String::new() }",
                "capability_world": "http-node",
                "allowed_hosts": ["api.example.test"],
                "allowed_secrets": ["*"],
            }],
            "edges": [],
        }),
    )
    .await;
    assert!(
        mcp_common::error_message(&resp).contains("allowed_secrets may not contain"),
        "{resp:?}"
    );
    assert_eq!(module_count(&pool, user).await, 0);
}

/// A2-2 (2026-10-15): `add_node_to_workflow`'s inline compile is bounded by
/// the user's own capability ceiling (and the agent's role), like every other
/// compile surface — an actor-less workflow has no actor ceiling to stop it.
#[tokio::test]
async fn an_inline_node_is_compiled_within_the_users_ceiling() {
    let ctx = common::setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = common::create_test_user(&ctx.auth_service, "inline-ceiling@example.com").await;
    grant(&pool, user, "minimal-node").await;
    let wf = seed_workflow(&pool, user).await;
    let before = graph(&pool, wf).await;
    let state = Arc::new(mcp_common::mcp_state(pool.clone()).await);
    let args = serde_json::json!({
        "workflow_id": wf.to_string(),
        "node_id": "ceiling-probe",
        "rust_code": "pub fn run(_input: String) -> String { String::new() }",
        "capability_world": "http-node",
        "allowed_hosts": ["api.example.test"],
    });
    let resp = workflow_tool(
        &state,
        mcp_common::agent(user),
        "add_node_to_workflow",
        args.clone(),
    )
    .await;
    assert!(
        mcp_common::error_message(&resp).contains("your capability ceiling is 'minimal-node'"),
        "{resp:?}"
    );
    // A role below the world refuses too.
    let resp = workflow_tool(
        &state,
        agent_with(user, &["minimal"]),
        "add_node_to_workflow",
        args,
    )
    .await;
    assert!(
        mcp_common::error_message(&resp).contains("lacks capability"),
        "{resp:?}"
    );
    assert_eq!(module_count(&pool, user).await, 0, "no module row");
    assert_eq!(graph(&pool, wf).await, before, "no graph change");
}

/// G2-1 (2026-10-15): `import_workflow` holds a bundle module's world — the
/// bundle's stated world, else the one its source declares — to the caller's
/// role and capability ceiling before it compiles anything.
#[tokio::test]
async fn an_imported_module_is_compiled_within_the_users_ceiling() {
    let ctx = common::setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = common::create_test_user(&ctx.auth_service, "import-ceiling@example.com").await;
    grant(&pool, user, "minimal-node").await;
    let state = Arc::new(mcp_common::mcp_state(pool.clone()).await);
    let module = Uuid::new_v4();
    let bundle = |world: Option<&str>, source: &str| {
        let mut m = serde_json::json!({
            "id": module.to_string(),
            "name": "imported-probe",
            "source_code": source,
        });
        if let Some(w) = world {
            m["capability_world"] = serde_json::json!(w);
        }
        serde_json::json!({
            "bundle": {
                "name": "import-probe",
                "graph_json": { "nodes": [{ "id": "n1", "type": module.to_string(), "data": {} }],
                                "edges": [] },
                "modules": [m],
            }
        })
    };
    let plain = "pub fn run(_input: String) -> String { String::new() }";
    let declaring = "#[talos_module(world = \"automation-node\")]\npub fn run(_input: String) -> String { String::new() }";
    for (world, src) in [(Some("automation-node"), plain), (None, declaring)] {
        let resp = workflow_tool(
            &state,
            mcp_common::agent(user),
            "import_workflow",
            bundle(world, src),
        )
        .await;
        assert!(
            mcp_common::error_message(&resp).contains("your capability ceiling is 'minimal-node'"),
            "{world:?}: {resp:?}"
        );
    }
    let resp = workflow_tool(
        &state,
        agent_with(user, &["minimal"]),
        "import_workflow",
        bundle(Some("http-node"), plain),
    )
    .await;
    assert!(
        mcp_common::error_message(&resp).contains("lacks capability"),
        "{resp:?}"
    );
    assert_eq!(module_count(&pool, user).await, 0, "no module row");
    let workflows: i64 = sqlx::query_scalar("SELECT count(*) FROM workflows WHERE user_id = $1")
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(workflows, 0, "no workflow imported");
}

/// A2-3 (2026-10-15): a `<prefix>/*` secret glob is a wildcard for a bearer
/// on `update_module_secrets` and at the repository write, as the marketplace
/// install already held it; a second-factor session writes it. A bare
/// namespace (`oauth/gmail`) is an exact-path-shaped grant and is written.
#[tokio::test]
async fn a_bearer_writes_no_secret_glob() {
    let ctx = common::setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = common::create_test_user(&ctx.auth_service, "glob-grant@example.com").await;
    grant(&pool, user, "automation-node").await;
    let module = seed_module(&pool, user, "http-node").await;
    let state = mcp_common::mcp_state(pool.clone()).await;
    let resp = sandbox(
        &state,
        mcp_common::agent(user),
        "update_module_secrets",
        serde_json::json!({ "module_id": module.to_string(), "allowed_secrets": ["svc/*"] }),
    )
    .await;
    assert_eq!(
        mcp_common::error_message(&resp),
        WILDCARD_GRANT_NEEDS_SECOND_FACTOR
    );
    assert_eq!(grants(&pool, module).await.0, vec!["svc/a"]);

    let repo = talos_module_repository::ModuleRepository::new(pool.clone());
    let glob = vec!["svc/*".to_string()];
    let keep = |_: &[String], new: &[String]| new.to_vec();
    assert!(repo
        .update_module_allowed_secrets(
            module,
            user,
            &glob,
            &keep,
            talos_capability_world::ChangeAuthority::BearerCredential,
        )
        .await
        .expect_err("refused")
        .downcast_ref::<talos_module_repository::WildcardGrantRefused>()
        .is_some());
    repo.update_module_allowed_secrets(
        module,
        user,
        &glob,
        &keep,
        talos_capability_world::ChangeAuthority::SecondFactorSession,
    )
    .await
    .unwrap()
    .expect("owned");
    assert_eq!(grants(&pool, module).await.0, vec!["svc/*"]);

    let resp = sandbox(
        &state,
        mcp_common::agent(user),
        "update_module_secrets",
        serde_json::json!({ "module_id": module.to_string(), "allowed_secrets": ["oauth/gmail"] }),
    )
    .await;
    assert!(resp.error.is_none(), "{resp:?}");
    assert_eq!(grants(&pool, module).await.0, vec!["oauth/gmail"]);
}
