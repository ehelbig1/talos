//! A privilege change is recorded in the SAME transaction as the change, and
//! the record names what it replaced (package CT, 2026-09-19).
//!
//! Package CS made credential changes atomic with their `admin_event_log`
//! row. The changes that widen what an actor, a module or a workflow may do
//! were still recorded best-effort or not at all:
//! * the dashboard's `updateActor` capability-ceiling change wrote NO record;
//! * the MCP tier / egress / write-ceiling setters recorded after the change
//!   committed, best-effort, with the previous value read outside any lock;
//! * the module permission setters and the workflow actor binding recorded
//!   from a detached task and could not say what they replaced;
//! * `hot_update_module` recorded a world change BEFORE compiling, so a
//!   failed compile left a record of a change that never happened.
//!
//! These tests drive the production MCP dispatch, the GraphQL schema and the
//! repositories, and read `admin_event_log` back: exactly one record per
//! change, carrying the previous value; nothing recorded when nothing
//! changed; and with the audit table unavailable, the change does not happen.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use common::{create_test_user, create_test_workflow, setup_test_context};
use controller::api::schema::IsTwoFactorVerified;
use mcp_common::{agent, error_message, mcp_state, text_json};
use uuid::Uuid;

async fn events(
    pool: &sqlx::PgPool,
    event_type: &str,
    resource_id: Uuid,
) -> Vec<serde_json::Value> {
    sqlx::query_scalar::<_, Option<serde_json::Value>>(
        "SELECT details FROM admin_event_log WHERE event_type = $1 AND resource_id = $2 \
         ORDER BY created_at, id",
    )
    .bind(event_type)
    .bind(resource_id)
    .fetch_all(pool)
    .await
    .unwrap()
    .into_iter()
    .map(|d| d.unwrap_or(serde_json::Value::Null))
    .collect()
}

async fn events_for(pool: &sqlx::PgPool, resource_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM admin_event_log WHERE resource_id = $1")
        .bind(resource_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Take the audit table away on this test's own database clone.
async fn break_audit_table(pool: &sqlx::PgPool) {
    sqlx::query("ALTER TABLE admin_event_log RENAME TO admin_event_log_moved")
        .execute(pool)
        .await
        .unwrap();
}

async fn seed_actor(pool: &sqlx::PgPool, user: Uuid, world: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO actors (id, user_id, name, max_capability_world, status) \
         VALUES ($1, $2, $3, $4, 'active')",
    )
    .bind(id)
    .bind(user)
    .bind(format!("ct-actor-{}", &id.to_string()[..8]))
    .bind(world)
    .execute(pool)
    .await
    .expect("seed actor");
    id
}

async fn seed_module(pool: &sqlx::PgPool, user: Uuid, world: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, kind, capability_world, allowed_secrets) \
         VALUES ($1, $2, $3, 'sandbox', $4, ARRAY['team/old_key'])",
    )
    .bind(id)
    .bind(user)
    .bind(format!("ct-module-{}", &id.to_string()[..8]))
    .bind(world)
    .execute(pool)
    .await
    .expect("seed module");
    id
}

async fn actor_column(pool: &sqlx::PgPool, actor: Uuid, column: &str) -> Option<String> {
    sqlx::query_scalar(&format!("SELECT {column} FROM actors WHERE id = $1"))
        .bind(actor)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn call(
    state: &controller::mcp::McpState,
    user: Uuid,
    tool: &str,
    args: serde_json::Value,
) -> controller::mcp::types::JsonRpcResponse {
    let id = Some(serde_json::json!(1));
    match tool {
        "set_actor_llm_tier_ceiling" | "set_actor_egress_scope" | "set_actor_write_ceiling" => {
            controller::mcp::actor::dispatch(tool, id, &args, state, agent(user)).await
        }
        "update_module_secrets" | "update_module_hosts" | "update_module_methods" => {
            controller::mcp::sandbox::dispatch(tool, id, &args, state, agent(user)).await
        }
        _ => {
            controller::mcp::workflows::dispatch(
                tool,
                id,
                &args,
                std::sync::Arc::new(state.clone()),
                agent(user),
            )
            .await
        }
    }
    .unwrap_or_else(|| panic!("{tool} is dispatched"))
}

#[tokio::test]
async fn actor_ceiling_changes_are_recorded_with_what_they_replaced() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "ct-ceilings@example.com").await;
    let stranger = create_test_user(&ctx.auth_service, "ct-ceilings-2@example.com").await;
    let actor = seed_actor(&pool, user, "http-node").await;
    let state = mcp_state(pool.clone()).await;
    let aid = actor.to_string();

    let tier = call(
        &state,
        user,
        "set_actor_llm_tier_ceiling",
        serde_json::json!({"actor_id": aid, "tier": "tier1"}),
    )
    .await;
    assert_eq!(text_json(&tier)["previous_tier"], "tier2");
    let egress = call(
        &state,
        user,
        "set_actor_egress_scope",
        serde_json::json!({"actor_id": aid, "scope": "public"}),
    )
    .await;
    assert_eq!(text_json(&egress)["previous_egress_scope"], "default");
    let cleared = call(
        &state,
        user,
        "set_actor_egress_scope",
        serde_json::json!({"actor_id": aid, "scope": null}),
    )
    .await;
    assert_eq!(text_json(&cleared)["previous_egress_scope"], "public");
    let write = call(
        &state,
        user,
        "set_actor_write_ceiling",
        serde_json::json!({"actor_id": aid, "ceiling": "write"}),
    )
    .await;
    assert_eq!(text_json(&write)["previous_ceiling"], "readonly");

    assert_eq!(
        events(&pool, "actor_llm_tier_ceiling_set", actor).await,
        vec![serde_json::json!({"previous_tier": "tier2", "new_tier": "tier1"})]
    );
    assert_eq!(
        events(&pool, "actor_egress_scope_set", actor).await,
        vec![
            serde_json::json!({"previous_egress_scope": "default", "new_egress_scope": "public"}),
            serde_json::json!({"previous_egress_scope": "public", "new_egress_scope": "default"}),
        ]
    );
    assert_eq!(
        events(&pool, "actor_write_ceiling_set", actor).await,
        vec![serde_json::json!({"previous_ceiling": "readonly", "new_ceiling": "write"})]
    );
    assert_eq!(events_for(&pool, actor).await, 4);

    // Another user's attempt changes nothing and records nothing.
    let refused = call(
        &state,
        stranger,
        "set_actor_llm_tier_ceiling",
        serde_json::json!({"actor_id": aid, "tier": "tier2"}),
    )
    .await;
    assert!(
        error_message(&refused).contains("not found"),
        "{}",
        error_message(&refused)
    );
    assert_eq!(
        actor_column(&pool, actor, "max_llm_tier").await.as_deref(),
        Some("tier1")
    );
    assert_eq!(events_for(&pool, actor).await, 4);
}

#[tokio::test]
async fn an_actor_ceiling_change_that_cannot_be_recorded_does_not_happen() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "ct-ceiling-fail@example.com").await;
    let actor = seed_actor(&pool, user, "http-node").await;
    let state = mcp_state(pool.clone()).await;
    let aid = actor.to_string();
    break_audit_table(&pool).await;

    for (tool, args) in [
        (
            "set_actor_llm_tier_ceiling",
            serde_json::json!({"actor_id": aid, "tier": "tier1"}),
        ),
        (
            "set_actor_egress_scope",
            serde_json::json!({"actor_id": aid, "scope": "public"}),
        ),
        (
            "set_actor_write_ceiling",
            serde_json::json!({"actor_id": aid, "ceiling": "write"}),
        ),
    ] {
        let resp = call(&state, user, tool, args).await;
        assert!(
            error_message(&resp).starts_with("Failed to update"),
            "{tool}: {}",
            error_message(&resp)
        );
    }
    assert_eq!(
        actor_column(&pool, actor, "max_llm_tier").await.as_deref(),
        Some("tier2")
    );
    assert_eq!(actor_column(&pool, actor, "egress_scope").await, None);
    assert_eq!(
        actor_column(&pool, actor, "max_write_ceiling")
            .await
            .as_deref(),
        Some("readonly")
    );
}

fn update_actor(user: Uuid, actor: Uuid, fields: &str) -> async_graphql::Request {
    async_graphql::Request::new(format!(
        r#"mutation {{ updateActor(id: "{actor}", {fields}) {{ id }} }}"#
    ))
    .data(user)
    .data(IsTwoFactorVerified(true))
}

#[tokio::test]
async fn a_dashboard_capability_ceiling_change_is_recorded() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    // First user on a fresh clone: the bootstrap grant is automation-node.
    let user = create_test_user(&ctx.auth_service, "ct-world@example.com").await;
    let actor = seed_actor(&pool, user, "minimal-node").await;

    // A name-only update is not a privilege change and records nothing.
    let renamed = ctx
        .schema
        .execute(update_actor(user, actor, r#"name: "ct-renamed""#))
        .await;
    assert!(renamed.errors.is_empty(), "{:?}", renamed.errors);
    assert_eq!(events_for(&pool, actor).await, 0);

    let raised = ctx
        .schema
        .execute(update_actor(
            user,
            actor,
            r#"maxCapabilityWorld: "http-node""#,
        ))
        .await;
    assert!(raised.errors.is_empty(), "{:?}", raised.errors);
    assert_eq!(
        events(&pool, "actor_capability_world_set", actor).await,
        vec![serde_json::json!({"previous_world": "minimal-node", "new_world": "http-node"})]
    );

    // With the audit table gone the raise fails and the ceiling is unchanged.
    break_audit_table(&pool).await;
    let refused = ctx
        .schema
        .execute(update_actor(
            user,
            actor,
            r#"maxCapabilityWorld: "network-node""#,
        ))
        .await;
    assert!(
        !refused.errors.is_empty(),
        "a raise without its record must fail"
    );
    assert_eq!(
        actor_column(&pool, actor, "max_capability_world")
            .await
            .as_deref(),
        Some("http-node")
    );
}

#[tokio::test]
async fn module_permission_changes_are_recorded_with_what_they_replaced() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "ct-perms@example.com").await;
    let stranger = create_test_user(&ctx.auth_service, "ct-perms-2@example.com").await;
    let module = seed_module(&pool, user, "http-node").await;
    let state = mcp_state(pool.clone()).await;
    let mid = module.to_string();

    let secrets = call(
        &state,
        user,
        "update_module_secrets",
        serde_json::json!({"module_id": mid, "allowed_secrets": ["team/new_key"]}),
    )
    .await;
    assert_eq!(
        text_json(&secrets)["previous_allowed_secrets"],
        serde_json::json!(["team/old_key"])
    );
    call(
        &state,
        user,
        "update_module_hosts",
        serde_json::json!({"module_id": mid, "allowed_hosts": ["api.example.com"]}),
    )
    .await;
    call(
        &state,
        user,
        "update_module_methods",
        serde_json::json!({"module_id": mid, "allowed_methods": ["GET", "POST"]}),
    )
    .await;

    assert_eq!(
        events(&pool, "module_allowed_secrets_updated", module).await,
        vec![
            serde_json::json!({"allowed_secrets": ["team/new_key"], "previous_allowed_secrets": ["team/old_key"]})
        ]
    );
    assert_eq!(
        events(&pool, "module_allowed_hosts_updated", module).await,
        vec![
            serde_json::json!({"allowed_hosts": ["api.example.com"], "previous_allowed_hosts": []})
        ]
    );
    assert_eq!(
        events(&pool, "module_allowed_methods_updated", module).await,
        vec![
            serde_json::json!({"allowed_methods": ["GET", "POST"], "previous_allowed_methods": []})
        ]
    );

    // Not the owner: denied, nothing changed, nothing recorded.
    let refused = call(
        &state,
        stranger,
        "update_module_hosts",
        serde_json::json!({"module_id": mid, "allowed_hosts": ["evil.example.com"]}),
    )
    .await;
    assert!(
        error_message(&refused).contains("not found"),
        "{}",
        error_message(&refused)
    );
    assert_eq!(events_for(&pool, module).await, 3);

    // Audit table gone: the replace fails and the grant list is unchanged.
    break_audit_table(&pool).await;
    let failed = call(
        &state,
        user,
        "update_module_secrets",
        serde_json::json!({"module_id": mid, "allowed_secrets": ["team/other"]}),
    )
    .await;
    assert_eq!(error_message(&failed), "Failed to update module secrets");
    let kept: Vec<String> = sqlx::query_scalar("SELECT allowed_secrets FROM modules WHERE id = $1")
        .bind(module)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(kept, vec!["team/new_key".to_string()]);
}

#[tokio::test]
async fn workflow_actor_binding_is_recorded_on_both_surfaces() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "ct-binding@example.com").await;
    let first = seed_actor(&pool, user, "http-node").await;
    let second = seed_actor(&pool, user, "http-node").await;
    let workflow = create_test_workflow(&pool, user, "ct-binding-workflow").await;
    let state = mcp_state(pool.clone()).await;

    let bound = call(
        &state,
        user,
        "set_workflow_actor_id",
        serde_json::json!({"workflow_id": workflow.to_string(), "actor_id": first.to_string()}),
    )
    .await;
    assert!(
        text_json(&bound)
            .as_str()
            .is_some_and(|t| t.contains("bound to actor")),
        "{bound:?}"
    );
    let rebound = ctx
        .schema
        .execute(
            async_graphql::Request::new(format!(
                r#"mutation {{ setWorkflowActorId(workflowId: "{workflow}", actorId: "{second}") }}"#
            ))
            .data(user)
            .data(IsTwoFactorVerified(true)),
        )
        .await;
    assert!(rebound.errors.is_empty(), "{:?}", rebound.errors);

    let recorded = events(&pool, "workflow_actor_binding_changed", workflow).await;
    assert_eq!(recorded.len(), 2);
    assert_eq!(recorded[0]["previous_actor_id"], serde_json::Value::Null);
    assert_eq!(recorded[0]["new_actor_id"], first.to_string());
    assert_eq!(recorded[0]["surface"], "mcp");
    assert_eq!(recorded[1]["previous_actor_id"], first.to_string());
    assert_eq!(recorded[1]["new_actor_id"], second.to_string());
    assert_eq!(recorded[1]["surface"], "graphql");

    break_audit_table(&pool).await;
    let failed = call(
        &state,
        user,
        "set_workflow_actor_id",
        serde_json::json!({"workflow_id": workflow.to_string(), "actor_id": null}),
    )
    .await;
    assert_eq!(
        error_message(&failed),
        "Failed to update workflow actor binding",
        "an unbind without its record must fail"
    );
    let kept: Option<Uuid> = sqlx::query_scalar("SELECT actor_id FROM workflows WHERE id = $1")
        .bind(workflow)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(kept, Some(second));
}

/// The MCP handlers check ownership before reaching the repository, so the
/// repositories' own owner predicate — the one on the row lock, which decides
/// whether anything is recorded — is only reachable by calling them directly.
#[tokio::test]
async fn the_recorded_writers_refuse_another_users_row_and_record_nothing() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let owner = create_test_user(&ctx.auth_service, "ct-owner@example.com").await;
    let stranger = create_test_user(&ctx.auth_service, "ct-stranger@example.com").await;
    let actor = seed_actor(&pool, owner, "http-node").await;
    let module = seed_module(&pool, owner, "http-node").await;
    let workflow = create_test_workflow(&pool, owner, "ct-owner-workflow").await;

    let actors = talos_actor_repository::ActorRepository::new(pool.clone());
    let tier = actors
        .set_actor_max_llm_tier(actor, stranger, talos_workflow_job_protocol::LlmTier::Tier1)
        .await
        .unwrap();
    assert!(tier.is_none());
    let modules = talos_module_repository::ModuleRepository::new(pool.clone());
    let hosts = modules
        .update_module_allowed_hosts(module, stranger, &["evil.example.com".to_string()])
        .await
        .unwrap();
    assert!(hosts.is_none());
    let workflows = talos_workflow_repository::WorkflowRepository::new(pool.clone());
    let binding = workflows
        .set_workflow_actor_id(
            workflow,
            stranger,
            Some(actor),
            talos_workflow_repository::ChangeSurface::Mcp,
        )
        .await
        .unwrap();
    assert!(binding.is_none());

    for id in [actor, module, workflow] {
        assert_eq!(
            events_for(&pool, id).await,
            0,
            "a refused change was recorded"
        );
    }
    assert_eq!(
        actor_column(&pool, actor, "max_llm_tier").await.as_deref(),
        Some("tier2")
    );
    // Control: the owner's own change is recorded.
    let own = actors
        .set_actor_max_llm_tier(actor, owner, talos_workflow_job_protocol::LlmTier::Tier1)
        .await
        .unwrap();
    assert_eq!(
        own,
        Some(talos_actor_repository::CeilingChange {
            previous: Some("tier2".into())
        })
    );
    assert_eq!(events_for(&pool, actor).await, 1);
}

async fn mirror(
    repo: &talos_module_repository::ModuleRepository,
    module: Uuid,
    user: Uuid,
    world_short: &str,
    audit: Option<talos_module_repository::CapabilityChangeAudit<'_>>,
) -> anyhow::Result<()> {
    repo.mirror_sandbox_compile_to_modules(
        module,
        module,
        Some(user),
        "ct-mirror",
        "sandbox",
        world_short,
        b"\0asm",
        "hash",
        "fn main() {}",
        1_000_000,
        &[],
        &[],
        &[],
        None,
        None,
        "rust",
        audit,
    )
    .await
}

fn describe(old: &str, new: &str) -> (String, serde_json::Value) {
    (
        format!("{old} -> {new}"),
        serde_json::json!({"old_capability_world": old, "new_capability_world": new}),
    )
}

#[tokio::test]
async fn a_module_world_change_is_recorded_by_its_write() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "ct-hot@example.com").await;
    let stranger = create_test_user(&ctx.auth_service, "ct-hot-2@example.com").await;
    let module = seed_module(&pool, user, "http-node").await;
    let repo = talos_module_repository::ModuleRepository::new(pool.clone());
    let audit = || talos_module_repository::CapabilityChangeAudit {
        recorded_by: user,
        event_type: "hot_update_capability_change",
        describe: &describe,
    };

    // Same world: a recompile, not a capability change — no record.
    mirror(&repo, module, user, "http", Some(audit()))
        .await
        .unwrap();
    assert_eq!(events_for(&pool, module).await, 0);

    mirror(&repo, module, user, "network", Some(audit()))
        .await
        .unwrap();
    assert_eq!(
        events(&pool, "hot_update_capability_change", module).await,
        vec![
            serde_json::json!({"old_capability_world": "http-node", "new_capability_world": "network-node"})
        ]
    );

    // A write refused as another user's row records nothing.
    let other = seed_module(&pool, stranger, "minimal-node").await;
    assert!(mirror(&repo, other, user, "network", Some(audit()))
        .await
        .is_err());
    assert_eq!(events_for(&pool, other).await, 0);

    // Audit table gone: the write rolls back and the world is unchanged.
    break_audit_table(&pool).await;
    assert!(mirror(&repo, module, user, "automation", Some(audit()))
        .await
        .is_err());
    let world: String = sqlx::query_scalar("SELECT capability_world FROM modules WHERE id = $1")
        .bind(module)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(world, "network-node");
}

/// TEXTUAL pin, stated as such: the handlers and services that used to write
/// these records themselves — detached, or awaited after the change had
/// committed — must not grow such a write back. The behavioural tests above
/// prove the repository writers record; this proves a caller has not added a
/// second, out-of-transaction copy (which the exactly-once reads would catch
/// only when the detached task happened to land before the read).
#[test]
fn no_caller_writes_a_privilege_record_outside_the_change() {
    let sources = [
        (
            "talos-mcp-handlers actor",
            include_str!("../../talos-mcp-handlers/src/actor.rs"),
        ),
        (
            "talos-mcp-handlers sandbox",
            include_str!("../../talos-mcp-handlers/src/sandbox.rs"),
        ),
        (
            "talos-mcp-handlers workflows",
            include_str!("../../talos-mcp-handlers/src/workflows.rs"),
        ),
        (
            "talos-api workflow mutations",
            include_str!("../../talos-api/src/schema/workflows/mutations.rs"),
        ),
        (
            "talos-api actor mutations",
            include_str!("../../talos-api/src/schema/actors/mutations.rs"),
        ),
        (
            "talos-hot-update-service",
            include_str!("../../talos-hot-update-service/src/lib.rs"),
        ),
        (
            "talos-inline-compile-service",
            include_str!("../../talos-inline-compile-service/src/lib.rs"),
        ),
    ];
    let events = [
        "\"actor_llm_tier_ceiling_set\"",
        "\"actor_egress_scope_set\"",
        "\"actor_write_ceiling_set\"",
        "\"actor_capability_world_set\"",
        "\"module_allowed_secrets_updated\"",
        "\"module_allowed_hosts_updated\"",
        "\"module_allowed_methods_updated\"",
        "\"workflow_actor_binding_changed\"",
        "\"hot_update_capability_change\"",
        "\"inline_compile_capability_change\"",
    ];
    for (name, src) in sources {
        for writer in ["spawn_log_admin_event(", "insert_admin_event_log("] {
            for (i, _) in src.match_indices(writer) {
                let call = &src[i..src.len().min(i + 400)];
                for e in events {
                    assert!(
                        !call.contains(e),
                        "{name}: {e} is written by `{writer}` outside its change again"
                    );
                }
            }
        }
    }
}

/// TEXTUAL pin, stated as such: `hot_update_module` and the inline compile
/// need a real compile to drive, so no DB test reaches their module write.
/// The repository half is proved above (`a_module_world_change_is_recorded_by_its_write`);
/// this pins that both services hand their write the audit, so a recompile to
/// a different world cannot land unrecorded by passing `None`.
#[test]
fn recompiling_services_hand_their_module_write_the_audit() {
    let hot = include_str!("../../talos-hot-update-service/src/lib.rs");
    assert_eq!(
        hot.matches("Some(world_change_audit)").count(),
        2,
        "both hot-update write paths (sandbox and compiled) must pass the audit"
    );
    assert!(hot.contains("event_type: \"hot_update_capability_change\""));
    let inline = include_str!("../../talos-inline-compile-service/src/lib.rs");
    assert!(inline.contains("Some(talos_module_repository::CapabilityChangeAudit {"));
    assert!(inline.contains("event_type: \"inline_compile_capability_change\""));
}
