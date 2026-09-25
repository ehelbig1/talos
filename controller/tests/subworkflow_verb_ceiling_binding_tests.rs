//! The sub-workflow binding carries `actors.http_verb_ceiling` (2026-09-25).
//!
//! `WorkflowRepository::get_workflow_actor_binding` did not project the column
//! and `ControllerSubActorContextResolver::resolve_binding` answered `None` for
//! it unconditionally, so a child workflow bound to an actor whose operator had
//! said "no POST" (`http_verb_ceiling = readonly`) could never tighten a
//! parent's `Some(Write)` override — and the executor did not stamp the axis
//! either (the engine's own unit tests cover that half). These drive the REAL
//! resolver over a real row, then compose it with a parent through the one
//! narrowing rule the executor uses.
//!
//! CI: `scripts/test-integration.sh` **CTRL_TESTS** (`common` harness ⇒ needs
//! `DATABASE_URL`, sub-leg 64b).

mod common;

use std::sync::Arc;

use talos_workflow_engine_core::{
    ActorCeilings, LlmTier, SubworkflowActorContextResolver, WriteCeiling,
};
use uuid::Uuid;

async fn seed_user(pool: &sqlx::Pool<sqlx::Postgres>) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("svb-{user}@talos.test"))
    .execute(pool)
    .await
    .expect("seed user");
    user
}

/// Seed an actor with the given data ceiling and verb override, and a
/// workflow bound to it. The override is written in a transaction holding the
/// sanctioned grant GUC, because both columns carry an escalation guard.
async fn seed_bound_workflow(
    pool: &sqlx::Pool<sqlx::Postgres>,
    user: Uuid,
    write: &str,
    verb: Option<&str>,
) -> Uuid {
    let actor = Uuid::new_v4();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT set_config('talos.allow_ceiling_grant', 'on', true)")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO actors (id, user_id, name, max_llm_tier, max_write_ceiling, http_verb_ceiling) \
         VALUES ($1, $2, $3, 'tier2', $4, $5)",
    )
    .bind(actor)
    .bind(user)
    .bind(format!("svb-actor-{actor}"))
    .bind(write)
    .bind(verb)
    .execute(&mut *tx)
    .await
    .expect("seed actor");
    tx.commit().await.unwrap();

    let wf = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, module_uri, graph_json, actor_id) \
         VALUES ($1, $2, $3, 'test://none', '{}'::jsonb, $4)",
    )
    .bind(wf)
    .bind(user)
    .bind(format!("svb-wf-{wf}"))
    .bind(actor)
    .execute(pool)
    .await
    .expect("seed workflow");
    wf
}

fn resolver(
    pool: &sqlx::Pool<sqlx::Postgres>,
) -> talos_engine::sub_actor_context_resolver::ControllerSubActorContextResolver {
    talos_engine::sub_actor_context_resolver::ControllerSubActorContextResolver::from_repo(
        Arc::new(talos_workflow_repository::WorkflowRepository::new(
            pool.clone(),
        )),
    )
}

/// A parent granting POST through the verb override — the shape of the Plaid
/// reader actor, and the one whose grant must not leak into a stricter child.
const POST_GRANTING_PARENT: ActorCeilings = ActorCeilings {
    max_llm_tier: LlmTier::Tier2,
    max_write_ceiling: WriteCeiling::ReadOnly,
    http_verb_ceiling: Some(WriteCeiling::Write),
    egress_scope: None,
};

/// A child whose actor is `readonly` with NO override: its effective verb
/// ceiling is its own `readonly`, and the parent's grant must not reach it.
#[tokio::test]
async fn a_readonly_child_with_a_null_override_refuses_post_under_a_granting_parent() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let wf = seed_bound_workflow(&pool, user, "readonly", None).await;

    let binding = resolver(&pool)
        .resolve_binding(wf, user)
        .await
        .expect("a bound, owned workflow resolves");
    assert_eq!(binding.ceilings.max_write_ceiling, WriteCeiling::ReadOnly);
    assert_eq!(
        binding.ceilings.http_verb_ceiling, None,
        "NULL stays inherit"
    );

    let child = POST_GRANTING_PARENT.narrowed_for_child(binding.ceilings);
    assert_eq!(child.effective_http_verb(), WriteCeiling::ReadOnly);
}

/// A child whose actor may keep notes (`write`) but must not POST
/// (`http_verb_ceiling = readonly`). Pre-fix the resolver never read the
/// column, so this child ran with the parent's POST grant.
#[tokio::test]
async fn a_child_verb_override_is_read_from_the_row() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let wf = seed_bound_workflow(&pool, user, "write", Some("readonly")).await;

    let binding = resolver(&pool)
        .resolve_binding(wf, user)
        .await
        .expect("a bound, owned workflow resolves");
    assert_eq!(binding.ceilings.max_write_ceiling, WriteCeiling::Write);
    assert_eq!(
        binding.ceilings.http_verb_ceiling,
        Some(WriteCeiling::ReadOnly),
        "the resolver must project http_verb_ceiling"
    );

    let parent = ActorCeilings {
        max_write_ceiling: WriteCeiling::Write,
        ..POST_GRANTING_PARENT
    };
    let child = parent.narrowed_for_child(binding.ceilings);
    assert_eq!(child.effective_http_verb(), WriteCeiling::ReadOnly);
    assert_eq!(
        child.max_write_ceiling,
        WriteCeiling::Write,
        "notes still allowed"
    );
}

/// Control: a child that grants POST itself, under a parent that grants POST,
/// keeps POST — the fix narrows, it does not refuse everything.
#[tokio::test]
async fn a_child_that_grants_post_keeps_it_under_a_granting_parent() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let wf = seed_bound_workflow(&pool, user, "readonly", Some("write")).await;

    let binding = resolver(&pool)
        .resolve_binding(wf, user)
        .await
        .expect("a bound, owned workflow resolves");
    assert_eq!(
        binding.ceilings.http_verb_ceiling,
        Some(WriteCeiling::Write)
    );
    let child = POST_GRANTING_PARENT.narrowed_for_child(binding.ceilings);
    assert_eq!(child.effective_http_verb(), WriteCeiling::Write);
}
