//! A security bound is loosened only by a caller who proved a second factor
//! (security review 2026-10-14, G-4, G-5, A-8, G-18).
//!
//! * G-4: a platform admin's MCP token could withdraw another user's
//!   `minimal-node` grant, which WIDENS them to the `http-node` default — the
//!   expansion the cross-user GRANT is refused over MCP for.
//! * G-5: the owner's MCP token could move an actor from tier 1 to tier 2,
//!   open its egress, or lift its write ceiling.
//! * A-8: an API key of any scope could revoke its owner's own grant.
//! * G-18: a self-grant of the world one already holds rewrote the admin's
//!   attribution and justification.
//!
//! Drives the production GraphQL schema, the MCP dispatcher and
//! `ActorRepository`. `common` harness (a template clone per test), so
//! CTRL_TESTS (64b).

mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use controller::api::schema::{ApiKeyScopes, IsTwoFactorVerified, SecondFactorVerified};
use talos_actor_repository::ActorRepository;
use talos_capability_world::{ChangeAuthority, LOOSENING_NEEDS_SECOND_FACTOR};
use uuid::Uuid;

async fn make_admin(pool: &sqlx::PgPool, user: Uuid) {
    sqlx::query("UPDATE users SET is_platform_admin = true WHERE id = $1")
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
}

/// A browser session; `second_factor` = verified this session and enrolled.
async fn session(
    pool: &sqlx::PgPool,
    user: Uuid,
    second_factor: bool,
    query: &str,
) -> async_graphql::Request {
    sqlx::query("UPDATE users SET totp_enabled = $2 WHERE id = $1")
        .bind(user)
        .bind(second_factor)
        .execute(pool)
        .await
        .unwrap();
    async_graphql::Request::new(query.to_string())
        .data(user)
        .data(IsTwoFactorVerified(true))
        .data(SecondFactorVerified(second_factor))
}

async fn mcp(
    pool: &sqlx::PgPool,
    user: Uuid,
    tool: &str,
    args: serde_json::Value,
) -> controller::mcp::types::JsonRpcResponse {
    let state = mcp_common::mcp_state(pool.clone()).await;
    controller::mcp::actor::dispatch(
        tool,
        Some(serde_json::json!(1)),
        &args,
        &state,
        mcp_common::agent(user),
    )
    .await
    .expect("dispatched")
}

async fn grant_row(pool: &sqlx::PgPool, user: Uuid) -> Option<(String, Uuid, Option<String>)> {
    sqlx::query_as(
        "SELECT max_capability_world, granted_by, notes FROM user_capability_grants \
         WHERE user_id = $1",
    )
    .bind(user)
    .fetch_optional(pool)
    .await
    .unwrap()
}

async fn seed_actor(pool: &sqlx::PgPool, user: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO actors (id, user_id, name, max_capability_world, status) \
         VALUES ($1, $2, $3, 'http-node', 'active')",
    )
    .bind(id)
    .bind(user)
    .bind(format!("loosening-{}", &id.to_string()[..8]))
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn actor_column(pool: &sqlx::PgPool, actor: Uuid, column: &str) -> Option<String> {
    let sql = match column {
        "max_llm_tier" => "SELECT max_llm_tier FROM actors WHERE id = $1",
        "egress_scope" => "SELECT egress_scope FROM actors WHERE id = $1",
        "max_write_ceiling" => "SELECT max_write_ceiling FROM actors WHERE id = $1",
        "http_verb_ceiling" => "SELECT http_verb_ceiling FROM actors WHERE id = $1",
        _ => unreachable!(),
    };
    sqlx::query_scalar(sql)
        .bind(actor)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// G-4: an admin's bearer token does not widen another user's ceiling by
/// revoking their narrow grant; a session with a second factor does; narrowing
/// stays open to the token.
#[tokio::test]
async fn another_users_ceiling_is_widened_only_with_a_second_factor() {
    let ctx = common::setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let repo = ActorRepository::new(pool.clone());
    let admin = common::create_test_user(&ctx.auth_service, "loosen-admin@example.com").await;
    make_admin(&pool, admin).await;
    let victim = common::create_test_user(&ctx.auth_service, "loosen-victim@example.com").await;

    for world in ["minimal-node", "governance-node"] {
        repo.upsert_capability_grant(victim, world, admin, Some("restricted"))
            .await
            .unwrap();

        let resp = mcp(
            &pool,
            admin,
            "revoke_capability_ceiling",
            serde_json::json!({ "user_id": victim.to_string() }),
        )
        .await;
        assert!(
            mcp_common::error_message(&resp).contains(LOOSENING_NEEDS_SECOND_FACTOR),
            "{resp:?}"
        );
        assert_eq!(grant_row(&pool, victim).await.unwrap().0, world);

        // A session without a second factor is refused too.
        let q = format!(r#"mutation {{ revokeCapabilityCeiling(userId: "{victim}") }}"#);
        let resp = ctx
            .schema
            .execute(session(&pool, admin, false, &q).await)
            .await;
        assert!(
            !resp.errors.is_empty(),
            "a widening revoke needs a second factor"
        );
        assert_eq!(grant_row(&pool, victim).await.unwrap().0, world);

        // With one, it is made.
        let resp = ctx
            .schema
            .execute(session(&pool, admin, true, &q).await)
            .await;
        assert!(resp.errors.is_empty(), "{:?}", resp.errors);
        assert!(grant_row(&pool, victim).await.is_none());
    }

    // Control: withdrawing a grant above the default narrows, and the token
    // may do it.
    repo.upsert_capability_grant(victim, "agent-node", admin, None)
        .await
        .unwrap();
    let resp = mcp(
        &pool,
        admin,
        "revoke_capability_ceiling",
        serde_json::json!({ "user_id": victim.to_string() }),
    )
    .await;
    assert_eq!(mcp_common::text_json(&resp)["revoked"], true, "{resp:?}");
    assert!(grant_row(&pool, victim).await.is_none());
    // And a narrowing GraphQL revoke needs no second factor.
    repo.upsert_capability_grant(victim, "agent-node", admin, None)
        .await
        .unwrap();
    let q = format!(r#"mutation {{ revokeCapabilityCeiling(userId: "{victim}") }}"#);
    let resp = ctx
        .schema
        .execute(session(&pool, admin, false, &q).await)
        .await;
    assert!(resp.errors.is_empty(), "{:?}", resp.errors);
    assert!(grant_row(&pool, victim).await.is_none());
}

/// A-8: an API key without the Admin scope cannot revoke even its owner's
/// own grant.
#[tokio::test]
async fn a_key_without_admin_scope_does_not_revoke_its_owners_grant() {
    let ctx = common::setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let repo = ActorRepository::new(pool.clone());
    let admin = common::create_test_user(&ctx.auth_service, "scope-admin@example.com").await;
    let user = common::create_test_user(&ctx.auth_service, "scope-user@example.com").await;
    repo.upsert_capability_grant(user, "agent-node", admin, None)
        .await
        .unwrap();
    let req = async_graphql::Request::new(format!(
        r#"mutation {{ revokeCapabilityCeiling(userId: "{user}") }}"#
    ))
    .data(user)
    .data(ApiKeyScopes(vec![
        talos_api_keys::ApiKeyScope::WorkflowsRead,
    ]))
    .data(IsTwoFactorVerified(true));
    let resp = ctx.schema.execute(req).await;
    assert!(!resp.errors.is_empty(), "a workflows:read key is refused");
    assert_eq!(grant_row(&pool, user).await.unwrap().0, "agent-node");
}

/// G-5: over MCP each per-actor ceiling may be tightened and not loosened;
/// `setActorCeiling` with a second factor loosens it, without one it is
/// refused.
#[tokio::test]
async fn an_actor_ceiling_is_loosened_only_with_a_second_factor() {
    let ctx = common::setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let owner = common::create_test_user(&ctx.auth_service, "ceiling-owner@example.com").await;
    let actor = seed_actor(&pool, owner).await;
    let repo = ActorRepository::new(pool.clone());

    // Start from the tight end of every axis (tier2 → tier1 is a tightening).
    let set = |tool: &'static str, key: &'static str, value: serde_json::Value| {
        let pool = pool.clone();
        async move {
            mcp(
                &pool,
                owner,
                tool,
                serde_json::json!({ "actor_id": actor.to_string(), key: value }),
            )
            .await
        }
    };
    let ok = |resp: &controller::mcp::types::JsonRpcResponse| {
        assert!(resp.error.is_none(), "{resp:?}");
        assert_ne!(
            resp.result.as_ref().and_then(|r| r.get("isError")),
            Some(&serde_json::Value::Bool(true)),
            "{resp:?}"
        );
    };
    let refused = |resp: &controller::mcp::types::JsonRpcResponse| {
        assert_eq!(
            mcp_common::error_message(resp),
            LOOSENING_NEEDS_SECOND_FACTOR
        );
    };

    ok(&set("set_actor_llm_tier_ceiling", "tier", "tier1".into()).await);
    ok(&set("set_actor_egress_scope", "scope", "local".into()).await);
    ok(&set("set_actor_http_verb_ceiling", "ceiling", "readonly".into()).await);
    // `max_write_ceiling` defaults to readonly.
    assert_eq!(
        actor_column(&pool, actor, "max_write_ceiling")
            .await
            .as_deref(),
        Some("readonly")
    );

    refused(&set("set_actor_llm_tier_ceiling", "tier", "tier2".into()).await);
    refused(&set("set_actor_egress_scope", "scope", "public".into()).await);
    refused(&set("set_actor_egress_scope", "scope", serde_json::Value::Null).await);
    refused(&set("set_actor_write_ceiling", "ceiling", "write".into()).await);
    refused(&set("set_actor_http_verb_ceiling", "ceiling", "write".into()).await);
    refused(
        &set(
            "set_actor_http_verb_ceiling",
            "ceiling",
            serde_json::Value::Null,
        )
        .await,
    );
    assert_eq!(
        actor_column(&pool, actor, "max_llm_tier").await.as_deref(),
        Some("tier1")
    );
    assert_eq!(
        actor_column(&pool, actor, "egress_scope").await.as_deref(),
        Some("local")
    );
    assert_eq!(
        actor_column(&pool, actor, "max_write_ceiling")
            .await
            .as_deref(),
        Some("readonly")
    );
    assert_eq!(
        actor_column(&pool, actor, "http_verb_ceiling")
            .await
            .as_deref(),
        Some("readonly")
    );

    // GraphQL without a second factor: refused.
    let loosen = |kind: &str, value: &str| {
        format!(
            r#"mutation {{ setActorCeiling(actorId: "{actor}", ceiling: {kind}, value: {value}) }}"#
        )
    };
    let resp = ctx
        .schema
        .execute(session(&pool, owner, false, &loosen("LLM_TIER", r#""tier2""#)).await)
        .await;
    assert!(!resp.errors.is_empty(), "no second factor, no loosening");
    assert_eq!(
        actor_column(&pool, actor, "max_llm_tier").await.as_deref(),
        Some("tier1")
    );

    // With one: every axis loosens.
    for (kind, value, column, want) in [
        ("LLM_TIER", r#""tier2""#, "max_llm_tier", Some("tier2")),
        (
            "EGRESS_SCOPE",
            r#""public""#,
            "egress_scope",
            Some("public"),
        ),
        (
            "WRITE_CEILING",
            r#""write""#,
            "max_write_ceiling",
            Some("write"),
        ),
        ("HTTP_VERB_CEILING", "null", "http_verb_ceiling", None),
    ] {
        let resp = ctx
            .schema
            .execute(session(&pool, owner, true, &loosen(kind, value)).await)
            .await;
        assert!(resp.errors.is_empty(), "{kind}: {:?}", resp.errors);
        assert_eq!(
            actor_column(&pool, actor, column).await.as_deref(),
            want,
            "{kind}"
        );
    }

    // A stranger's second factor does not reach the owner's actor.
    let stranger =
        common::create_test_user(&ctx.auth_service, "ceiling-stranger@example.com").await;
    let resp = ctx
        .schema
        .execute(session(&pool, stranger, true, &loosen("LLM_TIER", r#""tier1""#)).await)
        .await;
    assert!(!resp.errors.is_empty());
    assert_eq!(
        actor_column(&pool, actor, "max_llm_tier").await.as_deref(),
        Some("tier2")
    );

    // Tightening back over MCP is still self-service.
    ok(&set("set_actor_llm_tier_ceiling", "tier", "tier1".into()).await);
    assert_eq!(
        repo.set_actor_max_llm_tier(
            actor,
            owner,
            talos_workflow_job_protocol::LlmTier::Tier2,
            ChangeAuthority::BearerCredential,
        )
        .await
        .unwrap(),
        talos_actor_repository::CeilingWrite::LooseningRefused {
            previous: Some("tier1".into())
        }
    );
}

/// G-18: a self-grant of the world already held changes nothing — the
/// admin's attribution and notes stay.
#[tokio::test]
async fn an_equal_self_grant_keeps_the_admins_attribution() {
    let ctx = common::setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let repo = ActorRepository::new(pool.clone());
    let admin = common::create_test_user(&ctx.auth_service, "attr-admin@example.com").await;
    let user = common::create_test_user(&ctx.auth_service, "attr-user@example.com").await;
    repo.upsert_capability_grant(user, "agent-node", admin, Some("approved for the pilot"))
        .await
        .unwrap();
    let resp = mcp(
        &pool,
        user,
        "grant_capability_ceiling",
        serde_json::json!({
            "user_id": user.to_string(),
            "max_capability_world": "agent-node",
            "notes": "self",
        }),
    )
    .await;
    assert!(resp.error.is_none(), "{resp:?}");
    assert_eq!(
        grant_row(&pool, user).await,
        Some((
            "agent-node".to_string(),
            admin,
            Some("approved for the pilot".to_string())
        ))
    );
    let issued: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM admin_event_log WHERE event_type = 'capability_grant_issued' \
         AND resource_id = $1",
    )
    .bind(user)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(issued, 1, "the no-op self-grant records nothing");

    // Control: a narrowing self-grant is made, and attributed to the user.
    repo.upsert_capability_grant(user, "http-node", user, None)
        .await
        .unwrap();
    assert_eq!(grant_row(&pool, user).await.unwrap().1, user);
}
