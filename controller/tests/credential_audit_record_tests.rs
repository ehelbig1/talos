//! A change to a credential or privilege is recorded in the SAME transaction
//! as the change (2026-09-18).
//!
//! Before, every one of these records was a detached `tokio::spawn` written
//! after the change had committed — a failed or dropped task left a
//! permanent gap — and two populations were worse than that:
//! * API-key create / revoke / delete / rotate were recorded TWICE, once by
//!   `ApiKeyService` and once more by the GraphQL resolver;
//! * the GraphQL `grantCapabilityCeiling` / `revokeCapabilityCeiling` — the
//!   only cross-user grant route since the privileged tier — recorded
//!   NOTHING, and the first-user bootstrap grant recorded nothing either.
//!
//! These tests drive the production schema and services and read
//! `admin_event_log` back: each change writes exactly one record, and with
//! the audit table unavailable the change fails and nothing changed.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use controller::api::schema::{IsTwoFactorVerified, SecondFactorVerified};
use talos_api_keys::ApiKeyScope;
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

/// Take the audit table away on this test's own database clone.
async fn break_audit_table(pool: &sqlx::PgPool) {
    sqlx::query("ALTER TABLE admin_event_log RENAME TO admin_event_log_moved")
        .execute(pool)
        .await
        .unwrap();
}

/// A session that may perform privileged operations: 2FA enrolled on the
/// account and verified by the session.
async fn privileged(pool: &sqlx::PgPool, user: Uuid, query: &str) -> async_graphql::Request {
    sqlx::query("UPDATE users SET totp_enabled = true, is_platform_admin = true WHERE id = $1")
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
    async_graphql::Request::new(query.to_string())
        .data(user)
        .data(IsTwoFactorVerified(true))
        .data(SecondFactorVerified(true))
}

#[tokio::test]
async fn api_key_changes_are_recorded_exactly_once() {
    let ctx = common::setup_test_context().await;
    let user = common::create_test_user(&ctx.auth_service, "cred-apikey@example.com").await;

    // Create and revoke through the GraphQL resolvers — the surface that used
    // to add a second copy of each record.
    let created = ctx
        .schema
        .execute(
            privileged(
                &ctx.db_pool,
                user,
                r#"mutation { createApiKey(input: {name: "audit-key", scopes: ["workflows:read"]}) { id } }"#,
            )
            .await,
        )
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let key_id: Uuid = created.data.into_json().unwrap()["createApiKey"]["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        events(&ctx.db_pool, "api_key_created", key_id).await.len(),
        1
    );

    let revoked = ctx
        .schema
        .execute(
            privileged(
                &ctx.db_pool,
                user,
                &format!(r#"mutation {{ revokeApiKey(keyId: "{key_id}") }}"#),
            )
            .await,
        )
        .await;
    assert!(revoked.errors.is_empty(), "{:?}", revoked.errors);
    assert_eq!(
        events(&ctx.db_pool, "api_key_revoked", key_id).await.len(),
        1
    );

    // Rotate and delete through the service.
    let (_, second, _) = ctx
        .api_key_service
        .create_api_key(user, "rotating", vec![ApiKeyScope::WorkflowsRead], None)
        .await
        .unwrap();
    ctx.api_key_service.rotate_key(second, user).await.unwrap();
    let rotated = events(&ctx.db_pool, "api_key_rotated", second).await;
    assert_eq!(rotated.len(), 1);
    let new_id: Uuid = rotated[0]["new_key_id"].as_str().unwrap().parse().unwrap();
    ctx.api_key_service.delete_key(new_id, user).await.unwrap();
    assert_eq!(
        events(&ctx.db_pool, "api_key_deleted", new_id).await.len(),
        1
    );

    // Expiry: one record per expired key, written with the sweep.
    let (_, third, _) = ctx
        .api_key_service
        .create_api_key(user, "expiring", vec![ApiKeyScope::WorkflowsRead], None)
        .await
        .unwrap();
    sqlx::query("UPDATE api_keys SET expires_at = NOW() - interval '1 minute' WHERE id = $1")
        .bind(third)
        .execute(&ctx.db_pool)
        .await
        .unwrap();
    assert_eq!(ctx.api_key_service.cleanup_expired_keys().await.unwrap(), 1);
    assert_eq!(
        events(&ctx.db_pool, "api_key_expired", third).await.len(),
        1
    );
}

#[tokio::test]
async fn an_api_key_change_that_cannot_be_recorded_does_not_happen() {
    let ctx = common::setup_test_context().await;
    let user = common::create_test_user(&ctx.auth_service, "cred-apikey-atomic@example.com").await;
    let (_, key, _) = ctx
        .api_key_service
        .create_api_key(user, "kept", vec![ApiKeyScope::WorkflowsRead], None)
        .await
        .unwrap();
    break_audit_table(&ctx.db_pool).await;

    assert!(ctx
        .api_key_service
        .create_api_key(user, "never", vec![ApiKeyScope::WorkflowsRead], None)
        .await
        .is_err());
    assert!(ctx.api_key_service.revoke_key(key, user).await.is_err());
    assert!(ctx.api_key_service.rotate_key(key, user).await.is_err());
    assert!(ctx.api_key_service.delete_key(key, user).await.is_err());

    let rows: Vec<(String, bool)> =
        sqlx::query_as("SELECT name, is_active FROM api_keys WHERE user_id = $1")
            .bind(user)
            .fetch_all(&ctx.db_pool)
            .await
            .unwrap();
    assert_eq!(rows, vec![("kept".to_string(), true)], "no change survived");
}

#[tokio::test]
async fn capability_grants_are_recorded_on_every_surface() {
    let ctx = common::setup_test_context().await;
    // The first user is elevated by the bootstrap — and that is recorded,
    // with no user, as the platform's act.
    let admin = common::create_test_user(&ctx.auth_service, "cred-grant-admin@example.com").await;
    let boot = events(&ctx.db_pool, "capability_grant_issued", admin).await;
    assert_eq!(boot.len(), 1, "the bootstrap grant is recorded");
    assert_eq!(boot[0]["bootstrap"], true);
    let by: Option<Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM admin_event_log WHERE event_type = 'capability_grant_issued' \
         AND resource_id = $1",
    )
    .bind(admin)
    .fetch_one(&ctx.db_pool)
    .await
    .unwrap();
    assert_eq!(by, None);
    // Control: a second bootstrap call changes nothing and records nothing.
    assert!(
        !talos_auth::promote_first_user_if_needed(&ctx.db_pool, Some(admin))
            .await
            .unwrap()
    );
    assert_eq!(
        events(&ctx.db_pool, "capability_grant_issued", admin)
            .await
            .len(),
        1
    );

    let target = common::create_test_user(&ctx.auth_service, "cred-grant-target@example.com").await;
    for world in ["agent-node", "database-node"] {
        let resp = ctx
            .schema
            .execute(
                privileged(
                    &ctx.db_pool,
                    admin,
                    &format!(
                        r#"mutation {{ grantCapabilityCeiling(input: {{userId: "{target}", maxCapabilityWorld: "{world}", notes: "audit"}}) }}"#
                    ),
                )
                .await,
            )
            .await;
        assert!(resp.errors.is_empty(), "{:?}", resp.errors);
    }
    let issued = events(&ctx.db_pool, "capability_grant_issued", target).await;
    assert_eq!(issued.len(), 2, "each GraphQL grant is recorded once");
    assert_eq!(issued[0]["previous_world"], serde_json::Value::Null);
    assert_eq!(
        issued[1]["previous_world"], "agent-node",
        "an overwrite names what it replaced"
    );
    assert_eq!(issued[1]["max_capability_world"], "database-node");

    let resp = ctx
        .schema
        .execute(
            privileged(
                &ctx.db_pool,
                admin,
                &format!(r#"mutation {{ revokeCapabilityCeiling(userId: "{target}") }}"#),
            )
            .await,
        )
        .await;
    assert!(resp.errors.is_empty(), "{:?}", resp.errors);
    let revoked = events(&ctx.db_pool, "capability_grant_revoked", target).await;
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0]["withdrawn_world"], "database-node");

    // Nothing to revoke: no change, no record.
    let repo = talos_actor_repository::ActorRepository::new(ctx.db_pool.clone());
    assert_eq!(
        repo.delete_capability_grant(target, admin, None)
            .await
            .unwrap(),
        talos_actor_repository::CapabilityGrantRevocation::NoGrant
    );
    assert_eq!(
        events(&ctx.db_pool, "capability_grant_revoked", target)
            .await
            .len(),
        1
    );
}

#[tokio::test]
async fn a_grant_that_cannot_be_recorded_does_not_happen() {
    let ctx = common::setup_test_context().await;
    let admin = common::create_test_user(&ctx.auth_service, "cred-grant-atomic@example.com").await;
    let target =
        common::create_test_user(&ctx.auth_service, "cred-grant-atomic-t@example.com").await;
    let repo = talos_actor_repository::ActorRepository::new(ctx.db_pool.clone());
    repo.upsert_capability_grant(target, "agent-node", admin, None)
        .await
        .unwrap();
    break_audit_table(&ctx.db_pool).await;

    assert!(repo
        .upsert_capability_grant(target, "database-node", admin, None)
        .await
        .is_err());
    assert!(repo
        .delete_capability_grant(target, admin, None)
        .await
        .is_err());
    let world: Option<String> = sqlx::query_scalar(
        "SELECT max_capability_world FROM user_capability_grants WHERE user_id = $1",
    )
    .bind(target)
    .fetch_optional(&ctx.db_pool)
    .await
    .unwrap();
    assert_eq!(
        world.as_deref(),
        Some("agent-node"),
        "neither change survived"
    );
}

async fn enrol(ctx: &common::TestContext, user: Uuid) -> Result<Vec<String>, anyhow::Error> {
    let secret = ctx.totp_service.generate_secret();
    let code = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        totp_rs::Secret::Encoded(secret.clone()).to_bytes().unwrap(),
    )
    .unwrap()
    .generate_current()
    .unwrap();
    let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(&ctx.db_pool)
        .await
        .unwrap();
    ctx.totp_service
        .enable_2fa(user, &secret, &code, &email)
        .await
}

/// 2FA enrolment needs the user's personal org (the secret is sealed under
/// it) and an initialised DEK, as production signup provides.
async fn totp_ready(ctx: &common::TestContext, user: Uuid) {
    ctx.secrets_manager
        .initialize()
        .await
        .expect("initialize secrets");
    sqlx::query(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) VALUES ($1, $1, $2, true)",
    )
    .bind(format!("cred-2fa-{user}"))
    .bind(user)
    .execute(&ctx.db_pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn two_factor_changes_are_recorded_with_the_change() {
    let ctx = common::setup_test_context().await;
    let email = "cred-2fa@example.com";
    let user = common::create_test_user(&ctx.auth_service, email).await;
    totp_ready(&ctx, user).await;

    enrol(&ctx, user).await.expect("enable 2FA");
    assert_eq!(events(&ctx.db_pool, "2fa_enabled", user).await.len(), 1);

    common::login_test_user(&ctx.auth_service, email).await;
    ctx.totp_service
        .disable_2fa(user)
        .await
        .expect("disable 2FA");
    assert_eq!(events(&ctx.db_pool, "2fa_disabled", user).await.len(), 1);
    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM user_sessions WHERE user_id = $1")
        .bind(user)
        .fetch_one(&ctx.db_pool)
        .await
        .unwrap();
    assert_eq!(sessions, 0, "disabling 2FA signed every session out");
}

#[tokio::test]
async fn a_two_factor_change_that_cannot_be_recorded_does_not_happen() {
    let ctx = common::setup_test_context().await;
    let email = "cred-2fa-atomic@example.com";
    let user = common::create_test_user(&ctx.auth_service, email).await;
    totp_ready(&ctx, user).await;
    enrol(&ctx, user).await.expect("enable 2FA");
    common::login_test_user(&ctx.auth_service, email).await;
    break_audit_table(&ctx.db_pool).await;

    assert!(ctx.totp_service.disable_2fa(user).await.is_err());
    let (enabled, sessions): (bool, i64) = sqlx::query_as(
        "SELECT u.totp_enabled, (SELECT count(*) FROM user_sessions s WHERE s.user_id = u.id) \
         FROM users u WHERE u.id = $1",
    )
    .bind(user)
    .fetch_one(&ctx.db_pool)
    .await
    .unwrap();
    assert!(enabled, "2FA is still on");
    assert_eq!(sessions, 1, "the session revocation rolled back with it");

    // Enrolment likewise: a user without 2FA cannot be enrolled unrecorded.
    let other = common::create_test_user(&ctx.auth_service, "cred-2fa-atomic2@example.com").await;
    sqlx::query(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) VALUES ($1, $1, $2, true)",
    )
    .bind(format!("cred-2fa-{other}"))
    .bind(other)
    .execute(&ctx.db_pool)
    .await
    .unwrap();
    assert!(enrol(&ctx, other).await.is_err());
    let enabled: bool = sqlx::query_scalar("SELECT totp_enabled FROM users WHERE id = $1")
        .bind(other)
        .fetch_one(&ctx.db_pool)
        .await
        .unwrap();
    assert!(!enabled);
}

/// TEXTUAL, stated as such: the surfaces that used to write these records
/// from a detached task (or a second time) must not grow one back. The DB
/// tests above catch a missing or duplicated record on the paths they drive;
/// this catches a detached write reintroduced on a path they do not (the MCP
/// grant tools need the MCP harness and a platform-admin agent).
#[test]
fn no_credential_record_is_written_outside_its_transaction() {
    let sources = [
        (
            "talos-api security mutations",
            include_str!("../../talos-api/src/schema/security/mutations.rs"),
        ),
        (
            "talos-api auth mutations",
            include_str!("../../talos-api/src/schema/auth/mutations.rs"),
        ),
        (
            "talos-api platform mutations",
            include_str!("../../talos-api/src/schema/platform/mutations.rs"),
        ),
        (
            "talos-mcp-handlers actor",
            include_str!("../../talos-mcp-handlers/src/actor.rs"),
        ),
        (
            "talos-api-keys",
            include_str!("../../talos-api-keys/src/lib.rs"),
        ),
    ];
    let events = [
        "\"api_key_created\"",
        "\"api_key_revoked\"",
        "\"api_key_deleted\"",
        "\"api_key_rotated\"",
        "\"2fa_enabled\"",
        "\"2fa_disabled\"",
        "\"capability_grant_issued\"",
        "\"capability_grant_revoked\"",
    ];
    for (name, src) in sources {
        assert!(
            !src.contains("fn log_key_event"),
            "{name}: the detached API-key writer is back"
        );
        for (i, _) in src.match_indices("spawn_log_admin_event(") {
            let call = &src[i..src.len().min(i + 400)];
            for e in events {
                assert!(
                    !call.contains(e),
                    "{name}: {e} is written by a detached spawn_log_admin_event again"
                );
            }
        }
    }
}

/// The bootstrap's `granted == 0` guard fires only in a race: a concurrent
/// promotion grants the top ceiling after this call's fast-path check. The
/// race is made deterministic by holding that grant open on the row lock —
/// this call passes its fast path (the grant is uncommitted), waits on the
/// lock, then finds the ceiling already held, changes nothing, and must
/// record nothing.
#[tokio::test]
async fn a_bootstrap_that_loses_the_race_records_nothing() {
    let ctx = common::setup_test_context().await;
    let user = common::create_test_user(&ctx.auth_service, "cred-boot-race@example.com").await;
    // Start from a deployment that has not bootstrapped yet: nobody holds the
    // top ceiling and the one-shot bootstrap row (2026-09-25) is absent.
    for statement in [
        "DELETE FROM user_capability_grants",
        "DELETE FROM capability_bootstrap",
    ] {
        sqlx::query(statement).execute(&ctx.db_pool).await.unwrap();
    }
    let before = events(&ctx.db_pool, "capability_grant_issued", user)
        .await
        .len();

    let mut other = ctx.db_pool.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO user_capability_grants (user_id, max_capability_world, notes) \
         VALUES ($1, 'automation-node', 'the other promotion')",
    )
    .bind(user)
    .execute(&mut *other)
    .await
    .unwrap();

    let pool = ctx.db_pool.clone();
    let task =
        tokio::spawn(
            async move { talos_auth::promote_first_user_if_needed(&pool, Some(user)).await },
        );
    let mut waited = false;
    for _ in 0..300 {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE datname = current_database() AND wait_event_type = 'Lock'",
        )
        .fetch_one(&ctx.db_pool)
        .await
        .unwrap();
        if waiting > 0 {
            waited = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(waited, "the bootstrap never reached its upsert");
    other.commit().await.unwrap();

    assert!(
        !task.await.unwrap().unwrap(),
        "the race was lost, so nothing was granted"
    );
    assert_eq!(
        events(&ctx.db_pool, "capability_grant_issued", user)
            .await
            .len(),
        before,
        "a grant this call did not make is not recorded"
    );
}
