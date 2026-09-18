//! A signed-in user can change their own password (2026-09-18).
//!
//! Until then `AuthService::change_password` had no caller outside a test:
//! no GraphQL mutation, MCP tool or settings form reached it, so a leaked
//! password could only be rotated with SQL, and SOC 2 CC7.1-07 listed an
//! audited "password change" event nothing could produce. The function's own
//! write was also two statements with the session revocation "non-fatal" —
//! a failed DELETE left every old refresh token alive for up to 7 days after
//! a rotation whose whole purpose is to cut them off.
//!
//! These tests drive the PRODUCTION schema and `AuthService`: the session
//! gate for every credential shape; that a change signs out every session,
//! writes its audit row and re-issues the caller's own session; that wrong
//! current passwords share login's lockout counter while a policy failure or
//! an unchanged password costs no guess; that the write is atomic with its
//! audit row; that a concurrent change is a conflict, not a lost write; that
//! the auth limiter applies; and that the outcome counter moves.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use controller::api::schema::{
    ApiKeyScopes, IsTwoFactorVerified, RequestMetadata, SecondFactorRefusal, SecondFactorVerified,
};
use controller::auth::PasswordChangeError;
use uuid::Uuid;

/// `common::create_test_user`'s password.
const CURRENT: &str = "password123456!";
const NEW: &str = "Rotated-Passphrase-2026";

/// The outcome counter is process-global; tests in this binary run in
/// parallel and every one of them changes (or fails to change) a password.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn change(current: &str, new: &str) -> String {
    format!(
        r#"mutation {{ changePassword(input: {{currentPassword: "{current}", newPassword: "{new}"}}) }}"#
    )
}

/// A browser session: `pending` = still waiting for its 2FA code;
/// `second_factor` = what the session proved.
fn session(
    query: String,
    user: Uuid,
    pending: bool,
    second_factor: bool,
    cookies: tower_cookies::Cookies,
) -> async_graphql::Request {
    async_graphql::Request::new(query)
        .data(user)
        .data(IsTwoFactorVerified(!pending))
        .data(SecondFactorVerified(second_factor))
        .data(cookies)
}

async fn set_enrolled(pool: &sqlx::PgPool, user: Uuid) {
    sqlx::query("UPDATE users SET totp_enabled = true WHERE id = $1")
        .bind(user)
        .execute(pool)
        .await
        .expect("set totp_enabled");
}

async fn session_count(pool: &sqlx::PgPool, user: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM user_sessions WHERE user_id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn attempts(pool: &sqlx::PgPool, user: Uuid) -> i32 {
    sqlx::query_scalar("SELECT failed_login_attempts FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn change_audit_rows(pool: &sqlx::PgPool, user: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM auth_audit_log \
         WHERE user_id = $1 AND event_type = 'password_change' AND success",
    )
    .bind(user)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn message(schema: &common::TalosSchema, req: async_graphql::Request) -> String {
    let resp = schema.execute(req).await;
    assert!(!resp.errors.is_empty(), "expected a refusal");
    resp.errors[0].message.clone()
}

#[tokio::test]
async fn a_change_signs_out_every_session_and_reissues_the_callers() {
    let _serial = SERIAL.lock().await;
    let ctx = common::setup_test_context().await;
    let email = "pwchange-happy@example.com";
    let user = common::create_test_user(&ctx.auth_service, email).await;
    // Two sessions on other devices — or held by whoever stole the password.
    let (_, other_a) = common::login_test_user(&ctx.auth_service, email).await;
    let (_, other_b) = common::login_test_user(&ctx.auth_service, email).await;

    let cookies = tower_cookies::Cookies::default();
    let resp = ctx
        .schema
        .execute(session(
            change(CURRENT, NEW),
            user,
            false,
            false,
            cookies.clone(),
        ))
        .await;
    assert!(resp.errors.is_empty(), "{:?}", resp.errors);

    for token in [&other_a, &other_b] {
        assert!(
            ctx.auth_service.refresh_access_token(token).await.is_err(),
            "every earlier session must be signed out"
        );
    }
    // Exactly one session: the caller's, re-issued with the standing it had.
    let rows: Vec<(bool, bool)> = sqlx::query_as(
        "SELECT is_2fa_verified, second_factor_verified FROM user_sessions WHERE user_id = $1",
    )
    .bind(user)
    .fetch_all(&ctx.db_pool)
    .await
    .unwrap();
    assert_eq!(rows, vec![(true, false)]);
    let access = cookies
        .list()
        .into_iter()
        .find(|c| c.value().split('.').count() == 3)
        .expect("an access-token cookie was set")
        .value()
        .to_string();
    let claims = ctx.auth_service.verify_token(&access).unwrap();
    assert_eq!(claims.sub, user.to_string());
    assert!(!claims.second_factor_verified);

    assert_eq!(change_audit_rows(&ctx.db_pool, user).await, 1);
    assert!(ctx
        .auth_service
        .login(email, CURRENT, None, None)
        .await
        .is_err());
    assert!(ctx.auth_service.login(email, NEW, None, None).await.is_ok());
}

/// A verified session stays verified after the change: it proved the current
/// password and its second factor still holds.
#[tokio::test]
async fn a_verified_session_is_reissued_as_verified() {
    let _serial = SERIAL.lock().await;
    let ctx = common::setup_test_context().await;
    let user = common::create_test_user(&ctx.auth_service, "pwchange-verified@example.com").await;
    set_enrolled(&ctx.db_pool, user).await;
    let resp = ctx
        .schema
        .execute(session(
            change(CURRENT, NEW),
            user,
            false,
            true,
            tower_cookies::Cookies::default(),
        ))
        .await;
    assert!(resp.errors.is_empty(), "{:?}", resp.errors);
    let rows: Vec<(bool, bool)> = sqlx::query_as(
        "SELECT is_2fa_verified, second_factor_verified FROM user_sessions WHERE user_id = $1",
    )
    .bind(user)
    .fetch_all(&ctx.db_pool)
    .await
    .unwrap();
    assert_eq!(rows, vec![(true, true)]);
}

#[tokio::test]
async fn the_session_gate_refuses_what_must_not_change_a_password() {
    let _serial = SERIAL.lock().await;
    let ctx = common::setup_test_context().await;
    let user = common::create_test_user(&ctx.auth_service, "pwchange-gate@example.com").await;
    let no_cookies = tower_cookies::Cookies::default;

    // An API key — even with the Admin scope — cannot take over the
    // account's sign-in credential.
    let api_key = async_graphql::Request::new(change(CURRENT, NEW))
        .data(user)
        .data(ApiKeyScopes(vec![talos_api_keys::ApiKeyScope::Admin]))
        .data(IsTwoFactorVerified(true));
    assert_eq!(
        message(&ctx.schema, api_key).await,
        SecondFactorRefusal::ApiKey.message()
    );
    // A session still waiting for its 2FA code.
    assert_eq!(
        message(
            &ctx.schema,
            session(change(CURRENT, NEW), user, true, false, no_cookies())
        )
        .await,
        SecondFactorRefusal::Pending.message()
    );
    // With 2FA enrolled, a session that did not verify it.
    set_enrolled(&ctx.db_pool, user).await;
    assert_eq!(
        message(
            &ctx.schema,
            session(change(CURRENT, NEW), user, false, false, no_cookies())
        )
        .await,
        SecondFactorRefusal::NotVerified.message()
    );
    // Unauthenticated.
    let anon = async_graphql::Request::new(change(CURRENT, NEW));
    assert!(message(&ctx.schema, anon)
        .await
        .contains("Authentication required"));

    // None of that touched the password, the sessions or the lockout counter.
    assert_eq!(attempts(&ctx.db_pool, user).await, 0);
    assert_eq!(change_audit_rows(&ctx.db_pool, user).await, 0);

    // Control: the verified session passes the gate. A wrong current password
    // is then refused by the SERVICE, with its own sentence.
    assert_eq!(
        message(
            &ctx.schema,
            session(
                change("Wrong-Current-2026", NEW),
                user,
                false,
                true,
                no_cookies()
            )
        )
        .await,
        PasswordChangeError::WrongCurrentPassword.message()
    );
}

#[tokio::test]
async fn wrong_current_passwords_share_the_login_lockout() {
    let _serial = SERIAL.lock().await;
    let ctx = common::setup_test_context().await;
    let email = "pwchange-lockout@example.com";
    let user = common::create_test_user(&ctx.auth_service, email).await;
    common::login_test_user(&ctx.auth_service, email).await;
    let sessions_before = session_count(&ctx.db_pool, user).await;
    let svc = &ctx.auth_service;

    for n in 1..=4 {
        let r = svc
            .change_password(user, "Wrong-Current-2026", NEW, None, None)
            .await;
        assert!(
            matches!(r, Err(PasswordChangeError::WrongCurrentPassword)),
            "{r:?}"
        );
        assert_eq!(attempts(&ctx.db_pool, user).await, n);
    }
    let fifth = svc
        .change_password(user, "Wrong-Current-2026", NEW, None, None)
        .await;
    assert!(
        matches!(fifth, Err(PasswordChangeError::Locked)),
        "{fifth:?}"
    );

    // The same counter locks LOGIN, and a locked account cannot change its
    // password even with the right one.
    assert!(svc.login(email, CURRENT, None, None).await.is_err());
    let right = svc.change_password(user, CURRENT, NEW, None, None).await;
    assert!(
        matches!(right, Err(PasswordChangeError::Locked)),
        "{right:?}"
    );

    assert_eq!(session_count(&ctx.db_pool, user).await, sessions_before);
    assert_eq!(change_audit_rows(&ctx.db_pool, user).await, 0);
    let failed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_audit_log \
         WHERE user_id = $1 AND event_type = 'password_change_failed'",
    )
    .bind(user)
    .fetch_one(&ctx.db_pool)
    .await
    .unwrap();
    assert_eq!(failed, 6, "every refusal is recorded");
}

/// A policy failure or an unchanged password is refused before any guess is
/// counted; a successful change resets the counter.
#[tokio::test]
async fn policy_and_unchanged_cost_no_guess() {
    let _serial = SERIAL.lock().await;
    let ctx = common::setup_test_context().await;
    let user = common::create_test_user(&ctx.auth_service, "pwchange-policy@example.com").await;
    let svc = &ctx.auth_service;

    let weak = svc
        .change_password(user, CURRENT, "short", None, None)
        .await;
    assert!(
        matches!(weak, Err(PasswordChangeError::PolicyRejected(_))),
        "{weak:?}"
    );
    // The legacy OAuth sentinel is a reserved password (package CQ).
    let reserved = svc
        .change_password(
            user,
            CURRENT,
            talos_unusable_password::LEGACY_OAUTH_NO_PASSWORD_SENTINEL,
            None,
            None,
        )
        .await;
    assert!(
        matches!(reserved, Err(PasswordChangeError::PolicyRejected(_))),
        "{reserved:?}"
    );
    // The new password is checked FIRST: with a wrong current password too,
    // a policy failure still costs no guess.
    let weak_and_wrong = svc
        .change_password(user, "Wrong-Current-2026", "short", None, None)
        .await;
    assert!(
        matches!(weak_and_wrong, Err(PasswordChangeError::PolicyRejected(_))),
        "{weak_and_wrong:?}"
    );
    let same = svc
        .change_password(user, CURRENT, CURRENT, None, None)
        .await;
    assert!(
        matches!(same, Err(PasswordChangeError::Unchanged)),
        "{same:?}"
    );
    assert_eq!(attempts(&ctx.db_pool, user).await, 0);

    // One wrong guess, then a successful change: the counter is reset.
    let _ = svc
        .change_password(user, "Wrong-Current-2026", NEW, None, None)
        .await;
    assert_eq!(attempts(&ctx.db_pool, user).await, 1);
    svc.change_password(user, CURRENT, NEW, None, None)
        .await
        .expect("change");
    assert_eq!(attempts(&ctx.db_pool, user).await, 0);
}

/// The password, the session revocation and the audit row are ONE write. With
/// the audit table unavailable the change fails and nothing moves.
#[tokio::test]
async fn the_change_is_atomic_with_its_audit_row() {
    let _serial = SERIAL.lock().await;
    let ctx = common::setup_test_context().await;
    let email = "pwchange-atomic@example.com";
    let user = common::create_test_user(&ctx.auth_service, email).await;
    let (_, earlier) = common::login_test_user(&ctx.auth_service, email).await;
    sqlx::query("ALTER TABLE auth_audit_log RENAME TO auth_audit_log_moved")
        .execute(&ctx.db_pool)
        .await
        .unwrap();

    let r = ctx
        .auth_service
        .change_password(user, CURRENT, NEW, None, None)
        .await;
    assert!(matches!(r, Err(PasswordChangeError::Internal(_))), "{r:?}");
    assert!(
        ctx.auth_service
            .refresh_access_token(&earlier)
            .await
            .is_ok(),
        "the session revocation rolled back with the password"
    );
    assert!(ctx
        .auth_service
        .login(email, CURRENT, None, None)
        .await
        .is_ok());
}

/// Another request changes the password after this one verified it: the
/// write finds the stored hash moved and changes nothing, rather than
/// overwriting a change it never saw.
#[tokio::test]
async fn a_concurrent_change_is_a_conflict_not_a_lost_write() {
    let _serial = SERIAL.lock().await;
    let ctx = common::setup_test_context().await;
    let email = "pwchange-race@example.com";
    let user = common::create_test_user(&ctx.auth_service, email).await;
    common::login_test_user(&ctx.auth_service, email).await;

    // The "other request": a password write held open on the row.
    let other_hash = bcrypt::hash("Other-Request-2026", 4).unwrap();
    let mut other = ctx.db_pool.begin().await.unwrap();
    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(&other_hash)
        .bind(user)
        .execute(&mut *other)
        .await
        .unwrap();

    // This request verifies against the committed (old) hash, then its
    // UPDATE waits on the row lock.
    let svc = ctx.auth_service.clone();
    let task =
        tokio::spawn(async move { svc.change_password(user, CURRENT, NEW, None, None).await });
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
    assert!(waited, "the change never reached its UPDATE");
    other.commit().await.unwrap();

    let r = task.await.unwrap();
    assert!(matches!(r, Err(PasswordChangeError::Conflict)), "{r:?}");
    let stored: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(&ctx.db_pool)
        .await
        .unwrap();
    assert_eq!(stored, other_hash, "the other request's write stands");
    assert_eq!(session_count(&ctx.db_pool, user).await, 1);
    assert_eq!(change_audit_rows(&ctx.db_pool, user).await, 0);
}

/// The auth limiter login uses applies: a caller cycling through stolen
/// sessions is throttled per IP before the account lockout is reached.
#[tokio::test]
async fn the_auth_limiter_applies() {
    let _serial = SERIAL.lock().await;
    let ctx = common::setup_test_context().await;
    let user = common::create_test_user(&ctx.auth_service, "pwchange-limit@example.com").await;
    let limiter = std::sync::Arc::new(talos_rate_limit::DistributedRateLimiter::auto(
        None,
        talos_rate_limit::RateLimitConfig::auth(),
        "auth-test",
    ));
    let schema = async_graphql::Schema::build(
        controller::api::schema::QueryRoot::default(),
        controller::api::schema::MutationRoot::default(),
        controller::api::schema::SubscriptionRoot,
    )
    .data(ctx.db_pool.clone())
    .data(ctx.auth_service.clone())
    .data(limiter)
    .finish();
    let from_one_ip = || {
        session(
            change("Wrong-Current-2026", NEW),
            user,
            false,
            false,
            tower_cookies::Cookies::default(),
        )
        .data(RequestMetadata {
            ip_address: Some("203.0.113.9".to_string()),
            user_agent: None,
        })
    };
    // The limiter's burst is 2.
    for _ in 0..2 {
        assert_eq!(
            message(&schema, from_one_ip()).await,
            PasswordChangeError::WrongCurrentPassword.message()
        );
    }
    assert_eq!(
        message(&schema, from_one_ip()).await,
        "Too many attempts. Please try again later."
    );
    assert_eq!(
        attempts(&ctx.db_pool, user).await,
        2,
        "the throttled request never reached the password check"
    );
}

/// Every outcome reaches the seeded counter through the production wrapper.
/// Deltas, not absolutes: the registry is process-global.
#[tokio::test]
async fn outcomes_move_the_seeded_counter() {
    use talos_metrics::PasswordChangeOutcome as O;
    let _serial = SERIAL.lock().await;
    talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
    let m = talos_metrics::global().expect("global metrics installed");
    let get = |o: O| {
        m.password_changes_total
            .with_label_values(&[o.as_str()])
            .get()
    };
    let before: Vec<f64> = O::ALL.iter().map(|o| get(*o)).collect();

    let ctx = common::setup_test_context().await;
    let user = common::create_test_user(&ctx.auth_service, "pwchange-metric@example.com").await;
    let svc = &ctx.auth_service;
    let _ = svc
        .change_password(user, CURRENT, "short", None, None)
        .await;
    let _ = svc
        .change_password(user, CURRENT, CURRENT, None, None)
        .await;
    let _ = svc
        .change_password(user, "Wrong-Current-2026", NEW, None, None)
        .await;
    svc.change_password(user, CURRENT, NEW, None, None)
        .await
        .expect("change");

    let moved = |o: O| get(o) - before[O::ALL.iter().position(|x| *x == o).unwrap()];
    assert_eq!(moved(O::PolicyRejected), 1.0);
    assert_eq!(moved(O::Unchanged), 1.0);
    assert_eq!(moved(O::WrongCurrentPassword), 1.0);
    assert_eq!(moved(O::Changed), 1.0);
    assert_eq!(moved(O::Locked), 0.0);
}
