//! Three ways to gain privilege that a review found on 2026-09-25.
//!
//! 1. An API key could turn itself into a second-factor-verified browser
//!    session. The router marks every API-key request `IsTwoFactorVerified`
//!    (keys skip 2FA), so `require_2fa` admitted a `workflows:read` key to
//!    `enableTwoFactor` — which enrolled the key holder's own secret and signed
//!    the owner out — and then to `verifyTwoFactor`, which minted a 7-day
//!    renewable session that passes `require_second_factor`.
//! 2. 2FA enrolment and backup-code verification ran up to ten bcrypt
//!    operations inline on the async runtime thread (and hashed all ten even
//!    for an enrolment it was about to refuse), with no per-user bound.
//! 3. The capability bootstrap was re-armed by removing the last
//!    `automation-node` grant, and a user could widen their own ceiling by
//!    revoking a grant narrower than the default.
//!
//! These tests drive the PRODUCTION schema, `TotpService`, `ActorRepository`,
//! the bootstrap and the MCP handler. The router's half of (1) — an
//! `X-API-Key` request gets no cookie jar — is a source pin in
//! `controller/src/bootstrap/router.rs`, because `graphql_handler` lives in the
//! binary.
//!
//! The runtime-thread tests rely on `#[tokio::test]`'s current-thread runtime:
//! a ticker task runs only when the code under test yields, so a long gap
//! between ticks is time the thread spent blocked.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use controller::api::schema::{
    ApiKeyScopes, IsTwoFactorVerified, SecondFactorRefusal, SecondFactorVerified,
    NO_PENDING_SECOND_FACTOR,
};
use controller::totp_2fa::{ENROLMENT_THROTTLED_MESSAGE, MAX_ENROLMENT_ATTEMPTS};
use talos_actor_repository::{ActorRepository, CapabilityGrantRevocation};
use uuid::Uuid;

/// 2FA enrolment seals the TOTP secret under the user's personal-org DEK, as
/// production signup provides.
async fn totp_ready(ctx: &common::TestContext, user: Uuid) {
    ctx.secrets_manager
        .initialize()
        .await
        .expect("initialize secrets");
    sqlx::query(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) VALUES ($1, $1, $2, true)",
    )
    .bind(format!("2fa-session-{user}"))
    .bind(user)
    .execute(&ctx.db_pool)
    .await
    .expect("personal org");
}

fn current_code(secret: &str) -> String {
    totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        totp_rs::Secret::Encoded(secret.to_string())
            .to_bytes()
            .unwrap(),
    )
    .unwrap()
    .generate_current()
    .unwrap()
}

async fn totp_enabled(pool: &sqlx::PgPool, user: Uuid) -> bool {
    sqlx::query_scalar::<_, Option<bool>>("SELECT totp_enabled FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .unwrap()
        .unwrap_or(false)
}

async fn session_rows(pool: &sqlx::PgPool, user: Uuid) -> Vec<(bool, bool)> {
    sqlx::query_as(
        "SELECT is_2fa_verified, second_factor_verified FROM user_sessions \
         WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(user)
    .fetch_all(pool)
    .await
    .unwrap()
}

/// An API-key request, as the router builds one — plus a cookie jar the router
/// would NOT hand it, so the resolver's own refusal is what is tested.
fn api_key(query: &str, user: Uuid, cookies: tower_cookies::Cookies) -> async_graphql::Request {
    async_graphql::Request::new(query.to_string())
        .data(user)
        .data(ApiKeyScopes(vec![
            talos_api_keys::ApiKeyScope::WorkflowsRead,
        ]))
        .data(IsTwoFactorVerified(true))
        .data(cookies)
}

/// A browser session: `pending` = still waiting for its 2FA code.
fn session(
    query: &str,
    user: Uuid,
    pending: bool,
    second_factor: bool,
    cookies: tower_cookies::Cookies,
) -> async_graphql::Request {
    async_graphql::Request::new(query.to_string())
        .data(user)
        .data(IsTwoFactorVerified(!pending))
        .data(SecondFactorVerified(second_factor))
        .data(cookies)
}

fn enable_query(secret: &str, code: &str) -> String {
    format!(
        r#"mutation {{ enableTwoFactor(input: {{secret: "{secret}", code: "{code}"}}) {{ backupCodes }} }}"#
    )
}

fn verify_query(code: &str) -> String {
    format!(r#"mutation {{ verifyTwoFactor(input: {{code: "{code}"}}) {{ user {{ id }} }} }}"#)
}

async fn refusal(schema: &common::TalosSchema, req: async_graphql::Request) -> String {
    let resp = schema.execute(req).await;
    assert!(!resp.errors.is_empty(), "expected a refusal");
    resp.errors[0].message.clone()
}

/// Run `fut` beside a 5 ms ticker on this current-thread runtime. Returns its
/// output, the longest stretch in which the ticker could not run, and the
/// total elapsed time.
async fn with_ticker<F: Future>(fut: F) -> (F::Output, Duration, Duration) {
    let ticks: Arc<Mutex<Vec<Instant>>> = Arc::default();
    let recorder = ticks.clone();
    let ticker = tokio::spawn(async move {
        loop {
            recorder.lock().unwrap().push(Instant::now());
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
    tokio::task::yield_now().await;
    let start = Instant::now();
    let out = fut.await;
    let end = Instant::now();
    ticker.abort();
    let mut marks = vec![start];
    marks.extend(
        ticks
            .lock()
            .unwrap()
            .iter()
            .copied()
            .filter(|t| *t > start && *t < end),
    );
    marks.push(end);
    let longest = marks
        .windows(2)
        .map(|w| w[1] - w[0])
        .max()
        .unwrap_or_default();
    (out, longest, end - start)
}

// ── 1. An API key cannot become a second-factor session ─────────────────────

/// The attack as reported: a read-scoped key on an account without 2FA. Every
/// step is refused, the account stays unenrolled, and the owner stays signed in.
#[tokio::test]
async fn an_api_key_cannot_enrol_a_second_factor() {
    let ctx = common::setup_test_context().await;
    let email = "2fa-apikey-enrol@example.com";
    let user = common::create_test_user(&ctx.auth_service, email).await;
    totp_ready(&ctx, user).await;
    let (_, owners_refresh) = common::login_test_user(&ctx.auth_service, email).await;

    let jar = tower_cookies::Cookies::default();
    assert_eq!(
        refusal(
            &ctx.schema,
            api_key("mutation { setupTwoFactor { secret } }", user, jar.clone())
        )
        .await,
        SecondFactorRefusal::ApiKey.message()
    );

    // The key holder picks the secret, so a valid code is always at hand.
    let secret = ctx.totp_service.generate_secret();
    let code = current_code(&secret);
    assert_eq!(
        refusal(
            &ctx.schema,
            api_key(&enable_query(&secret, &code), user, jar.clone())
        )
        .await,
        SecondFactorRefusal::ApiKey.message()
    );
    assert!(!totp_enabled(&ctx.db_pool, user).await, "nothing enrolled");
    assert!(
        ctx.auth_service
            .refresh_access_token(&owners_refresh)
            .await
            .is_ok(),
        "the owner was not signed out"
    );
    assert!(jar.list().is_empty(), "no cookie was set");
}

/// Once the account IS enrolled, a key holding a valid code still cannot trade
/// it for a session.
#[tokio::test]
async fn an_api_key_cannot_verify_a_second_factor() {
    let ctx = common::setup_test_context().await;
    let email = "2fa-apikey-verify@example.com";
    let user = common::create_test_user(&ctx.auth_service, email).await;
    totp_ready(&ctx, user).await;
    let secret = ctx.totp_service.generate_secret();
    ctx.totp_service
        .enable_2fa(user, &secret, &current_code(&secret), email)
        .await
        .expect("owner enrols");
    let sessions_before = session_rows(&ctx.db_pool, user).await;

    let jar = tower_cookies::Cookies::default();
    assert_eq!(
        refusal(
            &ctx.schema,
            api_key(&verify_query(&current_code(&secret)), user, jar.clone())
        )
        .await,
        SecondFactorRefusal::ApiKey.message()
    );
    assert_eq!(
        session_rows(&ctx.db_pool, user).await,
        sessions_before,
        "no session was minted"
    );
    assert!(jar.list().is_empty(), "no cookie was set");
}

/// `verifyTwoFactor` completes a login, so only a session waiting for its code
/// may call it. A password-only or already-verified session is refused even
/// with a valid code; the pending session (control) still completes.
#[tokio::test]
async fn verify_two_factor_requires_a_pending_session() {
    let ctx = common::setup_test_context().await;
    let email = "2fa-verify-pending@example.com";
    let user = common::create_test_user(&ctx.auth_service, email).await;
    totp_ready(&ctx, user).await;
    let secret = ctx.totp_service.generate_secret();
    ctx.totp_service
        .enable_2fa(user, &secret, &current_code(&secret), email)
        .await
        .expect("enrol");
    let sessions_before = session_rows(&ctx.db_pool, user).await;

    for (pending, second_factor) in [(false, false), (false, true)] {
        let jar = tower_cookies::Cookies::default();
        assert_eq!(
            refusal(
                &ctx.schema,
                session(
                    &verify_query(&current_code(&secret)),
                    user,
                    pending,
                    second_factor,
                    jar.clone()
                )
            )
            .await,
            NO_PENDING_SECOND_FACTOR
        );
        assert!(jar.list().is_empty());
    }
    assert_eq!(session_rows(&ctx.db_pool, user).await, sessions_before);

    // Control: the session a 2FA login actually produces.
    let jar = tower_cookies::Cookies::default();
    let resp = ctx
        .schema
        .execute(session(
            &verify_query(&current_code(&secret)),
            user,
            true,
            false,
            jar.clone(),
        ))
        .await;
    assert!(resp.errors.is_empty(), "{:?}", resp.errors);
    assert!(session_rows(&ctx.db_pool, user)
        .await
        .contains(&(true, true)));
    assert!(!jar.list().is_empty(), "the verified session was issued");
}

/// The router gives an API-key request no cookie jar, so the operations that
/// read or clear cookies must cope: revoking every session still works for an
/// Admin key, and a refresh names what it needs instead of failing obscurely.
#[tokio::test]
async fn cookie_operations_without_a_jar() {
    let ctx = common::setup_test_context().await;
    let email = "2fa-no-jar@example.com";
    let user = common::create_test_user(&ctx.auth_service, email).await;
    let (_, refresh) = common::login_test_user(&ctx.auth_service, email).await;

    let admin_key = |query: &str| {
        async_graphql::Request::new(query.to_string())
            .data(user)
            .data(ApiKeyScopes(vec![talos_api_keys::ApiKeyScope::Admin]))
            .data(IsTwoFactorVerified(true))
    };
    let resp = ctx
        .schema
        .execute(admin_key("mutation { logoutAllSessions }"))
        .await;
    assert!(resp.errors.is_empty(), "{:?}", resp.errors);
    assert!(
        ctx.auth_service
            .refresh_access_token(&refresh)
            .await
            .is_err(),
        "every session was revoked"
    );

    let msg = refusal(
        &ctx.schema,
        admin_key("mutation { refreshToken { user { id } } }"),
    )
    .await;
    assert!(msg.contains("browser session"), "{msg}");
}

// ── 2. bcrypt stays off the runtime thread; enrolment is bounded ────────────

/// Enrolment's ten bcrypt hashes run on the blocking pool, and a re-enrolment
/// of an enabled account is refused before any of them.
#[tokio::test(flavor = "current_thread")]
async fn enrolment_hashes_off_the_runtime_and_refuses_before_hashing() {
    let ctx = common::setup_test_context().await;
    let email = "2fa-enrol-blocking@example.com";
    let user = common::create_test_user(&ctx.auth_service, email).await;
    totp_ready(&ctx, user).await;

    let secret = ctx.totp_service.generate_secret();
    let code = current_code(&secret);
    let (enrolled, longest, enrol_elapsed) =
        with_ticker(ctx.totp_service.enable_2fa(user, &secret, &code, email)).await;
    assert_eq!(enrolled.expect("enrol").len(), 10);
    assert!(
        longest < enrol_elapsed / 2,
        "the runtime thread was blocked for {longest:?} of a {enrol_elapsed:?} enrolment"
    );

    let again = ctx.totp_service.generate_secret();
    let started = Instant::now();
    let refused = ctx
        .totp_service
        .enable_2fa(user, &again, &current_code(&again), email)
        .await
        .expect_err("already enrolled");
    let refused_elapsed = started.elapsed();
    assert!(refused.to_string().contains("already enabled"), "{refused}");
    assert!(
        refused_elapsed < enrol_elapsed / 4,
        "the refusal took {refused_elapsed:?} against {enrol_elapsed:?} for a full enrolment"
    );
}

/// Backup-code verification runs its bcrypt verifies on the blocking pool, and
/// a code is still spent exactly once — sequentially and when two uses race.
#[tokio::test(flavor = "current_thread")]
async fn backup_codes_verify_off_the_runtime_and_spend_once() {
    let ctx = common::setup_test_context().await;
    let email = "2fa-backup-blocking@example.com";
    let user = common::create_test_user(&ctx.auth_service, email).await;
    totp_ready(&ctx, user).await;
    let secret = ctx.totp_service.generate_secret();
    let codes = ctx
        .totp_service
        .enable_2fa(user, &secret, &current_code(&secret), email)
        .await
        .expect("enrol");

    // A wrong code shaped like a backup code is checked against all ten.
    let (wrong, longest, elapsed) = with_ticker(ctx.totp_service.verify_2fa_login(
        user,
        "0123456789ab",
        email,
    ))
    .await;
    assert!(!wrong.expect("verify"), "a wrong code does not verify");
    assert!(
        longest < elapsed / 2,
        "the runtime thread was blocked for {longest:?} of a {elapsed:?} verification"
    );

    // Upper case is accepted (MCP-511), and a spent code does not verify twice.
    let first = codes[0].to_ascii_uppercase();
    assert!(ctx
        .totp_service
        .verify_2fa_login(user, &first, email)
        .await
        .unwrap());
    assert!(!ctx
        .totp_service
        .verify_2fa_login(user, &codes[0], email)
        .await
        .unwrap());

    // Two concurrent uses of one code: exactly one spends it.
    let (a, b) = tokio::join!(
        ctx.totp_service.verify_2fa_login(user, &codes[1], email),
        ctx.totp_service.verify_2fa_login(user, &codes[1], email),
    );
    assert_eq!(
        [a.unwrap(), b.unwrap()].iter().filter(|ok| **ok).count(),
        1,
        "one backup code, one login"
    );
    let left: Vec<String> = sqlx::query_scalar("SELECT backup_codes FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(&ctx.db_pool)
        .await
        .unwrap();
    assert_eq!(left.len(), 8, "exactly the two spent codes are gone");
}

/// Enrolment attempts are bounded per user: `setupTwoFactor` and
/// `enableTwoFactor` share one budget, and another user's is untouched.
#[tokio::test]
async fn enrolment_attempts_are_bounded_per_user() {
    let ctx = common::setup_test_context().await;
    let user = common::create_test_user(&ctx.auth_service, "2fa-throttle@example.com").await;
    let other = common::create_test_user(&ctx.auth_service, "2fa-throttle-2@example.com").await;
    let setup = |who: Uuid| {
        session(
            "mutation { setupTwoFactor { secret } }",
            who,
            false,
            false,
            tower_cookies::Cookies::default(),
        )
    };

    for attempt in 1..=MAX_ENROLMENT_ATTEMPTS {
        let resp = ctx.schema.execute(setup(user)).await;
        assert!(
            resp.errors.is_empty(),
            "attempt {attempt}: {:?}",
            resp.errors
        );
    }
    assert_eq!(
        refusal(&ctx.schema, setup(user)).await,
        ENROLMENT_THROTTLED_MESSAGE
    );
    let secret = ctx.totp_service.generate_secret();
    assert_eq!(
        refusal(
            &ctx.schema,
            session(
                &enable_query(&secret, &current_code(&secret)),
                user,
                false,
                false,
                tower_cookies::Cookies::default()
            )
        )
        .await,
        ENROLMENT_THROTTLED_MESSAGE,
        "enableTwoFactor draws on the same budget"
    );
    assert!(!totp_enabled(&ctx.db_pool, user).await);

    let resp = ctx.schema.execute(setup(other)).await;
    assert!(resp.errors.is_empty(), "another user is not throttled");
}

// ── 3. Capability ceilings cannot be raised by removing a grant ─────────────

/// The bootstrap runs once. Removing the last `automation-node` grant does not
/// elevate the next signup, and the boot-time call does not re-grant anyone.
#[tokio::test]
async fn the_capability_bootstrap_runs_once() {
    let ctx = common::setup_test_context().await;
    let repo = ActorRepository::new(ctx.db_pool.clone());
    let first = common::create_test_user(&ctx.auth_service, "boot-once-first@example.com").await;
    assert_eq!(
        repo.user_capability_ceiling(first).await.unwrap(),
        "automation-node"
    );

    // Someone else withdraws the only top-ceiling grant.
    let other = common::create_test_user(&ctx.auth_service, "boot-once-other@example.com").await;
    assert_eq!(
        repo.user_capability_ceiling(other).await.unwrap(),
        "http-node"
    );
    assert!(matches!(
        repo.delete_capability_grant(first, other, None)
            .await
            .unwrap(),
        CapabilityGrantRevocation::Revoked { .. }
    ));

    let later = common::create_test_user(&ctx.auth_service, "boot-once-later@example.com").await;
    assert_eq!(
        repo.user_capability_ceiling(later).await.unwrap(),
        "http-node",
        "a signup after the bootstrap is not elevated"
    );
    assert!(
        !talos_auth::promote_first_user_if_needed(&ctx.db_pool, None)
            .await
            .unwrap(),
        "a restart does not re-grant"
    );
    let top: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM user_capability_grants WHERE max_capability_world = 'automation-node'",
    )
    .fetch_one(&ctx.db_pool)
    .await
    .unwrap();
    assert_eq!(top, 0);

    // What makes it once: the bootstrap row, naming whom it promoted.
    let row: (Option<Uuid>, String) =
        sqlx::query_as("SELECT user_id, source FROM capability_bootstrap")
            .fetch_one(&ctx.db_pool)
            .await
            .unwrap();
    assert_eq!(row, (Some(first), "runtime".to_string()));
}

/// The migration's backfill, driven with its own SQL: a deployment where
/// someone holds the top ceiling, or whose audit log shows one was granted, is
/// marked bootstrapped; one with neither is left eligible.
#[tokio::test]
async fn the_bootstrap_backfill_marks_only_deployments_that_have_bootstrapped() {
    const MIGRATION: &str =
        include_str!("../../migrations/20260925140000_capability_bootstrap_once.sql");
    let ctx = common::setup_test_context().await;
    // Signup bootstraps this user and records `capability_grant_issued`.
    let user = common::create_test_user(&ctx.auth_service, "boot-backfill@example.com").await;
    let pool = &ctx.db_pool;
    let run = |statements: &'static [&'static str]| async move {
        for statement in statements {
            sqlx::raw_sql(statement).execute(pool).await.unwrap();
        }
    };
    let rows = || async {
        sqlx::query_as::<_, (Option<Uuid>, String)>(
            "SELECT user_id, source FROM capability_bootstrap",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    };
    const FORGET: &[&str] = &[
        "DELETE FROM capability_bootstrap",
        "DELETE FROM user_capability_grants",
    ];

    // Neither a top-ceiling grant nor a record of one (the audit table is
    // append-only, so it is swapped for an empty copy rather than emptied).
    run(FORGET).await;
    run(&[
        "ALTER TABLE admin_event_log RENAME TO admin_event_log_hidden",
        "CREATE TABLE admin_event_log (LIKE admin_event_log_hidden)",
    ])
    .await;
    sqlx::raw_sql(MIGRATION).execute(pool).await.unwrap();
    assert!(
        rows().await.is_empty(),
        "never bootstrapped: still eligible"
    );

    // Someone holds the top ceiling.
    sqlx::query(
        "INSERT INTO user_capability_grants (user_id, max_capability_world) \
         VALUES ($1, 'automation-node')",
    )
    .bind(user)
    .execute(pool)
    .await
    .unwrap();
    sqlx::raw_sql(MIGRATION).execute(pool).await.unwrap();
    assert_eq!(rows().await, vec![(None, "backfill".to_string())]);

    // Nobody does any more, but the audit log records the grant.
    run(FORGET).await;
    run(&[
        "DROP TABLE admin_event_log",
        "ALTER TABLE admin_event_log_hidden RENAME TO admin_event_log",
    ])
    .await;
    sqlx::raw_sql(MIGRATION).execute(pool).await.unwrap();
    assert_eq!(rows().await, vec![(None, "backfill".to_string())]);
}

/// Revoking your own grant must not widen your ceiling. A `minimal-node` or
/// `governance-node` grant stays until an admin removes it — over GraphQL and
/// over MCP. Controls: a narrowing self-revoke still works, and so does an
/// admin's revocation of the restricted grant.
#[tokio::test]
async fn a_user_cannot_widen_their_own_ceiling_by_revoking_it() {
    let ctx = common::setup_test_context().await;
    let repo = ActorRepository::new(ctx.db_pool.clone());
    let admin = common::create_test_user(&ctx.auth_service, "self-revoke-admin@example.com").await;
    sqlx::query("UPDATE users SET is_platform_admin = true WHERE id = $1")
        .bind(admin)
        .execute(&ctx.db_pool)
        .await
        .unwrap();
    let user = common::create_test_user(&ctx.auth_service, "self-revoke-user@example.com").await;
    let revoke = |who: Uuid, target: Uuid| {
        async_graphql::Request::new(format!(
            r#"mutation {{ revokeCapabilityCeiling(userId: "{target}") }}"#
        ))
        .data(who)
        .data(IsTwoFactorVerified(true))
        .data(SecondFactorVerified(false))
    };
    let revoked_events = |pool: sqlx::PgPool| async move {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM admin_event_log WHERE event_type = 'capability_grant_revoked' \
             AND resource_id = $1",
        )
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap()
    };

    for world in ["minimal-node", "governance-node"] {
        repo.upsert_capability_grant(user, world, admin, Some("restricted"))
            .await
            .unwrap();
        assert_eq!(
            refusal(&ctx.schema, revoke(user, user)).await,
            CapabilityGrantRevocation::self_revoke_refusal(world)
        );
        assert_eq!(repo.user_capability_ceiling(user).await.unwrap(), world);
    }
    assert_eq!(revoked_events(ctx.db_pool.clone()).await, 0);

    // Over MCP too.
    let state = mcp_common::mcp_state(ctx.db_pool.clone()).await;
    let resp = controller::mcp::actor::dispatch(
        "revoke_capability_ceiling",
        Some(serde_json::json!(1)),
        &serde_json::json!({ "user_id": user.to_string() }),
        &state,
        mcp_common::agent(user),
    )
    .await
    .expect("revoke_capability_ceiling is dispatched");
    assert_eq!(
        mcp_common::error_message(&resp),
        CapabilityGrantRevocation::self_revoke_refusal("governance-node")
    );
    assert_eq!(
        repo.user_capability_ceiling(user).await.unwrap(),
        "governance-node"
    );

    // Control: an admin may remove the restricted grant.
    let resp = ctx.schema.execute(revoke(admin, user)).await;
    assert!(resp.errors.is_empty(), "{:?}", resp.errors);
    assert_eq!(
        repo.user_capability_ceiling(user).await.unwrap(),
        "http-node"
    );

    // Control: withdrawing a grant ABOVE the default narrows, and is allowed.
    repo.upsert_capability_grant(user, "agent-node", admin, None)
        .await
        .unwrap();
    let resp = ctx.schema.execute(revoke(user, user)).await;
    assert!(resp.errors.is_empty(), "{:?}", resp.errors);
    assert_eq!(
        repo.user_capability_ceiling(user).await.unwrap(),
        "http-node"
    );
    assert_eq!(revoked_events(ctx.db_pool.clone()).await, 2);
}
