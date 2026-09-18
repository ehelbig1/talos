//! Privileged operations require a VERIFIED second factor (2026-09-18).
//!
//! `require_2fa` refuses only a session half-way through a 2FA login: a login
//! on an account with no second factor enrolled is minted
//! `is_2fa_verified = true` ("nothing is pending"), and every API-key request
//! is too. So master-key and DEK rotation, the re-encryption sweeps, API-key
//! creation and capability grants ran on a password alone, and enrolling 2FA
//! revoked nothing — a refresh token minted before enrolment kept renewing.
//!
//! These tests drive the PRODUCTION schema, `AuthService` and `TotpService`:
//! the privileged gate's decision for every credential shape (an API key, a
//! pending session, a password-only session, a verified session on an account
//! with nothing enrolled, and the one shape that passes); that ordinary
//! operations keep the old gate; that login and refresh record what the
//! session actually proved; and that enrolment signs out every earlier
//! session and re-issues the enrolling one as verified.
//!
//! The privileged probe is `rotateOrgDek`: right after the second-factor gate
//! it requires platform admin, so a request that PASSES the gate is refused
//! with "Only platform admins…" — a different, recognisable sentence that
//! proves the gate let it through.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use controller::api::schema::{
    ApiKeyScopes, IsTwoFactorVerified, SecondFactorRefusal, SecondFactorVerified,
};
use uuid::Uuid;

const PROBE: &str =
    r#"mutation { rotateOrgDek(orgId: "00000000-0000-0000-0000-000000000001") { newDekId } }"#;
const PASSED_THE_GATE: &str = "Only platform admins can perform this operation";

async fn probe(schema: &common::TalosSchema, req: async_graphql::Request) -> String {
    let resp = schema.execute(req).await;
    assert!(
        !resp.errors.is_empty(),
        "the probe must be refused somewhere"
    );
    resp.errors[0].message.clone()
}

fn session(user: Uuid, pending: bool, second_factor: Option<bool>) -> async_graphql::Request {
    let mut req = async_graphql::Request::new(PROBE)
        .data(user)
        .data(IsTwoFactorVerified(!pending));
    if let Some(v) = second_factor {
        req = req.data(SecondFactorVerified(v));
    }
    req
}

async fn set_enrolled(pool: &sqlx::PgPool, user: Uuid, enrolled: bool) {
    sqlx::query("UPDATE users SET totp_enabled = $2 WHERE id = $1")
        .bind(user)
        .bind(enrolled)
        .execute(pool)
        .await
        .expect("set totp_enabled");
}

#[tokio::test]
async fn the_privileged_gate_refuses_every_shape_but_a_verified_enrolled_session() {
    let ctx = common::setup_test_context().await;
    let user = common::create_test_user(&ctx.auth_service, "priv-gate@example.com").await;

    // An API key — even one carrying the Admin scope — cannot stand in for a
    // second factor.
    let api_key = async_graphql::Request::new(PROBE)
        .data(user)
        .data(ApiKeyScopes(vec![talos_api_keys::ApiKeyScope::Admin]))
        .data(IsTwoFactorVerified(true));
    assert_eq!(
        probe(&ctx.schema, api_key).await,
        SecondFactorRefusal::ApiKey.message()
    );

    // A session still waiting for its code.
    assert_eq!(
        probe(&ctx.schema, session(user, true, Some(false))).await,
        SecondFactorRefusal::Pending.message()
    );

    // A password-only session: not pending, but no second factor verified —
    // the shape that passed every `require_2fa` gate before this change. And
    // the same with the marker absent (a token minted before the claim existed).
    for marker in [Some(false), None] {
        assert_eq!(
            probe(&ctx.schema, session(user, false, marker)).await,
            SecondFactorRefusal::NotVerified.message()
        );
    }

    // A session claiming a verified factor on an account with none enrolled
    // (2FA disabled since the session was minted): the fresh read refuses.
    set_enrolled(&ctx.db_pool, user, false).await;
    assert_eq!(
        probe(&ctx.schema, session(user, false, Some(true))).await,
        SecondFactorRefusal::NotEnrolled.message()
    );

    // Control: verified AND enrolled passes the gate and meets the next one.
    set_enrolled(&ctx.db_pool, user, true).await;
    assert_eq!(
        probe(&ctx.schema, session(user, false, Some(true))).await,
        PASSED_THE_GATE
    );
}

#[tokio::test]
async fn ordinary_operations_keep_the_old_gate() {
    let ctx = common::setup_test_context().await;
    let user = common::create_test_user(&ctx.auth_service, "priv-ordinary@example.com").await;

    // `setupTwoFactor` is gated by `require_2fa` only: a password-only session
    // (no second factor enrolled) still reaches it.
    let req = async_graphql::Request::new("mutation { setupTwoFactor { secret } }")
        .data(user)
        .data(IsTwoFactorVerified(true))
        .data(SecondFactorVerified(false));
    let resp = ctx.schema.execute(req).await;
    assert!(
        resp.errors.is_empty(),
        "an ordinary operation must not require a verified second factor: {:?}",
        resp.errors
    );
}

#[tokio::test]
async fn login_and_refresh_record_what_the_session_proved() {
    let ctx = common::setup_test_context().await;
    let email = "priv-refresh@example.com";
    let user_id = common::create_test_user(&ctx.auth_service, email).await;

    // A password login on an account with nothing enrolled: not pending, and
    // no second factor proven.
    let (access, refresh) = common::login_test_user(&ctx.auth_service, email).await;
    let claims = ctx.auth_service.verify_token(&access).unwrap();
    assert!(claims.is_2fa_verified);
    assert!(
        !claims.second_factor_verified,
        "a password proves no second factor"
    );

    // Refresh carries forward exactly what the session proved.
    let (access2, _, _, _) = ctx
        .auth_service
        .refresh_access_token(&refresh)
        .await
        .unwrap();
    assert!(
        !ctx.auth_service
            .verify_token(&access2)
            .unwrap()
            .second_factor_verified
    );

    let user = ctx.auth_service.get_user(user_id).await.unwrap();
    let verified_refresh = ctx
        .auth_service
        .generate_refresh_token(user_id, talos_auth::SessionAuth::SecondFactorVerified)
        .await
        .unwrap();
    let (access3, _, _, _) = ctx
        .auth_service
        .refresh_access_token(&verified_refresh)
        .await
        .unwrap();
    let c3 = ctx.auth_service.verify_token(&access3).unwrap();
    assert!(
        c3.second_factor_verified,
        "a verified session stays verified across refresh"
    );
    assert_eq!(c3.sub, user.id.to_string());
}

#[tokio::test]
async fn enrolment_signs_out_earlier_sessions_and_reissues_the_enrolling_one() {
    let ctx = common::setup_test_context().await;
    // Enrolment encrypts the TOTP secret: the harness's `TotpService` holds this
    // `SecretsManager`, which needs its DEK (TALOS_MASTER_KEY is supplied to
    // every CTRL binary by the runner).
    ctx.secrets_manager
        .initialize()
        .await
        .expect("initialize secrets");
    let email = "priv-enrol@example.com";
    let user = common::create_test_user(&ctx.auth_service, email).await;
    // The TOTP secret is sealed under the user's PERSONAL org DEK, which
    // production signup creates; this user needs one too.
    sqlx::query(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) \
         VALUES ($1, $1, $2, true)",
    )
    .bind(format!("priv-enrol-{user}"))
    .bind(user)
    .execute(&ctx.db_pool)
    .await
    .expect("personal org");

    // Two sessions minted before enrolment (a second device, or a stolen token).
    let (_, earlier_a) = common::login_test_user(&ctx.auth_service, email).await;
    let (_, earlier_b) = common::login_test_user(&ctx.auth_service, email).await;

    let enrolling = |query: &str, cookies: tower_cookies::Cookies| {
        async_graphql::Request::new(query.to_string())
            .data(user)
            .data(IsTwoFactorVerified(true))
            .data(SecondFactorVerified(false))
            .data(cookies)
    };

    let setup = ctx
        .schema
        .execute(enrolling(
            "mutation { setupTwoFactor { secret } }",
            tower_cookies::Cookies::default(),
        ))
        .await;
    assert!(setup.errors.is_empty(), "{:?}", setup.errors);
    let secret = setup.data.into_json().unwrap()["setupTwoFactor"]["secret"]
        .as_str()
        .unwrap()
        .to_string();
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

    let cookies = tower_cookies::Cookies::default();
    let enable = ctx
        .schema
        .execute(enrolling(
            &format!(
                r#"mutation {{ enableTwoFactor(input: {{secret: "{secret}", code: "{code}"}}) {{ backupCodes }} }}"#
            ),
            cookies.clone(),
        ))
        .await;
    assert!(enable.errors.is_empty(), "{:?}", enable.errors);

    // Every earlier session is gone: their refresh tokens no longer work.
    for token in [&earlier_a, &earlier_b] {
        assert!(
            ctx.auth_service.refresh_access_token(token).await.is_err(),
            "a session minted before enrolment must be signed out"
        );
    }

    // Exactly one session remains — the re-issued enrolling one — and it
    // records a verified second factor.
    let rows: Vec<(bool, bool)> = sqlx::query_as(
        "SELECT is_2fa_verified, second_factor_verified FROM user_sessions WHERE user_id = $1",
    )
    .bind(user)
    .fetch_all(&ctx.db_pool)
    .await
    .unwrap();
    assert_eq!(rows, vec![(true, true)]);

    // And its cookies carry an access token that says so.
    let access = cookies
        .list()
        .into_iter()
        .find(|c| c.value().split('.').count() == 3)
        .expect("an access-token cookie was set")
        .value()
        .to_string();
    assert!(
        ctx.auth_service
            .verify_token(&access)
            .unwrap()
            .second_factor_verified
    );
}

/// Over MCP a cross-user capability grant is refused for EVERY caller — here a
/// platform admin, the one the old check admitted — because an MCP agent token
/// cannot prove a second factor. Nothing is written. Control: a self-grant,
/// which cannot raise anyone's ceiling, still goes through.
#[tokio::test]
async fn mcp_refuses_a_cross_user_capability_grant_even_for_an_admin() {
    let ctx = common::setup_test_context().await;
    let admin = common::create_test_user(&ctx.auth_service, "priv-mcp-admin@example.com").await;
    let other = common::create_test_user(&ctx.auth_service, "priv-mcp-other@example.com").await;
    sqlx::query("UPDATE users SET is_platform_admin = true WHERE id = $1")
        .bind(admin)
        .execute(&ctx.db_pool)
        .await
        .expect("platform admin");
    let state = mcp_common::mcp_state(ctx.db_pool.clone()).await;
    let grant = |target: Uuid| {
        let state = &state;
        async move {
            controller::mcp::actor::dispatch(
                "grant_capability_ceiling",
                Some(serde_json::json!(1)),
                &serde_json::json!({
                    "user_id": target.to_string(),
                    "max_capability_world": "http-node",
                }),
                state,
                mcp_common::agent(admin),
            )
            .await
            .expect("grant_capability_ceiling is dispatched")
        }
    };
    let grants = |user: Uuid| {
        let pool = ctx.db_pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM user_capability_grants WHERE user_id = $1",
            )
            .bind(user)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };

    let refused = grant(other).await;
    let msg = mcp_common::error_message(&refused);
    assert!(
        msg.contains("two-factor authentication") && msg.contains("grantCapabilityCeiling"),
        "names the reason and the gated route: {msg}"
    );
    assert_eq!(grants(other).await, 0, "nothing was granted");

    let own = grant(admin).await;
    let is_error = own.error.is_some()
        || own
            .result
            .as_ref()
            .and_then(|r| r.get("isError"))
            .and_then(|v| v.as_bool())
            == Some(true);
    assert!(!is_error, "a self-grant still goes through: {own:?}");
}
