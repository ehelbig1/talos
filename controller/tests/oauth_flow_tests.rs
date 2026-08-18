//! Security regression tests for the shared OAuth authorization-code + PKCE
//! flow helper (`talos_oauth::flow`). These lock in the CSRF / single-use /
//! tenancy guarantees that every OAuth integration now relies on, so a future
//! refactor of the shared helper can't silently weaken them:
//!
//! * the callback recovers the INITIATING user_id from the state token (not a
//!   cookie) — the account-linking/CSRF boundary,
//! * the state token is atomic single-use (replay fails),
//! * the state token is provider-scoped (can't be consumed under another
//!   provider), and a wrong-provider attempt doesn't burn it,
//! * malformed state fails the format gate,
//! * `peek_state_provider` routes WITHOUT consuming — the multi-tier Google
//!   callback depends on the peek being non-destructive, and on it refusing to
//!   answer for a state the consume would reject,
//! * an EXPIRED state is not redeemable,
//! * the PKCE verifier is scrubbed from the row on consume (MCP-1096).

mod common;

use talos_oauth::{
    begin_oauth_authorization, consume_oauth_state, peek_state_provider, AuthorizeRequest,
};
use uuid::Uuid;

async fn seed_user(pool: &sqlx::Pool<sqlx::Postgres>, id: Uuid, email: &str) {
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, $2, 'not-a-real-hash', true) ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(email)
    .execute(pool)
    .await
    .expect("seed user");
}

fn req() -> AuthorizeRequest<'static> {
    AuthorizeRequest {
        provider: "test-provider",
        auth_url: "https://example.com/authorize",
        token_url: "https://example.com/token",
        client_id: "test-client-id".to_string(),
        client_secret: "test-client-secret".to_string(),
        redirect_uri: "https://app.example.com/callback".to_string(),
        scopes: &["read", "write"],
        extra_params: &[("access_type", "offline")],
    }
}

#[tokio::test]
async fn oauth_state_is_single_use_provider_scoped_and_user_bound() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = Uuid::new_v4();
    seed_user(&pool, user, "oauth-flow@tenancy.test").await;

    // begin: the authorize URL carries the PKCE challenge (S256) + state, and
    // the state is persisted bound to `user`.
    let (auth_url, state) = begin_oauth_authorization(&pool, &req(), user)
        .await
        .expect("begin_oauth_authorization");
    assert!(
        auth_url.contains("code_challenge="),
        "PKCE challenge present"
    );
    assert!(
        auth_url.contains("code_challenge_method=S256"),
        "PKCE S256 method"
    );
    assert!(auth_url.contains("state="), "state param present");
    assert!(!state.is_empty());

    // consume: recovers the bound user_id (the tenancy anchor) + PKCE verifier.
    let consumed = consume_oauth_state(&pool, "test-provider", &state)
        .await
        .expect("consume valid state");
    assert_eq!(
        consumed.user_id, user,
        "user_id MUST be recovered from the state token, not a session cookie"
    );
    assert!(
        consumed.pkce_verifier.is_some(),
        "PKCE verifier must be recovered for the token exchange"
    );

    // replay: a second consume of the same state must fail (atomic single-use).
    assert!(
        consume_oauth_state(&pool, "test-provider", &state)
            .await
            .is_err(),
        "state token must be single-use — replay must fail"
    );

    // provider-scoping: a fresh token can't be consumed under a DIFFERENT
    // provider, and that failed attempt must NOT burn it.
    let (_url2, state2) = begin_oauth_authorization(&pool, &req(), user)
        .await
        .expect("begin second");
    assert!(
        consume_oauth_state(&pool, "other-provider", &state2)
            .await
            .is_err(),
        "state token is provider-scoped"
    );
    assert!(
        consume_oauth_state(&pool, "test-provider", &state2)
            .await
            .is_ok(),
        "a wrong-provider attempt must not consume the token"
    );

    // format gate: malformed state (spaces / punctuation) fails before any DB work.
    assert!(
        consume_oauth_state(&pool, "test-provider", "not a valid state!!")
            .await
            .is_err(),
        "malformed state must fail the format gate"
    );
}

/// `peek_state_provider` is routing metadata for provider families that share
/// one registered redirect URI (`google_cloud` vs `google_cloud_write`). Two
/// invariants make it safe to call before the consume, and both are asserted
/// here because a peek that CONSUMED would break every such callback, and a
/// peek that answered for a dead state would route a request the consume then
/// refuses.
#[tokio::test]
async fn peek_state_provider_routes_without_consuming() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = Uuid::new_v4();
    seed_user(&pool, user, "oauth-peek@tenancy.test").await;

    let (_url, state) = begin_oauth_authorization(&pool, &req(), user)
        .await
        .expect("begin");

    // Peeking is idempotent and non-destructive.
    for attempt in 1..=2 {
        assert_eq!(
            peek_state_provider(&pool, &state).await.expect("peek"),
            Some("test-provider".to_string()),
            "peek must report the bound provider (attempt {attempt})"
        );
    }
    assert!(
        consume_oauth_state(&pool, "test-provider", &state)
            .await
            .is_ok(),
        "peeking MUST NOT consume the state — the multi-tier Google callback \
         peeks to pick a handler and then consumes"
    );

    // Once consumed, the peek must stop answering: routing on a dead state     // would send the request to a handler whose consume is guaranteed to fail.
    assert_eq!(
        peek_state_provider(&pool, &state).await.expect("peek used"),
        None,
        "a consumed state must not be routable"
    );

    // Unknown-but-well-formed, and malformed, both fail closed as Ok(None) —
    // NOT as an Err, because the caller falls through to its default provider
    // and lets `consume_oauth_state` produce the canonical CSRF-safe error.
    assert_eq!(
        peek_state_provider(&pool, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .await
            .expect("peek unknown"),
        None
    );
    // Stated precisely, because a stronger claim would not be true: this pins
    // that malformed input yields `Ok(None)` and never an `Err` (the caller
    // falls through to its default provider and lets the consume produce the
    // canonical CSRF-safe error). It does NOT prove the format gate
    // short-circuits before the DB — deleting that gate would still return
    // `Ok(None)`, because no row matches the malformed literal either. The
    // gate's own behaviour is covered by `validate_oauth_state_token_format`'s
    // unit tests in `talos-oauth`.
    assert_eq!(
        peek_state_provider(&pool, "not a valid state!!")
            .await
            .expect("malformed state must not surface as an Err"),
        None,
        "malformed state must fail closed as None, not as an error"
    );
}

/// A state token past `expires_at` must be dead to both entry points. The
/// 10-minute TTL is the window in which a leaked `state`+`code` pair is
/// replayable; without this the expiry predicate could be dropped from either
/// query and every other test in this file would still pass.
#[tokio::test]
async fn expired_state_is_neither_consumable_nor_routable() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = Uuid::new_v4();
    seed_user(&pool, user, "oauth-expiry@tenancy.test").await;

    let (_url, state) = begin_oauth_authorization(&pool, &req(), user)
        .await
        .expect("begin");

    let rows = sqlx::query("UPDATE oauth_state_tokens SET expires_at = NOW() - INTERVAL '1 second' WHERE state_token = $1")
        .bind(&state)
        .execute(&pool)
        .await
        .expect("backdate expiry")
        .rows_affected();
    assert_eq!(
        rows, 1,
        "the backdate must have hit exactly the token under test"
    );

    assert!(
        consume_oauth_state(&pool, "test-provider", &state)
            .await
            .is_err(),
        "an expired state token must not be redeemable"
    );
    assert_eq!(
        peek_state_provider(&pool, &state).await.expect("peek"),
        None,
        "an expired state token must not be routable"
    );
}

/// MCP-1096: the `pkce_verifier` is scrubbed from the row as soon as it has
/// been handed to the caller for the exchange. It bounds the window in which a
/// read-only DB compromise yields a usable verifier to the in-flight exchange
/// rather than the full 10-minute TTL.
#[tokio::test]
async fn pkce_verifier_is_scrubbed_from_the_row_on_consume() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = Uuid::new_v4();
    seed_user(&pool, user, "oauth-scrub@tenancy.test").await;

    let (_url, state) = begin_oauth_authorization(&pool, &req(), user)
        .await
        .expect("begin");

    let stored: Option<String> =
        sqlx::query_scalar("SELECT pkce_verifier FROM oauth_state_tokens WHERE state_token = $1")
            .bind(&state)
            .fetch_one(&pool)
            .await
            .expect("read verifier");
    let stored = stored.expect("a PKCE verifier must be persisted at authorize time");

    let consumed = consume_oauth_state(&pool, "test-provider", &state)
        .await
        .expect("consume");
    assert_eq!(
        consumed.pkce_verifier.as_deref(),
        Some(stored.as_str()),
        "the consume must return the SAME verifier it stored — the exchange \
         sends this value and the provider checks it against the challenge"
    );

    let after: Option<String> =
        sqlx::query_scalar("SELECT pkce_verifier FROM oauth_state_tokens WHERE state_token = $1")
            .bind(&state)
            .fetch_one(&pool)
            .await
            .expect("re-read verifier");
    assert_eq!(
        after, None,
        "the verifier must be NULLed once handed to the caller (MCP-1096)"
    );
}
