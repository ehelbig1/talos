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
//! * malformed state fails the format gate.

mod common;

use talos_oauth::{begin_oauth_authorization, consume_oauth_state, AuthorizeRequest};
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
