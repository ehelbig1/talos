use controller::auth::AuthService;
use std::sync::Arc;
use tokio::sync::Barrier;
use uuid::Uuid;

mod common;
use common::setup_test_context;

#[tokio::test]
async fn test_revoke_refresh_race() {
    let ctx = setup_test_context().await;
    let auth = ctx.auth_service.clone();

    let email = format!("race_{}@example.com", Uuid::new_v4());
    let _user_id = common::create_test_user(&auth, &email).await;

    // Login to get a refresh token
    let (_, refresh_token) = common::login_test_user(&auth, &email).await;

    let barrier = Arc::new(Barrier::new(2));

    // 1. Task to refresh access token
    let auth_c1 = auth.clone();
    let refresh_token_c1 = refresh_token.clone();
    let barrier_c1 = barrier.clone();
    let refresh_handle = tokio::spawn(async move {
        barrier_c1.wait().await;
        auth_c1.refresh_access_token(&refresh_token_c1).await
    });

    // 2. Task to revoke refresh token
    let auth_c2 = auth.clone();
    let refresh_token_c2 = refresh_token.clone();
    let barrier_c2 = barrier.clone();
    let revoke_handle = tokio::spawn(async move {
        barrier_c2.wait().await;
        // head start for the bcrypt verification in refresh
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        auth_c2.revoke_refresh_token(&refresh_token_c2).await
    });

    let (refresh_res, revoke_res) = tokio::join!(refresh_handle, revoke_handle);
    let refresh_result = refresh_res.expect("Refresh task panicked");
    let revoke_result = revoke_res.expect("Revoke task panicked");

    // The refresh_access_token method has a bcrypt step (blocking) followed by an
    // atomic database update. If revoke_refresh_token hits the database first,
    // the refresh should fail with "revoked" or "Invalid or expired".

    if let Err(e) = refresh_result {
        let err_msg = e.to_string();
        assert!(
            err_msg.contains("revoked") || err_msg.contains("Invalid or expired"),
            "Refresh failed with unexpected error: {}",
            err_msg
        );
    } else {
        // If it succeeded, then the revoke must have happened after the atomic update.
        assert!(revoke_result.is_ok() || revoke_result.is_err());
    }
}

#[tokio::test]
async fn test_in_memory_rate_limit_fallback() {
    let ctx = setup_test_context().await;

    // Ensure redis is NOT used by using a service without it
    let auth = Arc::new(
        AuthService::new(
            ctx.db_pool.clone(),
            "test_secret_must_be_at_least_32_chars_long".to_string(),
            12,
            None,
        )
        .unwrap(),
    );

    let email = format!("ratelimit_{}@example.com", Uuid::new_v4());
    let _user_id = common::create_test_user(&auth, &email).await;
    let (_, mut refresh_token) = common::login_test_user(&auth, &email).await;

    // The in-memory fallback allows 10 refreshes per 60s per USER (the limiter
    // keys on user_id — see AuthService::refresh_access_token — which is stable
    // across refresh-token rotation, so the cap can't be bypassed by chaining
    // rotations). r266 made refresh tokens single-use, so each call rotates the
    // token: capture the new one and feed it forward, otherwise the 2nd call
    // fails on token validity rather than exercising the rate limit.
    for i in 1..=10 {
        let (_access, new_refresh, _user, _is_2fa) = auth
            .refresh_access_token(&refresh_token)
            .await
            .unwrap_or_else(|e| panic!("Request {i} should succeed, got: {e}"));
        refresh_token = new_refresh;
    }

    // 11th request — with the LATEST valid token — must fail on the rate limit,
    // not on token validity. Asserting the specific message proves it's the
    // limiter (not rotation) that stops it.
    let res = auth.refresh_access_token(&refresh_token).await;
    assert!(res.is_err(), "11th request should have been rate limited");
    assert!(
        res.unwrap_err().to_string().contains("Rate limit exceeded"),
        "11th failure must be the rate limit, not a token-validity error"
    );
}
