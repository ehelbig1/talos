mod test_helpers;

use controller::oauth::{OAuthProvider, OAuthService};

#[tokio::test]
async fn test_oauth_state_generation_and_validation() {
    let db_pool = test_helpers::get_test_db_pool().await;
    std::env::set_var(
        "OAUTH_STATE_SECRET",
        "test-state-secret-at-least-32-chars-long",
    );
    let oauth_service = OAuthService::new(db_pool, None).unwrap();

    let provider = "google";
    let state_token = uuid::Uuid::new_v4().to_string();

    // Store a state token with no session binding (legacy/unbound flow).
    oauth_service
        .store_state_token(&state_token, provider, None, None)
        .await
        .unwrap();

    // Should be valid for the same provider (no binding required).
    let result = oauth_service
        .validate_state_token(&state_token, provider, None)
        .await;
    assert!(
        result.is_ok(),
        "State should be valid for the same provider"
    );

    // Should be invalid for a different provider (already consumed)
    let result_wrong_provider = oauth_service
        .validate_state_token(&state_token, "github", None)
        .await;
    assert!(
        result_wrong_provider.is_err(),
        "State should be invalid for a different provider or after consumption"
    );

    // Should be invalid if tampered with
    let tampered_state = state_token.clone() + "a";
    let result_tampered = oauth_service
        .validate_state_token(&tampered_state, provider, None)
        .await;
    assert!(result_tampered.is_err(), "Tampered state should be invalid");
}

/// S1 (login-CSRF defense): when a state token is stored WITH a
/// session-binding hash, the callback must present the matching plaintext
/// nonce or be rejected — and a failed binding still burns the token.
#[tokio::test]
async fn test_oauth_state_session_binding_enforced() {
    let db_pool = test_helpers::get_test_db_pool().await;
    std::env::set_var(
        "OAUTH_STATE_SECRET",
        "test-state-secret-at-least-32-chars-long",
    );
    let oauth_service = OAuthService::new(db_pool, None).unwrap();
    let provider = "google";

    // --- Mismatched binding is rejected (and consumes the token) ---
    let (nonce, hash) = controller::oauth::generate_oauth_session_binding();
    let state_token = uuid::Uuid::new_v4().to_string();
    oauth_service
        .store_state_token(&state_token, provider, None, Some(&hash))
        .await
        .unwrap();

    // Wrong binding nonce → rejected.
    let wrong = oauth_service
        .validate_state_token(&state_token, provider, Some("not-the-nonce"))
        .await;
    assert!(
        wrong.is_err(),
        "Mismatched session binding must be rejected"
    );

    // The token was burned by the failed attempt — even the correct nonce
    // can't replay it now.
    let replay = oauth_service
        .validate_state_token(&state_token, provider, Some(&nonce))
        .await;
    assert!(
        replay.is_err(),
        "A consumed state token must not be replayable even with the right binding"
    );

    // --- Matching binding on a fresh token is accepted ---
    let (nonce2, hash2) = controller::oauth::generate_oauth_session_binding();
    let state_token2 = uuid::Uuid::new_v4().to_string();
    oauth_service
        .store_state_token(&state_token2, provider, None, Some(&hash2))
        .await
        .unwrap();
    let ok = oauth_service
        .validate_state_token(&state_token2, provider, Some(&nonce2))
        .await;
    assert!(ok.is_ok(), "Matching session binding must be accepted");

    // --- Missing binding cookie on a bound token is rejected ---
    let (_nonce3, hash3) = controller::oauth::generate_oauth_session_binding();
    let state_token3 = uuid::Uuid::new_v4().to_string();
    oauth_service
        .store_state_token(&state_token3, provider, None, Some(&hash3))
        .await
        .unwrap();
    let missing = oauth_service
        .validate_state_token(&state_token3, provider, None)
        .await;
    assert!(
        missing.is_err(),
        "A bound state token must reject a callback with no binding cookie"
    );
}

#[tokio::test]
async fn test_oauth_provider_enum_conversion() {
    assert_eq!(
        OAuthProvider::from_str("google").unwrap(),
        OAuthProvider::Google
    );
    assert_eq!(
        OAuthProvider::from_str("GOOGLE").unwrap(),
        OAuthProvider::Google
    );
    assert_eq!(
        OAuthProvider::from_str("okta").unwrap(),
        OAuthProvider::Okta
    );
    assert_eq!(
        OAuthProvider::from_str("snyk").unwrap(),
        OAuthProvider::Snyk
    );
    assert!(OAuthProvider::from_str("invalid").is_err());
}

/// Until 2026-09-18 an OAuth sign-up stored `bcrypt("__talos_oauth_account_no_password__")`
/// as the account's password hash, and bcrypt MATCHES that literal — so the
/// literal, public in this repository, signed in to every OAuth-created
/// account. Two independent guards are pinned here:
/// 1. a NEW OAuth account's hash matches nothing, the sentinel included
///    (driven through the production `link_or_create_user`);
/// 2. an account created BEFORE the fix still holds the legacy hash, and
///    `AuthService::login` refuses the sentinel against it.
/// A real password on an ordinary account still signs in (the control).
#[tokio::test]
async fn the_oauth_no_password_sentinel_opens_no_account() {
    use controller::auth::AuthService;
    use controller::oauth::OAuthUserInfo;
    use talos_unusable_password::LEGACY_OAUTH_NO_PASSWORD_SENTINEL as SENTINEL;

    let db_pool = test_helpers::get_test_db_pool().await;
    std::env::set_var(
        "OAUTH_STATE_SECRET",
        "test-state-secret-at-least-32-chars-long",
    );
    let auth = AuthService::new(
        db_pool.clone(),
        "test-secret-key-for-testing-only-min-32-chars".to_string(),
        10,
        None,
    )
    .unwrap();
    let oauth = OAuthService::new(db_pool.clone(), None).unwrap();

    // 1. A new OAuth sign-up, through the production path.
    let email = format!("oauth-new-{}@example.com", uuid::Uuid::new_v4());
    let (new_id, created) = oauth
        .link_or_create_user(
            OAuthProvider::Google,
            OAuthUserInfo {
                provider_user_id: uuid::Uuid::new_v4().to_string(),
                email: email.clone(),
                email_verified: true,
                name: None,
                picture: None,
                access_token: None,
                refresh_token: None,
                expires_in: None,
                scope: None,
            },
            None,
        )
        .await
        .expect("OAuth sign-up");
    assert!(created, "a new account must have been created");
    let stored: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
        .bind(new_id)
        .fetch_one(&db_pool)
        .await
        .unwrap();
    assert_eq!(
        stored.len(),
        60,
        "a well-formed bcrypt hash (timing parity)"
    );
    assert!(
        !bcrypt::verify(SENTINEL, &stored).unwrap(),
        "a new OAuth account's hash must not match the public sentinel"
    );
    assert!(auth.login(&email, SENTINEL, None, None).await.is_err());

    // 2. A row written before the fix: the legacy hash is still stored.
    let legacy_email = format!("oauth-legacy-{}@example.com", uuid::Uuid::new_v4());
    let legacy_hash = bcrypt::hash(SENTINEL, 10).unwrap();
    sqlx::query("INSERT INTO users (email, password_hash, is_active) VALUES ($1, $2, true)")
        .bind(&legacy_email)
        .bind(&legacy_hash)
        .execute(&db_pool)
        .await
        .unwrap();
    assert!(
        auth.login(&legacy_email, SENTINEL, None, None)
            .await
            .is_err(),
        "the sentinel must not sign in to a pre-fix OAuth account"
    );

    // Control: an ordinary account with a real password signs in.
    let real_email = format!("real-{}@example.com", uuid::Uuid::new_v4());
    auth.create_user(&real_email, "Correct-Horse-Battery-9", None, None, None)
        .await
        .unwrap();
    assert!(auth
        .login(&real_email, "Correct-Horse-Battery-9", None, None)
        .await
        .is_ok());

    for e in [&email, &legacy_email, &real_email] {
        sqlx::query("DELETE FROM users WHERE email = $1")
            .bind(e)
            .execute(&db_pool)
            .await
            .ok();
    }
}
