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
