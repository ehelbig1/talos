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

    // Store a state token
    oauth_service
        .store_state_token(&state_token, provider, None)
        .await
        .unwrap();

    // Should be valid for the same provider
    let result = oauth_service
        .validate_state_token(&state_token, provider)
        .await;
    assert!(
        result.is_ok(),
        "State should be valid for the same provider"
    );

    // Should be invalid for a different provider (already consumed)
    let result_wrong_provider = oauth_service
        .validate_state_token(&state_token, "github")
        .await;
    assert!(
        result_wrong_provider.is_err(),
        "State should be invalid for a different provider or after consumption"
    );

    // Should be invalid if tampered with
    let tampered_state = state_token.clone() + "a";
    let result_tampered = oauth_service
        .validate_state_token(&tampered_state, provider)
        .await;
    assert!(result_tampered.is_err(), "Tampered state should be invalid");
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
