mod common;

use common::{create_test_user, setup_test_context};
use controller::api_keys::ApiKeyScope;

#[tokio::test]
async fn test_api_key_lifecycle() {
    let ctx = setup_test_context().await;
    let user_id = create_test_user(&ctx.auth_service, "api_lifecycle@example.com").await;

    // 1. Create API key
    let (full_key, key_id, _expires_at) = ctx
        .api_key_service
        .create_api_key(user_id, "Test Key", vec![ApiKeyScope::WorkflowsRead], None)
        .await
        .expect("Failed to create API key");

    assert!(full_key.starts_with("talos_sk_"));

    // 2. Validate API key
    let (validated_user_id, scopes) = ctx
        .api_key_service
        .validate_key(&full_key)
        .await
        .expect("Failed to validate API key");

    assert_eq!(validated_user_id, user_id);
    assert_eq!(scopes, vec![ApiKeyScope::WorkflowsRead]);

    // 3. List API keys
    let keys = ctx
        .api_key_service
        .list_keys(user_id)
        .await
        .expect("Failed to list keys");
    assert!(keys.iter().any(|k| k.id == key_id));

    // 4. Revoke API key
    ctx.api_key_service
        .revoke_key(key_id, user_id)
        .await
        .expect("Failed to revoke key");

    // 5. Validation should fail now
    let validation_result = ctx.api_key_service.validate_key(&full_key).await;
    assert!(validation_result.is_err(), "Revoked key should be invalid");

    // 6. Delete API key
    ctx.api_key_service
        .delete_key(key_id, user_id)
        .await
        .expect("Failed to delete key");
}

#[tokio::test]
#[ignore = "Timing-flaky on slow CI: 60 bcrypt-verify (cost 12) calls plus DB hits run close to or past the 60s rate-limit window, so the in-memory counter resets mid-loop and the 61st call isn't denied. Real fix is mock-the-clock in the rate limiter, or lower bcrypt cost via env var in CI."]
async fn test_api_key_rate_limiting() {
    let ctx = setup_test_context().await;
    let user_id = create_test_user(&ctx.auth_service, "api_rate_limit@example.com").await;

    let (full_key, _key_id, _expires_at) = ctx
        .api_key_service
        .create_api_key(user_id, "Rate Limit Test", vec![ApiKeyScope::Admin], None)
        .await
        .unwrap();

    // Trigger rate limit (default is 60/min)
    for _ in 0..60 {
        ctx.api_key_service.validate_key(&full_key).await.unwrap();
    }

    let result = ctx.api_key_service.validate_key(&full_key).await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Rate limit exceeded"));
}

#[tokio::test]
async fn test_api_key_scopes() {
    let ctx = setup_test_context().await;
    let user_id = create_test_user(&ctx.auth_service, "api_scopes@example.com").await;

    let scopes_to_test = vec![ApiKeyScope::WorkflowsWrite, ApiKeyScope::SecretsRead];
    let (full_key, _key_id, _expires_at) = ctx
        .api_key_service
        .create_api_key(user_id, "Scope Test", scopes_to_test.clone(), None)
        .await
        .unwrap();

    let (_, validated_scopes) = ctx.api_key_service.validate_key(&full_key).await.unwrap();
    assert_eq!(validated_scopes.len(), 2);
    assert!(validated_scopes.contains(&ApiKeyScope::WorkflowsWrite));
    assert!(validated_scopes.contains(&ApiKeyScope::SecretsRead));
}
