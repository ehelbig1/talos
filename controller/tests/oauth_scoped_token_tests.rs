mod test_helpers;

use anyhow::Result;
use chrono::Utc;
use controller::oauth::credentials::OAuthCredentialService;
use controller::secrets::SecretsManager;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
async fn test_store_and_retrieve_credentials() -> Result<()> {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );

    let pool = test_helpers::get_test_db_pool().await;

    let secrets_manager = Arc::new(SecretsManager::new(pool.clone())?);
    secrets_manager.initialize().await?; // Ensure active DEK exists
    let oauth_service = OAuthCredentialService::new(pool.clone(), secrets_manager.clone());

    // 1. Setup test user
    let user_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(format!("test-{}@example.com", user_id))
    .bind("hash")
    .execute(&pool)
    .await?;

    // 2. Setup integration credentials
    let provider = "google";
    let provider_key = "test-key";
    let access_token = "test-access-token";
    let scope = "https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/userinfo.email";

    let module_id = Uuid::new_v4();

    oauth_service
        .store_credentials(
            user_id,
            provider,
            provider_key,
            access_token,
            None,
            Utc::now() + chrono::Duration::hours(1),
            scope,
            vec![module_id],
        )
        .await?;

    // 3. Retrieve and verify the access token
    let retrieved = oauth_service
        .get_valid_access_token(user_id, provider, provider_key)
        .await?;
    assert_eq!(retrieved, access_token);

    // 4. List credentials
    let creds = oauth_service.list_credentials(user_id, None).await?;
    assert!(!creds.is_empty(), "Should have at least one credential");

    // Cleanup
    sqlx::query("DELETE FROM integration_credentials WHERE user_id = $1")
        .bind(user_id)
        .execute(&pool)
        .await?;
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await?;

    Ok(())
}
