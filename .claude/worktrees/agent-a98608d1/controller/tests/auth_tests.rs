// Auth Service Integration Tests
//
// These tests verify the authentication service functionality including:
// - User signup with password validation
// - Login/logout flows
// - JWT token generation and verification
// - Refresh token rotation
// - Password change operations
// - Account lockout after failed attempts
// - Session cleanup
//
// SETUP REQUIRED:
// 1. Create a test database: createdb talos_test
// 2. Run migrations: sqlx migrate run --database-url postgres://localhost/talos_test
// 3. Set DATABASE_URL environment variable (optional):
//    export DATABASE_URL=postgres://username:password@localhost/talos_test
//
// To run these tests:
//    cargo test --test auth_tests

use controller::auth::AuthService;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

/// Helper to create a test database pool
async fn setup_test_db() -> Pool<Postgres> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/talos_test".to_string());

    sqlx::PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to test database")
}

/// Helper to create test auth service
async fn setup_auth_service() -> AuthService {
    let db_pool = setup_test_db().await;
    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "test-secret-key-for-testing-only-min-32-chars".to_string());
    let bcrypt_cost = 12; // Use production-recommended cost
    AuthService::new(db_pool, jwt_secret, bcrypt_cost).expect("Failed to create AuthService")
}

/// Helper to clean up test users
async fn cleanup_test_user(db_pool: &Pool<Postgres>, email: &str) {
    sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(email)
        .execute(db_pool)
        .await
        .ok();
}

#[tokio::test]
#[ignore]
async fn test_signup_creates_user() {
    let auth_service = setup_auth_service().await;
    let test_email = format!("test_signup_{}@example.com", Uuid::new_v4());
    let test_password = "SecurePassword123!";

    // Clean up any existing test user
    cleanup_test_user(&auth_service.db_pool, &test_email).await;

    // Create user should succeed
    let result = auth_service
        .create_user(&test_email, test_password, Some("Test User"), None, None)
        .await;

    assert!(result.is_ok(), "Signup should succeed");
    let user_id = result.unwrap();

    // Verify user exists in database
    let user = auth_service.get_user(user_id).await;
    assert!(user.is_ok(), "User should exist after signup");
    assert_eq!(user.unwrap().email, test_email);

    // Cleanup
    cleanup_test_user(&auth_service.db_pool, &test_email).await;
}

#[tokio::test]
#[ignore]
async fn test_signup_rejects_weak_password() {
    let auth_service = setup_auth_service().await;
    let test_email = format!("test_weak_pwd_{}@example.com", Uuid::new_v4());

    // Weak password should fail
    let result = auth_service
        .create_user(&test_email, "weak", Some("Test User"), None, None)
        .await;

    assert!(result.is_err(), "Weak password should be rejected");
    assert!(
        result.unwrap_err().to_string().contains("at least 12"),
        "Error should mention password length requirement"
    );
}

#[tokio::test]
#[ignore]
async fn test_signup_rejects_duplicate_email() {
    let auth_service = setup_auth_service().await;
    let test_email = format!("test_duplicate_{}@example.com", Uuid::new_v4());
    let test_password = "SecurePassword123!";

    // Clean up
    cleanup_test_user(&auth_service.db_pool, &test_email).await;

    // First signup should succeed
    let result1 = auth_service
        .create_user(&test_email, test_password, Some("User 1"), None, None)
        .await;
    assert!(result1.is_ok());

    // Second signup with same email should fail
    let result2 = auth_service
        .create_user(&test_email, test_password, Some("User 2"), None, None)
        .await;
    assert!(result2.is_err(), "Duplicate email should be rejected");

    // Cleanup
    cleanup_test_user(&auth_service.db_pool, &test_email).await;
}

#[tokio::test]
#[ignore]
async fn test_login_with_valid_credentials() {
    let auth_service = setup_auth_service().await;
    let test_email = format!("test_login_{}@example.com", Uuid::new_v4());
    let test_password = "SecurePassword123!";

    // Clean up
    cleanup_test_user(&auth_service.db_pool, &test_email).await;

    // Create user
    let user_id = auth_service
        .create_user(&test_email, test_password, Some("Test User"), None, None)
        .await
        .expect("Signup should succeed");

    // Login should succeed
    let result = auth_service
        .login(&test_email, test_password, None, None)
        .await;

    assert!(
        result.is_ok(),
        "Login with valid credentials should succeed"
    );
    let (access_token, _refresh_token, logged_in_user) = result.unwrap();

    // Verify access token is not empty
    assert!(!access_token.is_empty(), "Access token should not be empty");

    // Verify logged in user matches
    assert_eq!(logged_in_user.id, user_id);
    assert_eq!(logged_in_user.email, test_email);

    // Cleanup
    cleanup_test_user(&auth_service.db_pool, &test_email).await;
}

#[tokio::test]
#[ignore]
async fn test_login_with_invalid_password() {
    let auth_service = setup_auth_service().await;
    let test_email = format!("test_bad_pwd_{}@example.com", Uuid::new_v4());
    let test_password = "SecurePassword123!";
    let wrong_password = "WrongPassword123!";

    // Clean up
    cleanup_test_user(&auth_service.db_pool, &test_email).await;

    // Create user
    auth_service
        .create_user(&test_email, test_password, Some("Test User"), None, None)
        .await
        .expect("Signup should succeed");

    // Login with wrong password should fail
    let result = auth_service
        .login(&test_email, wrong_password, None, None)
        .await;

    assert!(result.is_err(), "Login with wrong password should fail");

    // Cleanup
    cleanup_test_user(&auth_service.db_pool, &test_email).await;
}

#[tokio::test]
#[ignore]
async fn test_login_with_nonexistent_user() {
    let auth_service = setup_auth_service().await;
    let test_email = format!("nonexistent_{}@example.com", Uuid::new_v4());

    // Login should fail for non-existent user
    let result = auth_service
        .login(&test_email, "AnyPassword123!", None, None)
        .await;

    assert!(result.is_err(), "Login with non-existent user should fail");
}

#[tokio::test]
#[ignore]
async fn test_refresh_token_flow() {
    let auth_service = setup_auth_service().await;
    let test_email = format!("test_refresh_{}@example.com", Uuid::new_v4());
    let test_password = "SecurePassword123!";

    // Clean up
    cleanup_test_user(&auth_service.db_pool, &test_email).await;

    // Create user and login
    auth_service
        .create_user(&test_email, test_password, Some("Test User"), None, None)
        .await
        .expect("Signup should succeed");

    let (_access_token, refresh_token, user) = auth_service
        .login(&test_email, test_password, None, None)
        .await
        .expect("Login should succeed");

    // Refresh token should work
    let result = auth_service.refresh_access_token(&refresh_token).await;

    assert!(result.is_ok(), "Token refresh should succeed");
    let (new_access_token, refreshed_user) = result.unwrap();

    // Verify new access token
    assert!(!new_access_token.is_empty());
    assert_eq!(refreshed_user.id, user.id);

    // Cleanup
    cleanup_test_user(&auth_service.db_pool, &test_email).await;
}

#[tokio::test]
#[ignore]
async fn test_refresh_with_invalid_token() {
    let auth_service = setup_auth_service().await;

    // Refresh with invalid token should fail
    let result = auth_service
        .refresh_access_token("invalid_token_12345")
        .await;

    assert!(result.is_err(), "Refresh with invalid token should fail");
}

#[tokio::test]
#[ignore]
async fn test_token_verification() {
    let auth_service = setup_auth_service().await;
    let test_email = format!("test_verify_{}@example.com", Uuid::new_v4());
    let test_password = "SecurePassword123!";

    // Clean up
    cleanup_test_user(&auth_service.db_pool, &test_email).await;

    // Create user and login
    let user_id = auth_service
        .create_user(&test_email, test_password, Some("Test User"), None, None)
        .await
        .expect("Signup should succeed");

    let (access_token, _refresh_token, _user) = auth_service
        .login(&test_email, test_password, None, None)
        .await
        .expect("Login should succeed");

    // Verify token
    let result = auth_service.verify_token(&access_token);

    assert!(result.is_ok(), "Token verification should succeed");
    let claims = result.unwrap();
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.email, test_email);

    // Cleanup
    cleanup_test_user(&auth_service.db_pool, &test_email).await;
}

#[tokio::test]
#[ignore]
async fn test_token_verification_with_invalid_token() {
    let auth_service = setup_auth_service().await;

    // Verify invalid token should fail
    let result = auth_service.verify_token("invalid.jwt.token");

    assert!(result.is_err(), "Invalid token verification should fail");
}

#[tokio::test]
#[ignore]
async fn test_logout_revokes_refresh_token() {
    let auth_service = setup_auth_service().await;
    let test_email = format!("test_logout_{}@example.com", Uuid::new_v4());
    let test_password = "SecurePassword123!";

    // Clean up
    cleanup_test_user(&auth_service.db_pool, &test_email).await;

    // Create user and login
    auth_service
        .create_user(&test_email, test_password, Some("Test User"), None, None)
        .await
        .expect("Signup should succeed");

    let (_access_token, refresh_token, _user) = auth_service
        .login(&test_email, test_password, None, None)
        .await
        .expect("Login should succeed");

    // Logout should succeed
    let logout_result = auth_service.revoke_refresh_token(&refresh_token).await;
    assert!(logout_result.is_ok(), "Logout should succeed");

    // Refresh token should no longer work
    let refresh_result = auth_service.refresh_access_token(&refresh_token).await;
    assert!(
        refresh_result.is_err(),
        "Refresh with revoked token should fail"
    );

    // Cleanup
    cleanup_test_user(&auth_service.db_pool, &test_email).await;
}

#[tokio::test]
#[ignore]
async fn test_password_change() {
    let auth_service = setup_auth_service().await;
    let test_email = format!("test_pwd_change_{}@example.com", Uuid::new_v4());
    let old_password = "OldPassword123!";
    let new_password = "NewPassword123!";

    // Clean up
    cleanup_test_user(&auth_service.db_pool, &test_email).await;

    // Create user
    let user_id = auth_service
        .create_user(&test_email, old_password, Some("Test User"), None, None)
        .await
        .expect("Signup should succeed");

    // Change password
    let result = auth_service
        .change_password(user_id, old_password, new_password)
        .await;

    assert!(result.is_ok(), "Password change should succeed");

    // Login with old password should fail
    let old_login = auth_service
        .login(&test_email, old_password, None, None)
        .await;
    assert!(old_login.is_err(), "Old password should not work");

    // Login with new password should succeed
    let new_login = auth_service
        .login(&test_email, new_password, None, None)
        .await;
    assert!(new_login.is_ok(), "New password should work");

    // Cleanup
    cleanup_test_user(&auth_service.db_pool, &test_email).await;
}

#[tokio::test]
#[ignore]
async fn test_password_change_with_wrong_old_password() {
    let auth_service = setup_auth_service().await;
    let test_email = format!("test_bad_old_pwd_{}@example.com", Uuid::new_v4());
    let password = "CorrectPassword123!";
    let wrong_old = "WrongOldPassword123!";
    let new_password = "NewPassword123!";

    // Clean up
    cleanup_test_user(&auth_service.db_pool, &test_email).await;

    // Create user
    let user_id = auth_service
        .create_user(&test_email, password, Some("Test User"), None, None)
        .await
        .expect("Signup should succeed");

    // Change password with wrong old password should fail
    let result = auth_service
        .change_password(user_id, wrong_old, new_password)
        .await;

    assert!(
        result.is_err(),
        "Password change with wrong old password should fail"
    );

    // Cleanup
    cleanup_test_user(&auth_service.db_pool, &test_email).await;
}

#[tokio::test]
#[ignore]
async fn test_cleanup_expired_sessions() {
    let auth_service = setup_auth_service().await;

    // Cleanup should not fail (even if no sessions to clean)
    let result = auth_service.cleanup_expired_sessions().await;

    assert!(result.is_ok(), "Cleanup should not fail");
}

#[tokio::test]
#[ignore]
async fn test_account_lockout_after_failed_attempts() {
    let auth_service = setup_auth_service().await;
    let test_email = format!("test_lockout_{}@example.com", Uuid::new_v4());
    let test_password = "SecurePassword123!";
    let wrong_password = "WrongPassword123!";

    // Clean up
    cleanup_test_user(&auth_service.db_pool, &test_email).await;

    // Create user
    auth_service
        .create_user(&test_email, test_password, Some("Test User"), None, None)
        .await
        .expect("Signup should succeed");

    // Attempt 5 failed logins to trigger lockout
    for _ in 0..5 {
        let _ = auth_service
            .login(&test_email, wrong_password, None, None)
            .await;
    }

    // Next login attempt should be locked out (even with correct password)
    let result = auth_service
        .login(&test_email, test_password, None, None)
        .await;

    assert!(result.is_err(), "Login should fail due to lockout");
    assert!(
        result.unwrap_err().to_string().contains("locked"),
        "Error should mention account locked"
    );

    // Cleanup
    cleanup_test_user(&auth_service.db_pool, &test_email).await;
}
