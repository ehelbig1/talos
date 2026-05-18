mod test_helpers;

use controller::secrets::{SecretRequestor, SecretsManager, SYSTEM_USER_ID};
use uuid::Uuid;

async fn setup_test_db() -> sqlx::Pool<sqlx::Postgres> {
    let pool = test_helpers::get_test_db_pool().await;

    // The secrets table's `created_by` column has a FK to users.id.
    // These tests pass `SYSTEM_USER_ID` as the creator, so the system
    // user has to exist first — production code paths use real user
    // IDs (created via signup), but the SYSTEM_USER constant is a
    // test-only convenience. ON CONFLICT keeps it idempotent so each
    // test can call setup_test_db() without coordination.
    sqlx::query(
        r#"
        INSERT INTO users (id, email, password_hash, is_active)
        VALUES ($1, 'system@talos.test', 'not-a-real-hash', true)
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(controller::secrets::SYSTEM_USER_ID)
    .execute(&pool)
    .await
    .expect("Failed to seed system user");

    // Clean up test data
    sqlx::query("DELETE FROM secret_audit_log")
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM secrets").execute(&pool).await.ok();

    pool
}

#[tokio::test]
async fn test_secret_encryption_roundtrip() {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );

    let pool = setup_test_db().await;
    let manager = SecretsManager::new(pool).unwrap();
    manager.initialize().await.unwrap();

    let original = "super-secret-api-key-12345";
    let secret_id = manager
        .create_secret(
            "Test Secret",
            "test/api-key",
            original,
            Some("Test description"),
            SYSTEM_USER_ID,
            vec![],
            None,
        )
        .await
        .unwrap();

    let retrieved = manager
        .get_secret("test/api-key", SecretRequestor::System, &[])
        .await
        .unwrap();

    assert_eq!(original, retrieved);

    // Verify audit log
    let audit = manager.get_audit_log(secret_id, 10, 0, None).await.unwrap();
    assert_eq!(audit.len(), 2); // create + read
    assert_eq!(audit[0].action, "read");
    assert_eq!(audit[1].action, "create");
}

#[tokio::test]
async fn test_unauthorized_module_access() {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );

    let pool = setup_test_db().await;
    let manager = SecretsManager::new(pool).unwrap();
    manager.initialize().await.unwrap();

    let module_a = Uuid::new_v4();
    let module_b = Uuid::new_v4();

    // Create secret allowed only for module A
    let secret_id = manager
        .create_secret(
            "Restricted Secret",
            "test/restricted",
            "secret-value",
            None,
            SYSTEM_USER_ID,
            vec![module_a],
            None,
        )
        .await
        .unwrap();

    // Module A should succeed
    let result_a = manager
        .get_secret("test/restricted", SecretRequestor::Module(module_a), &[])
        .await;
    assert!(result_a.is_ok());

    // Module B should fail
    let result_b = manager
        .get_secret("test/restricted", SecretRequestor::Module(module_b), &[])
        .await;
    assert!(result_b.is_err());
    assert!(result_b.unwrap_err().to_string().contains("not authorized"));

    // Check audit log shows both attempts
    let audit = manager.get_audit_log(secret_id, 10, 0, None).await.unwrap();
    let failed_attempt = audit.iter().find(|e| !e.success);
    assert!(failed_attempt.is_some());
    assert_eq!(failed_attempt.unwrap().action, "read");
}

#[tokio::test]
async fn test_secret_rotation() {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );

    let pool = setup_test_db().await;
    let manager = SecretsManager::new(pool).unwrap();
    manager.initialize().await.unwrap();

    let original = "original-value";
    manager
        .create_secret(
            "Rotatable Secret",
            "test/rotatable",
            original,
            None,
            SYSTEM_USER_ID,
            vec![],
            None,
        )
        .await
        .unwrap();

    let new_value = "rotated-value";
    manager
        .update_secret("test/rotatable", new_value, None, &[])
        .await
        .unwrap();

    let retrieved = manager
        .get_secret("test/rotatable", SecretRequestor::System, &[])
        .await
        .unwrap();

    assert_eq!(new_value, retrieved);
    assert_ne!(original, retrieved);
}

#[tokio::test]
async fn test_secret_extraction_and_resolution() {
    use controller::secrets::{extract_secret_references, resolve_secret_references};
    use serde_json::json;

    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );

    let pool = setup_test_db().await;
    let manager = SecretsManager::new(pool).unwrap();
    manager.initialize().await.unwrap();

    // Create test secrets
    manager
        .create_secret(
            "API Key",
            "openai/api-key",
            "sk-test-123",
            None,
            SYSTEM_USER_ID,
            vec![],
            None,
        )
        .await
        .unwrap();
    manager
        .create_secret(
            "Webhook Token",
            "slack/webhook/token",
            "xoxb-test-456",
            None,
            SYSTEM_USER_ID,
            vec![],
            None,
        )
        .await
        .unwrap();

    // Test extraction
    let config = json!({
        "API_KEY": "{{secret:openai/api-key}}",
        "WEBHOOK_TOKEN": "{{secret:slack/webhook/token}}",
        "REGULAR": "some_value",
        "NESTED": {
            "SECRET": "{{secret:nested/secret}}"
        }
    });

    let refs = extract_secret_references(&config);
    assert_eq!(refs.len(), 3);
    assert!(refs.contains(&"openai/api-key".to_string()));
    assert!(refs.contains(&"slack/webhook/token".to_string()));
    assert!(refs.contains(&"nested/secret".to_string()));

    // Test resolution
    let config_to_resolve = json!({
        "API_KEY": "{{secret:openai/api-key}}",
        "WEBHOOK_TOKEN": "{{secret:slack/webhook/token}}",
        "REGULAR": "some_value"
    });

    let resolved = resolve_secret_references(config_to_resolve, &manager, SecretRequestor::System)
        .await
        .unwrap();

    assert_eq!(resolved["API_KEY"], "sk-test-123");
    assert_eq!(resolved["WEBHOOK_TOKEN"], "xoxb-test-456");
    assert_eq!(resolved["REGULAR"], "some_value");
}
