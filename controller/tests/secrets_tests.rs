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

// ── Per-tenant (per-org) root DEKs — Phase 1 foundation ────────────────────
// These exercise the controller-side per-org DEK machinery end-to-end against
// a real DB. Env-gated like the rest of this suite (run in quality.yml).

fn set_master_key_for_dek_tests() {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
}

async fn create_test_org(pool: &sqlx::Pool<sqlx::Postgres>) -> Uuid {
    // owner_id is NOT NULL (FK -> users); reuse the test system user.
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, 'system@talos.test', 'not-a-real-hash', true) ON CONFLICT (id) DO NOTHING",
    )
    .bind(SYSTEM_USER_ID)
    .execute(pool)
    .await
    .expect("seed system user");

    let tag = Uuid::new_v4();
    sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(format!("dek-test-{tag}"))
    .bind(format!("dek-test-{tag}"))
    .bind(SYSTEM_USER_ID)
    .fetch_one(pool)
    .await
    .expect("create org")
}

#[tokio::test]
async fn per_org_dek_lifecycle_and_isolation() {
    set_master_key_for_dek_tests();
    let pool = test_helpers::get_test_db_pool().await;
    let manager = SecretsManager::new(pool.clone()).unwrap();
    manager.initialize().await.unwrap();

    let org_a = create_test_org(&pool).await;
    let org_b = create_test_org(&pool).await;

    // Lazy provisioning is idempotent: same org -> same active DEK id.
    let dek_a1 = manager.get_or_create_dek_for_org(org_a).await.unwrap();
    let dek_a2 = manager.get_or_create_dek_for_org(org_a).await.unwrap();
    assert_eq!(
        dek_a1.id, dek_a2.id,
        "second get_or_create must reuse org A's active DEK"
    );

    // Distinct org -> distinct root DEK.
    let dek_b = manager.get_or_create_dek_for_org(org_b).await.unwrap();
    assert_ne!(dek_a1.id, dek_b.id, "each org must get its own root DEK");

    // The GLOBAL path is unaffected: get_active_dek returns the org_id-IS-NULL
    // key, never an org DEK (the coexistence-scoping fix).
    let global = manager.get_active_dek().await.unwrap();
    assert_ne!(
        global.id, dek_a1.id,
        "global active DEK must not be an org DEK"
    );
    assert_ne!(
        global.id, dek_b.id,
        "global active DEK must not be an org DEK"
    );

    // v4 round-trip: encrypt under org A, decrypt via the versioned dispatch.
    let ctx = Uuid::new_v4();
    let (kid, ct, ver) = manager
        .encrypt_value_aad_v4_org("org-A-topsecret", org_a, ctx.as_bytes())
        .await
        .unwrap();
    assert_eq!(ver, 4, "v4 writer must stamp format 4");
    assert_eq!(
        kid, dek_a1.id,
        "v4 ciphertext must reference org A's DEK id"
    );
    let dec = manager
        .decrypt_versioned(kid, &ct, ctx.as_bytes(), ver)
        .await
        .unwrap();
    assert_eq!(dec.as_str(), "org-A-topsecret");

    // Wrong AAD context fails closed (no oracle).
    let wrong_ctx = Uuid::new_v4();
    assert!(
        manager
            .decrypt_versioned(kid, &ct, wrong_ctx.as_bytes(), ver)
            .await
            .is_err(),
        "v4 decrypt must fail under a different AAD context"
    );
}

#[tokio::test]
async fn per_org_dek_rotation_preserves_old_ciphertext_and_global() {
    set_master_key_for_dek_tests();
    let pool = test_helpers::get_test_db_pool().await;
    let manager = SecretsManager::new(pool.clone()).unwrap();
    manager.initialize().await.unwrap();

    let org = create_test_org(&pool).await;
    let dek1 = manager.get_or_create_dek_for_org(org).await.unwrap();
    let global_before = manager.get_active_dek().await.unwrap();

    // Encrypt a v4 row under the first org DEK.
    let ctx = Uuid::new_v4();
    let (kid1, ct, ver) = manager
        .encrypt_value_aad_v4_org("before-rotation", org, ctx.as_bytes())
        .await
        .unwrap();
    assert_eq!(kid1, dek1.id);

    // Rotate the org's DEK: active flips to a new key.
    let new_id = manager.rotate_dek_for_org(org, None).await.unwrap();
    assert_ne!(new_id, dek1.id, "rotation must mint a new active DEK");
    let active_after = manager.get_active_dek_for_org(org).await.unwrap().unwrap();
    assert_eq!(
        active_after.id, new_id,
        "org's active DEK must be the rotated one"
    );

    // The pre-rotation ciphertext still decrypts — it pins the old DEK by
    // key_id (re-encryption to the new key is the later-phase sweep's job).
    let dec = manager
        .decrypt_versioned(kid1, &ct, ctx.as_bytes(), ver)
        .await
        .unwrap();
    assert_eq!(dec.as_str(), "before-rotation");

    // The GLOBAL DEK is untouched by a per-org rotation.
    let global_after = manager.get_active_dek().await.unwrap();
    assert_eq!(
        global_before.id, global_after.id,
        "per-org rotation must not touch the global DEK"
    );
}

// ── v4_for_user (personal-org resolution) — used by totp/audit/webhook cutovers ─

async fn create_user_with_personal_org(pool: &sqlx::Pool<sqlx::Postgres>) -> (Uuid, Uuid) {
    let uid = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(uid)
    .bind(format!("v4user-{uid}@talos.test"))
    .execute(pool)
    .await
    .expect("create user");
    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("personal-{tag}"))
    .bind(format!("personal-{tag}"))
    .bind(uid)
    .fetch_one(pool)
    .await
    .expect("create personal org");
    (uid, org)
}

#[tokio::test]
async fn v4_for_user_encrypts_under_personal_org_dek_and_round_trips() {
    set_master_key_for_dek_tests();
    let pool = test_helpers::get_test_db_pool().await;
    let manager = SecretsManager::new(pool.clone()).unwrap();
    manager.initialize().await.unwrap();

    let (uid, personal_org) = create_user_with_personal_org(&pool).await;

    // TOTP-style call: AAD bound to user_id (as encrypt_totp_secret does).
    let (kid, ct, ver) = manager
        .encrypt_value_aad_v4_for_user("totp-seed-abc", uid, uid.as_bytes())
        .await
        .unwrap();
    assert_eq!(ver, 4, "v4_for_user must stamp format 4");

    // It must encrypt under the USER'S PERSONAL ORG's root DEK.
    let org_dek = manager
        .get_active_dek_for_org(personal_org)
        .await
        .unwrap()
        .expect("personal org DEK was lazily provisioned");
    assert_eq!(kid, org_dek.id, "must use the personal-org DEK id");

    let dec = manager
        .decrypt_versioned(kid, &ct, uid.as_bytes(), ver)
        .await
        .unwrap();
    assert_eq!(dec.as_str(), "totp-seed-abc");
}

#[tokio::test]
async fn v4_for_user_fails_closed_without_personal_org() {
    set_master_key_for_dek_tests();
    let pool = test_helpers::get_test_db_pool().await;
    let manager = SecretsManager::new(pool.clone()).unwrap();
    manager.initialize().await.unwrap();

    // A user with NO personal org is an invariant violation — fail closed,
    // never silently fall back to the global DEK.
    let uid = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(uid)
    .bind(format!("noorg-{uid}@talos.test"))
    .execute(&pool)
    .await
    .expect("create user");

    assert!(
        manager
            .encrypt_value_aad_v4_for_user("x", uid, uid.as_bytes())
            .await
            .is_err(),
        "must fail closed when the user has no personal org"
    );
}
