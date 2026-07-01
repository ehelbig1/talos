//! Encrypt-at-rest wiring for `integration_state.value`.
//!
//! Uses a reversible MOCK encryptor to test the `execute_op` wiring — encrypt on
//! write, decrypt on read, the ciphertext column layout, and that the per-slot
//! AAD is threaded — independent of the real AEAD (which is exercised by
//! talos-secrets-manager's own tests). Ciphertext = `[aad_len | aad | plaintext]`
//! so decrypt can assert the AAD it was handed matches the sealed one.

mod common;

use async_trait::async_trait;
use talos_integration_state::{execute_op, set_integration_state_crypto, IntegrationStateCrypto};
use talos_memory::integration_state_rpc::{IndexedSlots, IntegrationOp, IntegrationOpResult};
use uuid::Uuid;

struct MockCrypto;

#[async_trait]
impl IntegrationStateCrypto for MockCrypto {
    async fn encrypt(
        &self,
        value: &str,
        _user_id: Uuid,
        aad: &[u8],
    ) -> anyhow::Result<(Uuid, Vec<u8>, i16)> {
        let mut ct = (aad.len() as u32).to_le_bytes().to_vec();
        ct.extend_from_slice(aad);
        ct.extend_from_slice(value.as_bytes());
        Ok((Uuid::new_v4(), ct, 4))
    }

    async fn decrypt(
        &self,
        _key_id: Uuid,
        ciphertext: &[u8],
        aad: &[u8],
        _format: i16,
    ) -> anyhow::Result<String> {
        anyhow::ensure!(ciphertext.len() >= 4, "short ciphertext");
        let n = u32::from_le_bytes(ciphertext[0..4].try_into().unwrap()) as usize;
        anyhow::ensure!(ciphertext.len() >= 4 + n, "truncated ciphertext");
        anyhow::ensure!(
            &ciphertext[4..4 + n] == aad,
            "AAD mismatch — ciphertext bound to a different (integration, user, key) slot"
        );
        Ok(String::from_utf8(ciphertext[4 + n..].to_vec())?)
    }
}

#[tokio::test]
async fn integration_state_value_is_encrypted_at_rest_and_round_trips() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_integration_state_crypto(std::sync::Arc::new(MockCrypto));

    let user = Uuid::new_v4();
    let value = serde_json::json!({ "refresh_token": "super-secret", "n": 42 });

    // Set → encrypts at rest.
    let r = execute_op(
        &pool,
        "test-int",
        user,
        IntegrationOp::Set {
            key: "watch/1".into(),
            value: value.clone(),
            ttl_seconds: None,
            slots: IndexedSlots::default(),
        },
    )
    .await
    .expect("set");
    assert!(matches!(r, IntegrationOpResult::Ok));

    // The row holds ciphertext, not plaintext.
    let (plain, enc_present, fmt): (Option<serde_json::Value>, bool, Option<i16>) = sqlx::query_as(
        "SELECT value, value_enc IS NOT NULL, value_format FROM integration_state \
         WHERE integration_name = 'test-int' AND user_id = $1 AND key = 'watch/1'",
    )
    .bind(user)
    .fetch_one(&pool)
    .await
    .expect("row");
    assert!(
        plain.is_none(),
        "plaintext `value` must be NULL for an encrypted row"
    );
    assert!(enc_present, "value_enc must be populated");
    assert_eq!(fmt, Some(4), "the RETURNED format is persisted");

    // Get → decrypts back to the original (and the mock verifies the AAD matches).
    let got = execute_op(
        &pool,
        "test-int",
        user,
        IntegrationOp::Get {
            key: "watch/1".into(),
        },
    )
    .await
    .expect("get");
    let entry = match got {
        IntegrationOpResult::Entry { entry } => entry,
        _ => panic!("expected Entry"),
    };
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&entry.value).unwrap(),
        value
    );

    // Backward-compat: a legacy PLAINTEXT row (written before encryption existed)
    // still reads via the decrypt-or-plaintext fallback.
    let legacy_user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO integration_state (integration_name, user_id, key, value) \
         VALUES ('test-int', $1, 'legacy', $2::jsonb)",
    )
    .bind(legacy_user)
    .bind(serde_json::json!({ "cursor": 7 }).to_string())
    .execute(&pool)
    .await
    .expect("legacy insert");
    let legacy = execute_op(
        &pool,
        "test-int",
        legacy_user,
        IntegrationOp::Get {
            key: "legacy".into(),
        },
    )
    .await
    .expect("get legacy");
    let legacy_entry = match legacy {
        IntegrationOpResult::Entry { entry } => entry,
        _ => panic!("expected Entry"),
    };
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&legacy_entry.value).unwrap(),
        serde_json::json!({ "cursor": 7 })
    );
}
