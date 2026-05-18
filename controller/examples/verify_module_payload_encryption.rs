//! Smoke test for module_executions payload encryption (Phase A).
//! Creates a module_execution row through the canonical service path,
//! confirms ciphertext is in the *_enc columns, and that
//! plaintext input/trigger columns are NULL when SecretsManager is wired.
//!
//! Run with:
//!   DATABASE_URL=postgres://talos:postgres@127.0.0.1:5433/talos \
//!     TALOS_MASTER_KEY=$(docker compose exec -T controller printenv TALOS_MASTER_KEY) \
//!     VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root \
//!     KEK_PROVIDER=vault \
//!     cargo run --example verify_module_payload_encryption -p controller

use std::sync::Arc;

use anyhow::{Context, Result};
use serde_json::json;
use sqlx::Row as _;
use uuid::Uuid;

use controller::dlp::DlpService;
use controller::module_executions::{ModuleExecutionService, TriggerType};
use controller::secrets::kek_provider::{env_kek_provider_from_environment, KekProvider};
use controller::secrets::vault_kek_provider::VaultTransitProvider;
use controller::secrets::SecretsManager;

#[tokio::main]
async fn main() -> Result<()> {
    let db_url = std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?;
    let pool = sqlx::PgPool::connect(&db_url).await?;

    let kind = std::env::var("KEK_PROVIDER")
        .unwrap_or_else(|_| "env".to_string())
        .to_lowercase();
    let (active, legacy): (Arc<dyn KekProvider>, Option<Arc<dyn KekProvider>>) = match kind.as_str()
    {
        "env" => (env_kek_provider_from_environment()?, None),
        "vault" => {
            let v = VaultTransitProvider::from_env()?;
            v.health_check().await?;
            (Arc::new(v), Some(env_kek_provider_from_environment()?))
        }
        other => anyhow::bail!("Unknown KEK_PROVIDER={other}"),
    };
    let secrets = Arc::new(SecretsManager::with_kek_providers(
        pool.clone(),
        active,
        legacy,
    )?);

    let dlp = Arc::new(DlpService::from_env());
    let service = ModuleExecutionService::new(pool.clone(), dlp).with_encryption(secrets.clone());

    // Pick any module + user that exist to satisfy FKs.
    let module_id: Uuid = sqlx::query("SELECT id FROM modules LIMIT 1")
        .fetch_one(&pool)
        .await?
        .get(0);
    let user_id: Uuid = sqlx::query("SELECT id FROM users LIMIT 1")
        .fetch_one(&pool)
        .await?
        .get(0);

    let exec_id = Uuid::new_v4();
    let secret_marker = "smoke_test_marker_should_be_encrypted_xyz123";
    let input = json!({
        "input_field": secret_marker,
        "nested": { "more": secret_marker },
    });
    let trigger = json!({ "source": "verify_module_payload_encryption", "marker": secret_marker });

    service
        .create_execution(
            module_id,
            user_id,
            exec_id,
            TriggerType::Manual,
            Some(trigger.clone()),
            Some(input.clone()),
            None,
        )
        .await?;
    println!("✓ create_execution wrote row {exec_id}");

    // Inspect raw columns.
    let row = sqlx::query(
        "SELECT input_data, trigger_metadata, input_data_enc, trigger_metadata_enc, payload_enc_key_id \
         FROM module_executions WHERE id = $1",
    )
    .bind(exec_id)
    .fetch_one(&pool)
    .await?;
    let pt_input: Option<serde_json::Value> = row.try_get("input_data").ok();
    let pt_trigger: Option<serde_json::Value> = row.try_get("trigger_metadata").ok();
    let enc_input: Option<Vec<u8>> = row.try_get("input_data_enc").ok();
    let enc_trigger: Option<Vec<u8>> = row.try_get("trigger_metadata_enc").ok();
    let key_id: Option<Uuid> = row.try_get("payload_enc_key_id").ok();

    assert!(pt_input.is_none(), "PLAINTEXT LEAK: input_data is non-NULL");
    assert!(
        pt_trigger.is_none(),
        "PLAINTEXT LEAK: trigger_metadata is non-NULL"
    );
    assert!(enc_input.is_some(), "input_data_enc was not populated");
    assert!(
        enc_trigger.is_some(),
        "trigger_metadata_enc was not populated"
    );
    assert!(key_id.is_some(), "payload_enc_key_id was not populated");
    println!("✓ plaintext columns NULL; *_enc columns populated; key_id set");

    let enc_input_bytes = enc_input.unwrap();
    let enc_trigger_bytes = enc_trigger.unwrap();
    assert!(
        !String::from_utf8_lossy(&enc_input_bytes).contains(secret_marker),
        "PLAINTEXT LEAK in input_data_enc"
    );
    assert!(
        !String::from_utf8_lossy(&enc_trigger_bytes).contains(secret_marker),
        "PLAINTEXT LEAK in trigger_metadata_enc"
    );
    println!(
        "✓ ciphertext does not contain plaintext marker (input {}b, trigger {}b)",
        enc_input_bytes.len(),
        enc_trigger_bytes.len()
    );

    // Decrypt round-trip via SecretsManager.
    let kid = key_id.unwrap();
    let in_str = secrets.decrypt_value_by_key(kid, &enc_input_bytes).await?;
    let in_round: serde_json::Value = serde_json::from_str(&in_str)?;
    assert_eq!(in_round, input, "input round-trip mismatch");
    let tr_str = secrets
        .decrypt_value_by_key(kid, &enc_trigger_bytes)
        .await?;
    let tr_round: serde_json::Value = serde_json::from_str(&tr_str)?;
    assert_eq!(tr_round, trigger, "trigger round-trip mismatch");
    println!("✓ round-trip decrypts back to original input + trigger");

    // Cleanup.
    sqlx::query("DELETE FROM module_executions WHERE id = $1")
        .bind(exec_id)
        .execute(&pool)
        .await?;
    println!("✓ cleanup");

    println!("\n🎉 module_executions payload encryption PASSED");
    Ok(())
}
