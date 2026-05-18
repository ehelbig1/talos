//! Smoke test for actor_memory at-rest encryption Phase B.
//! Runs a write -> read round-trip against the live controller DB and
//! verifies that the value column is gone, ciphertext is stored in
//! value_enc, and recall_exact decrypts correctly.
//!
//! Run with:
//!   DATABASE_URL=postgres://talos:postgres@127.0.0.1:5433/talos \
//!   MASTER_ENCRYPTION_KEY=$(docker compose exec -T controller printenv MASTER_ENCRYPTION_KEY) \
//!     cargo run --example verify_phase_b -p controller

use anyhow::Result;
use sqlx::Row as _;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    let db_url = std::env::var("DATABASE_URL")?;
    let pool = sqlx::PgPool::connect(&db_url).await?;

    // 1. Confirm `value` column is gone.
    let cols: Vec<(String,)> = sqlx::query_as(
        "SELECT column_name FROM information_schema.columns WHERE table_name='actor_memory' AND column_name='value'"
    ).fetch_all(&pool).await?;
    assert!(
        cols.is_empty(),
        "Phase B failure: actor_memory.value still exists"
    );
    println!("✓ actor_memory.value column is dropped");

    // 2. Confirm value_enc + value_key_id are NOT NULL.
    let null_check: (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE value_enc IS NULL), COUNT(*) FILTER (WHERE value_key_id IS NULL) FROM actor_memory"
    ).fetch_one(&pool).await?;
    assert_eq!(
        null_check,
        (0, 0),
        "found rows with NULL value_enc or value_key_id"
    );
    println!("✓ all rows have non-null value_enc + value_key_id");

    // 3. Wire SecretsManager + crypto hook (same wiring as main.rs).
    // Respect KEK_PROVIDER so the verifier exercises whichever backend
    // the live controller is using.
    use controller::secrets::kek_provider::{env_kek_provider_from_environment, KekProvider};
    use controller::secrets::vault_kek_provider::VaultTransitProvider;
    use controller::secrets::SecretsManager;
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
        other => return Err(anyhow::anyhow!("Unknown KEK_PROVIDER={other}")),
    };
    let secrets = Arc::new(SecretsManager::with_kek_providers(
        pool.clone(),
        active,
        legacy,
    )?);
    talos_memory::register_memory_crypto_hook(Arc::new(
        controller::memory_crypto::SecretsManagerMemoryCrypto::new(secrets.clone()),
    ));

    // 4. Pick any actor; write+read+verify round-trip.
    let actor_id: Uuid = sqlx::query("SELECT id FROM actors LIMIT 1")
        .fetch_one(&pool)
        .await?
        .get(0);

    let key = format!(
        "phase_b_smoke_test_{}",
        chrono::Utc::now().timestamp_millis()
    );
    let original = serde_json::json!({
        "test": "phase_b_round_trip",
        "secret_marker": "hunter2_should_be_encrypted_at_rest",
        "ts": chrono::Utc::now().to_rfc3339(),
    });

    talos_memory::persist_memory(&pool, actor_id, &key, &original, "working", Some(1.0)).await?;
    println!("✓ persist_memory write succeeded");

    // Confirm row stored ciphertext, not plaintext.
    let stored = sqlx::query(
        "SELECT value_enc, value_key_id FROM actor_memory WHERE actor_id=$1 AND key=$2",
    )
    .bind(actor_id)
    .bind(&key)
    .fetch_one(&pool)
    .await?;
    let enc_bytes: Vec<u8> = stored.get("value_enc");
    assert!(!enc_bytes.is_empty(), "value_enc was empty");
    assert!(
        !String::from_utf8_lossy(&enc_bytes).contains("hunter2"),
        "PLAINTEXT LEAK: value_enc contains the marker bytes!"
    );
    println!(
        "✓ stored ciphertext does not contain plaintext marker ({} bytes)",
        enc_bytes.len()
    );

    // Read back via canonical recall path; expect decrypted plaintext.
    let recalled = talos_memory::recall_exact(&pool, actor_id, &key)
        .await?
        .expect("recall_exact returned None for the row we just wrote");
    assert_eq!(recalled.value, original, "round-trip value mismatch");
    println!("✓ recall_exact decrypted to original plaintext");

    // Cleanup.
    talos_memory::forget_exact(&pool, actor_id, &key).await?;
    println!("✓ forget_exact cleanup succeeded");

    println!("\n🎉 Phase B end-to-end verification PASSED");
    Ok(())
}
