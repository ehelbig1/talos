//! Backfill any `workflow_executions.output_data` rows that still have
//! plaintext output to the encrypted form. Idempotent; safe to re-run.
//!
//! Run with:
//!   DATABASE_URL=postgres://talos:postgres@127.0.0.1:5433/talos \
//!     TALOS_MASTER_KEY=$(docker compose exec -T controller printenv TALOS_MASTER_KEY) \
//!     VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root \
//!     KEK_PROVIDER=vault \
//!     cargo run --example backfill_workflow_output_encryption -p controller

use std::sync::Arc;

use anyhow::{Context, Result};
use sqlx::Row as _;
use uuid::Uuid;

use controller::secrets::kek_provider::{env_kek_provider_from_environment, KekProvider};
use controller::secrets::vault_kek_provider::VaultTransitProvider;
use controller::secrets::SecretsManager;

#[tokio::main]
async fn main() -> Result<()> {
    let db_url = std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?;
    let pool = sqlx::PgPool::connect(&db_url).await?;

    // Mirror main.rs's KEK provider selection so the backfill writes
    // ciphertext that the live controller can read.
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

    // Pre-flight count.
    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM workflow_executions WHERE output_data IS NOT NULL AND output_data_enc IS NULL",
    )
    .fetch_one(&pool)
    .await?;
    println!("workflow_executions: {pending} rows to encrypt");
    if pending == 0 {
        println!("✓ nothing to do");
        return Ok(());
    }

    let mut total: u64 = 0;
    let mut last_id: Option<Uuid> = None;
    let batch_size: i64 = 100;

    loop {
        let rows = sqlx::query(
            "SELECT id, output_data FROM workflow_executions \
             WHERE output_data IS NOT NULL AND output_data_enc IS NULL \
               AND ($1::uuid IS NULL OR id > $1) \
             ORDER BY id LIMIT $2",
        )
        .bind(last_id)
        .bind(batch_size)
        .fetch_all(&pool)
        .await?;
        if rows.is_empty() {
            break;
        }

        let mut tx = pool.begin().await?;
        let mut batch_count: u64 = 0;
        for row in &rows {
            let id: Uuid = row.try_get("id")?;
            let value: serde_json::Value = row.try_get("output_data")?;
            let plaintext = serde_json::to_string(&value)?;
            let (key_id, ciphertext) = secrets.encrypt_value(&plaintext).await?;
            sqlx::query(
                "UPDATE workflow_executions \
                 SET output_data = NULL, output_data_enc = $1, output_enc_key_id = $2 \
                 WHERE id = $3 AND output_data_enc IS NULL",
            )
            .bind(&ciphertext)
            .bind(key_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
            batch_count += 1;
            last_id = Some(id);
        }
        tx.commit().await?;
        total += batch_count;
        println!("  encrypted batch of {batch_count} (total {total})");

        if rows.len() < batch_size as usize {
            break;
        }
    }

    println!("\n🎉 backfill complete: {total} rows now encrypted");
    Ok(())
}
