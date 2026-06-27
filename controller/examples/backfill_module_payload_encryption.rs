//! Backfill plaintext rows in `module_executions` to the encrypted form.
//! Idempotent — only touches rows where `payload_enc_key_id IS NULL`
//! and at least one of `input_data` / `output_data` / `trigger_metadata`
//! is non-NULL. Safe to re-run.
//!
//! Run with:
//!   DATABASE_URL=postgres://talos:postgres@127.0.0.1:5433/talos \
//!     TALOS_MASTER_KEY=$(docker compose exec -T controller printenv TALOS_MASTER_KEY) \
//!     VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root \
//!     KEK_PROVIDER=vault \
//!     cargo run --example backfill_module_payload_encryption -p controller

use std::sync::Arc;

use anyhow::{Context, Result};
use sqlx::Row as _;
use uuid::Uuid;

use controller::module_payload_encryption::encrypt_payload_bundle;
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

    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM module_executions \
         WHERE payload_enc_key_id IS NULL \
           AND (input_data IS NOT NULL OR output_data IS NOT NULL OR trigger_metadata IS NOT NULL)",
    )
    .fetch_one(&pool)
    .await?;
    println!("module_executions pending encryption: {pending}");
    if pending == 0 {
        println!("✓ nothing to do");
        return Ok(());
    }

    let mut total: u64 = 0;
    let mut last_id: Option<Uuid> = None;
    let batch: i64 = 100;

    loop {
        let rows = sqlx::query(
            "SELECT id, input_data, output_data, trigger_metadata FROM module_executions \
             WHERE payload_enc_key_id IS NULL \
               AND (input_data IS NOT NULL OR output_data IS NOT NULL OR trigger_metadata IS NOT NULL) \
               AND ($1::uuid IS NULL OR id > $1) \
             ORDER BY id LIMIT $2",
        )
        .bind(last_id)
        .bind(batch)
        .fetch_all(&pool)
        .await?;
        if rows.is_empty() {
            break;
        }

        let mut tx = pool.begin().await?;
        let mut batch_count: u64 = 0;
        for row in &rows {
            let id: Uuid = row.try_get("id")?;
            let input: Option<serde_json::Value> = row.try_get("input_data").ok();
            let output: Option<serde_json::Value> = row.try_get("output_data").ok();
            let trigger: Option<serde_json::Value> = row.try_get("trigger_metadata").ok();
            // MCP-S2: backfill writes v1 with AAD = id, matching the
            // production write path. Resulting rows are decrypt-safe
            // under the AAD-bound read dispatcher.
            let bundle = encrypt_payload_bundle(
                Some(&secrets),
                id,
                // Backfill of existing rows — pass None so the org is resolved
                // from the existing module_executions row (workflow's org → v4,
                // or global v3 for standalone rows).
                None,
                input.as_ref(),
                output.as_ref(),
                trigger.as_ref(),
            )
            .await?;
            // Conditional UPDATE: only set on rows still NULL — defends
            // against a concurrent canonical writer.
            sqlx::query(
                "UPDATE module_executions \
                 SET input_data = NULL, output_data = NULL, trigger_metadata = NULL, \
                     input_data_enc = $1, output_data_enc = $2, trigger_metadata_enc = $3, \
                     payload_enc_key_id = $4, payload_format = $5 \
                 WHERE id = $6 AND payload_enc_key_id IS NULL",
            )
            .bind(bundle.input_enc.as_deref())
            .bind(bundle.output_enc.as_deref())
            .bind(bundle.trigger_enc.as_deref())
            .bind(bundle.key_id)
            .bind(bundle.format_version)
            .bind(id)
            .execute(&mut *tx)
            .await?;
            batch_count += 1;
            last_id = Some(id);
        }
        tx.commit().await?;
        total += batch_count;
        println!("  encrypted batch of {batch_count} (total {total})");

        if rows.len() < batch as usize {
            break;
        }
    }

    println!("\n🎉 backfill complete: {total} rows now encrypted");
    Ok(())
}
