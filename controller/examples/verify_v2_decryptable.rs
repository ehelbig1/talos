//! Phase 5 pre-flight: prove that every row in `encryption_keys` has a
//! `encrypted_key_v2` that actually decrypts with the configured KEK
//! provider (typically Vault). MUST be run successfully before applying
//! the Phase 5 terminal migration that drops the legacy column.
//!
//! The terminal migration is irreversible — once `encrypted_key`
//! (legacy) is dropped, any row that didn't have a valid v2 ciphertext
//! becomes unrecoverable. This tool catches the situation at "go/no-go"
//! time rather than at first-decrypt-after-migration.
//!
//! Run with:
//!   DATABASE_URL=postgres://talos:postgres@127.0.0.1:5433/talos \
//!     VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root \
//!     KEK_PROVIDER=vault \
//!     cargo run --example verify_v2_decryptable -p controller
//!
//! Exit code: 0 = all rows verified, safe to proceed.
//!            non-zero = at least one row failed; DO NOT MIGRATE.

use anyhow::{Context, Result};
use sqlx::Row as _;

use controller::secrets::kek_provider::{env_kek_provider_from_environment, KekProvider};
use controller::secrets::vault_kek_provider::VaultTransitProvider;

#[tokio::main]
async fn main() -> Result<()> {
    let db_url = std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?;
    let pool = sqlx::PgPool::connect(&db_url).await?;

    // Load the same provider main.rs would load.
    let kind = std::env::var("KEK_PROVIDER")
        .unwrap_or_else(|_| "env".to_string())
        .to_lowercase();
    let provider: std::sync::Arc<dyn KekProvider> = match kind.as_str() {
        "env" => env_kek_provider_from_environment()?,
        "vault" => {
            let v = VaultTransitProvider::from_env()?;
            v.health_check().await?;
            std::sync::Arc::new(v)
        }
        other => anyhow::bail!("Unknown KEK_PROVIDER={other}"),
    };
    println!("active provider: {}", provider.name());

    // Pre-checks first — fast SQL probes catch obvious problems before
    // we do expensive crypto.
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM encryption_keys")
        .fetch_one(&pool)
        .await?;
    let null_v2: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM encryption_keys WHERE encrypted_key_v2 IS NULL")
            .fetch_one(&pool)
            .await?;
    let empty_v2: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM encryption_keys WHERE encrypted_key_v2 IS NOT NULL AND octet_length(encrypted_key_v2) = 0",
    )
    .fetch_one(&pool)
    .await?;
    println!("encryption_keys: {total} total");
    println!("  rows with NULL  encrypted_key_v2: {null_v2}");
    println!("  rows with empty encrypted_key_v2: {empty_v2}");
    if null_v2 > 0 || empty_v2 > 0 {
        anyhow::bail!(
            "PRE-FLIGHT FAILED: {} NULL + {} empty encrypted_key_v2 rows. \
             Run `rewrap_deks_to_vault` to backfill before migrating.",
            null_v2,
            empty_v2
        );
    }

    // Real verification — unwrap every v2 ciphertext with the active
    // provider. Linear scan; bounded by the cardinality of encryption_keys
    // (typically 1-10 rows even on heavily-rotated installs).
    let rows = sqlx::query("SELECT id, encrypted_key_v2 FROM encryption_keys ORDER BY created_at")
        .fetch_all(&pool)
        .await?;
    let mut failed: Vec<String> = Vec::new();
    for row in &rows {
        let id: uuid::Uuid = row.get("id");
        let v2: Vec<u8> = row.get("encrypted_key_v2");
        match provider.unwrap_dek(&v2).await {
            Ok(plaintext) if plaintext.len() == 32 => {
                println!("  ✓ DEK {id} decrypts to 32 bytes");
            }
            Ok(plaintext) => {
                let msg = format!(
                    "DEK {id}: decrypted to {} bytes (expected 32)",
                    plaintext.len()
                );
                println!("  ✗ {msg}");
                failed.push(msg);
            }
            Err(e) => {
                let msg = format!("DEK {id}: unwrap failed: {e:#}");
                println!("  ✗ {msg}");
                failed.push(msg);
            }
        }
    }

    if !failed.is_empty() {
        anyhow::bail!(
            "PRE-FLIGHT FAILED: {} of {} rows could not be decrypted with active provider. \
             DO NOT MIGRATE. Investigate each failure before running Phase 5.",
            failed.len(),
            rows.len()
        );
    }

    println!(
        "\n🎉 PRE-FLIGHT PASSED — all {} DEKs verified decryptable with {}. \
         Safe to apply Phase 5 migration.",
        rows.len(),
        provider.name()
    );
    Ok(())
}
