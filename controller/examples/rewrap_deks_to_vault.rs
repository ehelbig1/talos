//! Phase 3 operator tool: rewrap every DEK in `encryption_keys` from
//! the env-var KEK provider into the Vault transit KEK provider,
//! storing the new ciphertext in `encrypted_key_v2`.
//!
//! Idempotent — safe to re-run. Verify-before-commit per row protects
//! against the irreversibility cliff (see `kek_rewrap` module docs).
//!
//! Run with:
//!   docker compose up -d vault vault-init
//!   DATABASE_URL=postgres://talos:postgres@127.0.0.1:5433/talos \
//!     TALOS_MASTER_KEY=$(docker compose exec -T controller printenv TALOS_MASTER_KEY) \
//!     VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root \
//!     cargo run --example rewrap_deks_to_vault -p controller

use std::sync::Arc;

use anyhow::{Context, Result};
use controller::secrets::kek_provider::{env_kek_provider_from_environment, KekProvider};
use controller::secrets::kek_rewrap::{rewrap_all_deks_to_v2, DEFAULT_BATCH_SIZE};
use controller::secrets::vault_kek_provider::VaultTransitProvider;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let db_url = std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?;
    let pool = sqlx::PgPool::connect(&db_url)
        .await
        .context("failed to connect to DATABASE_URL")?;

    let source = env_kek_provider_from_environment()?;
    println!("source provider: {}", source.name());

    let target_concrete = VaultTransitProvider::from_env()?;
    target_concrete
        .health_check()
        .await
        .context("Vault provider health check failed — refuse to rewrap into a broken target")?;
    let target: Arc<dyn KekProvider> = Arc::new(target_concrete);
    println!("target provider: {}", target.name());

    // Pre-flight visibility: how many rows are in scope.
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM encryption_keys")
        .fetch_one(&pool)
        .await?;
    let pending: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM encryption_keys WHERE encrypted_key_v2 IS NULL")
            .fetch_one(&pool)
            .await?;
    println!("encryption_keys: {total} total, {pending} pending rewrap");

    if pending == 0 {
        println!("✓ nothing to do — every DEK already has encrypted_key_v2 populated");
        return Ok(());
    }

    let stats = rewrap_all_deks_to_v2(&pool, source, target, DEFAULT_BATCH_SIZE)
        .await
        .context("rewrap_all_deks_to_v2 failed")?;

    println!("\n=== rewrap complete ===");
    println!("scanned:    {}", stats.scanned);
    println!("already_v2: {}", stats.already_v2);
    println!("rewrapped:  {}", stats.rewrapped);

    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM encryption_keys WHERE encrypted_key_v2 IS NULL")
            .fetch_one(&pool)
            .await?;
    if remaining > 0 {
        println!(
            "⚠️  {} rows still have NULL encrypted_key_v2 — likely written during the rewrap; re-run to catch them",
            remaining
        );
    } else {
        println!("✓ every DEK now has encrypted_key_v2 populated");
    }

    Ok(())
}
