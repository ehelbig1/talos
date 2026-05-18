//! Smoke test for the VaultTransitProvider — runs health_check + a
//! wrap/unwrap round-trip against the local docker-compose vault dev
//! service.
//!
//! Run with:
//!   docker compose up -d vault vault-init
//!   VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root \
//!     cargo run --example verify_vault_kek -p controller

use anyhow::Result;
use controller::secrets::kek_provider::KekProvider;
use controller::secrets::vault_kek_provider::VaultTransitProvider;

#[tokio::main]
async fn main() -> Result<()> {
    let provider = VaultTransitProvider::from_env()?;
    println!("✓ provider built: {}", provider.name());

    provider.health_check().await?;
    println!("✓ health_check passed (token authenticated, encrypt+decrypt round-trip OK)");

    // Independent round-trip with a known DEK so we can assert the
    // decrypted bytes match the input.
    let dek: [u8; 32] = [0x42; 32];
    let wrapped = provider.wrap_dek(&dek).await?;
    println!(
        "✓ wrap_dek returned {} bytes (vault:vN:<base64>)",
        wrapped.len()
    );
    assert!(
        wrapped.starts_with(b"vault:"),
        "wire format invariant: stored bytes must start with `vault:`"
    );

    let unwrapped = provider.unwrap_dek(&wrapped).await?;
    assert_eq!(unwrapped.as_slice(), &dek, "round-trip mismatch");
    println!("✓ unwrap_dek returned exact 32-byte DEK input");

    // Cross-provider isolation: a row written by EnvKekProvider would
    // NOT be valid Vault ciphertext. Verify Vault unwrap rejects
    // non-`vault:`-prefixed bytes loudly so we catch confused-provider
    // configs at request time, not silent corruption.
    let env_format = vec![0u8; 60]; // looks like an Env-wrapped DEK (12-byte nonce + ciphertext)
    let result = provider.unwrap_dek(&env_format).await;
    assert!(
        result.is_err(),
        "Vault unwrap should reject Env-format ciphertext"
    );
    println!("✓ unwrap rejects cross-provider (Env-format) ciphertext");

    println!("\n🎉 VaultTransitProvider end-to-end verification PASSED");
    Ok(())
}
