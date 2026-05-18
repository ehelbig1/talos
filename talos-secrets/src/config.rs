/// Selects which `SecretProvider` backend to instantiate.
/// Parsed from environment at startup. v1 has only `TalosVault`.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProviderConfig {
    /// Internal Talos vault backed by pre-fetched secrets (AES-256-GCM in v2)
    #[default]
    TalosVault,
    // Future: AwsKms { region: String, key_id: String },
    // Future: HashicorpVault { address: String, token_env: String },
}

/// Construct the appropriate provider from config.
///
/// The `secrets` map is consumed by `TalosVaultProvider::from_resolved()`.
/// When `audit` is `true`, the provider is wrapped in `AuditingProvider`
/// which logs every resolve / expose / release via `tracing`.
pub fn build_provider(
    config: &ProviderConfig,
    secrets: std::collections::HashMap<String, String>,
    audit: bool,
) -> Box<dyn crate::SecretProvider> {
    match config {
        ProviderConfig::TalosVault => {
            let inner = crate::TalosVaultProvider::from_resolved(secrets);
            if audit {
                Box::new(crate::AuditingProvider::new(inner))
            } else {
                Box::new(inner)
            }
        }
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
