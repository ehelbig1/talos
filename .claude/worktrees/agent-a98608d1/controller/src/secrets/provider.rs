use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait SecretProvider: Send + Sync {
    /// Fetch a secret by its path/name
    async fn get_secret(&self, key_path: &str) -> Result<String>;
    
    /// Optional: Store a secret (some enterprise providers might be read-only for Talos)
    async fn set_secret(&self, key_path: &str, value: &str) -> Result<()>;
}
