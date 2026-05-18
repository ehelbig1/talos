use anyhow::Result;

pub trait SecretProvider: Send + Sync {
    /// Fetch a secret by its path/name
    fn get_secret(
        &self,
        key_path: &str,
    ) -> impl std::future::Future<Output = Result<String>> + Send;

    /// Optional: Store a secret (some enterprise providers might be read-only for Talos)
    fn set_secret(
        &self,
        key_path: &str,
        value: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}
