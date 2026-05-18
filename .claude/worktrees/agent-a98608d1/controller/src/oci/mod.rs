use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait ArtifactRegistryProvider: Send + Sync {
    /// Pull a WebAssembly module from the artifact registry
    async fn pull_wasm(&self, uri: &str) -> Result<Vec<u8>>;
    
    /// Push a WebAssembly module to the artifact registry
    async fn push_wasm(&self, name: &str, tag: &str, wasm_bytes: &[u8]) -> Result<String>;
}

// Future implementation details for generic OCI registries (GHCR, GAR, JFrog)
pub struct GenericOciProvider {
    pub endpoint: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[async_trait]
impl ArtifactRegistryProvider for GenericOciProvider {
    async fn pull_wasm(&self, _uri: &str) -> Result<Vec<u8>> {
        // Implementation would use oci-distribution to pull
        // This validates the abstraction layer for the controller
        Ok(vec![])
    }

    async fn push_wasm(&self, _name: &str, _tag: &str, _wasm_bytes: &[u8]) -> Result<String> {
        // Implementation would push the wasm bytes as a new layer
        Ok("oci://...".to_string())
    }
}
