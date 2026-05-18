#[cfg(test)]
// `module_inception` — file-named-after-its-mod is conventional for
// our `*_tests.rs` companion files.
#[allow(clippy::module_inception)]
mod tests {
    use crate::provider::{SecretProvider, SlotHandle};
    use crate::AuditingProvider;
    use crate::TalosVaultProvider;
    use std::collections::HashMap;

    // A simple mock provider for testing the AuditingProvider wrapper
    struct MockProvider {
        resolved: HashMap<String, String>,
    }

    #[async_trait::async_trait]
    impl SecretProvider for MockProvider {
        async fn resolve(
            &self,
            path: &str,
            _execution_id: uuid::Uuid,
        ) -> anyhow::Result<SlotHandle> {
            if self.resolved.contains_key(path) {
                Ok(SlotHandle(1))
            } else {
                Err(anyhow::anyhow!("not found"))
            }
        }

        fn into_auth_header(
            &self,
            _handle: SlotHandle,
            _header_name: &str,
        ) -> anyhow::Result<zeroize::Zeroizing<String>> {
            Ok(zeroize::Zeroizing::new("Bearer test-token".to_string()))
        }

        fn sign(&self, _handle: SlotHandle, _payload: &[u8]) -> anyhow::Result<Vec<u8>> {
            Ok(vec![1, 2, 3, 4])
        }

        fn decrypt(
            &self,
            _handle: SlotHandle,
            _ciphertext: &[u8],
        ) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
            Ok(zeroize::Zeroizing::new(vec![5, 6, 7, 8]))
        }

        async fn release(&self, _handle: SlotHandle) -> anyhow::Result<()> {
            Ok(())
        }

        async fn health_check(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn auditing_provider_passes_through_resolve() {
        let mut map = HashMap::new();
        map.insert("test/key".to_string(), "secret".to_string());

        let inner = MockProvider { resolved: map };
        let provider = AuditingProvider::new(inner);

        let handle = provider
            .resolve("test/key", uuid::Uuid::new_v4())
            .await
            .unwrap();
        assert_eq!(handle.0, 1);
    }

    #[tokio::test]
    async fn auditing_provider_passes_through_resolve_error() {
        let inner = MockProvider {
            resolved: HashMap::new(),
        };
        let provider = AuditingProvider::new(inner);

        let result = provider.resolve("unknown/key", uuid::Uuid::new_v4()).await;
        assert!(result.is_err());
    }

    #[test]
    fn auditing_provider_passes_through_auth_header() {
        let inner = MockProvider {
            resolved: HashMap::new(),
        };
        let provider = AuditingProvider::new(inner);

        let header = provider
            .into_auth_header(SlotHandle(1), "Authorization")
            .unwrap();
        assert_eq!(header.as_str(), "Bearer test-token");
    }

    #[test]
    fn auditing_provider_passes_through_sign() {
        let inner = MockProvider {
            resolved: HashMap::new(),
        };
        let provider = AuditingProvider::new(inner);

        let sig = provider.sign(SlotHandle(1), b"payload").unwrap();
        assert_eq!(sig, vec![1, 2, 3, 4]);
    }

    #[test]
    fn auditing_provider_passes_through_decrypt() {
        let inner = MockProvider {
            resolved: HashMap::new(),
        };
        let provider = AuditingProvider::new(inner);

        let plaintext = provider.decrypt(SlotHandle(1), b"ciphertext").unwrap();
        assert_eq!(plaintext.as_slice(), &[5u8, 6, 7, 8]);
    }

    #[tokio::test]
    async fn auditing_provider_passes_through_release() {
        let inner = MockProvider {
            resolved: HashMap::new(),
        };
        let provider = AuditingProvider::new(inner);

        // Should not panic
        provider.release(SlotHandle(1)).await.unwrap();
    }

    #[tokio::test]
    async fn auditing_provider_passes_through_health_check() {
        let inner = MockProvider {
            resolved: HashMap::new(),
        };
        let provider = AuditingProvider::new(inner);

        provider.health_check().await.unwrap();
    }

    #[tokio::test]
    async fn auditing_provider_with_talos_vault_integration() {
        // Integration test: wrap an actual TalosVaultProvider
        let mut map = HashMap::new();
        map.insert("vault/key".to_string(), "my-secret".to_string());

        let inner = TalosVaultProvider::from_resolved(map);
        let provider = AuditingProvider::new(inner);

        let handle = provider
            .resolve("vault/key", uuid::Uuid::new_v4())
            .await
            .unwrap();
        let value = provider.into_auth_header(handle, "X-Api-Key").unwrap();
        assert_eq!(value.as_str(), "my-secret");

        // Sign should work
        let sig = provider.sign(handle, b"data").unwrap();
        assert!(!sig.is_empty());

        // Release should work
        provider.release(handle).await.unwrap();
    }
}
