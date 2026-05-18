#[cfg(test)]
// `module_inception` — file-named-after-its-mod is conventional for
// our `*_tests.rs` companion files.
#[allow(clippy::module_inception)]
mod tests {
    use crate::config::{build_provider, ProviderConfig};
    use std::collections::HashMap;

    #[tokio::test]
    async fn build_provider_creates_talos_vault() {
        let mut secrets = HashMap::new();
        secrets.insert("test/key".to_string(), "test-value".to_string());

        let provider = build_provider(&ProviderConfig::TalosVault, secrets, false);

        let handle = provider
            .resolve("test/key", uuid::Uuid::new_v4())
            .await
            .unwrap();
        let value = provider.into_auth_header(handle, "Authorization").unwrap();
        // Authorization header gets "Bearer " prefix for raw values
        assert_eq!(value.as_str(), "Bearer test-value");
    }

    #[tokio::test]
    async fn build_provider_with_audit() {
        let mut secrets = HashMap::new();
        secrets.insert("test/key".to_string(), "test-value".to_string());

        let provider = build_provider(&ProviderConfig::TalosVault, secrets, true);

        let handle = provider
            .resolve("test/key", uuid::Uuid::new_v4())
            .await
            .unwrap();
        let value = provider.into_auth_header(handle, "Authorization").unwrap();
        // Authorization header gets "Bearer " prefix for raw values
        assert_eq!(value.as_str(), "Bearer test-value");
    }

    #[tokio::test]
    async fn provider_health_check_always_ok() {
        let provider = build_provider(&ProviderConfig::TalosVault, HashMap::new(), false);

        provider.health_check().await.unwrap();
    }

    #[test]
    fn provider_config_default_is_talos_vault() {
        let config: ProviderConfig = Default::default();
        match config {
            ProviderConfig::TalosVault => {}
        }
    }

    #[tokio::test]
    async fn provider_multiple_secrets() {
        let mut secrets = HashMap::new();
        secrets.insert("key1".to_string(), "value1".to_string());
        secrets.insert("key2".to_string(), "value2".to_string());

        let provider = build_provider(&ProviderConfig::TalosVault, secrets, false);

        let handle1 = provider
            .resolve("key1", uuid::Uuid::new_v4())
            .await
            .unwrap();
        let handle2 = provider
            .resolve("key2", uuid::Uuid::new_v4())
            .await
            .unwrap();

        let value1 = provider.into_auth_header(handle1, "Auth").unwrap();
        let value2 = provider.into_auth_header(handle2, "Auth").unwrap();

        assert_eq!(value1.as_str(), "value1");
        assert_eq!(value2.as_str(), "value2");
    }

    #[tokio::test]
    async fn provider_releases_all_handles() {
        let mut secrets = HashMap::new();
        secrets.insert("test/key".to_string(), "secret".to_string());

        let provider = build_provider(&ProviderConfig::TalosVault, secrets, false);

        let handle = provider
            .resolve("test/key", uuid::Uuid::new_v4())
            .await
            .unwrap();
        provider.release(handle).await.unwrap();

        assert!(provider.into_auth_header(handle, "Auth").is_err());
    }

    #[tokio::test]
    async fn provider_sign_produces_hmac() {
        let mut secrets = HashMap::new();
        secrets.insert("signing/key".to_string(), "my-hmac-key".to_string());

        let provider = build_provider(&ProviderConfig::TalosVault, secrets, false);

        let handle = provider
            .resolve("signing/key", uuid::Uuid::new_v4())
            .await
            .unwrap();
        let sig = provider.sign(handle, b"payload").unwrap();
        assert!(!sig.is_empty());
    }

    #[tokio::test]
    async fn provider_decrypt_not_supported() {
        let mut secrets = HashMap::new();
        secrets.insert("test/key".to_string(), "secret".to_string());

        let provider = build_provider(&ProviderConfig::TalosVault, secrets, false);

        let handle = provider
            .resolve("test/key", uuid::Uuid::new_v4())
            .await
            .unwrap();
        let result = provider.decrypt(handle, b"ciphertext");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not supported"));
    }

    #[tokio::test]
    async fn provider_unknown_path_returns_error() {
        let provider = build_provider(&ProviderConfig::TalosVault, HashMap::new(), false);

        let result = provider.resolve("unknown/path", uuid::Uuid::new_v4()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn provider_independent_handles_for_same_path() {
        let mut secrets = HashMap::new();
        secrets.insert("shared/key".to_string(), "shared-secret".to_string());

        let provider = build_provider(&ProviderConfig::TalosVault, secrets, false);

        // Resolving the same path twice should create independent handles
        let handle1 = provider
            .resolve("shared/key", uuid::Uuid::new_v4())
            .await
            .unwrap();
        let handle2 = provider
            .resolve("shared/key", uuid::Uuid::new_v4())
            .await
            .unwrap();

        // Handles should be different
        assert_ne!(handle1, handle2);

        // Both should resolve to the same value
        let value1 = provider.into_auth_header(handle1, "Auth").unwrap();
        let value2 = provider.into_auth_header(handle2, "Auth").unwrap();
        assert_eq!(value1, value2);
        assert_eq!(value1.as_str(), "shared-secret");

        // Releasing one should not affect the other
        provider.release(handle1).await.unwrap();
        assert!(provider.into_auth_header(handle1, "Auth").is_err());
        assert_eq!(
            provider.into_auth_header(handle2, "Auth").unwrap().as_str(),
            "shared-secret"
        );
    }
}
