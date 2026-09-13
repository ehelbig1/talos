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

    /// The decorator's `secret.resolve` / `secret.resolve.failed` lines fire on
    /// every secret a module resolves, and an OAuth path carries the account's
    /// provider key — for gmail, the user's email — in its fourth segment.
    /// Drive the REAL decorator under a capturing subscriber and read the
    /// bytes it wrote: the message and the correlation token must be there,
    /// the address must not. (Check 91 is the textual gate; this is the half
    /// that proves the rendered field, not the named function.)
    #[tokio::test]
    async fn resolve_log_lines_carry_the_hashed_provider_key_not_the_email() {
        use std::sync::{Arc, Mutex};
        #[derive(Clone, Default)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
            type Writer = Capture;
            fn make_writer(&'a self) -> Capture {
                self.clone()
            }
        }
        let buf = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let uid = "11111111-2222-3333-4444-555555555555";
        let ok_path = format!("oauth/gmail/{uid}/alice@example.com/access_token");
        let mut map = HashMap::new();
        map.insert(ok_path.clone(), "secret".to_string());
        let provider = AuditingProvider::new(MockProvider { resolved: map });

        provider
            .resolve(&ok_path, uuid::Uuid::new_v4())
            .await
            .unwrap();
        let missing = format!("oauth/gmail/{uid}/bob@example.com/refresh_token");
        assert!(provider
            .resolve(&missing, uuid::Uuid::new_v4())
            .await
            .is_err());

        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(out.contains("secret.resolve"), "{out}");
        assert!(out.contains("secret.resolve.failed"), "{out}");
        assert!(out.contains("key_path="), "field is `key_path`: {out}");
        assert!(!out.contains("alice"), "email leaked into the log: {out}");
        assert!(
            !out.contains("bob"),
            "email leaked into the failure log: {out}"
        );
        assert!(!out.contains('@'), "an address survived redaction: {out}");
        let token =
            talos_workflow_job_protocol::redact_oauth_provider_key_for_log("alice@example.com");
        assert!(
            out.contains(&token),
            "correlation token {token} absent: {out}"
        );
        assert!(
            out.contains(&format!("oauth/gmail/{uid}/")),
            "provider + user id stay visible: {out}"
        );
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
