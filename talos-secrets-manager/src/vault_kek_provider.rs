//! `VaultTransitProvider` — KEK provider backed by HashiCorp Vault's
//! transit secrets engine.
//!
//! Vault transit is "encryption as a service": the master key never
//! leaves Vault. The controller calls `POST /v1/transit/encrypt/<key>`
//! with the plaintext DEK and receives back an opaque
//! `vault:v1:<base64>` ciphertext string; `POST /v1/transit/decrypt/<key>`
//! reverses it. This means a Postgres dump no longer reveals enough to
//! recover any DEK — the attacker would also need the Vault token AND
//! Vault to be unsealed.
//!
//! Wire format stored in `encryption_keys.encrypted_key`: the raw UTF-8
//! bytes of the `vault:v1:<base64>` string. Round-trips opaquely
//! through the `KekProvider` trait — `SecretsManager` never inspects.
//!
//! Boot-time policy: callers (typically `main.rs`) MUST run
//! [`VaultTransitProvider::health_check`] before publishing the provider
//! to `SecretsManager`. The check verifies (a) Vault reachable, (b)
//! token authenticated, (c) token can encrypt+decrypt with the named
//! transit key. Skipping the check means the controller starts but
//! every subsequent secret op fails — fail closed at startup, not at
//! request time.

use std::pin::Pin;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::kek_provider::KekProvider;

/// Default request timeout for Vault HTTP calls. Encrypt/decrypt are
/// sub-millisecond on Vault's side so 5s is generous for any plausible
/// network hop. Tighter than the typical reqwest default (no timeout)
/// so a wedged Vault doesn't stall every secret op.
const DEFAULT_TIMEOUT_SECS: u64 = 5;

/// Default transit key name. Override via `VAULT_TRANSIT_KEY_NAME`.
pub const DEFAULT_TRANSIT_KEY_NAME: &str = "talos-kek";

/// Vault transit KEK provider.
pub struct VaultTransitProvider {
    /// `https://vault.example.com` (no trailing slash). Mounted endpoint
    /// is constructed as `{addr}/v1/{mount}/{op}/{key_name}`.
    addr: String,
    /// Vault token used for `X-Vault-Token`. Wrapped in `Zeroizing` so
    /// the token bytes are wiped from memory on drop. Never logged.
    token: Zeroizing<String>,
    /// Mount path of the transit engine — typically `transit`. Override
    /// only if the engine is mounted at a non-default path.
    mount: String,
    /// Name of the transit key used for KEK ops.
    key_name: String,
    /// Pre-built reqwest client — connection pool reuse across calls.
    client: reqwest::Client,
    /// Display name (returned by `KekProvider::name`). Constructed once
    /// at build time so we don't allocate on every health-check log line.
    display_name: String,
}

#[derive(Serialize)]
struct EncryptRequest<'a> {
    plaintext: &'a str,
}

#[derive(Serialize)]
struct DecryptRequest<'a> {
    ciphertext: &'a str,
}

#[derive(Deserialize)]
struct VaultResponse<T> {
    data: T,
    /// Errors come back as a top-level `errors` array on non-2xx
    /// responses; we surface the HTTP status separately so this only
    /// fires when the body is unexpectedly malformed.
    #[serde(default)]
    errors: Vec<String>,
}

#[derive(Deserialize)]
struct EncryptData {
    ciphertext: String,
}

#[derive(Deserialize)]
struct DecryptData {
    plaintext: String,
}

#[derive(Deserialize)]
struct TokenLookupSelfData {
    /// Capabilities granted to this token on the policies it carries.
    /// We don't introspect these directly — instead the health check
    /// performs a real encrypt+decrypt round-trip against the named
    /// key, which is the source of truth for "can this token actually
    /// do what we need."
    #[serde(default, rename = "id")]
    _id: String,
}

impl VaultTransitProvider {
    /// Build from explicit parameters. Use `from_env` for the standard
    /// env-var driven construction.
    pub fn new(
        addr: impl Into<String>,
        token: impl Into<String>,
        mount: impl Into<String>,
        key_name: impl Into<String>,
    ) -> Result<Self> {
        let addr = addr.into();
        let mount = mount.into();
        let key_name = key_name.into();
        let display_name = format!("vault://{addr}/v1/{mount}/keys/{key_name}");
        // MCP-572: disable redirect following. Every request from this
        // client carries `X-Vault-Token` (the Vault transit-engine token
        // — effectively the master key for envelope encryption at rest).
        // reqwest's default redirect policy follows up to 10 hops; on
        // cross-origin redirects it strips KNOWN sensitive headers
        // (Authorization, Cookie, Proxy-Authorization) but custom
        // headers like `X-Vault-Token` are NOT in that strip list —
        // reqwest has no way to know our custom header is a credential.
        //
        // A compromised VAULT_ADDR (operator misconfiguration, MITM
        // upstream of the Vault pod, or a malicious sidecar) returning
        // a 302 to attacker.com would leak the token to the redirect
        // target. Same Mode-B credential-leak class as MCP-533/571.
        // Fail-closed at the policy layer.
        // MCP-1034: explicit connect_timeout (5s) so a black-holed
        // VAULT_ADDR (network partition, misconfigured DNS, slow-loris
        // on TCP-handshake) fails fast instead of holding the connection
        // pool until DEFAULT_TIMEOUT_SECS fires. Sibling discipline to
        // the canonical talos-atlassian / talos-gmail / talos-slack
        // shape applied workspace-wide in this sweep.
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none());
        // In-cluster TLS trust anchor. When `VAULT_ADDR` is `https://` against a
        // self-signed in-cluster Vault (the Helm chart's bundled Vault), the
        // server cert won't chain to a public root, so the operator points
        // `VAULT_CACERT` at the mounted cert (the chart projects
        // `<release>-vault-tls`'s `tls.crt` into the controller pod). We ADD it
        // to the default roots (not replace) so an externally-managed Vault on a
        // public CA still verifies. If `VAULT_CACERT` is set but unreadable /
        // not PEM we FAIL CLOSED — silently falling back to system trust would
        // just produce a confusing verification error at the first transit call
        // (the master-KEK path), and a misconfigured trust anchor on the
        // secrets layer must surface loudly at construction, not at request
        // time. Unset → unchanged behavior (system trust).
        if let Ok(ca_path) = std::env::var("VAULT_CACERT") {
            let ca_path = ca_path.trim();
            if !ca_path.is_empty() {
                let pem = std::fs::read(ca_path).with_context(|| {
                    format!("VAULT_CACERT is set ({ca_path}) but the file could not be read")
                })?;
                let cert = reqwest::Certificate::from_pem(&pem).with_context(|| {
                    format!("VAULT_CACERT file ({ca_path}) is not a valid PEM certificate")
                })?;
                builder = builder.add_root_certificate(cert);
            }
        }
        let client = builder
            .build()
            .context("failed to build Vault HTTP client")?;
        Ok(Self {
            addr: addr.trim_end_matches('/').to_string(),
            token: Zeroizing::new(token.into()),
            mount,
            key_name,
            client,
            display_name,
        })
    }

    /// Build from `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_TRANSIT_MOUNT`
    /// (default `transit`), `VAULT_TRANSIT_KEY_NAME` (default `talos-kek`).
    /// Returns Err if `VAULT_ADDR` or `VAULT_TOKEN` is missing — those
    /// are mandatory; the mount and key name have safe defaults.
    ///
    /// SECURITY: `VAULT_TOKEN=dev-root` is the dev/seeding default
    /// shipped with the Helm chart's bundled Vault; the chart's
    /// init-job creates a stable child token bound to `policy=root`
    /// for first-deploy convenience. In production this is a footgun —
    /// anyone with `kubectl get secret` access reads cluster-admin-on-Vault
    /// equivalent. Refuse to start in production with that literal token,
    /// and emit a loud WARN in dev so operators don't accidentally promote
    /// it. Operators should rotate to an AppRole / JWT-bound token before
    /// flipping `RUST_ENV=production`.
    pub fn from_env() -> Result<Self> {
        let addr = talos_config::read_env_or_file("VAULT_ADDR")
            .ok_or_else(|| anyhow!("VAULT_ADDR must be set when KEK_PROVIDER=vault"))?;
        let token = talos_config::read_env_or_file("VAULT_TOKEN")
            .ok_or_else(|| anyhow!("VAULT_TOKEN must be set when KEK_PROVIDER=vault (use VAULT_TOKEN_FILE for Docker secrets)"))?;
        // Refuse the chart's pre-init placeholder. install.sh seeds this
        // value into the bootstrap secret on fresh installs; the chart's
        // vault-init Job replaces it with a least-privilege talos-controller
        // token after the Vault transit engine is set up. Until that swap
        // happens, the controller has no usable Vault token, so failing
        // closed here is correct (rather than waiting until first encrypt).
        if token == "__pending_vault_init__" {
            return Err(anyhow!(
                "VAULT_TOKEN is the chart's pre-init placeholder. The vault-init \
                 Job has not yet patched the bootstrap secret with the \
                 talos-controller token. Check `kubectl -n talos logs job/talos-vault-init`; \
                 if the Job completed successfully, restart the controller \
                 Deployment (`kubectl -n talos rollout restart deploy/talos-controller`)."
            ));
        }
        if token == "dev-root" {
            if talos_config::is_production() {
                return Err(anyhow!(
                    "SECURITY: VAULT_TOKEN=dev-root is the chart's dev seed token \
                     (policy=root, never expires). Refusing to start in production. \
                     Rotate to an AppRole / JWT-bound least-privilege token before \
                     flipping RUST_ENV=production. See deploy/helm/talos/templates/vault/init-job.yaml."
                ));
            }
            tracing::warn!(
                "VAULT_TOKEN is the chart's `dev-root` seed token (policy=root). \
                 This is fine for local dev / first-deploy bootstrapping, but you \
                 MUST rotate to a least-privilege token before promoting this \
                 deployment to production (RUST_ENV=production refuses to start \
                 with this token)."
            );
        }
        let mount = talos_config::read_env_or_file("VAULT_TRANSIT_MOUNT")
            .unwrap_or_else(|| "transit".to_string());
        let key_name = talos_config::read_env_or_file("VAULT_TRANSIT_KEY_NAME")
            .unwrap_or_else(|| DEFAULT_TRANSIT_KEY_NAME.to_string());
        Self::new(addr, token, mount, key_name)
    }

    /// Boot-time check: confirm Vault is reachable, the token
    /// authenticates, and the token can both encrypt and decrypt with
    /// the configured transit key. The check uses a randomly-generated
    /// 32-byte payload so it doesn't pollute any audit log with
    /// predictable content. Failure is the operator's signal to fix
    /// configuration BEFORE the first secret op fails at request time.
    pub async fn health_check(&self) -> Result<()> {
        // 1. Token lookup-self — confirms reachability + auth.
        let url = format!("{}/v1/auth/token/lookup-self", self.addr);
        let resp = self
            .client
            .get(&url)
            .header("X-Vault-Token", self.token.as_str())
            .send()
            .await
            .with_context(|| format!("Vault unreachable at {}", self.addr))?;
        if !resp.status().is_success() {
            let status = resp.status();
            return Err(anyhow!(
                "Vault token lookup-self failed: {} ({})",
                status,
                status.canonical_reason().unwrap_or("unknown")
            ));
        }
        // Body shape doesn't matter beyond "well-formed" — we just need
        // to confirm the response parses. The actual capability check
        // is the encrypt+decrypt round-trip below.
        let _: VaultResponse<TokenLookupSelfData> =
            talos_http_body::read_json_capped(resp)
                .await
                .context("Vault token lookup-self returned malformed JSON")?;

        // 2. Real round-trip against the configured transit key. This
        // proves the token has both encrypt+decrypt capability AND the
        // named key exists. Use random bytes so we don't accidentally
        // leak a known fingerprint into Vault audit logs.
        let mut probe = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut probe);
        let wrapped = self.wrap_dek(&probe).await
            .context("Vault transit encrypt probe failed (token missing transit/encrypt cap, or key not initialized?)")?;
        let unwrapped = self
            .unwrap_dek(&wrapped)
            .await
            .context("Vault transit decrypt probe failed (token missing transit/decrypt cap?)")?;
        if unwrapped.as_slice() != probe {
            return Err(anyhow!(
                "Vault transit round-trip mismatch — encrypt/decrypt path is broken"
            ));
        }

        tracing::info!(
            provider = %self.display_name,
            "Vault transit KEK provider health check passed"
        );
        Ok(())
    }
}

impl KekProvider for VaultTransitProvider {
    fn wrap_dek(
        &self,
        dek: &[u8; 32],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + '_>> {
        // The base64 of the plaintext DEK is as sensitive as the DEK bytes
        // themselves — keep it in Zeroizing so the heap allocation is wiped
        // on drop rather than lingering until the allocator reuses the page.
        // Matches the Zeroizing discipline on every other plaintext-DEK path.
        let plaintext_b64 = Zeroizing::new(B64.encode(dek));
        Box::pin(async move {
            let url = format!("{}/v1/{}/encrypt/{}", self.addr, self.mount, self.key_name);
            let resp = self
                .client
                .post(&url)
                .header("X-Vault-Token", self.token.as_str())
                .json(&EncryptRequest {
                    plaintext: plaintext_b64.as_str(),
                })
                .send()
                .await
                .context("Vault transit encrypt: HTTP send failed")?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = talos_http_body::read_error_text_capped(resp).await;
                // Body may include the requested cipher op but never
                // the plaintext — Vault doesn't echo it back. Still log
                // bounded length to keep error messages reasonable.
                let truncated = body.chars().take(500).collect::<String>();
                return Err(anyhow!(
                    "Vault transit encrypt failed: HTTP {} — {}",
                    status,
                    truncated
                ));
            }
            let body: VaultResponse<EncryptData> = talos_http_body::read_json_capped(resp)
                .await
                .context("Vault transit encrypt: malformed JSON response")?;
            if !body.errors.is_empty() {
                return Err(anyhow!("Vault transit encrypt: {}", body.errors.join("; ")));
            }
            // The `vault:v1:<base64>` string IS the ciphertext we store.
            // Stored as raw UTF-8 bytes in the BYTEA column.
            Ok(body.data.ciphertext.into_bytes())
        })
    }

    fn unwrap_dek(
        &self,
        wrapped: &[u8],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Zeroizing<Vec<u8>>>> + Send + '_>> {
        // Reconstruct the `vault:vN:<base64>` string from stored bytes.
        // On corruption (non-UTF-8 row), fail closed — this would
        // indicate a row written by EnvKekProvider being read with
        // VaultTransitProvider, which is exactly the kind of confused-
        // provider scenario we want to surface loudly.
        let ciphertext = match std::str::from_utf8(wrapped) {
            Ok(s) => s.to_string(),
            Err(_) => {
                return Box::pin(async move {
                    Err(anyhow!(
                        "Vault transit unwrap: stored bytes are not valid UTF-8 — \
                         row was likely encrypted with a different KEK provider"
                    ))
                })
            }
        };
        Box::pin(async move {
            if !ciphertext.starts_with("vault:") {
                return Err(anyhow!(
                    "Vault transit unwrap: stored ciphertext lacks 'vault:' prefix — \
                     row was likely encrypted with a different KEK provider"
                ));
            }
            let url = format!("{}/v1/{}/decrypt/{}", self.addr, self.mount, self.key_name);
            let resp = self
                .client
                .post(&url)
                .header("X-Vault-Token", self.token.as_str())
                .json(&DecryptRequest {
                    ciphertext: &ciphertext,
                })
                .send()
                .await
                .context("Vault transit decrypt: HTTP send failed")?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = talos_http_body::read_error_text_capped(resp).await;
                let truncated = body.chars().take(500).collect::<String>();
                return Err(anyhow!(
                    "Vault transit decrypt failed: HTTP {} — {}",
                    status,
                    truncated
                ));
            }
            let mut body: VaultResponse<DecryptData> = talos_http_body::read_json_capped(resp)
                .await
                .context("Vault transit decrypt: malformed JSON response")?;
            if !body.errors.is_empty() {
                return Err(anyhow!("Vault transit decrypt: {}", body.errors.join("; ")));
            }
            // Both the base64 string and the decoded bytes are plaintext DEK
            // material. Move the base64 out of the deserialized response into a
            // Zeroizing buffer (so the copy held in `body` is wiped, not left
            // for the allocator), and decode into another Zeroizing buffer.
            let plaintext_b64 = Zeroizing::new(std::mem::take(&mut body.data.plaintext));
            let plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(
                B64.decode(plaintext_b64.as_bytes())
                    .context("Vault transit decrypt: returned plaintext is not valid base64")?,
            );
            if plaintext.len() != 32 {
                return Err(anyhow!(
                    "Vault transit decrypt: returned {} bytes, expected 32",
                    plaintext.len()
                ));
            }
            Ok(plaintext)
        })
    }

    fn name(&self) -> &str {
        &self.display_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unwrap_rejects_non_utf8_bytes() {
        let provider =
            VaultTransitProvider::new("http://127.0.0.1:1", "test-token", "transit", "talos-kek")
                .unwrap();
        // Invalid UTF-8 — should fail BEFORE any HTTP call, so no
        // network access is needed for this test.
        let bad = vec![0xff, 0xfe, 0xfd];
        assert!(provider.unwrap_dek(&bad).await.is_err());
    }

    #[tokio::test]
    async fn unwrap_rejects_wrong_prefix() {
        let provider =
            VaultTransitProvider::new("http://127.0.0.1:1", "test-token", "transit", "talos-kek")
                .unwrap();
        // Missing `vault:` prefix — should fail BEFORE any HTTP call.
        let bad = b"not-a-vault-ciphertext";
        assert!(provider.unwrap_dek(bad).await.is_err());
    }
}
