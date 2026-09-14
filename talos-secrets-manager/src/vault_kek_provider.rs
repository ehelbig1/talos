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
//!
//! Token lifetime (2026-09-14): the health check also classifies the token
//! from its own `lookup-self` ([`TokenLifetime`]) and REFUSES a production
//! boot on a token that has a finite TTL and cannot be renewed. A renewable
//! token is kept alive by [`VaultTransitProvider::run_token_renewal`], which
//! the controller runs as a supervised background task. Before that loop
//! existed nothing in the workspace renewed this token: Vault does NOT extend
//! a token because it is used (measured — a 45 s periodic token used for
//! `transit/encrypt` every 10 s expired on schedule and the next encrypt was a
//! 403), so a chart install's `-period=768h` controller token took the whole
//! KEK path down 32 days after install.

use std::pin::Pin;
use std::time::{Duration, Instant};

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

/// The lifetime fields of `auth/token/lookup-self`, as Vault 1.18 renders
/// them (captured from the dev Vault 2026-09-14): `ttl` is the seconds left
/// (0 = no TTL), `period` is ABSENT on a non-periodic token, `explicit_max_ttl`
/// is 0 when unset. `ttl` and `renewable` are REQUIRED — a body missing either
/// is malformed, never silently "non-expiring" or "renewable".
#[derive(Deserialize)]
struct TokenLookupSelfData {
    ttl: i64,
    renewable: bool,
    #[serde(default)]
    period: Option<i64>,
    #[serde(default)]
    explicit_max_ttl: i64,
    #[serde(default)]
    creation_ttl: i64,
}

/// `auth/token/renew-self`'s `auth` block.
#[derive(Deserialize)]
struct RenewSelfResponse {
    auth: RenewSelfAuth,
}

#[derive(Deserialize)]
struct RenewSelfAuth {
    lease_duration: u64,
    renewable: bool,
}

/// How a Vault token can live, classified from its own `lookup-self`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenLifetime {
    /// `ttl == 0`: the token has no TTL (e.g. a root token). Nothing to renew.
    NonExpiring,
    /// Renewable, periodic, no explicit max TTL: each renewal restores the full
    /// period, indefinitely. The shape the chart's vault-init Job mints.
    Periodic { ttl_secs: u64, period_secs: u64 },
    /// Renewable but bounded — non-periodic (capped by the mount/system max
    /// TTL) or carrying an explicit max TTL. Renewal extends it only until
    /// that ceiling; past it Vault grants less than asked (`capped`).
    RenewableBounded { ttl_secs: u64, increment_secs: u64 },
    /// A finite TTL that cannot be renewed: expires no matter what.
    Expiring { ttl_secs: u64 },
}

impl TokenLifetime {
    /// Classify from the raw `lookup-self` fields.
    #[must_use]
    pub fn classify(
        ttl: i64,
        renewable: bool,
        period: Option<i64>,
        explicit_max_ttl: i64,
        creation_ttl: i64,
    ) -> Self {
        let Ok(ttl_secs) = u64::try_from(ttl) else {
            // A negative TTL is not a shape Vault emits; treat it as the most
            // restrictive reading rather than as "no TTL".
            return Self::Expiring { ttl_secs: 0 };
        };
        if ttl_secs == 0 {
            return Self::NonExpiring;
        }
        if !renewable {
            return Self::Expiring { ttl_secs };
        }
        let period_secs = period
            .and_then(|p| u64::try_from(p).ok())
            .filter(|p| *p > 0);
        match period_secs {
            Some(period_secs) if explicit_max_ttl <= 0 => Self::Periodic {
                ttl_secs,
                period_secs,
            },
            Some(period_secs) => Self::RenewableBounded {
                ttl_secs,
                increment_secs: period_secs,
            },
            None => Self::RenewableBounded {
                ttl_secs,
                // Ask for the token's own TTL back each time. Omitting the
                // increment would ask for the mount default instead, which
                // can exceed the token's creation TTL and read as a false cap.
                increment_secs: u64::try_from(creation_ttl).unwrap_or(0).max(ttl_secs),
            },
        }
    }

    /// Seconds left, as Vault reported them (0 for [`Self::NonExpiring`]).
    #[must_use]
    pub const fn ttl_secs(self) -> u64 {
        match self {
            Self::NonExpiring => 0,
            Self::Periodic { ttl_secs, .. }
            | Self::RenewableBounded { ttl_secs, .. }
            | Self::Expiring { ttl_secs } => ttl_secs,
        }
    }

    /// The increment to request on renewal, or `None` when renewal cannot or
    /// need not happen.
    #[must_use]
    pub const fn renew_increment_secs(self) -> Option<u64> {
        match self {
            Self::Periodic { period_secs, .. } => Some(period_secs),
            Self::RenewableBounded { increment_secs, .. } => Some(increment_secs),
            Self::NonExpiring | Self::Expiring { .. } => None,
        }
    }

    /// The metric label for this class.
    #[must_use]
    pub const fn label(self) -> talos_metrics::VaultTokenLifetimeLabel {
        use talos_metrics::VaultTokenLifetimeLabel as L;
        match self {
            Self::NonExpiring => L::NonExpiring,
            Self::Periodic { .. } => L::Periodic,
            Self::RenewableBounded { .. } => L::RenewableBounded,
            Self::Expiring { .. } => L::Expiring,
        }
    }
}

/// The boot decision on a token's lifetime — the pure half of the posture
/// gate in [`VaultTransitProvider::health_check`].
///
/// * An [`TokenLifetime::Expiring`] token in PRODUCTION is refused: it takes
///   the KEK path down at its TTL and nothing can extend it. There is
///   deliberately no escape hatch — the token is read once at construction,
///   so even a sidecar that rotates `VAULT_TOKEN_FILE` would not be picked up,
///   and there is no production shape in which booting on it ends well.
/// * Outside production it is admitted with a WARN (dev stacks, drills).
/// * Every renewable or non-expiring token is admitted; a bounded one gets a
///   WARN/ERROR from the caller, because renewal cannot carry it past its max.
///
/// # Errors
/// Returns the refusal, naming the remaining TTL and the fix.
pub fn token_lifetime_posture(lifetime: TokenLifetime, is_production: bool) -> Result<()> {
    match lifetime {
        TokenLifetime::Expiring { ttl_secs } if is_production => Err(anyhow!(
            "SECURITY/AVAILABILITY: the Vault KEK token has a finite TTL ({ttl_secs} s left) and \
             is NOT renewable, so every DEK wrap and unwrap fails the moment it expires. \
             Refusing to start in production. Mint a renewable periodic token for the \
             controller (e.g. `vault token create -policy=talos-controller -period=768h \
             -orphan`); the controller renews it automatically."
        )),
        _ => Ok(()),
    }
}

/// Classify one renewal answer: `Renewed` only when Vault granted the full
/// increment and the token is still renewable. `lease_duration` below the
/// requested increment is Vault capping at the token's maximum TTL (measured:
/// `explicit_max_ttl=320` + `increment=600s` → `lease_duration: 320` with a
/// "TTL value is capped" warning).
#[must_use]
pub fn classify_renewal(
    requested_increment_secs: u64,
    lease_duration_secs: u64,
    still_renewable: bool,
) -> talos_metrics::VaultTokenRenewalOutcome {
    use talos_metrics::VaultTokenRenewalOutcome as O;
    if still_renewable && lease_duration_secs >= requested_increment_secs {
        O::Renewed
    } else {
        O::Capped
    }
}

/// When the renewal loop acts next. Production uses [`RenewalSchedule::DEFAULT`];
/// tests shrink the floor so they run in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenewalSchedule {
    /// Never act sooner than this.
    pub min: Duration,
    /// Never wait longer than this after a success.
    pub max: Duration,
    /// Never wait longer than this after a failure.
    pub retry_max: Duration,
}

impl RenewalSchedule {
    /// A third of the remaining TTL, at least 5 s, at most an hour — so a
    /// healthy token is renewed at least hourly (the cadence
    /// `TalosVaultTokenRenewalFailing`'s two-hour window is derived from) and
    /// a short one well before it lapses. After a failure: a third of what is
    /// left, at most a minute.
    pub const DEFAULT: Self = Self {
        min: Duration::from_secs(5),
        max: Duration::from_secs(3600),
        retry_max: Duration::from_secs(60),
    };

    /// Delay after a successful renewal (or the boot lookup) that left
    /// `ttl_secs`.
    #[must_use]
    pub fn after_success(&self, ttl_secs: u64) -> Duration {
        Duration::from_millis(ttl_secs.saturating_mul(1000) / 3)
            .clamp(self.min, self.max.max(self.min))
    }

    /// Delay after a failed attempt, with `remaining_secs` believed left.
    #[must_use]
    pub fn after_failure(&self, remaining_secs: u64) -> Duration {
        Duration::from_millis(remaining_secs.saturating_mul(1000) / 3)
            .clamp(self.min, self.retry_max.max(self.min))
    }
}

/// Why [`VaultTransitProvider::run_token_renewal`] returned. A healthy
/// renewable token never returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRenewalStop {
    /// The token has no TTL; there is nothing to renew.
    NotNeeded,
    /// The token was never renewable (only reachable outside production —
    /// production refuses it at boot). It will expire.
    NotRenewable,
    /// Vault reported a previously renewable token as no longer renewable. It
    /// will expire and nothing can extend it.
    NoLongerRenewable,
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
        // F7b: every request to this address carries `X-Vault-Token` — the
        // transit token that IS the master-KEK capability — and a plaintext
        // `http://` VAULT_ADDR puts it on the wire unencrypted. Redis, NATS,
        // Postgres and Neo4j all refuse plaintext in production
        // (`tls-prod-gate-*`); Vault did not. Refuse unless the operator has
        // explicitly accepted it for an in-pod sidecar over the loopback
        // (`TALOS_ALLOW_PLAINTEXT_VAULT=1`), which is logged at WARN.
        // tls-prod-gate-vault
        plaintext_vault_addr_gate(
            &addr,
            talos_config::is_production(),
            talos_config::bool_env_or_default("TALOS_ALLOW_PLAINTEXT_VAULT", false),
        )?;
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
                     (policy=root). Refusing to start in production. \
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
        self.health_check_in(talos_config::is_production()).await
    }

    /// [`Self::health_check`] with the environment decision passed in, so the
    /// production refusal is driven by tests through the real check.
    pub(crate) async fn health_check_in(&self, is_production: bool) -> Result<()> {
        // 1. Token lookup-self — confirms reachability + auth, and says how the
        //    token can live. A finite non-renewable token is refused in
        //    production BEFORE the transit probe: it would pass the probe
        //    today and take the KEK path down at its TTL.
        let lifetime = self.lookup_token_lifetime().await?;
        token_lifetime_posture(lifetime, is_production)?;
        match lifetime {
            TokenLifetime::Expiring { ttl_secs } => tracing::warn!(
                target: "talos_security",
                event_kind = "vault_token_expiring",
                ttl_secs,
                "the Vault KEK token is NOT renewable and expires in {ttl_secs} s; every DEK \
                 operation fails after that (refused in production)"
            ),
            TokenLifetime::RenewableBounded {
                ttl_secs,
                increment_secs,
            } => {
                let message = "the Vault KEK token is renewable but BOUNDED by a maximum TTL: \
                     renewal cannot carry it past that ceiling, after which every DEK \
                     operation fails. Prefer a periodic token (no explicit max TTL).";
                if is_production {
                    tracing::error!(target: "talos_security", event_kind = "vault_token_bounded",
                        ttl_secs, increment_secs, "{message}");
                } else {
                    tracing::warn!(target: "talos_security", event_kind = "vault_token_bounded",
                        ttl_secs, increment_secs, "{message}");
                }
            }
            TokenLifetime::Periodic { .. } | TokenLifetime::NonExpiring => {}
        }

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
            token_lifetime = lifetime.label().as_str(),
            token_ttl_secs = lifetime.ttl_secs(),
            "Vault transit KEK provider health check passed"
        );
        Ok(())
    }

    /// `auth/token/lookup-self`, classified.
    ///
    /// # Errors
    /// Transport failure, non-2xx, or a body missing the lifetime fields.
    pub async fn lookup_token_lifetime(&self) -> Result<TokenLifetime> {
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
        let body: VaultResponse<TokenLookupSelfData> = talos_http_body::read_json_capped(resp)
            .await
            .context("Vault token lookup-self returned malformed JSON")?;
        let d = body.data;
        Ok(TokenLifetime::classify(
            d.ttl,
            d.renewable,
            d.period,
            d.explicit_max_ttl,
            d.creation_ttl,
        ))
    }

    /// `auth/token/renew-self` with an explicit increment. Returns
    /// `(lease_duration_secs, still_renewable)`.
    async fn renew_token(&self, increment_secs: u64) -> Result<(u64, bool)> {
        let url = format!("{}/v1/auth/token/renew-self", self.addr);
        let resp = self
            .client
            .post(&url)
            .header("X-Vault-Token", self.token.as_str())
            .json(&serde_json::json!({ "increment": format!("{increment_secs}s") }))
            .send()
            .await
            .context("Vault token renew-self: HTTP send failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            // Vault's error body here is a short reason ("permission denied",
            // "lease is not renewable") and never echoes the token.
            let body = talos_http_body::read_error_text_capped(resp).await;
            let truncated = body.chars().take(200).collect::<String>();
            return Err(anyhow!(
                "Vault token renew-self failed: HTTP {status} — {truncated}"
            ));
        }
        let body: RenewSelfResponse = talos_http_body::read_json_capped(resp)
            .await
            .context("Vault token renew-self returned malformed JSON")?;
        Ok((body.auth.lease_duration, body.auth.renewable))
    }

    /// Keep the KEK token alive for the life of the process.
    ///
    /// Looks the token up (retrying until Vault answers), publishes its TTL,
    /// and — for a renewable token — renews it IMMEDIATELY (a token booted
    /// 31 days into a 32-day period has one day left, not 32) and then on
    /// [`RenewalSchedule::after_success`]. Every attempt is counted on
    /// `talos_vault_token_renewals_total{outcome}` against `metrics` (the
    /// process-global registry in production; an explicit one in tests).
    ///
    /// Returns only when renewal cannot or need not continue — see
    /// [`TokenRenewalStop`]. A failing Vault does NOT end the loop: it retries
    /// on [`RenewalSchedule::after_failure`] for as long as the process lives.
    pub async fn run_token_renewal(
        &self,
        schedule: RenewalSchedule,
        metrics: Option<&talos_metrics::TalosMetrics>,
    ) -> TokenRenewalStop {
        use talos_metrics::VaultTokenRenewalOutcome as O;
        if let Some(m) = metrics {
            talos_metrics::seed_vault_token_renewals_on(m);
        }
        let record = |outcome: O| {
            if let Some(m) = metrics {
                talos_metrics::record_vault_token_renewal_on(m, outcome);
            }
        };
        let publish = |lifetime: TokenLifetime, ttl_secs: u64| {
            if let Some(m) = metrics {
                talos_metrics::publish_vault_token_ttl_on(m, lifetime.label(), ttl_secs);
            }
        };

        let lifetime = loop {
            match self.lookup_token_lifetime().await {
                Ok(lifetime) => break lifetime,
                Err(e) => {
                    record(O::Failed);
                    tracing::warn!(
                        target: "talos_security",
                        event_kind = "vault_token_renewal_failed",
                        stage = "lookup",
                        error = %e,
                        "could not look up the Vault KEK token; retrying"
                    );
                    tokio::time::sleep(schedule.retry_max.max(schedule.min)).await;
                }
            }
        };
        publish(lifetime, lifetime.ttl_secs());
        let Some(increment_secs) = lifetime.renew_increment_secs() else {
            return match lifetime {
                TokenLifetime::NonExpiring => TokenRenewalStop::NotNeeded,
                _ => {
                    tracing::error!(
                        target: "talos_security",
                        event_kind = "vault_token_not_renewable",
                        ttl_secs = lifetime.ttl_secs(),
                        "the Vault KEK token cannot be renewed; it will expire and every DEK \
                         operation will fail after that"
                    );
                    TokenRenewalStop::NotRenewable
                }
            };
        };

        let mut current = lifetime;
        let mut expires_at = Instant::now() + Duration::from_secs(lifetime.ttl_secs());
        let mut delay = Duration::ZERO;
        loop {
            tokio::time::sleep(delay).await;
            match self.renew_token(increment_secs).await {
                Ok((lease_secs, still_renewable)) => {
                    let outcome = classify_renewal(increment_secs, lease_secs, still_renewable);
                    record(outcome);
                    expires_at = Instant::now() + Duration::from_secs(lease_secs);
                    if !still_renewable {
                        current = TokenLifetime::Expiring {
                            ttl_secs: lease_secs,
                        };
                        publish(current, lease_secs);
                        tracing::error!(
                            target: "talos_security",
                            event_kind = "vault_token_not_renewable",
                            ttl_secs = lease_secs,
                            "Vault reports the KEK token is no longer renewable; it expires in \
                             {lease_secs} s and every DEK operation fails after that"
                        );
                        return TokenRenewalStop::NoLongerRenewable;
                    }
                    publish(current, lease_secs);
                    if outcome == O::Capped {
                        tracing::warn!(
                            target: "talos_security",
                            event_kind = "vault_token_capped",
                            ttl_secs = lease_secs,
                            requested_secs = increment_secs,
                            "Vault granted less than the requested renewal: the KEK token has \
                             reached its maximum TTL and expires in {lease_secs} s"
                        );
                    }
                    delay = schedule.after_success(lease_secs);
                }
                Err(e) => {
                    record(O::Failed);
                    let remaining = expires_at.saturating_duration_since(Instant::now());
                    tracing::warn!(
                        target: "talos_security",
                        event_kind = "vault_token_renewal_failed",
                        stage = "renew",
                        believed_ttl_secs = remaining.as_secs(),
                        error = %e,
                        "could not renew the Vault KEK token; retrying"
                    );
                    delay = schedule.after_failure(remaining.as_secs());
                }
            }
        }
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

/// The pure decision behind `tls-prod-gate-vault`, unit-tested without env.
///
/// * not production → `Ok` (dev stacks run `http://vault:8200`);
/// * production + `https://` → `Ok`;
/// * production + plaintext + escape hatch → `Ok` with a WARN naming the risk;
/// * production + plaintext, no escape hatch → `Err` naming the variable.
///
/// Scheme comparison is case-insensitive and tolerates surrounding whitespace
/// (an env value of `" https://…"` is a config typo, not a downgrade).
pub fn plaintext_vault_addr_gate(
    addr: &str,
    is_production: bool,
    allow_plaintext: bool,
) -> Result<()> {
    let is_tls = addr.trim().to_ascii_lowercase().starts_with("https://");
    if !is_production || is_tls {
        return Ok(());
    }
    if allow_plaintext {
        tracing::warn!(
            target: "talos_audit",
            event_kind = "vault_plaintext_addr_allowed",
            "VAULT_ADDR is not https:// in production and TALOS_ALLOW_PLAINTEXT_VAULT is set — \
             the Vault transit token (master-KEK capability) travels unencrypted to this \
             address. Acceptable ONLY for an in-pod sidecar over loopback."
        );
        return Ok(());
    }
    Err(anyhow!(
        "SECURITY: VAULT_ADDR must use https:// in production (got scheme '{}'). Every \
         request carries the Vault transit token, which is the master-KEK capability. Set \
         TALOS_ALLOW_PLAINTEXT_VAULT=1 ONLY for an in-pod Vault agent sidecar reached over \
         loopback.",
        addr.trim().split("://").next().unwrap_or("<none>")
    ))
}

#[cfg(test)]
#[path = "vault_token_renewal_tests.rs"]
mod token_renewal_tests;

#[cfg(test)]
mod plaintext_gate_tests {
    use super::plaintext_vault_addr_gate;

    #[test]
    fn dev_accepts_plaintext() {
        assert!(plaintext_vault_addr_gate("http://vault:8200", false, false).is_ok());
    }

    #[test]
    fn production_accepts_tls_in_any_case_with_whitespace() {
        assert!(plaintext_vault_addr_gate("https://vault.internal:8200", true, false).is_ok());
        assert!(plaintext_vault_addr_gate("  HTTPS://vault.internal:8200 ", true, false).is_ok());
    }

    #[test]
    fn production_refuses_plaintext_without_the_escape_hatch() {
        let err = plaintext_vault_addr_gate("http://vault:8200", true, false)
            .expect_err("plaintext must be refused");
        let msg = err.to_string();
        assert!(msg.contains("TALOS_ALLOW_PLAINTEXT_VAULT"), "{msg}");
        assert!(msg.contains("'http'"), "{msg}");
        // A scheme-less value is also not TLS.
        assert!(plaintext_vault_addr_gate("vault:8200", true, false).is_err());
    }

    #[test]
    fn production_escape_hatch_admits_plaintext() {
        assert!(plaintext_vault_addr_gate("http://127.0.0.1:8200", true, true).is_ok());
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
