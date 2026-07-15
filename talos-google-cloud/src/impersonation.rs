//! GCP service-account impersonation (Phase D — dynamic secret minting).
//!
//! Implements [`talos_workflow_engine_core::GcpImpersonationTokenProvider`] so
//! a workflow module secret path of the form
//! `gcp/impersonated/<sa_email>/access_token` resolves, at dispatch time, to a
//! freshly-minted short-lived impersonated token instead of a stored secret.
//!
//! ## Security model
//!
//! 1. The requesting user holds a **`google_cloud_full`** consent — a broad
//!    `cloud-platform` token that is **host-reserved** (never handed to a
//!    guest; see `is_controller_internal_vault_path`). It is used ONLY here,
//!    controller-side, as the bearer for the mint call.
//! 2. The mint calls `iamcredentials.generateAccessToken` to impersonate
//!    `<sa_email>`, returning a token that lives ~10 minutes and is bounded by
//!    the SA's OWN IAM roles (mint scope `cloud-platform` ∩ the SA's granted
//!    roles = the SA's actual power). Google itself enforces that the caller
//!    holds `iam.serviceAccountTokenCreator` on `<sa_email>` — impersonating
//!    an SA the user wasn't granted returns 403.
//! 3. The guest module receives ONLY that scoped-down, short-lived token.
//!
//! Blast radius of a leaked minted token: run as one SA, for ~10 minutes.
//! Blast radius of a leaked broad token: bounded to controller memory (it is
//! never on the wire to a guest, same protection as LLM provider keys).

use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

use talos_workflow_engine_core::{BoxError, GcpImpersonationTokenProvider};

use crate::integration::GoogleCloudIntegrationService;

/// Scope requested for the minted token. `cloud-platform` is the widest the
/// IAM Credentials API accepts; the EFFECTIVE power is bounded by the target
/// SA's own IAM roles (a `talos-runner` SA with only `run.developer` yields a
/// token that can only touch Cloud Run, regardless of this scope).
const MINT_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
/// Minted-token lifetime. Short by design: mint-at-dispatch → worker-claim
/// happens within one dispatch RTT, so 10 minutes is ample slack while
/// keeping a leaked token near-useless.
const MINT_LIFETIME: &str = "600s";
/// Hard timeout on the mint HTTP call so a hung IAM Credentials endpoint
/// can't stall node dispatch (the resolve path has no outer timeout).
const MINT_TIMEOUT: Duration = Duration::from_secs(10);

/// Shared, hardened client for the IAM Credentials endpoint (fixed host →
/// `trusted_client`, lint 49: redirect-none + connect-timeout baked in).
static IAM_HTTP_CLIENT: LazyLock<reqwest::Client> =
    LazyLock::new(|| talos_http_utils::trusted_client::build_integration_client(MINT_TIMEOUT));

/// Mints impersonated SA tokens from a user's host-reserved `google_cloud_full`
/// consent. Holds the full-tier [`GoogleCloudIntegrationService`] (which
/// refreshes + reads the broad token) plus a pool to resolve the user's
/// full-tier `provider_key`.
pub struct GcpImpersonationService {
    db_pool: Pool<Postgres>,
    full_tier: Arc<GoogleCloudIntegrationService>,
}

impl GcpImpersonationService {
    /// `full_tier` MUST be a service constructed with
    /// [`GoogleCloudIntegrationService::new_full`] — it reads tokens from the
    /// `oauth/google_cloud_full/...` namespace.
    pub fn new(db_pool: Pool<Postgres>, full_tier: Arc<GoogleCloudIntegrationService>) -> Self {
        Self { db_pool, full_tier }
    }

    /// The user's active full-tier `provider_key`, or `None` if they have not
    /// consented to the full tier. (`google_cloud_integrations` holds at most
    /// one active `tier='full'` row per user — the same account may also hold
    /// read/write rows.)
    async fn full_tier_provider_key(&self, user_id: Uuid) -> Result<Option<Uuid>> {
        let row: Option<(Uuid,)> = sqlx::query_as(
            "SELECT provider_key FROM google_cloud_integrations \
             WHERE user_id = $1 AND tier = 'full' AND is_active = TRUE \
             ORDER BY updated_at DESC LIMIT 1",
        )
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("Failed to look up full-tier GCP consent")?;
        Ok(row.map(|(pk,)| pk))
    }

    /// Call `iamcredentials.generateAccessToken` to impersonate `sa_email`.
    async fn mint(&self, broad_token: &str, sa_email: &str) -> Result<String> {
        // `projects/-` lets IAM resolve the SA's project from its email.
        let url = format!(
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{}:generateAccessToken",
            urlencoding::encode(sa_email)
        );
        let body = serde_json::json!({
            "scope": [MINT_SCOPE],
            "lifetime": MINT_LIFETIME,
        });

        let resp = tokio::time::timeout(
            MINT_TIMEOUT,
            IAM_HTTP_CLIENT
                .post(&url)
                .bearer_auth(broad_token)
                .json(&body)
                .send(),
        )
        .await
        .map_err(|_| anyhow!("generateAccessToken timed out"))?
        .context("generateAccessToken request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = talos_http_body::read_error_text_capped(resp).await;
            let preview = talos_text_util::truncate_at_char_boundary(&text, 300);
            let redacted = talos_dlp_provider::redact_str(preview);
            // sa_email is not secret; the broad token is never in the body/url.
            return Err(anyhow!(
                "generateAccessToken for '{}' failed (HTTP {}): {}",
                sa_email,
                status,
                redacted
            ));
        }

        #[derive(serde::Deserialize)]
        struct MintResponse {
            #[serde(rename = "accessToken")]
            access_token: String,
        }
        let parsed: MintResponse = talos_http_body::read_json_capped(resp)
            .await
            .context("Failed to parse generateAccessToken response")?;
        if parsed.access_token.is_empty() {
            return Err(anyhow!("generateAccessToken returned an empty token"));
        }
        Ok(parsed.access_token)
    }
}

#[async_trait::async_trait]
impl GcpImpersonationTokenProvider for GcpImpersonationService {
    async fn impersonated_token(
        &self,
        service_account_email: &str,
        user_id: Uuid,
    ) -> Result<Option<String>, BoxError> {
        // No full-tier consent → not injected (fail closed). This is Ok(None),
        // not Err: it's an expected "user hasn't opted in" state, not a fault.
        let Some(provider_key) = self
            .full_tier_provider_key(user_id)
            .await
            .map_err(|e| -> BoxError { e.to_string().into() })?
        else {
            return Ok(None);
        };

        // Read (refresh-if-needed) the broad host-reserved cloud-platform
        // token. This never leaves the controller.
        let broad_token = self
            .full_tier
            .get_access_token(user_id, provider_key)
            .await
            .map_err(|e| -> BoxError { e.to_string().into() })?;

        // Mint. A 403 here (caller lacks tokenCreator on the SA) surfaces as
        // Err → logged at error, not injected, module fails closed.
        let minted = self
            .mint(&broad_token, service_account_email)
            .await
            .map_err(|e| -> BoxError { e.to_string().into() })?;
        Ok(Some(minted))
    }
}

/// Hand-written `Debug` — never let a stray `{:?}` expose the inner service
/// (which, while it doesn't hold plaintext, is one deref from token reads).
impl std::fmt::Debug for GcpImpersonationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpImpersonationService").finish()
    }
}
