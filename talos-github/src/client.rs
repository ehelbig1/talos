//! Async GitHub App API client (feature `client`).
//!
//! Wraps the network-free primitives ([`AppSigningKey`], the request builders,
//! the response parsers) into the two controller-side calls Phase B needs:
//! mint an installation token (B3 renewal, B4 dispatch) and fetch installation
//! metadata (B2b connect callback).
//!
//! Gated behind the `client` feature so the crypto/parse core stays
//! dependency-light (no `reqwest`) and fully unit-testable without it. Hardening
//! mirrors the workspace convention (`talos-gmail`): redirects disabled, explicit
//! timeouts, response bodies read through `talos-http-body`'s capped reader (OOM
//! defense — the controller is the credential-holding host).

use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::app_jwt::MAX_APP_JWT_TTL_SECS;
use crate::installation::{parse_installation_info, InstallationInfo};
use crate::installation_token::{
    installation_token_request, parse_installation_token_response, InstallationToken,
};
use crate::{AppSigningKey, GITHUB_API_BASE};

const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

/// A configured client for one GitHub App (one signing key + app id).
pub struct GithubAppClient {
    signing_key: AppSigningKey,
    app_id: String,
    api_base: String,
    http: reqwest::Client,
}

impl std::fmt::Debug for GithubAppClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubAppClient")
            .field("app_id", &self.app_id)
            .field("api_base", &self.api_base)
            .field("signing_key", &self.signing_key) // redacts itself
            .finish()
    }
}

impl GithubAppClient {
    /// Build a client against github.com.
    pub fn new(signing_key: AppSigningKey, app_id: impl Into<String>) -> Result<Self> {
        Self::with_base(signing_key, app_id, GITHUB_API_BASE)
    }

    /// Build a client against a custom API base (GitHub Enterprise Server — a
    /// non-goal for now — and tests).
    pub fn with_base(
        signing_key: AppSigningKey,
        app_id: impl Into<String>,
        api_base: impl Into<String>,
    ) -> Result<Self> {
        // Route through the shared hardened builder (redirect(Policy::none())
        // + connect_timeout baked in) so this credential-bearing client is
        // hardened by construction and covered by lint check 49 (security
        // review 2026-07-19, L7). We keep GitHub's longer 8s connect timeout by
        // overriding the shared 5s default. redirect-none is critical here — a
        // redirect could replay the App-JWT Bearer to an attacker-controlled
        // host — and is now guaranteed by the shared builder.
        let http = talos_http_utils::trusted_client::hardened_client_builder(HTTP_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .context("build GitHub App reqwest client")?;
        Ok(Self {
            signing_key,
            app_id: app_id.into(),
            api_base: api_base.into(),
            http,
        })
    }

    fn app_jwt(&self, now_unix: i64) -> Result<String> {
        self.signing_key
            .build_app_jwt(&self.app_id, now_unix, MAX_APP_JWT_TTL_SECS)
            .map_err(|e| anyhow::anyhow!("mint App JWT: {e}"))
    }

    /// Mint a fresh installation access token (1-hour, repo-scoped).
    ///
    /// `now_unix` is injected (consistent with the JWT minter) — production
    /// callers pass `chrono::Utc::now().timestamp()`.
    pub async fn mint_installation_token(
        &self,
        installation_id: i64,
        now_unix: i64,
    ) -> Result<InstallationToken> {
        let jwt = self.app_jwt(now_unix)?;
        let (url, headers) = installation_token_request(&self.api_base, installation_id, &jwt);
        let mut req = self.http.post(&url);
        for (name, value) in headers {
            req = req.header(name, value);
        }
        let resp = req
            .send()
            .await
            .context("installation-token request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            // Drain (capped) but don't log the body — GitHub error bodies can
            // echo request context; never risk surfacing the App JWT.
            let _ = talos_http_body::read_error_text_capped(resp).await;
            tracing::warn!(%status, installation_id, "installation-token mint returned error");
            bail!("installation-token mint returned HTTP {status}");
        }
        let body =
            talos_http_body::read_body_capped(resp, talos_http_body::DEFAULT_MAX_RESPONSE_BYTES)
                .await
                .context("read installation-token response")?;
        parse_installation_token_response(&body).map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Fetch installation account metadata (`GET /app/installations/{id}`).
    pub async fn get_installation(
        &self,
        installation_id: i64,
        now_unix: i64,
    ) -> Result<InstallationInfo> {
        let jwt = self.app_jwt(now_unix)?;
        let url = format!(
            "{}/app/installations/{}",
            self.api_base.trim_end_matches('/'),
            installation_id
        );
        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "talos")
            .send()
            .await
            .context("get-installation request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let _ = talos_http_body::read_error_text_capped(resp).await;
            tracing::warn!(%status, installation_id, "get-installation returned error");
            bail!("get-installation returned HTTP {status}");
        }
        let body =
            talos_http_body::read_body_capped(resp, talos_http_body::DEFAULT_MAX_RESPONSE_BYTES)
                .await
                .context("read get-installation response")?;
        parse_installation_info(&body).map_err(|e| anyhow::anyhow!("{e}"))
    }
}
