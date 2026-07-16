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
use dashmap::DashMap;
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
const MINT_LIFETIME_SECS: i64 = 600;
/// Hard timeout on the mint HTTP call so a hung IAM Credentials endpoint
/// can't stall node dispatch (the resolve path has no outer timeout).
const MINT_TIMEOUT: Duration = Duration::from_secs(10);
/// Re-mint once a cached token is within this many seconds of expiry, so a
/// caller always gets headroom. On a 600 s token this yields ~8.5 min of
/// cache usability — a whole short-job poll loop served by ONE mint.
const REFRESH_MARGIN_SECS: i64 = 90;
/// When the cache exceeds this many entries, opportunistically sweep expired
/// ones on the next insert. Bounds memory against distinct (user, SA) growth;
/// combined with insert-only-on-success this caps the map at the number of
/// legitimately-mintable pairs.
const CACHE_SWEEP_THRESHOLD: usize = 256;

/// Shared, hardened client for the IAM Credentials endpoint (fixed host →
/// `trusted_client`, lint 49: redirect-none + connect-timeout baked in).
static IAM_HTTP_CLIENT: LazyLock<reqwest::Client> =
    LazyLock::new(|| talos_http_utils::trusted_client::build_integration_client(MINT_TIMEOUT));

/// A cached impersonated token + its absolute expiry (unix seconds).
#[derive(Clone)]
struct CachedMint {
    token: String,
    expires_at_unix: i64,
}

/// True if a token expiring at `expires_at_unix` still has more than the
/// refresh margin of life left at `now_unix` — i.e. safe to serve from cache.
fn is_fresh(expires_at_unix: i64, now_unix: i64) -> bool {
    expires_at_unix - now_unix > REFRESH_MARGIN_SECS
}

/// Extract the project id from a standard SA email
/// (`<name>@<project>.iam.gserviceaccount.com`), used as the API
/// billing/quota project (`x-goog-user-project`). Returns `None` for
/// non-standard SAs (e.g. `…@developer.gserviceaccount.com`), where we omit
/// the header and let Google attribute the call to the OAuth client's project.
fn sa_project(sa_email: &str) -> Option<&str> {
    let domain = sa_email.split_once('@')?.1;
    let project = domain.strip_suffix(".iam.gserviceaccount.com")?;
    if project.is_empty() || project.contains('.') {
        return None;
    }
    Some(project)
}

/// Mints impersonated SA tokens from a user's host-reserved `google_cloud_full`
/// consent. Holds the full-tier [`GoogleCloudIntegrationService`] (which
/// refreshes + reads the broad token) plus a pool to resolve the user's
/// full-tier `provider_key`.
///
/// A short-TTL cache keyed by `(user_id, sa_email)` serves a live token across
/// repeated dispatches (a poll-until-done loop re-dispatches the node every
/// iteration — without the cache each iteration would re-mint, plus a DB
/// lookup and a vault read). Mirrors the GitHub App installation-token cache
/// pattern. The key includes the (module-supplied) SA email, so the cache is
/// populated ONLY on a successful mint — a workflow naming random
/// non-grantable SAs gets a 403 and never grows the map.
pub struct GcpImpersonationService {
    db_pool: Pool<Postgres>,
    full_tier: Arc<GoogleCloudIntegrationService>,
    cache: DashMap<(Uuid, String), CachedMint>,
}

impl GcpImpersonationService {
    /// `full_tier` MUST be a service constructed with
    /// [`GoogleCloudIntegrationService::new_full`] — it reads tokens from the
    /// `oauth/google_cloud_full/...` namespace.
    pub fn new(db_pool: Pool<Postgres>, full_tier: Arc<GoogleCloudIntegrationService>) -> Self {
        Self {
            db_pool,
            full_tier,
            cache: DashMap::new(),
        }
    }

    /// Drop expired entries when the map has grown past the threshold. Cheap
    /// (`retain` over a small map) and only runs on the occasional insert.
    fn maybe_sweep(&self, now_unix: i64) {
        if self.cache.len() > CACHE_SWEEP_THRESHOLD {
            self.cache.retain(|_, v| v.expires_at_unix > now_unix);
        }
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
    /// Returns the token and its absolute expiry (unix seconds), taken from
    /// the response's `expireTime` (falling back to `now + MINT_LIFETIME` if
    /// Google omits it).
    async fn mint(&self, broad_token: &str, sa_email: &str) -> Result<CachedMint> {
        // `projects/-` lets IAM resolve the SA's project from its email.
        let url = format!(
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{}:generateAccessToken",
            urlencoding::encode(sa_email)
        );
        let body = serde_json::json!({
            "scope": [MINT_SCOPE],
            "lifetime": format!("{MINT_LIFETIME_SECS}s"),
        });

        // Attribute the API call (enablement + quota) to the TARGET SA's
        // project, not the OAuth client's project. Google bills a user-token
        // call to the OAuth app's project by default; that project usually
        // hasn't enabled iamcredentials, whereas the operator DID enable it in
        // the sandbox project where the SA lives (per the runbook). Requires
        // the consenting user to hold `serviceusage.services.use` there — an
        // owner/editor does. Omitted for non-standard SA domains.
        let mut request = IAM_HTTP_CLIENT
            .post(&url)
            .bearer_auth(broad_token)
            .json(&body);
        if let Some(project) = sa_project(sa_email) {
            request = request.header("x-goog-user-project", project);
        }

        let resp = tokio::time::timeout(MINT_TIMEOUT, request.send())
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
            #[serde(rename = "expireTime", default)]
            expire_time: Option<String>,
        }
        let parsed: MintResponse = talos_http_body::read_json_capped(resp)
            .await
            .context("Failed to parse generateAccessToken response")?;
        if parsed.access_token.is_empty() {
            return Err(anyhow!("generateAccessToken returned an empty token"));
        }
        // Prefer Google's stated `expireTime` (always present in practice).
        // If it's ever missing/unparseable, fall back CONSERVATIVELY to the
        // refresh margin rather than the full requested lifetime: that makes
        // the entry immediately non-fresh so the next dispatch re-mints, so we
        // never serve a token whose real expiry we couldn't confirm (guards the
        // impossible-but-unsafe case of a below-request org-policy lifetime cap
        // combined with an omitted expireTime). The token minted THIS call is
        // still returned and used.
        let expires_at_unix = parsed
            .expire_time
            .as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.timestamp())
            .unwrap_or_else(|| chrono::Utc::now().timestamp() + REFRESH_MARGIN_SECS);
        Ok(CachedMint {
            token: parsed.access_token,
            expires_at_unix,
        })
    }
}

#[async_trait::async_trait]
impl GcpImpersonationTokenProvider for GcpImpersonationService {
    async fn impersonated_token(
        &self,
        service_account_email: &str,
        user_id: Uuid,
    ) -> Result<Option<String>, BoxError> {
        let now = chrono::Utc::now().timestamp();
        let cache_key = (user_id, service_account_email.to_string());

        // Cache hit: a still-fresh token for this (user, SA) — skip the DB
        // lookup, vault read, and mint entirely. This is what keeps a
        // poll-until-done loop to a single mint per token lifetime.
        if let Some(hit) = self.cache.get(&cache_key) {
            if is_fresh(hit.expires_at_unix, now) {
                return Ok(Some(hit.token.clone()));
            }
        }

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
        // Err → logged at error, not injected, module fails closed. Because we
        // only reach the insert on success, a 403'd SA never enters the cache.
        let minted = self
            .mint(&broad_token, service_account_email)
            .await
            .map_err(|e| -> BoxError { e.to_string().into() })?;

        let token = minted.token.clone();
        self.maybe_sweep(now);
        self.cache.insert(cache_key, minted);
        Ok(Some(token))
    }
}

/// Hand-written `Debug` — never let a stray `{:?}` expose the inner service
/// (which, while it doesn't hold plaintext, is one deref from token reads).
impl std::fmt::Debug for GcpImpersonationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpImpersonationService").finish()
    }
}

#[cfg(test)]
mod cache_freshness_tests {
    use super::{is_fresh, REFRESH_MARGIN_SECS};

    #[test]
    fn fresh_when_well_within_lifetime() {
        let now = 1_000_000;
        // Full 600 s token just minted → plenty of headroom.
        assert!(is_fresh(now + 600, now));
    }

    #[test]
    fn stale_inside_the_refresh_margin() {
        let now = 1_000_000;
        // Exactly at the margin is NOT fresh (strict >), and anything less
        // must re-mint so a caller never gets a token about to expire.
        assert!(!is_fresh(now + REFRESH_MARGIN_SECS, now));
        assert!(!is_fresh(now + REFRESH_MARGIN_SECS - 1, now));
        // Just outside the margin is fresh.
        assert!(is_fresh(now + REFRESH_MARGIN_SECS + 1, now));
    }

    #[test]
    fn expired_is_stale() {
        let now = 1_000_000;
        assert!(!is_fresh(now - 1, now));
        assert!(!is_fresh(now, now));
    }
}

#[cfg(test)]
mod sa_project_tests {
    use super::sa_project;

    #[test]
    fn extracts_project_from_standard_sa() {
        assert_eq!(
            sa_project("talos-runner@my-talos-sandbox.iam.gserviceaccount.com"),
            Some("my-talos-sandbox")
        );
    }

    #[test]
    fn none_for_nonstandard_domains() {
        // Default compute SA — project is the numeric prefix, not the domain.
        assert_eq!(
            sa_project("282126683646-compute@developer.gserviceaccount.com"),
            None
        );
        // Garbage / no domain.
        assert_eq!(sa_project("not-an-email"), None);
        assert_eq!(sa_project("a@b.com"), None);
    }
}
