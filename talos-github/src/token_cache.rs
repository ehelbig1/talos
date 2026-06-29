//! In-memory installation-token cache with on-demand rotation (RFC 0008 B3,
//! resolves open-question 4).
//!
//! Installation access tokens are 1-hour, repo-scoped secrets. This cache mints
//! one per installation on first use and re-mints it on demand once it's within
//! [`REFRESH_MARGIN_SECS`] of expiry, so callers always get a token with headroom
//! and **rotation is automatic with zero operator action**.
//!
//! Design choices (open-question 4 — "dedicated short-TTL cache" branch):
//! - **In-memory, not `integration_credentials`.** The token is a secret; keeping
//!   it only in a [`Zeroizing`] in-memory cell (never written to the DB) shrinks
//!   the secret-exposure surface. The App private key (controller-only) can
//!   always re-mint, so there's nothing durable worth persisting.
//! - **Single-flight per installation.** A per-installation async lock means a
//!   burst of concurrent requests for an expired token triggers exactly ONE mint
//!   (the "must not thunder on a popular installation" requirement), not N.
//! - Multi-replica controllers mint independently (≤ replica-count mints/hour per
//!   installation) — well within GitHub's installation-token rate limits.

use std::sync::Arc;

use anyhow::{Context, Result};
use dashmap::DashMap;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::GithubAppClient;

/// Re-mint once the cached token is within this many seconds of expiry. 5 min
/// of headroom comfortably covers a slow request + clock skew on a 1-hour token.
pub const REFRESH_MARGIN_SECS: i64 = 300;

/// True if a token expiring at `expires_at_unix` is still safe to hand out at
/// `now_unix` (i.e. more than [`REFRESH_MARGIN_SECS`] of life remaining).
fn is_fresh(expires_at_unix: i64, now_unix: i64) -> bool {
    expires_at_unix - now_unix > REFRESH_MARGIN_SECS
}

struct CachedToken {
    token: Zeroizing<String>,
    expires_at_unix: i64,
}

/// Caches installation tokens minted via a [`GithubAppClient`].
pub struct InstallationTokenCache {
    client: GithubAppClient,
    // Per-installation cell behind its own lock → single-flight minting.
    entries: DashMap<i64, Arc<Mutex<Option<CachedToken>>>>,
}

impl InstallationTokenCache {
    pub fn new(client: GithubAppClient) -> Self {
        Self {
            client,
            entries: DashMap::new(),
        }
    }

    /// Return a valid installation token, minting + caching it if absent or
    /// within the refresh margin of expiry. `now_unix` is injected (consistent
    /// with the rest of the crate); production callers pass
    /// `chrono::Utc::now().timestamp()`.
    pub async fn get_token(
        &self,
        installation_id: i64,
        now_unix: i64,
    ) -> Result<Zeroizing<String>> {
        // Clone the per-installation Arc<Mutex> out of the map, then drop the
        // DashMap guard BEFORE awaiting (never hold it across .await).
        let cell = self.entries.entry(installation_id).or_default().clone();
        let mut guard = cell.lock().await;

        if let Some(cached) = guard.as_ref() {
            if is_fresh(cached.expires_at_unix, now_unix) {
                return Ok(cached.token.clone());
            }
        }

        // Stale or absent → mint a fresh one (single-flight: we hold `guard`).
        let minted = self
            .client
            .mint_installation_token(installation_id, now_unix)
            .await
            .with_context(|| {
                format!("mint installation token for installation {installation_id}")
            })?;

        let token = minted.token.clone();
        *guard = Some(CachedToken {
            token: minted.token,
            expires_at_unix: minted.expires_at.timestamp(),
        });
        Ok(token)
    }

    /// Drop any cached token for an installation (e.g. on disconnect). The next
    /// `get_token` re-mints.
    pub fn invalidate(&self, installation_id: i64) {
        self.entries.remove(&installation_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_when_well_before_expiry() {
        // 1-hour token, just minted.
        assert!(is_fresh(1_000 + 3600, 1_000));
    }

    #[test]
    fn stale_within_refresh_margin() {
        // Exactly at the margin is NOT fresh (strictly greater required).
        assert!(!is_fresh(1_000 + REFRESH_MARGIN_SECS, 1_000));
        // Inside the margin.
        assert!(!is_fresh(1_000 + REFRESH_MARGIN_SECS - 1, 1_000));
    }

    #[test]
    fn stale_when_expired() {
        assert!(!is_fresh(1_000, 2_000));
    }

    #[test]
    fn fresh_just_outside_margin() {
        assert!(is_fresh(1_000 + REFRESH_MARGIN_SECS + 1, 1_000));
    }
}
