//! One-click correction links — email-embedded capability URLs that
//! record a severity correction without an authenticated session.
//!
//! Every correction is training gold for the severity classifier; the
//! bottleneck is throughput (opening an MCP session per label). These
//! links turn the digest/report emails the user already reads into a
//! labeling surface: each listed alert carries per-severity links to
//! `/corrections/{token}/{severity}`.
//!
//! Security model (mirrors the approval-gate pattern, PR #217, then
//! tightens it):
//! * **256-bit `OsRng` tokens, hash-only at rest.** Unlike
//!   `workflow_approval_gates` (which keeps the raw token for
//!   re-display), only `sha256_hex(token)` is stored — links are
//!   minted fresh per email render and never re-shown, so a DB read
//!   yields nothing clickable.
//! * **Lookup by `token_hash`** (lint 41 discipline) + constant-time
//!   hash comparison after fetch (belt-and-braces; the 256-bit entropy
//!   already defeats timing probes on the index).
//! * **GET is side-effect free.** The HTTP layer renders a confirm
//!   page; only the POST applies — link prefetchers (Gmail, Outlook
//!   SafeLinks) cannot mislabel training data.
//! * **Multi-use within TTL** (default 7 days — outlives the weekly
//!   report's read window): the blast radius of a leaked token is one
//!   alert's severity label, and re-correcting from the same email is
//!   legitimate. All writes go through
//!   [`crate::OpsAlertRepository::correct_severity`] — the same
//!   validated single write path MCP uses, so `unclassified` remains
//!   unassignable and the corrections-outrank-models invariant holds.
//! * **Tenancy** rides the token row (`user_id` captured at mint from
//!   the reader's resolved identity), never the HTTP request.

use anyhow::Result;
use chrono::{DateTime, Utc};
use rand::RngCore;
use sqlx::Row;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::OpsAlertRepository;

/// Default link lifetime. Weekly reports are read within the week;
/// expiring links degrade to a clear "expired" page, never a mislabel.
pub const DEFAULT_TOKEN_TTL_HOURS: i64 = 7 * 24;

/// Everything the HTTP layer needs to render the confirm page and
/// apply the correction.
#[derive(Debug, Clone)]
pub struct CorrectionTokenContext {
    pub alert_id: Uuid,
    pub user_id: Uuid,
    pub alert_title: String,
    pub current_severity: String,
    pub corrected_severity: Option<String>,
    pub expires_at: DateTime<Utc>,
}

fn new_raw_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Strict shape check for a provided token (64 lowercase-insensitive
/// hex chars) — rejects junk before any DB work.
#[must_use]
pub fn token_shape_valid(token: &str) -> bool {
    token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit())
}

impl OpsAlertRepository {
    /// Mint one correction token per alert id, order-aligned with the
    /// input. One batched INSERT (UNNEST) per call — digest renders
    /// mint up to ~15 tokens and run twice a day, so per-row
    /// round-trips are pure waste. Piggybacks an opportunistic
    /// expired-token DELETE (indexed range scan) so the table stays
    /// bounded without a dedicated sweep task.
    ///
    /// Returns the RAW tokens; they exist only in the rendered email.
    pub async fn mint_correction_tokens(
        &self,
        user_id: Uuid,
        alert_ids: &[Uuid],
        ttl_hours: i64,
    ) -> Result<Vec<String>> {
        if alert_ids.is_empty() {
            return Ok(Vec::new());
        }
        let ttl_hours = ttl_hours.clamp(1, 24 * 90);

        // Opportunistic cleanup — cheap (indexed), bounded frequency
        // (only runs when something is minting).
        sqlx::query("DELETE FROM ops_alert_correction_tokens WHERE expires_at < NOW()")
            .execute(&self.db_pool)
            .await?;

        let raw: Vec<String> = alert_ids.iter().map(|_| new_raw_token()).collect();
        let hashes: Vec<String> = raw.iter().map(|t| talos_text_util::sha256_hex(t)).collect();

        // The alert_id join guard pins every token to an alert the
        // minting user actually owns — a caller passing a foreign
        // alert id mints nothing for it.
        sqlx::query(
            "INSERT INTO ops_alert_correction_tokens \
                 (alert_id, user_id, token_hash, expires_at) \
             SELECT a.id, $1, x.token_hash, NOW() + make_interval(hours => $4::int) \
             FROM UNNEST($2::uuid[], $3::text[]) AS x(alert_id, token_hash) \
             JOIN ops_alerts a ON a.id = x.alert_id AND a.user_id = $1",
        )
        .bind(user_id)
        .bind(alert_ids)
        .bind(&hashes)
        .bind(i32::try_from(ttl_hours).unwrap_or(i32::MAX))
        .execute(&self.db_pool)
        .await?;

        Ok(raw)
    }

    /// Resolve a provided raw token to its alert context. `None` for
    /// unknown, malformed, or expired tokens — the HTTP layer shows
    /// one uniform "invalid or expired" page for all three (no oracle).
    pub async fn lookup_correction_token(
        &self,
        provided: &str,
    ) -> Result<Option<CorrectionTokenContext>> {
        if !token_shape_valid(provided) {
            return Ok(None);
        }
        let provided_hash = talos_text_util::sha256_hex(provided);
        let Some(row) = sqlx::query(
            "SELECT t.token_hash, t.alert_id, t.user_id, t.expires_at, \
                    a.title, a.severity, a.corrected_severity \
             FROM ops_alert_correction_tokens t \
             JOIN ops_alerts a ON a.id = t.alert_id \
             WHERE t.token_hash = $1 AND t.expires_at > NOW()",
        )
        .bind(&provided_hash)
        .fetch_optional(&self.db_pool)
        .await?
        else {
            return Ok(None);
        };

        // Constant-time re-compare of the stored vs computed hash —
        // the index lookup already matched, this guards pathological
        // collation/normalization surprises at zero cost.
        let stored: String = row.try_get("token_hash")?;
        if stored.as_bytes().ct_eq(provided_hash.as_bytes()).into() {
            Ok(Some(CorrectionTokenContext {
                alert_id: row.try_get("alert_id")?,
                user_id: row.try_get("user_id")?,
                alert_title: row.try_get("title")?,
                current_severity: row.try_get("severity")?,
                corrected_severity: row.try_get("corrected_severity")?,
                expires_at: row.try_get("expires_at")?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Stamp a token's `last_used_at` after a successful apply
    /// (observability only — tokens stay valid until expiry).
    pub async fn touch_correction_token(&self, provided: &str) -> Result<()> {
        if !token_shape_valid(provided) {
            return Ok(());
        }
        sqlx::query(
            "UPDATE ops_alert_correction_tokens SET last_used_at = NOW() WHERE token_hash = $1",
        )
        .bind(talos_text_util::sha256_hex(provided))
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }
}

/// Build the per-alert correction URL base (`{base}/corrections/{token}`).
/// Renderers append `/{severity}` per link. Pure — unit-testable.
#[must_use]
pub fn correction_url(public_base_url: &str, raw_token: &str) -> String {
    format!(
        "{}/corrections/{raw_token}",
        public_base_url.trim_end_matches('/')
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_tokens_are_64_hex_and_unique() {
        let a = new_raw_token();
        let b = new_raw_token();
        assert!(token_shape_valid(&a));
        assert!(token_shape_valid(&b));
        assert_ne!(a, b);
    }

    #[test]
    fn shape_check_rejects_junk() {
        assert!(!token_shape_valid(""));
        assert!(!token_shape_valid("short"));
        assert!(!token_shape_valid(&"g".repeat(64))); // non-hex
        assert!(!token_shape_valid(&"a".repeat(63)));
        assert!(!token_shape_valid(&"a".repeat(65)));
        assert!(token_shape_valid(&"A0f3".repeat(16)));
    }

    #[test]
    fn url_builder_normalizes_trailing_slash() {
        let t = "ab".repeat(32);
        assert_eq!(
            correction_url("https://x.example/", &t),
            format!("https://x.example/corrections/{t}")
        );
        assert_eq!(
            correction_url("https://x.example", &t),
            format!("https://x.example/corrections/{t}")
        );
    }
}
