//! One-click approval links — email-embedded capability URLs that
//! approve or reject a SUSPENDED (`waiting`) confidence-gate execution
//! without an authenticated session.
//!
//! The first approval-gated workflow (`pa-followup-approve-send`) pauses
//! at a `confidence_gate` node: the execution suspends to
//! `status = 'waiting'`, an `execution_approvals` row goes `pending`, and
//! the user must open the UI and call `submit_workflow_approval`. These
//! links turn the approval-request email into the decision surface: each
//! carries `/approval-actions/{token}/approve` and `.../reject`.
//!
//! Security model (mirrors `talos_ops_alerts_repository::correction_links`
//! — the proven ops-alerts pattern, PR #523/#524 — which is itself the
//! approval-gate pattern PR #217 tightened):
//! * **256-bit `OsRng` tokens, hash-only at rest.** Unlike
//!   `workflow_approval_gates` (which keeps the raw token for re-display),
//!   only `sha256_hex(token)` is stored. Tokens are minted fresh per email
//!   render and never re-shown, so a DB read yields nothing clickable.
//! * **Lookup by `token_hash`** (lint 41 discipline) + constant-time hash
//!   re-compare after fetch (the 256-bit entropy already defeats timing
//!   probes; this guards pathological collation surprises at zero cost).
//! * **GET is side-effect free.** The HTTP layer renders a confirm page;
//!   only the POST applies — link prefetchers (Gmail, Outlook SafeLinks,
//!   chat unfurlers) cannot silently approve or reject.
//! * **One token per execution, action in the path.** A single token
//!   authorises the decision; the `/approve` vs `/reject` path segment
//!   picks it. `used_at` is observability only — the authoritative
//!   "already decided" state is the underlying `execution_approvals`
//!   pending-row check (a decided execution has no pending row, so the
//!   apply path records nothing and the page shows "already decided").
//! * **TTL ~72h** (`DEFAULT_TOKEN_TTL_HOURS`) — outlives the email's read
//!   window without leaving a capability live indefinitely.
//! * **Tenancy** rides the token row (`user_id` captured at mint from the
//!   owning execution), never the HTTP request.
//! * **Same single write path.** Applying a decision goes through
//!   `ExecutionOrchestrationService::apply_waiting_approval_decision`,
//!   which records the decision (`update_execution_approval_decision`) and
//!   resumes the checkpoint (`resume_waiting_execution`) — the exact two
//!   steps `submit_workflow_approval` uses. No resume logic is duplicated.
//!
//! Known exposure (documented, accepted, same as correction_links): minted
//! URLs transit the notification NODE OUTPUT on their way to the compose/
//! send nodes, so raw tokens can also appear in persisted execution
//! outputs (encrypted at rest; readable only by the owning user, who could
//! equally call `submit_workflow_approval` directly, so no privilege is
//! gained). "Hash-only" is a claim about THIS TABLE, not every transit
//! surface. Minting is time-boxed by [`mint_approval_urls`] so a slow
//! token write can never stall the reader that embeds the links.

use anyhow::Result;
use chrono::{DateTime, Utc};
use rand::RngCore;
use sqlx::Row;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::ExecutionRepository;

/// Default link lifetime. Approval-request emails are acted on within a
/// few days; expiring links degrade to a clear "expired" page, never a
/// silent no-op.
pub const DEFAULT_TOKEN_TTL_HOURS: i64 = 72;

/// Everything the HTTP layer needs to render the confirm page and apply
/// the decision.
#[derive(Debug, Clone)]
pub struct ApprovalTokenContext {
    pub execution_id: Uuid,
    pub user_id: Uuid,
    pub workflow_name: Option<String>,
    /// Current execution status at lookup time — the confirm page uses it
    /// to show "already decided" when the run is no longer `waiting`.
    pub execution_status: String,
    pub expires_at: DateTime<Utc>,
}

fn new_raw_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Strict shape check for a provided token (64 hex chars) — rejects junk
/// before any DB work.
#[must_use]
pub fn token_shape_valid(token: &str) -> bool {
    token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit())
}

impl ExecutionRepository {
    /// Mint one approval token per execution id. Returns `Some(raw)`
    /// order-aligned with the input ONLY for ids the upsert actually
    /// stored — the ownership JOIN can skip rows (execution deleted
    /// between list and mint, or a foreign id), and rendering a link whose
    /// token was never persisted would be a silent dead link.
    ///
    /// One statement total: a CTE folds the opportunistic expired-token
    /// sweep (indexed range scan) into the batched UNNEST upsert, and
    /// RETURNING reports which ids landed. `ON CONFLICT (execution_id)`
    /// replaces any prior live token for the same execution (a resent
    /// notification re-mints rather than accumulating orphans).
    ///
    /// Raw tokens exist only in the return value and the rendered email;
    /// only `sha256_hex` is stored.
    pub async fn mint_approval_tokens(
        &self,
        user_id: Uuid,
        execution_ids: &[Uuid],
    ) -> Result<Vec<Option<String>>> {
        if execution_ids.is_empty() {
            return Ok(Vec::new());
        }

        let raw: Vec<String> = execution_ids.iter().map(|_| new_raw_token()).collect();
        let hashes: Vec<String> = raw.iter().map(|t| talos_text_util::sha256_hex(t)).collect();

        let inserted: std::collections::HashSet<Uuid> = sqlx::query_scalar(
            "WITH gc AS ( \
                 DELETE FROM execution_approval_tokens WHERE expires_at < NOW() \
             ) \
             INSERT INTO execution_approval_tokens \
                 (execution_id, user_id, token_hash, expires_at) \
             SELECT e.id, $1, x.token_hash, NOW() + make_interval(hours => $4::int) \
             FROM UNNEST($2::uuid[], $3::text[]) AS x(execution_id, token_hash) \
             JOIN workflow_executions e ON e.id = x.execution_id AND e.user_id = $1 \
             ON CONFLICT (execution_id) DO UPDATE \
                 SET token_hash = EXCLUDED.token_hash, \
                     expires_at = EXCLUDED.expires_at, \
                     created_at = NOW(), \
                     used_at = NULL \
             RETURNING execution_id",
        )
        .bind(user_id)
        .bind(execution_ids)
        .bind(&hashes)
        .bind(i32::try_from(DEFAULT_TOKEN_TTL_HOURS).unwrap_or(i32::MAX))
        .fetch_all(&self.db_pool)
        .await?
        .into_iter()
        .collect();

        Ok(execution_ids
            .iter()
            .zip(raw)
            .map(|(id, tok)| inserted.contains(id).then_some(tok))
            .collect())
    }

    /// Resolve a provided raw token to its execution context. `None` for
    /// unknown, malformed, or expired tokens — the HTTP layer shows one
    /// uniform "invalid or expired" page for all three (no oracle).
    pub async fn lookup_approval_token(
        &self,
        provided: &str,
    ) -> Result<Option<ApprovalTokenContext>> {
        if !token_shape_valid(provided) {
            return Ok(None);
        }
        let provided_hash = talos_text_util::sha256_hex(provided);
        let Some(row) = sqlx::query(
            "SELECT t.token_hash, t.execution_id, t.user_id, t.expires_at, \
                    e.status, w.name \
             FROM execution_approval_tokens t \
             JOIN workflow_executions e ON e.id = t.execution_id \
             LEFT JOIN workflows w ON w.id = e.workflow_id \
             WHERE t.token_hash = $1 AND t.expires_at > NOW()",
        )
        .bind(&provided_hash)
        .fetch_optional(&self.db_pool)
        .await?
        else {
            return Ok(None);
        };

        // Constant-time re-compare of the stored vs computed hash — the
        // index lookup already matched; this guards pathological
        // collation/normalization surprises at zero cost (lint 41 sibling
        // of `approval_token_matches`).
        let stored: String = row.try_get("token_hash")?;
        if stored.as_bytes().ct_eq(provided_hash.as_bytes()).into() {
            Ok(Some(ApprovalTokenContext {
                execution_id: row.try_get("execution_id")?,
                user_id: row.try_get("user_id")?,
                workflow_name: row.try_get::<Option<String>, _>("name")?,
                execution_status: row.try_get("status")?,
                expires_at: row.try_get("expires_at")?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Stamp a token's `used_at` after a decision applies (observability
    /// only — the authoritative decided-state is the execution_approvals
    /// pending-row check, so a token stays resolvable until expiry).
    pub async fn touch_approval_token(&self, provided: &str) -> Result<()> {
        if !token_shape_valid(provided) {
            return Ok(());
        }
        sqlx::query("UPDATE execution_approval_tokens SET used_at = NOW() WHERE token_hash = $1")
            .bind(talos_text_util::sha256_hex(provided))
            .execute(&self.db_pool)
            .await?;
        Ok(())
    }
}

/// Ready-to-render approve/reject URL pair for one execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalUrls {
    pub approve_url: String,
    pub reject_url: String,
}

/// Hard ceiling on how long link minting may delay the reader that embeds
/// the links — the pending-approvals response must never die for an
/// OPTIONAL link write.
const MINT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// The one reader-facing entry point: mint tokens for `execution_ids` and
/// return ready-to-render URL pairs, order-aligned, `None` where minting
/// was skipped/failed. Best-effort by construction — repo errors and the
/// [`MINT_TIMEOUT`] both degrade to link-less entries with a structured
/// warn, never an error. Mirrors `correction_links::mint_correction_urls`.
pub async fn mint_approval_urls(
    repo: &ExecutionRepository,
    user_id: Uuid,
    execution_ids: &[Uuid],
    base_url: &str,
) -> Vec<Option<ApprovalUrls>> {
    if execution_ids.is_empty() {
        return Vec::new();
    }
    match tokio::time::timeout(
        MINT_TIMEOUT,
        repo.mint_approval_tokens(user_id, execution_ids),
    )
    .await
    {
        Ok(Ok(tokens)) => tokens
            .into_iter()
            .map(|t| t.map(|t| approval_urls(base_url, &t)))
            .collect(),
        Ok(Err(e)) => {
            tracing::warn!(
                target: "talos_approvals",
                error = %e,
                "approval-token mint failed — rendering without links"
            );
            vec![None; execution_ids.len()]
        }
        Err(_) => {
            tracing::warn!(
                target: "talos_approvals",
                timeout_ms = MINT_TIMEOUT.as_millis() as u64,
                "approval-token mint timed out — rendering without links"
            );
            vec![None; execution_ids.len()]
        }
    }
}

/// Build the approve/reject URL pair for one raw token. Pure —
/// unit-testable. `{base}/approval-actions/{token}/{approve,reject}`.
#[must_use]
pub fn approval_urls(public_base_url: &str, raw_token: &str) -> ApprovalUrls {
    let base = public_base_url.trim_end_matches('/');
    ApprovalUrls {
        approve_url: format!("{base}/approval-actions/{raw_token}/approve"),
        reject_url: format!("{base}/approval-actions/{raw_token}/reject"),
    }
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
    fn url_builder_normalizes_trailing_slash_and_actions() {
        let t = "ab".repeat(32);
        let urls = approval_urls("https://x.example/", &t);
        assert_eq!(
            urls.approve_url,
            format!("https://x.example/approval-actions/{t}/approve")
        );
        assert_eq!(
            urls.reject_url,
            format!("https://x.example/approval-actions/{t}/reject")
        );
        // No trailing slash on the base → identical result.
        let urls2 = approval_urls("https://x.example", &t);
        assert_eq!(urls, urls2);
    }
}
