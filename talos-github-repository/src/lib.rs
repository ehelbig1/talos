//! `talos-github-repository` — persistence for the `github_app_installations`
//! table (RFC 0008 Phase B / B2a).
//!
//! Stores GitHub App installation **metadata** only — never tokens. Installation
//! access tokens are short-lived and minted on demand (see `talos-github` B1 +
//! the renewal arm B3). The connect flow (B2b) claims here through
//! [`GithubAppInstallationRepository::claim_recorded`] — the ONE writer of a
//! row's owner; module dispatch (B4) resolves an installation by the repo's
//! owning account.
//!
//! All queries are runtime-checked `sqlx::query_as` (no `query!` macros), so this
//! crate needs no `.sqlx` offline cache.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// One row of `github_app_installations`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GithubAppInstallation {
    pub id: Uuid,
    pub user_id: Uuid,
    pub installation_id: i64,
    pub account_login: String,
    pub account_type: Option<String>,
    pub permissions: Option<serde_json::Value>,
    pub repository_selection: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Column list shared by every SELECT so the `FromRow` mapping stays in lockstep.
const COLS: &str = "id, user_id, installation_id, account_login, account_type, \
                    permissions, repository_selection, is_active, created_at, updated_at";

/// The facts of a claim, all GitHub-verified by the caller.
#[derive(Debug, Clone, Copy)]
pub struct NewInstallationClaim<'a> {
    pub user_id: Uuid,
    pub installation_id: i64,
    pub account_login: &'a str,
    pub account_type: Option<&'a str>,
    pub permissions: Option<&'a serde_json::Value>,
    pub repository_selection: Option<&'a str>,
}

/// What a claim did. `#[must_use]`: ignoring `OwnedByAnotherUser` would report
/// a connect that did not happen.
#[must_use]
#[derive(Debug, Clone)]
pub enum InstallationClaim {
    /// The row is now this user's and active; the claim is recorded.
    Claimed {
        row: GithubAppInstallation,
        transition: ClaimTransition,
    },
    /// An ACTIVE row owned by another user — refused, nothing written.
    OwnedByAnotherUser,
}

/// How the claimed row came to be this user's (recorded as `transition`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimTransition {
    /// No row for this installation existed.
    Created,
    /// The row was already this user's (re-install / permission change).
    Refreshed,
    /// The row was this user's but inactive (a reconnect after disconnect).
    Reactivated,
    /// The row was another user's and INACTIVE — the only cross-user move.
    ReassignedFromInactive,
}

impl ClaimTransition {
    fn from_prior(prior: Option<(Uuid, bool)>, claimant: Uuid) -> Self {
        match prior {
            None => Self::Created,
            Some((owner, true)) if owner == claimant => Self::Refreshed,
            Some((owner, false)) if owner == claimant => Self::Reactivated,
            // (other, true) cannot reach here: the guarded upsert returned no row.
            Some(_) => Self::ReassignedFromInactive,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Refreshed => "refreshed",
            Self::Reactivated => "reactivated",
            Self::ReassignedFromInactive => "reassigned_from_inactive",
        }
    }
}

pub struct GithubAppInstallationRepository {
    pool: PgPool,
}

impl GithubAppInstallationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Claim an installation for `claim.user_id`, recording the claim in
    /// `admin_event_log` in the SAME transaction.
    ///
    /// **An active installation owned by another user is never reassigned.**
    /// Until 2026-09-25 this was an upsert whose conflict arm set
    /// `user_id = EXCLUDED.user_id` unconditionally, so any user who reached the
    /// connect callback with someone else's `installation_id` (GitHub documents
    /// that the Setup-URL value can be spoofed) moved the row — and with it
    /// `github_app:<owner>` token minting — to themselves. The conflict arm now
    /// updates only when the row is already this user's or is inactive, and a
    /// guarded-out conflict returns no row: [`InstallationClaim::OwnedByAnotherUser`].
    /// The SQL predicate is the authority (it also settles two concurrent first
    /// claims); the `FOR UPDATE` read before it exists only to record what the
    /// claim replaced.
    ///
    /// A claim that cannot be recorded does not happen (the transaction rolls
    /// back). Callers MUST first prove the user can access the installation —
    /// this method guards ownership, not access.
    pub async fn claim_recorded(
        &self,
        claim: &NewInstallationClaim<'_>,
    ) -> Result<InstallationClaim> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("begin installation claim")?;

        let prior: Option<(Uuid, Uuid, bool)> = sqlx::query_as(
            "SELECT id, user_id, is_active FROM github_app_installations \
             WHERE installation_id = $1 FOR UPDATE",
        )
        .bind(claim.installation_id)
        .fetch_optional(&mut *tx)
        .await
        .context("read prior github_app_installation")?;

        let row = sqlx::query_as::<_, GithubAppInstallation>(&format!(
            "INSERT INTO github_app_installations \
                 (user_id, installation_id, account_login, account_type, \
                  permissions, repository_selection, is_active) \
             VALUES ($1, $2, $3, $4, $5, $6, true) \
             ON CONFLICT (installation_id) DO UPDATE SET \
                 user_id = EXCLUDED.user_id, \
                 account_login = EXCLUDED.account_login, \
                 account_type = EXCLUDED.account_type, \
                 permissions = EXCLUDED.permissions, \
                 repository_selection = EXCLUDED.repository_selection, \
                 is_active = true, \
                 updated_at = now() \
             WHERE github_app_installations.user_id = EXCLUDED.user_id \
                OR NOT github_app_installations.is_active \
             RETURNING {COLS}"
        ))
        .bind(claim.user_id)
        .bind(claim.installation_id)
        .bind(claim.account_login)
        .bind(claim.account_type)
        .bind(claim.permissions)
        .bind(claim.repository_selection)
        .fetch_optional(&mut *tx)
        .await
        .context("claim github_app_installation")?;

        let Some(row) = row else {
            // Guarded out: an active row owned by someone else. Nothing was
            // written, so there is nothing to record here — the caller logs the
            // refusal. Dropping `tx` rolls back the row lock.
            return Ok(InstallationClaim::OwnedByAnotherUser);
        };

        let transition = ClaimTransition::from_prior(prior.map(|(_, u, a)| (u, a)), claim.user_id);
        let details = serde_json::json!({
            "installation_id": claim.installation_id,
            "account_login": claim.account_login,
            "account_type": claim.account_type,
            "repository_selection": claim.repository_selection,
            "transition": transition.as_str(),
            "previous_user_id": prior.and_then(|(_, u, _)| (u != claim.user_id).then_some(u)),
            "ownership_verified_by": "github_user_installations",
        });
        talos_admin_event_log::insert_on_conn(
            &mut tx,
            Some(claim.user_id),
            "github_installation_claimed",
            "github_app_installation",
            Some(row.id),
            &format!(
                "GitHub App installation {} ({}) connected ({})",
                claim.installation_id,
                claim.account_login,
                transition.as_str()
            ),
            Some(&details),
        )
        .await
        .context("record github installation claim")?;

        tx.commit().await.context("commit installation claim")?;
        Ok(InstallationClaim::Claimed { row, transition })
    }

    /// Look up an installation by GitHub's installation id (any active state).
    pub async fn get_by_installation_id(
        &self,
        installation_id: i64,
    ) -> Result<Option<GithubAppInstallation>> {
        let row = sqlx::query_as::<_, GithubAppInstallation>(&format!(
            "SELECT {COLS} FROM github_app_installations WHERE installation_id = $1"
        ))
        .bind(installation_id)
        .fetch_optional(&self.pool)
        .await
        .context("get github_app_installation by installation_id")?;
        Ok(row)
    }

    /// The active installation for a GitHub account login **owned by `user_id`**,
    /// if any. Used by module dispatch (B4) to resolve a token for a repo's
    /// owner.
    ///
    /// The `user_id` filter is a **tenancy boundary**, not an optimisation:
    /// `github_app:<owner>` token minting resolves to this row, so scoping to the
    /// owning user prevents one Talos user from minting installation tokens
    /// against another user's GitHub App install (each install is recorded here
    /// with its own `user_id`). Credential-path callers MUST pass the execution's
    /// user; an absent user must fail closed (skip the lookup entirely).
    pub async fn get_active_by_account_for_user(
        &self,
        account_login: &str,
        user_id: Uuid,
    ) -> Result<Option<GithubAppInstallation>> {
        let row = sqlx::query_as::<_, GithubAppInstallation>(&format!(
            "SELECT {COLS} FROM github_app_installations \
             WHERE account_login = $1 AND user_id = $2 AND is_active \
             ORDER BY updated_at DESC, id DESC LIMIT 1"
        ))
        .bind(account_login)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .context("get active github_app_installation by account for user")?;
        Ok(row)
    }

    /// List a user's installations (most recent first).
    pub async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<GithubAppInstallation>> {
        let rows = sqlx::query_as::<_, GithubAppInstallation>(&format!(
            "SELECT {COLS} FROM github_app_installations \
             WHERE user_id = $1 ORDER BY created_at DESC, id DESC"
        ))
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .context("list github_app_installations for user")?;
        Ok(rows)
    }

    /// Mark an installation inactive (disconnect), scoped to the owning user.
    /// Returns the number of rows affected (0 = not found / not owned).
    /// We soft-deactivate rather than DELETE so a re-install upserts cleanly and
    /// the audit trail (created_at) survives.
    pub async fn deactivate(&self, installation_id: i64, user_id: Uuid) -> Result<u64> {
        let res = sqlx::query(
            "UPDATE github_app_installations \
             SET is_active = false, updated_at = now() \
             WHERE installation_id = $1 AND user_id = $2",
        )
        .bind(installation_id)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .context("deactivate github_app_installation")?;
        Ok(res.rows_affected())
    }
}
