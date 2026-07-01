//! `talos-github-repository` — persistence for the `github_app_installations`
//! table (RFC 0008 Phase B / B2a).
//!
//! Stores GitHub App installation **metadata** only — never tokens. Installation
//! access tokens are short-lived and minted on demand (see `talos-github` B1 +
//! the renewal arm B3). The connect/install callback (B2b) upserts here; module
//! dispatch (B4) resolves an installation by the repo's owning account.
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

pub struct GithubAppInstallationRepository {
    pool: PgPool,
}

impl GithubAppInstallationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert (or update, on the unique `installation_id`) an installation.
    ///
    /// The connect callback (B2b) calls this. On re-install / permission change
    /// GitHub reuses the same `installation_id`, so we upsert: refresh the
    /// metadata, re-activate, and re-bind ownership to the connecting user.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert(
        &self,
        user_id: Uuid,
        installation_id: i64,
        account_login: &str,
        account_type: Option<&str>,
        permissions: Option<&serde_json::Value>,
        repository_selection: Option<&str>,
    ) -> Result<GithubAppInstallation> {
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
             RETURNING {COLS}"
        ))
        .bind(user_id)
        .bind(installation_id)
        .bind(account_login)
        .bind(account_type)
        .bind(permissions)
        .bind(repository_selection)
        .fetch_one(&self.pool)
        .await
        .context("upsert github_app_installation")?;
        Ok(row)
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
