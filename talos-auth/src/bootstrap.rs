//! First-user bootstrap: automatic admin + elevated capability ceiling.
//!
//! A fresh Talos install with zero users cannot produce an admin through
//! the normal grant flow (grant_capability_ceiling is admin-gated, nobody
//! is admin yet). The companion migration `20260410100002_bootstrap_admin_ceiling.sql`
//! handles the case where users already exist at migration time — but if
//! the DB is empty when migrations run (the normal case for a fresh
//! install), the migration no-ops and the first user who signs up later
//! is stuck at the default `http-node` ceiling.
//!
//! This module closes that gap by running the same promotion dynamically,
//! ONCE per deployment: a `capability_bootstrap` row records that it has
//! happened (migration `20260925140000`), and every later call is a no-op.
//! Until 2026-09-25 "done" meant "some user holds `automation-node` now", so
//! removing the last such grant re-armed it — the next signup was elevated to
//! the top of the lattice and every restart re-granted the earliest user.
//! Safe to call from:
//!
//! * Controller startup (after migrations run)
//! * After `auth::signup` (newly-registered user)
//! * After `ensure_dev_user` (synthetic dev bootstrap)
//!
//! Scope of the promotion:
//!
//! * **Capability ceiling** — grants `automation-node` so actor creation
//!   with any world is allowed. Unblocks agent/LLM/memory workflows.
//!
//! The `organization_members.role` admin flag (used by
//! `grant_capability_ceiling` and `list_capability_grants`) is NOT set
//! here — organization membership is a separate concern (multi-tenant,
//! typically scoped to an org created via UI/API). See
//! `is_platform_admin` in `actor_repository.rs` for the check surface.
//! For fresh single-user installs, the capability ceiling alone unblocks
//! every workflow-authoring path; admin-gated MCP tools (`set_secret`,
//! `query_paginated`) remain gated on agent capabilities which are set
//! by whichever auth layer (stdio local-dev = `*`, HTTP MCP = agent row)
//! is serving the request.

use sqlx::{Pool, Postgres};
use uuid::Uuid;

/// Promote the first user to the `automation-node` ceiling, once per
/// deployment. After the first successful promotion a `capability_bootstrap`
/// row exists and this is a no-op, whatever happens to the grants later.
/// Safe to call repeatedly and from concurrent paths: the row's primary key
/// serialises concurrent bootstraps, so exactly one of them claims it.
///
/// `candidate_user_id` is typically the user who just registered; pass
/// `None` at startup to let the function pick the earliest-created user.
pub async fn promote_first_user_if_needed(
    pool: &Pool<Postgres>,
    candidate_user_id: Option<Uuid>,
) -> anyhow::Result<bool> {
    // Fast path: the bootstrap has already happened on this deployment. The
    // grants are deliberately NOT consulted — removing every `automation-node`
    // grant must not re-arm a promotion.
    let already_bootstrapped: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM capability_bootstrap)")
            .fetch_one(pool)
            .await?;
    if already_bootstrapped {
        return Ok(false);
    }

    // L-14: optional operator pin (`BOOTSTRAP_FIRST_USER_EMAIL`). Unset =
    // legacy "first user wins" (non-public deploys, e.g. compose stacks where
    // nobody can beat the operator to signup).
    //
    // 2026-09-26: an INVALID pin refuses the promotion outright. It used to
    // fall back to first-user-wins — i.e. a typo in the one variable set to
    // close the public-deploy race reopened exactly that race. And a VALID pin
    // is honoured only for an account that PROVES it owns the address: password
    // signup verifies no email, so whoever registered the pinned address first
    // (the attacker the pin exists to stop) used to win it. Ownership is proven
    // by an OAuth sign-in whose provider reported that address verified
    // (`talos-oauth` refuses unverified emails); an operator who signs up with
    // a password grants the ceiling by hand instead (`grantCapabilityCeiling`
    // as platform admin).
    let pin = resolve_bootstrap_pin(std::env::var("BOOTSTRAP_FIRST_USER_EMAIL").ok().as_deref());

    // Resolve candidate: pinned email > caller-provided user > earliest-created.
    let user_id: Option<Uuid> = match pin {
        BootstrapPin::Invalid(reason) => {
            tracing::error!(
                target: "talos_auth",
                event_kind = "bootstrap_pinned_email_invalid_format",
                reason,
                "BOOTSTRAP_FIRST_USER_EMAIL is set but is not a valid email; the \
                 first-user promotion is REFUSED until it is fixed or unset (it no \
                 longer falls back to first-user-wins)."
            );
            return Ok(false);
        }
        BootstrapPin::Email(ref email) => {
            let proven: Option<Uuid> = sqlx::query_scalar(
                "SELECT u.id FROM users u \
                 JOIN oauth_accounts oa ON oa.user_id = u.id \
                 WHERE LOWER(u.email) = $1 AND LOWER(oa.email) = $1 AND u.is_active = true \
                 ORDER BY u.created_at ASC LIMIT 1",
            )
            .bind(email)
            .fetch_optional(pool)
            .await?;
            if proven.is_none() {
                tracing::warn!(
                    target: "talos_auth",
                    event_kind = "bootstrap_pinned_email_unproven",
                    "Bootstrap: no account has proven ownership of the pinned \
                     BOOTSTRAP_FIRST_USER_EMAIL (an OAuth sign-in with that verified \
                     address). A password signup does not qualify — grant the \
                     automation-node ceiling by hand (grantCapabilityCeiling as platform \
                     admin) or sign in once via OAuth and restart the controller."
                );
                return Ok(false);
            }
            proven
        }
        BootstrapPin::Unset => match candidate_user_id {
            Some(u) => Some(u),
            None => {
                sqlx::query_scalar("SELECT id FROM users ORDER BY created_at ASC LIMIT 1")
                    .fetch_optional(pool)
                    .await?
            }
        },
    };
    let Some(user_id) = user_id else {
        // No users in the DB yet — nothing to promote. Retry on next signup.
        return Ok(false);
    };

    // Upsert the grant. The WHERE guard prevents downgrading a higher grant
    // (defense-in-depth — we already short-circuit above, but a concurrent
    // path could race between the SELECT and INSERT). The grant and its
    // `capability_grant_issued` record commit together; the record's user is
    // NULL because the platform, not a person, granted it (2026-09-18 —
    // before, the first user's elevation to the top of the lattice left no
    // record at all).
    let mut tx = pool.begin().await?;
    // Claim the bootstrap first. A concurrent caller blocks on the primary key
    // until this transaction ends, then inserts nothing and gives up.
    let claimed = sqlx::query(
        "INSERT INTO capability_bootstrap (singleton, user_id, source) \
         VALUES (true, $1, 'runtime') ON CONFLICT (singleton) DO NOTHING",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if claimed == 0 {
        tx.rollback().await?;
        return Ok(false);
    }
    let granted = sqlx::query(
        "INSERT INTO user_capability_grants (user_id, max_capability_world, notes) \
         VALUES ($1, 'automation-node', 'Bootstrap: first-user elevation (runtime)') \
         ON CONFLICT (user_id) DO UPDATE \
         SET max_capability_world = EXCLUDED.max_capability_world, \
             granted_at = now(), \
             notes = EXCLUDED.notes \
         WHERE user_capability_grants.max_capability_world != 'automation-node'",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if granted == 0 {
        // This user already holds the top ceiling, so the bootstrap's purpose
        // is met: its claim commits, but nothing changed and nothing is
        // recorded as granted.
        tx.commit().await?;
        return Ok(false);
    }
    talos_admin_event_log::insert_on_conn(
        &mut tx,
        None,
        "capability_grant_issued",
        "user",
        Some(user_id),
        &format!(
            "Capability ceiling automation-node granted to user {user_id} (first-user bootstrap)"
        ),
        Some(&serde_json::json!({
            "target_user_id": user_id,
            "max_capability_world": "automation-node",
            "bootstrap": true,
        })),
    )
    .await?;
    tx.commit().await?;

    tracing::info!(
        %user_id,
        "Bootstrap: first user promoted to automation-node ceiling — \
         actor creation with LLM/memory/HTTP/secrets worlds is now unblocked. \
         For admin-gated MCP tools (e.g. query_paginated), grant \
         agent capabilities via the agents/roles tables or use the local-dev \
         stdio endpoint which auto-assigns '*'."
    );
    Ok(true)
}

/// The operator's `BOOTSTRAP_FIRST_USER_EMAIL`, classified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapPin {
    /// Unset or empty: legacy first-user-wins.
    Unset,
    /// A valid address, trimmed and lowercased.
    Email(String),
    /// Set but unparsable: the promotion is refused (never first-user-wins).
    Invalid(&'static str),
}

/// Classify the raw pin value. Pure so the refusal is unit-tested.
#[must_use]
pub fn resolve_bootstrap_pin(raw: Option<&str>) -> BootstrapPin {
    let Some(email) = raw
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
    else {
        return BootstrapPin::Unset;
    };
    match crate::validate_email_format(&email) {
        Ok(()) => BootstrapPin::Email(email),
        Err(reason) => BootstrapPin::Invalid(reason),
    }
}

#[cfg(test)]
mod pin_tests {
    use super::*;

    #[test]
    fn an_invalid_pin_refuses_rather_than_falling_back() {
        assert!(matches!(
            resolve_bootstrap_pin(Some("\"op@example.com\"")),
            BootstrapPin::Invalid(_)
        ));
        assert!(matches!(
            resolve_bootstrap_pin(Some("no-at-sign")),
            BootstrapPin::Invalid(_)
        ));
    }

    #[test]
    fn unset_and_valid_pins_classify() {
        assert_eq!(resolve_bootstrap_pin(None), BootstrapPin::Unset);
        assert_eq!(resolve_bootstrap_pin(Some("  ")), BootstrapPin::Unset);
        assert_eq!(
            resolve_bootstrap_pin(Some(" Op@Example.com ")),
            BootstrapPin::Email("op@example.com".into())
        );
    }
}
