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
//! every time it's safe to (idempotent, no-op once at least one user has
//! the elevated grant). Safe to call from:
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

/// Promote the first user if nobody currently has the `automation-node`
/// ceiling. Idempotent: once any user holds the elevated grant, this is a
/// no-op. Safe to call repeatedly and from concurrent paths — the
/// `ON CONFLICT` clause + the `!=` WHERE predicate keep the behavior
/// stable under races.
///
/// `candidate_user_id` is typically the user who just registered; pass
/// `None` at startup to let the function pick the earliest-created user.
pub async fn promote_first_user_if_needed(
    pool: &Pool<Postgres>,
    candidate_user_id: Option<Uuid>,
) -> anyhow::Result<bool> {
    // Fast path: if anyone already has automation-node, nothing to do.
    let already_bootstrapped: Option<bool> = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM user_capability_grants \
         WHERE max_capability_world = 'automation-node')",
    )
    .fetch_one(pool)
    .await?;
    if already_bootstrapped.unwrap_or(false) {
        return Ok(false);
    }

    // L-14: optional operator pin. When `BOOTSTRAP_FIRST_USER_EMAIL` is
    // set, only that email is allowed to win the bootstrap promotion —
    // closing the "fresh public deployment + attacker-registers-first"
    // race. Operators of single-tenant deploys typically own the email,
    // so this pin is the safest default for any deployment exposed to
    // the public internet before the operator's own signup completes.
    //
    // Unset = legacy "first user wins" behavior (intentionally preserved
    // for non-public deploys; e.g., compose stacks where no one can
    // beat the operator to /auth/register).
    // MCP-1154 (2026-05-16): validate the operator pin against the
    // canonical `validate_email_format` (MCP-1153 helper). Pre-fix
    // a misconfigured `BOOTSTRAP_FIRST_USER_EMAIL` (typo, missing
    // `@`, accidental quoting like "\"op@example.com\"") silently
    // produced a value that no signup could match — the `WHERE
    // LOWER(email) = $1` SQL never matched, so the bootstrap stayed
    // dormant indefinitely. The operator's intent ("pin to this
    // email") silently fell back to legacy "first user wins"
    // behaviour, exposing the public-deploy race the pin was added
    // (L-14) to close.
    //
    // Fix shape: validate at module entry. On failure emit a
    // structured ERROR and treat the env var as unset — the legacy
    // path is the safer fallback (a NEVER-MATCHING pin opens the
    // exact race operators set this var to close). Operator gets a
    // loud log line so misconfig is observable at first
    // `promote_first_user_if_needed` call.
    let pinned_email = std::env::var("BOOTSTRAP_FIRST_USER_EMAIL")
        .ok()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .and_then(|email| match crate::validate_email_format(&email) {
            Ok(()) => Some(email),
            Err(reason) => {
                tracing::error!(
                    target: "talos_auth",
                    event_kind = "bootstrap_pinned_email_invalid_format",
                    reason,
                    "BOOTSTRAP_FIRST_USER_EMAIL set but does not parse as a valid email; \
                     ignoring the operator pin and falling back to the legacy first-user-wins \
                     path. Fix the env var (or unset it) to re-enable the L-14 pinned-email \
                     race-close behaviour."
                );
                None
            }
        });

    // Resolve candidate: pinned email > caller-provided user > earliest-created.
    let user_id: Option<Uuid> = if let Some(ref email) = pinned_email {
        let pinned: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM users WHERE LOWER(email) = $1 LIMIT 1")
                .bind(email)
                .fetch_optional(pool)
                .await?;
        if pinned.is_none() {
            tracing::info!(
                target: "talos_auth",
                event_kind = "bootstrap_pinned_email_not_yet_registered",
                pinned_email = %email,
                "Bootstrap: pinned operator email not yet registered — \
                 leaving automation-node ceiling unbound until they sign up"
            );
            return Ok(false);
        }
        pinned
    } else {
        match candidate_user_id {
            Some(u) => Some(u),
            None => {
                sqlx::query_scalar("SELECT id FROM users ORDER BY created_at ASC LIMIT 1")
                    .fetch_optional(pool)
                    .await?
            }
        }
    };
    let Some(user_id) = user_id else {
        // No users in the DB yet — nothing to promote. Retry on next signup.
        return Ok(false);
    };

    // Upsert the grant. The WHERE guard prevents downgrading a higher grant
    // (defense-in-depth — we already short-circuit above, but a concurrent
    // path could race between the SELECT and INSERT).
    sqlx::query(
        "INSERT INTO user_capability_grants (user_id, max_capability_world, notes) \
         VALUES ($1, 'automation-node', 'Bootstrap: first-user elevation (runtime)') \
         ON CONFLICT (user_id) DO UPDATE \
         SET max_capability_world = EXCLUDED.max_capability_world, \
             granted_at = now(), \
             notes = EXCLUDED.notes \
         WHERE user_capability_grants.max_capability_world != 'automation-node'",
    )
    .bind(user_id)
    .execute(pool)
    .await?;

    tracing::info!(
        %user_id,
        "Bootstrap: first user promoted to automation-node ceiling — \
         actor creation with LLM/memory/HTTP/secrets worlds is now unblocked. \
         For admin-gated MCP tools (set_secret, query_paginated), grant \
         agent capabilities via the agents/roles tables or use the local-dev \
         stdio endpoint which auto-assigns '*'."
    );
    Ok(true)
}
