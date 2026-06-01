//! SystemRepository — cross-cutting infra queries that don't fit a single
//! domain repo. Currently: `system_settings` table + DB connectivity ping +
//! `pg_trigger` introspection used by the platform-info / wasm-config /
//! security-audit MCP handlers.
//!
//! Follows the same shape as the other repositories: plain struct, `new(db_pool)`,
//! `pub async fn` returning `anyhow::Result<T>`.

use anyhow::Result;
use sqlx::PgPool;
use std::sync::OnceLock;
use uuid::Uuid;

/// MCP-709 (2026-05-13): the synthetic `password_hash` written by
/// [`SystemRepository::ensure_user_row_for_agent`] must be a STRUCTURALLY
/// VALID bcrypt string so `bcrypt::verify` (in `talos-auth::login`) pays
/// the full ~100 ms cost on rejection rather than failing fast on a
/// malformed hash. Pre-fix the literal `"$2b$12$00...00"` (49 chars; a
/// real bcrypt hash is 60) was malformed, so `bcrypt::verify(any_pw,
/// fake)` errored in ~0 ms — distinguishable from "user not found"
/// (which runs the dummy-bcrypt-verify-for-timing at `talos-auth/src/lib.rs:613`
/// and takes ~100 ms). That's a UUID-keyed timing oracle for "is this
/// user_id a known synthetic MCP user," reachable via the public
/// `/auth/login` endpoint with `email=mcp-{uuid}@system.internal`.
///
/// The fix: lazily generate ONE process-wide bcrypt hash of a random
/// UUID at first use and reuse it for every synthetic-user INSERT.
/// Properties:
/// * Structurally valid → `bcrypt::verify` pays full cost → timing
///   matches the dummy-bcrypt user-not-found path.
/// * Seed UUID is `Uuid::new_v4()` (cryptographic random), generated
///   in-process, never returned, never logged, never persisted. Even
///   though every synthetic user shares the same hash, no client can
///   recover the seed to brute-force a login.
/// * One-time ~100 ms cost on the first ensure_user_row_for_agent
///   call; cached thereafter. Subsequent inserts and the no-op
///   ON CONFLICT (id) DO NOTHING path all cheap.
///
/// Sibling pattern: see `talos-auth/src/lib.rs:612` (the dummy hash
/// used for user-not-found timing match — same approach but with a
/// hash of a literal known string, since that path discards the
/// verify result; here we need a hash whose source is non-recoverable
/// because the hash is actually PERSISTED).
static SYNTHETIC_PASSWORD_HASH: OnceLock<String> = OnceLock::new();

fn synthetic_password_hash() -> &'static str {
    SYNTHETIC_PASSWORD_HASH.get_or_init(|| {
        let seed = Uuid::new_v4().to_string();
        bcrypt::hash(&seed, bcrypt::DEFAULT_COST).expect("bcrypt::hash of random UUID cannot fail")
    })
}

pub struct SystemRepository {
    db_pool: PgPool,
}

impl SystemRepository {
    pub fn new(db_pool: PgPool) -> Self {
        Self { db_pool }
    }

    /// Fetch a single setting from `system_settings`. Returns `Ok(None)` when
    /// the key does not exist; treats DB errors as Err so callers can choose
    /// to log + fall through.
    pub async fn get_setting(&self, key: &str) -> Result<Option<serde_json::Value>> {
        let row: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT value FROM system_settings WHERE key = $1")
                .bind(key)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(row)
    }

    /// Upsert a setting in `system_settings` (`updated_at = NOW()`).
    pub async fn upsert_setting(&self, key: &str, value: &serde_json::Value) -> Result<()> {
        sqlx::query(
            "INSERT INTO system_settings (key, value, updated_at) VALUES ($1, $2::jsonb, NOW()) \
             ON CONFLICT (key) DO UPDATE SET value = $2::jsonb, updated_at = NOW()",
        )
        .bind(key)
        .bind(value)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// Cheap DB connectivity probe used by `get_platform_info`. Returns true
    /// if the pool can satisfy a `SELECT 1`. Errors are swallowed and surfaced
    /// as `false` so the platform_info handler always has a reportable status.
    pub async fn ping(&self) -> bool {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.db_pool)
            .await
            .is_ok()
    }

    /// Count `pg_trigger` rows matching a name pattern. Used by `security_audit`
    /// to verify audit-immutability triggers are installed
    /// (`tgname LIKE 'trg_%_immutable'`). Returns 0 on DB error so the audit
    /// keeps running — a missing trigger is itself a finding.
    pub async fn count_triggers_like(&self, name_pattern: &str) -> i64 {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pg_trigger WHERE tgname LIKE $1")
            .bind(name_pattern)
            .fetch_one(&self.db_pool)
            .await
            .unwrap_or(0)
    }

    // ── mcp/mod.rs local-dev helpers ───────────────────────────────────────

    /// Find the oldest user (by created_at). Used by the local MCP endpoint to
    /// preserve user-id continuity when the web UI was used to register.
    pub async fn find_first_user_id(&self) -> Result<Option<Uuid>> {
        let id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM users ORDER BY created_at ASC LIMIT 1")
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(id)
    }

    /// Idempotent insert of the local-dev synthetic user. The
    /// `ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email` shape is a
    /// no-op update that forces RETURNING id to fire even when the row already
    /// exists (race-safe between concurrent first requests).
    pub async fn ensure_dev_user(&self) -> Result<Option<Uuid>> {
        let id: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO users \
                 (email, password_hash, is_active, failed_login_attempts, totp_enabled) \
             VALUES ('dev@talos.local', '', true, 0, false) \
             ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email \
             RETURNING id",
        )
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(id)
    }

    /// Check whether an mcp_agents row is currently active. Used by the SSE
    /// revocation-polling task. Returns false on DB error or missing row so a
    /// transient DB blip doesn't keep a revoked session alive.
    pub async fn is_agent_active(&self, agent_id: Uuid) -> bool {
        sqlx::query_scalar::<_, bool>("SELECT is_active FROM mcp_agents WHERE id = $1")
            .bind(agent_id)
            .fetch_optional(&self.db_pool)
            .await
            .ok()
            .flatten()
            .unwrap_or(false)
    }

    /// Batch variant: return the subset of `agent_ids` that are still
    /// active. Used by the bcrypt verification cache revocation sweep
    /// (MCP-991) — one batched query against all cached agent_ids on
    /// each tick beats one query per agent.
    ///
    /// On DB error, returns `Err` so the caller can preserve the
    /// existing cache rather than evicting everything (matching the
    /// `is_agent_active` fail-safe semantics — transient DB blips
    /// don't expand the revocation window). Cache callers
    /// short-circuit on Err and try again on the next tick.
    pub async fn list_active_agent_ids(
        &self,
        agent_ids: &[Uuid],
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM mcp_agents WHERE id = ANY($1) AND is_active = true",
        )
        .bind(agent_ids)
        .fetch_all(&self.db_pool)
        .await
    }

    // ── mcp/auth.rs middleware helpers ─────────────────────────────────────

    /// Look up an active mcp_agents row by token_lookup_hash + join role.
    /// Returns the bcrypt-target token_hash so the caller can run constant-time
    /// verification on a worker thread.
    pub async fn find_active_agent_by_token_lookup_hash(
        &self,
        token_lookup_hash: &str,
    ) -> Result<Option<AgentLookupRow>, sqlx::Error> {
        sqlx::query_as::<_, AgentLookupRow>(
            r#"
            SELECT a.id, a.name, r.name as role_name, r.allowed_capabilities, a.token_hash, a.user_id
            FROM mcp_agents a
            JOIN agent_roles r ON a.role_id = r.id
            WHERE a.token_lookup_hash = $1 AND a.is_active = true
            "#,
        )
        .bind(token_lookup_hash)
        .fetch_optional(&self.db_pool)
        .await
    }

    /// Touch `mcp_agents.last_connected_at` (fire-and-forget by callers).
    pub async fn touch_agent_last_connected(&self, agent_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE mcp_agents SET last_connected_at = NOW() WHERE id = $1")
            .bind(agent_id)
            .execute(&self.db_pool)
            .await?;
        Ok(())
    }

    /// Lazy upsert of a synthetic users row to satisfy FK constraints when the
    /// agent's user_id was issued by an external OAuth/SSO provider before
    /// the local DB row was written. ON CONFLICT (id) DO NOTHING keeps it
    /// idempotent and safe to call on every request.
    pub async fn ensure_user_row_for_agent(
        &self,
        user_id: Uuid,
        synthetic_email: &str,
    ) -> Result<()> {
        // MCP-709 (2026-05-13): use a real bcrypt hash (process-wide
        // cached) instead of the pre-fix malformed `"$2b$12$00...00"`.
        // See the doc comment on `SYNTHETIC_PASSWORD_HASH` for the
        // timing-oracle enumeration leak this closes.
        sqlx::query(
            "INSERT INTO users \
             (id, email, password_hash, is_active, failed_login_attempts, totp_enabled, \
              created_at, updated_at) \
             VALUES ($1, $2, $3, true, 0, false, NOW(), NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(user_id)
        .bind(synthetic_email)
        .bind(synthetic_password_hash())
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }
}

/// Agent lookup row returned by `find_active_agent_by_token_lookup_hash`.
/// `derive(sqlx::FromRow)` lets it work with the same query the original
/// inline lookup used.
#[derive(Debug, sqlx::FromRow)]
pub struct AgentLookupRow {
    pub id: Uuid,
    pub name: String,
    pub role_name: String,
    pub allowed_capabilities: Vec<String>,
    pub token_hash: String,
    pub user_id: Option<Uuid>,
}

#[cfg(test)]
mod synthetic_hash_tests {
    use super::synthetic_password_hash;

    /// MCP-709: regression guard for the timing-oracle fix. The hash
    /// MUST be a structurally valid bcrypt string — 60 chars,
    /// `$2b$` or `$2a$` or `$2y$` prefix, cost field, 22-char salt,
    /// 31-char hash. Pre-fix the literal `"$2b$12$00...00"` was 49
    /// chars and bcrypt::verify rejected it as malformed in ~0 ms,
    /// distinguishable from a real verify (~100 ms at cost=12).
    #[test]
    fn synthetic_hash_is_structurally_valid_bcrypt() {
        let h = synthetic_password_hash();
        assert_eq!(
            h.len(),
            60,
            "bcrypt hash must be exactly 60 chars; got {}",
            h.len()
        );
        assert!(
            h.starts_with("$2b$") || h.starts_with("$2a$") || h.starts_with("$2y$"),
            "bcrypt hash must start with $2b$/$2a$/$2y$; got {}",
            &h[..h.len().min(8)]
        );
    }

    /// MCP-709: the cached hash is deterministic within a process —
    /// subsequent calls return the same Arc-cached value (not a new
    /// bcrypt computation). Sanity check that OnceLock semantics hold.
    #[test]
    fn synthetic_hash_is_process_stable() {
        let a = synthetic_password_hash();
        let b = synthetic_password_hash();
        assert_eq!(a, b);
    }

    /// MCP-709: bcrypt::verify against the synthetic hash with any
    /// caller-supplied password MUST return Ok(false), not Err. An
    /// Err return propagates through the `??` at talos-auth/src/lib.rs:674
    /// as an internal error rather than the generic "Login failed"
    /// path — and Err returns nearly-instantly, recreating the timing
    /// leak. Ok(false) takes the full bcrypt cost and routes through
    /// the failed_login_attempts increment / generic-error path.
    #[test]
    fn bcrypt_verify_returns_false_not_err() {
        let h = synthetic_password_hash();
        let result = bcrypt::verify("any password an attacker would try", h);
        assert!(
            matches!(result, Ok(false)),
            "bcrypt::verify against synthetic hash must return Ok(false); got {:?}",
            result
        );
    }
}
