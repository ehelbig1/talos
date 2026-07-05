//! `WorkerIdentityRepository` — persistence for the RFC 0010 P2 inc.4
//! `worker_identities` table: the dynamic registry of per-worker Ed25519 public
//! keys the controller unions with the static `TALOS_WORKER_PUBLIC_KEYS` env
//! registry when verifying worker-signed `JobResult` / RPC.
//!
//! Rows hold only PUBLIC keys, so the trust boundary is entirely on WRITE — the
//! registration path (inc.4c) authenticates callers before calling
//! [`WorkerIdentityRepository::register`]. This layer is deliberately dumb about
//! auth (it trusts its caller) and owns only SQL correctness, the per-worker
//! active-key cap, and fail-loud row decoding.
//!
//! Also owns `worker_provisioning_tokens` (P2 hardening inc.2): single-use,
//! expiring, optionally worker_id-bound registration tokens, stored as SHA-256
//! hashes. [`WorkerIdentityRepository::register_with_provisioning_token`]
//! consumes + registers atomically in one transaction.

use anyhow::{anyhow, Context, Result};
use sqlx::{PgPool, Row};

/// Ceiling on simultaneously-ACTIVE keys per `worker_id`. Comfortably covers
/// blue/green + rotation overlap while bounding how far a compromised registrant
/// (or a buggy pod re-registering fresh keys in a loop) can inflate the table.
/// A genuine rotation deactivates the old key, so steady state is 1–2.
pub const MAX_ACTIVE_KEYS_PER_WORKER: i64 = 4;

/// One `(worker_id, public_key)` pair from the active registry — the minimal
/// shape the controller's refresh task merges into the verifying-key snapshot.
#[derive(Debug, Clone)]
pub struct WorkerKeyEntry {
    pub worker_id: String,
    /// Raw 32-byte Ed25519 verifying key.
    pub public_key: [u8; 32],
}

/// A full row for operator/admin listing surfaces. `public_key` is safe to
/// expose (it is public); no secret material lives in this table.
#[derive(Debug, Clone)]
pub struct WorkerIdentityRow {
    pub worker_id: String,
    pub public_key: [u8; 32],
    pub supports_sealing: bool,
    pub active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_seen_at: chrono::DateTime<chrono::Utc>,
}

/// Outcome of a [`WorkerIdentityRepository::register`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// The key is now active (fresh insert or idempotent re-registration of an
    /// existing key — the latter also refreshes `last_seen_at`).
    Registered,
    /// Refused: `worker_id` already holds [`MAX_ACTIVE_KEYS_PER_WORKER`] active
    /// keys and this is a NEW key. Deactivate an old key before adding another.
    CapReached,
}

/// Outcome of a [`WorkerIdentityRepository::register_tofu`] call — the
/// trust-on-first-use rule the shared-token network registration path enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TofuOutcome {
    /// The key is active: either this `worker_id` had no history at all (first
    /// use — the key is now its trusted identity) or the submitted key IS the
    /// worker's existing ACTIVE key (idempotent boot-time refresh; bumps
    /// `last_seen_at` and the `supports_sealing` bit).
    Registered,
    /// Refused: `worker_id` already has registration history and the submitted
    /// key is not one of its ACTIVE keys. Covers all three impersonation /
    /// revocation-bypass shapes: a DIFFERENT key while active keys exist, a
    /// re-activation attempt on a deliberately deactivated key, and a claim on
    /// a decommissioned `worker_id` (rows exist, all inactive). Rotation,
    /// revocation reversal, and identity re-issue are operator actions
    /// (`register-worker-identity` CLI / a worker_id-bound provisioning token),
    /// never a shared-bearer-token network call.
    IdentityConflict,
}

/// Outcome of [`WorkerIdentityRepository::register_with_provisioning_token`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRegisterOutcome {
    /// Token consumed, key active.
    Registered,
    /// No eligible token matched: unknown hash, already used, revoked,
    /// expired, bound to a different `worker_id`, or wildcard while bound-token
    /// enforcement is on. Deliberately ONE variant — the endpoint must not let
    /// a caller distinguish these (the repo logs nothing here; the endpoint
    /// emits a generic 401 and a server-side security log).
    InvalidToken,
    /// Wildcard-token path hit the TOFU rule (see [`TofuOutcome::IdentityConflict`]).
    /// The token was NOT consumed.
    IdentityConflict,
    /// Bound-token path hit the per-worker active-key cap. The token was NOT
    /// consumed.
    CapReached,
}

/// One provisioning-token row for operator listing — metadata only, never the
/// hash (and the raw token is never stored at all).
#[derive(Debug, Clone)]
pub struct ProvisioningTokenRow {
    pub id: uuid::Uuid,
    /// `None` = wildcard token.
    pub worker_id: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub used_by_worker_id: Option<String>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub note: Option<String>,
}

pub struct WorkerIdentityRepository {
    db_pool: PgPool,
}

/// Per-`worker_id` transaction-scoped advisory lock — serialises every
/// registration path touching one worker so count-then-insert style races
/// (cap, TOFU first-use) cannot interleave. Cheap at boot-time frequency.
async fn advisory_lock_worker(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    worker_id: &str,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(worker_id)
        .execute(&mut **tx)
        .await
        .context("advisory lock")?;
    Ok(())
}

/// Operator-grade registration body (see [`WorkerIdentityRepository::register`]
/// for semantics). Runs inside the caller's transaction; the caller must hold
/// the per-worker advisory lock.
///
/// Single gated upsert: the INSERT ... SELECT emits a row ONLY when the worker
/// is under the cap OR this exact key already exists (idempotent path is
/// always allowed). A new key at the cap yields zero rows — no insert, no
/// ON CONFLICT — read back as `CapReached`. Atomic; no separate
/// count-then-insert window.
async fn register_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    worker_id: &str,
    public_key: &[u8; 32],
    supports_sealing: bool,
) -> Result<RegisterOutcome> {
    let res = sqlx::query(
        "INSERT INTO worker_identities (worker_id, public_key, supports_sealing)
         SELECT $1, $2, $3
         WHERE (SELECT count(*) FROM worker_identities
                WHERE worker_id = $1 AND active) < $4
            OR EXISTS (SELECT 1 FROM worker_identities
                       WHERE worker_id = $1 AND public_key = $2)
         ON CONFLICT (worker_id, public_key) DO UPDATE
            SET active = true,
                supports_sealing = EXCLUDED.supports_sealing,
                last_seen_at = now()",
    )
    .bind(worker_id)
    .bind(&public_key[..])
    .bind(supports_sealing)
    .bind(MAX_ACTIVE_KEYS_PER_WORKER)
    .execute(&mut **tx)
    .await
    .context("gated upsert")?;

    Ok(if res.rows_affected() == 1 {
        RegisterOutcome::Registered
    } else {
        RegisterOutcome::CapReached
    })
}

/// Trust-on-first-use registration body (see
/// [`WorkerIdentityRepository::register_tofu`] for semantics). Runs inside the
/// caller's transaction; the caller must hold the per-worker advisory lock.
async fn register_tofu_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    worker_id: &str,
    public_key: &[u8; 32],
    supports_sealing: bool,
) -> Result<TofuOutcome> {
    // Exact-row lookup: does this (worker_id, key) pair already exist, and is
    // it live? Typed query_scalar — no silent-default reads (check 52).
    let exact: Option<bool> = sqlx::query_scalar(
        "SELECT active FROM worker_identities WHERE worker_id = $1 AND public_key = $2",
    )
    .bind(worker_id)
    .bind(&public_key[..])
    .fetch_optional(&mut **tx)
    .await
    .context("tofu exact-row lookup")?;

    match exact {
        // Idempotent refresh of the worker's own ACTIVE key.
        Some(true) => {
            sqlx::query(
                "UPDATE worker_identities
                 SET supports_sealing = $3, last_seen_at = now()
                 WHERE worker_id = $1 AND public_key = $2",
            )
            .bind(worker_id)
            .bind(&public_key[..])
            .bind(supports_sealing)
            .execute(&mut **tx)
            .await
            .context("tofu refresh")?;
            Ok(TofuOutcome::Registered)
        }
        // The key exists but was deliberately deactivated — re-activating it
        // here would let a shared-token holder undo a revocation.
        Some(false) => Ok(TofuOutcome::IdentityConflict),
        None => {
            let history: i64 =
                sqlx::query_scalar("SELECT count(*) FROM worker_identities WHERE worker_id = $1")
                    .bind(worker_id)
                    .fetch_one(&mut **tx)
                    .await
                    .context("tofu history count")?;
            if history == 0 {
                sqlx::query(
                    "INSERT INTO worker_identities (worker_id, public_key, supports_sealing)
                     VALUES ($1, $2, $3)",
                )
                .bind(worker_id)
                .bind(&public_key[..])
                .bind(supports_sealing)
                .execute(&mut **tx)
                .await
                .context("tofu first-use insert")?;
                Ok(TofuOutcome::Registered)
            } else {
                Ok(TofuOutcome::IdentityConflict)
            }
        }
    }
}

impl WorkerIdentityRepository {
    #[must_use]
    pub fn new(db_pool: PgPool) -> Self {
        Self { db_pool }
    }

    /// Register (or idempotently refresh) a worker's public key.
    ///
    /// Idempotent on `(worker_id, public_key)`: re-registering an existing key
    /// re-activates it (rotation reversal is a deliberate operator/worker action
    /// gated by the caller's auth) and bumps `last_seen_at`. A genuinely NEW key
    /// is admitted only while the worker is under the active-key cap.
    ///
    /// Concurrency-safe: a per-`worker_id` transaction-scoped advisory lock
    /// serialises concurrent registrations so two racing NEW-key inserts cannot
    /// both slip past the cap (the TOCTOU the webhook repo's `try_create_under_cap`
    /// closes the same way).
    pub async fn register(
        &self,
        worker_id: &str,
        public_key: &[u8; 32],
        supports_sealing: bool,
    ) -> Result<RegisterOutcome> {
        let mut tx = self.db_pool.begin().await.context("begin register tx")?;
        advisory_lock_worker(&mut tx, worker_id).await?;
        let outcome = register_in_tx(&mut tx, worker_id, public_key, supports_sealing).await?;
        tx.commit().await.context("commit register tx")?;
        Ok(outcome)
    }

    /// Trust-on-first-use registration — the rule for the NETWORK
    /// self-registration path, where the caller is authenticated only as "some
    /// pod holding the shared registration token", not as a specific worker.
    ///
    /// A `worker_id`'s FIRST registered key becomes its trusted identity; from
    /// then on this path only accepts an idempotent refresh of that exact
    /// ACTIVE key. Anything else — a different key, a deactivated key, a new
    /// key for a fully-retired `worker_id` — is [`TofuOutcome::IdentityConflict`]:
    /// without this rule, any shared-token holder could register its own key
    /// under another worker's id and impersonate it for result signing and
    /// (P3) secret claims. Legitimate key rotation always accompanies an
    /// operator (worker signing keys are provisioned via Secret, never
    /// generated in-pod), so the operator paths — [`Self::register`] via the
    /// CLI — carry the rotation semantics instead.
    ///
    /// Same advisory-lock serialisation as [`Self::register`], so a concurrent
    /// first-use race on one `worker_id` admits exactly one key.
    pub async fn register_tofu(
        &self,
        worker_id: &str,
        public_key: &[u8; 32],
        supports_sealing: bool,
    ) -> Result<TofuOutcome> {
        let mut tx = self.db_pool.begin().await.context("begin tofu tx")?;
        advisory_lock_worker(&mut tx, worker_id).await?;
        let outcome = register_tofu_in_tx(&mut tx, worker_id, public_key, supports_sealing).await?;
        tx.commit().await.context("commit tofu tx")?;
        Ok(outcome)
    }

    /// Redeem a provisioning token and register the key, atomically.
    ///
    /// One transaction: consume the token (single `UPDATE … WHERE used_at IS
    /// NULL … RETURNING` — the row lock makes two concurrent redeems admit
    /// exactly one) then register under the semantics the token's binding
    /// earns:
    /// * **worker_id-BOUND token** — the mint was an explicit operator action
    ///   for that one worker, so it carries operator-grade [`Self::register`]
    ///   semantics: new key, rotation, or re-activation, under the active-key
    ///   cap. The token must be bound to the `worker_id` being registered.
    /// * **wildcard token** (`worker_id IS NULL`, migration compat) — like the
    ///   shared token it replaces, it proves nothing about WHICH worker, so
    ///   TOFU semantics apply ([`Self::register_tofu`]). Refused outright when
    ///   `require_bound` is set (`TALOS_WORKER_REG_REQUIRE_BOUND_TOKEN=1`) —
    ///   inside the consume SQL, so an ineligible token is never burned.
    ///
    /// A REFUSED registration (TOFU conflict / cap) ROLLS BACK the
    /// consumption: a failed attempt does not burn the operator's token, and
    /// because the rollback releases the row lock, a racing legitimate redeem
    /// of the same token can still win afterwards.
    ///
    /// `token_hash` is the SHA-256 hex of the raw bearer token — the raw value
    /// is never stored or compared in SQL (lint check 41 discipline; hashing
    /// happens at the endpoint, so this layer never sees the credential).
    pub async fn register_with_provisioning_token(
        &self,
        token_hash: &str,
        worker_id: &str,
        public_key: &[u8; 32],
        supports_sealing: bool,
        require_bound: bool,
    ) -> Result<TokenRegisterOutcome> {
        let mut tx = self.db_pool.begin().await.context("begin token tx")?;
        advisory_lock_worker(&mut tx, worker_id).await?;

        // Atomic single-use consume. All eligibility conditions live in the
        // WHERE so an ineligible call cannot consume: unused, unrevoked,
        // unexpired, binding matches the registering worker_id (NULL =
        // wildcard), and wildcard only while enforcement is off.
        let consumed: Option<Option<String>> = sqlx::query_scalar(
            "UPDATE worker_provisioning_tokens
             SET used_at = now(), used_by_worker_id = $2
             WHERE token_hash = $1
               AND used_at IS NULL
               AND revoked_at IS NULL
               AND expires_at > now()
               AND (worker_id IS NULL OR worker_id = $2)
               AND (worker_id IS NOT NULL OR NOT $3)
             RETURNING worker_id",
        )
        .bind(token_hash)
        .bind(worker_id)
        .bind(require_bound)
        .fetch_optional(&mut *tx)
        .await
        .context("consume provisioning token")?;

        let Some(binding) = consumed else {
            tx.rollback().await.context("rollback invalid token")?;
            return Ok(TokenRegisterOutcome::InvalidToken);
        };

        let outcome = if binding.is_some() {
            match register_in_tx(&mut tx, worker_id, public_key, supports_sealing).await? {
                RegisterOutcome::Registered => TokenRegisterOutcome::Registered,
                RegisterOutcome::CapReached => TokenRegisterOutcome::CapReached,
            }
        } else {
            match register_tofu_in_tx(&mut tx, worker_id, public_key, supports_sealing).await? {
                TofuOutcome::Registered => TokenRegisterOutcome::Registered,
                TofuOutcome::IdentityConflict => TokenRegisterOutcome::IdentityConflict,
            }
        };

        if outcome == TokenRegisterOutcome::Registered {
            tx.commit().await.context("commit token registration")?;
        } else {
            // Registration refused — undo the consumption so the token
            // survives for a corrected retry.
            tx.rollback()
                .await
                .context("rollback refused token registration")?;
        }
        Ok(outcome)
    }

    /// Record a freshly minted provisioning token (hash only — the caller
    /// shows the raw token once and forgets it). Returns the row id operators
    /// use to list/revoke.
    pub async fn create_provisioning_token(
        &self,
        token_hash: &str,
        worker_id: Option<&str>,
        expires_at: chrono::DateTime<chrono::Utc>,
        note: Option<&str>,
    ) -> Result<uuid::Uuid> {
        let id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO worker_provisioning_tokens (token_hash, worker_id, expires_at, note)
             VALUES ($1, $2, $3, $4)
             RETURNING id",
        )
        .bind(token_hash)
        .bind(worker_id)
        .bind(expires_at)
        .bind(note)
        .fetch_one(&self.db_pool)
        .await
        .context("insert provisioning token")?;
        Ok(id)
    }

    /// Revoke an un-redeemed provisioning token. Returns `true` if a live
    /// (unused, unrevoked) token was revoked, `false` otherwise — revoking a
    /// consumed token is a no-op so the redemption record stays truthful.
    pub async fn revoke_provisioning_token(&self, id: uuid::Uuid) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE worker_provisioning_tokens SET revoked_at = now()
             WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL",
        )
        .bind(id)
        .execute(&self.db_pool)
        .await
        .context("revoke provisioning token")?;
        Ok(res.rows_affected() > 0)
    }

    /// Append a provisioning-token lifecycle event to `admin_event_log` — the
    /// same audit trail the platform's operator mutations write, keyed on
    /// `resource_type = 'worker_provisioning_token'` / the token row id.
    /// `user_id` is NULL: mints/revokes happen from the DB-credentialed
    /// operator CLI, where holding DB credentials IS the authorization and no
    /// platform user exists. Callers must never place token material in
    /// `summary`/`details` — mint-site discipline, the raw token is shown once
    /// on the mint stdout and exists nowhere else.
    pub async fn insert_provisioning_token_audit(
        &self,
        event_type: &str,
        token_id: uuid::Uuid,
        summary: &str,
        details: Option<&serde_json::Value>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO admin_event_log
             (user_id, event_type, resource_type, resource_id, summary, details)
             VALUES (NULL, $1, 'worker_provisioning_token', $2, $3, $4)",
        )
        .bind(event_type)
        .bind(token_id)
        .bind(summary)
        .bind(details)
        .execute(&self.db_pool)
        .await
        .context("insert provisioning-token audit event")?;
        Ok(())
    }

    /// All provisioning-token rows for the operator listing surface, newest
    /// first. Exposes metadata only — never `token_hash` (an offline-crackable
    /// digest has no business in ops output).
    pub async fn list_provisioning_tokens(&self) -> Result<Vec<ProvisioningTokenRow>> {
        let rows = sqlx::query(
            "SELECT id, worker_id, created_at, expires_at, used_at, used_by_worker_id,
                    revoked_at, note
             FROM worker_provisioning_tokens
             ORDER BY created_at DESC, id",
        )
        .fetch_all(&self.db_pool)
        .await
        .context("list provisioning tokens")?;

        rows.into_iter()
            .map(|r| {
                Ok(ProvisioningTokenRow {
                    id: r.try_get("id")?,
                    worker_id: r.try_get("worker_id")?,
                    created_at: r.try_get("created_at")?,
                    expires_at: r.try_get("expires_at")?,
                    used_at: r.try_get("used_at")?,
                    used_by_worker_id: r.try_get("used_by_worker_id")?,
                    revoked_at: r.try_get("revoked_at")?,
                    note: r.try_get("note")?,
                })
            })
            .collect()
    }

    /// Every ACTIVE `(worker_id, public_key)` pair. The controller's refresh task
    /// calls this on its interval and merges the result into the verifying-key
    /// snapshot. One indexed scan (partial index `WHERE active`); the table is
    /// small (fleet-sized), so this is cheap.
    pub async fn load_active_registry(&self) -> Result<Vec<WorkerKeyEntry>> {
        let rows = sqlx::query("SELECT worker_id, public_key FROM worker_identities WHERE active")
            .fetch_all(&self.db_pool)
            .await
            .context("load active worker registry")?;

        rows.into_iter()
            .map(|r| {
                // Fail-loud decode (lint check 52): a dropped/renamed column or a
                // wrong-width key errors here rather than silently defaulting to
                // an empty/garbage key that would then fail every verify opaquely.
                let worker_id: String = r.try_get("worker_id")?;
                let public_key = decode_pubkey(&r, &worker_id)?;
                Ok(WorkerKeyEntry {
                    worker_id,
                    public_key,
                })
            })
            .collect()
    }

    /// Soft-retire one key (rotation). Returns `true` if a live key was
    /// deactivated, `false` if it was already inactive / absent. Idempotent.
    pub async fn deactivate(&self, worker_id: &str, public_key: &[u8; 32]) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE worker_identities SET active = false
             WHERE worker_id = $1 AND public_key = $2 AND active",
        )
        .bind(worker_id)
        .bind(&public_key[..])
        .execute(&self.db_pool)
        .await
        .context("deactivate worker key")?;
        Ok(res.rows_affected() > 0)
    }

    /// Whether `worker_id` has at least one ACTIVE key advertising the P3/D3b
    /// claim-sealing capability. Lets the controller seal claim-based to capable
    /// workers and inline (legacy WSK) to the rest during a heterogeneous rollout.
    pub async fn worker_supports_sealing(&self, worker_id: &str) -> Result<bool> {
        let supported: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM worker_identities
             WHERE worker_id = $1 AND active AND supports_sealing)",
        )
        .bind(worker_id)
        .fetch_one(&self.db_pool)
        .await
        .context("query worker sealing capability")?;
        Ok(supported)
    }

    /// Full listing for operator/admin surfaces, newest-key-last within a worker.
    /// Deterministic order (no OFFSET pagination here; ordered for stable output).
    pub async fn list(&self) -> Result<Vec<WorkerIdentityRow>> {
        let rows = sqlx::query(
            "SELECT worker_id, public_key, supports_sealing, active, created_at, last_seen_at
             FROM worker_identities
             ORDER BY worker_id, created_at, public_key",
        )
        .fetch_all(&self.db_pool)
        .await
        .context("list worker identities")?;

        rows.into_iter()
            .map(|r| {
                let worker_id: String = r.try_get("worker_id")?;
                let public_key = decode_pubkey(&r, &worker_id)?;
                Ok(WorkerIdentityRow {
                    worker_id,
                    public_key,
                    supports_sealing: r.try_get("supports_sealing")?,
                    active: r.try_get("active")?,
                    created_at: r.try_get("created_at")?,
                    last_seen_at: r.try_get("last_seen_at")?,
                })
            })
            .collect()
    }
}

/// Decode the `public_key` bytea column into a fixed 32-byte array, erroring
/// loudly (with the offending `worker_id`) on any width mismatch. The DB CHECK
/// already guarantees 32 bytes on write, so this only trips on corruption or a
/// schema change — exactly when a silent default would be dangerous.
fn decode_pubkey(row: &sqlx::postgres::PgRow, worker_id: &str) -> Result<[u8; 32]> {
    let bytes: Vec<u8> = row.try_get("public_key")?;
    let len = bytes.len();
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        anyhow!("worker_identities.public_key for {worker_id} is {len} bytes, expected 32")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests require a migrated Postgres reachable via DATABASE_URL. They
    // no-op (skip) when it is unset so the crate's `cargo test` stays green in
    // environments without a DB; CI's integration lane provides one.
    async fn pool_or_skip() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        Some(
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(2)
                .connect(&url)
                .await
                .expect("connect to DATABASE_URL"),
        )
    }

    // Remove any rows a prior run left for this worker_id so each test starts
    // from a known-empty state (distinct worker_ids keep tests mutually isolated).
    async fn clean(pool: &PgPool, worker_id: &str) {
        sqlx::query("DELETE FROM worker_identities WHERE worker_id = $1")
            .bind(worker_id)
            .execute(pool)
            .await
            .expect("test cleanup delete");
    }

    // A distinct worker_id per test so a shared DB stays isolated without a
    // global cleanup step. `key(n)` makes deterministic distinct 32-byte keys.
    fn key(n: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = n;
        k[31] = n.wrapping_add(7);
        k
    }

    #[tokio::test]
    async fn register_is_idempotent_and_loads_back() {
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let wid = "test-idem-worker";
        clean(&repo.db_pool, wid).await;

        assert_eq!(
            repo.register(wid, &key(1), false).await.unwrap(),
            RegisterOutcome::Registered
        );
        // Re-register the SAME key: idempotent, still one active key.
        assert_eq!(
            repo.register(wid, &key(1), true).await.unwrap(),
            RegisterOutcome::Registered
        );

        let reg = repo.load_active_registry().await.unwrap();
        let mine: Vec<_> = reg.iter().filter(|e| e.worker_id == wid).collect();
        assert_eq!(mine.len(), 1, "idempotent re-register must not duplicate");
        assert_eq!(mine[0].public_key, key(1));
        // The re-register updated the capability bit.
        assert!(repo.worker_supports_sealing(wid).await.unwrap());
    }

    #[tokio::test]
    async fn tofu_first_use_then_idempotent_then_conflicts() {
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let wid = "test-tofu-worker";
        clean(&repo.db_pool, wid).await;

        // First use: no history → key(1) becomes the trusted identity.
        assert_eq!(
            repo.register_tofu(wid, &key(1), false).await.unwrap(),
            TofuOutcome::Registered
        );
        // Idempotent same-key refresh, updating the capability bit.
        assert_eq!(
            repo.register_tofu(wid, &key(1), true).await.unwrap(),
            TofuOutcome::Registered
        );
        assert!(repo.worker_supports_sealing(wid).await.unwrap());

        // A DIFFERENT key for the same worker_id is refused (the gap this
        // closes: shared-token impersonation).
        assert_eq!(
            repo.register_tofu(wid, &key(2), false).await.unwrap(),
            TofuOutcome::IdentityConflict
        );
        // ...and the refusal wrote nothing.
        let active: Vec<_> = repo
            .load_active_registry()
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.worker_id == wid)
            .collect();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].public_key, key(1));
    }

    #[tokio::test]
    async fn tofu_refuses_revoked_key_reactivation_and_retired_id_claims() {
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let wid = "test-tofu-revoked-worker";
        clean(&repo.db_pool, wid).await;

        assert_eq!(
            repo.register_tofu(wid, &key(1), false).await.unwrap(),
            TofuOutcome::Registered
        );
        // Operator revokes the key (compromise / decommission).
        assert!(repo.deactivate(wid, &key(1)).await.unwrap());

        // The revoked key cannot re-activate itself over the network path.
        assert_eq!(
            repo.register_tofu(wid, &key(1), false).await.unwrap(),
            TofuOutcome::IdentityConflict
        );
        // Nor can a NEW key claim the retired worker_id (history exists).
        assert_eq!(
            repo.register_tofu(wid, &key(2), false).await.unwrap(),
            TofuOutcome::IdentityConflict
        );

        // The OPERATOR path still rotates freely: register a new key, and the
        // worker's subsequent boot-time TOFU refresh of that key succeeds.
        assert_eq!(
            repo.register(wid, &key(2), false).await.unwrap(),
            RegisterOutcome::Registered
        );
        assert_eq!(
            repo.register_tofu(wid, &key(2), true).await.unwrap(),
            TofuOutcome::Registered
        );
    }

    // Provisioning-token helpers: the repo treats token_hash as opaque (the
    // endpoint owns SHA-256), so tests can mint with any distinct 64-char id.
    fn hash(tag: &str) -> String {
        format!("{tag:0<64}")
    }

    async fn clean_token(pool: &PgPool, token_hash: &str) {
        sqlx::query("DELETE FROM worker_provisioning_tokens WHERE token_hash = $1")
            .bind(token_hash)
            .execute(pool)
            .await
            .expect("test token cleanup delete");
    }

    fn in_one_hour() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now() + chrono::Duration::hours(1)
    }

    async fn token_used_at(
        repo: &WorkerIdentityRepository,
        id: uuid::Uuid,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        repo.list_provisioning_tokens()
            .await
            .unwrap()
            .into_iter()
            .find(|t| t.id == id)
            .expect("minted token must list")
            .used_at
    }

    #[tokio::test]
    async fn bound_token_is_single_use_and_carries_rotation_semantics() {
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let wid = "test-token-bound-worker";
        let th = hash("bound-rotation");
        clean(&repo.db_pool, wid).await;
        clean_token(&repo.db_pool, &th).await;

        // Worker already has a TOFU-bound identity...
        assert_eq!(
            repo.register_tofu(wid, &key(1), false).await.unwrap(),
            TofuOutcome::Registered
        );
        // ...so a NEW key would be an IdentityConflict on the shared path. A
        // worker_id-BOUND token is the operator's rotation grant: it admits it.
        let id = repo
            .create_provisioning_token(&th, Some(wid), in_one_hour(), Some("rotation"))
            .await
            .unwrap();
        assert_eq!(
            repo.register_with_provisioning_token(&th, wid, &key(2), false, true)
                .await
                .unwrap(),
            TokenRegisterOutcome::Registered
        );
        assert!(token_used_at(&repo, id).await.is_some(), "token consumed");

        // Single use: a second redemption is refused even for a valid request.
        assert_eq!(
            repo.register_with_provisioning_token(&th, wid, &key(3), false, true)
                .await
                .unwrap(),
            TokenRegisterOutcome::InvalidToken
        );
    }

    #[tokio::test]
    async fn concurrent_redeems_of_one_token_admit_exactly_one() {
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = std::sync::Arc::new(WorkerIdentityRepository::new(pool));
        let wid = "test-token-race-worker";
        let th = hash("race");
        clean(&repo.db_pool, wid).await;
        clean_token(&repo.db_pool, &th).await;
        repo.create_provisioning_token(&th, Some(wid), in_one_hour(), None)
            .await
            .unwrap();

        // Two concurrent redeems with different keys. Both would individually
        // succeed; the token's row lock must let exactly one through.
        let (a, b) = tokio::join!(
            {
                let repo = repo.clone();
                let th = th.clone();
                async move {
                    repo.register_with_provisioning_token(&th, wid, &key(10), false, true)
                        .await
                        .unwrap()
                }
            },
            {
                let repo = repo.clone();
                let th = th.clone();
                async move {
                    repo.register_with_provisioning_token(&th, wid, &key(11), false, true)
                        .await
                        .unwrap()
                }
            }
        );
        let registered = [a, b]
            .iter()
            .filter(|o| **o == TokenRegisterOutcome::Registered)
            .count();
        let invalid = [a, b]
            .iter()
            .filter(|o| **o == TokenRegisterOutcome::InvalidToken)
            .count();
        assert_eq!((registered, invalid), (1, 1), "exactly one redeem wins");

        // Exactly one key landed in the registry.
        let mine: Vec<_> = repo
            .load_active_registry()
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.worker_id == wid)
            .collect();
        assert_eq!(mine.len(), 1);
    }

    #[tokio::test]
    async fn expired_revoked_and_mismatched_tokens_refuse_without_consuming() {
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let wid = "test-token-refusals-worker";
        clean(&repo.db_pool, wid).await;

        // Expired.
        let th_expired = hash("expired");
        clean_token(&repo.db_pool, &th_expired).await;
        let id_expired = repo
            .create_provisioning_token(
                &th_expired,
                Some(wid),
                chrono::Utc::now() - chrono::Duration::minutes(1),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            repo.register_with_provisioning_token(&th_expired, wid, &key(1), false, true)
                .await
                .unwrap(),
            TokenRegisterOutcome::InvalidToken
        );
        assert!(token_used_at(&repo, id_expired).await.is_none());

        // Bound to a DIFFERENT worker_id.
        let th_other = hash("otherbound");
        clean_token(&repo.db_pool, &th_other).await;
        let id_other = repo
            .create_provisioning_token(&th_other, Some("some-other-worker"), in_one_hour(), None)
            .await
            .unwrap();
        assert_eq!(
            repo.register_with_provisioning_token(&th_other, wid, &key(1), false, true)
                .await
                .unwrap(),
            TokenRegisterOutcome::InvalidToken
        );
        assert!(token_used_at(&repo, id_other).await.is_none());

        // Revoked.
        let th_revoked = hash("revoked");
        clean_token(&repo.db_pool, &th_revoked).await;
        let id_revoked = repo
            .create_provisioning_token(&th_revoked, Some(wid), in_one_hour(), None)
            .await
            .unwrap();
        assert!(repo.revoke_provisioning_token(id_revoked).await.unwrap());
        assert!(
            !repo.revoke_provisioning_token(id_revoked).await.unwrap(),
            "second revoke is a no-op"
        );
        assert_eq!(
            repo.register_with_provisioning_token(&th_revoked, wid, &key(1), false, true)
                .await
                .unwrap(),
            TokenRegisterOutcome::InvalidToken
        );

        // Nothing registered through any of the refusals.
        assert!(!repo
            .load_active_registry()
            .await
            .unwrap()
            .iter()
            .any(|e| e.worker_id == wid));
    }

    #[tokio::test]
    async fn wildcard_token_tofu_semantics_and_enforcement_flag() {
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let wid = "test-token-wildcard-worker";
        let th = hash("wildcard");
        clean(&repo.db_pool, wid).await;
        clean_token(&repo.db_pool, &th).await;
        let id = repo
            .create_provisioning_token(&th, None, in_one_hour(), Some("migration compat"))
            .await
            .unwrap();

        // Enforcement ON → wildcard refused outright, NOT consumed.
        assert_eq!(
            repo.register_with_provisioning_token(&th, wid, &key(1), false, true)
                .await
                .unwrap(),
            TokenRegisterOutcome::InvalidToken
        );
        assert!(token_used_at(&repo, id).await.is_none());

        // Enforcement OFF → accepted, TOFU semantics, consumed.
        assert_eq!(
            repo.register_with_provisioning_token(&th, wid, &key(1), false, false)
                .await
                .unwrap(),
            TokenRegisterOutcome::Registered
        );
        assert!(token_used_at(&repo, id).await.is_some());

        // A second wildcard token cannot re-bind the now-taken worker_id to a
        // different key (TOFU applies to wildcards) — and the refusal does not
        // burn the new token.
        let th2 = hash("wildcard-second");
        clean_token(&repo.db_pool, &th2).await;
        let id2 = repo
            .create_provisioning_token(&th2, None, in_one_hour(), None)
            .await
            .unwrap();
        assert_eq!(
            repo.register_with_provisioning_token(&th2, wid, &key(2), false, false)
                .await
                .unwrap(),
            TokenRegisterOutcome::IdentityConflict
        );
        assert!(
            token_used_at(&repo, id2).await.is_none(),
            "refusal rolls back"
        );
    }

    #[tokio::test]
    async fn refused_bound_registration_does_not_burn_the_token() {
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let wid = "test-token-cap-worker";
        let th = hash("capbound");
        clean(&repo.db_pool, wid).await;
        clean_token(&repo.db_pool, &th).await;

        // Fill the worker to its active-key cap via the operator path.
        for i in 0..MAX_ACTIVE_KEYS_PER_WORKER as u8 {
            assert_eq!(
                repo.register(wid, &key(i), false).await.unwrap(),
                RegisterOutcome::Registered
            );
        }
        let id = repo
            .create_provisioning_token(&th, Some(wid), in_one_hour(), None)
            .await
            .unwrap();

        // Bound-token redemption hits the cap → refused, token survives.
        assert_eq!(
            repo.register_with_provisioning_token(&th, wid, &key(100), false, true)
                .await
                .unwrap(),
            TokenRegisterOutcome::CapReached
        );
        assert!(token_used_at(&repo, id).await.is_none());

        // Operator frees a slot; the SAME token now redeems.
        assert!(repo.deactivate(wid, &key(0)).await.unwrap());
        assert_eq!(
            repo.register_with_provisioning_token(&th, wid, &key(100), false, true)
                .await
                .unwrap(),
            TokenRegisterOutcome::Registered
        );
    }

    #[tokio::test]
    async fn rotation_overlap_then_cap_then_deactivate() {
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let wid = "test-rotation-worker";
        clean(&repo.db_pool, wid).await;

        // Fill up to the cap with distinct keys — all admitted.
        for i in 0..MAX_ACTIVE_KEYS_PER_WORKER as u8 {
            assert_eq!(
                repo.register(wid, &key(i), false).await.unwrap(),
                RegisterOutcome::Registered
            );
        }
        // One more NEW key is refused.
        assert_eq!(
            repo.register(wid, &key(200), false).await.unwrap(),
            RegisterOutcome::CapReached
        );
        // But re-registering an EXISTING key is still allowed at the cap.
        assert_eq!(
            repo.register(wid, &key(0), false).await.unwrap(),
            RegisterOutcome::Registered
        );

        // Deactivate one, freeing a slot; the new key now fits.
        assert!(repo.deactivate(wid, &key(0)).await.unwrap());
        assert!(
            !repo.deactivate(wid, &key(0)).await.unwrap(),
            "second deactivate is a no-op"
        );
        assert_eq!(
            repo.register(wid, &key(200), false).await.unwrap(),
            RegisterOutcome::Registered
        );

        let active: Vec<_> = repo
            .load_active_registry()
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.worker_id == wid)
            .collect();
        assert_eq!(active.len(), MAX_ACTIVE_KEYS_PER_WORKER as usize);
        assert!(
            !active.iter().any(|e| e.public_key == key(0)),
            "deactivated key must not load"
        );
    }
}
