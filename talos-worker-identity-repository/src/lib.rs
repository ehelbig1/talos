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

pub struct WorkerIdentityRepository {
    db_pool: PgPool,
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

        // Serialise per worker_id — cheap (boot-time frequency) and closes the
        // count-then-insert race on the cap.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(worker_id)
            .execute(&mut *tx)
            .await
            .context("advisory lock")?;

        // Single gated upsert: the INSERT ... SELECT emits a row ONLY when the
        // worker is under the cap OR this exact key already exists (idempotent
        // path is always allowed). A new key at the cap yields zero rows — no
        // insert, no ON CONFLICT — which we read back as CapReached. Atomic; no
        // separate count-then-insert window.
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
        .execute(&mut *tx)
        .await
        .context("gated upsert")?;

        tx.commit().await.context("commit register tx")?;

        Ok(if res.rows_affected() == 1 {
            RegisterOutcome::Registered
        } else {
            RegisterOutcome::CapReached
        })
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
