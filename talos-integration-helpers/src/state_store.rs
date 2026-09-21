//! Shared watch-channel row plumbing over the `integration_state`
//! primitive, plus the create-lock map both reference integrations
//! use to serialize channel creation.
//!
//! The store owns the `execute_op` boilerplate (op construction +
//! the `"integration_state <op> failed: {:?}"` error wrapping —
//! identical strings in gmail and gcal) and the 14-day TTL grace
//! rule. Row DECODING stays in each integration: the row structs,
//! `serde` context strings, and not-found error text are
//! provider-specific by design.

use anyhow::{anyhow, Result};
use chrono::Utc;
use dashmap::DashMap;
use std::hash::Hash;
use std::sync::Arc;
use talos_integration_state::execute_op;
use talos_memory::integration_state_rpc::{
    IndexedSlots, IntegrationOp, IntegrationOpResult, IntegrationStateError, ListFilter,
    StoredEntry,
};
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

/// TTL grace past the upstream expiration: always 14 days
/// (`docs/integration-pattern.md`). Gives the hourly renewal
/// scheduler ≥14 full-day retry windows past expiry before the row is
/// swept — the 5-minute grace gcal started with caused silent row
/// disappearance during OAuth-dead streaks (commit `e43430b`).
pub const TTL_GRACE_SECONDS: i64 = 14 * 24 * 3600;

/// Row TTL from an upstream expiration: expiration + 14-day grace,
/// floored at one hour so an already-past expiration (unexpected, but
/// refusing to write would break create entirely) still gives the
/// scheduler at least one cycle to see + retry.
///
/// Happy-path rows are deleted explicitly by renew/stop paths; this
/// TTL only fires for truly abandoned rows.
pub fn ttl_with_grace(expiration_ms: i64) -> Option<u64> {
    let ttl_ms = expiration_ms + TTL_GRACE_SECONDS * 1000 - Utc::now().timestamp_millis();
    if ttl_ms > 0 {
        Some((ttl_ms / 1000) as u64)
    } else {
        Some(3600) // floor: at least one scheduler cycle
    }
}

/// Thin, user-scoped handle over `integration_state` for one
/// integration's watch rows. Cheap to construct per call (`PgPool` is
/// `Arc`-backed).
///
/// Tenancy: every method takes the owning `user_id` and routes through
/// `execute_op`, whose row scoping is `(integration_name, user_id,
/// key)` — cross-user access is impossible by construction.
pub struct ChannelStore {
    pool: sqlx::PgPool,
    integration_name: &'static str,
    key_prefix: &'static str,
}

impl ChannelStore {
    pub fn new(
        pool: sqlx::PgPool,
        integration_name: &'static str,
        key_prefix: &'static str,
    ) -> Self {
        Self {
            pool,
            integration_name,
            key_prefix,
        }
    }

    /// Build the `key` column value for a given channel uuid
    /// (`"watch/{uuid}"` for gmail, `"channel/{uuid}"` for gcal).
    pub fn key(&self, id: Uuid) -> String {
        format!("{}{}", self.key_prefix, id)
    }

    /// Upsert a row keyed by `id`. Callers pass the serialized row
    /// value, TTL (usually [`ttl_with_grace`]) and every indexed slot
    /// so webhook/renewal lookups work consistently.
    pub async fn set(
        &self,
        user_id: Uuid,
        id: Uuid,
        value: serde_json::Value,
        ttl_seconds: Option<u64>,
        slots: IndexedSlots,
    ) -> Result<()> {
        execute_op(
            &self.pool,
            self.integration_name,
            user_id,
            IntegrationOp::Set {
                key: self.key(id),
                value,
                ttl_seconds,
                slots,
            },
        )
        .await
        .map_err(|e| anyhow!("integration_state set failed: {:?}", e))?;
        Ok(())
    }

    /// Delete a row keyed by `id`.
    pub async fn delete(&self, user_id: Uuid, id: Uuid) -> Result<()> {
        execute_op(
            &self.pool,
            self.integration_name,
            user_id,
            IntegrationOp::Delete { key: self.key(id) },
        )
        .await
        .map_err(|e| anyhow!("integration_state delete failed: {:?}", e))?;
        Ok(())
    }

    /// Get a row by `id`. **Three-way**, and that is the whole point:
    ///
    /// * `Ok(Some(entry))` — the row exists.
    /// * `Ok(None)` — the row genuinely does not exist (or its TTL has
    ///   passed). `execute_op` signals this as
    ///   `Err(IntegrationStateError::KeyNotFound)`; it is an ANSWER, not
    ///   a failure, so it is folded into the success side here.
    /// * `Err(_)` — we could not look: pool timeout, Postgres restart,
    ///   decrypt/projection drift. Nothing may be concluded about
    ///   whether the row exists.
    ///
    /// Before this split every absent key arrived as
    /// `Err("integration_state get failed: KeyNotFound")`, so `Ok(None)`
    /// was unreachable and every caller had to collapse the two —
    /// which is how a database outage came to be reported as
    /// "Watch not found" (404) on the probe handlers and, worse, as a
    /// SUCCESSFUL stop on the idempotent `stop_watch` paths.
    ///
    /// A non-`Entry` success variant cannot occur for a `Get` (the op
    /// returns `Entry` or errors), so it is a protocol violation and is
    /// reported as one rather than being laundered into "absent".
    pub async fn get_entry(&self, user_id: Uuid, id: Uuid) -> Result<Option<StoredEntry>> {
        match execute_op(
            &self.pool,
            self.integration_name,
            user_id,
            IntegrationOp::Get { key: self.key(id) },
        )
        .await
        {
            Ok(IntegrationOpResult::Entry { entry }) => Ok(Some(entry)),
            Ok(other) => Err(anyhow!(
                "integration_state get returned a non-entry result: {:?}",
                other
            )),
            Err(IntegrationStateError::KeyNotFound) => Ok(None),
            Err(e) => Err(anyhow!("integration_state get failed: {:?}", e)),
        }
    }

    /// List rows matching `filter`. Non-`Entries` success variants
    /// collapse to an empty vec (pre-extraction `_ => Ok(vec![])`
    /// behavior at every call site this serves).
    pub async fn list_entries(
        &self,
        user_id: Uuid,
        filter: ListFilter,
        limit: u32,
    ) -> Result<Vec<StoredEntry>> {
        match execute_op(
            &self.pool,
            self.integration_name,
            user_id,
            IntegrationOp::List { filter, limit },
        )
        .await
        .map_err(|e| anyhow!("integration_state list failed: {:?}", e))?
        {
            IntegrationOpResult::Entries { entries } => Ok(entries),
            _ => Ok(vec![]),
        }
    }
}

/// Per-key async mutex map serializing watch-channel create/renew so
/// two concurrent callers can't both pass the "no existing channel"
/// check and register with the upstream twice.
///
/// Key granularity is the integration's uniqueness grain — gmail:
/// `(user_id, integration_id)` (one watch per mailbox); gcal:
/// `(user_id, integration_id, calendar_id)` (one per calendar).
///
/// [`Self::acquire`] is process-local. [`Self::acquire_fleet`] adds the
/// cross-controller half — every controller replica runs the renewal loop
/// and serves the create endpoints — and is what create/renew paths that
/// call an upstream API must use.
pub struct CreateLockMap<K: Eq + Hash> {
    map: DashMap<K, Arc<AsyncMutex<()>>>,
}

impl<K: Eq + Hash> Default for CreateLockMap<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Eq + Hash> CreateLockMap<K> {
    pub fn new() -> Self {
        Self {
            map: DashMap::new(),
        }
    }

    /// Take the lock for `key`, creating it on demand. The returned
    /// guard must be held until the upstream API call + row write are
    /// complete.
    pub async fn acquire(&self, key: K) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = self
            .map
            .entry(key)
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone();
        lock.lock_owned().await
    }

    /// Take the lock for `key` across the whole controller FLEET.
    ///
    /// Two layers, in this order:
    /// 1. the process-local mutex, so N in-process waiters for one key queue
    ///    in memory and hold at most ONE database connection between them;
    /// 2. a Postgres transaction-scoped advisory lock on `fleet_key`, which
    ///    BLOCKS until the other replica is done. Blocking (not try-lock) is
    ///    the point: the second caller then runs its own "does a channel
    ///    already exist?" check and reuses what the first created, instead of
    ///    registering with the upstream a second time.
    ///
    /// The guard owns the transaction; dropping it rolls the transaction back
    /// and the lock goes with it, including when the holder's process dies.
    /// A wait longer than [`FLEET_LOCK_TIMEOUT`] is an ERROR, never a reason
    /// to proceed unlocked.
    ///
    /// `fleet_key` must name the integration and the same grain as `key`
    /// (e.g. `gcal:<user>:<integration>:<calendar>`). It is only ever a bind
    /// parameter to `hashtextextended`, so its content cannot reach SQL text;
    /// a 64-bit hash collision merely serializes two unrelated creates.
    pub async fn acquire_fleet(
        &self,
        pool: &sqlx::Pool<sqlx::Postgres>,
        key: K,
        fleet_key: &str,
    ) -> Result<FleetCreateGuard, sqlx::Error> {
        let local = self.acquire(key).await;
        let mut tx = pool.begin().await?;
        sqlx::query(FLEET_LOCK_TIMEOUT_SQL)
            .execute(&mut *tx)
            .await?;
        sqlx::query(FLEET_LOCK_SQL)
            .bind(fleet_key)
            .execute(&mut *tx)
            .await?;
        Ok(FleetCreateGuard {
            _tx: tx,
            _local: local,
        })
    }

    /// Evict idle locks so churn doesn't accumulate one mutex per key
    /// forever. `Arc::strong_count == 1` (only the map's copy) is the
    /// idle signal; a later `acquire` re-creates on demand. Call from
    /// an hourly sweep.
    pub fn cleanup(&self) {
        self.map.retain(|_k, lock| Arc::strong_count(lock) > 1);
    }
}

/// How long [`CreateLockMap::acquire_fleet`] waits for another replica. The
/// holder is inside one upstream API call (30 s client timeout) plus a row
/// write, so a longer wait means a stuck holder, not a slow one.
pub const FLEET_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

/// `SET LOCAL` cannot bind parameters; the value is this crate's constant,
/// pinned equal to [`FLEET_LOCK_TIMEOUT`] by a unit test.
const FLEET_LOCK_TIMEOUT_SQL: &str = "SET LOCAL lock_timeout = '45s'";

const FLEET_LOCK_SQL: &str = "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))";

/// Held for the length of one create/renew. Field order is drop order: the
/// database lock is released BEFORE the local mutex, so the next in-process
/// waiter never finds the fleet lock still held by its own predecessor.
#[must_use = "dropping the guard releases the fleet lock"]
pub struct FleetCreateGuard {
    _tx: sqlx::Transaction<'static, sqlx::Postgres>,
    _local: tokio::sync::OwnedMutexGuard<()>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_with_grace_applies_14_day_grace() {
        let one_day_out = Utc::now().timestamp_millis() + 24 * 3600 * 1000;
        let ttl = ttl_with_grace(one_day_out).unwrap();
        let expected = (15 * 24 * 3600) as u64; // 1 day + 14-day grace
        assert!(
            ttl > expected - 5 && ttl <= expected,
            "ttl {ttl} not within a few seconds of {expected}"
        );
    }

    #[test]
    fn ttl_with_grace_floors_past_expirations_at_one_hour() {
        // Expiration far enough past that even the grace is consumed.
        let long_gone = Utc::now().timestamp_millis() - (TTL_GRACE_SECONDS + 10) * 1000;
        assert_eq!(ttl_with_grace(long_gone), Some(3600));
    }

    #[test]
    fn the_lock_timeout_statement_matches_the_constant() {
        assert_eq!(
            FLEET_LOCK_TIMEOUT_SQL,
            format!(
                "SET LOCAL lock_timeout = '{}s'",
                FLEET_LOCK_TIMEOUT.as_secs()
            )
        );
    }

    #[tokio::test]
    async fn create_lock_map_serializes_same_key() {
        let locks: Arc<CreateLockMap<(Uuid, Uuid)>> = Arc::new(CreateLockMap::new());
        let key = (Uuid::new_v4(), Uuid::new_v4());

        let guard = locks.acquire(key).await;
        // Same key: second acquire must block while the guard lives.
        let contender = {
            let locks = locks.clone();
            tokio::spawn(async move { locks.acquire(key).await })
        };
        tokio::task::yield_now().await;
        assert!(!contender.is_finished(), "same-key acquire should block");

        // Different key proceeds immediately.
        let _other = locks.acquire((Uuid::new_v4(), Uuid::new_v4())).await;

        drop(guard);
        contender.await.unwrap();
    }

    #[tokio::test]
    async fn create_lock_map_cleanup_evicts_only_idle_locks() {
        let locks: CreateLockMap<u32> = CreateLockMap::new();
        let held = locks.acquire(1).await;
        drop(locks.acquire(2).await); // idle immediately

        locks.cleanup();
        assert!(locks.map.contains_key(&1), "held lock must survive sweep");
        assert!(!locks.map.contains_key(&2), "idle lock must be evicted");
        drop(held);
    }
}
