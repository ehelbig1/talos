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
    IndexedSlots, IntegrationOp, IntegrationOpResult, ListFilter, StoredEntry,
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

    /// Get a row by `id`. Note `execute_op` returns `Err(KeyNotFound)`
    /// for missing keys, so a missing row surfaces as
    /// `Err("integration_state get failed: KeyNotFound")` — exactly
    /// the pre-extraction behavior. `Ok(None)` only covers the
    /// (never-observed) non-`Entry` success variant; callers map it to
    /// their own not-found message.
    pub async fn get_entry(&self, user_id: Uuid, id: Uuid) -> Result<Option<StoredEntry>> {
        match execute_op(
            &self.pool,
            self.integration_name,
            user_id,
            IntegrationOp::Get { key: self.key(id) },
        )
        .await
        .map_err(|e| anyhow!("integration_state get failed: {:?}", e))?
        {
            IntegrationOpResult::Entry { entry } => Ok(Some(entry)),
            _ => Ok(None),
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
/// Process-local; cross-controller coordination would require a Redis
/// or DB advisory lock. Single-controller is the current deployment.
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

    /// Evict idle locks so churn doesn't accumulate one mutex per key
    /// forever. `Arc::strong_count == 1` (only the map's copy) is the
    /// idle signal; a later `acquire` re-creates on demand. Call from
    /// an hourly sweep.
    pub fn cleanup(&self) {
        self.map.retain(|_k, lock| Arc::strong_count(lock) > 1);
    }
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
