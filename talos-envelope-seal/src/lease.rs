//! RFC 0010 P3 (D3b) — the Redis lease / single-claim state machine.
//!
//! In-memory [`super::InFlightSeals::take`] is authoritative for single-claim on
//! the dispatching replica. This lease is the **durability / crash-recovery**
//! layer: a per-`exec_id` Redis key with `PX = lease_ms` so that if the
//! dispatching replica dies between dispatch and claim, the key expires and a
//! surviving replica can re-dispatch. The claim CAS (`dispatched → claimed_by`)
//! is a defence-in-depth cross-replica guard.
//!
//! State value forms: `"dispatched"` and `"claimed:<worker_id>"`.
//!
//! Same fail-open posture as `talos-replay-guard`: if Redis is unavailable the
//! lease returns [`ClaimLeaseOutcome::Unavailable`] and the caller falls back to
//! the in-memory `take` (which still enforces single-claim within the replica).

use uuid::Uuid;

/// Outcome of a claim CAS against the Redis lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimLeaseOutcome {
    /// The lease was `dispatched` and is now `claimed:<worker_id>`. Proceed.
    Claimed,
    /// The lease is already `claimed:<worker_id>` by THIS worker (an idempotent
    /// redelivery of the same claim). Proceed as if freshly claimed.
    AlreadyClaimedBySelf,
    /// The lease is `claimed` by a DIFFERENT worker — reject this claim.
    ClaimedByOther,
    /// The lease key is missing/expired — the job should be re-dispatched.
    Missing,
    /// Redis was unreachable — caller falls back to in-memory single-claim.
    Unavailable,
}

/// Atomic CAS lease keyed `envelope:lease:{exec_id}`. Cheap to clone (wraps a
/// multiplexed `ConnectionManager`).
#[derive(Clone)]
pub struct RedisLease {
    conn: redis::aio::ConnectionManager,
    prefix: String,
}

impl RedisLease {
    /// Connect a lease from a shared `redis::Client`.
    pub async fn connect(client: &redis::Client) -> redis::RedisResult<Self> {
        let conn = redis::aio::ConnectionManager::new(client.clone()).await?;
        Ok(Self {
            conn,
            prefix: "envelope:lease:".to_string(),
        })
    }

    /// Override the key prefix (default `envelope:lease:`).
    #[must_use]
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    fn key(&self, exec_id: Uuid) -> String {
        format!("{}{}", self.prefix, exec_id)
    }

    /// Record a dispatch: `SET key "dispatched" PX lease_ms`. Unconditional so a
    /// re-dispatch after expiry resets cleanly. Returns `Ok(())` on success;
    /// Redis errors are surfaced so the caller can log (dispatch proceeds
    /// regardless — the in-memory context is authoritative).
    pub async fn record_dispatch(&self, exec_id: Uuid, lease_ms: u64) -> redis::RedisResult<()> {
        let mut conn = self.conn.clone();
        let res: redis::RedisResult<()> = redis::cmd("SET")
            .arg(self.key(exec_id))
            .arg("dispatched")
            .arg("PX")
            .arg(lease_ms.max(1))
            .query_async(&mut conn)
            .await;
        res
    }

    /// CAS a claim: if the lease is `dispatched`, set it to `claimed:<worker_id>`
    /// (refreshing the TTL) and return [`ClaimLeaseOutcome::Claimed`]. If it is
    /// already `claimed:<this worker>`, return `AlreadyClaimedBySelf`. If claimed
    /// by another, `ClaimedByOther`. If missing, `Missing`. On any Redis error,
    /// `Unavailable` (fail-open to in-memory single-claim).
    ///
    /// The whole read-compare-write runs in one Lua `EVAL`, so it is atomic
    /// across replicas — two racing claims cannot both observe `dispatched`.
    pub async fn try_claim(
        &self,
        exec_id: Uuid,
        worker_id: &str,
        lease_ms: u64,
    ) -> ClaimLeaseOutcome {
        // KEYS[1] = lease key; ARGV[1] = worker_id; ARGV[2] = lease_ms.
        const CAS: &str = r#"
            local cur = redis.call('GET', KEYS[1])
            if cur == false then return 'MISSING' end
            if cur == 'dispatched' then
                redis.call('SET', KEYS[1], 'claimed:' .. ARGV[1], 'PX', ARGV[2])
                return 'CLAIMED'
            end
            if cur == 'claimed:' .. ARGV[1] then return 'SELF' end
            return 'OTHER'
        "#;
        let mut conn = self.conn.clone();
        let res: redis::RedisResult<String> = redis::Script::new(CAS)
            .key(self.key(exec_id))
            .arg(worker_id)
            .arg(lease_ms.max(1))
            .invoke_async(&mut conn)
            .await;
        match res {
            Ok(s) => match s.as_str() {
                "CLAIMED" => ClaimLeaseOutcome::Claimed,
                "SELF" => ClaimLeaseOutcome::AlreadyClaimedBySelf,
                "MISSING" => ClaimLeaseOutcome::Missing,
                _ => ClaimLeaseOutcome::ClaimedByOther,
            },
            Err(e) => {
                tracing::warn!(
                    target: "talos_security",
                    error = %e,
                    "envelope lease: Redis unavailable — falling back to in-memory single-claim"
                );
                ClaimLeaseOutcome::Unavailable
            }
        }
    }

    /// Release a lease (job completed / discarded). Best-effort.
    pub async fn release(&self, exec_id: Uuid) {
        let mut conn = self.conn.clone();
        let res: redis::RedisResult<()> = redis::cmd("DEL")
            .arg(self.key(exec_id))
            .query_async(&mut conn)
            .await;
        let _ = res;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Live-Redis tests. Gated on TALOS_TEST_REDIS_URL so they no-op in
    // environments without a broker (mirrors talos-replay-guard's gating).
    fn redis_client() -> Option<redis::Client> {
        let url = std::env::var("TALOS_TEST_REDIS_URL").ok()?;
        redis::Client::open(url).ok()
    }

    #[tokio::test]
    async fn dispatch_then_single_claim_cas() {
        let Some(client) = redis_client() else {
            eprintln!("skipping: set TALOS_TEST_REDIS_URL to run");
            return;
        };
        let lease = RedisLease::connect(&client)
            .await
            .unwrap()
            .with_prefix("test:envelope:lease:");
        let exec = Uuid::new_v4();

        // No dispatch yet → claim finds it missing.
        assert_eq!(
            lease.try_claim(exec, "w1", 30_000).await,
            ClaimLeaseOutcome::Missing
        );

        lease.record_dispatch(exec, 30_000).await.unwrap();

        // First claim wins.
        assert_eq!(
            lease.try_claim(exec, "w1", 30_000).await,
            ClaimLeaseOutcome::Claimed
        );
        // Same worker redelivered → self.
        assert_eq!(
            lease.try_claim(exec, "w1", 30_000).await,
            ClaimLeaseOutcome::AlreadyClaimedBySelf
        );
        // A different worker → rejected.
        assert_eq!(
            lease.try_claim(exec, "w2", 30_000).await,
            ClaimLeaseOutcome::ClaimedByOther
        );

        lease.release(exec).await;
        assert_eq!(
            lease.try_claim(exec, "w1", 30_000).await,
            ClaimLeaseOutcome::Missing
        );
    }
}
