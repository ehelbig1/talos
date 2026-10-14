//! A delivery token is used once (security review 2026-10-14, F-2 / F-10).
//!
//! A Jira delivery's JWT proves only that the app's client secret signed it at
//! some time; it carries no `qsh`, so it is not bound to the body. Without a
//! memory of tokens already seen, one captured token forged any number of
//! deliveries, each with a fresh `X-Atlassian-Webhook-Identifier` (the dedup
//! key is a header the sender chooses).
//!
//! [`DeliveryReplayCache`] remembers the SHA-256 of every token it admits, in
//! the two-generation `ArcSwap<DashMap>` shape `talos_memory::rpc_auth` uses:
//! rotation is an atomic pointer swap, and an entry lives at least one full
//! rotation interval. The interval is the longest a verified token can stay
//! valid (`MAX_TOKEN_LIFETIME_SECS + LEEWAY_SECS`), so no token is forgotten
//! while it could still verify. Memory is bounded: at most
//! [`MAX_ENTRIES_PER_GENERATION`] per generation, and a full generation
//! REFUSES rather than admits (fail closed).
//!
//! It is checked before any database read. When the controller registered a
//! shared replay guard (`talos_replay_guard`, Redis), the token is also checked
//! there, so a token used on one replica is refused on another.
//!
//! A token is RELEASED again when its delivery is answered with a 5xx:
//! Atlassian retries such a delivery, possibly with the same token, and a
//! retry the receiver itself asked for must not be refused as a replay.

use arc_swap::ArcSwap;
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::push_jwt::{LEEWAY_SECS, MAX_TOKEN_LIFETIME_SECS};

/// Most token hashes held per generation (32 bytes each, so ~3 MiB at most
/// per generation). Atlassian sends one delivery per matched change; a
/// deployment near this in one hour is under a flood, and refusing is the
/// right answer to a flood of verified tokens.
pub const MAX_ENTRIES_PER_GENERATION: usize = 100_000;

/// Key prefix in the shared replay guard.
const SHARED_KEY_PREFIX: &str = "jira-delivery:";

/// The SHA-256 of a delivery token: what is remembered, never the token.
pub type TokenHash = [u8; 32];

#[must_use]
pub fn token_hash(token: &str) -> TokenHash {
    Sha256::digest(token.as_bytes()).into()
}

/// Whether a token was admitted, and why not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayVerdict {
    /// First sighting; recorded.
    Fresh,
    /// Seen before (here or, with a shared guard, on another replica).
    Replayed,
    /// The cache is full, or the shared guard could not be asked and the
    /// deployment fails closed. Refused.
    Unavailable,
}

/// Process-local, bounded memory of the delivery tokens already admitted.
pub struct DeliveryReplayCache {
    current: ArcSwap<DashMap<TokenHash, ()>>,
    previous: ArcSwap<DashMap<TokenHash, ()>>,
    rotated_at: std::sync::Mutex<Instant>,
    interval: Duration,
}

impl Default for DeliveryReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DeliveryReplayCache {
    #[must_use]
    pub fn new() -> Self {
        Self::with_interval(Duration::from_secs(MAX_TOKEN_LIFETIME_SECS + LEEWAY_SECS))
    }

    fn with_interval(interval: Duration) -> Self {
        Self {
            current: ArcSwap::from(Arc::new(DashMap::new())),
            previous: ArcSwap::from(Arc::new(DashMap::new())),
            rotated_at: std::sync::Mutex::new(Instant::now()),
            interval,
        }
    }

    fn rotate_if_due(&self) {
        let Ok(mut rotated_at) = self.rotated_at.lock() else {
            return;
        };
        if rotated_at.elapsed() < self.interval {
            return;
        }
        let promoted = self.current.swap(Arc::new(DashMap::new()));
        self.previous.store(promoted);
        *rotated_at = Instant::now();
    }

    /// Check and record, locally. Linearizable per key: the insert is the
    /// shard's `entry()`, so two concurrent uses of one token cannot both win.
    #[must_use]
    pub fn check_and_record(&self, hash: TokenHash) -> ReplayVerdict {
        self.rotate_if_due();
        let current = self.current.load();
        let previous = self.previous.load();
        if previous.contains_key(&hash) {
            return ReplayVerdict::Replayed;
        }
        if current.len() >= MAX_ENTRIES_PER_GENERATION {
            tracing::warn!(
                target: "talos_audit",
                event_kind = "jira_delivery_replay_cache_full",
                cap = MAX_ENTRIES_PER_GENERATION,
                "Jira delivery replay cache is full; refusing deliveries until it rotates"
            );
            return ReplayVerdict::Unavailable;
        }
        use dashmap::mapref::entry::Entry;
        let verdict = match current.entry(hash) {
            Entry::Occupied(_) => ReplayVerdict::Replayed,
            Entry::Vacant(v) => {
                v.insert(());
                ReplayVerdict::Fresh
            }
        };
        verdict
    }

    /// Forget a token, so a delivery answered with a 5xx can be retried with
    /// it. Forgets it in both generations.
    pub fn release(&self, hash: &TokenHash) {
        self.current.load().remove(hash);
        self.previous.load().remove(hash);
    }

    /// [`Self::check_and_record`], then — when the local answer is Fresh and a
    /// shared guard is registered — the shared guard, for a token used on
    /// another replica. A shared refusal releases the local record.
    pub async fn admit(&self, hash: TokenHash, expires_at: u64) -> ReplayVerdict {
        let local = self.check_and_record(hash);
        if local != ReplayVerdict::Fresh {
            return local;
        }
        let Some(guard) = talos_replay_guard::shared_replay_guard() else {
            return ReplayVerdict::Fresh;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        // Remembered until the token can no longer verify.
        let ttl = expires_at
            .saturating_sub(now)
            .saturating_add(LEEWAY_SECS)
            .max(1);
        let outcome = guard.check_and_record(&shared_key(&hash), ttl).await;
        let verdict = match outcome {
            talos_replay_guard::ReplayOutcome::Fresh => ReplayVerdict::Fresh,
            talos_replay_guard::ReplayOutcome::Replay => ReplayVerdict::Replayed,
            talos_replay_guard::ReplayOutcome::Unavailable => {
                if talos_replay_guard::admit(outcome, talos_replay_guard::fail_closed_from_env()) {
                    ReplayVerdict::Fresh
                } else {
                    ReplayVerdict::Unavailable
                }
            }
        };
        if verdict != ReplayVerdict::Fresh {
            self.release(&hash);
        }
        verdict
    }

    /// [`Self::release`] here and in the shared guard.
    pub async fn release_everywhere(&self, hash: &TokenHash) {
        self.release(hash);
        if let Some(guard) = talos_replay_guard::shared_replay_guard() {
            guard.release(&shared_key(hash)).await;
        }
    }
}

fn shared_key(hash: &TokenHash) -> String {
    format!("{SHARED_KEY_PREFIX}{}", hex::encode(hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_admitted_once() {
        let cache = DeliveryReplayCache::new();
        let hash = token_hash("a.b.c");
        assert_eq!(cache.check_and_record(hash), ReplayVerdict::Fresh);
        assert_eq!(cache.check_and_record(hash), ReplayVerdict::Replayed);
        assert_eq!(
            cache.check_and_record(token_hash("a.b.d")),
            ReplayVerdict::Fresh
        );
    }

    #[test]
    fn a_released_token_can_be_used_again() {
        let cache = DeliveryReplayCache::new();
        let hash = token_hash("a.b.c");
        assert_eq!(cache.check_and_record(hash), ReplayVerdict::Fresh);
        cache.release(&hash);
        assert_eq!(cache.check_and_record(hash), ReplayVerdict::Fresh);
    }

    #[test]
    fn a_token_is_remembered_across_one_rotation_and_forgotten_after_two() {
        let cache = DeliveryReplayCache::with_interval(Duration::from_millis(30));
        let hash = token_hash("a.b.c");
        assert_eq!(cache.check_and_record(hash), ReplayVerdict::Fresh);
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(cache.check_and_record(hash), ReplayVerdict::Replayed);
        std::thread::sleep(Duration::from_millis(40));
        // Rotated twice: the entry has aged out of both generations. The
        // production interval is the longest a token can verify, so a token
        // this old is refused by its `exp` before it reaches the cache.
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(cache.check_and_record(hash), ReplayVerdict::Fresh);
    }

    #[test]
    fn the_production_interval_outlives_every_token_it_admits() {
        assert!(
            DeliveryReplayCache::new().interval.as_secs() >= MAX_TOKEN_LIFETIME_SECS + LEEWAY_SECS
        );
    }
}
