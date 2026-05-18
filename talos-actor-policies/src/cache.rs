//! Per-actor policy cache with TTL + read-path eviction + periodic sweep.
//!
//! Mirrors the LLM-key cache pattern in `secrets::mod::LlmKeysCache`:
//! a `DashMap` keyed by `actor_id`, bounded by a TTL that triggers
//! lazy eviction on read, plus a background sweeper for actors that
//! go dark.
//!
//! ## Why negative-cache actors with zero policies
//! The common case is an actor with no policies at all. Hitting the DB
//! on every `publish_version` for those is wasteful; caching an empty
//! `Vec` keeps the path constant-time.
//!
//! ## Invalidation
//! Write-path callers (`add_actor_approval_policy` /
//! `remove_actor_approval_policy` / `clone_actor`) call
//! `PolicyCache::invalidate(actor_id)` to force the next read to
//! re-fetch. Matches the LLM-key-cache eviction contract.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use uuid::Uuid;

use super::types::{PolicyMode, TriggerCondition};
use talos_actor_repository::ActorRepository;

/// Policy row expanded into runtime-ready form. Kept inside the cache
/// so we parse `trigger_condition` once (not per-evaluation) and hold
/// a typed representation ready for the evaluator.
#[derive(Debug, Clone)]
pub struct ParsedPolicy {
    pub policy_id: Uuid,
    pub actor_id: Uuid,
    pub trigger: TriggerCondition,
    pub mode: PolicyMode,
    pub approvers: Vec<String>,
    /// Used for `created_at ASC` ordering inside the evaluator so the
    /// first-matching `block` wins deterministically.
    pub created_at_ns: i128,
}

#[derive(Clone)]
struct CachedEntry {
    policies: Arc<Vec<ParsedPolicy>>,
    cached_at: Instant,
}

pub struct PolicyCache {
    inner: DashMap<Uuid, CachedEntry>,
    ttl: Duration,
    repo: Arc<ActorRepository>,
}

impl PolicyCache {
    pub fn new(repo: Arc<ActorRepository>, ttl: Duration) -> Arc<Self> {
        Arc::new(Self {
            inner: DashMap::new(),
            ttl,
            repo,
        })
    }

    /// Fetch policies for an actor. Lazy-evicts expired entries on
    /// read; re-populates from DB on miss.
    pub async fn get(&self, actor_id: Uuid) -> anyhow::Result<Arc<Vec<ParsedPolicy>>> {
        if let Some(entry) = self.inner.get(&actor_id) {
            if entry.cached_at.elapsed() < self.ttl {
                return Ok(entry.policies.clone());
            }
            // Fall through — stale entry, refetch.
        }
        let raw = self.repo.list_actor_approval_policies(actor_id).await?;
        let parsed: Vec<ParsedPolicy> = raw
            .into_iter()
            .filter_map(|row| {
                let mode = match PolicyMode::parse(&row.approval_mode) {
                    Some(m) => m,
                    None => {
                        tracing::warn!(
                            target: "actor_policies",
                            policy_id = %row.id,
                            approval_mode = %row.approval_mode,
                            "Unknown approval_mode — dropping policy from cache",
                        );
                        return None;
                    }
                };
                let trigger = TriggerCondition::parse(&row.trigger_condition);
                let created_at_ns = row
                    .created_at
                    .and_then(|dt| dt.timestamp_nanos_opt())
                    .map(|n| n as i128)
                    .unwrap_or(0);
                Some(ParsedPolicy {
                    policy_id: row.id,
                    actor_id,
                    trigger,
                    mode,
                    approvers: row.approvers.unwrap_or_default(),
                    created_at_ns,
                })
            })
            .collect();
        let policies = Arc::new(parsed);
        self.inner.insert(
            actor_id,
            CachedEntry {
                policies: policies.clone(),
                cached_at: Instant::now(),
            },
        );
        Ok(policies)
    }

    /// Evict a single actor's entry so the next read re-fetches.
    /// Called from write-path handlers (add/remove/clone).
    pub fn invalidate(&self, actor_id: Uuid) {
        self.inner.remove(&actor_id);
    }

    /// Drop all entries whose TTL has expired. Called from the
    /// background sweeper.
    pub fn sweep_expired(&self) {
        let ttl = self.ttl;
        self.inner
            .retain(|_, entry| entry.cached_at.elapsed() < ttl);
    }

    /// Size signal for telemetry.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True if no entries are cached.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}
