//! `state` (workflow-scoped kv store) and `env` (workflow metadata)
//! host interfaces.

use super::*;

// ============================================================================
// State (workflow-scoped in-memory key-value store)
// ============================================================================

// MCP-603 (2026-05-12): WIT-world linkage restricts `talos:core/state`
// to http-node and above (minimal-node is the only world that does NOT
// `import state`). The existing `exists` method enforced this via a
// `CapabilityWorld::Minimal | Unknown → deny` gate; the sibling
// methods (get / set / delete / list_keys) did not — per-method-gate
// regression class (same shape as MCP-586 wit_files and MCP-601
// wit_cache::set). Without the gate, a mis-tagged Minimal-world
// module whose imports somehow linked would silently access the
// shared state store. Fail closed.
fn require_state_capability(
    world: &crate::wit_inspector::CapabilityWorld,
) -> Result<(), wit_state::Error> {
    use crate::wit_inspector::CapabilityWorld;
    if matches!(world, CapabilityWorld::Minimal | CapabilityWorld::Unknown) {
        tracing::warn!(
            ?world,
            "WASM module attempted wit_state call but lacks the required capability"
        );
        Err(wit_state::Error::Storagefailed)
    } else {
        Ok(())
    }
}

/// Maximum caller-supplied key length for wit_state operations, in
/// bytes. `set` has enforced this since MCP-712; the parity sweep
/// (this audit) extends the same cap to get / delete / exists so a
/// guest can't drive the host into per-call `format!("{module_id}:{key}")`
/// heap-alloc work with megabyte keys. Matches `state_rpc`'s
/// `MAX_STATE_KEY_LEN` on the controller side.
pub(crate) const MAX_STATE_KEY_LEN: usize = 1024;

fn require_state_key_in_range(key: &str) -> Result<(), wit_state::Error> {
    if key.is_empty() || key.len() > MAX_STATE_KEY_LEN {
        Err(wit_state::Error::Invalidkey)
    } else {
        Ok(())
    }
}

impl wit_state::Host for TalosContext {
    async fn get(&mut self, key: String) -> Result<String, wit_state::Error> {
        // MCP-712 (2026-05-13): audit-ledger emission for capability-
        // denial parity with exists() / list_keys() (which got it in
        // MCP-690) AND with the wit_secrets / wit_cache /
        // wit_graphql / wit_events / wit_agent_orchestration / etc.
        // host impls swept in MCP-686/690/696/697. Pre-fix the `?`
        // operator on `require_state_capability` propagated Err
        // without an audit row — a Minimal-world module repeatedly
        // probing wit_state::get left only `tracing::warn!` evidence,
        // operator-blind to the WORM ledger that dashboards alert on.
        if require_state_capability(&self.capability_world).is_err() {
            self.record_capability_denied("state-get", "capability-world", &key)
                .await;
            return Err(wit_state::Error::Storagefailed);
        }
        // Parity with `set` (which enforced this since MCP-712). Without
        // the cap here, a guest can drive per-call
        // `format!("{module_id}:{key}")` heap-alloc work with megabyte
        // keys via repeated get/delete/exists calls.
        require_state_key_in_range(&key)?;
        let scoped = self.scoped_state_key(&key);
        let store = self
            .state_store
            .lock()
            .map_err(|_| wit_state::Error::Storagefailed)?;
        store
            .get(&scoped)
            .cloned()
            .ok_or(wit_state::Error::Notfound)
    }

    async fn set(&mut self, key: String, value: String) -> Result<(), wit_state::Error> {
        // MCP-712 (2026-05-13): see comment on `get` above for the
        // audit-parity rationale. set() is the most-important of the
        // three fallible siblings to audit because a denied write
        // attempt is a stronger signal of capability mismatch than a
        // denied read.
        if require_state_capability(&self.capability_world).is_err() {
            self.record_capability_denied("state-set", "capability-world", &key)
                .await;
            return Err(wit_state::Error::Storagefailed);
        }
        require_state_key_in_range(&key)?;
        if value.len() > 1024 * 1024 {
            // 1MB limit
            tracing::warn!("State value exceeds 1MB limit");
            return Err(wit_state::Error::Storagefailed);
        }
        let scoped = self.scoped_state_key(&key);
        let mut store = self
            .state_store
            .lock()
            .map_err(|_| wit_state::Error::Storagefailed)?;

        // Enforce 1000 key limit to prevent host OOM
        if store.len() >= 1000 && !store.contains_key(&scoped) {
            tracing::warn!("State store exceeds 1000 key limit");
            return Err(wit_state::Error::Storagefailed);
        }

        // Enforce 100 MB aggregate state store limit to prevent DoS via 1000 × 1MB keys
        const MAX_STATE_STORE_AGGREGATE_BYTES: usize = 100 * 1024 * 1024;
        let old_size = store.get(&scoped).map(|v| v.len()).unwrap_or(0);
        let current_total: usize = store.values().map(|v| v.len()).sum();
        let new_total = current_total
            .saturating_sub(old_size)
            .saturating_add(value.len());
        if new_total > MAX_STATE_STORE_AGGREGATE_BYTES {
            tracing::warn!(
                total_bytes = new_total,
                "State store would exceed 100 MB aggregate limit"
            );
            return Err(wit_state::Error::Storagefailed);
        }

        store.insert(scoped.clone(), value.clone());
        drop(store); // Release lock before spawning async work

        // Write-through to durable storage via the state-write RPC
        // (best-effort, non-blocking). Signed + NATS-published so the
        // worker no longer needs direct Postgres credentials.
        spawn_state_write_through(
            self.nats_client.as_ref().cloned(),
            self.execution_id.as_deref(),
            self.actor_id,
            &scoped,
            Some(value.as_str()),
        );

        Ok(())
    }

    async fn delete(&mut self, key: String) -> Result<(), wit_state::Error> {
        // MCP-712 (2026-05-13): audit-parity with get/set/exists/list_keys.
        if require_state_capability(&self.capability_world).is_err() {
            self.record_capability_denied("state-delete", "capability-world", &key)
                .await;
            return Err(wit_state::Error::Storagefailed);
        }
        // Key-length parity with set; see the sibling cap on get().
        require_state_key_in_range(&key)?;
        let scoped = self.scoped_state_key(&key);
        let mut store = self
            .state_store
            .lock()
            .map_err(|_| wit_state::Error::Storagefailed)?;
        store.remove(&scoped);
        drop(store);

        // Mirror the durable store so restored workers don't see a
        // tombstone-less key.
        spawn_state_write_through(
            self.nats_client.as_ref().cloned(),
            self.execution_id.as_deref(),
            self.actor_id,
            &scoped,
            None, // None ⇒ delete
        );

        Ok(())
    }

    async fn exists(&mut self, key: String) -> bool {
        // MCP-603: routed through the shared helper so the gate
        // stays in lockstep with get/set/delete/list_keys.
        if require_state_capability(&self.capability_world).is_err() {
            // MCP-690 (2026-05-13): audit-ledger emission for
            // capability denial parity. The fallible siblings
            // (get/set/delete) emit via `record_capability_denied`;
            // this one used to silently return `false`, leaving no
            // trail in the audit ledger for repeated probes from a
            // Minimal-world module enumerating namespace keys.
            self.record_capability_denied("state-exists", "capability-world", &key)
                .await;
            return false;
        }
        // Key-length parity with set; oversized keys collapse to
        // false (this is an infallible WIT method — no Err variant
        // to surface). The cap prevents per-call
        // `format!("{module_id}:{key}")` allocation on megabyte input.
        if key.is_empty() || key.len() > MAX_STATE_KEY_LEN {
            return false;
        }
        let scoped = self.scoped_state_key(&key);
        self.state_store
            .lock()
            .map(|s| s.contains_key(&scoped))
            .unwrap_or(false)
    }

    async fn list_keys(&mut self) -> Vec<String> {
        // MCP-603: per-method gate aligned with siblings. Pre-fix
        // a Minimal-world module could enumerate every state key
        // in its scoped namespace (key names may carry semantic
        // information that the operator considered out-of-scope
        // for the module's capability tier).
        if require_state_capability(&self.capability_world).is_err() {
            // MCP-690: audit-ledger emission for capability denial parity.
            self.record_capability_denied("state-list-keys", "capability-world", "")
                .await;
            return Vec::new();
        }
        let prefix = match &self.module_id {
            Some(mid) => format!("{}:", mid),
            None => String::new(),
        };
        self.state_store
            .lock()
            .map(|s| {
                s.keys()
                    .filter(|k| {
                        if prefix.is_empty() {
                            true
                        } else {
                            k.starts_with(&prefix)
                        }
                    })
                    .map(|k| {
                        if prefix.is_empty() {
                            k.clone()
                        } else {
                            k[prefix.len()..].to_string()
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

// ============================================================================
// Environment / workflow metadata
// ============================================================================

impl wit_env::Host for TalosContext {
    async fn get_var(&mut self, key: String) -> Option<String> {
        self.env_vars.get(&key).cloned()
    }

    async fn get_all_vars(&mut self) -> String {
        serde_json::to_string(&self.env_vars).unwrap_or_else(|_| "{}".to_string())
    }

    async fn get_workflow_id(&mut self) -> String {
        self.workflow_id.clone().unwrap_or_default()
    }

    async fn get_execution_id(&mut self) -> String {
        self.execution_id.clone().unwrap_or_default()
    }

    async fn get_module_id(&mut self) -> String {
        self.module_id.clone().unwrap_or_default()
    }
}

#[cfg(test)]
mod wit_state_key_range_tests {
    use super::{require_state_key_in_range, MAX_STATE_KEY_LEN};

    #[test]
    fn empty_key_rejected() {
        assert!(require_state_key_in_range("").is_err());
    }

    #[test]
    fn single_char_key_accepted() {
        assert!(require_state_key_in_range("k").is_ok());
    }

    #[test]
    fn key_at_limit_accepted() {
        let k: String = "a".repeat(MAX_STATE_KEY_LEN);
        assert!(require_state_key_in_range(&k).is_ok());
    }

    #[test]
    fn key_just_over_limit_rejected() {
        let k: String = "a".repeat(MAX_STATE_KEY_LEN + 1);
        assert!(require_state_key_in_range(&k).is_err());
    }

    #[test]
    fn megabyte_key_rejected_get_delete_exists_parity() {
        // The cap previously lived only inside `set`; sweep parity
        // (this PR) ensures get/delete/exists/set all share the same
        // gate so a guest cannot drive per-call
        // `format!("{module_id}:{key}")` heap-alloc work via the
        // unbounded siblings.
        let k: String = "x".repeat(1024 * 1024);
        assert!(require_state_key_in_range(&k).is_err());
    }
}
