//! `HashMap`-backed trait impls that return configured data.
//!
//! Each store exposes a fluent `with_*` builder API plus `insert`/
//! `remove` for tests that mutate state mid-run. All impls are
//! `Send + Sync` via `Arc<DashMap>` — the engine's speculative
//! prefetch path can hit these from multiple tasks concurrently
//! without additional locking.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value as JsonValue;
use talos_workflow_engine_core::{
    BoxError, CheckpointStore, ModuleFetcher, SecretsResolver, WasmModuleArtifact,
    WorkflowGraphStore,
};
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// InMemoryModuleFetcher
// ─────────────────────────────────────────────────────────────────────────────

/// [`ModuleFetcher`] backed by an in-memory `module_id → WasmModuleArtifact`
/// map. Ignores `user_id` — tests that need per-user isolation should
/// key modules into separate fetchers per user.
#[derive(Clone, Default)]
pub struct InMemoryModuleFetcher {
    modules: Arc<DashMap<Uuid, WasmModuleArtifact>>,
    rate_limits: Arc<DashMap<Uuid, i32>>,
}

impl InMemoryModuleFetcher {
    /// Build an empty fetcher.
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure a `(module_id → artifact)` mapping. Fluent — chain
    /// multiple `.with_module` calls to seed a full module set.
    pub fn with_module(self, module_id: Uuid, artifact: WasmModuleArtifact) -> Self {
        self.modules.insert(module_id, artifact);
        self
    }

    /// Configure a per-module rate limit.
    pub fn with_rate_limit(self, module_id: Uuid, limit_per_minute: i32) -> Self {
        self.rate_limits.insert(module_id, limit_per_minute);
        self
    }

    /// Number of seeded modules.
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    /// True when no modules are seeded.
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }
}

impl std::fmt::Debug for InMemoryModuleFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryModuleFetcher")
            .field("modules", &self.modules.len())
            .field("rate_limited", &self.rate_limits.len())
            .finish()
    }
}

#[async_trait]
impl ModuleFetcher for InMemoryModuleFetcher {
    async fn fetch(&self, module_id: Uuid, _user_id: Uuid) -> Result<WasmModuleArtifact, BoxError> {
        self.modules
            .get(&module_id)
            .map(|entry| entry.clone())
            .ok_or_else(|| {
                let e: BoxError = format!("module {module_id} not seeded in fetcher").into();
                e
            })
    }

    async fn load_rate_limits(&self, module_ids: &[Uuid]) -> HashMap<Uuid, i32> {
        module_ids
            .iter()
            .filter_map(|id| self.rate_limits.get(id).map(|e| (*id, *e)))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InMemoryCheckpointStore
// ─────────────────────────────────────────────────────────────────────────────

/// [`CheckpointStore`] backed by `execution_id → snapshot` map.
/// Values are stored as-is; the trait's doc contract that snapshots
/// are objects of `(node_id_str → output)` is the caller's concern.
#[derive(Clone, Default)]
pub struct InMemoryCheckpointStore {
    snapshots: Arc<DashMap<Uuid, JsonValue>>,
    /// Highest `seq` written per execution. Mirrors the production
    /// `checkpoint_seq` column so the monotonicity guard is exercised in
    /// DB-free tests.
    seqs: Arc<DashMap<Uuid, i64>>,
}

impl InMemoryCheckpointStore {
    /// Build an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a checkpoint so a subsequent `load` call returns it.
    pub fn with_snapshot(self, execution_id: Uuid, snapshot: JsonValue) -> Self {
        self.snapshots.insert(execution_id, snapshot);
        self
    }

    /// Number of snapshots in the store.
    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    /// True when no snapshots are present.
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }
}

impl std::fmt::Debug for InMemoryCheckpointStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryCheckpointStore")
            .field("snapshots", &self.snapshots.len())
            .finish()
    }
}

#[async_trait]
impl CheckpointStore for InMemoryCheckpointStore {
    async fn load(&self, execution_id: Uuid) -> Result<HashMap<Uuid, JsonValue>, BoxError> {
        let Some(entry) = self.snapshots.get(&execution_id) else {
            return Ok(HashMap::new());
        };
        let Some(obj) = entry.as_object() else {
            return Ok(HashMap::new());
        };
        Ok(obj
            .iter()
            .filter_map(|(k, v)| Uuid::parse_str(k).ok().map(|u| (u, v.clone())))
            .collect())
    }

    async fn save(
        &self,
        execution_id: Uuid,
        snapshot: &JsonValue,
        seq: i64,
    ) -> Result<(), BoxError> {
        // Mirror the production guard: drop a save whose seq is strictly
        // less than the seq already stored, so a reordered stale snapshot
        // can't clobber a newer one. Equal seq overwrites idempotently.
        let mut entry = self.seqs.entry(execution_id).or_insert(i64::MIN);
        if seq >= *entry {
            *entry = seq;
            self.snapshots.insert(execution_id, snapshot.clone());
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InMemoryWorkflowGraphStore
// ─────────────────────────────────────────────────────────────────────────────

/// [`WorkflowGraphStore`] backed by `workflow_id → graph_json` map.
/// Ignores `user_id`; tests needing multi-tenant isolation should use
/// separate stores per user.
#[derive(Clone, Default)]
pub struct InMemoryWorkflowGraphStore {
    graphs: Arc<DashMap<Uuid, JsonValue>>,
    by_name: Arc<DashMap<String, Uuid>>,
    by_capability: Arc<DashMap<Vec<String>, (Uuid, String)>>,
}

impl InMemoryWorkflowGraphStore {
    /// Build an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a workflow graph.
    pub fn with_graph(self, workflow_id: Uuid, graph_json: JsonValue) -> Self {
        self.graphs.insert(workflow_id, graph_json);
        self
    }

    /// Seed a name-to-id resolution for `resolve_by_name`.
    pub fn with_name(self, name: impl Into<String>, workflow_id: Uuid) -> Self {
        self.by_name.insert(name.into(), workflow_id);
        self
    }

    /// Seed a capability-set match for `resolve_by_capabilities`.
    /// Capability matching here is **exact** (same set); the production
    /// impl uses `@>` superset matching, but exact is sufficient for
    /// testing branch selection.
    pub fn with_capabilities(
        self,
        capabilities: Vec<String>,
        workflow_id: Uuid,
        name: impl Into<String>,
    ) -> Self {
        self.by_capability
            .insert(capabilities, (workflow_id, name.into()));
        self
    }
}

impl std::fmt::Debug for InMemoryWorkflowGraphStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryWorkflowGraphStore")
            .field("graphs", &self.graphs.len())
            .finish()
    }
}

#[async_trait]
impl WorkflowGraphStore for InMemoryWorkflowGraphStore {
    async fn get_graph(
        &self,
        workflow_id: Uuid,
        _user_id: Uuid,
    ) -> Result<Option<JsonValue>, BoxError> {
        Ok(self.graphs.get(&workflow_id).map(|e| e.clone()))
    }

    async fn resolve_by_name(&self, name: &str, _user_id: Uuid) -> Result<Option<Uuid>, BoxError> {
        Ok(self.by_name.get(name).map(|e| *e))
    }

    async fn resolve_by_capabilities(
        &self,
        required_capabilities: &[String],
        _user_id: Uuid,
    ) -> Result<Option<(Uuid, String)>, BoxError> {
        let key = required_capabilities.to_vec();
        Ok(self.by_capability.get(&key).map(|e| e.clone()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InMemorySecretsResolver
// ─────────────────────────────────────────────────────────────────────────────

/// [`SecretsResolver`] with three configurable layers matching the
/// production `SecretsManager`'s method surface:
///
/// * `module_secrets`: `node_id → { name → value }` — per-node grants
///   (e.g. an `allowed_secrets` list).
/// * `vault`: `path → value` — arbitrary `vault://...` references.
/// * `llm_keys`: `user_id → { provider → key }` — canonical LLM keys.
///
/// `refresh_vault_paths` is a no-op (no short-lived credentials to
/// refresh).
#[derive(Clone, Default)]
pub struct InMemorySecretsResolver {
    module_secrets: Arc<DashMap<Uuid, HashMap<String, String>>>,
    vault: Arc<DashMap<String, String>>,
    llm_keys: Arc<DashMap<Uuid, HashMap<String, String>>>,
}

impl InMemorySecretsResolver {
    /// Build an empty resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a per-node secret grant.
    pub fn with_module_secret(
        self,
        node_id: Uuid,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.module_secrets
            .entry(node_id)
            .or_default()
            .insert(name.into(), value.into());
        self
    }

    /// Seed a vault-path resolution.
    pub fn with_vault_path(self, path: impl Into<String>, value: impl Into<String>) -> Self {
        self.vault.insert(path.into(), value.into());
        self
    }

    /// Seed an LLM-key mapping for a user.
    pub fn with_llm_key(
        self,
        user_id: Uuid,
        provider: impl Into<String>,
        key: impl Into<String>,
    ) -> Self {
        self.llm_keys
            .entry(user_id)
            .or_default()
            .insert(provider.into(), key.into());
        self
    }
}

impl std::fmt::Debug for InMemorySecretsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never `Debug` the actual secret values — the resolver's whole
        // purpose is to move plaintext around; accidentally logging it
        // through a default Derive would be a mistake tests should not
        // have to notice.
        f.debug_struct("InMemorySecretsResolver")
            .field("nodes_with_grants", &self.module_secrets.len())
            .field("vault_paths", &self.vault.len())
            .field("users_with_llm_keys", &self.llm_keys.len())
            .finish()
    }
}

#[async_trait]
impl SecretsResolver for InMemorySecretsResolver {
    async fn resolve_module_secrets(
        &self,
        node_id: Uuid,
    ) -> Result<HashMap<String, String>, BoxError> {
        Ok(self
            .module_secrets
            .get(&node_id)
            .map(|e| e.clone())
            .unwrap_or_default())
    }

    async fn resolve_by_paths(
        &self,
        paths: &[String],
        _user_id: Option<Uuid>,
    ) -> Result<HashMap<String, String>, BoxError> {
        let mut out = HashMap::with_capacity(paths.len());
        for path in paths {
            if let Some(v) = self.vault.get(path) {
                out.insert(path.clone(), v.clone());
            }
        }
        Ok(out)
    }

    async fn resolve_llm_keys(
        &self,
        user_id: Option<Uuid>,
    ) -> Result<HashMap<String, String>, BoxError> {
        let Some(uid) = user_id else {
            return Ok(HashMap::new());
        };
        Ok(self
            .llm_keys
            .get(&uid)
            .map(|e| e.clone())
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_fetcher_returns_seeded_artifact() {
        let id = Uuid::new_v4();
        let artifact = WasmModuleArtifact {
            module_id: id,
            content_hash: "sha256".into(),
            wasm_bytes: vec![1, 2, 3],
            oci_url: None,
            max_fuel: 1_000_000,
            capability_world: "test".into(),
            allowed_hosts: vec![],
            allowed_methods: vec![],
            allowed_secrets: vec![],
            requires_approval_for: vec![],
            integration_name: None,
            config: None,
        };
        let fetcher = InMemoryModuleFetcher::new().with_module(id, artifact);
        let got = fetcher.fetch(id, Uuid::new_v4()).await.expect("seeded");
        assert_eq!(got.content_hash, "sha256");
    }

    #[tokio::test]
    async fn in_memory_fetcher_returns_rate_limits() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        let fetcher = InMemoryModuleFetcher::new()
            .with_rate_limit(a, 10)
            .with_rate_limit(b, 20);
        let got = fetcher.load_rate_limits(&[a, b, c]).await;
        assert_eq!(got.len(), 2);
        assert_eq!(got[&a], 10);
        assert_eq!(got[&b], 20);
    }

    #[tokio::test]
    async fn in_memory_checkpoint_roundtrip() {
        let exec = Uuid::new_v4();
        let store = InMemoryCheckpointStore::new();
        assert!(store.load(exec).await.unwrap().is_empty());

        let node = Uuid::new_v4();
        let snapshot = serde_json::json!({ node.to_string(): { "ok": true } });
        store.save(exec, &snapshot, 1).await.unwrap();

        let loaded = store.load(exec).await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[&node], serde_json::json!({ "ok": true }));
    }

    #[tokio::test]
    async fn checkpoint_save_is_monotonic() {
        // A reordered stale save (older seq landing after a newer one) must
        // not clobber the newer snapshot — the production `checkpoint_seq`
        // guard, modelled here in-memory.
        let exec = Uuid::new_v4();
        let store = InMemoryCheckpointStore::new();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        // Newer snapshot (2 nodes, seq=2) lands first.
        let newer = serde_json::json!({
            a.to_string(): { "n": 1 },
            b.to_string(): { "n": 2 },
        });
        store.save(exec, &newer, 2).await.unwrap();

        // Older snapshot (1 node, seq=1) arrives late — must be dropped.
        let older = serde_json::json!({ a.to_string(): { "n": 1 } });
        store.save(exec, &older, 1).await.unwrap();

        let loaded = store.load(exec).await.unwrap();
        assert_eq!(loaded.len(), 2, "stale seq=1 save must not clobber seq=2");

        // A genuinely newer save (seq=3) is accepted.
        let newest = serde_json::json!({
            a.to_string(): { "n": 1 },
            b.to_string(): { "n": 2 },
            Uuid::new_v4().to_string(): { "n": 3 },
        });
        store.save(exec, &newest, 3).await.unwrap();
        assert_eq!(store.load(exec).await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn in_memory_graph_store_resolvers() {
        let id = Uuid::new_v4();
        let store = InMemoryWorkflowGraphStore::new()
            .with_graph(id, serde_json::json!({"nodes": []}))
            .with_name("my-workflow", id)
            .with_capabilities(vec!["send_email".into()], id, "email-workflow");

        assert!(store.get_graph(id, Uuid::nil()).await.unwrap().is_some());
        assert_eq!(
            store
                .resolve_by_name("my-workflow", Uuid::nil())
                .await
                .unwrap(),
            Some(id)
        );
        let got = store
            .resolve_by_capabilities(&["send_email".into()], Uuid::nil())
            .await
            .unwrap();
        assert_eq!(got, Some((id, "email-workflow".into())));
    }

    #[tokio::test]
    async fn in_memory_secrets_resolver_layers() {
        let node = Uuid::new_v4();
        let user = Uuid::new_v4();
        let r = InMemorySecretsResolver::new()
            .with_module_secret(node, "API_KEY", "secret-a")
            .with_vault_path("stripe/key", "secret-b")
            .with_llm_key(user, "anthropic", "secret-c");

        let m = r.resolve_module_secrets(node).await.unwrap();
        assert_eq!(m.get("API_KEY"), Some(&"secret-a".to_string()));

        let v = r
            .resolve_by_paths(&["stripe/key".into(), "missing".into()], Some(user))
            .await
            .unwrap();
        assert_eq!(v.get("stripe/key"), Some(&"secret-b".to_string()));
        assert_eq!(v.get("missing"), None);

        let l = r.resolve_llm_keys(Some(user)).await.unwrap();
        assert_eq!(l.get("anthropic"), Some(&"secret-c".to_string()));
    }
}
