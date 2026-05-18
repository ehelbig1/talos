//! Controller-side [`ModuleFetcher`] impl backed by [`ModuleRegistry`].
//!
//! The trait itself (and the [`WasmModuleArtifact`] shape it returns) lives
//! in [`talos_workflow_engine_core`]; this module wires the Talos registry's
//! 4-level fallback pipeline (`get_module_for_execution`) behind it and
//! projects `WasmModule` down to the leaner `WasmModuleArtifact`.
//!
//! # Cross-user fallback policy
//!
//! The Talos registry's Levels 3-4 (template catalog, precompiled-legacy)
//! deliberately accept cross-user matches by design — templates are
//! shared catalog entries that any user can instantiate. Levels 1-2
//! (stale ref, user's own compile) are strictly `user_id`-scoped. See
//! [`ModuleRegistry::get_module_for_execution`] for the exact
//! precedence; impls that must enforce stricter tenant isolation
//! should not use this adapter.

use std::collections::HashMap;

use async_trait::async_trait;
use talos_workflow_engine_core::{BoxError, ModuleFetcher, WasmModuleArtifact};
use uuid::Uuid;

use crate::{ModuleRegistry, WasmModule};

#[async_trait]
impl ModuleFetcher for ModuleRegistry {
    async fn fetch(&self, module_id: Uuid, user_id: Uuid) -> Result<WasmModuleArtifact, BoxError> {
        let m = self
            .get_module_for_execution(module_id, user_id)
            .await
            .map_err(|e| -> BoxError { e.to_string().into() })?;
        Ok(wasm_module_to_artifact(module_id, m))
    }

    async fn load_rate_limits(&self, module_ids: &[Uuid]) -> HashMap<Uuid, i32> {
        if module_ids.is_empty() {
            return HashMap::new();
        }
        // Phase 5.1: query the unified `modules` table by canonical id.
        let rows: Vec<(Uuid, i32)> = sqlx::query_as(
            "SELECT id, rate_limit_per_minute FROM modules \
             WHERE id = ANY($1) AND rate_limit_per_minute IS NOT NULL",
        )
        .bind(module_ids)
        .fetch_all(&self.db_pool)
        .await
        .unwrap_or_default();
        rows.into_iter().collect()
    }
}

/// Project the Talos-internal [`WasmModule`] down to the executor-facing
/// [`WasmModuleArtifact`]. All fields the dispatch loop reads are preserved;
/// compile-time metadata (source language, imported WIT interfaces,
/// size, name, dependencies) and ownership bookkeeping (`user_id`,
/// `template_id`) are dropped — the executor has no use for them.
///
/// Exposed to the rest of the controller so other sites that already
/// hold a `WasmModule` (e.g. prefetch warmers) can build an artifact
/// without re-querying.
pub fn wasm_module_to_artifact(module_id: Uuid, m: WasmModule) -> WasmModuleArtifact {
    WasmModuleArtifact {
        module_id,
        content_hash: m.content_hash,
        wasm_bytes: m.wasm_bytes,
        oci_url: m.oci_url,
        // `i64 → u64`: `max_fuel` is constrained non-negative at the
        // schema level; a negative value means the column was
        // misconfigured, in which case we fall back to zero and let
        // the per-node fuel default take over downstream.
        max_fuel: u64::try_from(m.max_fuel).unwrap_or(0),
        capability_world: m.capability_world.to_string(),
        allowed_hosts: m.allowed_hosts,
        allowed_methods: m.allowed_methods,
        allowed_secrets: m.allowed_secrets,
        requires_approval_for: m.requires_approval_for,
        integration_name: m.integration_name,
        config: m.config,
    }
}
