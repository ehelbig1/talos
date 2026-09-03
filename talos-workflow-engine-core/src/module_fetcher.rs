//! Pluggable module-artifact resolution for the workflow executor.
//!
//! The executor only asks "give me the wasm module that should run for
//! this `(module_id, user_id)` pair." Whether the backing store is a
//! Postgres + Redis catalog, an OCI registry, or an in-memory map for
//! tests is the impl's business.
//!
//! # Security contract
//!
//! Impls are the **single authority** on what module `user_id` sees
//! for a given `module_id`. The executor does not re-check ownership
//! after this returns. Concretely that means:
//!
//! * A module owned by `user_id` MUST always be preferred over a
//!   cross-user fallback.
//! * Whether a fallback path *may* cross users (for example, shared
//!   template catalogs that deliberately resolve any user's compile
//!   when the caller has none of their own) is an impl-level policy
//!   decision. Impls that allow cross-user fallbacks MUST document it
//!   on the impl type.
//! * Returning `Err(...)` when the module isn't visible under the
//!   impl's policy is correct and indistinguishable from "really
//!   doesn't exist" at this layer.

use std::collections::HashMap;

use async_trait::async_trait;
use uuid::Uuid;

use crate::{BoxError, WasmModuleArtifact};

/// Resolve the wasm artifact for a workflow node.
#[async_trait]
pub trait ModuleFetcher: Send + Sync {
    /// Fetch the [`WasmModuleArtifact`] identified by `module_id` for
    /// `user_id`. Impls run whatever fallback pipeline they need to
    /// produce a dispatch-ready artifact; the executor expects a
    /// single outcome — a ready artifact or an error.
    async fn fetch(&self, module_id: Uuid, user_id: Uuid) -> Result<WasmModuleArtifact, BoxError>;

    /// Batch-load per-module rate limits (requests-per-minute).
    /// Called once at graph init to populate the engine's per-module
    /// rate-limit map. Ids that do not carry a rate limit (or do not
    /// exist) are simply absent from the returned map.
    ///
    /// Default impl returns an empty map — consumers without a
    /// rate-limit concept opt out implicitly, and the engine then
    /// performs no rate limiting. A Postgres-backed impl might run a
    /// single `UNION ALL` over its module tables.
    ///
    /// # Why this returns `Result` (and an empty map does not mean
    /// "no limits")
    ///
    /// An **absent** entry is read downstream as UNLIMITED:
    /// `check_rate_limit` does `*self.rate_limits.get(&id)?` and the
    /// `?` on that `Option` early-returns "dispatch may proceed". So an
    /// empty map produced by a FAILED read is not a degraded answer, it
    /// is the removal of an enforcement control the operator explicitly
    /// configured — and it is indistinguishable, in the map alone, from
    /// the legitimate "nothing declares a limit" case.
    ///
    /// An impl that cannot determine the limits MUST therefore return
    /// `Err`, never `Ok(empty)`. The engine refuses the graph load on
    /// `Err` rather than running the workflow with rate limiting
    /// silently switched off — the same posture as
    /// `SecretsResolverMissing` and `ModuleFetcherMissing`, which also
    /// refuse rather than dispatch under a control that is not there.
    async fn load_rate_limits(&self, _module_ids: &[Uuid]) -> Result<HashMap<Uuid, i32>, BoxError> {
        Ok(HashMap::new())
    }
}
