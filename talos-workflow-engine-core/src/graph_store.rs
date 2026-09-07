//! Pluggable read-only access to workflow graph definitions.
//!
//! When a workflow graph contains a system node whose body is *another*
//! workflow (sub-workflow, judge, ensemble child, `AgentLoop`, etc.), the
//! executor needs to load that workflow's `graph_json` at dispatch time.
//! [`WorkflowGraphStore`] is the abstraction it uses — the backing store
//! can be Postgres, an in-memory map for tests, or anything else the
//! consumer wires in.
//!
//! The trait is **read-only**: callers that need to *create* workflows
//! go through a different path (e.g. a dedicated workflow-authoring
//! service). The executor's concern is hydration, not mutation.
//!
//! # Return type
//!
//! Graphs come back as parsed [`serde_json::Value`], not as a `String`.
//! Every executor call site immediately parses what it gets, so parsing
//! at the storage boundary collapses N parses into one (Postgres can
//! return JSONB natively as `Value`, skipping a text round-trip
//! entirely). Impls whose backing store holds a raw string should call
//! `serde_json::from_str` inside the impl, not push that cost onto
//! every consumer.

use std::collections::HashMap;

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::BoxError;

/// What a by-id graph read found — THREE-valued, because "the operator retired
/// this workflow" and "there is no such workflow" are different answers and a
/// parent node that reports the second for the first sends its author looking
/// for a typo.
///
/// The narrow lifecycle gate (2026-09-07). Same shape and the same reason as
/// `ExecutionLookup::{Live, Archived, Absent}` (#748): deliberately NO
/// `Into<Option>`, no `graph()` accessor and no `.ok()`, so the compiler makes
/// every consumer decide what an archived child means to it rather than
/// letting one `unwrap_or` collapse the distinction back.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum GraphLookup {
    /// The workflow is visible to this user and is not retired.
    Found(JsonValue),
    /// The workflow is visible to this user and `status = 'archived'`.
    /// It exists; the platform refuses to dispatch it.
    Archived,
    /// No workflow with that id is visible to this user. Indistinguishable
    /// from "not owned" BY DESIGN — see the trait's security contract.
    Absent,
}

/// Resolve stored workflow graphs by id, scoped to a user/tenant.
///
/// # Security contract
///
/// Both methods take a `user_id` parameter and impls **MUST NOT** return
/// a graph the caller does not own — returning `None` (or an absent map
/// entry) for a workflow the caller is not authorized to read is correct
/// and indistinguishable from "no such workflow" at this layer. This is
/// a hard invariant, not a soft expectation: the executor does not
/// re-check ownership on the returned graph.
#[async_trait]
pub trait WorkflowGraphStore: Send + Sync {
    /// Fetch one workflow's parsed graph, three-valued.
    ///
    /// [`GraphLookup::Archived`] is a REFUSAL, not a miss: the row is there and
    /// the caller may not run it. An impl that cannot distinguish the two (an
    /// in-memory test map with no lifecycle column) returns
    /// [`GraphLookup::Absent`] for a missing id and never `Archived` — which is
    /// honest, because it has no lifecycle to report.
    async fn get_graph(&self, workflow_id: Uuid, user_id: Uuid) -> Result<GraphLookup, BoxError>;

    /// Batch-fetch parsed graphs for a set of workflow ids scoped to
    /// `user_id`. Ids that do not resolve are simply absent from the
    /// returned map — the caller is expected to tolerate partial results.
    ///
    /// # Overriding
    ///
    /// The default implementation is a serial loop over
    /// [`get_graph`](Self::get_graph). It's correct, but it's `O(N)`
    /// round-trips with no parallelism — acceptable only for in-memory
    /// test impls. **Override this method in any impl whose backing
    /// store has per-call latency greater than ~1 ms** (databases,
    /// remote caches, RPC-fronted services) with a single batch query
    /// like `WHERE id = ANY($1) AND user_id = $2`.
    async fn get_graphs(
        &self,
        ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<HashMap<Uuid, JsonValue>, BoxError> {
        let mut out = HashMap::with_capacity(ids.len());
        for id in ids {
            // An ARCHIVED child is absent from the cache, exactly as a missing
            // one is — and that is deliberate rather than lazy. This map only
            // WARMS a cache; a miss falls through to `get_graph`, which reports
            // `Archived` with its own wording. Reporting the refusal here as
            // well would give one policy two messages that could drift.
            if let GraphLookup::Found(graph) = self.get_graph(*id, user_id).await? {
                out.insert(*id, graph);
            }
        }
        Ok(out)
    }

    /// Resolve a workflow by its display name, scoped to `user_id`.
    ///
    /// **Required for `SystemNodeKind::DynamicDispatch`** when the
    /// target expression resolves to a string instead of a UUID. If
    /// your graphs only ever use UUID targets, the default impl
    /// (always returns `None`) is fine.
    ///
    /// Returns the first matching workflow's id (impls may order
    /// however they like — a typical impl takes the most recent by
    /// update time). Returns `Ok(None)` when no workflow matches.
    ///
    /// # The silent-no-op trap
    ///
    /// The default impl returns `None` for every input. If your
    /// graphs use name-based `DynamicDispatch` and you forgot to
    /// override this method, every dispatch surfaces only as a
    /// per-node `__error` envelope reading "Could not resolve
    /// dispatch target: ..." — easy to miss in logs. The engine
    /// emits a `tracing::warn!` at the dispatch site naming this
    /// override as the likely cause; check your log pipeline for
    /// it before assuming the workflow data is wrong.
    async fn resolve_by_name(&self, _name: &str, _user_id: Uuid) -> Result<Option<Uuid>, BoxError> {
        Ok(None)
    }

    /// Resolve a workflow whose declared capabilities are a superset
    /// of `required_capabilities`, scoped to `user_id`.
    ///
    /// **Required for `SystemNodeKind::CapabilityDispatch`** —
    /// "find a workflow that can do these things." If your graphs
    /// don't use capability dispatch, the default impl (always
    /// returns `None`) is fine.
    ///
    /// Returns the first matching workflow's `(id, name)` — impls may
    /// order however they like (a typical impl takes the most recent
    /// by update time). `Ok(None)` means no workflow satisfies the
    /// capability set.
    ///
    /// Same silent-no-op trap as
    /// [`resolve_by_name`](Self::resolve_by_name): the engine emits
    /// a `tracing::warn!` at the dispatch site when an unresolved
    /// `CapabilityDispatch` could plausibly be a missing override
    /// rather than a genuine no-match.
    async fn resolve_by_capabilities(
        &self,
        _required_capabilities: &[String],
        _user_id: Uuid,
    ) -> Result<Option<(Uuid, String)>, BoxError> {
        Ok(None)
    }
}
