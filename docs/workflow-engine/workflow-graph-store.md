# Implementing a `WorkflowGraphStore`

When a workflow contains a system node whose body is *another* workflow
— `SubWorkflow`, `Judge`, `Ensemble`, `AgentLoop`, `ReActLoop`,
`ReflectiveRetry`, `LlmDispatch`, `DynamicDispatch`,
`CapabilityDispatch` — the engine has to load the child graph at
dispatch time. The trait that bridges the engine to your storage layer
is [`WorkflowGraphStore`][gs]. This guide covers what the engine
expects from your impl, how the security contract works, and the
performance characteristics you need to honor.

## When the engine calls in

Three call sites:

1. **Run-start batch prefetch.** Before the reactor begins,
   the engine walks every node in the loaded graph, collects the
   workflow ids referenced by `SubWorkflow` / `Judge` / `Ensemble` /
   etc., and issues a single
   [`WorkflowGraphStore::get_graphs(ids, user_id)`][batch] call. The
   returned graphs land in `sub_workflow_cache`. Sub-workflow handlers
   later read from the cache instead of hitting the store again.
2. **`DynamicDispatch::resolve_by_name`.** A `DynamicDispatch` node
   whose target expression resolves to a string (not a UUID) calls
   [`resolve_by_name`][rbn] to look up the workflow id, then takes
   the same prefetch / cache-or-fetch path.
3. **`CapabilityDispatch::resolve_by_capabilities`.** A
   `CapabilityDispatch` node calls
   [`resolve_by_capabilities`][rbc] with its required capability
   labels. Your impl picks one workflow that can satisfy the set.

The engine never inspects the store between dispatches. If you change
a workflow definition mid-run, the in-flight execution still sees the
version it cached at run-start — by design, so behavior doesn't drift
under a workflow's feet.

## The security contract

Every method takes a `user_id`. The trait's docstring puts it bluntly:

> Impls **MUST NOT** return a graph the caller does not own — returning
> `None` (or an absent map entry) for a workflow the caller is not
> authorized to read is correct and indistinguishable from "no such
> workflow" at this layer. **This is a hard invariant, not a soft
> expectation: the executor does not re-check ownership on the
> returned graph.**

Two practical consequences:

* **Don't return a graph based on id alone.** Even if `workflow_id` is
  a true UUID, the SQL `WHERE id = $1` clause is wrong — make it
  `WHERE id = $1 AND user_id = $2` (or whatever your tenancy column
  is). Otherwise a tenant who guesses another tenant's id can read
  their workflow.
* **Don't 401 vs 404.** Return `None` for both "doesn't exist" and
  "not visible to this user." The engine treats them identically;
  leaking the distinction back through the trait is a tenant
  enumeration vector.

## Reference impl: in-memory (tests)

The simplest impl backs onto a `HashMap` keyed by id, with no real
tenancy enforcement. `talos-workflow-engine-test-utils` ships
[`InMemoryWorkflowGraphStore`][ims] for tests:

```rust
let store = Arc::new(
    InMemoryWorkflowGraphStore::new()
        .with_graph(judge_workflow_id, judge_graph_json)
);
engine.set_graph_store(store);
```

Use this for unit tests of nodes that consult sub-workflows. Don't
ship it to production: it ignores `user_id`.

## Reference impl: Postgres

Production deployments typically back the store with the same database
the workflow-authoring service writes to. Sketch:

```rust
use std::collections::HashMap;
use async_trait::async_trait;
use serde_json::Value as JsonValue;
use uuid::Uuid;
use talos_workflow_engine_core::{BoxError, WorkflowGraphStore};

pub struct PgWorkflowGraphStore {
    pool: sqlx::PgPool,
}

#[async_trait]
impl WorkflowGraphStore for PgWorkflowGraphStore {
    async fn get_graph(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<JsonValue>, BoxError> {
        // The user_id filter is the security boundary — see the
        // contract above.
        let row: Option<(JsonValue,)> = sqlx::query_as(
            "SELECT graph FROM workflows
             WHERE id = $1 AND user_id = $2"
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Box::new(e) as BoxError)?;
        Ok(row.map(|(g,)| g))
    }

    /// MUST be overridden — the default impl is `O(N)` round-trips,
    /// fine for the in-memory test store and prohibitive for any real
    /// database. One batch query, one round-trip.
    async fn get_graphs(
        &self,
        ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<HashMap<Uuid, JsonValue>, BoxError> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let rows: Vec<(Uuid, JsonValue)> = sqlx::query_as(
            "SELECT id, graph FROM workflows
             WHERE id = ANY($1) AND user_id = $2"
        )
        .bind(ids)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Box::new(e) as BoxError)?;
        Ok(rows.into_iter().collect())
    }

    async fn resolve_by_name(
        &self,
        name: &str,
        user_id: Uuid,
    ) -> Result<Option<Uuid>, BoxError> {
        // "First match" by some stable ordering — the executor doesn't
        // care which row wins as long as the choice is deterministic
        // under load. Most-recent-update is a reasonable default.
        let row: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM workflows
             WHERE name = $1 AND user_id = $2
             ORDER BY updated_at DESC
             LIMIT 1"
        )
        .bind(name)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Box::new(e) as BoxError)?;
        Ok(row.map(|(id,)| id))
    }

    async fn resolve_by_capabilities(
        &self,
        required_capabilities: &[String],
        user_id: Uuid,
    ) -> Result<Option<(Uuid, String)>, BoxError> {
        // `capabilities` is a TEXT[] column on `workflows`; the
        // `@>` operator is "contains all of" — i.e. the workflow's
        // declared capabilities are a superset of what's required.
        let row: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT id, name FROM workflows
             WHERE user_id = $1 AND capabilities @> $2
             ORDER BY updated_at DESC
             LIMIT 1"
        )
        .bind(user_id)
        .bind(required_capabilities)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Box::new(e) as BoxError)?;
        Ok(row)
    }
}
```

### Why parsed `Value`, not `String`?

The trait returns
[`serde_json::Value`](https://docs.rs/serde_json/latest/serde_json/enum.Value.html),
not `String`. Two reasons:

1. **Postgres `JSONB` returns `Value` natively.** A `String` round-trip
   would force the driver to serialize what it already has parsed,
   only for the engine to immediately re-parse on the other side.
2. **Every executor call site parses what it gets.** Pushing the
   parse to the storage boundary collapses N parses into one and
   surfaces malformed-JSON failures at the right blame line (the
   store, not the dispatch handler).

If your backing store holds a raw string (S3 file, blob column),
`serde_json::from_str` inside the impl. Don't push that cost out.

## Override `get_graphs`. Always.

The default `get_graphs` implementation is a serial loop:

```rust
async fn get_graphs(&self, ids: &[Uuid], user_id: Uuid)
    -> Result<HashMap<Uuid, JsonValue>, BoxError>
{
    let mut out = HashMap::with_capacity(ids.len());
    for id in ids {
        if let Some(graph) = self.get_graph(*id, user_id).await? {
            out.insert(*id, graph);
        }
    }
    Ok(out)
}
```

Correct for the in-memory test store. **Catastrophic for any real
database**: a workflow with 50 sub-workflow references makes 50
round-trips at run-start, each paying connection-pool acquisition +
network RTT + query parse. Override with a single
`WHERE id = ANY($1)` query and the cost collapses to one round-trip.

The engine's run-start prefetch is the only caller of `get_graphs`.
Every byte you save here lands directly in fresh-run latency for
workflows that compose other workflows.

## Caching at the store layer

The engine maintains its own in-memory cache (`sub_workflow_cache`)
for the duration of one run, but it doesn't share that cache across
runs. Two patterns work:

1. **Trust the engine's cache.** Each run pays one batch fetch at
   start; subsequent dispatches in that run hit the engine's cache.
   Production-grade for short-to-medium workflows.
2. **Add a TTL cache inside your impl.** Wrap the database call in a
   [`moka`](https://crates.io/crates/moka) cache with a few-minute
   TTL. Workflows rarely change mid-day; cross-run cache hits cut
   the per-run prefetch cost. Worth the complexity only when fresh-run
   latency is hot enough to matter.

Don't share state between `WorkflowGraphStore` impls and your
`CheckpointStore` / `EventSink` impls. Each trait's lifetime is
independent and the engine clones each `Arc` separately on every
sub-engine hydration.

## Testing your impl

Two layers:

1. **Trait-level unit tests** for the security boundary:
   ```rust
   #[tokio::test]
   async fn get_graph_returns_none_for_other_users_workflow() {
       let store = build_pg_store_with_seed(/* ... */).await;
       let other_user = Uuid::new_v4();
       let result = store.get_graph(seeded_workflow_id, other_user).await;
       assert!(matches!(result, Ok(None)),
           "MUST return None for cross-tenant lookup, not the graph");
   }
   ```
2. **End-to-end tests** that wire your store into a real
   `ParallelWorkflowEngine` with a sub-workflow node, run the parent,
   and assert the child ran. The
   [`InMemoryWorkflowGraphStore`][ims] from `talos-workflow-engine-test-utils`
   is the reference shape for what your impl must match — copy its
   test layout and swap the storage layer.

## When NOT to back this trait with your real database

If your sub-workflow definitions are essentially static (compiled into
the binary, loaded from a config file at startup), wire an
`InMemoryWorkflowGraphStore` populated at boot. The engine's contract
is the same; only the storage layer differs. Don't pay for a Postgres
round-trip per run-start when the graphs never change.

[gs]: https://docs.rs/talos-workflow-engine-core/0.2/talos_workflow_engine_core/trait.WorkflowGraphStore.html
[batch]: https://docs.rs/talos-workflow-engine-core/0.2/talos_workflow_engine_core/trait.WorkflowGraphStore.html#method.get_graphs
[rbn]: https://docs.rs/talos-workflow-engine-core/0.2/talos_workflow_engine_core/trait.WorkflowGraphStore.html#method.resolve_by_name
[rbc]: https://docs.rs/talos-workflow-engine-core/0.2/talos_workflow_engine_core/trait.WorkflowGraphStore.html#method.resolve_by_capabilities
[ims]: https://docs.rs/talos-workflow-engine-test-utils/0.2/talos_workflow_engine_test_utils/memory/struct.InMemoryWorkflowGraphStore.html
