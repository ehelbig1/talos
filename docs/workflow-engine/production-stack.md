# Assembling a production stack

The four cookbook guides under `docs/` cover individual trait
boundaries — [custom dispatcher](./custom-dispatcher.md),
[checkpoint lifecycle](./checkpoint-lifecycle.md),
[sub-workflow composition](./sub-workflow-composition.md), and
[`WorkflowGraphStore`](./workflow-graph-store.md). This guide
assembles them: a complete production-ready engine wiring across
**Postgres** (for persistent state), **Redis** (for the rate-limit
counter), and **NATS** (for transport) — the typical production
shape for a deployed workflow controller.

## Architecture at a glance

```text
                   ┌─────────────────────────────┐
                   │  Postgres                   │
                   │  • workflows                │ ←─ WorkflowGraphStore
                   │  • workflow_checkpoints     │ ←─ CheckpointStore
                   │  • module_executions        │ ←─ ModuleExecutionStore
                   │  • secrets                  │ ←─ SecretsResolver
                   └──────────────┬──────────────┘
                                  │
                  ┌───────────────┴───────────────┐
                  │  ParallelWorkflowEngine       │
                  │  (talos-workflow-engine)      │
                  └───────┬───────────────┬───────┘
                          │               │
           NodeDispatcher │               │ RateLimitStore
                          ▼               ▼
                  ┌──────────────┐  ┌──────────────┐
                  │  NATS        │  │  Redis       │
                  │  • signed    │  │  • per-      │
                  │    HMAC wire │  │    module    │
                  │    format    │  │    counters  │
                  └──────┬───────┘  └──────────────┘
                         │
                         ▼
                  ┌──────────────┐
                  │  worker      │
                  │  pool        │
                  │  (consumes   │
                  │   the wire   │
                  │   format)    │
                  └──────────────┘
```

The engine itself talks to none of these directly. It holds
`Arc<dyn Trait>` for each boundary; the consumer wires concrete
adapters. Nothing about the engine code knows about Postgres, Redis,
or NATS — swap any one independently.

## Wiring sketch

Most of this is already covered by existing crates and helpers; the
production wiring is just the assembly. The shape:

```rust
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use talos_workflow_engine::ParallelWorkflowEngine;
use talos_workflow_engine_nats::NatsNodeDispatcher;
use tokio_util::sync::CancellationToken;

# // Hypothetical concrete impls — see the per-trait guides for
# // each shape. Replace with your real types.
# struct PgGraphStore;       // impl WorkflowGraphStore
# struct PgCheckpointStore;  // impl CheckpointStore
# struct PgModuleExecutionStore;  // impl ModuleExecutionStore
# struct PgSecretsResolver;  // impl SecretsResolver
# struct PgModuleFetcher;    // impl ModuleFetcher
# struct PgApprovalGate;     // impl ApprovalGate
# struct RhaiExpressionEvaluator;  // impl ExpressionEvaluator
# struct DlpOutputSanitizer; // impl OutputSanitizer
# struct ProductionRetryClassifier;  // impl RetryClassifier
# struct PgEventSink;        // impl EventSink
# struct CostNodeLifecycleHook;  // impl NodeLifecycleHook
# struct RedisRateLimitStore;  // impl RateLimitStore

async fn build_production_engine(
    pg_pool: sqlx::PgPool,
    redis: redis::Client,
    nats: async_nats::Client,
    user_id: Uuid,
    workflow_id: Uuid,
    actor_id: Option<Uuid>,
    shutdown: CancellationToken,
) -> Result<ParallelWorkflowEngine, Box<dyn std::error::Error>> {
    let mut engine = ParallelWorkflowEngine::new();

    // ── Identity (every dispatch is scoped to these) ──────────
    engine.set_user_id(user_id);
    engine.set_workflow_id(workflow_id);
    if let Some(a) = actor_id {
        engine.set_actor_id(a);
    }

    // ── Persistent state (Postgres) ────────────────────────────
    engine.set_secrets_resolver(Arc::new(PgSecretsResolver { /* pool */ }));
    engine.set_graph_store(Arc::new(PgGraphStore { /* pool */ }));
    engine.set_module_fetcher(Arc::new(PgModuleFetcher { /* pool */ }));
    engine.set_module_execution_store(Arc::new(PgModuleExecutionStore { /* pool */ }));
    engine.set_approval_gate(Arc::new(PgApprovalGate { /* pool */ }));
    engine.set_event_sink(Arc::new(PgEventSink { /* pool */ }));

    // ── Rate-limit counter (Redis, cross-replica) ─────────────
    engine.set_rate_limit_store(Arc::new(RedisRateLimitStore { /* client */ }));

    // ── Cross-cutting hooks ────────────────────────────────────
    engine.set_node_hook(Arc::new(CostNodeLifecycleHook { /* metrics sink */ }));
    engine.set_expression_evaluator(Arc::new(RhaiExpressionEvaluator::new()));
    engine.set_output_sanitizer(Arc::new(DlpOutputSanitizer::new()));
    engine.set_retry_classifier(Arc::new(ProductionRetryClassifier::new()));

    // ── Resource caps ──────────────────────────────────────────
    engine.set_execution_timeout(Some(Duration::from_secs(600)));      // 10-min wall clock
    engine.set_max_workflow_nodes(2_000);                              // raise from default 500
    engine.set_max_node_output_bytes(20 * 1024 * 1024);                // raise from 5 MiB
    engine.set_max_fuel_per_node(100_000_000);                         // raise from 50M
    engine.set_max_prefetch_successors(16);                            // raise from 8
    engine.set_agent_loop_max_history(40);                             // raise from 20

    // ── Shutdown signal ────────────────────────────────────────
    // A graceful-shutdown handler (SIGTERM, /shutdown endpoint, …)
    // calls `shutdown.cancel()`. The engine reactor sees it on
    // the next dispatch boundary and returns Cancelled.
    engine.set_cancellation_token(Some(shutdown));

    Ok(engine)
}

# fn doctest_compile_only() {}
```

Then run a workflow:

```rust,no_run
# use std::sync::Arc;
# use uuid::Uuid;
# use talos_workflow_engine::ParallelWorkflowEngine;
# use talos_workflow_engine_nats::NatsNodeDispatcher;
# use talos_workflow_engine_core::WorkerSharedKey;
# async fn demo(
#     mut engine: ParallelWorkflowEngine,
#     graph_json: String,
#     nats: async_nats::Client,
#     worker_key: Vec<u8>,
# ) -> Result<(), Box<dyn std::error::Error>> {
let dispatcher = Arc::new(NatsNodeDispatcher::new(nats.clone()));

engine.load_graph_from_json(&graph_json).await?;

let execution_id = Uuid::new_v4();
let ctx = engine
    .run_with_transport(
        dispatcher,
        Some(WorkerSharedKey::new(worker_key)),
        execution_id,
    )
    .await?;
# Ok(()) }
```

That's the whole hot path. Resume from a checkpoint:

```rust,no_run
# use std::collections::HashMap;
# use std::sync::Arc;
# use serde_json::Value as JsonValue;
# use uuid::Uuid;
# use talos_workflow_engine::ParallelWorkflowEngine;
# use talos_workflow_engine_core::{CheckpointStore, NodeDispatcher, WorkerSharedKey};
# async fn resume(
#     engine: &ParallelWorkflowEngine,
#     dispatcher: Arc<dyn NodeDispatcher>,
#     checkpoint_store: Arc<dyn CheckpointStore>,
#     worker_key: Vec<u8>,
#     execution_id: Uuid,
# ) -> Result<(), Box<dyn std::error::Error>> {
let snapshot: HashMap<Uuid, JsonValue> = checkpoint_store
    .load(execution_id)
    .await?;

let ctx = engine
    .run_with_seed_with_transport(
        dispatcher,
        Some(WorkerSharedKey::new(worker_key)),
        snapshot,
        execution_id, // same id — observability stays correlated
    )
    .await?;
# Ok(()) }
```

## What goes where (and why)

| Concern | Where it lives | Why |
|---|---|---|
| Workflow graph definitions | Postgres (`workflows` table) | Versionable, queryable, supports name + capability lookups. |
| Per-execution checkpoints | Postgres (`workflow_checkpoints` table) | Durable across replica restarts. Encrypted at rest under a per-execution AES-GCM subkey (HKDF folds `execution_id`; v2→v1 decrypt fallback). |
| Per-dispatch audit log | Postgres (`module_executions` table) | Joinable with workflow + user tables for cost attribution. |
| Secrets | Postgres (`secrets` table, envelope-encrypted) | Single source of truth; OAuth refresh hook colocated. |
| Rate-limit counters | Redis | Sub-millisecond counter increments; shared across replicas. |
| Job dispatch | NATS | Topic-routed, signed wire format, multi-worker pub/sub. |
| Module artifacts | Postgres + Redis cache | Postgres canonical, Redis hot cache for the dispatch path. |

You can collapse / split this however your infra dictates — the
engine doesn't care. A small deployment might run only Postgres +
the in-process default rate-limiter; a large one might split
modules into S3 + Redis and use a JetStream-backed NATS for
durability.

## Configuration knobs that matter

The engine ships sensible defaults; production deployments typically
override:

| Setter | Default | When to raise / lower |
|---|---|---|
| `set_execution_timeout` | 5 min | Raise for batch / report workflows; lower for user-facing latency-sensitive flows. |
| `set_max_workflow_nodes` | 500 | Raise for code-generated DAGs (data-pipeline shape). Don't disable — it's a defence-in-depth ceiling. |
| `set_max_node_output_bytes` | 5 MiB | Raise for nodes legitimately producing large blobs (PDF, image, log aggregation). Lower on memory-constrained hosts. |
| `set_max_fuel_per_node` | 50M | Raise on dedicated workers; lower on shared infrastructure. |
| `set_max_prefetch_successors` | 8 | Raise for wide fan-out graphs; lower on memory-constrained hosts. |
| `set_agent_loop_max_history` | 20 | Raise for agents reasoning over long sessions; lower for stateless tools. |
| `set_cancellation_token` | none | **Always wire a shutdown token.** Without it, a SIGTERM during a long workflow waits for the wall-clock timeout (or worse, the tokio runtime drops mid-dispatch). |
| `set_rate_limit_store` | in-memory | **Always wire Redis** for sharded fleets. The default counter resets on restart — fine for single-replica deployments, broken under horizontal scaling. |

## Observability

The engine is `tracing`-instrumented end-to-end. Each `run_*` call
produces a `workflow` span; sub-workflow handlers (`judge`,
`ensemble`, `agent_loop`, `confidence_gate`, etc.) produce nested
spans with the relevant identifiers. `skip_all` is applied to every
span so no plaintext input or secret reaches the tracing sink.

Wire `tracing-subscriber` with your observability stack:

```rust,no_run
# fn main() {
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

tracing_subscriber::registry()
    .with(tracing_subscriber::EnvFilter::from_default_env())
    .with(tracing_subscriber::fmt::layer().json())  // structured logs
    // .with(opentelemetry_sdk::...)                // OTLP / Jaeger
    .init();
# }
```

The `EventSink` trait covers the per-node lifecycle ledger
(`node_started` / `node_completed` / `node_failed`) — typically
written to a Postgres `execution_events` table for the workflow
inspector UI to read back.

## Security defaults

Production deployments inherit several security-by-default behaviors;
nothing here requires opt-in:

* **Secrets never reach tracing.** Every sub-workflow handler span
  uses `skip_all`; `DispatchJob`'s `Debug` impl redacts
  `input_payload` and `encrypted_secrets_*`.
* **Wire-format integrity.** `talos-workflow-job-protocol` signs
  every `JobRequest` and `JobResult` with HMAC-SHA256 over a
  canonical byte string covering all security-sensitive fields.
  See [`docs/wire-format-snapshots`](../talos-workflow-job-protocol/tests/wire_format_snapshots.rs)
  for the locked shape.
* **Vault path deny-list.** LLM provider keys (`anthropic/*`,
  `openai/*`, etc.) are deny-listed from the modular vault path
  allowlist — they can only be fetched via the dedicated
  `SecretsResolver::resolve_llm_keys` hook.
* **Per-node fuel + timeout caps.** A runaway / malicious module
  can't burn unbounded compute.
* **Per-execution sandbox dirs.** Filesystem scratch space is
  isolated per-`execution_id`; RAII guard cleans up on panic.

## Common operational issues

**"My workflow runs but the rate-limit counter doesn't seem to
work across replicas."**
You're using the default in-memory store. Wire `RedisRateLimitStore`
(or whatever your shared backing is) via `set_rate_limit_store`.

**"Cancellation works in tests but not in production."**
Wire `set_cancellation_token` with a token that your shutdown
handler actually cancels. The token must be the same instance that
the shutdown path triggers — clones are connected (it's an `Arc`
internally), but a fresh `CancellationToken::new()` per request
won't observe the global shutdown signal.

**"`DynamicDispatch` returns no-such-target for what should be a
valid name."**
You forgot to override `WorkflowGraphStore::resolve_by_name` — the
default impl returns `None` for everything. The engine emits a
`tracing::warn!` at the dispatch site naming this as the likely
cause; check your log pipeline.

**"Wire-format change broke my workers after I upgraded the
controller."**
The wire-format snapshot tests caught this in CI — but you released
anyway. See [RELEASING.md](../RELEASING.md): wire-format changes
require a coordinated controller-then-worker rollout window. Yank
the controller release, redeploy the prior version, then redo the
rollout in the right order.

## See also

* [Custom dispatcher](./custom-dispatcher.md) — the
  `NatsNodeDispatcher` shape if you need a non-NATS transport.
* [Checkpoint lifecycle](./checkpoint-lifecycle.md) — the
  `CheckpointStore` contract and Postgres reference impl.
* [`WorkflowGraphStore`](./workflow-graph-store.md) — the
  per-tenant security boundary for sub-workflow lookup.
* [Sub-workflow composition](./sub-workflow-composition.md) —
  designing `Judge` / `Ensemble` / `AgentLoop` body workflows.
* [Benchmarking](./benchmarking.md) — scheduler perf regression
  detection.
* [`RELEASING.md`](../RELEASING.md) — version-bump rules + the
  publish workflow.
