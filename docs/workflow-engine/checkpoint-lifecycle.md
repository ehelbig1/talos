# Checkpoint lifecycle: pause and resume

The engine supports resuming a workflow from a snapshot of completed-node
outputs. The mechanism is intentionally minimal: the engine doesn't run
the persistence layer itself. The consumer implements the
[`CheckpointStore`][cs] trait, snapshots state at the right moments, and
uses [`run_with_seed_with_transport`][seed] to resume.

This guide covers the three pieces:

1. When the engine pauses (and what "pause" means here).
2. How to implement `CheckpointStore` and snapshot the right state.
3. How to resume — what to seed, what NOT to seed.

## When does a workflow pause?

Three signals come from the engine to the consumer:

| Signal | Source | Resume path |
|---|---|---|
| `Wait` system node | Workflow author | Caller waits for an external signal (webhook, human approval), then resumes. |
| `ConfidenceGate` with `on_low_confidence: "pause"` | Engine, when the gate's threshold isn't met | Caller waits for the configured `ApprovalGate` to flip to `Approved`, then resumes. |
| Approval-required module | Engine, when a module declares `requires_approval_for` | Same as above. |

In every case the engine returns a [`WorkflowContext`][ctx] whose
`results` map carries an entry with `__waiting__: true` (or
`__paused__: true`) for the paused node. That's the signal to snapshot
and stop dispatching.

## Implementing `CheckpointStore`

The trait has two methods:

```rust
use std::collections::HashMap;
use async_trait::async_trait;
use serde_json::Value as JsonValue;
use uuid::Uuid;
use talos_workflow_engine_core::{BoxError, CheckpointStore};

#[async_trait]
pub trait CheckpointStore: Send + Sync {
    async fn load(&self, execution_id: Uuid) -> Result<HashMap<Uuid, JsonValue>, BoxError>;
    async fn save(&self, execution_id: Uuid, snapshot: &JsonValue) -> Result<(), BoxError>;
}
```

A Postgres-backed reference impl looks like:

```rust
pub struct PgCheckpointStore {
    pool: sqlx::PgPool,
}

#[async_trait]
impl CheckpointStore for PgCheckpointStore {
    async fn load(&self, execution_id: Uuid) -> Result<HashMap<Uuid, JsonValue>, BoxError> {
        let row: Option<(JsonValue,)> = sqlx::query_as(
            "SELECT snapshot FROM workflow_checkpoints WHERE execution_id = $1"
        )
        .bind(execution_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Box::new(e) as BoxError)?;

        // Empty map = no checkpoint = fresh run. Documented contract.
        let Some((snapshot,)) = row else {
            return Ok(HashMap::new());
        };

        // The snapshot is a JSON object: { "<node-uuid>": <output> }.
        let obj = snapshot
            .as_object()
            .ok_or_else(|| -> BoxError { "snapshot is not an object".into() })?;

        let mut out = HashMap::with_capacity(obj.len());
        for (k, v) in obj {
            let id = Uuid::parse_str(k)
                .map_err(|e| -> BoxError { format!("bad node id {k}: {e}").into() })?;
            out.insert(id, v.clone());
        }
        Ok(out)
    }

    async fn save(&self, execution_id: Uuid, snapshot: &JsonValue) -> Result<(), BoxError> {
        sqlx::query(
            "INSERT INTO workflow_checkpoints (execution_id, snapshot, saved_at)
             VALUES ($1, $2, now())
             ON CONFLICT (execution_id) DO UPDATE
                SET snapshot = EXCLUDED.snapshot, saved_at = EXCLUDED.saved_at"
        )
        .bind(execution_id)
        .bind(snapshot)
        .execute(&self.pool)
        .await
        .map_err(|e| Box::new(e) as BoxError)?;
        Ok(())
    }
}
```

### Encryption at rest

The trait traffics in plaintext `JsonValue`. Per-node outputs may carry
PII or secrets that the engine has already let through its
`OutputSanitizer`. **If your store persists to disk or a database, wrap
the snapshot in AES-256-GCM (or the consumer's chosen AEAD) inside the
impl** — the engine never sees the ciphertext. The reference controller
store derives a **per-execution AEAD subkey** from the `WORKER_SHARED_KEY`
root via HKDF, folding `execution_id` into the derivation `info`
(`checkpoint-aead/v2-per-execution`), with a fresh nonce per save. Decrypt
tries the per-execution (v2) derivation, then falls back to the legacy
static (v1) derivation so checkpoints written before the rollout still
resume. `execution_id` is also bound as AES-GCM additional-authenticated
data, so a snapshot stolen from one execution can't be opened — let alone
replayed — under another id.

### Idempotency

`save` overwrites prior snapshots for the same `execution_id`. Use
`INSERT … ON CONFLICT DO UPDATE` (Postgres) or the equivalent
transactional upsert, not blind `INSERT`.

## Snapshotting at the right moments

The engine doesn't auto-call `save` for you. Pick a snapshot trigger
based on durability vs. latency:

* **After every node completes** — strongest durability; one DB write
  per node. Wire via [`NodeLifecycleHook::on_node_completed`][hook] —
  the hook receives the node id and output as it lands. Best for
  long-running workflows where you can't afford to redo work.
* **On pause only** — cheapest; one DB write per pause. The caller
  detects the `__waiting__` entry in the returned `WorkflowContext`,
  snapshots the entire `results` map, and stops dispatching. Best for
  short workflows where pause is rare.

The on-completion path needs your `NodeLifecycleHook` impl to hold the
`Arc<dyn CheckpointStore>` and call `save` from inside `on_node_completed`.
The pause path is purely caller-side:

```rust
let ctx = engine
    .run_with_transport(dispatcher.clone(), shared_key.clone(), execution_id)
    .await?;

if ctx.results.values().any(is_waiting) {
    let snapshot = serde_json::Value::Object(
        ctx.results
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect(),
    );
    checkpoint_store.save(execution_id, &snapshot).await?;
    return Ok(());  // bail out; resume later via the trigger.
}

fn is_waiting(v: &serde_json::Value) -> bool {
    v.get("__waiting__").and_then(|w| w.as_bool()).unwrap_or(false)
        || v.get("__paused__").and_then(|w| w.as_bool()).unwrap_or(false)
}
```

## Resuming

Resume is one method:

```rust
let prior_results = checkpoint_store.load(execution_id).await?;

let ctx = engine
    .run_with_seed_with_transport(
        dispatcher,
        shared_key,
        prior_results,         // ← what `load` returned
        execution_id,          // ← same id as the original run
    )
    .await?;
```

The seeded path treats every node in `prior_results` as already
completed and only schedules its successors. Three things to watch:

1. **Same `execution_id`.** Observability events, module-execution
   audit rows, and the engine's own internal accounting key off
   `execution_id`. Resume with a fresh id and you've started a new run
   that happens to share state.
2. **Pre-pause node outputs only.** Don't seed with the `__waiting__`
   marker for the paused node — that's not its real output. Either
   omit the paused node from the seed (so the engine re-dispatches it,
   which is what you want for `Wait` nodes after the external signal
   arrives) or replace its entry with the actual external input that
   the resume should treat as the node's output.
3. **The pipeline-chain optimization is disabled on resume.** The
   engine dispatches every node individually because the chain
   detector would otherwise build chains spanning already-completed
   nodes. Single-node throughput is the same; large linear graphs may
   take a few extra round-trips.

## End-to-end example

A runnable demo that exercises the entire pause-checkpoint-resume cycle
ships in `talos-workflow-engine/examples/checkpoint_resume.rs`:

```bash
cargo run --example checkpoint_resume -p talos-workflow-engine
```

It uses an in-memory `CheckpointStore` (one `Mutex<HashMap>`) and the
test-utils dispatcher so you can read the whole flow in ~150 lines.
The pattern transfers verbatim to a real Postgres or S3 store.

[cs]: https://docs.rs/talos-workflow-engine-core/0.2/talos_workflow_engine_core/trait.CheckpointStore.html
[seed]: https://docs.rs/talos-workflow-engine/0.2/talos_workflow_engine/struct.ParallelWorkflowEngine.html#method.run_with_seed_with_transport
[ctx]: https://docs.rs/talos-workflow-engine-core/0.2/talos_workflow_engine_core/struct.WorkflowContext.html
[hook]: https://docs.rs/talos-workflow-engine-core/0.2/talos_workflow_engine_core/trait.NodeLifecycleHook.html
