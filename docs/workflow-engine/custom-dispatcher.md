# Implementing a custom `NodeDispatcher`

The engine's primary public API — [`ParallelWorkflowEngine::run_with_transport`][run] —
takes an `Arc<dyn NodeDispatcher>`. Everything from wire encoding to retries
to result decoding is the dispatcher's responsibility. The reference NATS
implementation lives in `talos-workflow-engine-nats`; everything else is up
to the consumer.

This guide walks through implementing a dispatcher that talks to an HTTP
worker pool. The same shape applies to any "send a job, get a result"
transport (gRPC, in-process, shell-out, AWS Lambda, …).

## The trait

```rust
use async_trait::async_trait;
use talos_workflow_engine_core::{
    BoxError, ChainDispatchRequest, ChainDispatchResult, DispatchJob,
    DispatchResult, NodeDispatcher, dispatch_chain_sequential,
};

#[async_trait]
pub trait NodeDispatcher: Send + Sync {
    async fn dispatch(&self, job: DispatchJob) -> Result<DispatchResult, BoxError>;

    async fn dispatch_chain(
        &self,
        request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        dispatch_chain_sequential(self, request).await
    }
}
```

`dispatch_chain` has a default body that loops over `dispatch`, so the
minimum impl is one method.

## Minimal HTTP dispatcher

```rust
use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use serde_json::Value as JsonValue;
use talos_workflow_engine_core::{BoxError, DispatchJob, DispatchResult, NodeDispatcher};

pub struct HttpDispatcher {
    client: reqwest::Client,
    worker_url: String,
}

impl HttpDispatcher {
    pub fn new(worker_url: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            // Honor the engine-supplied per-job timeout instead of
            // a global one — see the timeout section below.
            .build()
            .expect("reqwest client builds");
        Self { client, worker_url: worker_url.into() }
    }
}

#[async_trait]
impl NodeDispatcher for HttpDispatcher {
    async fn dispatch(&self, job: DispatchJob) -> Result<DispatchResult, BoxError> {
        // 1. Encode the job. Keep your wire format stable across releases —
        //    a workflow can be enqueued by one engine and resumed by a
        //    later one.
        let body = serde_json::json!({
            "execution_id": job.execution_id,
            "node_id":      job.node_id,
            "module_id":    job.module_id,
            "module_uri":   job.module_uri,
            "input":        job.input_payload,
            "max_fuel":     job.max_fuel,
            "allowed_hosts":   job.allowed_hosts,
            "allowed_methods": job.allowed_methods,
            "allowed_secrets": job.allowed_secrets,
            "encrypted_secrets_ct":    job.encrypted_secrets_ciphertext,
            "encrypted_secrets_nonce": job.encrypted_secrets_nonce,
            "dry_run":  job.dry_run,
            "priority": job.priority,
        });

        // 2. Honor the per-job timeout. The engine does NOT wrap dispatch
        //    in tokio::time::timeout — see the dispatcher trait docs.
        let response = tokio::time::timeout(
            job.timeout,
            self.client
                .post(&self.worker_url)
                .json(&body)
                .send(),
        )
        .await
        .map_err(|_| Box::<dyn std::error::Error + Send + Sync>::from(
            format!("dispatch timed out after {:?}", job.timeout),
        ))?
        .map_err(|e| Box::new(e) as BoxError)?;

        // 3. Decode the worker's response. Returning an Err triggers the
        //    engine's retry classifier; returning Ok with an `__error`
        //    envelope inside the JSON does NOT (it's treated as the
        //    node's own output).
        let output: JsonValue = response
            .json()
            .await
            .map_err(|e| Box::new(e) as BoxError)?;
        Ok(DispatchResult { output })
    }
}
```

## Wire it into the engine

```rust
use std::sync::Arc;
use uuid::Uuid;

let dispatcher = Arc::new(HttpDispatcher::new("https://workers.internal/jobs"));
let context = engine
    .run_with_transport(dispatcher, /* worker_shared_key */ None, Uuid::new_v4())
    .await?;
```

That's the whole integration. The engine builds `DispatchJob`s for each
node it schedules and hands them to your impl; everything else (topology,
fan-out, retries-against-classifier, sub-workflows) is unchanged.

## Five things to get right

### 1. Honor `job.timeout`

The engine deliberately does not wrap your dispatcher in
[`tokio::time::timeout`][to]. The dispatcher owns the full lifecycle
(retries, per-attempt timeouts, transport idle timeouts) and the engine
can't express a sensible outer cap without understanding your retry
policy. If you forget the timeout, a hung worker hangs the whole node.

The reference NATS impl wraps the inner request and adds a small grace
window on top to absorb scheduler jitter.

### 2. Return errors from the trait method, not in the JSON

Two outcomes look superficially similar:

* `Err(BoxError)` from `dispatch` → engine treats this as a transport
  failure. The retry classifier (`set_retry_classifier`) sees the error
  message and decides transient vs permanent.
* `Ok(DispatchResult { output })` where `output` is
  `{"__error": true, "error_message": "..."}` → the node *succeeded* and
  its output happens to encode an error. Downstream nodes still run
  unless an `ErrorHandler` is wired in.

Pick deliberately:

* Network failure, malformed response, signing error → `Err`.
* Worker ran the module and the module itself produced an error envelope
  → `Ok` with `__error: true`.

### 3. Populate `encrypted_secrets_ciphertext` / `_nonce` on the wire

The engine has already encrypted them by the time `dispatch` is called.
Pass them through to the worker untouched. The worker decrypts using the
shared key (out-of-band), populates `vault://...` references in the
config, and runs the module.

If you drop them on the floor, vault-resolved configuration in the
module silently sees empty values. (This is the regression the engine's
`SecretsResolverMissing` typed error was added to prevent — keep the
contract end-to-end.)

### 4. Respect `dry_run`

`job.dry_run = true` means the engine wants a preview run with no
write-bearing side effects. Forward this to the worker. Reference
implementations mock non-GET HTTP calls, webhooks, and messaging; what
your worker does with it depends on what side effects it owns.

### 5. Override `dispatch_chain` if your transport supports batching

The default `dispatch_chain` body loops over `dispatch` sequentially.
Each step pays a full transport round-trip and there is no shared
sandbox between steps. If your transport can ship a batch of jobs to a
single worker (the reference NATS impl uses a `PipelineJobRequest` for
this), override `dispatch_chain` and you'll save N-1 round-trips per
linear chain plus get the option of true sandbox sharing.

```rust
async fn dispatch_chain(
    &self,
    request: ChainDispatchRequest,
) -> Result<ChainDispatchResult, BoxError> {
    // Encode the entire request as one wire message; let the worker
    // pool execute the steps inside a single sandbox.
    self.send_pipeline(request).await
}
```

If you don't care about chain optimization (small graphs, no shared
filesystem state between consecutive nodes), the default is fine.

## Testing your dispatcher

Use the test-utils crate's [`minimal_engine`][me] helper to wire every
other adapter as an in-memory stub, then plug your dispatcher in:

```rust
use std::sync::Arc;
use uuid::Uuid;
use talos_workflow_engine::WorkflowGraphBuilder;
use talos_workflow_engine_test_utils::minimal_engine;

let mut engine = minimal_engine();
engine.set_user_id(Uuid::new_v4());

let dispatcher = Arc::new(HttpDispatcher::new("http://127.0.0.1:8080/jobs"));
let module_id = Uuid::new_v4();

let graph = WorkflowGraphBuilder::new()
    .add_module("hello", module_id, None)
    .build()?;
engine.load_graph_from_json(&serde_json::to_string(&graph)?).await?;

let ctx = engine
    .run_with_transport(dispatcher, None, Uuid::new_v4())
    .await?;
```

Pair with [`wiremock`][wm] (or any HTTP mock) to assert on the request
body and stub the worker's response. The engine doesn't know the
difference between your real transport and a mock one — that's the
trait boundary's whole point.

[run]: https://docs.rs/talos-workflow-engine/0.2/talos_workflow_engine/struct.ParallelWorkflowEngine.html#method.run_with_transport
[to]: https://docs.rs/tokio/latest/tokio/time/fn.timeout.html
[me]: https://docs.rs/talos-workflow-engine-test-utils/0.2/talos_workflow_engine_test_utils/fn.minimal_engine.html
[wm]: https://crates.io/crates/wiremock
