# NATS subject registry

Every `talos.*` NATS subject the platform uses is named ONCE in code so a
producer and its consumer share a compiler-checked identity instead of two
independent string literals that can silently drift apart.

## Where the names live

| Family | Canonical Rust location |
|---|---|
| Job / pipeline / results / audit / approvals / worker-fleet / agent / events / LLM-stream | **`talos_workflow_job_protocol::subjects`** (this is the authoritative module) |
| Signed data-RPC subjects (`memory` / `graph` / `database` / `state` / `ml` / `integration_state`) | `talos_memory::*::SUBJECT_*` consts (on the protocol types); re-listed below for reading order |
| `talos.alerts.execution_failed` | `talos_execution_result_collector::EXECUTION_FAILED_ALERT_SUBJECT` |

**Wire-compatibility rule:** the string *values* are frozen protocol identifiers.
Renaming a Rust const is free; changing the string it holds is a breaking change
that would split producers from consumers during a rolling deploy. Add new
subjects to `talos_workflow_job_protocol::subjects` (or the appropriate protocol
type) — never re-introduce a bare `"talos...."` literal in production code.

## Subject table

Legend — Mode: **R/R** = request/reply, **F&F** = fire-and-forget, **Stream** =
JetStream/durable, **Sub** = long-lived subscription.

| Subject (value) | Const / builder | Payload type | Mode | Producer | Consumer |
|---|---|---|---|---|---|
| `talos.jobs` | `subjects::JOBS` | `JobRequest` | R/R (signed reply inbox) | engine dispatcher / integration dispatchers (fallback) | worker pool |
| `talos.jobs.<user_id>` | `subjects::jobs_for(user_id)` | `JobRequest` | R/R | Gmail / GCal / GCloud dispatchers, webhook router (edge routing on) | per-user worker pool |
| `talos.pipeline.jobs` | `subjects::PIPELINE_JOBS` | `PipelineJobRequest` | R/R | engine dispatcher | worker pool |
| `talos.results.*` | `subjects::RESULTS_WILDCARD` | `JobResult` | Sub | worker | controller results collector |
| `talos.results.<job_id>` | `subjects::results_for(job_id)` | `JobResult` | F&F (audit topic branch) | worker | controller |
| `talos.pipeline.results.<job_id>` | `subjects::pipeline_results_for(job_id)` | `PipelineJobResult` | R/R + F&F cache-replay | worker | controller |
| `talos.audit.ledger` | `subjects::AUDIT_LEDGER` | `AuditEvent` (hash-chained, signed) | Stream (F&F publish) | worker host fns (audit) | `talos-audit-ledger` WORM consumer |
| `talos.approvals.pending` | `subjects::APPROVALS_PENDING` | approval-request JSON | F&F | worker governance host | controller continuation trigger |
| `talos.approvals.wait.<exec_id>` | `subjects::approvals_wait_for(exec_id)` | approval-response JSON | R/R (reply topic) | worker governance host (subscribes) | approve/reject webhook handler |
| `talos.workers.heartbeat.>` | `subjects::WORKERS_HEARTBEAT_WILDCARD` | `WorkerHeartbeat` | Sub | worker | fleet manager |
| `talos.workers.heartbeat.<worker_id>` | `subjects::worker_heartbeat_for(id)` | `WorkerHeartbeat` | F&F | worker | fleet manager |
| `talos.workers.cmd.shutdown` | `subjects::WORKERS_CMD_SHUTDOWN` | shutdown command | F&F | **inert** — zero publishers, zero subscribers (`docs/inert-mechanisms.md`) | — |
| `talos.workers.cmd.cancel` | `subjects::WORKERS_CMD_CANCEL` | `CancelCommand` (signed) | F&F, PLAIN subscribe on every worker (never a queue group) | controller (`talos-execution-orchestration::cancel`) | every worker (`run_cancel_listener`) |
| `talos.agent.<target>.invoke` | `subjects::agent_invoke_for(target)` | signed agent-invoke envelope | F&F | worker agent-orchestration host | target agent subscriber |
| `talos.agent.<target>.message` | `subjects::agent_message_for(target)` | signed agent-message envelope | F&F | worker agent-orchestration host | target agent subscriber |
| `talos.events.<exec_id>.<event_type>` | `subjects::workflow_event_for(exec_id, ty)` | guest event JSON | F&F | worker `events` host | event subscribers |
| `talos.llm.stream.<execution_id>` | `subjects::llm_stream_for(execution_id)` | token-chunk JSON | Sub | **none today** (measured 2026-09-10: no publisher in `worker/` or `talos-worker-runtime/`) | GraphQL subscription relay (`talos-api` subscriptions) |
| `talos.alerts.execution_failed` | `EXECUTION_FAILED_ALERT_SUBJECT` (in `talos-execution-result-collector`) | failure-alert JSON | F&F | execution-result collector | alert consumers |
| `talos.memory.op` | `talos_memory::memory_rpc::SUBJECT_MEMORY_OP` | `MemoryOp` | R/R (cap 16) | worker | controller memory subscriber |
| `talos.graph.search` | `talos_memory::graph_rpc::SUBJECT_GRAPH_SEARCH` | `GraphSearchRequest` | R/R (cap 8) | worker | controller graph subscriber |
| `talos.database.query` | `talos_memory::database_rpc::SUBJECT_DATABASE_QUERY` | `DatabaseRpcRequest` | R/R (cap 8) | worker | controller DB subscriber |
| `talos.state.write` | `talos_memory::state_rpc::SUBJECT_STATE_WRITE` | `StateWriteRequest` | F&F (cap 32) | worker | controller state subscriber |
| `talos.ml.predict` | `talos_memory::ml_rpc::SUBJECT_ML_PREDICT` | `MlPredictRequest` | R/R (cap 8) | worker | controller ML subscriber |
| `talos.ml.fewshot` | `talos_memory::ml_rpc::SUBJECT_ML_FEWSHOT` | `MlFewShotRequest` | R/R (cap 8) | worker | controller ML subscriber |
| `talos.integration_state.op` | `talos_memory::integration_state_rpc::SUBJECT_INTEGRATION_STATE_OP` | `IntegrationStateRequest` | R/R | worker | controller integration-state subscriber |

`talos.` (namespace prefix) is `subjects::NAMESPACE_PREFIX` — used by the worker's
guest-publish deny-list (`RESERVED_PUBLISH_PREFIXES`), not a subject itself.

Subjects the engine dispatcher (`talos-workflow-engine-nats`) derives from
`WORKFLOW_NATS_PREFIX` — default `workflow`, set to `talos` by every deployment
(docker-compose.yml, the chart's controller ConfigMap) — also produce
`<prefix>.jobs.priority` / `<prefix>.pipeline.jobs.priority` for
high-priority dispatch. **No worker subscribes to the `.priority` children**;
a priority dispatch lands on a subject nobody is listening on. Recorded here so
the table is honest about it; it is not repaired by this document.

## Broker permissions — two credentials (2026-09-10)

Every process used to authenticate as ONE NATS user with no `permissions`
block, so a worker could subscribe to `_INBOX.>` (every reply the controller
awaits), `talos.results.*` (other workers' output) and `wasm.log.*`, and could
publish forged jobs, cancels and approvals that signing rejected only AFTER a
verify. There are now two credentials, and the worker's carries a permission
set whose ONE home is `talos_workflow_job_protocol::nats_permissions`:

| Credential | Env (deployment) | Permissions |
|---|---|---|
| controller | `NATS_USER` / `NATS_PASSWORD` | none — unrestricted (the trusted party; replies to worker RPCs into `_WINBOX.>`) |
| worker | `NATS_WORKER_USER` / `NATS_WORKER_PASSWORD` in the bootstrap Secret / `.env`; the worker BINARY still reads them as `NATS_USER` / `NATS_PASSWORD` | `WORKER_PERMISSIONS` — see below |

* **Subscribe is an ALLOW-list** (`WORKER_SUBSCRIBE_ALLOW`): `talos.jobs`,
  `talos.jobs.>`, `talos.pipeline.jobs`, `talos.pipeline.jobs.>`,
  `talos.workers.cmd.cancel`, `talos.approvals.wait.>`, `_WINBOX.>`. That is
  the worker's whole subscribe footprint; everything else on the bus is
  refused at the broker.
* **Publish is a DENY-list** (`WORKER_PUBLISH_DENY`): the two job families,
  `talos.workers.cmd.>`, `talos.alerts.>`, `talos.approvals.wait.>`,
  `talos.llm.stream.>`, `_WINBOX.>`, `$SYS.>`, `$JS.>`, `$KV.>`, `$O.>`. A
  deny-list rather than an allow-list because the guest `messaging` WIT may
  publish to ANY non-reserved subject (the catalog's `message-publisher` takes
  its topic from module config), and a publish permission violation is an
  asynchronous `-ERR` the publisher never sees — an allow-list would have made
  every guest publish to an unlisted subject a silent drop reported as success.
* **`_WINBOX`** is the worker connection's inbox prefix
  (`ConnectOptions::custom_inbox_prefix`, set in `worker/src/main.rs`); the
  controller keeps async-nats' default `_INBOX`. A controller credential that
  is ever given a permissions block must allow publish on `_WINBOX.>`.
* The worker connection installs an **event callback** that logs the broker's
  `-ERR Permissions Violation …` lines at WARN (`target: "talos_nats"`), since
  neither `publish()` nor `subscribe()` returns that refusal to the caller.

Where the set is enforced and pinned: the rendered fragment lives at
`deploy/nats/worker-permissions.conf` (compose) and
`deploy/helm/talos/files/nats-worker-permissions.conf` (chart), both
byte-pinned to the Rust render by `cargo test -p talos-workflow-job-protocol
nats_permissions` (regenerate with `TALOS_NATS_PERMISSIONS_WRITE=1`); the seven
signed-RPC subjects are cross-pinned from `talos-memory`; and
`talos-workflow-engine-nats/tests/nats_worker_permissions.rs` drives the real
config on a live `nats-server` in `make test-integration`, asserting the broker
agrees with the model on every subject in its table (each probe with a control
on the unrestricted credential) and that both request/reply shapes round-trip.

**Stated limits.** The prefix is per process KIND, not per worker — every
worker shares `_WINBOX.>`, so a compromised worker can still read a sibling's
RPC replies; per-worker isolation needs NATS accounts or auth callout, which a
static config cannot mint. `talos.jobs` is visible to every worker by design (it
is the queue), so the `encrypted_secrets` envelope under the fleet-shared
`WORKER_SHARED_KEY` is readable by every worker; the control for that is
per-execution envelope sealing (`TALOS_ENVELOPE_SEALING=required`), not
permissions. An operator who overrides `NATS_JOB_TOPIC` / `NATS_PIPELINE_TOPIC`
outside `talos.jobs.>` / `talos.pipeline.jobs.>` must widen the allow-list.

## Notes / not subjects

The following `talos.`-prefixed strings are NOT NATS subjects and are
deliberately left as-is:

- **`talos.json` / `talos.wit`** — module manifest / WIT interface filenames.
- **`talos:core/*`** — WIT interface names (colon namespace).
- **OTLP span-attribute keys** in `talos-audit-ledger` (`talos.workflow.id`,
  `talos.crypto.sequence`, …) and tracing `target: "talos_audit_ledger"` labels.
