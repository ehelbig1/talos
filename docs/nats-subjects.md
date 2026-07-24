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
| `talos.workers.cmd.shutdown` | `subjects::WORKERS_CMD_SHUTDOWN` | shutdown command | F&F | operator/controller | worker |
| `talos.agent.<target>.invoke` | `subjects::agent_invoke_for(target)` | signed agent-invoke envelope | F&F | worker agent-orchestration host | target agent subscriber |
| `talos.agent.<target>.message` | `subjects::agent_message_for(target)` | signed agent-message envelope | F&F | worker agent-orchestration host | target agent subscriber |
| `talos.events.<exec_id>.<event_type>` | `subjects::workflow_event_for(exec_id, ty)` | guest event JSON | F&F | worker `events` host | event subscribers |
| `talos.llm.stream.<execution_id>` | `subjects::llm_stream_for(execution_id)` | token-chunk JSON | Sub | worker LLM-streaming host | GraphQL subscription relay |
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

## Notes / not subjects

The following `talos.`-prefixed strings are NOT NATS subjects and are
deliberately left as-is:

- **`talos.json` / `talos.wit`** — module manifest / WIT interface filenames.
- **`talos:core/*`** — WIT interface names (colon namespace).
- **OTLP span-attribute keys** in `talos-audit-ledger` (`talos.workflow.id`,
  `talos.crypto.sequence`, …) and tracing `target: "talos_audit_ledger"` labels.
