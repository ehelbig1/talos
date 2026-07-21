//! NATS-backed `NodeDispatcher` + `JobTransport` for the
//! [`talos-workflow-engine`](../talos_workflow_engine/) crate.
//!
//! Implements a signed-NATS job protocol (see [`talos_workflow_job_protocol`]):
//! every dispatched node becomes a `JobRequest` with an HMAC-SHA256
//! signature over its canonical byte form, sent to a priority-routed
//! NATS subject and matched with a reply `JobResult` that is verified
//! before its output is unwrapped back to the engine.
//!
//! ## Topic routing
//!
//! Single-node jobs publish to `workflow.jobs` (or, when
//! `ENABLE_EDGE_ROUTING=true`, `workflow.jobs.<user_id>`). Jobs with
//! priority >= 200 are suffixed with `.priority` so workers can
//! subscribe to high-priority work first. Chain dispatches use the
//! parallel `workflow.pipeline.jobs[.<user_id>][.priority]` tree.
//!
//! The `Uuid::nil()` user-id sentinel maps back to `None` so "no user
//! context" stays on the tenant-agnostic subject rather than being
//! mis-routed to `workflow.jobs.00000000-...`.
//!
//! ## Retry semantics
//!
//! Both the transport loop and the application-level job loop retry
//! with exponential backoff + jitter. The application loop also:
//!
//! * verifies the result's HMAC signature when `worker_shared_key` is
//!   set;
//! * evaluates an optional `retry_condition` (rhai expression) against
//!   the error payload to block retries in known-permanent-failure
//!   shapes;
//! * classifies unconditional errors via
//!   [`talos_workflow_engine_core::RetryClassifier`] and skips retries on
//!   non-transient classes (auth / fuel / missing-secret);
//! * emits per-attempt `node_retrying` / `retry_skipped`
//!   execution events when an [`EventSink`] is wired and the caller
//!   opted into retry-event emission.
//!
//! Timeouts are never retried — a timeout means the job ran but took
//! too long, which is not a delivery issue.
//!
//! ## When to use this crate
//!
//! If your worker pool already speaks this signed-NATS job protocol,
//! reuse the dispatcher directly — the wire format, HMAC canonicalisation,
//! and topic routing here match what the worker expects.
//!
//! If you're embedding [`talos-workflow-engine`](../talos_workflow_engine/) in a
//! new product, you can either:
//!
//! 1. reuse this crate and adopt the job protocol for your workers
//!    (easy path); or
//! 2. implement your own `NodeDispatcher` + `JobTransport` and ignore
//!    this crate entirely (preferred when you have a different wire
//!    format or a non-NATS transport).
//!
//! [`EventSink`]: talos_workflow_engine_core::EventSink
//! [`talos_workflow_job_protocol`]: ../talos_workflow_job_protocol/

mod dispatcher;
mod run;
mod transport;

pub use dispatcher::{EnvelopeSealingHandle, LlmUsageReport, LlmUsageSink, NatsNodeDispatcher};
pub use run::{run_with_nats, run_with_seed_via_nats};
pub use transport::NatsTransport;
