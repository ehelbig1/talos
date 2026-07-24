//! Canonical NATS subject registry.
//!
//! Every `talos.*` NATS subject the platform publishes to or subscribes on is
//! named here ONCE. Before this module the ~two dozen subjects were spelled
//! out as bare string literals scattered across a dozen crates (worker,
//! controller, the OAuth integration dispatchers, the audit ledger, …), so a
//! typo or a rename could silently split a producer from its consumer with no
//! compile-time signal. Centralising them turns "does the worker publish where
//! the controller listens?" into a shared-const identity the compiler checks.
//!
//! # Scope
//!
//! This module owns the **job / pipeline / results / audit / approvals /
//! worker-fleet / agent-orchestration / workflow-event / LLM-stream** subjects
//! — the ones shared across process boundaries. Two families are canonical
//! ELSEWHERE and are intentionally NOT duplicated here (referencing the
//! existing const is the rule, per the platform's "one authoritative name"
//! discipline):
//!
//! * **Signed data-RPC subjects** (`talos.memory.op`, `talos.graph.search`,
//!   `talos.database.query`, `talos.state.write`, `talos.ml.predict`,
//!   `talos.ml.fewshot`, `talos.integration_state.op`) live on their protocol
//!   types in `talos-memory` as `SUBJECT_*` consts (e.g.
//!   `talos_memory::memory_rpc::SUBJECT_MEMORY_OP`). They are re-exported here
//!   only so the documentation table has a single reading order — the source of
//!   truth stays in `talos-memory`.
//! * **`talos.alerts.execution_failed`** is `EXECUTION_FAILED_ALERT_SUBJECT` in
//!   `talos-execution-result-collector`. Mirrored here as [`ALERTS_EXECUTION_FAILED`]
//!   for the registry table; that crate keeps the canonical const (adding a
//!   job-protocol dependency there just for a string is not worth the edge).
//!
//! # Wire-compatibility rule
//!
//! The string VALUES here are load-bearing wire identifiers. Changing a value
//! is a breaking protocol change (a rolling deploy would split producers from
//! consumers mid-flight). Renames of the Rust CONSTS are free; the strings are
//! frozen.

// ── Namespace ────────────────────────────────────────────────────────────

/// The reserved subject namespace prefix for every platform-owned NATS
/// subject. Guest (WASM) code is denied publish rights on anything under this
/// prefix — see `RESERVED_PUBLISH_PREFIXES` in the worker runtime. This is a
/// PREFIX, not a subject; do not publish to it directly.
pub const NAMESPACE_PREFIX: &str = "talos.";

// ── Job dispatch ─────────────────────────────────────────────────────────

/// Tenant-agnostic single-node job subject (fallback when no user context).
/// Request → worker; the worker replies on the signed reply inbox.
pub const JOBS: &str = "talos.jobs";

/// Tenant-agnostic pipeline (chain) job subject.
pub const PIPELINE_JOBS: &str = "talos.pipeline.jobs";

/// Per-user single-node job subject: `talos.jobs.<user_id>`.
///
/// The OAuth integration dispatchers (Gmail / Google Calendar / Google Cloud)
/// and the inbound webhook router publish module-bound jobs here so a
/// per-user worker pool can subscribe to only its own tenant's work.
#[must_use]
pub fn jobs_for(user_id: impl std::fmt::Display) -> String {
    format!("{JOBS}.{user_id}")
}

// ── Job / pipeline results ─────────────────────────────────────────────────

/// Wildcard the controller subscribes on to collect single-node job results:
/// `talos.results.*`. (Used only where the reply-inbox path is not in play.)
pub const RESULTS_WILDCARD: &str = "talos.results.*";

/// Per-job single-node result subject: `talos.results.<job_id>`.
#[must_use]
pub fn results_for(job_id: impl std::fmt::Display) -> String {
    format!("talos.results.{job_id}")
}

/// Per-job pipeline result subject: `talos.pipeline.results.<job_id>`.
#[must_use]
pub fn pipeline_results_for(job_id: impl std::fmt::Display) -> String {
    format!("talos.pipeline.results.{job_id}")
}

// ── Audit ledger ───────────────────────────────────────────────────────────

/// Append-only cryptographic audit-event stream. The worker (producer) publishes
/// hash-chained, HMAC-signed `AuditEvent`s here; the `talos-audit-ledger` WORM
/// consumer subscribes. Fire-and-forget.
pub const AUDIT_LEDGER: &str = "talos.audit.ledger";

// ── Human-in-the-loop approvals ────────────────────────────────────────────

/// Subject the worker publishes an approval REQUEST on when a governance node
/// suspends for human review. Fire-and-forget; the controller's continuation
/// trigger consumes it.
pub const APPROVALS_PENDING: &str = "talos.approvals.pending";

/// Per-execution approval-wait reply subject: `talos.approvals.wait.<exec_id>`.
/// The worker publishes its `reply_topic` here so the approve/reject webhook can
/// resume the suspended execution.
#[must_use]
pub fn approvals_wait_for(exec_id: impl std::fmt::Display) -> String {
    format!("talos.approvals.wait.{exec_id}")
}

// ── Worker fleet ───────────────────────────────────────────────────────────

/// Wildcard the fleet manager subscribes on to observe worker heartbeats:
/// `talos.workers.heartbeat.>`.
pub const WORKERS_HEARTBEAT_WILDCARD: &str = "talos.workers.heartbeat.>";

/// Per-worker heartbeat subject: `talos.workers.heartbeat.<worker_id>`.
#[must_use]
pub fn worker_heartbeat_for(worker_id: impl std::fmt::Display) -> String {
    format!("talos.workers.heartbeat.{worker_id}")
}

/// Fleet-wide graceful-shutdown command subject.
pub const WORKERS_CMD_SHUTDOWN: &str = "talos.workers.cmd.shutdown";

// ── Agent orchestration ────────────────────────────────────────────────────

/// Per-target agent invoke subject: `talos.agent.<target>.invoke`. The worker's
/// `agent-orchestration` host publishes a signed invoke envelope here.
#[must_use]
pub fn agent_invoke_for(target: impl std::fmt::Display) -> String {
    format!("talos.agent.{target}.invoke")
}

/// Per-target agent message subject: `talos.agent.<target>.message`.
#[must_use]
pub fn agent_message_for(target: impl std::fmt::Display) -> String {
    format!("talos.agent.{target}.message")
}

// ── Workflow events ────────────────────────────────────────────────────────

/// Per-execution workflow-event subject: `talos.events.<exec_id>.<event_type>`.
/// Emitted by the worker's `messaging` host for guest-observable lifecycle
/// events.
#[must_use]
pub fn workflow_event_for(
    exec_id: impl std::fmt::Display,
    event_type: impl std::fmt::Display,
) -> String {
    format!("talos.events.{exec_id}.{event_type}")
}

// ── LLM streaming ──────────────────────────────────────────────────────────

/// Per-execution LLM token-stream subject: `talos.llm.stream.<execution_id>`.
/// The GraphQL subscription layer subscribes here to relay streamed tokens to a
/// connected client.
#[must_use]
pub fn llm_stream_for(execution_id: impl std::fmt::Display) -> String {
    format!("talos.llm.stream.{execution_id}")
}

// ── Mirrored-for-documentation subjects (canonical const lives elsewhere) ──

/// Execution-failure alert subject. **Canonical const:**
/// `talos_execution_result_collector::EXECUTION_FAILED_ALERT_SUBJECT`. Mirrored
/// here only for the registry table — do not import this in preference to the
/// canonical const in the crate that owns the alert pipeline.
pub const ALERTS_EXECUTION_FAILED: &str = "talos.alerts.execution_failed";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builders_match_frozen_wire_format() {
        let id = "abc123";
        assert_eq!(jobs_for(id), "talos.jobs.abc123");
        assert_eq!(results_for(id), "talos.results.abc123");
        assert_eq!(pipeline_results_for(id), "talos.pipeline.results.abc123");
        assert_eq!(approvals_wait_for(id), "talos.approvals.wait.abc123");
        assert_eq!(worker_heartbeat_for(id), "talos.workers.heartbeat.abc123");
        assert_eq!(agent_invoke_for(id), "talos.agent.abc123.invoke");
        assert_eq!(agent_message_for(id), "talos.agent.abc123.message");
        assert_eq!(workflow_event_for(id, "done"), "talos.events.abc123.done");
    }

    #[test]
    fn every_builder_and_const_is_under_the_namespace() {
        for s in [
            JOBS,
            PIPELINE_JOBS,
            RESULTS_WILDCARD,
            AUDIT_LEDGER,
            APPROVALS_PENDING,
            WORKERS_HEARTBEAT_WILDCARD,
            WORKERS_CMD_SHUTDOWN,
            ALERTS_EXECUTION_FAILED,
        ] {
            assert!(s.starts_with(NAMESPACE_PREFIX), "{s} escapes the namespace");
        }
    }

    #[test]
    fn llm_stream_uses_execution_id() {
        let ex = uuid::Uuid::nil();
        assert_eq!(llm_stream_for(ex), format!("talos.llm.stream.{ex}"));
    }
}
