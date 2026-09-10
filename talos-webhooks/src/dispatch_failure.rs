//! Classification of POST-AUTH webhook dispatch failures for DLQ capture.
//!
//! The webhook DLQ holds two classes of row, and `dispatch_replay` treats
//! them oppositely (see `dlq::DLQ_AUTHENTICATED_KEY`):
//!
//! * **Pre-auth drops** (`drop_reason` `circuit_breaker` / `rate_limit`) —
//!   refusals taken BEFORE the signature / verification-token / IP-allowlist
//!   gate. Kept as a record; NEVER replayable, because nothing ever verified
//!   the payload.
//! * **Post-auth dispatch failures** — the request passed the auth gate and
//!   the platform then failed to run it. These are the rows replay exists
//!   for, and this module decides which post-auth failure points qualify.
//!
//! The rule for the second class: a replay is the right remedy ONLY when the
//! module (or workflow engine) never observed the delivery. A module that
//! RAN and returned an error has already been recorded in
//! `module_executions` and may have had side effects (sent a message, wrote
//! memory); re-dispatching it doubles those. So the partition is drawn at
//! the worker: everything up to and including "we published and heard
//! nothing back" is replayable, everything from "the worker answered" on is
//! not.
//!
//! Stated limit, carried into every replayable variant's doc: at-least-once.
//! A publish that reports failure after the broker accepted it, or a reply
//! window that expires while the worker is still executing, leaves a
//! replayable row for a job that may well have run. The sender ALSO receives
//! a 500 at these sites and may retry on its own, so an operator replay is
//! a THIRD possible execution of one delivery. Replay is an operator
//! decision; `webhook_request_log` and `module_executions` are the record to
//! consult before taking it. The dedup store does not protect against this —
//! `dispatch_replay` bypasses it by design, and the pre-dispatch sites
//! release the claim so the sender's retry is honoured.

/// Why a module-bound webhook dispatch failed, partitioned by whether the
/// worker ever observed the job. Returned from the request/reply dispatch
/// task in place of a bare `anyhow::Error` so the caller can decide DLQ
/// capture from the TYPE rather than by matching error text.
#[derive(Debug)]
pub enum ModuleDispatchFailure {
    /// The job never left this process — a registry read, secret
    /// preparation, request signing/encoding, the reply-inbox subscribe or
    /// the publish itself failed. Replayable: the worker saw nothing.
    ///
    /// The one at-least-once edge: `publish` can report an error after the
    /// broker has accepted the message (connection reset mid-ack). Recorded
    /// under `module_publish_failed` so an operator can tell it apart.
    NotDispatched {
        drop_reason: &'static str,
        detail: String,
    },
    /// The job WAS published and no result arrived on the signed reply inbox
    /// within the reply window, or the inbox closed first. Replayable per the
    /// task brief, with the caveat in the module doc: the worker may still be
    /// executing (the window is 3 s, the same as the job's own `timeout_ms`,
    /// but queue wait is not counted), so this is the variant most likely to
    /// double an execution on replay.
    ReplyLost {
        drop_reason: &'static str,
        detail: String,
    },
    /// The worker answered. The result failed signature verification, could
    /// not be parsed, or reported a failed execution. NOT replayable: an
    /// execution happened (or something is impersonating one), and
    /// `module_executions` already records it.
    Answered { detail: String },
}

/// Drop reasons for the replayable post-auth sites, one per site so the DLQ
/// list says WHERE the platform failed rather than only that it did.
pub mod drop_reason {
    /// `ModuleRegistry::get_module_bytes` failed (handle_webhook step 6).
    pub const MODULE_LOAD_FAILED: &str = "module_load_failed";
    /// `ModuleRegistry::get_module_config` failed.
    pub const MODULE_CONFIG_FAILED: &str = "module_config_failed";
    /// The bound actor's tier/ceiling/egress triple could not be read; the
    /// dispatch refused rather than run at a posture it never read (#736).
    pub const MODULE_ACTOR_CEILINGS_UNREADABLE: &str = "module_actor_ceilings_unreadable";
    /// The `module_executions` tracking row INSERT failed; dispatching an
    /// untrackable job is refused.
    pub const MODULE_EXECUTION_ROW_FAILED: &str = "module_execution_row_failed";
    /// `ModuleRegistry::get_execution_info` failed inside the dispatch task.
    pub const MODULE_EXEC_INFO_FAILED: &str = "module_exec_info_failed";
    /// Ed25519 / HMAC signing of the `JobRequest` failed.
    pub const MODULE_SIGN_FAILED: &str = "module_sign_failed";
    /// The signed `JobRequest` could not be serialised.
    pub const MODULE_REQUEST_ENCODE_FAILED: &str = "module_request_encode_failed";
    /// Subscribing to the signed reply inbox failed (nothing was published).
    pub const MODULE_REPLY_SUBSCRIBE_FAILED: &str = "module_reply_subscribe_failed";
    /// `publish_with_reply` failed. At-least-once edge — see the module doc.
    pub const MODULE_PUBLISH_FAILED: &str = "module_publish_failed";
    /// No result within the reply window.
    pub const MODULE_REPLY_TIMEOUT: &str = "module_reply_timeout";
    /// The reply inbox subscription ended before a result arrived (NATS
    /// connection loss).
    pub const MODULE_REPLY_INBOX_CLOSED: &str = "module_reply_inbox_closed";

    /// Workflow path: the dispatch-authorization read failed (DB error; the
    /// gate fails closed). Engine never ran.
    pub const WORKFLOW_AUTH_DB_ERROR: &str = "workflow_auth_db_error";
    /// Workflow path: `create_execution_under_concurrency_limit` failed.
    /// Engine never ran.
    pub const WORKFLOW_EXECUTION_ROW_FAILED: &str = "workflow_execution_row_failed";
    /// Workflow path: the graph could not be loaded / the engine could not be
    /// built. The execution row was created and marked failed; the engine
    /// never ran.
    pub const WORKFLOW_GRAPH_LOAD_FAILED: &str = "workflow_graph_load_failed";
}

impl ModuleDispatchFailure {
    /// The DLQ `drop_reason` to record, or `None` when the failure must NOT
    /// produce a replayable row (the worker answered).
    pub fn dlq_drop_reason(&self) -> Option<&'static str> {
        match self {
            ModuleDispatchFailure::NotDispatched { drop_reason, .. }
            | ModuleDispatchFailure::ReplyLost { drop_reason, .. } => Some(drop_reason),
            ModuleDispatchFailure::Answered { .. } => None,
        }
    }

    /// True when the worker never observed the job — the module did not run.
    pub fn worker_never_saw_job(&self) -> bool {
        self.dlq_drop_reason().is_some()
    }

    fn detail(&self) -> &str {
        match self {
            ModuleDispatchFailure::NotDispatched { detail, .. }
            | ModuleDispatchFailure::ReplyLost { detail, .. }
            | ModuleDispatchFailure::Answered { detail } => detail,
        }
    }
}

/// Renders the detail text ONLY, byte-identical to the `anyhow` messages
/// this enum replaced ("job publish failed: …", "WASM execution timed out
/// after 3s", "Execution failed: …"), because that text is what
/// `webhook_request_log.error_message` stores and what
/// `talos_engine::module_error_type::derive_error_type` classifies — a
/// wording change here would move `module_executions.error_type`.
impl std::fmt::Display for ModuleDispatchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.detail())
    }
}

impl std::error::Error for ModuleDispatchFailure {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_failures_the_worker_never_saw_are_replayable() {
        let not_dispatched = ModuleDispatchFailure::NotDispatched {
            drop_reason: drop_reason::MODULE_PUBLISH_FAILED,
            detail: "job publish failed: connection reset".into(),
        };
        let reply_lost = ModuleDispatchFailure::ReplyLost {
            drop_reason: drop_reason::MODULE_REPLY_TIMEOUT,
            detail: "WASM execution timed out after 3s".into(),
        };
        let answered = ModuleDispatchFailure::Answered {
            detail: "Execution failed: {\"__error\":\"upstream 502\"}".into(),
        };

        assert_eq!(
            not_dispatched.dlq_drop_reason(),
            Some(drop_reason::MODULE_PUBLISH_FAILED)
        );
        assert_eq!(
            reply_lost.dlq_drop_reason(),
            Some(drop_reason::MODULE_REPLY_TIMEOUT)
        );
        // A module that RAN and returned an error is an execution failure,
        // already recorded; replaying it would double side effects.
        assert_eq!(answered.dlq_drop_reason(), None);
        assert!(!answered.worker_never_saw_job());
        assert!(not_dispatched.worker_never_saw_job());
    }

    /// The Display text feeds `webhook_request_log.error_message` and the
    /// `error_type` derivation; it must be the bare detail, no prefix.
    #[test]
    fn display_is_the_bare_detail() {
        let e = ModuleDispatchFailure::Answered {
            detail: "Execution failed: boom".into(),
        };
        assert_eq!(e.to_string(), "Execution failed: boom");
        let e = ModuleDispatchFailure::NotDispatched {
            drop_reason: drop_reason::MODULE_SIGN_FAILED,
            detail: "Failed to sign job request: no key".into(),
        };
        assert_eq!(e.to_string(), "Failed to sign job request: no key");
    }

    /// Every post-auth drop reason is distinct and none collides with the two
    /// pre-auth reasons `handle_webhook` writes (`circuit_breaker`,
    /// `rate_limit`), so a DLQ listing can be partitioned by the string alone.
    #[test]
    fn drop_reasons_are_distinct_and_never_the_pre_auth_ones() {
        let all = [
            drop_reason::MODULE_LOAD_FAILED,
            drop_reason::MODULE_CONFIG_FAILED,
            drop_reason::MODULE_ACTOR_CEILINGS_UNREADABLE,
            drop_reason::MODULE_EXECUTION_ROW_FAILED,
            drop_reason::MODULE_EXEC_INFO_FAILED,
            drop_reason::MODULE_SIGN_FAILED,
            drop_reason::MODULE_REQUEST_ENCODE_FAILED,
            drop_reason::MODULE_REPLY_SUBSCRIBE_FAILED,
            drop_reason::MODULE_PUBLISH_FAILED,
            drop_reason::MODULE_REPLY_TIMEOUT,
            drop_reason::MODULE_REPLY_INBOX_CLOSED,
            drop_reason::WORKFLOW_AUTH_DB_ERROR,
            drop_reason::WORKFLOW_EXECUTION_ROW_FAILED,
            drop_reason::WORKFLOW_GRAPH_LOAD_FAILED,
        ];
        let set: std::collections::HashSet<&str> = all.iter().copied().collect();
        assert_eq!(set.len(), all.len(), "drop reasons must be distinct");
        for pre_auth in ["circuit_breaker", "rate_limit"] {
            assert!(!set.contains(pre_auth));
        }
    }
}
