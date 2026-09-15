//! The ONE home for the deployment-wide execution pause.
//!
//! `pause_executions` / `resume_executions` are the platform's incident
//! kill-switch: one `system_settings` row (`key = 'execution_paused'`) that
//! every tenant's workflow starts are supposed to honour. Measured 2026-09-14
//! (package BF), it had never once taken effect, for two independent reasons:
//!
//! 1. **The switch could not be set.** Two byte-identical writers (in
//!    `talos-execution-repository` and `talos-workflow-repository`) bound a
//!    Rust `&str` — a TEXT parameter — into `system_settings.value`, which is
//!    `jsonb NOT NULL`. Postgres refuses that assignment ("column value is of
//!    type jsonb but expression is of type text"), so `pause_executions`
//!    answered "Failed to pause executions" on every call; `admin_event_log`
//!    held zero `executions_paused` events and no row existed. Check 88 could
//!    not see it: it PREPAREs without a type list, so the server infers
//!    `jsonb` for `$1` and the statement plans — the probe's stated limit
//!    ("PREPARE proves a statement plans, never that its bind TYPES match").
//! 2. **Almost nothing read it.** The flag was consulted by the manual
//!    trigger and replay services and six MCP handlers. The scheduler (1 982
//!    of 2 951 workflow runs in the measured week, 67%), the Gmail push branch
//!    of the continuation trigger (952, 32%) and the webhook router never
//!    read it, so a pause that DID land would have stopped under 1% of real
//!    dispatch.
//!
//! This crate fixes the first and gives the second one place to call. The
//! reader is THREE-valued and the gate fails CLOSED: the old reader was
//! `(value)::text = 'true'`, so any stored value it did not recognise read as
//! RUNNING — a kill-switch that reads garbage as "carry on" is the failure a
//! kill-switch exists to prevent.
//!
//! It is a LEAF (sqlx + serde_json + talos-metrics) so the workflow
//! repository, the scheduler, the webhook router and the Gmail handler can
//! all call it without an edge between them.

use sqlx::PgExecutor;
/// Re-exported so a caller names the gate's labels from the gate's own home.
pub use talos_metrics::{PauseGatePath, PauseRefusal};

/// The `system_settings.key` of the pause flag.
pub const EXECUTION_PAUSED_SETTING_KEY: &str = "execution_paused";

/// What the stored flag says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionPause {
    /// No row, or the row holds JSON `false`: starts are admitted.
    Running,
    /// The row holds JSON `true`: starts are refused.
    Paused,
    /// The row holds something other than a JSON boolean. Refused — never
    /// read as running (see the crate docs).
    Unreadable,
}

impl ExecutionPause {
    /// The refusal this state produces, or `None` when a start is admitted.
    #[must_use]
    pub const fn refusal(self) -> Option<PauseRefusal> {
        match self {
            Self::Running => None,
            Self::Paused => Some(PauseRefusal::Paused),
            Self::Unreadable => Some(PauseRefusal::Unreadable),
        }
    }
}

/// Classify a stored `system_settings.value` (`None` = no row). Pure, so the
/// fail-closed rule is testable without a database.
#[must_use]
pub fn classify_stored_value(value: Option<&serde_json::Value>) -> ExecutionPause {
    match value {
        None | Some(serde_json::Value::Bool(false)) => ExecutionPause::Running,
        Some(serde_json::Value::Bool(true)) => ExecutionPause::Paused,
        Some(_) => ExecutionPause::Unreadable,
    }
}

/// Read the flag. A database error is returned as-is: it is not a verdict,
/// and every caller already has a failure path for a read it could not make.
pub async fn read_execution_pause<'e, E: PgExecutor<'e>>(
    executor: E,
) -> Result<ExecutionPause, sqlx::Error> {
    let value: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT value FROM system_settings WHERE key = $1")
            .bind(EXECUTION_PAUSED_SETTING_KEY)
            .fetch_optional(executor)
            .await?;
    Ok(classify_stored_value(value.as_ref()))
}

/// Set or clear the flag. The value is written as a JSON BOOLEAN through
/// `to_jsonb($2::boolean)`: the parameter's type is stated in the statement,
/// so it cannot be inferred into the wrong one again, and the stored value is
/// exactly what [`classify_stored_value`] reads.
pub async fn set_execution_paused<'e, E: PgExecutor<'e>>(
    executor: E,
    paused: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO system_settings (key, value, updated_at) \
         VALUES ($1, to_jsonb($2::boolean), NOW()) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
    )
    .bind(EXECUTION_PAUSED_SETTING_KEY)
    .bind(paused)
    .execute(executor)
    .await?;
    Ok(())
}

/// Read the flag for a start about to happen on `path` and decide. On a
/// refusal the counter is moved here — one recording site for every gate —
/// and the caller renders the refusal in its own protocol. `Ok(None)` admits.
///
/// Callers that already hold the stored state (the row-creation chokepoint
/// reads it inside its own transaction) use [`record_refusal`] instead.
#[must_use = "a pause gate whose answer is dropped admits every start"]
pub async fn gate_start<'e, E: PgExecutor<'e>>(
    executor: E,
    path: PauseGatePath,
) -> Result<Option<PauseRefusal>, sqlx::Error> {
    let refusal = read_execution_pause(executor).await?.refusal();
    if let Some(reason) = refusal {
        record_refusal(path, reason);
    }
    Ok(refusal)
}

/// Count one refusal. Exposed for the callers that decide on a state they
/// read themselves; everything else goes through [`gate_start`].
pub fn record_refusal(path: PauseGatePath, reason: PauseRefusal) {
    talos_metrics::record_execution_pause_refusal(path, reason);
}

/// `Retry-After` (seconds) an HTTP surface sends with its 503. A pause is an
/// operator act measured in minutes; a sender that honours the header comes
/// back after one, and one that ignores it (Pub/Sub uses its subscription's
/// own backoff) is unaffected.
pub const PAUSE_RETRY_AFTER_SECS: u32 = 60;

/// What an inbound push that would start work must do while the pause may be
/// in force. The RULE lives here, once, for every push integration (Gmail,
/// Google Calendar, GCP): a push that starts nothing is admitted; a paused or
/// unreadable flag DEFERS it; a flag the database could not return DEFERS it
/// too, because a start whose kill-switch could not be read is not admitted
/// and a push sender retries a non-2xx. The handler answers 503 on any
/// `Defer*` BEFORE it moves a cursor, a dedup marker or spawns work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushAdmission {
    Admit,
    Defer(PauseRefusal),
    DeferReadFailed,
}

impl PushAdmission {
    #[must_use]
    pub const fn defers(self) -> bool {
        !matches!(self, Self::Admit)
    }
}

/// Decide a push. `starts_work` is the integration's own "is this watch bound
/// to something that runs" predicate. A read failure is logged here with the
/// path label; a refusal is counted by [`gate_start`].
#[must_use = "a push admission whose answer is dropped admits every push"]
pub async fn push_admission<'e, E: PgExecutor<'e>>(
    executor: E,
    starts_work: bool,
    path: PauseGatePath,
) -> PushAdmission {
    if !starts_work {
        return PushAdmission::Admit;
    }
    match gate_start(executor, path).await {
        Ok(None) => PushAdmission::Admit,
        Ok(Some(reason)) => PushAdmission::Defer(reason),
        Err(e) => {
            tracing::error!(
                path = path.as_str(),
                error = %e,
                "could not read the execution pause flag; deferring the push (503)"
            );
            PushAdmission::DeferReadFailed
        }
    }
}

/// The one sentence a caller shows for a refusal. `Unreadable` names the
/// repair, because a stored value nothing can classify refuses every start
/// until an operator rewrites it.
#[must_use]
pub const fn refusal_message(reason: PauseRefusal) -> &'static str {
    match reason {
        PauseRefusal::Paused => "Execution queue is paused. Use resume_executions to re-enable.",
        PauseRefusal::Unreadable => {
            "Execution queue pause flag is unreadable (system_settings.execution_paused \
             is not a JSON boolean); starts are refused until an operator runs \
             pause_executions or resume_executions to rewrite it."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_a_json_boolean_is_a_verdict() {
        assert_eq!(classify_stored_value(None), ExecutionPause::Running);
        assert_eq!(
            classify_stored_value(Some(&json!(false))),
            ExecutionPause::Running
        );
        assert_eq!(
            classify_stored_value(Some(&json!(true))),
            ExecutionPause::Paused
        );
        // The old reader was `(value)::text = 'true'`: every one of these read
        // as RUNNING. A string "true" is exactly what the broken TEXT writer
        // would have stored had Postgres accepted it.
        for garbage in [
            json!("true"),
            json!("false"),
            json!(1),
            json!(null),
            json!({}),
        ] {
            assert_eq!(
                classify_stored_value(Some(&garbage)),
                ExecutionPause::Unreadable,
                "{garbage} must refuse, not admit"
            );
        }
    }

    #[test]
    fn only_running_admits() {
        assert_eq!(ExecutionPause::Running.refusal(), None);
        assert_eq!(ExecutionPause::Paused.refusal(), Some(PauseRefusal::Paused));
        assert_eq!(
            ExecutionPause::Unreadable.refusal(),
            Some(PauseRefusal::Unreadable)
        );
    }

    /// Text between `start` and the first `end` after it, in `src`.
    fn region<'a>(src: &'a str, start: &str, end: &str) -> &'a str {
        let i = src
            .find(start)
            .unwrap_or_else(|| panic!("anchor `{start}` gone"));
        let rest = &src[i..];
        let j = rest
            .find(end)
            .unwrap_or_else(|| panic!("anchor `{end}` gone after `{start}`"));
        &rest[..j]
    }

    /// SOURCE PINS (textual, stated as such) for the three gates no DB test in
    /// this workspace can drive without a live push or an axum `Next`:
    ///
    /// * the Gmail push handler reads the flag BEFORE the detached task that
    ///   advances the history cursor and answers 200 — a gate inside that
    ///   task would ack the push and move the cursor, i.e. DROP it;
    /// * the webhook router reads it before it creates the execution row;
    /// * `retry` reads it before it loads the execution it re-runs.
    ///
    /// A pin proves the call is present and ORDERED, never that its answer is
    /// honoured; `gate_start` is `#[must_use]` for the second half.
    #[test]
    fn each_http_and_retry_start_path_reads_the_pause_before_it_starts_work() {
        let gmail = region(
            include_str!("../../talos-gmail/src/handlers.rs"),
            "pub async fn pubsub_push_handler(",
            "tokio::spawn(async move",
        );
        assert!(
            gmail.contains("if super::dispatch::execution_pause_defers_push(&ctx.db_pool, &row).await {\n            return StatusCode::SERVICE_UNAVAILABLE;"),
            "the Gmail push gate must sit before the cursor-advancing task"
        );

        let webhook = region(
            include_str!("../../talos-webhooks/src/router.rs"),
            "async fn trigger_workflow_execution(",
            ".create_execution_under_concurrency_limit(",
        );
        assert!(webhook.contains("PauseGatePath::Webhook"));

        // A fire claimed before the pause and refused at row creation must be
        // RE-ARMED, or the claim's advanced `next_trigger_at` drops it. The
        // arm lives in a spawned task no DB test can reach.
        let scheduler_arm = region(
            include_str!("../../talos-scheduler/src/lib.rs"),
            "ConcurrencyAdmission::ExecutionsPaused(reason) => {",
            "ConcurrencyAdmission::LimitReached",
        );
        assert!(scheduler_arm.contains("rearm_schedule_deferred_by_pause(&db_pool, schedule_id)"));

        let retry = region(
            include_str!("../../talos-execution-orchestration/src/retry.rs"),
            "pub async fn retry(",
            ".lookup_execution(",
        );
        assert!(retry.contains("PauseGatePath::Retry"));
    }

    /// Package BG's call sites, textual and stated as such: each gate sits
    /// BEFORE the statement that would consume the event or start the run.
    #[test]
    fn each_remaining_start_path_reads_the_pause_before_it_consumes_or_starts() {
        let gcal = region(
            include_str!("../../talos-google-calendar/src/handlers.rs"),
            "let integration_uuid = watch.integration_id;",
            ".advance_message_number(",
        );
        assert!(
            gcal.contains("PauseGatePath::GcalPush")
                && gcal.contains("if pause.defers() {")
                && gcal.contains("return StatusCode::SERVICE_UNAVAILABLE;")
        );

        let gcp = region(
            include_str!("../../talos-google-cloud/src/handlers.rs"),
            "let parsed = parse_monitoring_incident(&payload);",
            "tokio::spawn(async move",
        );
        assert!(
            gcp.contains("PauseGatePath::GcpPush")
                && gcp.contains("if pause.defers() {")
                && gcp.contains("return StatusCode::SERVICE_UNAVAILABLE;")
        );

        let mcp_approval = region(
            include_str!("../../talos-mcp-handlers/src/advanced.rs"),
            "let cwf_id = gate.continuation_workflow_id;",
            ".resolve_approval_gate(gate_id, user_id, resolution, note)",
        );
        assert!(mcp_approval.contains("PauseGatePath::Continuation"));

        let mcp_resume = region(
            include_str!("../../talos-mcp-handlers/src/advanced.rs"),
            "async fn handle_resume_workflow_by_correlation_id(",
            ".claim_suspension_for_mcp_resume(",
        );
        assert!(mcp_resume.contains("PauseGatePath::Continuation"));

        let link = region(
            include_str!("../../talos-webhooks/src/approval.rs"),
            "pub async fn approval_gate_handler(",
            "UPDATE workflow_approval_gates",
        );
        assert!(link.contains("PauseGatePath::Continuation"));

        let callback = region(
            include_str!("../../talos-webhooks/src/suspension.rs"),
            "pub async fn suspension_callback_handler(",
            "UPDATE workflow_suspensions",
        );
        assert!(callback.contains("PauseGatePath::Continuation"));

        let handoff = region(
            include_str!("../../talos-actor-lifecycle-service/src/handoff.rs"),
            "pub async fn handoff(",
            ".insert_handoff_execution(",
        );
        assert!(
            handoff.contains("PauseGatePath::Handoff")
                && handoff.contains(
                    "Ok(Some(reason)) => return Err(HandoffError::ExecutionPaused(reason))"
                )
        );

        let graphql = region(
            include_str!("../../talos-api/src/schema/workflows/mutations.rs"),
            "async fn test_workflow(",
            ".insert_test_execution_row(",
        );
        assert!(
            graphql.contains("PauseGatePath::GraphqlTest")
                && graphql.contains(
                    "async_graphql::Error::new(talos_execution_pause::refusal_message(reason))"
                )
        );

        let contract = region(
            include_str!("../../talos-mcp-handlers/src/workflows.rs"),
            "use talos_subworkflow_contract::{run_contract_test, ContractKind, ContractTestError};",
            "match run_contract_test(&deps",
        );
        assert!(contract.contains("enforce_executions_not_paused(&state.workflow_repo, req_id.clone()).await\n    {\n        return resp;"));
    }

    /// ONE home: the two deleted repository copies (whose writer bound TEXT
    /// into jsonb and never succeeded) must not grow back.
    #[test]
    fn the_flag_has_no_second_reader_or_writer() {
        for (file, src) in [
            (
                "talos-execution-repository/src/lib.rs",
                include_str!("../../talos-execution-repository/src/lib.rs"),
            ),
            (
                "talos-workflow-repository/src/executions.rs",
                include_str!("../../talos-workflow-repository/src/executions.rs"),
            ),
            (
                "talos-mcp-handlers/src/executions.rs",
                include_str!("../../talos-mcp-handlers/src/executions.rs"),
            ),
        ] {
            assert!(
                !src.contains("key = 'execution_paused'")
                    && !src.contains("VALUES ('execution_paused'"),
                "{file} carries its own execution_paused SQL again"
            );
        }
    }

    #[test]
    fn the_paused_message_is_the_one_mcp_callers_already_see() {
        // `enforce_executions_not_paused` returned this exact sentence before
        // the home existed; clients match on it.
        assert_eq!(
            refusal_message(PauseRefusal::Paused),
            "Execution queue is paused. Use resume_executions to re-enable."
        );
    }
}
