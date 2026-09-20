//! The controller's `wasm.log.*` relay: what the worker's guest and host log
//! lines become once they reach a controller.
//!
//! Every line has TWO consumers with opposite delivery needs, so the relay
//! holds TWO subscriptions:
//!
//! * **Persist** — a QUEUE subscribe in
//!   [`CONTROLLER_WASM_LOG_QUEUE_GROUP`]. A line is stored by exactly one
//!   controller replica. Neither log table has a de-duplication key, so with
//!   a plain subscribe N replicas stored N copies of every line (reproduced
//!   2026-09-20: 50 lines, two relays, 100 rows). The orphan counter is
//!   recorded here too, so it counts a line once fleet-wide.
//! * **Broadcast** — a PLAIN subscribe. The GraphQL `execution_updates`
//!   stream reads a per-process channel, and the browser watching a run is
//!   connected to whichever replica the load balancer chose, so every replica
//!   must see every line. A queue group here would silently drop live logs
//!   for clients on the other replicas.
//!
//! The two halves share one parser ([`parse_log_line`]) and nothing else: the
//! persister never broadcasts and the broadcaster never writes.
//!
//! This lived inline in the controller binary's `bootstrap/background.rs`
//! until 2026-09-20, where no test could drive the loop.

use futures::StreamExt;
use std::sync::Arc;
use talos_engine_events::{ExecutionEvent, ExecutionStatus};
use talos_execution_repository::ExecutionRepository;
use talos_module_executions::{LogLevel, ModuleExecutionService};
use talos_task_supervision::{spawn_supervised, BackgroundTask};
use talos_workflow_job_protocol::subjects::{CONTROLLER_WASM_LOG_QUEUE_GROUP, WASM_LOG_WILDCARD};

/// `talos_wasm_log_orphaned_total{kind}` label values — a closed set; the
/// alert's `{{ $labels.kind }}` annotation names exactly these.
pub const WASM_LOG_ORPHAN_NO_EXECUTION_ROW: &str = "no_execution_row";
pub const WASM_LOG_ORPHAN_UNPARSEABLE_ID: &str = "unparseable_id";

/// Maximum characters of WASM-emitted log content broadcast on the
/// `execution_updates` GraphQL subscription. Mirrors the persistence
/// path's per-row cap (`MAX_MSG_LEN` in
/// `talos_execution_repository::add_workflow_log`); kept in lockstep
/// so the live channel can't carry more than the persisted row.
pub const MAX_BROADCAST_LOG_CHARS: usize = 8 * 1024;

/// Sanitise a WASM-emitted log message for live broadcast on
/// `execution_updates`. Mirrors the pipeline `add_workflow_log` runs
/// before persisting to `workflow_execution_logs.message`:
///   1. char-count truncate to `MAX_BROADCAST_LOG_CHARS`
///   2. strip control chars except newline/tab/carriage return
///   3. DLP redact (`talos_dlp_provider::redact_str`)
///
/// Same MCP-481 / MCP-1011 class — every operator-visible WASM-log
/// surface needs identical scrubbing.
#[must_use]
pub fn scrub_wasm_log_for_broadcast(message: &str) -> String {
    let truncated: String = if message.chars().count() > MAX_BROADCAST_LOG_CHARS {
        let mut s: String = message.chars().take(MAX_BROADCAST_LOG_CHARS).collect();
        s.push_str("... (truncated)");
        s
    } else {
        message.to_string()
    };
    let sanitized: String = truncated
        .chars()
        .filter(|c| !c.is_control() || matches!(*c, '\n' | '\t' | '\r'))
        .collect();
    // 2026-05-28 audit F3: the Cow variant keeps the nothing-to-redact common
    // case allocation-free on this per-line hot path.
    talos_dlp_provider::redact_str_cow(&sanitized).into_owned()
}

/// One worker log line, parsed once.
#[derive(Debug, Clone, PartialEq)]
pub struct LogLine {
    pub execution_id: uuid::Uuid,
    pub node_id: Option<uuid::Uuid>,
    pub level: LogLevel,
    pub message: String,
    pub metadata: Option<serde_json::Value>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
}

impl LogLine {
    /// The level as stored and as broadcast: one of four fixed strings, never
    /// the payload's own text.
    #[must_use]
    pub fn level_upper(&self) -> &'static str {
        match self.level {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }
}

/// What a `wasm.log.*` payload turned out to be.
#[derive(Debug, Clone, PartialEq)]
pub enum ParsedLog {
    Line(LogLine),
    /// Valid JSON with a missing or non-UUID `execution_id`.
    UnparseableId,
    /// Not JSON at all. A different failure from [`Self::UnparseableId`] and
    /// never counted as one — conflating them would make the alert's `kind`
    /// label lie about what to go grep.
    Malformed,
}

/// THE parser for a `wasm.log.*` payload; both halves of the relay call it.
#[must_use]
pub fn parse_log_line(payload: &[u8]) -> ParsedLog {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(payload) else {
        return ParsedLog::Malformed;
    };
    let str_field = |k: &str| v.get(k).and_then(|x| x.as_str());
    let Some(execution_id) = str_field("execution_id").and_then(|s| uuid::Uuid::parse_str(s).ok())
    else {
        return ParsedLog::UnparseableId;
    };
    // Case-insensitive: the worker emits UPPERCASE while older test paths
    // used lowercase; without the fold every uppercase line read as Info.
    let level = match str_field("level")
        .unwrap_or("info")
        .to_ascii_lowercase()
        .as_str()
    {
        "debug" => LogLevel::Debug,
        "warn" => LogLevel::Warn,
        "error" => LogLevel::Error,
        _ => LogLevel::Info,
    };
    let metadata = v.get("metadata").cloned();
    let node_id = metadata
        .as_ref()
        .and_then(|m| m.get("node_id"))
        .and_then(|x| x.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok());
    ParsedLog::Line(LogLine {
        execution_id,
        node_id,
        level,
        message: str_field("message").unwrap_or("").to_string(),
        trace_id: str_field("trace_id").map(str::to_string),
        span_id: str_field("span_id").map(str::to_string),
        metadata,
    })
}

/// The PERSIST half, per message. Stores the line in the right log table and
/// records a line that lands nowhere. Never broadcasts.
///
/// Route: `workflow_execution_logs` when the id is a workflow execution (the
/// common case); `module_execution_logs` for a standalone module run.
/// `add_workflow_log` does a `WHERE EXISTS`-guarded insert and returns
/// `Ok(false)` rather than tripping the FK when the id is not a workflow
/// execution — a single round trip for the common case.
pub async fn persist_log_message(
    msg: &async_nats::Message,
    exec_repo: &ExecutionRepository,
    exec_service: &ModuleExecutionService,
) {
    // DEBUG, not INFO: measured 2026-09-13 this line was 21 % of controller
    // INFO volume, acknowledging a message the worker had already relayed.
    tracing::debug!("📩 Received WASM log from NATS topic: {}", msg.subject);
    let line = match parse_log_line(&msg.payload) {
        ParsedLog::Line(line) => line,
        ParsedLog::UnparseableId => {
            // The line is discarded here and nothing downstream will ever
            // mention it. No message body — it is guest-authored.
            // Inline, not through a shared count-and-warn helper: structural
            // check 58 sees an increment textually, and a helper whose call
            // sites were deleted would still read as a live metric.
            if let Some(m) = talos_metrics::global() {
                m.wasm_log_orphaned_total
                    .with_label_values(&[WASM_LOG_ORPHAN_UNPARSEABLE_ID])
                    .inc();
            }
            tracing::warn!(
                target: "talos_controller",
                event_kind = "wasm_log_unparseable_execution_id",
                subject = %msg.subject,
                "WASM log line discarded: missing or unparseable execution_id"
            );
            return;
        }
        ParsedLog::Malformed => {
            tracing::debug!("Failed to parse WASM log message");
            return;
        }
    };
    let exec_id = line.execution_id;
    let level_upper = line.level_upper();
    match exec_repo
        .add_workflow_log(
            exec_id,
            line.node_id,
            level_upper,
            &line.message,
            line.metadata.as_ref(),
        )
        .await
    {
        Ok(true) => {} // landed in workflow_execution_logs
        Ok(false) => {
            // Not a workflow execution → standalone module run.
            let outcome = exec_service
                .add_log_best_effort(exec_id, line.level, line.message, line.metadata)
                .await;
            // BOTH routes missed: `exec_id` names
            // neither a `workflow_executions` row nor a
            // `module_executions` row, so this line has
            // been DISCARDED. This is the terminal hop —
            // if we don't say it here, nobody does, and
            // `get_execution_logs` will return `[]`,
            // byte-identical to an execution that
            // genuinely logged nothing. That silence is
            // how every Loop-node iteration lost all of
            // its logs (host diagnostics AND guest
            // `logging::log`) unnoticed until 2026-07-30.
            //
            // Only `NoExecutionRow` warns: a `RateLimited`
            // drop is deliberate back-pressure and a
            // `WriteFailed` already warned inside
            // `add_log_best_effort` — calling either
            // "orphaned" would be the misleading-signal
            // bug in the fix for a misleading signal.
            //
            // CONTENT: execution id + level ONLY. The
            // message body is guest-authored and may carry
            // anything the module printed; it must not be
            // copied into the controller's operator log by
            // a diagnostic about routing.
            //
            // VOLUME: one warn per orphaned line is
            // bounded, not unbounded — a producer's
            // per-execution log budget is capped in the
            // worker (MAX_LOG_MESSAGES_PER_EXECUTION for
            // guest lines, HOST_DIAG_CAP for host
            // diagnostics), so a single pathological module
            // cannot emit more warns than it can emit logs.
            //
            // EXPECTED RATE: zero on ordinary
            // trigger / schedule / webhook / push traffic
            // — every routine dispatch path pre-INSERTs its
            // row before publishing (single-node
            // `engine_dispatch_single.rs`, pipeline steps via
            // the parent `workflow_executions.id`, loop bodies
            // as of 2026-07-30, and the live webhook path at
            // `talos-webhooks/src/router.rs`). It is NOT
            // zero everywhere, and the earlier draft of this
            // comment claiming otherwise was the same
            // unearned-certainty class the warn exists to
            // close.
            //
            // The 2026-07-30 audit listed three residual
            // producers here. Two of them — webhook DLQ
            // replay (no row at all) and Google Calendar
            // push (random `job_id` when `create_execution`
            // errored) — were closed on 2026-07-31, along
            // with a fourth the audit itself had missed: the
            // LIVE webhook INSERT, which on error logged and
            // dispatched anyway. All three webhook/GCal paths
            // now fail closed. Do not re-derive that list
            // from this comment: it is a snapshot, and this
            // is the second time it has gone stale. The warn
            // below is the live detector — trust it over the
            // prose.
            //
            // ONE deliberate producer remains, and it is not
            // a bug: either engine `record_started` failing
            // is non-fatal by design (always paired with a
            // nearby `tracing::error!`), so a DB blip during
            // a node dispatch still orphans that node's
            // lines.
            //
            // A burst of these named by `exec_id` therefore
            // means either that, or a NEW dispatch path that
            // mints an id without recording a row — which is
            // what this warn is FOR. Fix the producer; do
            // not silence the warn.
            if outcome.is_orphaned() {
                // The metric twin of the WARN below. The label is a
                // closed-set &'static str — never the guest-authored message
                // body, never `exec_id` (unbounded cardinality).
                if let Some(m) = talos_metrics::global() {
                    m.wasm_log_orphaned_total
                        .with_label_values(&[WASM_LOG_ORPHAN_NO_EXECUTION_ROW])
                        .inc();
                }
                tracing::warn!(
                    target: "talos_controller",
                    event_kind = "wasm_log_orphaned",
                    %exec_id,
                    level = level_upper,
                    "WASM log line discarded: execution id matches \
                     neither workflow_executions nor module_executions. \
                     The dispatching path minted an id without \
                     recording an execution row — its logs are being \
                     lost and will not appear in get_execution_logs."
                );
            }
        }
        Err(e) => {
            // exec_id IS a workflow execution but the insert failed
            // (5000-entry rate-limit trigger, DB outage). Don't misroute a
            // real workflow log to the module table.
            tracing::debug!(
                %exec_id,
                error = %e,
                "workflow_execution_logs insert failed (capped or DB error)"
            );
        }
    }
}

/// What the broadcast half did with one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastOutcome {
    /// Scrubbed and sent to this replica's live subscribers.
    Sent,
    /// Nobody on this replica is subscribed: the payload was not parsed and
    /// the DLP scrubber was not run.
    NoListeners,
    /// Not a log line (malformed, or no execution id). The persist half
    /// counts and reports those; this half says nothing, so a discarded line
    /// is reported once per fleet and not once per replica.
    NotALine,
}

/// The BROADCAST half, per message. Sends the scrubbed line to this
/// replica's `execution_updates` subscribers. Never writes.
///
/// MCP-1011: the broadcast text goes through the same scrub the persisted
/// row gets, so the live channel cannot carry a token the stored row would
/// have redacted. The level is the closed four-value form, as stored — the
/// payload's own level string is never echoed.
pub fn broadcast_log_message(
    msg: &async_nats::Message,
    tx: &tokio::sync::broadcast::Sender<ExecutionEvent>,
) -> BroadcastOutcome {
    if tx.receiver_count() == 0 {
        return BroadcastOutcome::NoListeners;
    }
    let ParsedLog::Line(line) = parse_log_line(&msg.payload) else {
        return BroadcastOutcome::NotALine;
    };
    let _ = tx.send(ExecutionEvent {
        execution_id: line.execution_id,
        node_id: line.node_id,
        status: ExecutionStatus::Running,
        log_message: Some(format!(
            "[{}] {}",
            line.level_upper(),
            scrub_wasm_log_for_broadcast(&line.message)
        )),
        trace_id: line.trace_id,
        span_id: line.span_id,
        iteration_index: None,
        iteration_total: None,
        duration_ms: None,
        output: None,
    });
    BroadcastOutcome::Sent
}

/// How a relay half binds `wasm.log.*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delivery {
    /// One replica per line.
    OncePerFleet,
    /// Every replica.
    EveryReplica,
}

async fn bind(
    nats: &async_nats::Client,
    delivery: Delivery,
) -> Result<async_nats::Subscriber, async_nats::SubscribeError> {
    match delivery {
        Delivery::OncePerFleet => {
            nats.queue_subscribe(
                WASM_LOG_WILDCARD,
                CONTROLLER_WASM_LOG_QUEUE_GROUP.to_string(),
            )
            .await
        }
        Delivery::EveryReplica => nats.subscribe(WASM_LOG_WILDCARD).await,
    }
}

/// Supervisor loop shared by both halves (MCP-1121): a stream end (NATS
/// reconnect, server-side unsubscribe) re-binds after 1 s instead of ending
/// the task; a subscribe failure backs off, doubling to 60 s.
async fn run_half<F, Fut>(
    nats: Arc<async_nats::Client>,
    delivery: Delivery,
    half: &'static str,
    mut on_message: F,
) -> !
where
    F: FnMut(async_nats::Message) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut backoff_secs: u64 = 1;
    loop {
        let mut subscriber = match bind(&nats, delivery).await {
            Ok(sub) => sub,
            Err(e) => {
                tracing::error!(
                    target: "talos_controller",
                    event_kind = "wasm_log_subscribe_failed",
                    half,
                    error = %e,
                    backoff_secs,
                    "Failed to subscribe to WASM logs; retrying after backoff"
                );
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(60);
                continue;
            }
        };
        backoff_secs = 1;
        tracing::info!(half, "WASM log subscriber active - waiting for messages");
        while let Some(msg) = subscriber.next().await {
            on_message(msg).await;
        }
        tracing::warn!(
            target: "talos_controller",
            event_kind = "wasm_log_subscriber_rebinding",
            half,
            "WASM log subscriber stream ended; supervisor re-binding (no controller restart required)"
        );
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// Start both halves of the relay on `nats`, each as its own supervised task.
pub fn spawn_wasm_log_relay(
    nats: Arc<async_nats::Client>,
    exec_repo: Arc<ExecutionRepository>,
    exec_service: Arc<ModuleExecutionService>,
    tx: tokio::sync::broadcast::Sender<ExecutionEvent>,
) {
    let persist_nats = nats.clone();
    spawn_supervised(BackgroundTask::WasmLogSubscriber, async move {
        run_half(persist_nats, Delivery::OncePerFleet, "persist", |msg| {
            let (repo, service) = (exec_repo.clone(), exec_service.clone());
            async move { persist_log_message(&msg, &repo, &service).await }
        })
        .await
    });
    spawn_supervised(BackgroundTask::WasmLogBroadcaster, async move {
        run_half(nats, Delivery::EveryReplica, "broadcast", |msg| {
            let outcome = broadcast_log_message(&msg, &tx);
            async move {
                let _ = outcome;
            }
        })
        .await
    });
}

#[cfg(test)]
mod scrub_wasm_log_for_broadcast_tests {
    use super::{scrub_wasm_log_for_broadcast, MAX_BROADCAST_LOG_CHARS};

    #[test]
    fn redacts_anthropic_secret() {
        // MCP-1011 sibling: a WASM module emitting `sk-ant-...` must
        // have it redacted BEFORE the broadcast lands on the live
        // `execution_updates` channel. The persistence path
        // (`add_workflow_log`) applied this; the broadcast didn't.
        let raw = "thinking response sk-ant-abcdefghijklmnopqrstuvwxyz0123456789 returned";
        let out = scrub_wasm_log_for_broadcast(raw);
        assert!(
            !out.contains("sk-ant-abcdefghijklmnopqrstuvwxyz0123456789"),
            "DLP scrubber must remove the secret. Got: {out}"
        );
    }

    #[test]
    fn redacts_bearer_token() {
        let raw = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig";
        let out = scrub_wasm_log_for_broadcast(raw);
        assert!(
            !out.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"),
            "Bearer JWT must be redacted. Got: {out}"
        );
    }

    #[test]
    fn redacts_github_token() {
        let raw = "git push uses ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // secret-scan-allow: DLP redaction test fixture
        let out = scrub_wasm_log_for_broadcast(raw);
        assert!(
            !out.contains("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), // secret-scan-allow: DLP redaction test fixture
            "GitHub PAT must be redacted. Got: {out}"
        );
    }

    #[test]
    fn strips_control_chars_except_whitespace() {
        // ANSI escape sequences and other control chars must not
        // reach operator dashboards (terminal-render attacks). \n,
        // \t, \r preserved so multi-line logs format correctly.
        let raw = "before\x1b[31mafter\nnext\ttabbed\rret\x07bell";
        let out = scrub_wasm_log_for_broadcast(raw);
        assert!(!out.contains('\x1b'));
        assert!(!out.contains('\x07'));
        assert!(out.contains('\n'));
        assert!(out.contains('\t'));
        assert!(out.contains('\r'));
    }

    #[test]
    fn truncates_oversize_input() {
        // Char-based truncation must respect the 8 KiB cap so the
        // broadcast can't carry more than `add_workflow_log` persists.
        let raw: String = "a".repeat(MAX_BROADCAST_LOG_CHARS + 1000);
        let out = scrub_wasm_log_for_broadcast(&raw);
        assert!(out.contains("... (truncated)"));
        // After truncation the prefix is exactly MAX chars, then the
        // marker; total chars <= cap + marker length.
        assert!(out.chars().count() <= MAX_BROADCAST_LOG_CHARS + "... (truncated)".chars().count());
    }

    #[test]
    fn small_input_passes_through_clean() {
        let raw = "user logged in successfully";
        let out = scrub_wasm_log_for_broadcast(raw);
        assert_eq!(out, raw);
    }
}

#[cfg(test)]
mod relay_unit_tests {
    use super::*;

    fn msg(payload: &str) -> async_nats::Message {
        async_nats::Message {
            subject: "wasm.log.test".to_string().into(),
            reply: None,
            payload: payload.as_bytes().to_vec().into(),
            headers: None,
            status: None,
            description: None,
            length: payload.len(),
        }
    }

    const EXEC: &str = "5b0f7a52-5c1e-4a53-9a0e-6f3f0d6c9a11";
    const NODE: &str = "0e2d6c1b-2f3a-4b8c-9d7e-1a2b3c4d5e6f";

    #[test]
    fn a_full_line_parses_into_every_field() {
        let payload = format!(
            r#"{{"execution_id":"{EXEC}","level":"WARN","message":"hello","trace_id":"t","span_id":"s","metadata":{{"node_id":"{NODE}"}}}}"#
        );
        let ParsedLog::Line(line) = parse_log_line(payload.as_bytes()) else {
            panic!("expected a line");
        };
        assert_eq!(line.execution_id.to_string(), EXEC);
        assert_eq!(line.node_id.map(|n| n.to_string()).as_deref(), Some(NODE));
        assert_eq!(line.level_upper(), "WARN");
        assert_eq!(line.message, "hello");
        assert_eq!(line.trace_id.as_deref(), Some("t"));
        assert_eq!(line.span_id.as_deref(), Some("s"));
        assert!(line.metadata.is_some());
    }

    #[test]
    fn the_level_is_folded_and_an_unknown_one_is_info() {
        for (given, want) in [
            ("debug", "DEBUG"),
            ("Error", "ERROR"),
            ("WARN", "WARN"),
            ("info", "INFO"),
            ("shout", "INFO"),
        ] {
            let payload = format!(r#"{{"execution_id":"{EXEC}","level":"{given}"}}"#);
            let ParsedLog::Line(line) = parse_log_line(payload.as_bytes()) else {
                panic!("expected a line");
            };
            assert_eq!(line.level_upper(), want, "level {given}");
        }
    }

    #[test]
    fn a_bad_id_and_bad_json_are_different_answers() {
        assert_eq!(
            parse_log_line(br#"{"level":"INFO","message":"hi"}"#),
            ParsedLog::UnparseableId
        );
        assert_eq!(
            parse_log_line(br#"{"execution_id":"not-a-uuid"}"#),
            ParsedLog::UnparseableId
        );
        assert_eq!(parse_log_line(b"not json at all"), ParsedLog::Malformed);
    }

    #[test]
    fn a_broadcast_is_scrubbed_and_carries_the_closed_level() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(4);
        // The payload's own level text must never reach a subscriber, and a
        // token in the body must be redacted exactly as the stored row is.
        let payload = format!(
            r#"{{"execution_id":"{EXEC}","level":"<b>loud</b>","message":"key sk-ant-api03-{}","metadata":{{"node_id":"{NODE}"}},"trace_id":"t1"}}"#,
            "A".repeat(90)
        );
        assert_eq!(
            broadcast_log_message(&msg(&payload), &tx),
            BroadcastOutcome::Sent
        );
        let ev = rx.try_recv().expect("one event");
        let text = ev.log_message.expect("text");
        assert!(text.starts_with("[INFO] "), "got {text}");
        assert!(!text.contains("loud"));
        assert!(
            !text.contains("sk-ant-api03-AAAA"),
            "token not redacted: {text}"
        );
        assert_eq!(ev.execution_id.to_string(), EXEC);
        assert_eq!(ev.node_id.map(|n| n.to_string()).as_deref(), Some(NODE));
        assert_eq!(ev.trace_id.as_deref(), Some("t1"));
        assert!(rx.try_recv().is_err(), "exactly one event per line");
    }

    #[test]
    fn nothing_is_parsed_or_sent_when_nobody_listens() {
        let (tx, rx) = tokio::sync::broadcast::channel::<ExecutionEvent>(4);
        drop(rx);
        let payload = format!(r#"{{"execution_id":"{EXEC}","message":"x"}}"#);
        assert_eq!(
            broadcast_log_message(&msg(&payload), &tx),
            BroadcastOutcome::NoListeners
        );
        // Even a malformed payload is not inspected without a listener.
        assert_eq!(
            broadcast_log_message(&msg("not json"), &tx),
            BroadcastOutcome::NoListeners
        );
    }

    #[test]
    fn a_non_line_is_not_broadcast() {
        let (tx, mut rx) = tokio::sync::broadcast::channel::<ExecutionEvent>(4);
        assert_eq!(
            broadcast_log_message(&msg("not json"), &tx),
            BroadcastOutcome::NotALine
        );
        assert_eq!(
            broadcast_log_message(&msg(r#"{"message":"no id"}"#), &tx),
            BroadcastOutcome::NotALine
        );
        assert!(rx.try_recv().is_err());
    }

    /// Both halves are long-lived loops and both go through
    /// `spawn_supervised`; nothing here is a bare `tokio::spawn`.
    #[test]
    fn both_halves_are_supervised() {
        assert_eq!(
            talos_task_supervision::production_spawn_counts(include_str!("lib.rs")),
            (2, 0)
        );
    }
}
