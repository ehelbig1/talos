//! The fleet-wide stale-execution sweep, and — the point of this module —
//! the ATTRIBUTION it writes into `workflow_executions.error_message`.
//!
//! # Why this exists
//!
//! The sweep is the last line of defence for a `running` row nothing else
//! ever finalized. Until 2026-09 it was a single bulk `UPDATE` in
//! `controller/src/bootstrap/background.rs` that stamped one constant string
//! on every row it closed:
//!
//! ```text
//! Auto-cleaned: execution stale (running > configured threshold)
//! ```
//!
//! That sentence describes the SWEEP'S RULE, not what happened to the
//! execution, and the two are frequently different things. The incident that
//! motivated this module (2026-08-31, `pa-inbox-organizer-work`) reads as
//! follows in the record: an execution that "ran" 3 795 seconds against a
//! workflow whose normal runs take 23–30 s and whose engine budget is 300 s.
//!
//! What actually happened: the run dispatched its third node at 17:25:14 and
//! the controller **process was replaced ~15 seconds later** (`docker compose
//! up`). Both the engine's 300 s budget and the scheduler's 3 600 s outer cap
//! are `tokio::time::timeout`s living inside that process's task; when the
//! process went, so did they. The execution did not run for an hour — it ran
//! for five seconds and was then orphaned, and the row sat `running` until
//! this sweep closed it 63 minutes later with a sentence that says "it ran too
//! long".
//!
//! A whole investigation was spent reconstructing that from Prometheus counter
//! resets, because the terminal record — the one artefact whose entire job is
//! to say why the execution ended — said nothing. This module makes it say
//! what it knows.
//!
//! # What is knowable, and what is only guessable
//!
//! Two facts are cheap and certain, and together they separate the two very
//! different situations the old message merged:
//!
//! * **The last node that started and never reported.** `execution_events`
//!   already holds it. The 30-minute `module_executions` reaper had already
//!   written a per-node row saying "worker did not report completion" half an
//!   hour before the sweep ran, and the sweep discarded that attribution.
//! * **Whether the row has had any activity during the current controller
//!   process's lifetime.** If its last recorded activity predates the moment
//!   this process started sweeping, then nothing in this process is driving it
//!   — for a single-replica deployment that is exactly "the owning process is
//!   gone", i.e. orphaned by a restart or a kill.
//!
//! The comparison is deliberately made against a **Postgres-clock** epoch
//! (`SELECT NOW()` at sweep start), not `chrono::Utc::now()` in the
//! controller: every timestamp it is compared against is Postgres-generated,
//! and the incident's own margin was **17 seconds**. A controller-clock epoch
//! would need a skew grace wider than that margin, which would have silently
//! declined to attribute the very execution this module was written for. When
//! the epoch is unavailable the sweep degrades to a factual, non-attributing
//! message rather than guessing — see [`StaleExecutionEvidence`].
//!
//! # Stated limits
//!
//! * **Multi-replica.** "No activity since before THIS process started" is a
//!   true statement in every deployment, but "therefore the owner is gone" is
//!   only sound where this process is the only controller. The message
//!   asserts the first and names the second as the cause it implies; an
//!   operator running replicas should read it as "not owned by the replica
//!   that closed it".
//! * **The message is classified downstream by substring.**
//!   `talos_ops_alerts_repository::self_monitor::classify_execution_error`
//!   matches `"timed out"` / `"timeout"` / `"401"` BEFORE it matches
//!   `"execution stale"`, so this module keeps the leading `Auto-cleaned:
//!   execution stale` phrase, writes no bare integers (timestamps only, whose
//!   longest digit run is the four-digit year), and avoids those needles. A
//!   node LABEL is author-written and can still contain them — the same
//!   exposure every `node 'X' failed: …` engine message already has, so it is
//!   documented rather than sanitised away.
//! * It says nothing about WHY the node never reported. That is
//!   `module_executions` / `get_execution_trace` territory.
//! * It cannot resurrect the execution. Making an orphan visible in seconds
//!   rather than an hour is crash recovery's job (RFC 0003), and that path is
//!   default-off and windowed to rows idle > 5 minutes — so a run orphaned
//!   seconds before the restart is invisible to its one-shot startup sweep.
//!   Deliberately not changed here.

use anyhow::Result;
use chrono::{DateTime, SecondsFormat, Utc};
use uuid::Uuid;

use crate::ExecutionRepository;

/// Hard cap on how many stale rows one sweep tick closes.
///
/// The pre-2026-09 sweep was a single unbounded bulk `UPDATE`. Attribution
/// costs one extra statement per row, so the tick is bounded instead; the
/// remainder is picked up 5 minutes later by the next tick. Rows are taken
/// oldest-first so a backlog drains in a defined order rather than whatever
/// the planner returns.
pub const STALE_SWEEP_BATCH: i64 = 500;

/// Longest node label echoed into the message. Labels are author-written
/// graph JSON; the terminal record is not the place to store an essay.
const MAX_LABEL_CHARS: usize = 80;

/// Everything one stale `running` row can tell the sweep about itself.
///
/// `last_event_at` is `None` for an execution that never emitted a single
/// `execution_events` row (it died before its first node started, or events
/// were pruned). `in_flight_node` is `None` when no node ever started.
#[derive(Debug, Clone)]
pub struct StaleExecutionEvidence {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    /// Most recent `execution_events.created_at` for this execution.
    pub last_event_at: Option<DateTime<Utc>>,
    /// The most recently STARTED node. It may or may not have reported; the
    /// sweep only claims "never reported" when no later event exists at all
    /// (see [`describe_stale_execution`]).
    pub in_flight_node: Option<Uuid>,
    pub in_flight_node_started_at: Option<DateTime<Utc>>,
    /// The owning workflow's graph, for resolving `in_flight_node` back to a
    /// display label. `None` when the workflow row was deleted.
    pub graph_json: Option<String>,
}

impl StaleExecutionEvidence {
    /// The last moment this execution demonstrably did anything. Falls back
    /// to `started_at`: the row's own creation IS activity, and treating an
    /// event-less row as "no activity ever" would lose the one timestamp it
    /// does have.
    #[must_use]
    pub fn last_activity_at(&self) -> DateTime<Utc> {
        self.last_event_at.unwrap_or(self.started_at)
    }
}

/// Whether this row's last recorded activity PRECEDES the moment the current
/// controller process began sweeping — i.e. nothing in this process is driving
/// it, so (single-replica) the process that owned it is gone.
///
/// Strictly `<`: equal timestamps do not establish precedence, and the message
/// this gates makes a causal claim that must not rest on a tie. `None` epoch
/// means the question cannot be answered, not that the answer is "no" —
/// callers must not read `false` as "definitely not orphaned".
#[must_use]
pub fn orphaned_before_this_process(
    ev: &StaleExecutionEvidence,
    sweep_epoch: Option<DateTime<Utc>>,
) -> bool {
    sweep_epoch.is_some_and(|epoch| ev.last_activity_at() < epoch)
}

/// Render the terminal `error_message` for one swept execution.
///
/// Pure — no clock, no database — so the wording is unit-testable and cannot
/// drift from what production writes.
///
/// `sweep_epoch` is the Postgres-clock instant at which THIS controller
/// process began sweeping. `None` means it could not be read; the message
/// then states the facts and makes no ownership claim.
///
/// `node_label` is the resolved display label for
/// [`StaleExecutionEvidence::in_flight_node`], or `None` to fall back to the
/// node's UUID (which `get_execution_trace` renders under the same id).
#[must_use]
pub fn describe_stale_execution(
    ev: &StaleExecutionEvidence,
    sweep_epoch: Option<DateTime<Utc>>,
    node_label: Option<&str>,
) -> String {
    let last_activity = ev.last_activity_at();
    // The leading phrase is load-bearing: `classify_execution_error` keys the
    // `stale` error class off `"execution stale"`. Changing it forks every
    // existing ops-alert dedup bucket.
    let mut msg = String::from("Auto-cleaned: execution stale (running > configured threshold).");

    match sweep_epoch {
        Some(epoch) if orphaned_before_this_process(ev, sweep_epoch) => {
            msg.push_str(&format!(
                " Orphaned, not overrunning: no execution activity since {}, which precedes \
                 the start of the controller process that closed it ({}) — the process that \
                 owned this run exited first, so the run's own execution budget never got \
                 the chance to expire.",
                ts(last_activity),
                ts(epoch),
            ));
        }
        Some(epoch) => {
            msg.push_str(&format!(
                " Last execution activity {}, within the lifetime of the controller process \
                 that closed it (sweeping since {}).",
                ts(last_activity),
                ts(epoch),
            ));
        }
        None => {
            msg.push_str(&format!(" Last execution activity {}.", ts(last_activity)));
        }
    }

    match (ev.in_flight_node, ev.in_flight_node_started_at) {
        (Some(node), Some(at)) => {
            let label = node_label
                .map(|l| l.chars().take(MAX_LABEL_CHARS).collect::<String>())
                .filter(|l| !l.trim().is_empty())
                .unwrap_or_else(|| node.to_string());
            // Deliberately NOT the engine's `node 'X' failed` shape:
            // `self_monitor::extract_failed_node` parses that literal, and
            // this node is not known to have failed — it never reported.
            // Claiming it as the failing node would put a guess into the
            // ops-alert dedup key.
            msg.push_str(&format!(
                " Last node to start: {label} at {} — it never reported.",
                ts(at)
            ));
        }
        _ => msg.push_str(" No node ever started."),
    }

    // Node labels come from author-written graph JSON and land in a persisted,
    // operator-visible field; every sibling terminal-write path redacts on the
    // same grounds.
    talos_dlp_provider::redact_str(&msg)
}

/// RFC-3339 with second precision and no sub-second field.
///
/// Second precision is a correctness constraint, not a style choice: the
/// message is substring-classified downstream, `"401"` is matched before
/// `"execution stale"`, and the longest run of adjacent digits an RFC-3339
/// second-precision timestamp can produce is the four-digit year. Milliseconds
/// would reintroduce a three-digit field that can read `401`.
fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

impl ExecutionRepository {
    /// Read the Postgres-clock instant this process starts sweeping from.
    ///
    /// Used as the ownership epoch in [`describe_stale_execution`]. Read from
    /// the DATABASE, not the controller, because every timestamp it is
    /// compared against is Postgres-generated — see the module docs for why a
    /// skew-tolerant controller clock would have missed the motivating
    /// incident by 43 seconds.
    pub async fn sweep_ownership_epoch(&self) -> Result<DateTime<Utc>> {
        let row: (DateTime<Utc>,) = sqlx::query_as("SELECT NOW()")
            .fetch_one(&self.db_pool)
            .await?;
        Ok(row.0)
    }

    /// Stale `running` executions, oldest first, with the evidence needed to
    /// say why each is being closed.
    ///
    /// Predicate is `started_at`-based, matching the pre-2026-09 sweep exactly
    /// and deliberately: an activity-based predicate would kill healthy runs,
    /// because a single long node emits NO events for its whole duration (the
    /// same workflow that motivated this module has a legitimate node
    /// observed running 1 970 seconds silently, to completion).
    ///
    /// Non-positive `stale_minutes` is refused — `make_interval(mins => -N)`
    /// flips the predicate to `started_at < NOW() + INTERVAL`, which matches
    /// every running execution on the platform. Same refusal as
    /// [`ExecutionRepository::cleanup_stale_executions`].
    pub async fn list_stale_running_executions(
        &self,
        stale_minutes: i64,
        limit: i64,
    ) -> Result<Vec<StaleExecutionEvidence>> {
        if stale_minutes <= 0 {
            tracing::warn!(
                target: "talos_audit",
                stale_minutes,
                "stale-execution sweep refused: stale_minutes must be positive \
                 (would match every running execution)"
            );
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            "SELECT e.id, \
                    e.started_at, \
                    ev.last_event_at, \
                    ns.node_id AS in_flight_node, \
                    ns.created_at AS in_flight_node_started_at, \
                    w.graph_json \
             FROM workflow_executions e \
             LEFT JOIN LATERAL ( \
                 SELECT MAX(created_at) AS last_event_at \
                 FROM execution_events WHERE execution_id = e.id \
             ) ev ON TRUE \
             LEFT JOIN LATERAL ( \
                 SELECT node_id, created_at \
                 FROM execution_events \
                 WHERE execution_id = e.id \
                   AND event_type = 'node_started' \
                   AND node_id IS NOT NULL \
                 ORDER BY created_at DESC, id DESC \
                 LIMIT 1 \
             ) ns ON TRUE \
             LEFT JOIN workflows w ON w.id = e.workflow_id \
             WHERE e.status = 'running' \
               AND e.started_at < NOW() - make_interval(mins => $1::int) \
             ORDER BY e.started_at, e.id \
             LIMIT $2",
        )
        .bind(stale_minutes)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            use sqlx::Row as _;
            out.push(StaleExecutionEvidence {
                id: r.try_get("id")?,
                started_at: r.try_get("started_at")?,
                last_event_at: r.try_get::<Option<DateTime<Utc>>, _>("last_event_at")?,
                in_flight_node: r.try_get::<Option<Uuid>, _>("in_flight_node")?,
                in_flight_node_started_at: r
                    .try_get::<Option<DateTime<Utc>>, _>("in_flight_node_started_at")?,
                graph_json: r.try_get::<Option<String>, _>("graph_json")?,
            });
        }
        Ok(out)
    }

    /// Close one stale execution with an attributed message.
    ///
    /// Status-guarded (structural check 39): the row may have finalized itself
    /// between [`Self::list_stale_running_executions`] and this write — an
    /// engine that finally returned, a cancel, a crash-recovery claim moving
    /// it to `resuming`. Returns `false` in that case and the sweep leaves the
    /// real outcome standing. That race resolution is the opposite of the
    /// pre-2026-09 bulk UPDATE's (which had no read, so it simply won), and
    /// the new direction is the correct one: a genuine terminal status always
    /// beats the janitor's.
    pub async fn fail_stale_execution(&self, id: Uuid, error_message: &str) -> Result<bool> {
        // Excluding 'resuming' is deliberate, and widening it would be a
        // behaviour change rather than a fix: a `resuming` row is OWNED by crash
        // recovery, and `reclaim_orphaned_resuming` is the writer that fails one
        // out. The pre-2026-09 bulk sweep this replaces guarded
        // `status IN ('running')` for exactly that reason; this preserves it.
        //
        // allow-running-only-finalize: see the paragraph directly above.
        let r = sqlx::query(
            "UPDATE workflow_executions \
             SET status = 'failed', completed_at = NOW(), error_message = $2 \
             WHERE id = $1 AND status = 'running'",
        )
        .bind(id)
        .bind(error_message)
        .execute(&self.db_pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    /// The motivating incident, to the second. `b11b9755` dispatched its third
    /// node at 17:25:14 and the controller process was replaced ~15 s later;
    /// the sweep closed the row at 18:28:24.
    fn incident() -> StaleExecutionEvidence {
        StaleExecutionEvidence {
            id: Uuid::nil(),
            started_at: at("2026-08-31T17:25:09Z"),
            last_event_at: Some(at("2026-08-31T17:25:14Z")),
            in_flight_node: Some(Uuid::nil()),
            in_flight_node_started_at: Some(at("2026-08-31T17:25:14Z")),
            graph_json: None,
        }
    }

    #[test]
    fn an_execution_orphaned_by_a_restart_says_so() {
        let msg = describe_stale_execution(
            &incident(),
            Some(at("2026-08-31T17:25:31Z")),
            Some("classify_work"),
        );
        assert!(msg.contains("Orphaned, not overrunning"), "{msg}");
        assert!(msg.contains("2026-08-31T17:25:14Z"), "{msg}");
        assert!(msg.contains("2026-08-31T17:25:31Z"), "{msg}");
        assert!(
            msg.contains("Last node to start: classify_work"),
            "the node that was holding the run must be named: {msg}"
        );
        assert!(
            msg.contains("never got the chance to expire"),
            "the record must say the budget did not fire, not that it did: {msg}"
        );
    }

    /// The 17-second margin is the whole reason the ownership epoch is read
    /// from Postgres rather than the controller clock. Pin it: a comparison
    /// that needed more than 17 s of separation would not have attributed the
    /// incident at all.
    #[test]
    fn attribution_survives_a_seventeen_second_margin() {
        let ev = incident();
        let epoch = at("2026-08-31T17:25:31Z");
        assert_eq!(
            (epoch - ev.last_activity_at()).num_seconds(),
            17,
            "the incident's real margin"
        );
        assert!(describe_stale_execution(&ev, Some(epoch), None).contains("Orphaned"));
    }

    #[test]
    fn activity_during_this_process_is_not_called_an_orphan() {
        let mut ev = incident();
        ev.last_event_at = Some(at("2026-08-31T18:20:00Z"));
        let msg = describe_stale_execution(&ev, Some(at("2026-08-31T17:25:31Z")), Some("compose"));
        assert!(!msg.contains("Orphaned"), "{msg}");
        assert!(
            msg.contains("within the lifetime of the controller process"),
            "{msg}"
        );
    }

    /// Exactly-equal timestamps must not be called orphaned. The claim is
    /// "activity PRECEDES this process", and `==` does not establish that.
    #[test]
    fn equal_timestamps_make_no_ownership_claim() {
        let mut ev = incident();
        ev.last_event_at = Some(at("2026-08-31T17:25:31Z"));
        let epoch = Some(at("2026-08-31T17:25:31Z"));
        assert!(!orphaned_before_this_process(&ev, epoch));
        assert!(!describe_stale_execution(&ev, epoch, None).contains("Orphaned"));
    }

    /// The predicate and the wording must agree — the caller counts orphans
    /// with the predicate and the operator reads the wording, and a metric
    /// that disagrees with the record it summarises is its own defect class.
    #[test]
    fn the_verdict_predicate_and_the_wording_never_disagree() {
        let mut cases = vec![incident()];
        let mut late = incident();
        late.last_event_at = Some(at("2026-08-31T18:20:00Z"));
        cases.push(late);
        let mut eventless = incident();
        eventless.last_event_at = None;
        cases.push(eventless);

        for ev in &cases {
            for epoch in [
                None,
                Some(at("2026-08-31T17:25:31Z")),
                Some(at("2026-08-31T19:00:00Z")),
            ] {
                let says_orphan = describe_stale_execution(ev, epoch, None).contains("Orphaned");
                assert_eq!(
                    says_orphan,
                    orphaned_before_this_process(ev, epoch),
                    "ev {ev:?} epoch {epoch:?}"
                );
            }
        }
    }

    #[test]
    fn an_unreadable_epoch_states_facts_and_claims_nothing() {
        let msg = describe_stale_execution(&incident(), None, Some("classify_work"));
        assert!(!msg.contains("Orphaned"), "{msg}");
        assert!(!msg.contains("controller process"), "{msg}");
        assert!(
            msg.contains("Last execution activity 2026-08-31T17:25:14Z"),
            "{msg}"
        );
    }

    #[test]
    fn an_event_less_row_falls_back_to_started_at() {
        let ev = StaleExecutionEvidence {
            id: Uuid::nil(),
            started_at: at("2026-08-31T17:25:09Z"),
            last_event_at: None,
            in_flight_node: None,
            in_flight_node_started_at: None,
            graph_json: None,
        };
        let msg = describe_stale_execution(&ev, Some(at("2026-08-31T17:25:31Z")), None);
        assert!(msg.contains("2026-08-31T17:25:09Z"), "{msg}");
        assert!(msg.contains("No node ever started."), "{msg}");
    }

    #[test]
    fn an_unresolvable_label_falls_back_to_the_node_uuid() {
        let node = Uuid::parse_str("d04d5824-02ce-0dc5-ebad-187cb7ad2f47").unwrap();
        let mut ev = incident();
        ev.in_flight_node = Some(node);
        for label in [None, Some(""), Some("   ")] {
            let msg = describe_stale_execution(&ev, None, label);
            assert!(
                msg.contains("d04d5824-02ce-0dc5-ebad-187cb7ad2f47"),
                "label {label:?}: {msg}"
            );
        }
    }

    /// The message is substring-classified downstream, and the branches that
    /// win over `"execution stale"` include `"timed out"`, `"timeout"`,
    /// `"401"`, and `"missing" && "config"`. A message that reclassifies forks
    /// the ops-alert dedup history for every stale execution on the platform.
    ///
    /// Digits are the sharp edge: the only ones this module emits come from
    /// RFC-3339 second-precision timestamps, whose longest adjacent-digit run
    /// is the four-digit year. Sub-second precision would add a three-digit
    /// field that can read `401`.
    #[test]
    fn no_wording_hijacks_the_downstream_error_classifier() {
        let mut samples = vec![
            describe_stale_execution(
                &incident(),
                Some(at("2026-08-31T17:25:31Z")),
                Some("classify_work"),
            ),
            describe_stale_execution(&incident(), Some(at("2026-08-31T18:20:00Z")), None),
            describe_stale_execution(&incident(), None, Some("compose")),
        ];
        let mut ev = incident();
        ev.last_event_at = Some(at("2026-08-31T18:20:00Z"));
        samples.push(describe_stale_execution(
            &ev,
            Some(at("2026-08-31T17:25:31Z")),
            None,
        ));

        for msg in &samples {
            let m = msg.to_lowercase();
            assert!(
                m.contains("execution stale"),
                "lost the class anchor: {msg}"
            );
            for needle in [
                "timed out",
                "timeout",
                "401",
                "unauthorized",
                "access_token invalid",
                "missing",
                "fuel exhausted",
                "forbiddenhost",
                "signature verification failed",
                "no upstream",
                "networkerror",
                "llm",
                "model served nothing",
                "approval was denied",
                "approval denied",
            ] {
                assert!(
                    !m.contains(needle),
                    "message contains {needle:?}, which classifies ahead of \"execution stale\": {msg}"
                );
            }
            assert!(
                !m.contains("node '"),
                "`extract_failed_node` would read this as a FAILED node; it never reported: {msg}"
            );
        }
    }

    /// Longest adjacent-digit run, proved rather than asserted — the property
    /// the `401` needle actually depends on.
    #[test]
    fn timestamps_never_produce_a_three_digit_run_outside_the_year() {
        let msg = describe_stale_execution(
            &incident(),
            Some(at("2026-08-31T17:25:31Z")),
            Some("classify_work"),
        );
        let mut run = 0usize;
        let mut longest = 0usize;
        for c in msg.chars() {
            if c.is_ascii_digit() {
                run += 1;
                longest = longest.max(run);
            } else {
                run = 0;
            }
        }
        assert_eq!(
            longest, 4,
            "only the four-digit year may be a long run: {msg}"
        );
    }

    #[test]
    fn a_long_label_is_capped() {
        let msg = describe_stale_execution(&incident(), None, Some(&"x".repeat(500)));
        assert!(msg.contains(&"x".repeat(MAX_LABEL_CHARS)));
        assert!(!msg.contains(&"x".repeat(MAX_LABEL_CHARS + 1)), "{msg}");
    }
}
