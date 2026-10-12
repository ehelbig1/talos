//! What started an execution.
//!
//! Until 2026-10-12 `list_executions` returned nothing about how a run came
//! to exist. A run started by a schedule, by `test_workflow` and by an action
//! link tapped on a phone were three rows that differed only in their
//! timestamps; the only way to tell a real tap from a rehearsal was the time.
//!
//! # Where it is kept
//!
//! `workflow_executions.provenance` (JSONB), under the key
//! [`STARTED_BY_KEY`]: `{"kind": "action_link", "id": "<uuid>"}`.
//!
//! **`provenance.trigger_type` is not touched.** It is an older, coarser
//! vocabulary (`manual`, `scheduled`, `webhook`, `actor_dispatch`, `api`)
//! that the ops-alert self-monitor, the operator digest and the schedule
//! statistics filter on, and a row with no `trigger_type` reads as `manual`
//! through every one of them. A start path that had no provenance at all now
//! writes ONLY `started_by`, so each of those readers sees exactly what it
//! saw. Whether a run started by a push channel or an action link should
//! count as unattended (and so raise an alert when it fails) is a separate
//! decision this does not make.
//!
//! # Reading it back
//!
//! [`started_by`] answers for every row, including the ones written before
//! this existed and the paths that record their origin somewhere else: the
//! scheduler and the webhook router already write `trigger_type` with their
//! own id, a test run carries `is_test_execution`, a replay carries
//! `replayed_from_id`, a chained run `triggered_by_module_execution_id`. A
//! row none of those explain is `not_recorded`, never `manual`: "a person
//! started this" is a claim, and a row that says nothing does not make it.

use serde_json::Value;
use uuid::Uuid;

/// The provenance key the origin is stored under.
pub const STARTED_BY_KEY: &str = "started_by";

/// A way a workflow run is started, for the paths that record it here.
///
/// The scheduler, the webhook router, the test tools, replay and chains are
/// not variants: each already marks its rows (see the module docs), and
/// [`started_by`] reads those marks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionOrigin {
    /// `trigger_workflow`, by a person or an agent through MCP.
    Manual,
    /// The GraphQL `triggerWorkflow` mutation (the web UI, or a script).
    Api,
    /// `call_workflow`: a synchronous run for its output.
    CallWorkflow,
    /// `bulk_trigger_workflow`: one of a batch.
    BulkTrigger,
    /// `trigger_workflow_as_actors`: one run per actor.
    TriggerAsActors,
    /// `test_workflow_draft`: the draft graph, not flagged as a test row.
    TestDraft,
    /// `enqueue_workflow`: queued for the dispatcher.
    Enqueue,
    /// A continuation: a suspended workflow resumed by its correlation id.
    Continuation,
    /// The memory A/B evaluation harness.
    Evaluation,
    /// An action link was confirmed. `link_id` is the token row's id, never
    /// the token.
    ActionLink { link_id: Uuid },
    /// A push channel bound to this workflow received a notification.
    PushChannel {
        /// The integration that owns the channel (`google_calendar`, …).
        integration: &'static str,
        channel_id: Uuid,
    },
}

impl ExecutionOrigin {
    /// The stable word for this origin.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Api => "api",
            Self::CallWorkflow => "call_workflow",
            Self::BulkTrigger => "bulk_trigger",
            Self::TriggerAsActors => "trigger_as_actors",
            Self::TestDraft => "test_draft",
            Self::Enqueue => "enqueue",
            Self::Continuation => "continuation",
            Self::Evaluation => "evaluation",
            Self::ActionLink { .. } => "action_link",
            Self::PushChannel { .. } => "push_channel",
        }
    }

    /// The `started_by` object: `{"kind", "id"?, "integration"?}`.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = serde_json::json!({ "kind": self.kind() });
        match self {
            Self::ActionLink { link_id } => {
                object["id"] = Value::String(link_id.to_string());
            }
            Self::PushChannel {
                integration,
                channel_id,
            } => {
                object["id"] = Value::String(channel_id.to_string());
                object["integration"] = Value::String((*integration).to_string());
            }
            _ => {}
        }
        object
    }

    /// `provenance` with this origin recorded in it.
    ///
    /// Whatever the caller already put there (`actor_id`, `trigger_type`) is
    /// kept; only [`STARTED_BY_KEY`] is written. A `provenance` that is not a
    /// JSON object is replaced: nothing reads one.
    #[must_use]
    pub fn stamp(&self, provenance: Option<Value>) -> Value {
        let mut object = match provenance {
            Some(Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        };
        object.insert(STARTED_BY_KEY.to_string(), self.to_json());
        Value::Object(object)
    }
}

/// What started a run, as read back from its row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedBy {
    /// One of [`ExecutionOrigin::kind`]'s words, or `schedule`, `webhook`,
    /// `actor_dispatch`, `handoff`, `test`, `replay`, `chain`, or
    /// [`NOT_RECORDED`].
    pub kind: String,
    /// The schedule, webhook trigger, link, channel, actor or execution
    /// concerned, where there is one.
    pub id: Option<String>,
    /// The integration, for a push channel.
    pub integration: Option<String>,
}

/// The `kind` of a row that records nothing about how it started.
pub const NOT_RECORDED: &str = "not_recorded";

impl StartedBy {
    fn of(kind: &str, id: Option<String>) -> Self {
        Self {
            kind: kind.to_string(),
            id,
            integration: None,
        }
    }

    /// `{"kind", "id"?, "integration"?}`.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = serde_json::json!({ "kind": self.kind });
        if let Some(id) = &self.id {
            object["id"] = Value::String(id.clone());
        }
        if let Some(integration) = &self.integration {
            object["integration"] = Value::String(integration.clone());
        }
        object
    }
}

/// Longest `kind` / `id` / `integration` read back from a row, in characters.
/// The values are this crate's own, so the bound only matters for a row
/// something else wrote.
const FIELD_MAX_CHARS: usize = 64;

/// What started the run a row describes.
///
/// In order: an explicit [`STARTED_BY_KEY`]; the marks the older paths leave
/// (`trigger_type` with its id, `is_test_execution`, `replayed_from_id`,
/// `triggered_by_module_execution_id`); otherwise [`NOT_RECORDED`].
#[must_use]
pub fn started_by(
    provenance: Option<&Value>,
    is_test_execution: bool,
    replayed_from_id: Option<Uuid>,
    triggered_by_module_execution_id: Option<Uuid>,
) -> StartedBy {
    let text = |value: Option<&Value>| -> Option<String> {
        value
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(|s| s.chars().take(FIELD_MAX_CHARS).collect())
    };
    if let Some(recorded) = provenance.and_then(|p| p.get(STARTED_BY_KEY)) {
        if let Some(kind) = text(recorded.get("kind")) {
            return StartedBy {
                kind,
                id: text(recorded.get("id")),
                integration: text(recorded.get("integration")),
            };
        }
    }
    // A test run and a replay are what they are whatever else the row says.
    if is_test_execution {
        return StartedBy::of("test", None);
    }
    if let Some(original) = replayed_from_id {
        return StartedBy::of("replay", Some(original.to_string()));
    }
    let field = |key: &str| text(provenance.and_then(|p| p.get(key)));
    match field("trigger_type").as_deref() {
        Some("scheduled") => return StartedBy::of("schedule", field("schedule_id")),
        Some("webhook") => return StartedBy::of("webhook", field("trigger_id")),
        Some("actor_dispatch" | "agent_dispatch") => {
            return StartedBy::of("actor_dispatch", field("actor_id"))
        }
        Some("actor_handoff") => return StartedBy::of("handoff", field("actor_id")),
        Some("api") => return StartedBy::of("api", None),
        // `manual` written explicitly is a claim somebody made; a missing
        // `trigger_type` is not, and falls through.
        Some("manual") => return StartedBy::of("manual", None),
        _ => {}
    }
    if let Some(module_execution) = triggered_by_module_execution_id {
        return StartedBy::of("chain", Some(module_execution.to_string()));
    }
    StartedBy::of(NOT_RECORDED, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn read(provenance: Value) -> StartedBy {
        started_by(Some(&provenance), false, None, None)
    }

    #[test]
    fn an_origin_written_is_the_origin_read() {
        let link = Uuid::from_u128(7);
        let channel = Uuid::from_u128(9);
        for origin in [
            ExecutionOrigin::Manual,
            ExecutionOrigin::Api,
            ExecutionOrigin::CallWorkflow,
            ExecutionOrigin::BulkTrigger,
            ExecutionOrigin::TriggerAsActors,
            ExecutionOrigin::TestDraft,
            ExecutionOrigin::Enqueue,
            ExecutionOrigin::Continuation,
            ExecutionOrigin::Evaluation,
            ExecutionOrigin::ActionLink { link_id: link },
            ExecutionOrigin::PushChannel {
                integration: "google_calendar",
                channel_id: channel,
            },
        ] {
            let back = read(origin.stamp(None));
            assert_eq!(back.kind, origin.kind(), "{origin:?}");
        }
        // The observed pair: a tap on a phone, and a rehearsal.
        let tapped = read(ExecutionOrigin::ActionLink { link_id: link }.stamp(None));
        assert_eq!(
            tapped.to_json(),
            json!({ "kind": "action_link", "id": link.to_string() })
        );
        let pushed = read(
            ExecutionOrigin::PushChannel {
                integration: "google_calendar",
                channel_id: channel,
            }
            .stamp(None),
        );
        assert_eq!(
            pushed.to_json(),
            json!({ "kind": "push_channel", "id": channel.to_string(), "integration": "google_calendar" })
        );
    }

    /// The older vocabulary is not this change's to alter: stamping an origin
    /// writes one key and leaves the rest of the object alone.
    #[test]
    fn stamping_keeps_what_was_there_and_adds_no_trigger_type() {
        let actor = Uuid::from_u128(3);
        let stamped = ExecutionOrigin::Manual.stamp(Some(
            json!({ "actor_id": actor, "trigger_type": "actor_dispatch" }),
        ));
        assert_eq!(
            stamped,
            json!({
                "actor_id": actor,
                "trigger_type": "actor_dispatch",
                "started_by": { "kind": "manual" },
            })
        );
        // A path that had no provenance at all still has no `trigger_type`,
        // so every reader that defaults a missing one sees what it saw.
        let bare = ExecutionOrigin::ActionLink { link_id: actor }.stamp(None);
        assert!(bare.get("trigger_type").is_none());
        assert_eq!(bare.as_object().map(serde_json::Map::len), Some(1));
        // Something that is not an object is replaced, not merged into.
        assert_eq!(
            ExecutionOrigin::Enqueue.stamp(Some(json!("text"))),
            json!({ "started_by": { "kind": "enqueue" } })
        );
    }

    #[test]
    fn the_paths_that_mark_their_rows_another_way_are_read_from_those_marks() {
        let schedule = Uuid::from_u128(11);
        assert_eq!(
            read(json!({ "trigger_type": "scheduled", "schedule_id": schedule })).to_json(),
            json!({ "kind": "schedule", "id": schedule.to_string() })
        );
        let trigger = Uuid::from_u128(12);
        assert_eq!(
            read(json!({ "trigger_type": "webhook", "trigger_id": trigger })).to_json(),
            json!({ "kind": "webhook", "id": trigger.to_string() })
        );
        let actor = Uuid::from_u128(13);
        for legacy in ["actor_dispatch", "agent_dispatch"] {
            assert_eq!(
                read(json!({ "trigger_type": legacy, "actor_id": actor })).kind,
                "actor_dispatch"
            );
        }
        assert_eq!(
            read(json!({ "trigger_type": "actor_handoff" })).kind,
            "handoff"
        );

        assert_eq!(started_by(None, true, None, None).kind, "test");
        let original = Uuid::from_u128(14);
        assert_eq!(
            started_by(None, false, Some(original), None).to_json(),
            json!({ "kind": "replay", "id": original.to_string() })
        );
        let module_execution = Uuid::from_u128(15);
        assert_eq!(
            started_by(None, false, None, Some(module_execution)).to_json(),
            json!({ "kind": "chain", "id": module_execution.to_string() })
        );
        // A replay of a scheduled run is a replay.
        assert_eq!(
            started_by(
                Some(&json!({ "trigger_type": "scheduled" })),
                false,
                Some(original),
                None
            )
            .kind,
            "replay"
        );
    }

    /// A row that says nothing is not a row a person started.
    #[test]
    fn a_row_that_records_nothing_is_not_recorded_never_manual() {
        assert_eq!(started_by(None, false, None, None).kind, NOT_RECORDED);
        assert_eq!(read(json!({})).kind, NOT_RECORDED);
        assert_eq!(read(json!({ "actor_id": Uuid::nil() })).kind, NOT_RECORDED);
        assert_eq!(
            read(json!({ "trigger_type": "something-else" })).kind,
            NOT_RECORDED
        );
        assert_eq!(
            read(json!({ "started_by": { "kind": "" } })).kind,
            NOT_RECORDED
        );
        assert_eq!(read(json!({ "started_by": "text" })).kind, NOT_RECORDED);
        // `manual` written down is a claim somebody made, and is kept.
        assert_eq!(read(json!({ "trigger_type": "manual" })).kind, "manual");
    }

    /// Every production statement that inserts an execution row, and how the
    /// row it writes says what started it.
    ///
    /// A site added to one of these files changes a count and fails here,
    /// which is the point: whoever adds a way to start a run decides how it
    /// is recorded. (Structural check 95 counts the same eleven statements
    /// across the whole workspace, for the actor budget; a statement in a
    /// file not listed here is that check's to find.)
    #[test]
    fn every_insert_of_an_execution_row_has_an_origin() {
        // (file, statements, how each row's origin is known)
        let sites: [(&str, &str, usize, &str); 5] = [
            (
                "talos-workflow-repository/src/executions.rs",
                include_str!("executions.rs"),
                4,
                "create_execution and create_execution_under_concurrency_limit take the \
                 caller's provenance (an ExecutionOrigin stamp, or the scheduler's / webhook \
                 router's trigger_type); the batch insert stamps Enqueue itself; \
                 create_test_execution sets is_test_execution",
            ),
            (
                "talos-advanced-repository/src/lib.rs",
                include_str!("../../talos-advanced-repository/src/lib.rs"),
                1,
                "insert_queued_execution stamps Continuation itself",
            ),
            (
                "talos-execution-repository/src/lib.rs",
                include_str!("../../talos-execution-repository/src/lib.rs"),
                2,
                "create_replay_execution writes replayed_from_id; insert_test_execution_row \
                 sets is_test_execution",
            ),
            (
                "talos-actor-repository/src/lib.rs",
                include_str!("../../talos-actor-repository/src/lib.rs"),
                1,
                "insert_handoff_execution writes trigger_type actor_handoff",
            ),
            (
                "talos-engine/src/workflow_chains.rs",
                include_str!("../../talos-engine/src/workflow_chains.rs"),
                3,
                "a chained run's rows: the first writes triggered_by_module_execution_id; \
                 the two failed-row upserts write a row for a chain that never started, \
                 which reads not_recorded",
            ),
        ];
        const INSERT: &str = "INSERT INTO workflow_executions";
        for (file, source, expected, how) in sites {
            let found = source
                .match_indices(INSERT)
                .filter(|(at, _)| {
                    // Not `workflow_executions_archive` or another longer name.
                    !source[at + INSERT.len()..]
                        .starts_with(|c: char| c == '_' || c.is_ascii_alphanumeric())
                })
                .count();
            assert_eq!(
                found, expected,
                "{file} now holds {found} inserts into workflow_executions, not {expected}. \
                 Decide how the new (or removed) one records what started its run, then \
                 update this table. Known so far: {how}"
            );
        }
        // The two inserts that had no provenance column until 2026-10-12 now
        // carry their own stamp.
        assert!(sites[0].1.contains("ExecutionOrigin::Enqueue.stamp(None)"));
        assert!(sites[1]
            .1
            .contains("ExecutionOrigin::Continuation.stamp(None)"));
    }

    #[test]
    fn a_value_something_else_wrote_is_bounded() {
        let long = "k".repeat(500);
        let back = read(json!({ "started_by": { "kind": long, "id": "i".repeat(500) } }));
        assert_eq!(back.kind.chars().count(), FIELD_MAX_CHARS);
        assert_eq!(back.id.map(|i| i.chars().count()), Some(FIELD_MAX_CHARS));
    }
}
