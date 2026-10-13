//! An execution says what started it.
//!
//! Observed 2026-10-11: `list_executions` returned nothing about how a run
//! came to exist. A run started by a schedule, by `test_workflow` and by an
//! action link tapped on a phone were three rows that differed only in their
//! timestamps.
//!
//! Each start path here goes through the PRODUCTION function that inserts its
//! row, with the origin that path's own caller passes, and is read back
//! through the query `list_executions` uses. The paths that mark their rows
//! another way (the scheduler, the webhook router, a replay, a chain, a test)
//! are written in the shape their writers use.
//!
//! The last test is about what did NOT change: every reader that takes
//! `provenance->>'trigger_type'` and defaults a missing one to `manual` sees
//! exactly what it saw, because a path that had no provenance now writes only
//! `started_by`.
//!
//! DB tests on the `common` harness.

mod common;

use serde_json::json;
use sqlx::{Pool, Postgres};
use talos_advanced_repository::AdvancedRepository;
use talos_execution_repository::ExecutionRepository;
use talos_workflow_repository::{
    ExecutionOrigin, ExecutionPriority, InitialExecutionStatus, WorkflowRepository,
};
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'started-by test')",
    )
    .bind(id)
    .bind(format!("started-by-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

/// `workflow_executions.actor_id` is NOT NULL: every run is attributed.
async fn seed_actor(pool: &Pool<Postgres>, user: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(id)
        .bind(user)
        .bind(format!("started-by-actor-{id}"))
        .execute(pool)
        .await
        .expect("seed actor");
    id
}

/// The insert went ahead: the actor's budget did not refuse it.
fn admitted(admission: impl std::fmt::Debug) {
    let said = format!("{admission:?}");
    assert!(
        said.starts_with("Admitted"),
        "the insert was refused: {said}"
    );
}

struct World {
    pool: Pool<Postgres>,
    _db: common::TestDb,
    user: Uuid,
    actor: Uuid,
    workflow: Uuid,
    workflows: WorkflowRepository,
    executions: ExecutionRepository,
}

async fn world() -> World {
    let (pool, db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let actor = seed_actor(&pool, user).await;
    let workflow = common::create_test_workflow(&pool, user, "started-by").await;
    World {
        workflows: WorkflowRepository::new(pool.clone()),
        executions: ExecutionRepository::new(pool.clone()),
        pool,
        _db: db,
        user,
        actor,
        workflow,
    }
}

impl World {
    /// The row's `started_by`, as `list_executions` returns it.
    async fn started_by(&self, execution: Uuid) -> serde_json::Value {
        let rows = self
            .executions
            .list_executions(self.workflow, self.user, 200, 0)
            .await
            .expect("list");
        rows.into_iter()
            .find(|r| r.id == execution)
            .unwrap_or_else(|| panic!("execution {execution} is not listed"))
            .started_by
            .to_json()
    }

    /// A row through the insert `trigger_workflow`, the scheduler, the
    /// webhook router and `call_workflow` all use.
    async fn through_the_trigger_insert(&self, provenance: &serde_json::Value) -> Uuid {
        let id = Uuid::new_v4();
        self.workflows
            .create_execution_under_concurrency_limit(
                id,
                self.workflow,
                self.user,
                None,
                ExecutionPriority::Normal,
                Some(self.actor),
                Some(provenance),
                None,
                None,
                InitialExecutionStatus::Running,
                talos_workflow_repository::RunMode::Real,
            )
            .await
            .expect("insert");
        id
    }
}

#[tokio::test]
async fn each_start_path_is_read_back_as_itself() {
    let w = world().await;

    // The observed pair: a tap on a phone …
    let link = Uuid::new_v4();
    let tapped = w
        .through_the_trigger_insert(&ExecutionOrigin::ActionLink { link_id: link }.stamp(None))
        .await;
    assert_eq!(
        w.started_by(tapped).await,
        json!({ "kind": "action_link", "id": link.to_string() })
    );

    // … and a rehearsal, through `test_workflow`'s own insert.
    let rehearsal = Uuid::new_v4();
    admitted(
        w.workflows
            .create_test_execution(
                rehearsal,
                w.workflow,
                w.user,
                None,
                ExecutionPriority::Normal,
                Some(w.actor),
                talos_workflow_repository::RunMode::Real,
            )
            .await
            .expect("test insert"),
    );
    assert_eq!(w.started_by(rehearsal).await, json!({ "kind": "test" }));
    let listed = w
        .executions
        .list_executions(w.workflow, w.user, 200, 0)
        .await
        .expect("list");
    assert!(
        listed
            .iter()
            .find(|r| r.id == rehearsal)
            .expect("row")
            .is_test
    );
    assert!(!listed.iter().find(|r| r.id == tapped).expect("row").is_test);

    // A push channel, with its integration.
    let channel = Uuid::new_v4();
    let pushed = w
        .through_the_trigger_insert(
            &ExecutionOrigin::PushChannel {
                integration: "google_calendar",
                channel_id: channel,
            }
            .stamp(None),
        )
        .await;
    assert_eq!(
        w.started_by(pushed).await,
        json!({ "kind": "push_channel", "id": channel.to_string(), "integration": "google_calendar" })
    );

    // `trigger_workflow` with an explicit actor: the service keeps writing
    // `actor_id` and `trigger_type`, and the origin beside them is what is read.
    let manual = w
        .through_the_trigger_insert(&ExecutionOrigin::Manual.stamp(Some(
            json!({ "actor_id": w.actor, "trigger_type": "actor_dispatch" }),
        )))
        .await;
    assert_eq!(w.started_by(manual).await, json!({ "kind": "manual" }));

    // The other callers of the same insert.
    for origin in [
        ExecutionOrigin::Api,
        ExecutionOrigin::CallWorkflow,
        ExecutionOrigin::BulkTrigger,
        ExecutionOrigin::TriggerAsActors,
        ExecutionOrigin::Evaluation,
    ] {
        let id = w.through_the_trigger_insert(&origin.stamp(None)).await;
        assert_eq!(w.started_by(id).await, json!({ "kind": origin.kind() }));
    }

    // `test_workflow_draft`, through the plain insert.
    let draft = Uuid::new_v4();
    admitted(
        w.workflows
            .create_execution(
                draft,
                w.workflow,
                w.user,
                None,
                ExecutionPriority::Normal,
                Some(w.actor),
                Some(&ExecutionOrigin::TestDraft.stamp(None)),
            )
            .await
            .expect("draft insert"),
    );
    assert_eq!(w.started_by(draft).await, json!({ "kind": "test_draft" }));

    // `enqueue_workflow`: the batch insert stamps its own rows.
    let queued = [Uuid::new_v4(), Uuid::new_v4()];
    let batch = w
        .workflows
        .create_executions_batch_under_concurrency_limit(
            &queued,
            w.workflow,
            w.user,
            None,
            Some(w.actor),
        )
        .await
        .expect("batch insert");
    assert_eq!(batch.inserted, 2);
    for id in queued {
        assert_eq!(w.started_by(id).await, json!({ "kind": "enqueue" }));
    }

    // A continuation: its insert stamps its own row.
    let continued = Uuid::new_v4();
    admitted(
        AdvancedRepository::new(w.pool.clone())
            .insert_queued_execution(continued, w.workflow, w.user, Some(w.actor), &json!({}))
            .await
            .expect("continuation insert"),
    );
    assert_eq!(
        w.started_by(continued).await,
        json!({ "kind": "continuation" })
    );
}

#[tokio::test]
async fn the_paths_that_mark_their_rows_another_way_are_read_from_those_marks() {
    let w = world().await;

    // The scheduler and the webhook router write `trigger_type` and their id.
    let schedule = Uuid::new_v4();
    let scheduled = w
        .through_the_trigger_insert(
            &json!({ "trigger_type": "scheduled", "schedule_id": schedule }),
        )
        .await;
    assert_eq!(
        w.started_by(scheduled).await,
        json!({ "kind": "schedule", "id": schedule.to_string() })
    );
    let trigger = Uuid::new_v4();
    let hooked = w
        .through_the_trigger_insert(&json!({ "trigger_type": "webhook", "trigger_id": trigger }))
        .await;
    assert_eq!(
        w.started_by(hooked).await,
        json!({ "kind": "webhook", "id": trigger.to_string() })
    );

    // A replay, through its own insert: the row names what it replays.
    let replay = Uuid::new_v4();
    admitted(
        w.executions
            .create_replay_execution(
                replay,
                w.workflow,
                w.user,
                scheduled,
                Some(w.actor),
                None,
                talos_workflow_repository::RunMode::Real,
            )
            .await
            .expect("replay insert"),
    );
    assert_eq!(
        w.started_by(replay).await,
        json!({ "kind": "replay", "id": scheduled.to_string() })
    );

    // A chained run carries the module execution that fired it. Its insert is
    // private to the engine, so the row is written in that insert's shape.
    let chained = Uuid::new_v4();
    let module_execution = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions \
         (id, workflow_id, user_id, actor_id, status, started_at, triggered_by_module_execution_id) \
         VALUES ($1, $2, $3, $4, 'running', NOW(), $5)",
    )
    .bind(chained)
    .bind(w.workflow)
    .bind(w.user)
    .bind(w.actor)
    .bind(module_execution)
    .execute(&w.pool)
    .await
    .expect("chain-shaped insert");
    assert_eq!(
        w.started_by(chained).await,
        json!({ "kind": "chain", "id": module_execution.to_string() })
    );

    // A row that records nothing is not a row a person started.
    let silent = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, actor_id, status, started_at) \
         VALUES ($1, $2, $3, $4, 'running', NOW())",
    )
    .bind(silent)
    .bind(w.workflow)
    .bind(w.user)
    .bind(w.actor)
    .execute(&w.pool)
    .await
    .expect("bare insert");
    assert_eq!(
        w.started_by(silent).await,
        json!({ "kind": "not_recorded" })
    );
}

/// What did not change. The self-monitor's alert scope, the operator digest
/// and the schedule statistics all read `provenance->>'trigger_type'` and
/// treat a missing one as `manual`. A path that used to write no provenance
/// now writes `started_by` and nothing else, so each of them sees the row as
/// it did.
#[tokio::test]
async fn recording_an_origin_adds_no_trigger_type() {
    let w = world().await;
    let what_the_older_readers_see = |id: Uuid| {
        let pool = w.pool.clone();
        async move {
            sqlx::query_scalar::<_, String>(
                "SELECT COALESCE(provenance->>'trigger_type', 'manual') \
                 FROM workflow_executions WHERE id = $1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("read")
        }
    };

    for origin in [
        ExecutionOrigin::ActionLink {
            link_id: Uuid::new_v4(),
        },
        ExecutionOrigin::PushChannel {
            integration: "google_calendar",
            channel_id: Uuid::new_v4(),
        },
        ExecutionOrigin::CallWorkflow,
        ExecutionOrigin::Api,
    ] {
        let id = w.through_the_trigger_insert(&origin.stamp(None)).await;
        assert_eq!(
            what_the_older_readers_see(id).await,
            "manual",
            "{origin:?} changed what the trigger_type readers see"
        );
    }

    let queued = [Uuid::new_v4()];
    w.workflows
        .create_executions_batch_under_concurrency_limit(
            &queued,
            w.workflow,
            w.user,
            None,
            Some(w.actor),
        )
        .await
        .expect("batch insert");
    assert_eq!(what_the_older_readers_see(queued[0]).await, "manual");
}
