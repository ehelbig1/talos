//! A dry run stays a dry run (2026-10-13).
//!
//! The dry-run flag used to live only in the engine that STARTED a run. A
//! run that paused (an approval, a wait node) or was caught by a controller
//! restart is given a new engine, and that engine was an ordinary one: the
//! rehearsal came back as a real run, with its stubbed sends made and its
//! action links minted. A retry or a replay of a dry run was real for the
//! same reason.
//!
//! The mode is now a column written by the statement that creates the row.
//! Pinned here on real rows:
//!
//! * each row-creating statement that can start a dry run records it, and
//!   an ordinary start records that it is not one;
//! * every path that hands a row to the resume kernel returns the row's
//!   mode with it (the paused-run claim and the crash-recovery claim);
//! * a replay carries the original's mode, and the by-id reader a retry
//!   uses returns it;
//! * the archive keeps it.
//!
//! That the resume kernel, retry and replay BUILD their engine with what
//! they are handed is `talos-execution-orchestration`'s `run_mode` tests;
//! driving those needs NATS, which this harness has none of.
//!
//! `common` harness (a template clone per test), so the migrated-database
//! job runs it.

mod common;

use common::{create_test_user, create_test_workflow, setup_test_context};
use sqlx::PgPool;
use talos_execution_repository::{ExecutionLookup, ExecutionRepository};
use talos_workflow_repository::{
    ConcurrencyAdmission, ExecutionPriority, InitialExecutionStatus, RunMode, WorkflowRepository,
};
use uuid::Uuid;

struct World {
    /// Owns the test database: dropping it drops the database.
    _ctx: common::TestContext,
    pool: PgPool,
    user: Uuid,
    actor: Uuid,
    workflow: Uuid,
    workflows: WorkflowRepository,
    executions: ExecutionRepository,
}

async fn world(email: &str) -> World {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, email).await;
    let workflow = create_test_workflow(&pool, user, "dry-run-survives").await;
    let actor = talos_actor_repository::ActorRepository::new(pool.clone())
        .get_or_create_default_actor(user)
        .await
        .expect("default actor");
    World {
        workflows: WorkflowRepository::new(pool.clone()),
        executions: ExecutionRepository::new(pool.clone()),
        _ctx: ctx,
        pool,
        user,
        actor,
        workflow,
    }
}

impl World {
    /// Start a run the way `trigger_workflow` and `call_workflow` do.
    async fn start(&self, mode: RunMode) -> Uuid {
        let id = Uuid::new_v4();
        let admission = self
            .workflows
            .create_execution_under_concurrency_limit(
                id,
                self.workflow,
                self.user,
                None,                      // version_id
                ExecutionPriority::Normal, // priority
                Some(self.actor),          // actor_id
                None,                      // provenance
                None,                      // parent_execution_id
                None,                      // root_execution_id
                InitialExecutionStatus::Running,
                mode,
            )
            .await
            .expect("create execution");
        assert!(matches!(admission, ConcurrencyAdmission::Created));
        id
    }

    async fn recorded(&self, id: Uuid) -> bool {
        sqlx::query_scalar("SELECT dry_run FROM workflow_executions WHERE id = $1")
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .expect("read dry_run")
    }
}

#[tokio::test]
async fn the_statement_that_creates_a_row_records_its_mode() {
    let w = world("dry-run-create@example.com").await;

    let (dry, real) = (w.start(RunMode::DryRun).await, w.start(RunMode::Real).await);
    assert!(w.recorded(dry).await, "a dry run was recorded as real");
    assert!(!w.recorded(real).await, "a real run was recorded as dry");

    // `test_workflow`'s own statement.
    for (mode, expected) in [(RunMode::DryRun, true), (RunMode::Real, false)] {
        let id = Uuid::new_v4();
        let admission = w
            .workflows
            .create_test_execution(
                id,
                w.workflow,
                w.user,
                None,
                ExecutionPriority::Normal,
                Some(w.actor),
                mode,
            )
            .await
            .expect("create test execution");
        assert!(matches!(
            admission,
            talos_actor_budget_refusal::BudgetAdmission::Admitted
        ));
        assert_eq!(w.recorded(id).await, expected, "{mode:?}");
    }
}

/// The resume of a run paused on an approval or a wait node: the claim hands
/// the kernel the row's mode.
#[tokio::test]
async fn a_paused_dry_run_is_claimed_back_as_a_dry_run() {
    let w = world("dry-run-paused@example.com").await;
    let (dry, real) = (w.start(RunMode::DryRun).await, w.start(RunMode::Real).await);
    sqlx::query("UPDATE workflow_executions SET status = 'waiting' WHERE id = ANY($1)")
        .bind(vec![dry, real])
        .execute(&w.pool)
        .await
        .expect("pause both");

    let claimed = w
        .executions
        .claim_waiting_execution_for_resume(dry, w.user, &[])
        .await
        .expect("claim")
        .expect("the paused dry run is claimable by its owner");
    assert_eq!(claimed.id, dry);
    assert!(
        claimed.dry_run,
        "a paused dry run was handed to the resume kernel as a real run"
    );

    let claimed = w
        .executions
        .claim_waiting_execution_for_resume(real, w.user, &[])
        .await
        .expect("claim")
        .expect("claimable");
    assert!(!claimed.dry_run, "a real run was resumed as a dry run");
}

/// Crash recovery: a run a controller restart caught mid-flight.
#[tokio::test]
async fn a_dry_run_caught_by_a_restart_is_recovered_as_a_dry_run() {
    let w = world("dry-run-recovered@example.com").await;
    let (dry, real) = (w.start(RunMode::DryRun).await, w.start(RunMode::Real).await);
    // `updated_at` is maintained by a trigger, so it is set with the
    // table's user triggers off (the database is this test's own).
    for statement in [
        "ALTER TABLE workflow_executions DISABLE TRIGGER USER",
        "UPDATE workflow_executions SET updated_at = NOW() - interval '30 minutes'",
        "ALTER TABLE workflow_executions ENABLE TRIGGER USER",
    ] {
        sqlx::query(statement)
            .execute(&w.pool)
            .await
            .expect("make both stale");
    }

    // The claim that feeds the kernel. Two stale rows, two claims, each
    // with its own mode.
    let mut claimed = std::collections::HashMap::new();
    while let Some(row) = w
        .executions
        .claim_stuck_execution_for_resume(5)
        .await
        .expect("claim")
    {
        claimed.insert(row.id, row.dry_run);
    }
    assert_eq!(
        claimed.get(&dry),
        Some(&true),
        "a dry run caught by a restart was recovered as a real run"
    );
    assert_eq!(claimed.get(&real), Some(&false));
}

/// A replay starts a NEW run from an old one, and a retry re-runs the same
/// row: both read the mode from the row, here.
#[tokio::test]
async fn a_replay_carries_the_originals_mode_and_the_reader_a_retry_uses_returns_it() {
    let w = world("dry-run-replay@example.com").await;
    let original = w.start(RunMode::DryRun).await;

    let ExecutionLookup::Live(row) = w
        .executions
        .lookup_execution(original, w.user)
        .await
        .expect("lookup")
    else {
        panic!("the execution was just created and is live");
    };
    assert!(row.dry_run, "the by-id reader lost the row's mode");

    // What `replay` does with it.
    let replay = Uuid::new_v4();
    let admission = w
        .executions
        .create_replay_execution(
            replay,
            w.workflow,
            w.user,
            original,
            Some(w.actor),
            None,
            RunMode::from_dry_run(row.dry_run),
        )
        .await
        .expect("replay insert");
    assert!(matches!(
        admission,
        talos_actor_budget_refusal::BudgetAdmission::Admitted
    ));
    assert!(
        w.recorded(replay).await,
        "a replay of a dry run was recorded as a real run"
    );

    // The other readers that build the same row type.
    let listed = w
        .executions
        .get_executions_by_ids(&[original, replay], w.user)
        .await
        .expect("by ids");
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().all(|r| r.dry_run));
}

/// The archive is a column-for-column copy made from an explicit list. A
/// column missing from the list would be archived as its default: a dry run
/// read back from the archive would say it had been real.
#[tokio::test]
async fn an_archived_dry_run_is_still_recorded_as_one() {
    let w = world("dry-run-archived@example.com").await;
    let dry = w.start(RunMode::DryRun).await;
    sqlx::query(
        "UPDATE workflow_executions \
         SET status = 'completed', completed_at = NOW() - interval '40 days' WHERE id = $1",
    )
    .bind(dry)
    .execute(&w.pool)
    .await
    .expect("finish it long ago");

    let moved = talos_advanced_repository::AdvancedRepository::new(w.pool.clone())
        .archive_executions(30, w.user)
        .await
        .expect("archive");
    assert_eq!(moved, 1);

    match w
        .executions
        .lookup_execution(dry, w.user)
        .await
        .expect("lookup")
    {
        ExecutionLookup::Archived { row, .. } => {
            assert!(row.dry_run, "the archive recorded a dry run as a real one")
        }
        ExecutionLookup::Live(_) => panic!("the execution was not moved"),
        ExecutionLookup::Absent => panic!("the archived execution was not found"),
    }
}
