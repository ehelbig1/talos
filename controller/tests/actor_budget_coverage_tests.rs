//! Every start path runs the actor's five-cap budget check (package CK,
//! 2026-09-18).
//!
//! Until this package the five caps were enforced atomically only inside
//! `create_execution_under_concurrency_limit`. Measured by statement, the
//! other start paths passed a lock-free pre-check that covered at most
//! actor status, per-hour and total: the continuation path (3 104 runs in 30
//! days on the reference fleet — every `pa-ask-email` Gmail push), replay,
//! retry, handoff and the three test-run writers never consulted per-minute,
//! fuel per hour or LLM tokens per day at all.
//!
//! Each test drives the PRODUCTION writer of one path against a real clone,
//! with the actor held at exactly one cap, and asserts: the start is REFUSED
//! with that cap, NO row was written (read back), and the refusal was
//! COUNTED. The control is the same writer for an actor with no policy, which
//! must write its row — and write it under the actor it was given, because
//! the continuation and MCP test writers used to bind no actor at all and let
//! the default-actor trigger stamp the user's Default actor on a run
//! executing as someone else.
//!
//! The three caps looped over are exactly the ones the old pre-checks never
//! read; per-hour and total run through the same shared function and are
//! covered for all five caps by `actor_budget_alert_tests`.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use sqlx::{Pool, Postgres};
use talos_execution_repository::BudgetAdmission;
use talos_workflow_repository::ExecutionPriority;
use uuid::Uuid;

/// The caps the pre-checks never consulted: (policy column, cap label).
const PRECHECK_BLIND_CAPS: [(&str, &str); 3] = [
    ("max_workflows_per_minute", "per_minute"),
    ("max_fuel_per_hour", "fuel_per_hour"),
    ("max_llm_tokens_per_day", "llm_tokens_per_day"),
];

struct Fixture {
    user: Uuid,
    actor: Uuid,
    wf: Uuid,
}

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'coverage')",
    )
    .bind(id)
    .bind(format!("budget-coverage-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_actor(pool: &Pool<Postgres>, user: Uuid, is_default: bool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO actors (id, user_id, name, status, is_default) VALUES ($1, $2, $3, 'active', $4)",
    )
    .bind(id)
    .bind(user)
    .bind(format!("coverage-actor-{id}"))
    .bind(is_default)
    .execute(pool)
    .await
    .expect("seed actor");
    id
}

/// A user with a DEFAULT actor (so the default-actor trigger has something to
/// stamp) and a second, non-default actor the path is asked to run as.
async fn fixture(pool: &Pool<Postgres>) -> Fixture {
    let user = seed_user(pool).await;
    seed_actor(pool, user, true).await;
    let actor = seed_actor(pool, user, false).await;
    let wf = common::create_test_workflow(pool, user, &format!("coverage-wf-{actor}")).await;
    Fixture { user, actor, wf }
}

/// One execution in the last minute, 5 fuel and 5 tokens of usage, then a
/// policy capping `column` at 1 — so exactly that cap refuses the next start.
async fn hold_at_cap(pool: &Pool<Postgres>, f: &Fixture, column: &str) {
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, status, started_at, actor_id) \
         VALUES ($1, $2, $3, 'completed', NOW(), $4)",
    )
    .bind(Uuid::new_v4())
    .bind(f.wf)
    .bind(f.user)
    .bind(f.actor)
    .execute(pool)
    .await
    .expect("seed prior execution");
    sqlx::query(
        "INSERT INTO execution_cost_rollup (actor_id, workflow_id, execution_id, node_id, fuel_consumed) \
         VALUES ($1, $2, $3, 'n', 5)",
    )
    .bind(f.actor)
    .bind(f.wf)
    .bind(Uuid::new_v4())
    .execute(pool)
    .await
    .expect("seed fuel");
    sqlx::query(
        "INSERT INTO llm_usage (actor_id, user_id, provider, model, prompt_tokens, completion_tokens) \
         VALUES ($1, $2, 'test', 'test', 3, 2)",
    )
    .bind(f.actor)
    .bind(f.user)
    .execute(pool)
    .await
    .expect("seed tokens");
    // `column` is a test constant, never input.
    sqlx::query(&format!(
        "INSERT INTO actor_budget_policies (actor_id, {column}, on_budget_exceeded) VALUES ($1, 1, 'block')"
    ))
    .bind(f.actor)
    .execute(pool)
    .await
    .expect("seed budget policy");
}

async fn row_actor(pool: &Pool<Postgres>, exec: Uuid) -> Option<Option<Uuid>> {
    sqlx::query_scalar("SELECT actor_id FROM workflow_executions WHERE id = $1")
        .bind(exec)
        .fetch_optional(pool)
        .await
        .expect("read row")
}

fn refusals(cap: &str) -> f64 {
    talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
    talos_metrics::global()
        .expect("global metrics")
        .actor_budget_refusals_total
        .with_label_values(&[cap, "block"])
        .get()
}

/// A writer under test: run it for `f` and return the new execution's id and
/// what the budget said.
type BoxedWrite =
    std::pin::Pin<Box<dyn std::future::Future<Output = (Uuid, BudgetAdmission)> + Send + 'static>>;
type Writer = fn(&Pool<Postgres>, &Fixture) -> BoxedWrite;

fn continuation(pool: &Pool<Postgres>, f: &Fixture) -> BoxedWrite {
    let pool = pool.clone();
    let (wf, user, actor) = (f.wf, f.user, f.actor);
    Box::pin(async move {
        let exec = Uuid::new_v4();
        let got = talos_advanced_repository::AdvancedRepository::new(pool)
            .insert_queued_execution(exec, wf, user, Some(actor), &serde_json::json!({"k": 1}))
            .await
            .expect("continuation insert");
        (exec, got)
    })
}

fn replay(pool: &Pool<Postgres>, f: &Fixture) -> BoxedWrite {
    let pool = pool.clone();
    let (wf, user, actor) = (f.wf, f.user, f.actor);
    Box::pin(async move {
        // `replayed_from_id` is a foreign key, so replay a real original. It is
        // written with NO actor, so the trigger gives it the user's Default
        // actor and it never counts toward the actor under test.
        let original = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO workflow_executions (id, workflow_id, user_id, status, started_at) \
             VALUES ($1, $2, $3, 'failed', NOW())",
        )
        .bind(original)
        .bind(wf)
        .bind(user)
        .execute(&pool)
        .await
        .expect("seed original");
        let exec = Uuid::new_v4();
        let got = talos_execution_repository::ExecutionRepository::new(pool)
            .create_replay_execution(exec, wf, user, original, Some(actor), None)
            .await
            .expect("replay insert");
        (exec, got)
    })
}

fn handoff(pool: &Pool<Postgres>, f: &Fixture) -> BoxedWrite {
    let pool = pool.clone();
    let (wf, user, actor) = (f.wf, f.user, f.actor);
    Box::pin(async move {
        let exec = Uuid::new_v4();
        let got = talos_actor_repository::ActorRepository::new(pool)
            .insert_handoff_execution(
                exec,
                wf,
                user,
                None,
                actor,
                &serde_json::json!({"handoff": true}),
                None,
                None,
            )
            .await
            .expect("handoff insert");
        (exec, got)
    })
}

fn mcp_test(pool: &Pool<Postgres>, f: &Fixture) -> BoxedWrite {
    let pool = pool.clone();
    let (wf, user, actor) = (f.wf, f.user, f.actor);
    Box::pin(async move {
        let exec = Uuid::new_v4();
        let got = talos_workflow_repository::WorkflowRepository::new(pool)
            .create_test_execution(exec, wf, user, None, ExecutionPriority::Normal, Some(actor))
            .await
            .expect("mcp test insert");
        (exec, got)
    })
}

fn mcp_draft(pool: &Pool<Postgres>, f: &Fixture) -> BoxedWrite {
    let pool = pool.clone();
    let (wf, user, actor) = (f.wf, f.user, f.actor);
    Box::pin(async move {
        let exec = Uuid::new_v4();
        let got = talos_workflow_repository::WorkflowRepository::new(pool)
            .create_execution(
                exec,
                wf,
                user,
                None,
                ExecutionPriority::Normal,
                Some(actor),
                None,
            )
            .await
            .expect("mcp draft insert");
        (exec, got)
    })
}

fn graphql_test(pool: &Pool<Postgres>, f: &Fixture) -> BoxedWrite {
    let pool = pool.clone();
    let (wf, user, actor) = (f.wf, f.user, f.actor);
    Box::pin(async move {
        let exec = Uuid::new_v4();
        let got = talos_execution_repository::ExecutionRepository::new(pool)
            .insert_test_execution_row(exec, wf, user, Some(actor), ExecutionPriority::Normal)
            .await
            .expect("graphql test insert");
        (exec, got)
    })
}

const WRITERS: [(&str, Writer); 6] = [
    ("continuation", continuation),
    ("replay", replay),
    ("handoff", handoff),
    ("mcp_test", mcp_test),
    ("mcp_draft", mcp_draft),
    ("graphql_test", graphql_test),
];

/// Every row-creating start path refuses an actor held at a cap the old
/// pre-checks never read, writes nothing, and counts the refusal.
#[tokio::test]
async fn every_start_path_refuses_at_a_cap_the_prechecks_never_read() {
    let (pool, _db) = common::isolated_db_pool().await;
    for (path, write) in WRITERS {
        for (column, cap) in PRECHECK_BLIND_CAPS {
            let f = fixture(&pool).await;
            hold_at_cap(&pool, &f, column).await;
            let before = refusals(cap);

            let (exec, got) = write(&pool, &f).await;
            match got {
                BudgetAdmission::Refused(r) => {
                    assert_eq!(r.cap.as_str(), cap, "{path}: refused on the wrong cap");
                    assert_eq!(r.actor_id, f.actor, "{path}: refused the wrong actor");
                    assert_eq!(r.limit, 1, "{path}/{cap}");
                }
                BudgetAdmission::Admitted => {
                    panic!("{path}: an actor at its {cap} cap was admitted")
                }
            }
            assert_eq!(
                row_actor(&pool, exec).await,
                None,
                "{path}/{cap}: a refused start must write no row"
            );
            assert!(
                refusals(cap) - before >= 1.0,
                "{path}/{cap}: the refusal must be counted"
            );
        }
    }
}

/// The control: with no budget policy every path writes its row — under the
/// actor it was GIVEN, not the user's Default actor the trigger would stamp.
#[tokio::test]
async fn every_start_path_admits_and_records_the_actor_it_runs_as() {
    let (pool, _db) = common::isolated_db_pool().await;
    for (path, write) in WRITERS {
        let f = fixture(&pool).await;
        let (exec, got) = write(&pool, &f).await;
        assert_eq!(
            got,
            BudgetAdmission::Admitted,
            "{path}: no policy, must admit"
        );
        assert_eq!(
            row_actor(&pool, exec).await,
            Some(Some(f.actor)),
            "{path}: the row must carry the actor the run executes as, not the Default actor"
        );
    }
}

/// Retry reuses a row instead of writing one, so it is driven separately: a
/// failed row of an actor at a cap is NOT reset (status and started_at are
/// read back unchanged), and the control actor's row IS reset.
#[tokio::test]
async fn retry_refuses_at_a_cap_and_leaves_the_row_untouched() {
    use talos_execution_repository::{ExecutionRepository, RetryReset};
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = ExecutionRepository::new(pool.clone());

    async fn failed_row(pool: &Pool<Postgres>, f: &Fixture) -> Uuid {
        let exec = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO workflow_executions (id, workflow_id, user_id, status, started_at, actor_id) \
             VALUES ($1, $2, $3, 'failed', NOW() - INTERVAL '2 days', $4)",
        )
        .bind(exec)
        .bind(f.wf)
        .bind(f.user)
        .bind(f.actor)
        .execute(pool)
        .await
        .expect("seed failed row");
        exec
    }
    async fn status_and_age(pool: &Pool<Postgres>, exec: Uuid) -> (String, bool) {
        sqlx::query_as(
            "SELECT status, started_at < NOW() - INTERVAL '1 day' FROM workflow_executions WHERE id = $1",
        )
        .bind(exec)
        .fetch_one(pool)
        .await
        .expect("read row")
    }

    for (column, cap) in PRECHECK_BLIND_CAPS {
        let f = fixture(&pool).await;
        hold_at_cap(&pool, &f, column).await;
        let exec = failed_row(&pool, &f).await;
        let before = refusals(cap);
        match repo
            .mark_execution_running(exec)
            .await
            .expect("retry reset")
        {
            RetryReset::BudgetRefused(r) => assert_eq!(r.cap.as_str(), cap),
            other => panic!("retry of an actor at its {cap} cap was not refused: {other:?}"),
        }
        assert_eq!(
            status_and_age(&pool, exec).await,
            ("failed".to_string(), true),
            "{cap}: a refused retry must not reset the row"
        );
        assert!(
            refusals(cap) - before >= 1.0,
            "{cap}: the refusal is counted"
        );
    }

    let f = fixture(&pool).await;
    let exec = failed_row(&pool, &f).await;
    assert_eq!(
        repo.mark_execution_running(exec).await.unwrap(),
        RetryReset::Reset
    );
    assert_eq!(
        status_and_age(&pool, exec).await,
        ("running".to_string(), false),
        "control: no policy, the retry resets the row"
    );
    assert_eq!(
        repo.mark_execution_running(exec).await.unwrap(),
        RetryReset::AlreadyRunning,
        "a second retry of a running row still reports the concurrent winner (MCP-693)"
    );
}

/// `enqueue_workflow`'s batch twin had no in-transaction budget check. It now
/// refuses the WHOLE batch at a cap, writes nothing, and says so in
/// `budget_refused` — and for the count caps it is batch-aware: with a
/// per-hour cap of 3 and one run already in the hour, a batch of 3 is refused
/// (1 + 3 > 3) while a batch of 2 is admitted (1 + 2 = 3).
#[tokio::test]
async fn the_enqueue_batch_is_refused_whole_and_counts_the_batch() {
    use talos_workflow_repository::WorkflowRepository;
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = WorkflowRepository::new(pool.clone());

    for (column, cap) in PRECHECK_BLIND_CAPS {
        let f = fixture(&pool).await;
        hold_at_cap(&pool, &f, column).await;
        let ids = [Uuid::new_v4(), Uuid::new_v4()];
        let a = repo
            .create_executions_batch_under_concurrency_limit(
                &ids,
                f.wf,
                f.user,
                None,
                Some(f.actor),
            )
            .await
            .expect("batch admission");
        assert_eq!(a.inserted, 0, "{cap}: nothing admitted");
        assert_eq!(
            a.budget_refused.as_ref().map(|r| r.cap.as_str()),
            Some(cap),
            "{cap}: the refusal names the cap"
        );
        for id in ids {
            assert_eq!(row_actor(&pool, id).await, None, "{cap}: no row written");
        }
    }

    // Batch-awareness on a count cap.
    let f = fixture(&pool).await;
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, status, started_at, actor_id) \
         VALUES ($1, $2, $3, 'completed', NOW(), $4)",
    )
    .bind(Uuid::new_v4())
    .bind(f.wf)
    .bind(f.user)
    .bind(f.actor)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO actor_budget_policies (actor_id, max_executions_per_hour, on_budget_exceeded) \
         VALUES ($1, 3, 'block')",
    )
    .bind(f.actor)
    .execute(&pool)
    .await
    .unwrap();
    let three = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
    let a = repo
        .create_executions_batch_under_concurrency_limit(&three, f.wf, f.user, None, Some(f.actor))
        .await
        .unwrap();
    assert_eq!(
        a.inserted, 0,
        "1 in the hour + a batch of 3 exceeds a cap of 3"
    );
    assert_eq!(
        a.budget_refused
            .as_ref()
            .map(|r| (r.cap.as_str(), r.limit, r.used)),
        Some(("per_hour", 3, 1))
    );
    let two = [Uuid::new_v4(), Uuid::new_v4()];
    let a = repo
        .create_executions_batch_under_concurrency_limit(&two, f.wf, f.user, None, Some(f.actor))
        .await
        .unwrap();
    assert_eq!(a.budget_refused, None, "1 + 2 = 3 fits a cap of 3");
    assert_eq!(a.inserted, 2);
}

/// TEXTUAL pins, stated as such, for the start paths no test here can drive
/// end to end: the chain dispatcher (needs NATS and a module-bound trigger),
/// the continuation trigger's choice of actor, and the two MCP test handlers'
/// choice of actor. Each proves the call is SPELLED so — a bypass written
/// differently passes it.
#[test]
fn the_undriven_start_paths_name_the_shared_check() {
    let chains = include_str!("../../talos-engine/src/workflow_chains.rs");
    assert!(
        chains.contains("talos_actor_budget_refusal::admit_actor_budget(&mut tx, aid)"),
        "chain dispatch no longer runs the shared budget check"
    );
    assert!(
        chains.find("chain_dispatch_denied_by_budget\",\n                    %workflow_id,\n                    actor_id = %aid")
            .is_some(),
        "chain dispatch no longer refuses on the shared check's answer"
    );
    let continuation = include_str!("../../talos-continuation-trigger/src/lib.rs");
    assert!(
        continuation.contains("            effective_actor_id,\n            &trigger_payload,"),
        "the continuation row must carry the gate-resolved actor"
    );
    let mcp = include_str!("../../talos-mcp-handlers/src/workflows.rs");
    assert!(
        mcp.contains("test_actor_arg.or(test_wf_record.actor_id),"),
        "MCP test_workflow must record the actor its engine runs as"
    );
    assert!(
        mcp.contains("let draft_row_actor = draft_actor_arg.or(wf_agent_id);"),
        "MCP test_workflow_draft must record the actor its engine runs as"
    );
}
