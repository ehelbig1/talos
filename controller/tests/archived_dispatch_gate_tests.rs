//! "Archived" must mean "will not run" — the NARROW dispatch gate.
//!
//! `workflows.status` and `workflows.is_enabled` are two columns for one fact
//! with two independent writers, and neither writer touches the other's column.
//! Measured on the reference fleet 2026-09-07: all 8 archived rows still read
//! `is_enabled = true`. Package 21 proved with a scratch row that NO execution
//! path filtered on `status`; this binary is the guard for the gate that closed
//! it.
//!
//! **The decision is NARROW and these tests pin its edges as hard as its
//! centre.** `status = 'archived'` is refused. A DRAFT still dispatches — four
//! drafts on the reference fleet carry enabled schedules and fire today — and
//! `is_enabled` keeps whatever meaning each path already gave it. So every test
//! comes in a TRIO: archived refused, active admitted, draft admitted. A test
//! that only proved "the archived one is refused" would pass just as well on a
//! tree where the gate had been widened to `status = 'active'`, which is the
//! change the operator explicitly did not authorise.
//!
//! These are DB tests on the `common` harness (each gets a template clone of
//! the migrated DB), so they belong in CTRL_TESTS, not TC_TESTS (sub-leg 64b).

mod common;

use sqlx::{Pool, Postgres};
use talos_workflow_engine_core::{GraphLookup, WorkflowGraphStore};
use talos_workflow_repository::{
    ConcurrencyAdmission, InitialExecutionStatus, WorkflowDispatchLookup, WorkflowRepository,
};
use uuid::Uuid;

const EMPTY_GRAPH: &str = r#"{"nodes":[],"edges":[]}"#;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'gate test')",
    )
    .bind(id)
    .bind(format!("archived-gate-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

/// Seed a workflow with an explicit `(status, is_enabled)` PAIR — the whole
/// point is that the two axes are set independently, exactly as the two
/// production writers set them. `is_enabled` is `true` on every row here,
/// including the archived one, because that is the shape the live fleet has.
async fn seed_workflow(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    name: &str,
    status: &str,
    capabilities: &[&str],
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows \
         (id, user_id, name, graph_json, module_uri, status, is_enabled, capabilities) \
         VALUES ($1, $2, $3, $4, 'talos://t', $5, true, $6)",
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .bind(EMPTY_GRAPH)
    .bind(status)
    .bind(
        &capabilities
            .iter()
            .map(|c| (*c).to_string())
            .collect::<Vec<_>>(),
    )
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

/// `workflow_executions.actor_id` is NOT NULL, so the CONTROL half of the
/// admission tests needs a real actor. This is not incidental plumbing: an
/// earlier draft passed `None` and the archived case "passed" while BOTH
/// controls died on the NOT NULL constraint — i.e. the refusal would have been
/// indistinguishable from a broken INSERT, which is the exact way the #754
/// write-ceiling test once survived its own gate being deleted.
async fn seed_actor(pool: &Pool<Postgres>, user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(id)
        .bind(user_id)
        .bind(format!("gate-actor-{id}"))
        .execute(pool)
        .await
        .expect("seed actor");
    id
}

async fn execution_rows(pool: &Pool<Postgres>, wf: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM workflow_executions WHERE workflow_id = $1")
        .bind(wf)
        .fetch_one(pool)
        .await
        .expect("count executions")
}

// ───────────────────── the by-id chokepoint ─────────────────────

/// `dispatch_lifecycle` is the read `retry`, `replay` and the continuation
/// trigger gate on. THREE-valued: a retired workflow must not read as absent,
/// because "not found or access denied" is false on both clauses for a row
/// `list_workflows` happily returns.
///
/// MUTATION that turns this red: fold `Retired` into `Absent`.
#[tokio::test]
async fn dispatch_lifecycle_is_three_valued_and_a_draft_still_dispatches() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = WorkflowRepository::new(pool.clone());

    let retired = seed_workflow(&pool, user, "retired", "archived", &[]).await;
    let active = seed_workflow(&pool, user, "live", "active", &[]).await;
    let draft = seed_workflow(&pool, user, "shaped-draft", "draft", &[]).await;

    assert_eq!(
        repo.dispatch_lifecycle(retired, user).await.unwrap(),
        WorkflowDispatchLookup::Retired,
        "an archived workflow must be REFUSED, not reported absent"
    );
    // THE CONTROLS. Without them a gate widened to `status = 'active'` — the
    // change that was explicitly not authorised — would pass this file.
    assert_eq!(
        repo.dispatch_lifecycle(active, user).await.unwrap(),
        WorkflowDispatchLookup::Dispatchable
    );
    assert_eq!(
        repo.dispatch_lifecycle(draft, user).await.unwrap(),
        WorkflowDispatchLookup::Dispatchable,
        "a DRAFT still dispatches — 4 drafts on the reference fleet carry \
         enabled schedules and fire today"
    );
    // Absent stays absent, and a foreign user's workflow reads absent too.
    assert_eq!(
        repo.dispatch_lifecycle(Uuid::new_v4(), user).await.unwrap(),
        WorkflowDispatchLookup::Absent
    );
    assert_eq!(
        repo.dispatch_lifecycle(active, Uuid::new_v4())
            .await
            .unwrap(),
        WorkflowDispatchLookup::Absent
    );
}

/// The narrow gate must NOT have quietly become `is_dispatchable` (which also
/// requires `is_enabled`). A paused-but-not-archived workflow is still
/// dispatchable as far as THIS gate is concerned; whether it runs is the other
/// column's business, enforced (or deliberately not) by each path exactly as
/// before.
///
/// MUTATION that turns this red: swap `is_not_retired` for `is_dispatchable`
/// inside `dispatch_lifecycle`.
#[tokio::test]
async fn the_gate_does_not_reach_the_pause_toggle() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = WorkflowRepository::new(pool.clone());

    let paused = seed_workflow(&pool, user, "paused", "active", &[]).await;
    sqlx::query("UPDATE workflows SET is_enabled = false WHERE id = $1")
        .bind(paused)
        .execute(&pool)
        .await
        .unwrap();

    assert_eq!(
        repo.dispatch_lifecycle(paused, user).await.unwrap(),
        WorkflowDispatchLookup::Dispatchable,
        "the NARROW gate is archived-only; widening it to is_enabled would \
         stop four live draft schedules and every path that has never \
         consulted that column"
    );
}

// ───────── the admission backstop: seven surfaces, one read ─────────

/// `create_execution_under_concurrency_limit` is the row-minting chokepoint for
/// the scheduler, the webhook router, `trigger_workflow`, `call_workflow`,
/// `bulk_trigger_workflow` and `trigger_workflow_as_actors`. The gate rides on
/// the `FOR UPDATE` read it already issued, so it costs no query and is atomic
/// with the INSERT it guards.
///
/// Asserts on ROWS, not just on the returned variant — an earlier version of
/// the #754 write-ceiling test passed because the INSERT would have failed
/// anyway, and it survived the gate being deleted.
#[tokio::test]
async fn the_admission_gate_writes_no_row_for_an_archived_workflow() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = WorkflowRepository::new(pool.clone());

    let actor = seed_actor(&pool, user).await;
    let retired = seed_workflow(&pool, user, "retired", "archived", &[]).await;
    let active = seed_workflow(&pool, user, "live", "active", &[]).await;
    let draft = seed_workflow(&pool, user, "draft", "draft", &[]).await;

    let admit = |wf: Uuid| {
        let repo = repo.clone();
        async move {
            repo.create_execution_under_concurrency_limit(
                Uuid::new_v4(),
                wf,
                user,
                None,
                None,
                Some(actor),
                None,
                None,
                None,
                InitialExecutionStatus::Running,
            )
            .await
            .expect("admission query")
        }
    };

    assert!(matches!(
        admit(retired).await,
        ConcurrencyAdmission::WorkflowArchived
    ));
    assert_eq!(
        execution_rows(&pool, retired).await,
        0,
        "a refused admission must leave NO execution row — the variant alone \
         would pass even if the transaction had committed"
    );

    // THE CONTROLS: both non-archived shapes are admitted and DO write a row.
    assert!(matches!(admit(active).await, ConcurrencyAdmission::Created));
    assert_eq!(execution_rows(&pool, active).await, 1);
    assert!(matches!(admit(draft).await, ConcurrencyAdmission::Created));
    assert_eq!(execution_rows(&pool, draft).await, 1);
}

/// `enqueue_workflow`'s batch twin. `inserted == 0` already refuses; the
/// `archived` flag is what lets the caller say WHY instead of reporting a
/// retired workflow as one whose concurrency cap is full.
#[tokio::test]
async fn the_batch_admission_gate_names_the_reason() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = WorkflowRepository::new(pool.clone());

    let actor = seed_actor(&pool, user).await;
    let retired = seed_workflow(&pool, user, "retired", "archived", &[]).await;
    let active = seed_workflow(&pool, user, "live", "active", &[]).await;
    let ids: Vec<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();

    let refused = repo
        .create_executions_batch_under_concurrency_limit(&ids, retired, user, None, Some(actor))
        .await
        .expect("batch admission");
    assert!(refused.archived);
    assert_eq!(refused.inserted, 0);
    assert_eq!(execution_rows(&pool, retired).await, 0);

    // THE CONTROL.
    let ids2: Vec<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();
    let admitted = repo
        .create_executions_batch_under_concurrency_limit(&ids2, active, user, None, Some(actor))
        .await
        .expect("batch admission");
    assert!(!admitted.archived);
    assert_eq!(admitted.inserted, 3);
    assert_eq!(execution_rows(&pool, active).await, 3);
}

// ───────────── the sub-workflow / dispatch-target reads ─────────────

/// `WorkflowGraphStore::get_graph` is how every parent node — `sub_workflow`,
/// judge, ensemble, reflective-retry, `llm_dispatch`, the agent-loop body —
/// loads its child. It is CLASSIFIED rather than SQL-filtered so the parent can
/// say "archived" instead of "not found": the child plainly exists, and a node
/// that reports a deletion sends its author looking for one that never happened.
#[tokio::test]
async fn an_archived_child_is_refused_by_name_not_reported_missing() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = WorkflowRepository::new(pool.clone());

    let retired = seed_workflow(&pool, user, "retired-child", "archived", &[]).await;
    let active = seed_workflow(&pool, user, "live-child", "active", &[]).await;
    let draft = seed_workflow(&pool, user, "draft-child", "draft", &[]).await;

    assert_eq!(
        repo.get_graph(retired, user).await.unwrap(),
        GraphLookup::Archived
    );
    assert_eq!(
        repo.get_graph(Uuid::new_v4(), user).await.unwrap(),
        GraphLookup::Absent,
        "a genuinely missing child must still read Absent"
    );
    // CONTROLS: a live child and a DRAFT child both still load. The draft one
    // matters — a parent dispatches a child's `graph_json` column with no
    // version join and no status predicate.
    assert!(matches!(
        repo.get_graph(active, user).await.unwrap(),
        GraphLookup::Found(_)
    ));
    assert!(matches!(
        repo.get_graph(draft, user).await.unwrap(),
        GraphLookup::Found(_)
    ));

    // The batch prefetch that warms the sub-workflow cache excludes the
    // archived child, so a cache HIT is always dispatchable and the refusal is
    // reported exactly once — by `get_graph`, on the miss.
    let batch = repo
        .get_graphs(&[retired, active, draft], user)
        .await
        .unwrap();
    assert!(!batch.contains_key(&retired));
    assert!(batch.contains_key(&active));
    assert!(batch.contains_key(&draft));
}

/// `resolve_by_capabilities` is the ONE site in this change that is not latent
/// on the reference fleet: all 8 archived rows there carry non-empty
/// `capabilities` (`email-delivery`, `sub-workflow`, `world-http`, …), and this
/// resolver is `ORDER BY updated_at DESC LIMIT 1` — so a retired workflow was
/// not merely a candidate, it could be the WINNING one.
///
/// Filtered in SQL rather than classified, and the ordering is why: a retired
/// candidate must not shadow a live one, which a read-then-refuse would do.
/// This test seeds the retired row LAST so it is the newer `updated_at` and
/// would win on a pre-fix tree.
#[tokio::test]
async fn a_retired_capability_match_does_not_shadow_a_live_one() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = WorkflowRepository::new(pool.clone());

    let live = seed_workflow(&pool, user, "live-sender", "active", &["email-delivery"]).await;
    let retired = seed_workflow(
        &pool,
        user,
        "retired-sender",
        "archived",
        &["email-delivery"],
    )
    .await;
    // Make the retired one unambiguously the most recent, i.e. the winner of
    // `ORDER BY updated_at DESC, id DESC` before the gate existed.
    sqlx::query("UPDATE workflows SET updated_at = NOW() + INTERVAL '1 hour' WHERE id = $1")
        .bind(retired)
        .execute(&pool)
        .await
        .unwrap();

    let got = repo
        .resolve_by_capabilities(&["email-delivery".to_string()], user)
        .await
        .unwrap();
    assert_eq!(
        got.map(|(id, _)| id),
        Some(live),
        "the live workflow must win even though the retired one is newer"
    );

    // And when the ONLY match is retired, the resolver answers nothing rather
    // than handing a parent node a workflow the platform will not run.
    let only_retired = seed_workflow(&pool, user, "retired-only", "archived", &["nudge-crm"]).await;
    let _ = only_retired;
    assert_eq!(
        repo.resolve_by_capabilities(&["nudge-crm".to_string()], user)
            .await
            .unwrap(),
        None
    );
}

/// `resolve_by_name` backs name-target `DynamicDispatch`. Same rule, same
/// reason, and the same control.
#[tokio::test]
async fn a_retired_workflow_is_not_a_name_dispatch_target() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = WorkflowRepository::new(pool.clone());

    let retired = seed_workflow(&pool, user, "retired-target", "archived", &[]).await;
    let draft = seed_workflow(&pool, user, "draft-target", "draft", &[]).await;
    let _ = retired;

    assert_eq!(
        repo.resolve_by_name("retired-target", user).await.unwrap(),
        None
    );
    // CONTROL: a draft target still resolves.
    assert_eq!(
        repo.resolve_by_name("draft-target", user).await.unwrap(),
        Some(draft)
    );
}

// ───────────────────────── the handoff path ─────────────────────────

/// `handoff_to_actor` REFUSED an archived workflow long before this gate
/// existed — it was the only dispatch surface that did, and
/// `talos-workflow-liveness`' own module doc claimed otherwise. The refusal was
/// right and the REPORT was not: the SQL filtered `status != 'archived'`, so
/// the caller saw `None` and rendered "Workflow not found or access denied",
/// false on both clauses.
///
/// The read now returns the status so the caller can classify it. The
/// wording is pinned in `handoff.rs`'s own unit tests; what a DB test can
/// prove is that the row COMES BACK instead of being filtered away.
#[tokio::test]
async fn the_handoff_read_reports_the_lifecycle_instead_of_hiding_the_row() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = talos_actor_repository::ActorRepository::new(pool.clone());

    let retired = seed_workflow(&pool, user, "retired", "archived", &[]).await;
    let active = seed_workflow(&pool, user, "live", "active", &[]).await;

    let (graph, status) = repo
        .get_workflow_graph_and_status_for_user(retired, user)
        .await
        .unwrap()
        .expect("an archived workflow is VISIBLE — it must not read as absent");
    assert_eq!(status, "archived");
    assert!(!graph.is_empty());
    assert!(!talos_workflow_liveness::is_not_retired(&status));

    // CONTROLS: the live row still comes back, and a genuinely absent one is
    // still absent.
    let (_, live_status) = repo
        .get_workflow_graph_and_status_for_user(active, user)
        .await
        .unwrap()
        .expect("live workflow");
    assert!(talos_workflow_liveness::is_not_retired(&live_status));
    assert!(repo
        .get_workflow_graph_and_status_for_user(Uuid::new_v4(), user)
        .await
        .unwrap()
        .is_none());
}
