//! RLS on the three tenant-content tables a SCOPED transaction reads and, until
//! migration `20260912130000`, nothing guarded: `workflow_versions`,
//! `execution_approvals`, `actor_action_log`.
//!
//! The policies derive the tenant from the PARENT row (`workflows` / `actors`),
//! whose own policy applies inside the subquery under `talos_app`, because the
//! tables' own `org_id` columns were added in May and never written (NULL on
//! every row of the reference database), so the sibling `org_id IS NULL →
//! permit` template would admit everything. Each isolation test below drives a
//! PRODUCTION scoped reader whose statement carries no owner predicate
//! (`list_versions_on_conn`: `WHERE workflow_id = $1`; `list_action_log_scoped`:
//! `WHERE actor_id = $1`) — on pristine main those return the other tenant's
//! rows under `talos_app`, so the tests fail by assertion there. Every isolation
//! test has an owner CONTROL beside it: a policy of `USING (false)` must not pass.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use sqlx::Executor as _;
use talos_actor_repository::ActorRepository;
use talos_workflow_versions::WorkflowVersionService;
use uuid::Uuid;

struct Seeded {
    user: Uuid,
    workflow: Uuid,
    actor: Uuid,
    version: Uuid,
    approval: Uuid,
    action: Uuid,
}

async fn seed_tenant(pool: &sqlx::PgPool) -> Seeded {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@rls-scoped.test"))
    .execute(pool)
    .await
    .expect("seed user");
    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("rlsorg-{tag}"))
    .bind(format!("rlsorg-{tag}"))
    .bind(user)
    .fetch_one(pool)
    .await
    .expect("seed org");
    let workflow = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, org_id, name, module_uri, graph_json) VALUES ($1, $2, $3, $4, 'test://none', '{}'::jsonb)",
    )
    .bind(workflow)
    .bind(user)
    .bind(org)
    .bind(format!("rlswf-{tag}"))
    .execute(pool)
    .await
    .expect("seed workflow");
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, org_id) VALUES ($1, $2, $3, $4)")
        .bind(actor)
        .bind(user)
        .bind(format!("rlsactor-{tag}"))
        .bind(org)
        .execute(pool)
        .await
        .expect("seed actor");
    let version: Uuid = sqlx::query_scalar(
        "INSERT INTO workflow_versions (workflow_id, version_number, graph_json, published_by) VALUES ($1, 1, '{}'::jsonb, $2) RETURNING id",
    )
    .bind(workflow)
    .bind(user)
    .fetch_one(pool)
    .await
    .expect("seed version");
    let approval: Uuid = sqlx::query_scalar(
        "INSERT INTO execution_approvals (workflow_id, execution_id, node_id, status) VALUES ($1, gen_random_uuid(), gen_random_uuid(), 'pending') RETURNING id",
    )
    .bind(workflow)
    .fetch_one(pool)
    .await
    .expect("seed approval");
    let action: Uuid = sqlx::query_scalar(
        "INSERT INTO actor_action_log (actor_id, action_type, summary) VALUES ($1, 'rls-probe', 'probe') RETURNING id",
    )
    .bind(actor)
    .fetch_one(pool)
    .await
    .expect("seed action log");
    Seeded {
        user,
        workflow,
        actor,
        version,
        approval,
        action,
    }
}

/// The one-round-trip prologue `talos_db::begin_tenant_read_scoped` issues when
/// `TALOS_RLS_SET_ROLE` is on. Simple-query protocol, several commands.
async fn as_user(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, user: Uuid) {
    (&mut **tx)
        .execute(
            format!(
                "SET LOCAL ROLE talos_app; SET LOCAL app.current_user_id = '{user}'; SET LOCAL app.current_org_ids = ''"
            )
            .as_str(),
        )
        .await
        .expect("set role + GUCs");
}

async fn count(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, sql: &str, id: Uuid) -> i64 {
    sqlx::query_scalar(sql)
        .bind(id)
        .fetch_one(&mut **tx)
        .await
        .expect("count")
}

const TABLES: [(&str, &str); 3] = [
    ("workflow_versions", "workflow_versions_tenant_isolation"),
    (
        "execution_approvals",
        "execution_approvals_tenant_isolation",
    ),
    ("actor_action_log", "actor_action_log_tenant_isolation"),
];

#[tokio::test]
async fn the_three_tables_are_rls_enabled_forced_and_policied() {
    let (pool, _db) = common::isolated_db_pool().await;
    for (table, policy) in TABLES {
        let (enabled, forced): (bool, bool) = sqlx::query_as(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = $1::regclass",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(enabled && forced, "{table}: RLS must be ENABLED and FORCED");
        let present: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_policy WHERE polname = $1)")
                .bind(policy)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(present, "{policy} must exist");
    }
}

/// The scoped readers whose statements carry NO owner predicate must return
/// nothing for another tenant's parent id under `talos_app`. Fails by assertion
/// on pristine main (each returns 1).
#[tokio::test]
async fn another_tenants_rows_are_invisible_through_the_scoped_readers() {
    let (pool, _db) = common::isolated_db_pool().await;
    let a = seed_tenant(&pool).await;
    let b = seed_tenant(&pool).await;
    let repo = ActorRepository::new(pool.clone());

    let mut tx = pool.begin().await.unwrap();
    as_user(&mut tx, a.user).await;
    let versions = WorkflowVersionService::list_versions_on_conn(&mut tx, b.workflow, 50, 0)
        .await
        .expect("list versions");
    assert_eq!(
        versions.len(),
        0,
        "user A must not list user B's workflow versions"
    );
    let actions = repo
        .list_action_log_scoped(&mut tx, b.actor, 50)
        .await
        .expect("list action log");
    assert_eq!(
        actions.len(),
        0,
        "user A must not list user B's actor action log"
    );
    let approvals = count(
        &mut tx,
        "SELECT COUNT(*) FROM execution_approvals WHERE id = $1",
        b.approval,
    )
    .await;
    assert_eq!(
        approvals, 0,
        "user A must not see user B's execution approval"
    );
    tx.commit().await.unwrap();
}

/// CONTROL: the owner still reads their own rows through the same readers.
#[tokio::test]
async fn the_owner_still_reads_their_own_rows_under_rls() {
    let (pool, _db) = common::isolated_db_pool().await;
    let a = seed_tenant(&pool).await;
    let repo = ActorRepository::new(pool.clone());

    let mut tx = pool.begin().await.unwrap();
    as_user(&mut tx, a.user).await;
    let versions = WorkflowVersionService::list_versions_on_conn(&mut tx, a.workflow, 50, 0)
        .await
        .expect("list versions");
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].id, a.version);
    let actions = repo
        .list_action_log_scoped(&mut tx, a.actor, 50)
        .await
        .expect("list action log");
    assert_eq!(actions.len(), 1);
    let approvals = count(
        &mut tx,
        "SELECT COUNT(*) FROM execution_approvals WHERE id = $1",
        a.approval,
    )
    .await;
    assert_eq!(approvals, 1);
    let actions_raw = count(
        &mut tx,
        "SELECT COUNT(*) FROM actor_action_log WHERE id = $1",
        a.action,
    )
    .await;
    assert_eq!(actions_raw, 1);
    tx.commit().await.unwrap();
}

/// The transition clause: the scoped role with NO tenant GUC (the posture an
/// un-wired path would have) is permitted everything, matching every sibling
/// policy. A `USING (EXISTS ...)` without the clause would fail here.
#[tokio::test]
async fn the_scoped_role_without_a_tenant_guc_is_permitted_everything() {
    let (pool, _db) = common::isolated_db_pool().await;
    let a = seed_tenant(&pool).await;
    let b = seed_tenant(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    (&mut *tx)
        .execute("SET LOCAL ROLE talos_app")
        .await
        .unwrap();
    for (sql, ids) in [
        (
            "SELECT COUNT(*) FROM workflow_versions WHERE id = ANY($1)",
            [a.version, b.version],
        ),
        (
            "SELECT COUNT(*) FROM execution_approvals WHERE id = ANY($1)",
            [a.approval, b.approval],
        ),
        (
            "SELECT COUNT(*) FROM actor_action_log WHERE id = ANY($1)",
            [a.action, b.action],
        ),
    ] {
        let n: i64 = sqlx::query_scalar(sql)
            .bind(ids.to_vec())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(n, 2, "{sql}: unset GUC must permit both tenants' rows");
    }
    tx.commit().await.unwrap();
}

/// WITH CHECK: a scoped write may land a row under the writer's own workflow and
/// is refused (42501) under another tenant's.
#[tokio::test]
async fn a_scoped_write_is_bound_to_a_visible_parent() {
    let (pool, _db) = common::isolated_db_pool().await;
    let a = seed_tenant(&pool).await;
    let b = seed_tenant(&pool).await;

    let mut tx = pool.begin().await.unwrap();
    as_user(&mut tx, a.user).await;
    sqlx::query("INSERT INTO workflow_versions (workflow_id, version_number, graph_json, published_by) VALUES ($1, 2, '{}'::jsonb, $2)")
        .bind(a.workflow)
        .bind(a.user)
        .execute(&mut *tx)
        .await
        .expect("the owner publishes a version of their own workflow");
    let err = sqlx::query("INSERT INTO workflow_versions (workflow_id, version_number, graph_json, published_by) VALUES ($1, 2, '{}'::jsonb, $2)")
        .bind(b.workflow)
        .bind(a.user)
        .execute(&mut *tx)
        .await
        .expect_err("a version under another tenant's workflow must be refused");
    let code = err
        .as_database_error()
        .and_then(|e| e.code().map(|c| c.to_string()));
    assert_eq!(
        code.as_deref(),
        Some("42501"),
        "expected an RLS WITH CHECK refusal, got {err}"
    );
    tx.rollback().await.unwrap();
}
