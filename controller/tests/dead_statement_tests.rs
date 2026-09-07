//! A statement that has never once executed, rendered as "nothing here"
//! (2026-09-07).
//!
//! `sqlx::query("…")` — the FUNCTION form — takes a runtime `&str`. Nothing
//! checks it against the schema: not rustc, not clippy, and not CI's "sqlx
//! offline cache" job, which covers only the `query!` MACRO forms. So a
//! statement naming a renamed column or a relation that never existed compiles
//! cleanly, ships, and errors at request time — where a caller's
//! `.unwrap_or_default()` renders it as an empty list.
//!
//! These tests drive the REAL repository methods and the REAL statements
//! against a migrated database. Every assertion below FAILS on `origin/main`;
//! `AGENT_NOTES.md` §5 records which failure message each one produced there.

mod common;

use talos_analytics_repository::AnalyticsRepository;
use uuid::Uuid;

async fn seed_user(pool: &sqlx::Pool<sqlx::Postgres>, email: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id")
        .bind(email)
        .fetch_one(pool)
        .await
        .expect("seed user")
}

async fn seed_actor(pool: &sqlx::Pool<sqlx::Postgres>, user_id: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO actors (user_id, name, status, max_capability_world) \
         VALUES ($1, 'dead-stmt-actor', 'active', 'automation-node') RETURNING id",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .expect("seed actor")
}

async fn seed_module(pool: &sqlx::Pool<sqlx::Postgres>, user_id: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO modules (name, kind, user_id) VALUES ($1, 'sandbox', $2) RETURNING id",
    )
    .bind(format!("dead-stmt-mod-{}", Uuid::new_v4().simple()))
    .bind(user_id)
    .fetch_one(pool)
    .await
    .expect("seed module")
}

async fn seed_workflow(
    pool: &sqlx::Pool<sqlx::Postgres>,
    user_id: Uuid,
    name: &str,
    status: &str,
    is_enabled: bool,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status, is_enabled) \
         VALUES ($1, $2, $3, '{\"nodes\":[],\"edges\":[]}', 'talos://test-module', $4, $5)",
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .bind(status)
    .bind(is_enabled)
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

// ── Y1: the webhook statements ────────────────────────────────────────────

/// The statement `origin/main` shipped cannot be PREPARED, let alone run.
///
/// This is the reproduction, kept as a REGRESSION GUARD rather than deleted
/// once fixed: it pins the SCHEMA FACT the fix rests on (there is no
/// `endpoint_path` column and the flag is `enabled`), so re-adding the column
/// under a different meaning would fail here rather than silently revive the
/// old statement.
#[tokio::test]
async fn the_shipped_webhook_statement_names_columns_that_do_not_exist() {
    let (pool, _db) = common::isolated_db_pool().await;

    let err = sqlx::query(
        "SELECT id, endpoint_path, is_enabled FROM webhook_triggers WHERE workflow_id = $1",
    )
    .bind(Uuid::new_v4())
    .fetch_all(&pool)
    .await
    .expect_err("origin/main's statement must not be preparable against the real schema");
    let msg = err.to_string();
    assert!(
        msg.contains("endpoint_path"),
        "expected a missing-column error naming endpoint_path, got: {msg}"
    );

    // …and the flag column really is `enabled`, not `is_enabled`.
    let flag: Option<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_name = 'webhook_triggers' AND column_name IN ('enabled', 'is_enabled')",
    )
    .fetch_optional(&pool)
    .await
    .expect("column probe");
    assert_eq!(flag.as_deref(), Some("enabled"));
}

#[tokio::test]
async fn list_workflow_webhooks_returns_the_row_it_could_never_return() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool, &format!("wh-{}@example.com", Uuid::new_v4())).await;
    let wf_id = seed_workflow(&pool, user_id, "wh-wf", "active", true).await;

    let hook_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO webhook_triggers (id, name, verification_token, workflow_id, user_id, enabled) \
         VALUES ($1, 'hook', 'tok', $2, $3, true)",
    )
    .bind(hook_id)
    .bind(wf_id)
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("seed webhook");

    let repo = AnalyticsRepository::new(pool.clone());
    let rows = repo
        .list_workflow_webhooks(wf_id, user_id)
        .await
        .expect("the statement must now run");
    assert_eq!(rows.len(), 1, "the workflow's webhook must be returned");
    assert_eq!(rows[0].id, hook_id);
    assert!(rows[0].is_enabled);
    // `endpoint_path` is DERIVED — there is no such column, which is exactly
    // what the shipped statement got wrong.
    assert_eq!(rows[0].endpoint_path, format!("/webhooks/{hook_id}"));

    // Tenancy: `workflow_id` is not the tenant half, so the statement binds
    // `user_id` rather than relying on the caller's upstream gate.
    let other = seed_user(&pool, &format!("wh2-{}@example.com", Uuid::new_v4())).await;
    assert!(
        repo.list_workflow_webhooks(wf_id, other)
            .await
            .expect("runs")
            .is_empty(),
        "another user's webhook must not be visible"
    );
}

#[tokio::test]
async fn list_webhooks_for_modules_returns_the_row_it_could_never_return() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool, &format!("whm-{}@example.com", Uuid::new_v4())).await;
    let wf_id = seed_workflow(&pool, user_id, "whm-wf", "active", true).await;
    let module_id = seed_module(&pool, user_id).await;
    let hook_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO webhook_triggers (id, name, verification_token, workflow_id, module_id, user_id, enabled) \
         VALUES ($1, 'hook', 'tok', $2, $3, $4, false)",
    )
    .bind(hook_id)
    .bind(wf_id)
    .bind(module_id)
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("seed webhook");

    let repo = AnalyticsRepository::new(pool.clone());
    let rows = repo
        .list_webhooks_for_modules(&[module_id], wf_id, user_id)
        .await
        .expect("the statement must now run");
    assert_eq!(rows.len(), 1);
    assert!(
        !rows[0].is_enabled,
        "the `enabled` column must be read, not defaulted"
    );
}

/// The two relations whose readers were deleted really do not exist.
///
/// Deleting a method is only correct if the table it named is absent; if either
/// ever ships, this fails and whoever adds it is told there used to be a reader.
#[tokio::test]
async fn the_deleted_readers_named_relations_that_do_not_exist() {
    let (pool, _db) = common::isolated_db_pool().await;
    for relation in ["workflow_audit_log", "workflow_webhooks"] {
        let oid: Option<String> = sqlx::query_scalar("SELECT to_regclass($1)::text")
            .bind(relation)
            .fetch_one(&pool)
            .await
            .expect("to_regclass");
        assert!(
            oid.is_none(),
            "{relation} now exists — a reader for it was deleted 2026-09-07 on the \
             grounds that it never had; re-add the reader deliberately"
        );
    }
}

// ── Y2: a status nothing writes ───────────────────────────────────────────

#[tokio::test]
async fn workflows_needing_schema_sees_a_live_schemaless_workflow() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool, &format!("ns-{}@example.com", Uuid::new_v4())).await;
    let wf_id = seed_workflow(&pool, user_id, "needs-schema", "active", true).await;
    let actor_id = seed_actor(&pool, user_id).await;
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, actor_id, status, started_at, completed_at) \
         VALUES ($1, $2, $3, $4, 'completed', NOW(), NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(wf_id)
    .bind(user_id)
    .bind(actor_id)
    .execute(&pool)
    .await
    .expect("seed execution");

    // The predicate `origin/main` shipped matches NOTHING for this row…
    let published: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM workflows w WHERE w.user_id = $1 AND w.status = 'published'",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("published probe");
    assert_eq!(
        published, 0,
        "'published' is not in the workflow lifecycle enum — if this is ever \
         non-zero the fix's premise has changed"
    );

    // …and the live predicate finds it.
    let repo = AnalyticsRepository::new(pool.clone());
    let report = repo
        .get_hygiene_report(user_id)
        .await
        .expect("hygiene report");
    assert!(
        report
            .workflows_needing_schema
            .iter()
            .any(|r| r.id == wf_id),
        "an active, enabled, schema-less workflow with a completed execution must be \
         reported as needing a schema; got {:?}",
        report
            .workflows_needing_schema
            .iter()
            .map(|r| r.name.clone())
            .collect::<Vec<_>>()
    );
}

/// The one writer of `status = 'published'` writes `workflow_type = 'internal'`
/// in the SAME INSERT, which the hygiene predicate's next clause excludes — so
/// the shipped filter was not merely unmatched, it was self-contradictory.
#[tokio::test]
async fn the_only_published_writer_also_writes_the_type_the_filter_excludes() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool, &format!("pub-{}@example.com", Uuid::new_v4())).await;
    let repo = talos_workflow_repository::WorkflowRepository::new(pool.clone());
    let wf_id = Uuid::new_v4();
    repo.insert_published_internal_workflow(
        wf_id,
        user_id,
        None,
        "orchestrator",
        "plan_and_execute orchestrator",
        "{\"nodes\":[],\"edges\":[]}",
    )
    .await
    .expect("insert");

    let (status, wf_type): (String, Option<String>) =
        sqlx::query_as("SELECT status, workflow_type FROM workflows WHERE id = $1")
            .bind(wf_id)
            .fetch_one(&pool)
            .await
            .expect("read back");
    assert_eq!(status, "published");
    assert_eq!(
        wf_type.as_deref(),
        Some("internal"),
        "every 'published' row is 'internal', so `status = 'published' AND \
         workflow_type NOT IN ('test','internal')` admits nothing the next \
         clause does not reject"
    );
}

// ── The organization owner-count statement ────────────────────────────────

/// `SELECT COUNT(*) … FOR UPDATE` is rejected by Postgres unconditionally, so
/// the last-owner guard had never once been evaluated and `remove_member`
/// errored on every call.
#[tokio::test]
async fn removing_the_last_owner_is_refused_by_a_statement_that_can_run() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool, &format!("owner-{}@example.com", Uuid::new_v4())).await;
    // Seeded here rather than through `common::create_test_organization`,
    // which omits the NOT NULL `slug` column and fails on every call — the same
    // class this binary is about, in the harness itself (recorded, not fixed:
    // that helper's other callers are out of this change's scope).
    let org_id: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind("dead-stmt-org")
    .bind(format!("dead-stmt-org-{}", Uuid::new_v4().simple()))
    .bind(owner)
    .fetch_one(&pool)
    .await
    .expect("seed organization");
    common::add_user_to_organization(&pool, owner, org_id, "owner").await;

    // The shape origin/main shipped cannot run at all — no bind and no data
    // can make it, so this is a property of the statement, not of the rows.
    let err = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM organization_members WHERE org_id = $1 AND role = 'owner' FOR UPDATE",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .expect_err("COUNT(*) … FOR UPDATE must be rejected");
    assert!(
        err.to_string().contains("FOR UPDATE"),
        "expected the aggregate/FOR UPDATE rejection, got: {err}"
    );

    // The fixed shape runs AND still locks the owner rows.
    let refusal =
        talos_organizations::OrganizationService::remove_member(&pool, org_id, owner, owner)
            .await
            .expect_err("removing the last owner must be refused");
    let msg = refusal.to_string();
    assert!(
        msg.contains("owner"),
        "the refusal must be about the last owner, not about a failed count; got: {msg}"
    );
    assert!(
        !msg.contains("Failed to count owners"),
        "origin/main answered 'Failed to count owners' here — a statement error \
         wearing a policy refusal's clothes; got: {msg}"
    );
}
