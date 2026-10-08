// ci-store: migrated — scripts/test-integration.sh runs this with that store (scripts/ci_test_targets.py)
//! What the role `query_paginated` runs as holds, on the migrated schema
//! (`migrations/20261008200000_talos_admin_read_role.sql`):
//!
//! * no privilege of any kind on a table `BLOCKED_TABLES_LIST` withholds;
//! * SELECT on every other table and view in `public`, and nothing but
//!   SELECT — so a migration that adds a table fails here until it either
//!   grants the table to the role or withholds it by name;
//! * the attributes it is entered for (BYPASSRLS, never superuser) and none
//!   it could escalate with.
//!
//! The migrated store is one database the store's binaries run against in
//! turn; a binary that creates a probe table in `public` and fails before
//! dropping it (`talos-db/tests/rls_org_isolation.rs` creates three) leaves a
//! relation this test then names as undecided. The message says which.
//!
//! Gated on `TALOS_TEST_DATABASE_URL` pointing at a MIGRATED database.
//! ```sh
//! scripts/dev-test-db.sh run sh -c \
//!   'TALOS_TEST_DATABASE_URL=$DATABASE_URL cargo test -p talos-advanced-repository --test admin_read_role_grants'
//! ```

use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use talos_admin_query_gate::BLOCKED_TABLES_LIST;
use talos_advanced_repository::QUERY_PAGINATED_ROLE;

async fn pool() -> Option<Pool<Postgres>> {
    let url = match std::env::var("TALOS_TEST_DATABASE_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            eprintln!("SKIP: set TALOS_TEST_DATABASE_URL (migrated) to run admin_read_role_grants");
            return None;
        }
    };
    Some(
        PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("connect"),
    )
}

/// Every relation in `public` a caller could name: tables, partitioned
/// tables, views, materialized views, foreign tables — not the ones an
/// extension owns (`pg_stat_statements`, which the parsed gate refuses by its
/// `pg_` name).
const PUBLIC_RELATIONS: &str = "SELECT c.relname::text FROM pg_catalog.pg_class c \
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
     WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f') \
       AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d \
                       WHERE d.classid = 'pg_catalog.pg_class'::regclass \
                         AND d.objid = c.oid AND d.deptype = 'e') \
     ORDER BY 1";

async fn privilege(pool: &Pool<Postgres>, relation: &str, privileges: &str) -> bool {
    sqlx::query_scalar("SELECT has_table_privilege($1, format('public.%I', $2), $3)")
        .bind(QUERY_PAGINATED_ROLE)
        .bind(relation)
        .bind(privileges)
        .fetch_one(pool)
        .await
        .expect("has_table_privilege")
}

async fn any_column_privilege(pool: &Pool<Postgres>, relation: &str) -> bool {
    sqlx::query_scalar(
        "SELECT has_any_column_privilege($1, format('public.%I', $2), \
         'SELECT, INSERT, UPDATE, REFERENCES')",
    )
    .bind(QUERY_PAGINATED_ROLE)
    .bind(relation)
    .fetch_one(pool)
    .await
    .expect("has_any_column_privilege")
}

/// The decision the migration records, per relation: granted SELECT, or
/// withheld by name and holding nothing at all.
#[tokio::test]
async fn every_public_relation_is_granted_to_the_role_or_withheld() {
    let Some(pool) = pool().await else { return };
    let relations: Vec<String> = sqlx::query_scalar(PUBLIC_RELATIONS)
        .fetch_all(&pool)
        .await
        .expect("relations");
    assert!(relations.len() > 50, "only {} relations", relations.len());

    let mut undecided = Vec::new();
    let mut withheld_but_readable = Vec::new();
    let mut more_than_select = Vec::new();
    for r in &relations {
        let withheld = BLOCKED_TABLES_LIST.contains(&r.as_str());
        if withheld {
            if privilege(
                &pool,
                r,
                "SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER",
            )
            .await
                || any_column_privilege(&pool, r).await
            {
                withheld_but_readable.push(r.clone());
            }
        } else if !privilege(&pool, r, "SELECT").await {
            undecided.push(r.clone());
        }
        if privilege(
            &pool,
            r,
            "INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER",
        )
        .await
        {
            more_than_select.push(r.clone());
        }
    }
    assert!(
        withheld_but_readable.is_empty(),
        "{QUERY_PAGINATED_ROLE} holds a privilege on a table BLOCKED_TABLES_LIST withholds: \
         {withheld_but_readable:?}"
    );
    assert!(
        undecided.is_empty(),
        "relations in public that are neither granted to {QUERY_PAGINATED_ROLE} nor withheld by \
         BLOCKED_TABLES_LIST (talos-admin-query-gate): {undecided:?}. In the migration that adds \
         the table, `GRANT SELECT ON public.<t> TO {QUERY_PAGINATED_ROLE};` — or withhold it by \
         name."
    );
    assert!(
        more_than_select.is_empty(),
        "{QUERY_PAGINATED_ROLE} holds more than SELECT on: {more_than_select:?}"
    );
}

/// No default privileges (a future table is unreadable until granted), no
/// sequence, and no role it could become.
#[tokio::test]
async fn the_role_gets_nothing_by_default_and_belongs_to_nothing() {
    let Some(pool) = pool().await else { return };
    let defaults: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_catalog.pg_default_acl d, \
         LATERAL aclexplode(d.defaclacl) a \
         WHERE a.grantee = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1)",
    )
    .bind(QUERY_PAGINATED_ROLE)
    .fetch_one(&pool)
    .await
    .expect("default acl");
    assert_eq!(defaults, 0, "{QUERY_PAGINATED_ROLE} has default privileges");

    let sequences: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_catalog.pg_class c \
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') \
           AND CASE WHEN c.relkind = 'S' \
                    THEN has_sequence_privilege($1, c.oid, 'USAGE, SELECT, UPDATE') \
                    ELSE false END",
    )
    .bind(QUERY_PAGINATED_ROLE)
    .fetch_one(&pool)
    .await
    .expect("sequences");
    assert_eq!(sequences, 0, "{QUERY_PAGINATED_ROLE} may use a sequence");

    let memberships: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_catalog.pg_auth_members m \
         JOIN pg_catalog.pg_roles r ON r.oid = m.member WHERE r.rolname = $1",
    )
    .bind(QUERY_PAGINATED_ROLE)
    .fetch_one(&pool)
    .await
    .expect("memberships");
    assert_eq!(
        memberships, 0,
        "{QUERY_PAGINATED_ROLE} is a member of a role"
    );
}

#[tokio::test]
async fn the_role_has_the_attributes_it_is_entered_for() {
    let Some(pool) = pool().await else { return };
    let (login, superuser, inherit, create_role, create_db, bypass_rls): (
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
    ) = sqlx::query_as(
        "SELECT rolcanlogin, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolbypassrls \
         FROM pg_catalog.pg_roles WHERE rolname = $1",
    )
    .bind(QUERY_PAGINATED_ROLE)
    .fetch_one(&pool)
    .await
    .expect("the role exists on a migrated database");
    assert!(!login && !superuser && !inherit && !create_role && !create_db);
    assert!(
        bypass_rls,
        "without BYPASSRLS a cross-tenant read under the role silently misses rows"
    );
}
