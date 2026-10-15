//! The row-security backstop on `actor_memory` and the five integration tables
//! a scoped reader now reads (migration `20261015100000`, security review
//! 2026-10-14, D-1).
//!
//! `actor_memory` had a policy before this one, keyed on the ORG GUC: a
//! `begin_user_scoped` transaction sets `app.current_org_ids` to the empty
//! string, which that policy read as "unset → permit", so a user-scoped read
//! saw EVERY tenant's memory rows. The isolation test below drives the
//! production scoped reader `talos_memory::list_memories_with_ciphertext_scoped`
//! (`WHERE actor_id = $1`, no owner predicate); on the pre-migration policy it
//! returns the other tenant's row. Every isolation check has an owner control
//! beside it, so a policy of `USING (false)` does not pass.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use sqlx::Executor as _;
use uuid::Uuid;

const TABLES: [&str; 6] = [
    "actor_memory",
    "plaid_items",
    "google_health_integrations",
    "microsoft_365_integrations",
    "google_calendar_write_integrations",
    "google_cloud_integrations",
];

async fn seed_user(pool: &sqlx::PgPool) -> (Uuid, Uuid) {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@rls-backstop.test"))
    .execute(pool)
    .await
    .expect("seed user");
    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) \
         VALUES ($1, $1, $2, true) RETURNING id",
    )
    .bind(format!("rlsb-{tag}"))
    .bind(user)
    .fetch_one(pool)
    .await
    .expect("seed org");
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, org_id) VALUES ($1, $2, $3, $4)")
        .bind(actor)
        .bind(user)
        .bind(format!("rlsb-actor-{tag}"))
        .bind(org)
        .execute(pool)
        .await
        .expect("seed actor");
    (user, actor)
}

/// The prologue `talos_db::begin_user_scoped` issues when `TALOS_RLS_SET_ROLE`
/// is on: the app role, the user, an EMPTY org list.
async fn as_user(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, user: Uuid) {
    (&mut **tx)
        .execute(sqlx::AssertSqlSafe(format!(
            "SET LOCAL ROLE talos_app; SET LOCAL app.current_user_id = '{user}'; \
             SET LOCAL app.current_org_ids = ''"
        )))
        .await
        .expect("set role + GUCs");
}

#[tokio::test]
async fn the_six_tables_are_rls_enabled_forced_and_policied() {
    let (pool, _db) = common::isolated_db_pool().await;
    for table in TABLES {
        let (enabled, forced): (bool, bool) = sqlx::query_as(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class \
             WHERE relname = $1 AND relnamespace = 'public'::regnamespace",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .expect("pg_class");
        assert!(
            enabled && forced,
            "{table}: enabled={enabled} forced={forced}"
        );
        let policy: Option<String> = sqlx::query_scalar(
            "SELECT policyname::text FROM pg_policies WHERE tablename = $1 \
             AND policyname = $1 || '_tenant_isolation'",
        )
        .bind(table)
        .fetch_optional(&pool)
        .await
        .expect("pg_policies");
        assert!(policy.is_some(), "{table}: no tenant policy");
    }
}

/// Another tenant's memory row is invisible to a user-scoped read, an
/// org-less row included; the owner still reads theirs.
#[tokio::test]
async fn a_user_scoped_memory_read_sees_only_the_users_own_actors() {
    let (pool, _db) = common::isolated_db_pool().await;
    let secrets = controller::secrets::SecretsManager::new(pool.clone()).expect("secrets");
    secrets.initialize().await.expect("active DEK");
    let key_id: Uuid = sqlx::query_scalar("SELECT id FROM encryption_keys LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("a DEK");
    let (owner, owner_actor) = seed_user(&pool).await;
    let (stranger, _) = seed_user(&pool).await;
    for (key, org_less) in [("rls/with-org", false), ("rls/org-less", true)] {
        sqlx::query(
            "INSERT INTO actor_memory (actor_id, key, value_enc, value_key_id, org_id) \
             SELECT $1, $2, '\\x00'::bytea, $3, CASE WHEN $4 THEN NULL ELSE a.org_id END \
             FROM actors a WHERE a.id = $1",
        )
        .bind(owner_actor)
        .bind(key)
        .bind(key_id)
        .bind(org_less)
        .execute(&pool)
        .await
        .expect("seed memory");
    }

    let read = |user: Uuid| {
        let pool = pool.clone();
        async move {
            let mut tx = pool.begin().await.expect("tx");
            as_user(&mut tx, user).await;
            let rows =
                talos_memory::list_memories_with_ciphertext_scoped(&mut tx, owner_actor, None, 50)
                    .await
                    .expect("scoped read");
            tx.rollback().await.expect("rollback");
            rows.len()
        }
    };
    assert_eq!(
        read(stranger).await,
        0,
        "another tenant's memory is invisible"
    );
    assert_eq!(read(owner).await, 2, "control: the owner reads both rows");

    // A scoped write naming another tenant's actor is refused.
    let mut tx = pool.begin().await.expect("tx");
    as_user(&mut tx, stranger).await;
    let write = sqlx::query(
        "INSERT INTO actor_memory (actor_id, key, value_enc, value_key_id) \
         VALUES ($1, 'rls/planted', '\\x00'::bytea, $2)",
    )
    .bind(owner_actor)
    .bind(key_id)
    .execute(&mut *tx)
    .await;
    assert!(write.is_err(), "WITH CHECK refuses another tenant's actor");
}

/// Each integration table: another user's row is invisible and cannot be
/// written in the user's scope; the owner's row is visible to the owner.
#[tokio::test]
async fn an_integration_row_is_its_users_alone_in_a_scoped_transaction() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (owner, _) = seed_user(&pool).await;
    let (stranger, _) = seed_user(&pool).await;
    let seeds: [(&str, &str); 5] = [
        (
            "plaid_items",
            "INSERT INTO plaid_items (user_id, item_id, environment) \
             VALUES ($1, 'item-rls', 'sandbox') RETURNING id",
        ),
        (
            "google_health_integrations",
            "INSERT INTO google_health_integrations (user_id, provider_key) \
             VALUES ($1, gen_random_uuid()) RETURNING id",
        ),
        (
            "microsoft_365_integrations",
            "INSERT INTO microsoft_365_integrations (user_id, provider_key) \
             VALUES ($1, 'rls-key') RETURNING id",
        ),
        (
            "google_calendar_write_integrations",
            "INSERT INTO google_calendar_write_integrations (user_id, provider_key) \
             VALUES ($1, gen_random_uuid()) RETURNING id",
        ),
        (
            "google_cloud_integrations",
            "INSERT INTO google_cloud_integrations (user_id, provider_key) \
             VALUES ($1, gen_random_uuid()) RETURNING id",
        ),
    ];
    for (table, insert) in seeds {
        let id: Uuid = sqlx::query_scalar(sqlx::AssertSqlSafe(insert))
            .bind(owner)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("seed {table}: {e}"));
        let count = format!("SELECT count(*) FROM {table} WHERE id = $1");
        for (user, want) in [(stranger, 0_i64), (owner, 1)] {
            let mut tx = pool.begin().await.expect("tx");
            as_user(&mut tx, user).await;
            let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(count.as_str()))
                .bind(id)
                .fetch_one(&mut *tx)
                .await
                .expect("count");
            tx.rollback().await.expect("rollback");
            assert_eq!(
                n,
                want,
                "{table}: as {}",
                if want == 0 { "stranger" } else { "owner" }
            );
        }
        // The stranger cannot plant a row for the owner in their own scope.
        let mut tx = pool.begin().await.expect("tx");
        as_user(&mut tx, stranger).await;
        let planted = sqlx::query_scalar::<_, Uuid>(sqlx::AssertSqlSafe(insert))
            .bind(owner)
            .fetch_one(&mut *tx)
            .await;
        assert!(
            planted.is_err(),
            "{table}: WITH CHECK refuses another user's row"
        );
    }
}

/// The production readers moved into the user's scope still answer the
/// owner (a scope with the wrong GUC would return nothing).
#[tokio::test]
async fn the_scoped_connection_listing_still_lists_the_owners_connections() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (owner, _) = seed_user(&pool).await;
    sqlx::query(
        "INSERT INTO plaid_items (user_id, item_id, environment, institution_name) \
         VALUES ($1, 'item-list', 'sandbox', 'Example Bank')",
    )
    .bind(owner)
    .execute(&pool)
    .await
    .expect("seed plaid item");
    let rows = talos_integrations::store::list_user_connections(&pool, owner)
        .await
        .expect("listing");
    assert!(
        rows.iter().any(|r| r.provider_id == "plaid"),
        "the owner's Plaid connection is listed: {rows:?}"
    );
}
