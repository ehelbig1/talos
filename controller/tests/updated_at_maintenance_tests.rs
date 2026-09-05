//! `updated_at` must date a USER EDIT, not a maintenance write.
//!
//! Migration `20260905120000_updated_at_is_not_a_maintenance_clock` replaced the
//! bump-on-any-change trigger with one that ignores each table's declared
//! MAINTENANCE columns. These tests drive the REAL trigger with the REAL
//! statements the background jobs issue.
//!
//! Every test comes in a pair — a maintenance write that must NOT move the
//! column, and a content write that MUST. The negative half alone would pass on
//! a table whose trigger had simply been dropped, which is the failure mode a
//! negative assertion cannot see on its own.
//!
//! These are DB tests on the `common` harness (each gets a template clone of the
//! migrated DB), so they belong in CTRL_TESTS, not TC_TESTS.

mod common;

use chrono::{DateTime, Utc};
use sqlx::{Pool, Postgres, Row};
use uuid::Uuid;

async fn updated_at_of(pool: &Pool<Postgres>, table: &str, id: Uuid) -> DateTime<Utc> {
    let sql = format!("SELECT updated_at FROM {table} WHERE id = $1");
    sqlx::query(&sql)
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("read {table}.updated_at: {e}"))
        .try_get::<DateTime<Utc>, _>("updated_at")
        .expect("updated_at is readable")
}

/// Force `updated_at` to a known, distant instant so a bump is unambiguous.
/// Written directly (the trigger leaves an explicitly-supplied value alone
/// when nothing else changed, which is itself part of the contract).
async fn pin_updated_at(pool: &Pool<Postgres>, table: &str, id: Uuid) -> DateTime<Utc> {
    let sql = format!("UPDATE {table} SET updated_at = '2020-01-01T00:00:00Z' WHERE id = $1");
    sqlx::query(&sql).bind(id).execute(pool).await.unwrap();
    updated_at_of(pool, table, id).await
}

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'test user')",
    )
    .bind(id)
    .bind(format!("updated-at-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_workflow(pool: &Pool<Postgres>, user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status) \
         VALUES ($1, $2, 'updated-at probe', '{\"nodes\":[],\"edges\":[]}', 'talos://t', 'draft')",
    )
    .bind(id)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

// ───────────────────────── workflows: the reported defect ─────────────────────

/// F1 REPRODUCTION. The exact statement `controller/src/bootstrap/background.rs`
/// issues every hour (and at every boot) for every workflow.
///
/// Pre-fix this FAILS: the trigger stamped `updated_at` on any column change, so
/// all 36 workflows on the dev fleet carried `updated_at == readiness_computed_at`
/// to the microsecond. The column recorded the recompute clock, not an edit.
#[tokio::test]
async fn a_readiness_recompute_does_not_date_a_workflow() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let wf = seed_workflow(&pool, user).await;
    let before = pin_updated_at(&pool, "workflows", wf).await;

    // Verbatim from background.rs's readiness recomputation loop.
    sqlx::query(
        "UPDATE workflows SET readiness_score = $1, readiness_computed_at = NOW() WHERE id = $2",
    )
    .bind(77_i32)
    .bind(wf)
    .execute(&pool)
    .await
    .expect("readiness recompute");

    let after = updated_at_of(&pool, "workflows", wf).await;
    assert_eq!(
        before, after,
        "the hourly readiness recompute re-dated the workflow as though a user had edited it"
    );

    // …and it really did write the score, so the test is not passing because the
    // UPDATE silently matched nothing.
    let score: i32 = sqlx::query("SELECT readiness_score FROM workflows WHERE id = $1")
        .bind(wf)
        .fetch_one(&pool)
        .await
        .unwrap()
        .try_get("readiness_score")
        .unwrap();
    assert_eq!(score, 77, "the recompute must still have written the score");
}

/// POSITIVE CONTROL for the test above. Without this, dropping the trigger
/// entirely would make `a_readiness_recompute_does_not_date_a_workflow` pass.
#[tokio::test]
async fn a_graph_save_does_date_a_workflow() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let wf = seed_workflow(&pool, user).await;
    let before = pin_updated_at(&pool, "workflows", wf).await;

    sqlx::query("UPDATE workflows SET graph_json = $1 WHERE id = $2")
        .bind(r#"{"nodes":[{"id":"n1"}],"edges":[]}"#)
        .bind(wf)
        .execute(&pool)
        .await
        .expect("graph save");

    let after = updated_at_of(&pool, "workflows", wf).await;
    assert!(
        after > before,
        "a graph save is a user edit and must move updated_at (before={before}, after={after})"
    );
}

/// The other two `workflows` maintenance writers: the embedding backfill and the
/// search-vector rebuild. Both are derived from content that already stamped the
/// row on its own edit.
#[tokio::test]
async fn workflow_embedding_and_search_text_writes_do_not_date_a_workflow() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let wf = seed_workflow(&pool, user).await;
    let before = pin_updated_at(&pool, "workflows", wf).await;

    // Read the declared dimension rather than hardcoding one — the column is
    // vector(N) and a mismatch fails the INSERT, not the property under test.
    // pgvector stores the dimension in atttypmod directly (no VARHDRSZ offset,
    // unlike varchar), so there is nothing to subtract.
    let dims: i32 = sqlx::query(
        "SELECT atttypmod AS dims FROM pg_attribute \
          WHERE attrelid = 'workflows'::regclass AND attname = 'embedding'",
    )
    .fetch_one(&pool)
    .await
    .unwrap()
    .try_get("dims")
    .unwrap();
    let emb = format!("[{}]", vec!["0.1"; dims as usize].join(","));
    sqlx::query("UPDATE workflows SET embedding = $1::vector WHERE id = $2 AND user_id = $3")
        .bind(&emb)
        .bind(wf)
        .bind(user)
        .execute(&pool)
        .await
        .expect("embedding write");
    assert_eq!(
        before,
        updated_at_of(&pool, "workflows", wf).await,
        "an embedding backfill re-dated the workflow"
    );

    sqlx::query("UPDATE workflows SET search_text = to_tsvector('english', $1) WHERE id = $2")
        .bind("probe text")
        .bind(wf)
        .execute(&pool)
        .await
        .expect("search_text write");
    assert_eq!(
        before,
        updated_at_of(&pool, "workflows", wf).await,
        "a search-vector rebuild re-dated the workflow"
    );
}

// ───────────────────────── modules: the boot seeder ───────────────────────────

async fn seed_module(pool: &Pool<Postgres>, user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, kind, description, source_code) \
         VALUES ($1, $2, $3, 'catalog', 'probe', 'fn run() {}')",
    )
    .bind(id)
    .bind(user_id)
    .bind(format!("probe-{id}"))
    .execute(pool)
    .await
    .expect("seed module");
    id
}

/// 75 of 112 `modules` rows on the dev fleet shared one second — the catalog
/// seeder rewrites every catalog row at every controller boot with the SAME
/// values. An idempotent rewrite is not an edit.
#[tokio::test]
async fn an_idempotent_catalog_reseed_does_not_date_a_module() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let m = seed_module(&pool, user).await;
    let before = pin_updated_at(&pool, "modules", m).await;

    // The seeder's shape: rewrite content columns with identical values.
    for _ in 0..3 {
        sqlx::query("UPDATE modules SET description = $2, source_code = $3 WHERE id = $1")
            .bind(m)
            .bind("probe")
            .bind("fn run() {}")
            .execute(&pool)
            .await
            .expect("reseed");
    }

    assert_eq!(
        before,
        updated_at_of(&pool, "modules", m).await,
        "re-seeding identical catalog content re-dated the module at every boot"
    );
}

/// THE TRIGGER CANNOT SAVE A STATEMENT THAT STAMPS THE COLUMN ITSELF.
///
/// A BEFORE UPDATE trigger decides whether to OVERWRITE `updated_at`; it can
/// never revert a value the statement supplied. So `SET …, updated_at = NOW()`
/// re-dates the row no matter what the trigger concludes — which is why the fix
/// for the catalog seeder had to be in the STATEMENTS (check 83), not only in
/// the trigger.
///
/// This test exists because its sibling above did NOT catch that.
/// `an_idempotent_catalog_reseed_does_not_date_a_module` exercises
/// `UPDATE modules SET description=…, source_code=…` — a shape the seeder does
/// not issue. The seeder issues an upsert carrying an explicit
/// `updated_at = NOW()`, so the test was green while 75 of 112 module rows went
/// on being re-dated at every boot. Asserting the OVERRIDE (rather than
/// asserting it away) keeps the reason the statement fix is load-bearing
/// visible: if someone deletes the check-82 lint, this test still documents why
/// it existed.
#[tokio::test]
async fn an_explicit_stamp_overrides_the_trigger() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let m = seed_module(&pool, user).await;
    let before = pin_updated_at(&pool, "modules", m).await;

    // Identical content — the trigger correctly concludes "not an edit"…
    sqlx::query(
        "UPDATE modules SET description = 'probe', source_code = 'fn run() {}' WHERE id = $1",
    )
    .bind(m)
    .execute(&pool)
    .await
    .expect("reseed without an explicit stamp");
    assert_eq!(
        before,
        updated_at_of(&pool, "modules", m).await,
        "control: without an explicit stamp the trigger leaves an unchanged row alone"
    );

    // …and the identical write WITH an explicit stamp re-dates it anyway.
    sqlx::query(
        "UPDATE modules SET description = 'probe', source_code = 'fn run() {}', \
         updated_at = NOW() WHERE id = $1",
    )
    .bind(m)
    .execute(&pool)
    .await
    .expect("reseed with an explicit stamp");
    assert!(
        updated_at_of(&pool, "modules", m).await > before,
        "a statement that writes updated_at itself is NOT subject to the trigger's \
         verdict — if this ever stops being true, check 83 and the six statement \
         fixes it guards are dead weight and should be reconsidered, not deleted \
         silently"
    );
}

/// Compile outputs and usage telemetry are declared maintenance columns.
#[tokio::test]
async fn module_compile_output_and_usage_do_not_date_a_module() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let m = seed_module(&pool, user).await;
    let before = pin_updated_at(&pool, "modules", m).await;

    sqlx::query(
        "UPDATE modules SET wasm_bytes = $1, size_bytes = LENGTH($1)::INTEGER, \
         compiled_at = NOW() WHERE id = $2",
    )
    .bind(vec![0u8, 1, 2, 3])
    .bind(m)
    .execute(&pool)
    .await
    .expect("precompile store");
    assert_eq!(
        before,
        updated_at_of(&pool, "modules", m).await,
        "an AOT precompile re-dated the module"
    );

    sqlx::query(
        "UPDATE modules SET usage_count = usage_count + 1, last_used_at = NOW() WHERE id = $1",
    )
    .bind(m)
    .execute(&pool)
    .await
    .expect("usage telemetry");
    assert_eq!(
        before,
        updated_at_of(&pool, "modules", m).await,
        "usage telemetry re-dated the module"
    );
}

/// POSITIVE CONTROL for both module tests.
#[tokio::test]
async fn a_source_change_does_date_a_module() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let m = seed_module(&pool, user).await;
    let before = pin_updated_at(&pool, "modules", m).await;

    sqlx::query("UPDATE modules SET source_code = $2 WHERE id = $1")
        .bind(m)
        .bind("fn run() { /* actually different */ }")
        .execute(&pool)
        .await
        .expect("source edit");

    assert!(
        updated_at_of(&pool, "modules", m).await > before,
        "editing a module's source is a user edit and must move updated_at"
    );
}

// ───────────────────────── secrets: the hottest maintenance write ─────────────

/// `last_accessed_at`/`access_count` are written on EVERY module secret read.
/// Pre-fix, reading a secret dated it as though it had been rotated.
#[tokio::test]
async fn reading_a_secret_does_not_date_it_but_rotating_it_does() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let key_id = Uuid::new_v4();
    sqlx::query("INSERT INTO encryption_keys (id, encrypted_key) VALUES ($1, '\\x00'::bytea)")
        .bind(key_id)
        .execute(&pool)
        .await
        .expect("seed encryption key");

    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO secrets (id, name, key_path, encrypted_value, encryption_key_id, user_id, owner_user_id) \
         VALUES ($1, 'probe', $2, '\\x00'::bytea, $3, $4, $4)",
    )
    .bind(id)
    .bind(format!("probe/{id}"))
    .bind(key_id)
    .bind(user)
    .execute(&pool)
    .await
    .expect("seed secret");

    let before = pin_updated_at(&pool, "secrets", id).await;

    // Verbatim from SecretsManager's bulk module-secret read.
    sqlx::query("UPDATE secrets SET last_accessed_at = NOW(), access_count = access_count + 1 WHERE id = ANY($1)")
        .bind(vec![id])
        .execute(&pool)
        .await
        .expect("access telemetry");
    assert_eq!(
        before,
        updated_at_of(&pool, "secrets", id).await,
        "reading a secret dated it as though the value had been rotated"
    );

    // POSITIVE CONTROL: rotating the value is a real change.
    sqlx::query("UPDATE secrets SET encrypted_value = '\\x01'::bytea WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("rotate");
    assert!(
        updated_at_of(&pool, "secrets", id).await > before,
        "rotating a secret's value must move updated_at"
    );
}

// ───────────────────────── users: login telemetry ─────────────────────────────

#[tokio::test]
async fn logging_in_does_not_date_a_user_but_a_password_change_does() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let before = pin_updated_at(&pool, "users", user).await;

    // Verbatim from AuthService's successful-login path.
    sqlx::query("UPDATE users SET last_login_at = NOW(), failed_login_attempts = 0, locked_until = NULL WHERE id = $1")
        .bind(user)
        .execute(&pool)
        .await
        .expect("login stamp");
    assert_eq!(
        before,
        updated_at_of(&pool, "users", user).await,
        "signing in re-dated the user account as though it had been edited"
    );

    // …and the failed-login counter, which also drives lockout.
    sqlx::query("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = $1")
        .bind(user)
        .execute(&pool)
        .await
        .expect("failed-login stamp");
    assert_eq!(
        before,
        updated_at_of(&pool, "users", user).await,
        "a failed login re-dated the user account"
    );

    // POSITIVE CONTROL.
    sqlx::query("UPDATE users SET password_hash = 'changed' WHERE id = $1")
        .bind(user)
        .execute(&pool)
        .await
        .expect("password change");
    assert!(
        updated_at_of(&pool, "users", user).await > before,
        "changing a password must move updated_at"
    );
}

// ───────────────────────── webhook_triggers + mcp_agents ──────────────────────

#[tokio::test]
async fn firing_a_webhook_does_not_date_it_but_renaming_it_does() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO webhook_triggers (id, name, verification_token, user_id) VALUES ($1, 'probe', $2, $3)",
    )
    .bind(id)
    .bind(format!("tok-{id}"))
    .bind(user)
    .execute(&pool)
    .await
    .expect("seed webhook trigger");

    let before = pin_updated_at(&pool, "webhook_triggers", id).await;

    sqlx::query(
        "UPDATE webhook_triggers SET last_triggered_at = NOW(), trigger_count = trigger_count + 1, \
         success_count = success_count + 1 WHERE id = $1",
    )
    .bind(id)
    .execute(&pool)
    .await
    .expect("fire stats");
    assert_eq!(
        before,
        updated_at_of(&pool, "webhook_triggers", id).await,
        "receiving a webhook re-dated the trigger's configuration"
    );

    sqlx::query("UPDATE webhook_triggers SET name = 'renamed' WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("rename");
    assert!(
        updated_at_of(&pool, "webhook_triggers", id).await > before,
        "renaming a webhook trigger must move updated_at"
    );
}

#[tokio::test]
async fn an_agent_heartbeat_does_not_date_it_but_deactivating_it_does() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let role = Uuid::new_v4();
    sqlx::query("INSERT INTO agent_roles (id, name) VALUES ($1, $2)")
        .bind(role)
        .bind(format!("probe-role-{role}"))
        .execute(&pool)
        .await
        .expect("seed agent role");

    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO mcp_agents (id, name, role_id, token_hash, user_id) VALUES ($1, 'probe', $2, 'h', $3)",
    )
    .bind(id)
    .bind(role)
    .bind(user)
    .execute(&pool)
    .await
    .expect("seed mcp agent");

    let before = pin_updated_at(&pool, "mcp_agents", id).await;

    sqlx::query("UPDATE mcp_agents SET last_connected_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("heartbeat");
    assert_eq!(
        before,
        updated_at_of(&pool, "mcp_agents", id).await,
        "an agent connection heartbeat re-dated the agent record"
    );

    sqlx::query("UPDATE mcp_agents SET is_active = false WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("deactivate");
    assert!(
        updated_at_of(&pool, "mcp_agents", id).await > before,
        "deactivating an agent must move updated_at"
    );
}

// ───────────────────────── the declarations themselves ────────────────────────

/// A declared maintenance column that does not exist silently disables the guard
/// for that column — the quiet re-corruption this whole change exists to end. The
/// migration refuses to install such a declaration; this re-checks it against the
/// live catalog on every CI run, so the guard outlives the migration that
/// installed it (a renamed column would otherwise re-open the hole).
#[tokio::test]
async fn updated_at_declarations_name_real_columns() {
    let (pool, _db) = common::isolated_db_pool().await;

    // Two separate facts, asserted separately and in order, because collapsing
    // them produces a misleading failure. A zero-argument trigger yields
    // `string_to_array('', …) = {}`, so `unnest` returns NO rows for it — an
    // empty declaration set is therefore indistinguishable from a missing
    // FUNCTION if you only count the unnested rows. Against a tree without this
    // migration that reported "the shared implementation is gone" about eight
    // triggers that were all present and all using it.
    let trigger_count: i64 = sqlx::query(
        "SELECT count(*) AS n FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid \
          WHERE p.proname = 'update_updated_at_column' AND NOT t.tgisinternal",
    )
    .fetch_one(&pool)
    .await
    .expect("count triggers using the shared function")
    .try_get("n")
    .expect("count is readable");
    assert!(
        trigger_count > 0,
        "no trigger uses update_updated_at_column — the shared implementation is gone"
    );

    let rows = sqlx::query(
        "SELECT tgrelid::regclass::text AS tbl, tgname, unnest(tgargs_text) AS col \
           FROM ( \
             SELECT t.tgrelid, t.tgname, \
                    string_to_array(encode(t.tgargs, 'escape'), '\\000') AS tgargs_text \
               FROM pg_trigger t \
               JOIN pg_proc p ON p.oid = t.tgfoid \
              WHERE p.proname = 'update_updated_at_column' AND NOT t.tgisinternal \
           ) s",
    )
    .fetch_all(&pool)
    .await
    .expect("read trigger declarations");

    assert!(
        !rows.is_empty(),
        "{trigger_count} trigger(s) use update_updated_at_column but NONE declares a \
         maintenance column. Every maintenance write on those tables is being read as a \
         user edit — which is the defect migration 20260905120000 exists to fix."
    );

    let mut checked = 0usize;
    for r in &rows {
        let table: String = r.try_get("tbl").unwrap();
        let col: String = r.try_get("col").unwrap();
        if col.is_empty() {
            continue; // trailing element of the NUL-separated tgargs blob
        }
        let exists: bool = sqlx::query(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
              WHERE table_schema='public' AND table_name=$1 AND column_name=$2)",
        )
        .bind(table.replace("public.", ""))
        .bind(&col)
        .fetch_one(&pool)
        .await
        .unwrap()
        .try_get("exists")
        .unwrap();
        assert!(
            exists,
            "trigger on {table} declares maintenance column '{col}', which does not exist — \
             that declaration matches nothing and silently re-opens the maintenance-clock hole"
        );
        assert_ne!(
            col, "updated_at",
            "trigger on {table} declares updated_at itself; the function already ignores it"
        );
        checked += 1;
    }

    assert!(
        checked > 0,
        "no maintenance columns were checked — the declarations were not readable, so this \
         test proved nothing"
    );
}

/// An UNDECLARED table (empty `TG_ARGV`) must behave exactly as it did before
/// this migration: any real column change bumps. `agent_roles` has no
/// maintenance writer today and declares no maintenance columns, so it is the
/// control for "the deny-list defaults to empty, and empty means bump".
///
/// Without this, a bug that made `COALESCE(TG_ARGV, …)` swallow everything
/// would leave every negative assertion above passing and every table silently
/// frozen.
#[tokio::test]
async fn an_undeclared_table_still_bumps_on_any_change() {
    let (pool, _db) = common::isolated_db_pool().await;
    let role = Uuid::new_v4();
    sqlx::query("INSERT INTO agent_roles (id, name) VALUES ($1, $2)")
        .bind(role)
        .bind(format!("probe-role-{role}"))
        .execute(&pool)
        .await
        .expect("seed agent role");
    let before = pin_updated_at(&pool, "agent_roles", role).await;

    sqlx::query("UPDATE agent_roles SET description = 'changed' WHERE id = $1")
        .bind(role)
        .execute(&pool)
        .await
        .expect("edit role");

    assert!(
        updated_at_of(&pool, "agent_roles", role).await > before,
        "a table declaring NO maintenance columns must bump on any change — an \
         empty deny-list means 'everything is content', not 'nothing is'"
    );
}

/// The ONE behaviour change that is not about a declared column: a statement
/// that rewrites a row with byte-identical values no longer bumps. That is the
/// catalog seeder's shape (75 of 112 module rows shared one boot second), and
/// it holds even on a table with an empty declaration.
#[tokio::test]
async fn rewriting_identical_values_is_not_an_edit() {
    let (pool, _db) = common::isolated_db_pool().await;
    let role = Uuid::new_v4();
    sqlx::query("INSERT INTO agent_roles (id, name, description) VALUES ($1, $2, 'same')")
        .bind(role)
        .bind(format!("probe-role-{role}"))
        .execute(&pool)
        .await
        .expect("seed agent role");
    let before = pin_updated_at(&pool, "agent_roles", role).await;

    sqlx::query("UPDATE agent_roles SET description = 'same' WHERE id = $1")
        .bind(role)
        .execute(&pool)
        .await
        .expect("idempotent rewrite");

    assert_eq!(
        before,
        updated_at_of(&pool, "agent_roles", role).await,
        "rewriting a row with the values it already had is not an edit"
    );
}

/// The fast path (`OLD IS NOT DISTINCT FROM NEW`) needs a usable `=` for every
/// column type on every table carrying the trigger. A future column of a type
/// with no equality operator (`json`, `xml`, `point`) would raise on EVERY
/// UPDATE of that table. That is loud rather than silent — but it should be
/// loud HERE, in CI, and not the first time someone saves a workflow.
///
/// The table set is DERIVED from `pg_trigger`, not listed, so a table that
/// starts carrying the trigger later is covered without anyone remembering to
/// add it (the hand-maintained-list rot mode).
#[tokio::test]
async fn every_table_carrying_the_trigger_supports_record_comparison() {
    let (pool, _db) = common::isolated_db_pool().await;

    let tables: Vec<String> = sqlx::query(
        "SELECT DISTINCT t.tgrelid::regclass::text AS tbl \
           FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid \
          WHERE p.proname = 'update_updated_at_column' AND NOT t.tgisinternal",
    )
    .fetch_all(&pool)
    .await
    .expect("read trigger tables")
    .iter()
    .map(|r| r.try_get::<String, _>("tbl").expect("tbl"))
    .collect();

    assert!(
        !tables.is_empty(),
        "no table carries update_updated_at_column — this test proved nothing"
    );

    for t in &tables {
        // A NULL composite still forces per-column equality-operator
        // resolution, so this probes the TYPE rather than whether the table
        // happens to hold rows.
        let sql = format!(
            "SELECT ROW(x.*) IS NOT DISTINCT FROM ROW(x.*) AS ok FROM (SELECT (NULL::{t}).*) x"
        );
        sqlx::query(&sql)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "table {t} carries update_updated_at_column but its row type cannot be \
                 compared, so the trigger's fast path will raise on every UPDATE: {e}"
                )
            });
    }
}
