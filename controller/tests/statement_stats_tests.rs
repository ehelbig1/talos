//! "Not available" must never render as "no slow statements" (2026-09-10).
//!
//! `#786` turned `pg_stat_statements` COLLECTION on and shipped no reader.
//! `get_sql_statement_report` is the reader, and its whole difficulty is that
//! the relation it reads is OPTIONAL BY DESIGN: `shared_preload_libraries` is
//! a postmaster GUC, the Helm chart deliberately does not set it, and the
//! migration no-ops where the preload is absent. So on most deployments this
//! view does not exist, and a reader that answers "nothing slow here" there is
//! the misleading-report class (checks 74 / 76 / 79 / 81) in its quietest
//! form.
//!
//! What needs a ROUND TRIP rather than a unit test, and why:
//!
//! * **The AVAILABLE arm at all.** The crate's unit tests drive `render` over
//!   a hand-built report; nothing in them proves the SQL runs, that the column
//!   names are right, or that `pg_stat_statements` is even reachable from a
//!   `CREATE DATABASE … TEMPLATE` clone. The statements here are `sqlx::query`
//!   over a runtime `&str` in a crate that is deliberately OUTSIDE check 88's
//!   PREPARE roots (its relation is absent by design on most servers, so a
//!   gate whose premise is "this relation must exist" would go red on correct
//!   code) — which makes this binary the only thing that can say the SQL runs.
//! * **The NOT-AVAILABLE arm**, driven by DROPPING the extension in the
//!   isolated clone. This is the arm that regresses silently.
//! * **The SANITISER, end to end.** A column ALIAS is one of the three things
//!   `pg_stat_statements` does not normalise, and it is arbitrary
//!   caller-chosen text. The test plants a real ANSI escape in a real alias,
//!   runs the real statement, and reads it back through the real report.
//! * **The ADMIN GATE**, because `pg_stat_statements` has no tenancy
//!   dimension and the refusal is the whole tenancy decision.
//!
//! Every test carries its CONTROL in the same run. The database is a per-test
//! `CREATE DATABASE … TEMPLATE` clone (`common::isolated_db_pool`), so
//! dropping an extension here cannot reach any other test or the developer's
//! stack.
//!
//! **Stated limit.** The `NotLoaded` (`SQLSTATE 55000`) arm is NOT reachable
//! from here: producing it needs a postmaster with the extension installed and
//! the library absent, and this suite runs against a cluster that has the
//! preload. It was reproduced by hand in a throwaway
//! `pgvector/pgvector:pg17` container (`CREATE EXTENSION` succeeds; the first
//! read raises `55000`), and the classifier arm is pinned by unit test in
//! `talos-statement-stats`. Saying which instrument covers what matters more
//! than implying one covers both.

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use mcp_common::{agent, error_message, mcp_state};
use uuid::Uuid;

/// The MACHINE block of a `mcp_text_with_json` response — `content[1]`.
///
/// Deliberately not `mcp_common::text_json`, which reads `content[0]`: that is
/// the human summary here, and asserting on it would prove nothing about the
/// payload a tool consumer parses.
fn machine_json(resp: &controller::mcp::types::JsonRpcResponse) -> serde_json::Value {
    let text = resp
        .result
        .as_ref()
        .and_then(|r| r.pointer("/content/1/text"))
        .and_then(|t| t.as_str())
        .unwrap_or_else(|| panic!("expected a machine block, got: {resp:?}"));
    serde_json::from_str(text).expect("machine block is JSON")
}

fn summary_text(resp: &controller::mcp::types::JsonRpcResponse) -> String {
    resp.result
        .as_ref()
        .and_then(|r| r.pointer("/content/0/text"))
        .and_then(|t| t.as_str())
        .unwrap_or_else(|| panic!("expected a summary block, got: {resp:?}"))
        .to_string()
}

async fn seed_user(pool: &sqlx::PgPool, platform_admin: bool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_platform_admin, created_at, updated_at) \
         VALUES ($1, $2, 'x', $3, NOW(), NOW())",
    )
    .bind(id)
    .bind(format!("p39-{id}@example.com"))
    .bind(platform_admin)
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn report(
    state: &controller::mcp::McpState,
    user_id: Uuid,
    args: serde_json::Value,
) -> controller::mcp::types::JsonRpcResponse {
    controller::mcp::platform::dispatch(
        "get_sql_statement_report",
        Some(serde_json::json!(1)),
        &args,
        state,
        agent(user_id),
    )
    .await
    .expect("get_sql_statement_report is dispatched")
}

// ───────────────────────────────────────────────────────────────────────────
// 1. The available arm — the SQL runs, and the coverage is real.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_available_view_reports_real_statements_with_their_coverage() {
    let (pool, _db) = common::isolated_db_pool().await;
    let admin = seed_user(&pool, true).await;
    let state = mcp_state(pool.clone()).await;

    // A statement of this test's own, so the view has something to report that
    // belongs to THIS database.
    for _ in 0..3 {
        sqlx::query("SELECT count(*) FROM users WHERE email LIKE $1")
            .bind("p39-%")
            .fetch_one(&pool)
            .await
            .expect("probe statement");
    }

    let resp = report(&state, admin, serde_json::json!({})).await;
    let v = machine_json(&resp);

    assert_eq!(
        v["available"],
        serde_json::json!(true),
        "the cluster this suite runs against preloads pg_stat_statements, so the \
         view must be available: {v}"
    );
    assert!(
        v.get("reason").is_none(),
        "an available report named a reason: {v}"
    );
    let stmts = v["statements"].as_array().expect("statements array");
    assert!(
        !stmts.is_empty(),
        "the view answered but reported no statement for a database this test just \
         issued statements against: {v}"
    );
    // Coverage is what makes the numbers readable at all.
    let cov = &v["coverage"];
    assert!(
        cov["window_seconds"].as_f64().unwrap_or(-1.0) >= 0.0,
        "{cov}"
    );
    assert!(
        cov["entries_this_database"].as_i64().unwrap_or(0) > 0,
        "{cov}"
    );
    assert!(
        cov["entries_cluster"].as_i64().unwrap_or(0)
            >= cov["entries_this_database"].as_i64().unwrap_or(0),
        "the cluster count must include this database's: {cov}"
    );
    assert_eq!(cov["order_by"], serde_json::json!("total_time"));
    assert!(
        cov.get("max_entries").is_some(),
        "pg_stat_statements.max is readable on a loaded server: {cov}"
    );
    // `_info` exists from 1.9; this cluster is PG 17, so eviction is KNOWN.
    assert!(
        cov.get("entries_evicted").is_some(),
        "PG 17 has pg_stat_statements_info, so the eviction count must be measured, \
         not reported as unknown: {cov}"
    );
    assert!(v["query_text_disclosure"].as_str().is_some(), "{v}");
    assert!(
        !summary_text(&resp).contains("no statement was measured"),
        "an available report claimed nothing was measured"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 2. The arm that regresses silently — an ABSENT extension is not an empty
//    report. This is the whole reason the read is classified.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_absent_extension_is_not_reported_as_zero_slow_statements() {
    let (pool, _db) = common::isolated_db_pool().await;
    let admin = seed_user(&pool, true).await;
    let state = mcp_state(pool.clone()).await;

    // CONTROL, in the same run: with the extension present this same call
    // answers `available: true`. Without it the assertions below would pass on
    // a tree where the tool never worked at all.
    let control = machine_json(&report(&state, admin, serde_json::json!({})).await);
    assert_eq!(control["available"], serde_json::json!(true), "{control}");
    assert!(control.get("statements").is_some(), "{control}");

    sqlx::query("DROP EXTENSION pg_stat_statements")
        .execute(&pool)
        .await
        .expect("drop the extension the reader names");

    let resp = report(&state, admin, serde_json::json!({})).await;
    let v = machine_json(&resp);
    assert_eq!(v["available"], serde_json::json!(false), "{v}");
    assert_eq!(v["reason"], serde_json::json!("not_installed"), "{v}");
    // The load-bearing assertion of this whole binary: an unavailable report
    // must not carry a statement list, because an empty list is what reads as
    // "there is nothing slow here".
    assert!(
        v.get("statements").is_none(),
        "an unavailable report rendered a statement list: {v}"
    );
    assert!(v.get("coverage").is_none(), "{v}");
    let summary = summary_text(&resp);
    assert!(
        summary.contains("NOT INSTALLED") && summary.contains("no statement was measured"),
        "the prose must say nothing was measured: {summary}"
    );
    // The guest-attribution block is present even here, so an operator who
    // turns the extension on is not surprised a second time.
    assert!(v.get("guest_sql_attribution").is_some(), "{v}");
}

// ───────────────────────────────────────────────────────────────────────────
// 3. An unreadable CATALOG is a third answer — neither absent nor empty.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unreadable_database_is_neither_absent_nor_empty() {
    let (pool, _db) = common::isolated_db_pool().await;
    let admin = seed_user(&pool, true).await;

    // A pool that cannot connect: the shape a database outage takes. Built
    // lazily so construction succeeds and the FIRST query is what fails,
    // which is where the classification happens.
    let dead: sqlx::PgPool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect_lazy("postgres://talos:wrong@127.0.0.1:1/definitely_not_a_database")
        .expect("build a lazy pool");
    // The gate and the report must read the SAME pool for the test to mean
    // anything, but the ADMIN check would then fail closed and refuse before
    // the read. So the state keeps the healthy pool for identity and the read
    // is driven directly — the handler's own wiring is covered by tests 1/2/4.
    let read = talos_statement_stats::read_statement_stats(
        &dead,
        talos_statement_stats::ReadOptions::default(),
    )
    .await;
    let v =
        talos_statement_stats::render(&read, &talos_statement_stats::GuestAttribution::Unfenced);

    assert_eq!(v["available"], serde_json::json!(false), "{v}");
    assert_eq!(v["reason"], serde_json::json!("unreadable"), "{v}");
    assert_eq!(
        v["failure_class"],
        serde_json::json!("catalog_unreadable"),
        "a pool that cannot connect must classify as an unreadable CATALOG, not \
         as a missing extension: {v}"
    );
    assert!(v.get("statements").is_none(), "{v}");
    // Never the driver's message: a Postgres error can quote the statement,
    // and a statement can be caller-authored.
    let s = v.to_string();
    for leak in ["definitely_not_a_database", "wrong", "Connection refused"] {
        assert!(!s.contains(leak), "the driver error leaked '{leak}': {s}");
    }
    let _ = admin;
}

// ───────────────────────────────────────────────────────────────────────────
// 4. The tenancy decision: a non-admin is REFUSED, not narrowed.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_non_admin_is_refused_and_gets_no_statement_data() {
    let (pool, _db) = common::isolated_db_pool().await;
    let admin = seed_user(&pool, true).await;
    let plain = seed_user(&pool, false).await;
    let state = mcp_state(pool.clone()).await;

    // CONTROL: the same call as the platform admin succeeds, so the refusal
    // below is about the FLAG and not about the tool being broken.
    let ok = machine_json(&report(&state, admin, serde_json::json!({})).await);
    assert_eq!(ok["available"], serde_json::json!(true), "{ok}");

    let resp = report(&state, plain, serde_json::json!({})).await;
    let msg = error_message(&resp);
    assert!(
        msg.contains("platform-admin"),
        "the refusal must say what is required: {msg}"
    );
    assert!(
        msg.contains("no tenancy dimension"),
        "the refusal must say WHY there is no narrowed answer: {msg}"
    );
    // A refusal must carry no report at all — not even an empty one.
    let raw = serde_json::to_string(&resp).expect("serialise");
    assert!(
        !raw.contains("\\\"statements\\\"") && !raw.contains("queryid"),
        "a refused call leaked report structure: {raw}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 5. The sanitiser, END TO END through a real alias in the real view.
//
//    A column ALIAS is one of the three things `pg_stat_statements` does not
//    normalise, and it is arbitrary caller-chosen text — so this is the exact
//    channel a `database`-world module would use to plant bytes in an
//    operator's console.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_planted_ansi_escape_in_an_alias_does_not_survive_into_the_report() {
    let (pool, _db) = common::isolated_db_pool().await;
    let admin = seed_user(&pool, true).await;
    let state = mcp_state(pool.clone()).await;

    // The alias carries an ESC, an RTL override and a newline. Postgres stores
    // a double-quoted identifier verbatim.
    let alias = "p39probe\u{1b}[31m\u{202e}gnitrofni\nX";
    let sql = format!("SELECT 1 AS \"{alias}\"");
    sqlx::query(&sql)
        .fetch_one(&pool)
        .await
        .expect("plant the alias");

    let v = machine_json(&report(&state, admin, serde_json::json!({ "limit": 50 })).await);
    let stmts = v["statements"].as_array().expect("statements");
    let planted = stmts
        .iter()
        .find(|s| s["query"].as_str().is_some_and(|q| q.contains("p39probe")))
        .unwrap_or_else(|| {
            panic!("the planted statement is not in the report — the test proves nothing: {v}")
        });
    let text = planted["query"].as_str().expect("query text");

    // CONTROL: the row IS the planted one, so the assertions below are about
    // sanitisation and not about having found nothing.
    assert!(text.contains("p39probe"), "{text:?}");
    assert!(
        !text.contains('\u{1b}'),
        "ANSI escape reached the report: {text:?}"
    );
    assert!(
        !text.contains('\u{202e}'),
        "RTL override reached the report: {text:?}"
    );
    assert!(
        !text.contains('\n'),
        "a newline reached the report: {text:?}"
    );
    assert!(
        text.chars().count() <= talos_statement_stats::MAX_QUERY_TEXT_CHARS + 1,
        "the text was not truncated: {} chars",
        text.chars().count()
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 6. The closed argument set: an unrecognised ordering is REFUSED, and the
//    one the caller asked for is the one the report says it used.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_ordering_is_a_closed_set_and_the_row_cap_is_honoured() {
    let (pool, _db) = common::isolated_db_pool().await;
    let admin = seed_user(&pool, true).await;
    let state = mcp_state(pool.clone()).await;
    for i in 0..4 {
        sqlx::query(&format!("SELECT {i}, count(*) FROM users"))
            .fetch_one(&pool)
            .await
            .expect("probe");
    }

    let v = machine_json(
        &report(
            &state,
            admin,
            serde_json::json!({ "order_by": "calls", "limit": 1 }),
        )
        .await,
    );
    assert_eq!(v["coverage"]["order_by"], serde_json::json!("calls"), "{v}");
    assert_eq!(v["statements"].as_array().map(Vec::len), Some(1), "{v}");
    assert_eq!(
        v["coverage"]["truncated"],
        serde_json::json!(true),
        "one row out of many must be disclosed as truncated: {v}"
    );

    // A typo must not be read as a ranking the caller asked for.
    let bad = report(
        &state,
        admin,
        serde_json::json!({ "order_by": "total time" }),
    )
    .await;
    let msg = error_message(&bad);
    assert!(
        msg.contains("total_time") && msg.contains("mean_time"),
        "the refusal must name the accepted values: {msg}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 7. Guest attribution: on a deployment with no `TALOS_RPC_GUEST_ROLE`, the
//    report must say that a role name here is NOT provenance.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unfenced_deployment_is_told_sandbox_sql_is_indistinguishable() {
    let (pool, _db) = common::isolated_db_pool().await;
    let admin = seed_user(&pool, true).await;
    let state = mcp_state(pool.clone()).await;

    let v = machine_json(&report(&state, admin, serde_json::json!({})).await);
    let g = &v["guest_sql_attribution"];
    // This suite runs with TALOS_RPC_GUEST_ROLE unset, which is also the
    // default posture of a non-production deployment. The FENCED arm is
    // covered by unit test — `guest_role_for_query` caches in a `OnceLock`,
    // so one process cannot exercise both.
    assert_eq!(g["fenced"], serde_json::json!(false), "{g}");
    assert!(g["role"].is_null(), "{g}");
    assert!(
        g["note"]
            .as_str()
            .unwrap_or_default()
            .contains("INDISTINGUISHABLE"),
        "{g}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 8. Postgres' OWN redaction. A non-superuser without `pg_read_all_stats`
//    reads the literal string `<insufficient privilege>` in the `query`
//    column for every statement it did not issue — the migration's own header
//    names a managed-Postgres migration role as the common case, so this is
//    not exotic. A reader that renders that column blind reports a statement
//    whose text is a Postgres marker.
// ───────────────────────────────────────────────────────────────────────────

/// A pool on the SAME database whose backend runs as `talos_app`.
///
/// `talos_app` is NOLOGIN by design, so it cannot be a connection user; the
/// libpq `options=-c role=…` startup parameter makes the backend `SET role`
/// before the first statement, which is exactly the privilege posture a
/// managed-Postgres deployment has.
async fn app_role_pool(pool: &sqlx::PgPool) -> sqlx::PgPool {
    let db: (String,) = sqlx::query_as("SELECT current_database()")
        .fetch_one(pool)
        .await
        .expect("current_database");
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let (prefix, _) = base.rsplit_once('/').expect("a database in DATABASE_URL");
    let url = format!("{prefix}/{}?options=-c%20role%3Dtalos_app", db.0);
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect as talos_app")
}

#[tokio::test]
async fn text_postgres_withheld_is_reported_as_withheld_not_as_the_statement() {
    let (pool, _db) = common::isolated_db_pool().await;
    // A statement issued by the SUPERUSER, so `talos_app` may not see its text.
    sqlx::query("SELECT 1 AS \"p39_superuser_only_marker\"")
        .fetch_one(&pool)
        .await
        .expect("probe");

    // CONTROL: as the superuser the text IS visible, so the assertions below
    // are about the ROLE and not about the reader failing to read anything.
    let full = talos_statement_stats::read_statement_stats(
        &pool,
        talos_statement_stats::ReadOptions {
            order_by: talos_statement_stats::OrderBy::Calls,
            limit: 50,
        },
    )
    .await;
    let full_json =
        talos_statement_stats::render(&full, &talos_statement_stats::GuestAttribution::Unfenced);
    assert_eq!(
        full_json["coverage"]["entries_text_redacted"],
        serde_json::json!(0),
        "the superuser sees every statement's text: {full_json}"
    );
    assert!(
        full_json["statements"]
            .as_array()
            .expect("statements")
            .iter()
            .any(|s| s["query"]
                .as_str()
                .is_some_and(|q| q.contains("p39_superuser_only_marker"))),
        "the control did not find the planted statement: {full_json}"
    );

    let limited = app_role_pool(&pool).await;
    let read = talos_statement_stats::read_statement_stats(
        &limited,
        talos_statement_stats::ReadOptions {
            order_by: talos_statement_stats::OrderBy::Calls,
            limit: 50,
        },
    )
    .await;
    let v =
        talos_statement_stats::render(&read, &talos_statement_stats::GuestAttribution::Unfenced);

    assert_eq!(v["available"], serde_json::json!(true), "{v}");
    assert!(
        v["coverage"]["entries_text_redacted"].as_i64().unwrap_or(0) > 0,
        "as talos_app, Postgres must have withheld some statement text: {v}"
    );
    let stmts = v["statements"].as_array().expect("statements");
    let redacted: Vec<_> = stmts
        .iter()
        .filter(|s| s["text_redacted"] == serde_json::json!(true))
        .collect();
    assert!(!redacted.is_empty(), "no row was marked redacted: {v}");
    for r in redacted {
        assert!(
            r.get("query").is_none(),
            "a withheld row rendered a query field: {r}"
        );
    }
    // The marker must not reach the report as if it were SQL.
    assert!(
        !v.to_string().contains("insufficient privilege"),
        "Postgres' redaction marker was rendered as a statement: {v}"
    );
    assert_eq!(
        v["coverage"]["connecting_role"],
        serde_json::json!("talos_app"),
        "the report must name the role it read AS, because that role decides \
         what text it could see: {v}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 9. `pg_stat_statements` is CLUSTER-wide. A per-database report that forgot
//    its `dbid` filter would render another database's statements — on a
//    server hosting more than one Talos deployment, another tenant's.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_statement_from_another_database_is_not_in_this_databases_report() {
    let (pool, _db) = common::isolated_db_pool().await;
    let admin = seed_user(&pool, true).await;
    let state = mcp_state(pool.clone()).await;

    // Issue a uniquely-marked statement against the MAINTENANCE database, on
    // its own connection. Same cluster, same shared-memory hash, different
    // `dbid`.
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let (prefix, _) = base.rsplit_once('/').expect("a database in DATABASE_URL");
    let other = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!("{prefix}/postgres"))
        .await
        .expect("connect to the maintenance database");
    let marker = format!("p39_other_db_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("SELECT 1 AS \"{marker}\""))
        .fetch_one(&other)
        .await
        .expect("probe in the other database");

    // CONTROL: the same shape of statement issued HERE does appear, so a
    // report that simply found nothing would not pass this test.
    let here = format!("p39_this_db_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("SELECT 1 AS \"{here}\""))
        .fetch_one(&pool)
        .await
        .expect("probe in this database");

    let v = machine_json(&report(&state, admin, serde_json::json!({ "limit": 50 })).await);
    let text = v["statements"].to_string();
    assert!(
        text.contains(&here),
        "the control statement issued in THIS database is missing, so the \
         absence below proves nothing: {v}"
    );
    assert!(
        !text.contains(&marker),
        "a statement from ANOTHER database in the same cluster reached this \
         database's report: {v}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 10. The gate must fail CLOSED. `is_platform_admin` is a `Result` collapsed
//     with `.unwrap_or(false)` — a gate that cannot read its rule must refuse
//     and must never grant, and the difference is one word at the call site.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unreadable_admin_flag_refuses_rather_than_granting() {
    let (pool, _db) = common::isolated_db_pool().await;
    let admin = seed_user(&pool, true).await;
    let state = mcp_state(pool.clone()).await;

    // CONTROL: with the column intact this user IS an admin and gets a report,
    // so the refusal below is about the unreadable flag and not about the user.
    let ok = machine_json(&report(&state, admin, serde_json::json!({})).await);
    assert_eq!(ok["available"], serde_json::json!(true), "{ok}");

    // The flag read now cannot run. `users.is_platform_admin` is the column it
    // names.
    sqlx::query("ALTER TABLE users DROP COLUMN is_platform_admin CASCADE")
        .execute(&pool)
        .await
        .expect("drop the column the gate reads");

    let resp = report(&state, admin, serde_json::json!({})).await;
    let msg = error_message(&resp);
    assert!(
        msg.contains("platform-admin"),
        "an unreadable admin flag must REFUSE, not grant: {msg}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 11. A pre-1.9 `pg_stat_statements` has no `_info` view, so eviction is
//     UNKNOWN — and unknown must not render as zero. `0` claims the
//     instrument has evicted nothing, which is exactly what such a server
//     cannot establish.
//
//     Reproduced rather than simulated: PG 17 still ships the 1.8 script, so
//     `CREATE EXTENSION … VERSION '1.8'` is a real pre-`_info` install.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_pre_info_extension_reports_eviction_as_unknown_not_as_zero() {
    let (pool, _db) = common::isolated_db_pool().await;

    // CONTROL: at the default version the eviction count is MEASURED, so the
    // absence below is about the extension version and not about the reader
    // dropping a field it cannot decode.
    let modern = talos_statement_stats::read_statement_stats(
        &pool,
        talos_statement_stats::ReadOptions::default(),
    )
    .await;
    let modern_json =
        talos_statement_stats::render(&modern, &talos_statement_stats::GuestAttribution::Unfenced);
    assert!(
        modern_json["coverage"].get("entries_evicted").is_some(),
        "the control must measure eviction: {modern_json}"
    );

    sqlx::query("DROP EXTENSION pg_stat_statements")
        .execute(&pool)
        .await
        .expect("drop");
    sqlx::query("CREATE EXTENSION pg_stat_statements VERSION '1.8'")
        .execute(&pool)
        .await
        .expect("install the pre-_info version");

    let read = talos_statement_stats::read_statement_stats(
        &pool,
        talos_statement_stats::ReadOptions::default(),
    )
    .await;
    let v =
        talos_statement_stats::render(&read, &talos_statement_stats::GuestAttribution::Unfenced);

    // Still AVAILABLE — a 1.8 server measures statements perfectly well.
    assert_eq!(v["available"], serde_json::json!(true), "{v}");
    assert!(
        v["coverage"].get("entries_evicted").is_none(),
        "a server with no pg_stat_statements_info reported an eviction count it \
         cannot possibly know: {v}"
    );
    assert_eq!(
        v["coverage"]["top_n_may_be_incomplete"],
        serde_json::json!(false),
        "an UNKNOWN eviction count must not be read as evidence of eviction: {v}"
    );
    assert!(
        v["statements"].as_array().is_some_and(|a| !a.is_empty()),
        "1.8 carries every column this reader names, so the rows must still \
         decode: {v}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 12. `pg_stat_statements` entries OUTLIVE the database that minted them, and
//     the cap is cluster-wide. On this stack 1139 of 1793 entries belonged to
//     dropped databases — all of them from this very harness's per-test
//     clones — so the report says so rather than leaving an operator to
//     wonder where their capacity went.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn entries_from_a_dropped_database_are_counted_and_disclosed() {
    let (pool, _db) = common::isolated_db_pool().await;
    let admin = seed_user(&pool, true).await;
    let state = mcp_state(pool.clone()).await;

    let before = machine_json(&report(&state, admin, serde_json::json!({})).await)["coverage"]
        ["entries_for_dropped_databases"]
        .as_i64()
        .expect("the field is present");

    // Mint an entry in a database, then drop the database.
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let (prefix, _) = base.rsplit_once('/').expect("a database in DATABASE_URL");
    let victim = format!("p39_victim_{}", Uuid::new_v4().simple());
    let admin_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!("{prefix}/postgres"))
        .await
        .expect("maintenance connection");
    sqlx::query(&format!("CREATE DATABASE \"{victim}\""))
        .execute(&admin_pool)
        .await
        .expect("create the victim database");
    {
        let vp = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&format!("{prefix}/{victim}"))
            .await
            .expect("connect to the victim");
        sqlx::query(&format!(
            "SELECT 1 AS \"p39_victim_marker_{}\"",
            Uuid::new_v4().simple()
        ))
        .fetch_one(&vp)
        .await
        .expect("mint an entry");
        vp.close().await;
    }
    sqlx::query(&format!("DROP DATABASE \"{victim}\" WITH (FORCE)"))
        .execute(&admin_pool)
        .await
        .expect("drop the victim database");

    let after = machine_json(&report(&state, admin, serde_json::json!({})).await)["coverage"]
        ["entries_for_dropped_databases"]
        .as_i64()
        .expect("the field is present");
    assert!(
        after > before,
        "an entry minted by a database that was then dropped must be counted \
         against the shared cap: before={before} after={after}"
    );
}

/// The PRECONDITION every `available: true` assertion in this file rests on,
/// checked directly so an environment that lacks it fails HERE with the cause
/// named, instead of as ten assertions about a report that could only ever say
/// `not_installed`. That is exactly how this suite first failed in CI: the
/// disposable Postgres in `scripts/test-integration.sh` did not preload the
/// library that `docker-compose.yml` does, and it had only been run against the
/// compose cluster.
#[tokio::test]
async fn the_suite_runs_on_a_cluster_that_preloads_the_library() {
    let (pool, _db) = common::isolated_db_pool().await;
    let preload: String = sqlx::query_scalar("SELECT current_setting('shared_preload_libraries')")
        .fetch_one(&pool)
        .await
        .expect("read shared_preload_libraries");
    assert!(
        preload
            .split(',')
            .any(|lib| lib.trim() == "pg_stat_statements"),
        "shared_preload_libraries = {preload:?}: this suite needs a cluster started with \
         `-c shared_preload_libraries=pg_stat_statements` (docker-compose.yml and \
         scripts/test-integration.sh both pass it); without it the migration no-ops and \
         every report reads `not_installed`"
    );
}
