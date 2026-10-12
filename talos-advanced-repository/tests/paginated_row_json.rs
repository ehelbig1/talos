// ci-store: selfcontained — scripts/test-integration.sh runs this with that store (scripts/ci_test_targets.py)
//! A `query_paginated` row reaches its reader with every value it held.
//!
//! The rows here come from the real `AdvancedRepository::execute_paginated_select`
//! (the extended protocol, so values arrive in Postgres's binary format, as in
//! production) and go through the encoder the handler uses,
//! `row_json::row_to_json`.
//!
//! Until 2026-10-12 a `timestamp`, a `numeric`, a `smallint`, a `date` and
//! every array came back `null`, the same as SQL NULL. The first test is that
//! defect; the second holds the hand-written `numeric` decoder to the text the
//! server itself prints; the third is the refusal for a type with no rendering.
//!
//! Gated on `TALOS_TEST_DATABASE_URL` (any Postgres; needs no migrations).
//! ```sh
//! cargo test -p talos-advanced-repository --test paginated_row_json
//! ```

use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, Pool, Postgres};
use std::time::Duration;
use talos_advanced_repository::row_json::{row_to_json, RowJsonError};
use talos_advanced_repository::{AdvancedRepository, PaginationMode, QUERY_PAGINATED_ROLE};

fn url() -> Option<String> {
    match std::env::var("TALOS_TEST_DATABASE_URL") {
        Ok(u) if !u.is_empty() => Some(u),
        _ => {
            eprintln!("SKIP: set TALOS_TEST_DATABASE_URL to run paginated_row_json");
            None
        }
    }
}

/// A pool, and the role the method enters: created as the migration makes it
/// on a cluster that has not run the migrations. Two tests may race to create
/// it. The statements below read no table, so the role needs no grant.
async fn repository(url: &str) -> (Pool<Postgres>, AdvancedRepository) {
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(10))
        .connect(url)
        .await
        .expect("connect");
    for sql in [
        format!(
            "DO $$ BEGIN CREATE ROLE {QUERY_PAGINATED_ROLE} \
             NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS; \
             EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$"
        ),
        format!(
            "DO $$ BEGIN IF NOT pg_has_role(current_user, '{QUERY_PAGINATED_ROLE}', 'MEMBER') \
             THEN GRANT {QUERY_PAGINATED_ROLE} TO CURRENT_USER; END IF; END $$"
        ),
    ] {
        pool.execute(sqlx::AssertSqlSafe(sql)).await.expect("role");
    }
    let repo = AdvancedRepository::new(pool.clone());
    (pool, repo)
}

async fn one_row(repo: &AdvancedRepository, query: &str) -> Result<Value, RowJsonError> {
    let rows = repo
        .execute_paginated_select(query, 10, PaginationMode::Offset { offset: 0 })
        .await
        .expect("the statement runs");
    assert_eq!(rows.len(), 1, "one row expected from {query}");
    row_to_json(&rows[0]).map(Value::Object)
}

#[tokio::test]
async fn a_value_that_is_present_is_never_null() {
    let Some(url) = url() else { return };
    let (_pool, repo) = repository(&url).await;

    let row = one_row(
        &repo,
        "SELECT \
           TIMESTAMP '2026-10-12 09:30:00' AS ts, \
           TIMESTAMP '2026-10-12 09:30:00.25' AS ts_fraction, \
           TIMESTAMPTZ '2026-10-12 09:30:00+00' AS tstz, \
           DATE '2026-10-12' AS d, \
           TIME '09:30:00' AS t, \
           round(1.5::numeric, 0) AS rounded, \
           12345.6789::numeric AS n, \
           3::smallint AS small, \
           7::int AS i, \
           9000000000::bigint AS big, \
           1.5::real AS f4, \
           2.25::double precision AS f8, \
           'NaN'::double precision AS not_a_number, \
           true AS b, \
           'text'::text AS s, \
           'var'::varchar(8) AS v, \
           '00000000-0000-0000-0000-000000000001'::uuid AS id, \
           '{\"k\": [1, 2]}'::jsonb AS j, \
           INTERVAL '1 month 2 days 3 seconds' AS span, \
           ARRAY['a', NULL, 'c'] AS texts, \
           ARRAY[1, 2]::int[] AS ints, \
           ARRAY[1]::bigint[] AS bigs, \
           NULL::numeric AS absent_numeric, \
           NULL::timestamp AS absent_timestamp, \
           NULL::int[] AS absent_array",
    )
    .await
    .expect("every column here has a rendering");

    let expected = json!({
        "ts": "2026-10-12T09:30:00",
        "ts_fraction": "2026-10-12T09:30:00.250",
        "tstz": "2026-10-12T09:30:00+00:00",
        "d": "2026-10-12",
        "t": "09:30:00",
        "rounded": "2",
        "n": "12345.6789",
        "small": 3,
        "i": 7,
        "big": 9_000_000_000_i64,
        "f4": 1.5,
        "f8": 2.25,
        "not_a_number": "NaN",
        "b": true,
        "s": "text",
        "v": "var",
        "id": "00000000-0000-0000-0000-000000000001",
        "j": {"k": [1, 2]},
        "span": {"months": 1, "days": 2, "microseconds": 3_000_000},
        "texts": ["a", null, "c"],
        "ints": [1, 2],
        "bigs": [1],
        "absent_numeric": null,
        "absent_timestamp": null,
        "absent_array": null,
    });
    assert_eq!(row, expected);

    // The defect, stated as the property: only the columns that are SQL NULL
    // may be null.
    let nulls: Vec<&String> = row
        .as_object()
        .expect("an object")
        .iter()
        .filter(|(_, v)| v.is_null())
        .map(|(k, _)| k)
        .collect();
    assert_eq!(
        nulls,
        ["absent_array", "absent_numeric", "absent_timestamp"],
        "a present value came back null"
    );
}

#[tokio::test]
async fn a_numeric_reads_exactly_as_the_server_prints_it() {
    let Some(url) = url() else { return };
    let (_pool, repo) = repository(&url).await;

    // Each literal is cast by the server; `shown` is the server's own text
    // for the same value, so the expected side is not this crate's arithmetic.
    let literals = [
        "0",
        "0.00",
        "1",
        "-1",
        "9999",
        "10000",
        "10001",
        "100000000",
        "123456789012345678901234567890",
        "-123456789012345678901234567890.123456789012345678901234567890",
        "0.1",
        "0.0001",
        "0.00001",
        "0.000000001",
        "-0.00000001",
        "1.50",
        "12345.6789",
        "1000000.000001",
        "99999999.99999999",
        "1e20",
        "1e-20",
        "NaN",
        "Infinity",
        "-Infinity",
    ];
    let array = literals
        .iter()
        .map(|l| format!("'{l}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let rows = repo
        .execute_paginated_select(
            &format!(
                "SELECT l AS literal, l::numeric AS value, l::numeric::text AS shown \
                 FROM unnest(ARRAY[{array}]) AS l"
            ),
            100,
            PaginationMode::Offset { offset: 0 },
        )
        .await
        .expect("the statement runs");
    assert_eq!(rows.len(), literals.len());
    for row in &rows {
        let row = row_to_json(row).expect("numeric and text both have a rendering");
        assert_eq!(
            row["value"], row["shown"],
            "numeric '{}' decoded differently from the server's text",
            row["literal"]
        );
        assert!(row["value"].is_string());
    }
}

#[tokio::test]
async fn a_type_with_no_rendering_is_refused_by_column_and_type() {
    let Some(url) = url() else { return };
    let (_pool, repo) = repository(&url).await;

    let refused = one_row(&repo, "SELECT 1 AS fine, '10.0.0.1'::inet AS address")
        .await
        .expect_err("inet has no rendering");
    assert_eq!(
        refused,
        RowJsonError::UnsupportedType {
            column: "address".to_string(),
            type_name: "INET".to_string(),
        }
    );
    assert_eq!(refused.column(), "address");
    assert_eq!(refused.type_name(), "INET");

    // Cast to text, as the refusal advises, and it is carried.
    let cast = one_row(&repo, "SELECT '10.0.0.1'::inet::text AS address")
        .await
        .expect("text has a rendering");
    assert_eq!(cast, json!({"address": "10.0.0.1/32"}));

    // A NULL of that type holds nothing to lose, so it is not refused.
    let absent = one_row(&repo, "SELECT NULL::inet AS address")
        .await
        .expect("NULL is null whatever the type");
    assert_eq!(absent, json!({"address": null}));
}
