//! The auditor-facing documents state schema facts, and the schema is the judge.
//!
//! Package BV (2026-09-16) corrected ~112 false claims across the SOC 2 control
//! mapping, the security architecture, the pentest scope and the threat model.
//! Two of the most-repeated errors were schema facts: the documents named FOUR
//! immutable audit tables for five days after `audit_events` was dropped, and
//! the architecture's budget section listed eight budget columns of which six
//! never existed. Check 92 proves a cited PATH exists; it cannot see a false
//! sentence beside a real path. These tests read the claims out of the
//! documents and hold them to the migrated schema, so the next migration that
//! adds or drops an audit table or a budget column fails here until the
//! documents follow.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use std::collections::BTreeSet;

const SOC2: &str = include_str!("../../docs/compliance/soc2-control-mapping.md");
const THREAT_MODEL: &str = include_str!("../../docs/THREAT_MODEL.md");
const ARCHITECTURE: &str = include_str!("../../docs/security/architecture.md");

/// Backticked identifiers in `text` that look like table or column names.
fn backticked_idents(text: &str) -> BTreeSet<String> {
    text.split('`')
        .skip(1)
        .step_by(2)
        .filter(|s| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
        .map(str::to_string)
        .collect()
}

/// The one line of `doc` containing `marker`; panics if absent or repeated,
/// because a claim that moved is a claim this test no longer reads.
fn line_with<'a>(doc: &'a str, marker: &str) -> &'a str {
    let hits: Vec<&str> = doc.lines().filter(|l| l.contains(marker)).collect();
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one line containing {marker:?}, found {}",
        hits.len()
    );
    hits[0]
}

/// The count word/number directly before `suffix` in `line` ("3 audit tables").
fn count_before(line: &str, suffix: &str) -> usize {
    let idx = line
        .find(suffix)
        .unwrap_or_else(|| panic!("{suffix:?} not in {line:?}"));
    line[..idx]
        .split_whitespace()
        .last()
        .and_then(|w| w.parse().ok())
        .unwrap_or_else(|| panic!("no count before {suffix:?} in {line:?}"))
}

/// The audit-table set each document names, keyed by document.
fn documented_audit_table_sets() -> Vec<(&'static str, usize, BTreeSet<String>)> {
    let mut out = Vec::new();

    let soc2 = line_with(SOC2, "| CC7.1-01 |");
    let named = soc2.split("with BEFORE").next().unwrap();
    out.push((
        "soc2 CC7.1-01",
        count_before(soc2, "audit tables"),
        backticked_idents(named),
    ));

    let tm = line_with(THREAT_MODEL, "Immutability triggers on all");
    let paren = tm
        .split('(')
        .nth(1)
        .and_then(|s| s.split(')').next())
        .unwrap();
    out.push((
        "THREAT_MODEL",
        count_before(tm, "audit tables"),
        backticked_idents(paren),
    ));

    let section = ARCHITECTURE
        .split("### 6.1 Audit Tables")
        .nth(1)
        .and_then(|s| s.split("####").next())
        .expect("architecture §6.1");
    let rows: BTreeSet<String> = section
        .lines()
        .filter(|l| l.starts_with("| `"))
        .map(|l| l.split('`').nth(1).unwrap().to_string())
        .collect();
    out.push(("architecture §6.1", rows.len(), rows));
    out
}

#[tokio::test]
async fn every_document_names_exactly_the_immutable_audit_tables() {
    let (pool, _db) = common::isolated_db_pool().await;
    let live: BTreeSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT c.relname::text FROM pg_trigger t \
         JOIN pg_proc p ON p.oid = t.tgfoid JOIN pg_class c ON c.oid = t.tgrelid \
         WHERE p.proname = 'prevent_audit_modification' AND NOT t.tgisinternal",
    )
    .fetch_all(&pool)
    .await
    .unwrap()
    .into_iter()
    .collect();
    assert!(
        !live.is_empty(),
        "no immutability trigger on a migrated schema — the query is wrong"
    );

    for (doc, count, named) in documented_audit_table_sets() {
        assert_eq!(named, live, "{doc} names the wrong audit tables");
        assert_eq!(
            count,
            live.len(),
            "{doc} states the wrong audit-table count"
        );
    }
    // Architecture also names each trigger; they must be the live ones.
    let live_triggers: BTreeSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT t.tgname::text FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid \
         WHERE p.proname = 'prevent_audit_modification' AND NOT t.tgisinternal",
    )
    .fetch_all(&pool)
    .await
    .unwrap()
    .into_iter()
    .collect();
    let section = ARCHITECTURE
        .split("### 6.1 Audit Tables")
        .nth(1)
        .unwrap()
        .split("####")
        .next()
        .unwrap();
    let doc_triggers: BTreeSet<String> = backticked_idents(section)
        .into_iter()
        .filter(|s| s.starts_with("trg_"))
        .collect();
    assert_eq!(
        doc_triggers, live_triggers,
        "architecture §6.1 names the wrong triggers"
    );
}

#[tokio::test]
async fn architecture_budget_table_is_the_actor_budget_policies_table() {
    let (pool, _db) = common::isolated_db_pool().await;
    let columns: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT column_name::text, column_default::text FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'actor_budget_policies' \
           AND column_name NOT IN ('actor_id', 'org_id', 'updated_at')",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        columns.len() > 5,
        "actor_budget_policies query returned {} columns",
        columns.len()
    );

    let section = ARCHITECTURE
        .split("### 4.2 Actor Budget System")
        .nth(1)
        .and_then(|s| s.split("### 4.3").next())
        .expect("architecture §4.2");
    let rows: Vec<&str> = section.lines().filter(|l| l.starts_with("| `")).collect();
    let documented: BTreeSet<String> = rows
        .iter()
        .map(|l| l.split('`').nth(1).unwrap().to_string())
        .collect();
    let live: BTreeSet<String> = columns.iter().map(|(c, _)| c.clone()).collect();
    assert_eq!(
        documented, live,
        "architecture §4.2 lists the wrong budget columns"
    );

    // A "(default N)" annotation in the first cell must be the column default,
    // and a column with an integer default must carry the annotation.
    for (col, default) in &columns {
        let row = rows
            .iter()
            .find(|l| l.split('`').nth(1) == Some(col))
            .unwrap();
        let first_cell = row.split('|').nth(1).unwrap();
        let documented_default = first_cell
            .split("(default ")
            .nth(1)
            .and_then(|s| s.split(')').next())
            .and_then(|s| s.trim().parse::<i64>().ok());
        let live_default = default.as_deref().and_then(|d| d.parse::<i64>().ok());
        assert_eq!(
            documented_default, live_default,
            "architecture §4.2 default for {col}"
        );
    }

    // The sentence under the table counts the numeric columns.
    let numeric = columns
        .iter()
        .filter(|(c, _)| c.starts_with("max_"))
        .count();
    let sentence = line_with(
        ARCHITECTURE,
        "rejects zero, negative and non-integer values for",
    );
    let next = ARCHITECTURE
        .lines()
        .skip_while(|l| *l != sentence)
        .nth(1)
        .unwrap_or("");
    let words = format!("{sentence} {next}");
    let stated = match words
        .split("all ")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
    {
        Some("nine") => 9,
        Some(w) => w.parse().unwrap_or(0),
        None => 0,
    };
    assert_eq!(
        stated, numeric,
        "architecture §4.2 states the wrong number of numeric budget columns"
    );
}
