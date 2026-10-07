//! The controller's SQL admission functions over the shared SQL corpus, held
//! against a recorded snapshot. The corpus and the other two gates' snapshots
//! live in `talos-sql-classify/corpus/` (see the README there).
//!
//! The verdict is composed the way the `talos.database.query` handler
//! composes it: one statement, a data statement, no denied function — and
//! then whether it mutates, which is what the write ceiling is asked.

use super::{
    controller_permits_data_statement, controller_side_denied_function,
    controller_statement_mutates, statement_type_label,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

const CORPUS: &str = include_str!("../../talos-sql-classify/corpus/statements.sql");
const RECORDED: &str = include_str!("../../talos-sql-classify/corpus/controller.snapshot");
const SNAPSHOT_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../talos-sql-classify/corpus/controller.snapshot"
);

fn statements() -> impl Iterator<Item = &'static str> {
    CORPUS
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
}

fn verdict(sql: &str) -> String {
    let parsed = match Parser::parse_sql(&PostgreSqlDialect {}, sql) {
        Err(_) => return "parse-error".to_string(),
        Ok(parsed) if parsed.len() != 1 => return format!("statements={}", parsed.len()),
        Ok(parsed) => parsed,
    };
    let stmt = &parsed[0];
    if !controller_permits_data_statement(stmt) {
        return "refuse statement".to_string();
    }
    if let Some(name) = controller_side_denied_function(stmt) {
        return format!("refuse function {name}");
    }
    format!(
        "admit {} {}",
        if controller_statement_mutates(stmt) {
            "write"
        } else {
            "read"
        },
        statement_type_label(stmt)
    )
}

#[test]
fn the_controller_matches_the_recorded_verdict_for_every_corpus_statement() {
    let actual: String = statements()
        .map(|sql| format!("{:<32} | {sql}\n", verdict(sql)))
        .collect();
    if std::env::var_os("SQL_CORPUS_BLESS").is_some() {
        std::fs::write(SNAPSHOT_PATH, &actual).expect("write the snapshot");
        return;
    }
    let changed: Vec<String> = RECORDED
        .lines()
        .zip(actual.lines())
        .filter(|(recorded, now)| recorded != now)
        .map(|(recorded, now)| format!("  recorded: {recorded}\n  now:      {now}"))
        .collect();
    assert!(
        changed.is_empty() && RECORDED.lines().count() == actual.lines().count(),
        "{} verdict(s) differ from talos-sql-classify/corpus/controller.snapshot ({} recorded, \
         {} now). A changed verdict is a decision: review each, then re-record with \
         SQL_CORPUS_BLESS=1 (talos-sql-classify/corpus/README.md).\n{}",
        changed.len(),
        RECORDED.lines().count(),
        actual.lines().count(),
        changed.join("\n")
    );
}

/// A statement the controller would run as a READ is a `SELECT` that carries
/// no other statement and creates no table. Asserted per statement, not read off the snapshot, so
/// a re-recorded snapshot cannot quietly carry a violation.
#[test]
fn nothing_the_controller_calls_a_read_carries_a_mutation() {
    let mut reads = 0;
    for sql in statements() {
        if verdict(sql) != "admit read SELECT" {
            continue;
        }
        reads += 1;
        let upper = sql.to_ascii_uppercase();
        for keyword in [
            "INSERT INTO",
            "DELETE FROM",
            "UPDATE T SET",
            "UPDATE U SET",
            "MERGE INTO",
            "INTO NEW_TABLE",
            "INTO TEMP ",
        ] {
            // A keyword inside a string literal or a comment is not a statement.
            let in_text = upper.contains('\'')
                || upper.contains("--")
                || upper.contains("/*")
                || upper.contains("$$");
            assert!(
                !upper.contains(keyword) || in_text,
                "called a read, and it carries `{keyword}`: {sql}"
            );
        }
    }
    assert!(reads > 50, "the corpus holds only {reads} reads");
}

/// Nothing the controller would run at all — as a read or as a write —
/// creates a table through `SELECT … INTO`, or calls `XMLTABLE`, a denied
/// function with syntax of its own that no name check sees.
#[test]
fn nothing_the_controller_admits_creates_a_table_or_calls_xmltable() {
    let mut checked = 0;
    for sql in statements() {
        let upper = sql.to_ascii_uppercase();
        if upper.contains("INTO NEW_TABLE")
            || upper.contains("INTO TEMP ")
            || upper.contains("XMLTABLE(")
        {
            checked += 1;
            let verdict = verdict(sql);
            assert!(
                !verdict.starts_with("admit"),
                "admitted, and it should never be: {sql} -> {verdict}"
            );
        }
    }
    assert!(
        checked >= 6,
        "the corpus holds only {checked} such statements"
    );
}
