//! `classify` over the shared SQL corpus, held against a recorded snapshot.
//!
//! The corpus (`corpus/statements.sql`) is shared with the worker's validator
//! and the controller's admission functions, each of which records its own
//! snapshot beside it. See `corpus/README.md`.

use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

const CORPUS: &str = include_str!("../corpus/statements.sql");
const RECORDED: &str = include_str!("../corpus/classify.snapshot");
const SNAPSHOT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/classify.snapshot");

fn statements() -> impl Iterator<Item = &'static str> {
    CORPUS
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
}

fn verdict(sql: &str) -> String {
    match Parser::parse_sql(&PostgreSqlDialect {}, sql) {
        Err(_) => "parse-error".to_string(),
        Ok(parsed) if parsed.len() != 1 => format!("statements={}", parsed.len()),
        Ok(parsed) => format!("{:?}", talos_sql_classify::classify(&parsed[0])),
    }
}

#[test]
fn classify_matches_the_recorded_verdict_for_every_corpus_statement() {
    let actual: String = statements()
        .map(|sql| format!("{:<24} | {sql}\n", verdict(sql)))
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
        "{} verdict(s) differ from corpus/classify.snapshot ({} recorded, {} now). \
         A changed verdict is a decision: review each, then re-record with \
         SQL_CORPUS_BLESS=1 (corpus/README.md).\n{}",
        changed.len(),
        RECORDED.lines().count(),
        actual.lines().count(),
        changed.join("\n")
    );
}

/// The snapshot can only pin what the corpus exercises. These are the shapes
/// the classifier exists for; if one stops being a row, the pin is hollow.
#[test]
fn the_corpus_still_exercises_every_verdict() {
    let seen: std::collections::BTreeSet<String> = statements().map(verdict).collect();
    for needed in [
        "ReadOnly",
        "Mutates { nested: false }",
        "Mutates { nested: true }",
        "Unclassified",
        "parse-error",
        "statements=2",
    ] {
        assert!(
            seen.contains(needed),
            "no corpus statement is {needed}: {seen:?}"
        );
    }
}
