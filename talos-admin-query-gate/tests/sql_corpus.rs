//! The `query_paginated` gate over the shared SQL corpus, held against a
//! recorded snapshot. The corpus and the other three gates' snapshots live in
//! `talos-sql-classify/corpus/` (see the README there).
//!
//! Each line records both layers of the gate, in the order the tool asks
//! them: `T=` the text rules, `P=` the parsed gate on its own. The tool admits
//! a statement only when both say `ok`. Recording the parsed gate even where
//! a text rule already refused shows which text rules it makes redundant.

use talos_admin_query_gate::{
    parsed_refusal, text_rule_refusal, validate_paginated_query, QueryRefusal, RelationRule,
};

const CORPUS: &str = include_str!("../../talos-sql-classify/corpus/statements.sql");
const RECORDED: &str = include_str!("../../talos-sql-classify/corpus/query_paginated.snapshot");
const SNAPSHOT_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../talos-sql-classify/corpus/query_paginated.snapshot"
);

fn statements() -> impl Iterator<Item = &'static str> {
    CORPUS
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
}

fn label(refusal: Option<QueryRefusal>) -> String {
    let Some(refusal) = refusal else {
        return "ok".to_string();
    };
    match refusal {
        QueryRefusal::Empty => "empty".to_string(),
        QueryRefusal::TooLong => "too-long".to_string(),
        QueryRefusal::NotSelect => "not-select".to_string(),
        QueryRefusal::Semicolon => "semicolon".to_string(),
        QueryRefusal::SetOperation => "set-operation".to_string(),
        QueryRefusal::Comment => "comment".to_string(),
        QueryRefusal::Cte => "cte".to_string(),
        QueryRefusal::Explain => "explain".to_string(),
        QueryRefusal::BlockedTable(table) => format!("table({table})"),
        QueryRefusal::BlockedSchema(schema) => format!("schema({schema})"),
        QueryRefusal::Unparseable => "parse-error".to_string(),
        QueryRefusal::NotOneStatement(n) => format!("statements={n}"),
        QueryRefusal::NotRead => "not-read".to_string(),
        QueryRefusal::Function(name) => format!("function({name})"),
        QueryRefusal::Relation { name, rule } => format!(
            "relation({name},{})",
            match rule {
                RelationRule::NotPublic => "not-public",
                RelationRule::SystemCatalog => "catalog",
                RelationRule::Blocked => "blocked",
                RelationRule::OnlyKeyword => "only",
                RelationRule::TableCommand => "table-command",
            }
        ),
    }
}

fn line(sql: &str) -> String {
    let trimmed = sql.trim();
    format!(
        "T={:<22} P={} | {sql}\n",
        label(text_rule_refusal(trimmed)),
        label(parsed_refusal(trimmed))
    )
}

#[test]
fn the_gate_matches_the_recorded_verdict_for_every_corpus_statement() {
    let actual: String = statements().map(line).collect();
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
        "{} verdict(s) differ from talos-sql-classify/corpus/query_paginated.snapshot ({} \
         recorded, {} now). A changed verdict is a decision: review each, then re-record with \
         SQL_CORPUS_BLESS=1 (talos-sql-classify/corpus/README.md).\n{}",
        changed.len(),
        RECORDED.lines().count(),
        actual.lines().count(),
        changed.join("\n")
    );
}

/// Words in a statement's TEXT that the parsed gate must never admit, read
/// off the text so this test does not lean on the walks it is checking: a
/// word that starts a write, a word beginning `pg_` (a system catalog, or a
/// server function), a system schema, a withheld table, and a function the
/// deny lists pin, written as a call. A statement that carries a string, a
/// comment or a quoted identifier is checked for the call and the catalog
/// only: there a write word may be data.
fn forbidden_words_in(sql: &str) -> Vec<String> {
    let lower = sql.to_ascii_lowercase();
    let words: Vec<&str> = lower
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .collect();
    let mut found = Vec::new();
    for w in &words {
        if w.starts_with("pg_") {
            found.push(format!("catalog-or-server word {w}"));
        }
        if ["information_schema", "pg_catalog", "pg_toast"].contains(w) {
            found.push(format!("system schema {w}"));
        }
        if talos_admin_query_gate::BLOCKED_TABLES_LIST.contains(w) && !sql.contains('\'') {
            found.push(format!("withheld table {w}"));
        }
    }
    let pinned = talos_workflow_job_protocol::DISALLOWED_SQL_FUNCTIONS
        .iter()
        .chain(talos_workflow_job_protocol::SQL_TEXT_EVALUATOR_FUNCTIONS);
    for f in pinned {
        if lower.contains(&format!("{f}(")) || lower.contains(&format!("{f} (")) {
            found.push(format!("call to {f}"));
        }
    }
    if !(sql.contains('\'') || sql.contains("--") || sql.contains("/*") || sql.contains('"')) {
        for write in [
            "insert into",
            "update t ",
            "update u ",
            "delete from",
            "merge into",
            "into new_table",
            "into temp ",
        ] {
            if lower.contains(write) {
                found.push(format!("write `{write}`"));
            }
        }
    }
    found
}

/// What the PARSED gate admits on its own — not only what reaches it behind
/// the text rules — names no write, no catalog, no withheld table and no
/// pinned function. Asserted per statement from the text, not read off the
/// snapshot, so a re-recorded snapshot cannot quietly carry a violation.
#[test]
fn the_parsed_gate_alone_admits_nothing_the_text_names_as_forbidden() {
    let mut admitted = 0;
    for sql in statements() {
        if parsed_refusal(sql.trim()).is_none() {
            admitted += 1;
            assert_eq!(
                forbidden_words_in(sql),
                Vec::<String>::new(),
                "admitted by the parsed gate: {sql}"
            );
        }
    }
    assert!(
        admitted > 30,
        "the parsed gate admitted only {admitted} statements"
    );
}

/// The tool admits a statement only when both layers do.
#[test]
fn the_tool_admits_only_what_both_layers_admit() {
    for sql in statements() {
        let trimmed = sql.trim();
        let both = text_rule_refusal(trimmed).is_none() && parsed_refusal(trimmed).is_none();
        assert_eq!(validate_paginated_query(sql).is_ok(), both, "{sql}");
    }
}
