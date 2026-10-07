//! The worker's SQL validator over the shared SQL corpus, held against a
//! recorded snapshot. The corpus and the other two gates' snapshots live in
//! `talos-sql-classify/corpus/` (see the README there).
//!
//! Each statement is validated under the three configurations that exist:
//!   E  an empty allowlist, mutations denied  — every dispatch site in the fleet
//!   I  INSERT granted, and nothing else
//!   P  an empty allowlist in the legacy permissive mode

use talos_worker_runtime::sql_validator::{
    validate_sql_with_policy, EmptyAllowlistPolicy, SqlValidationError,
};

const CORPUS: &str = include_str!("../../talos-sql-classify/corpus/statements.sql");
const RECORDED: &str = include_str!("../../talos-sql-classify/corpus/worker.snapshot");
const SNAPSHOT_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../talos-sql-classify/corpus/worker.snapshot"
);

fn statements() -> impl Iterator<Item = &'static str> {
    CORPUS
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
}

fn verdict(sql: &str, allowed: &[String], policy: EmptyAllowlistPolicy) -> String {
    match validate_sql_with_policy(sql, allowed, policy) {
        Ok(v) => format!(
            "ok({},{},{:?})",
            v.stmt_type,
            if v.returns_rows { "rows" } else { "no-rows" },
            v.access
        ),
        // The parser's message is not part of the verdict: it is reworded
        // between releases.
        Err(SqlValidationError::ParseError(_)) => "parse-error".to_string(),
        Err(SqlValidationError::MultipleStatements) => "multiple".to_string(),
        Err(SqlValidationError::DdlBlocked(what)) => format!("ddl({what})"),
        Err(SqlValidationError::DisallowedOperation(what)) => format!("disallowed({what})"),
        Err(SqlValidationError::CteMutationBlocked(what)) => format!("cte({what})"),
        Err(SqlValidationError::AlwaysBlocked(what)) => format!("blocked({what})"),
        Err(SqlValidationError::UnknownStatement) => "unknown".to_string(),
        Err(SqlValidationError::DisallowedFunction(what)) => format!("function({what})"),
    }
}

fn line(sql: &str) -> String {
    let insert_only = ["INSERT".to_string()];
    let e = verdict(sql, &[], EmptyAllowlistPolicy::DenyMutations);
    let i = verdict(sql, &insert_only, EmptyAllowlistPolicy::DenyMutations);
    let p = verdict(sql, &[], EmptyAllowlistPolicy::AllowAllNonDdl);
    if e == i && i == p {
        format!("*={e} | {sql}\n")
    } else {
        format!("E={e} I={i} P={p} | {sql}\n")
    }
}

#[test]
fn the_validator_matches_the_recorded_verdict_for_every_corpus_statement() {
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
        "{} verdict(s) differ from talos-sql-classify/corpus/worker.snapshot ({} recorded, \
         {} now). A changed verdict is a decision: review each, then re-record with \
         SQL_CORPUS_BLESS=1 (talos-sql-classify/corpus/README.md).\n{}",
        changed.len(),
        RECORDED.lines().count(),
        actual.lines().count(),
        changed.join("\n")
    );
}

/// What a statement names that no ungranted module may do, read off the SQL
/// TEXT so the two tests below do not lean on the walk they are checking: the
/// words that start a write, as the corpus spells them, and `XMLTABLE(` — a
/// denied function with syntax of its own, which a parser bump turned from
/// unparseable into a node no name check saw.
///
/// A statement that quotes a write inside a string or a comment is left out:
/// there the word is data. `XMLTABLE(` is looked for regardless, since every
/// use of it carries a string.
fn writes_named_in(sql: &str) -> Vec<&'static str> {
    let upper = sql.to_ascii_uppercase();
    let mut named = Vec::new();
    if upper.contains("XMLTABLE(") {
        named.push("XMLTABLE");
    }
    if sql.contains('\'') || sql.contains("--") || sql.contains("/*") || sql.contains("$$") {
        return named;
    }
    named.extend(
        [
            ("INSERT", "INSERT INTO"),
            ("UPDATE", "UPDATE T "),
            ("UPDATE", "UPDATE U "),
            ("UPDATE", "UPDATE ONLY "),
            ("DELETE", "DELETE FROM"),
            ("MERGE", "MERGE INTO"),
            ("SELECT INTO", "INTO NEW_TABLE"),
            ("SELECT INTO", "INTO TEMP "),
        ]
        .into_iter()
        .filter(|(_, spelling)| upper.contains(spelling))
        .map(|(kind, _)| kind),
    );
    named
}

/// With an empty allowlist and mutations denied — the only configuration the
/// fleet dispatches — the validator admits nothing but a read. Asserted per
/// statement, not read off the snapshot, so a re-recorded snapshot cannot
/// quietly carry a violation.
///
/// Written 2026-10-06, and it failed on the tree it was written against:
/// `WITH a AS (SELECT 1 AS x) INSERT INTO t (a) SELECT x FROM a` was admitted.
#[test]
fn nothing_but_a_read_is_admitted_under_the_fleet_configuration() {
    let mut admitted = 0;
    for sql in statements() {
        if let Ok(v) = validate_sql_with_policy(sql, &[], EmptyAllowlistPolicy::DenyMutations) {
            admitted += 1;
            assert!(
                v.access.is_read_only() && v.stmt_type == "SELECT",
                "admitted with no grant, and not a read: {sql} -> {} {:?}",
                v.stmt_type,
                v.access
            );
            assert_eq!(
                writes_named_in(sql),
                Vec::<&str>::new(),
                "admitted with no grant, and it names a write: {sql}"
            );
        }
    }
    assert!(admitted > 50, "the corpus admitted only {admitted} reads");
}

/// A grant of INSERT admits INSERT and nothing else — wherever in the
/// statement the other write sits, and whatever the root is.
#[test]
fn a_grant_of_insert_admits_no_other_write() {
    let insert_only = ["INSERT".to_string()];
    let mut admitted_inserts = 0;
    for sql in statements() {
        if validate_sql_with_policy(sql, &insert_only, EmptyAllowlistPolicy::DenyMutations).is_ok()
        {
            let named = writes_named_in(sql);
            admitted_inserts += usize::from(named.contains(&"INSERT"));
            assert!(
                named.iter().all(|kind| *kind == "INSERT"),
                "admitted under an INSERT-only grant, and it names {named:?}: {sql}"
            );
        }
    }
    assert!(
        admitted_inserts > 10,
        "the corpus admitted only {admitted_inserts} inserts"
    );
}
