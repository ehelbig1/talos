//! # One read-only classifier for SQL, with one home
//!
//! "Does this SQL statement mutate?" is asked on BOTH sides of the
//! `talos.database.query` signed RPC — by the worker before it forwards a
//! guest's query, and by the controller before it runs one on its
//! full-privilege pool. Until this crate existed the two sides answered it
//! with two independent implementations, and they DISAGREED:
//!
//! * The controller (`talos_rpc_subscribers::controller_statement_mutates`,
//!   #757) walks the AST and treats any nested non-`Query` statement as a
//!   mutation.
//! * The worker (`host::database::sql_stmt_type_is_read_only`) matched the
//!   STRING `"SELECT" | "EXPLAIN"` against `sql_validator`'s top-level
//!   statement label — so
//!   `WITH ins AS (INSERT INTO t VALUES (1) RETURNING a) SELECT * FROM ins`,
//!   which sqlparser 0.53 + `PostgreSqlDialect` parses as a
//!   `Statement::Query` whose CTE body is `SetExpr::Insert`, was labelled
//!   `"SELECT"` and called a READ. A `readonly` actor's INSERT reached the
//!   controller.
//!
//! Two paths answering one question differently IS the bug (the house rule
//! behind lint checks 33, 63 and 71). So the classification lives here, in a
//! leaf crate that depends on `sqlparser` and nothing else, and both consumers
//! call in.
//!
//! ## What else lives here, for the same reason
//!
//! * [`try_for_each_carried_statement`] — WHICH statements a statement
//!   carries. The worker's operation allowlist is asked about each one; it
//!   used to answer with its own walk, which missed positions this one
//!   reaches.
//! * [`selects_into_table`] — `SELECT … INTO new_table`, a table creation
//!   that parses as a plain query. [`classify`] calls it
//!   [`SqlAccess::Unclassified`] and both consumers refuse it.
//!
//! The verdicts of this crate and of both consumers over one corpus of
//! statements are recorded in `corpus/` (see its README).
//!
//! ## What this crate does NOT decide
//!
//! * **Which statement kinds may run at all.** Admission (DDL / `CALL` /
//!   `COPY` / `SET` are refused outright) stays in each consumer — the worker's
//!   `sql_validator::is_ddl` + `always_blocked_label`, the controller's
//!   `controller_permits_data_statement`. Re-enumerating a DDL taxonomy here
//!   would create the second copy this crate exists to remove.
//! * **Statement LABELS.** `sql_validator::statement_type` and
//!   `statement_type_label` answer "what kind is it" for allowlists, audit
//!   targets and error text. That is a different question with a different
//!   right answer (top-level only), and it stays where it is.
//! * **Function side effects.** `SELECT nextval('s')` / `setval` / a
//!   `VOLATILE` function that writes are mutations Postgres will happily run
//!   inside a statement this crate calls [`SqlAccess::ReadOnly`]. No
//!   statement-shape classifier can see them; the worker's expression-level
//!   `check_disallowed_functions` deny-list is the surface that can, and
//!   widening it is a separate piece of work. Stated so the gap is visible
//!   rather than implied.
//! * **Size and recursion bounds.** Callers cap the SQL byte length before
//!   parsing (the worker's `MAX_SQL_BYTES`, the controller's
//!   `database_rpc::validate_structure`). sqlparser's own
//!   `DEFAULT_REMAINING_DEPTH` bounds parse recursion, so an AST this crate
//!   receives is already shallow; `parse_depth_is_bounded_by_sqlparser` pins
//!   that rather than assuming it.

use sqlparser::ast::{Query, SetExpr, Statement, Visit, Visitor};
use std::ops::ControlFlow;

/// How a single parsed SQL statement accesses data.
///
/// Total over every `sqlparser::ast::Statement`, and fail-closed: only
/// [`SqlAccess::ReadOnly`] is a read, so a statement kind this crate has not
/// been taught lands in [`SqlAccess::Unclassified`] and is treated as a
/// mutation by every caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlAccess {
    /// Provably changes no rows: the root is a `Query` and the ONLY
    /// `Statement` nodes anywhere in its tree are `Query`s.
    ///
    /// `SELECT … FOR UPDATE` is included, deliberately. A locking clause takes
    /// row locks for the duration of the enclosing transaction (which the
    /// controller commits as soon as the query returns) but writes no data, so
    /// refusing it would deny a legitimate read while preventing no durable
    /// change. Recorded by `select_for_update_is_read_only_by_decision`, so the
    /// choice is visible and a future reversal is a deliberate edit.
    ReadOnly,
    /// Changes rows. `nested` distinguishes where:
    ///
    /// * `false` — the root statement is the mutation (`INSERT` / `UPDATE` /
    ///   `DELETE` / `MERGE`).
    /// * `true` — the root is a `Query` CARRYING a mutation: a Postgres
    ///   data-modifying CTE (`WITH x AS (INSERT … RETURNING …) SELECT …`), or
    ///   one nested inside a derived table. This is the shape both consumers
    ///   used to call a read.
    Mutates { nested: bool },
    /// Neither: DDL, `CALL`, `COPY`, `SET`, `PREPARE`, a query that creates a
    /// table (`SELECT … INTO`), or any `Statement` variant a future sqlparser
    /// adds. NOT read-only.
    ///
    /// Both consumers reject these before the read/write question is even
    /// asked, so in practice this variant is a fail-closed backstop rather
    /// than a routing decision — but it must never read as a read.
    Unclassified,
}

impl SqlAccess {
    /// The one predicate both consumers gate their write ceiling on.
    #[must_use]
    pub fn is_read_only(self) -> bool {
        matches!(self, SqlAccess::ReadOnly)
    }
}

/// Classify a parsed statement.
///
/// # The nested walk is not an enumeration of known-bad shapes
///
/// It breaks on **any** `Statement` node below the root that is not itself a
/// `Query`. On a genuine read the only statement in the tree is the root
/// `Query`, so the walk completes; anything else present is a mutation the
/// outer `Query` is carrying. That is fail-closed against every statement type
/// sqlparser learns to nest in future — including `DELETE` and `MERGE` inside
/// a CTE, which 0.53 refuses to parse today (pinned by
/// `delete_and_merge_ctes_are_parse_errors_today`) and a later version may
/// accept.
#[must_use]
pub fn classify(stmt: &Statement) -> SqlAccess {
    match stmt {
        Statement::Insert(_)
        | Statement::Update { .. }
        | Statement::Delete(_)
        | Statement::Merge { .. } => SqlAccess::Mutates { nested: false },
        Statement::Query(_) => {
            if selects_into_table(stmt) {
                // `SELECT … INTO new_table` CREATES a table. It is a query
                // only in shape; both consumers refuse it outright.
                SqlAccess::Unclassified
            } else if carries_nested_statement(stmt) {
                SqlAccess::Mutates { nested: true }
            } else {
                SqlAccess::ReadOnly
            }
        }
        _ => SqlAccess::Unclassified,
    }
}

/// Convenience for the many call sites that only need the predicate.
#[must_use]
pub fn is_read_only(stmt: &Statement) -> bool {
    classify(stmt).is_read_only()
}

fn carries_nested_statement(stmt: &Statement) -> bool {
    try_for_each_carried_statement(stmt, |_| ControlFlow::Break(())).is_break()
}

/// Call `f` with every statement `stmt` CARRIES: each `Statement` node below
/// the root that is not itself a `Query`.
///
/// This is the one walk behind "does this query hide a mutation". The
/// classifier asks it whether there is any such statement; the worker's
/// operation allowlist asks it WHICH, so that a carried `DELETE` is admitted
/// only where a top-level `DELETE` would be. It rides sqlparser's derived
/// `Visit`, which reaches every position a statement can sit in — a CTE body,
/// the body of the query a `WITH` introduces, a derived table, a subquery in
/// any expression. The worker used to answer this with a hand-written walk
/// over the positions someone had thought of, and was patched twice for the
/// ones nobody had (`corpus/README.md`).
///
/// The root is skipped whatever its kind, so an `INSERT` whose source query
/// carries an `UPDATE` reports the `UPDATE`.
pub fn try_for_each_carried_statement<B>(
    stmt: &Statement,
    f: impl FnMut(&Statement) -> ControlFlow<B>,
) -> ControlFlow<B> {
    struct CarriedStatementVisitor<F> {
        root_seen: bool,
        f: F,
    }
    impl<B, F: FnMut(&Statement) -> ControlFlow<B>> Visitor for CarriedStatementVisitor<F> {
        type Break = B;
        fn pre_visit_statement(&mut self, s: &Statement) -> ControlFlow<B> {
            if !self.root_seen {
                self.root_seen = true;
                return ControlFlow::Continue(());
            }
            match s {
                Statement::Query(_) => ControlFlow::Continue(()),
                carried => (self.f)(carried),
            }
        }
    }

    stmt.visit(&mut CarriedStatementVisitor {
        root_seen: false,
        f,
    })
}

/// Does any query in `stmt` carry an `INTO` target — Postgres's
/// `SELECT … INTO [TEMP] new_table FROM …`, which CREATES a table?
///
/// sqlparser parses it as an ordinary `Query` with a field set on the
/// `Select`, so nothing that matches on statement kind can see it: until
/// 2026-10-06 both consumers called it a read. Postgres accepts it only at
/// the top level; this looks everywhere, because the question is what the
/// parser will hand over, not what the server will then run.
#[must_use]
pub fn selects_into_table(stmt: &Statement) -> bool {
    fn body_selects_into(body: &SetExpr) -> bool {
        match body {
            SetExpr::Select(select) => select.into.is_some(),
            SetExpr::SetOperation { left, right, .. } => {
                body_selects_into(left) || body_selects_into(right)
            }
            // A parenthesised query is a `Query` of its own and is visited
            // as one; the other bodies hold no `Select` at this level.
            _ => false,
        }
    }
    struct SelectIntoVisitor;
    impl Visitor for SelectIntoVisitor {
        type Break = ();
        fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
            if body_selects_into(&query.body) {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        }
    }
    stmt.visit(&mut SelectIntoVisitor).is_break()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    fn parse1(sql: &str) -> Statement {
        let mut s = Parser::parse_sql(&PostgreSqlDialect {}, sql)
            .unwrap_or_else(|e| panic!("parse {sql}: {e}"));
        assert_eq!(s.len(), 1, "expected one statement: {sql}");
        s.remove(0)
    }

    /// `SELECT … INTO new_table` creates a table. It parses as a `Query`, and
    /// until 2026-10-06 that made it a read here and for both consumers.
    #[test]
    fn select_into_is_never_a_read() {
        for sql in [
            "SELECT * INTO new_table FROM t",
            "SELECT * INTO TEMP new_table FROM t",
            "SELECT 1 UNION SELECT a INTO new_table FROM t",
            "WITH a AS (SELECT 1 AS x) SELECT x INTO new_table FROM a",
            "SELECT * FROM (SELECT a INTO new_table FROM t) x",
        ] {
            let stmt = parse1(sql);
            assert!(selects_into_table(&stmt), "{sql}");
            assert_eq!(classify(&stmt), SqlAccess::Unclassified, "{sql}");
        }
        // `INSERT INTO … SELECT` and a plain read have no such target.
        for sql in ["SELECT a FROM t", "INSERT INTO t (a) SELECT a FROM u"] {
            assert!(!selects_into_table(&parse1(sql)), "{sql}");
        }
    }

    /// The carried-statement walk names each statement below the root, in
    /// every position, and skips the root whatever its kind.
    #[test]
    fn the_carried_walk_names_what_a_statement_carries() {
        fn carried(sql: &str) -> Vec<&'static str> {
            let mut kinds = Vec::new();
            let _ = try_for_each_carried_statement(&parse1(sql), |s| {
                kinds.push(match s {
                    Statement::Insert(_) => "INSERT",
                    Statement::Update { .. } => "UPDATE",
                    Statement::Delete(_) => "DELETE",
                    _ => "OTHER",
                });
                ControlFlow::<()>::Continue(())
            });
            kinds
        }
        assert_eq!(carried("SELECT 1"), Vec::<&str>::new());
        assert_eq!(carried("INSERT INTO t (a) VALUES (1)"), Vec::<&str>::new());
        assert_eq!(
            carried("WITH a AS (SELECT 1 AS x) INSERT INTO t (a) SELECT x FROM a"),
            ["INSERT"]
        );
        assert_eq!(
            carried(
                "INSERT INTO t (a) WITH upd AS (UPDATE u SET a = 1 RETURNING a) SELECT a FROM upd"
            ),
            ["UPDATE"]
        );
        assert_eq!(
            carried(
                "WITH i AS (INSERT INTO t (a) VALUES (1) RETURNING a), \
                 u AS (UPDATE t SET a = 2 RETURNING a) SELECT * FROM i, u"
            ),
            ["INSERT", "UPDATE"]
        );
        assert_eq!(
            carried(
                "SELECT * FROM t WHERE a IN \
                 (WITH i AS (INSERT INTO u (a) VALUES (1) RETURNING a) SELECT a FROM i)"
            ),
            ["INSERT"]
        );
    }

    /// The corpus both consumers are pinned against. Every entry states the
    /// EXPECTED verdict, so a change in sqlparser's parse or in the walk
    /// surfaces here first.
    const CORPUS: &[(&str, SqlAccess)] = &[
        // --- plain reads (must stay byte-identical in decision) ---
        ("SELECT 1", SqlAccess::ReadOnly),
        ("SELECT * FROM users WHERE id = $1", SqlAccess::ReadOnly),
        ("SELECT * FROM t UNION SELECT * FROM u", SqlAccess::ReadOnly),
        ("SELECT * FROM (SELECT 1) x", SqlAccess::ReadOnly),
        ("WITH a AS (SELECT 1) SELECT * FROM a", SqlAccess::ReadOnly),
        (
            "SELECT * FROM t WHERE id IN (SELECT id FROM u)",
            SqlAccess::ReadOnly,
        ),
        // --- plain mutations (must stay byte-identical in decision) ---
        (
            "INSERT INTO t (a) VALUES ($1)",
            SqlAccess::Mutates { nested: false },
        ),
        (
            "UPDATE t SET a = 1 WHERE id = $1",
            SqlAccess::Mutates { nested: false },
        ),
        ("DELETE FROM t WHERE id = $1", SqlAccess::Mutates { nested: false }),
        (
            "MERGE INTO t USING u ON t.a = u.a WHEN MATCHED THEN UPDATE SET a = 1",
            SqlAccess::Mutates { nested: false },
        ),
        // --- the hole: a mutation wearing a Query's clothes ---
        (
            "WITH ins AS (INSERT INTO t (a) VALUES (1) RETURNING a) SELECT * FROM ins",
            SqlAccess::Mutates { nested: true },
        ),
        (
            "WITH d AS (UPDATE t SET a = 1 RETURNING a) SELECT * FROM d",
            SqlAccess::Mutates { nested: true },
        ),
        (
            "WITH a AS (SELECT 1), b AS (INSERT INTO t VALUES (1) RETURNING 1) SELECT * FROM a",
            SqlAccess::Mutates { nested: true },
        ),
        (
            "SELECT * FROM (WITH x AS (INSERT INTO t VALUES (1) RETURNING 1) SELECT * FROM x) y",
            SqlAccess::Mutates { nested: true },
        ),
        (
            "SELECT * FROM t WHERE a IN (WITH x AS (UPDATE u SET a = 1 RETURNING a) SELECT * FROM x)",
            SqlAccess::Mutates { nested: true },
        ),
        // A mutation carrying a mutation is still a mutation, at the root.
        (
            "INSERT INTO t SELECT * FROM (WITH x AS (UPDATE u SET a=1 RETURNING a) SELECT * FROM x) z",
            SqlAccess::Mutates { nested: false },
        ),
        // --- neither: fail closed ---
        ("CREATE TABLE t (id INT)", SqlAccess::Unclassified),
        ("DROP TABLE t", SqlAccess::Unclassified),
        ("ALTER TABLE t ADD COLUMN a INT", SqlAccess::Unclassified),
        ("TRUNCATE t", SqlAccess::Unclassified),
        ("GRANT SELECT ON t TO r", SqlAccess::Unclassified),
        ("CALL p()", SqlAccess::Unclassified),
        ("COPY t FROM '/etc/passwd'", SqlAccess::Unclassified),
        ("SET search_path = x", SqlAccess::Unclassified),
        ("PREPARE x AS INSERT INTO t VALUES (1)", SqlAccess::Unclassified),
        ("EXECUTE x", SqlAccess::Unclassified),
        // `EXPLAIN ANALYZE <dml>` EXECUTES its inner statement, so EXPLAIN is
        // emphatically not a read. Both consumers refuse it outright before
        // reaching this crate; this arm is the fail-closed backstop.
        ("EXPLAIN SELECT 1", SqlAccess::Unclassified),
        (
            "EXPLAIN ANALYZE INSERT INTO t VALUES (1)",
            SqlAccess::Unclassified,
        ),
    ];

    #[test]
    fn corpus_pins_every_verdict() {
        for (sql, expected) in CORPUS {
            assert_eq!(classify(&parse1(sql)), *expected, "classify: {sql}");
        }
    }

    #[test]
    fn only_read_only_reads() {
        for (sql, expected) in CORPUS {
            assert_eq!(
                is_read_only(&parse1(sql)),
                *expected == SqlAccess::ReadOnly,
                "is_read_only: {sql}"
            );
        }
    }

    /// The two statement kinds #757 measured as UNPARSEABLE inside a CTE on
    /// sqlparser 0.53. Pinned so a version bump that starts accepting them is
    /// noticed — the walk already handles them, but silently gaining a new
    /// admitted shape should be a visible event.
    #[test]
    fn delete_and_merge_ctes_are_parse_errors_today() {
        for sql in [
            "WITH d AS (DELETE FROM t RETURNING a) SELECT * FROM d",
            "WITH m AS (MERGE INTO t USING u ON t.a=u.a WHEN MATCHED THEN UPDATE SET a=1) SELECT 1",
        ] {
            assert!(
                Parser::parse_sql(&PostgreSqlDialect {}, sql).is_err(),
                "sqlparser 0.53 now parses this — re-check the walk: {sql}"
            );
        }
    }

    /// A DECISION, recorded rather than assumed: a locking clause takes row
    /// locks but changes no rows, and the controller commits the enclosing
    /// transaction as soon as the query returns.
    #[test]
    fn select_for_update_is_read_only_by_decision() {
        for sql in [
            "SELECT * FROM t FOR UPDATE",
            "SELECT * FROM t FOR SHARE",
            "SELECT * FROM t FOR UPDATE NOWAIT",
        ] {
            assert_eq!(classify(&parse1(sql)), SqlAccess::ReadOnly, "{sql}");
        }
    }

    /// A STATED LIMIT, pinned so it cannot be forgotten: a function with a
    /// side effect is invisible to a statement-shape classifier. The worker's
    /// `check_disallowed_functions` deny-list is the surface that can see it.
    #[test]
    fn function_side_effects_are_out_of_range_and_read_as_reads() {
        for sql in [
            "SELECT nextval('s')",
            "SELECT setval('s', 1)",
            "SELECT pg_catalog.setval('s', 1)",
        ] {
            assert_eq!(
                classify(&parse1(sql)),
                SqlAccess::ReadOnly,
                "documented gap changed: {sql}"
            );
        }
    }

    /// F4, MEASURED rather than assumed. The AST this crate walks is shallow
    /// because sqlparser bounds its OWN parse recursion
    /// (`DEFAULT_REMAINING_DEPTH = 50`): deeply nested guest SQL is refused by
    /// the parser, so no deep tree is ever handed to the walk, the `Drop`, or
    /// the controller.
    ///
    /// Measured threshold on sqlparser 0.53 + `PostgreSqlDialect`: depth 45
    /// parses, depth 48 is a `ParserError`. Both nesting shapes are checked —
    /// a derived-table chain and a CTE chain — because they descend through
    /// different parser functions.
    ///
    /// **The stack question, answered with numbers instead of a claim.** Run
    /// under a **release** build (what the fleet ships) a 3 500-deep, 124 KB
    /// input parses to `Err` with no overflow on a 2 MiB stack (tokio's worker
    /// default) or an 8 MiB one. Under a **debug** build the same input
    /// overflows a 2 MiB stack at depth 50, because debug parser frames are
    /// ~40× larger; that is a `cargo test` / dev-binary hazard, not a
    /// production one, and it is the reason this test asserts the RECURSION
    /// LIMIT (the actual guard, identical in both profiles) rather than
    /// asserting "no overflow" under a small stack — an assertion whose
    /// outcome would be decided by the build profile rather than by the code.
    /// The 16 MiB thread below exists only to make the test deterministic
    /// across profiles.
    ///
    /// Both consumers additionally cap the SQL byte length BEFORE parsing (the
    /// worker's `MAX_SQL_BYTES`, the controller's
    /// `database_rpc::validate_structure`), so the parser is never even
    /// offered an unbounded string.
    #[test]
    fn parse_depth_is_bounded_by_sqlparsers_recursion_limit() {
        fn parse_in_a_deep_stack(sql: String) -> bool {
            std::thread::Builder::new()
                .stack_size(16 * 1024 * 1024)
                .spawn(move || Parser::parse_sql(&PostgreSqlDialect {}, &sql).is_err())
                .expect("spawn")
                .join()
                .expect("parser must return, not abort")
        }
        let derived = |d: usize| {
            format!(
                "SELECT * FROM ({}SELECT 1{}) x",
                "SELECT * FROM (".repeat(d),
                ") y".repeat(d)
            )
        };
        let ctes = |d: usize| {
            let mut sql = String::from("SELECT 1");
            for i in 0..d {
                sql = format!("WITH c{i} AS ({sql}) SELECT * FROM c{i}");
            }
            sql
        };

        for shape in [&derived as &dyn Fn(usize) -> String, &ctes] {
            // Shallow nesting is legitimate SQL and must still parse.
            assert!(
                !parse_in_a_deep_stack(shape(40)),
                "depth 40 must parse — the limit must not be tightened silently"
            );
            // Beyond the limit the parser refuses, at every depth up to and
            // past what the callers' byte caps admit.
            for d in [48usize, 100, 1_000, 3_500] {
                assert!(
                    parse_in_a_deep_stack(shape(d)),
                    "depth {d} must be refused by the recursion limit"
                );
            }
        }
    }

    /// Mutation guard: deleting the nested walk must break the CTE cases and
    /// ONLY the CTE cases. Encoded as a positive assertion that the walk is
    /// what separates them — the root-variant match alone calls every CTE
    /// shape a read.
    #[test]
    fn the_nested_walk_is_what_catches_the_cte_shapes() {
        let root_only = |stmt: &Statement| {
            matches!(
                stmt,
                Statement::Insert(_)
                    | Statement::Update { .. }
                    | Statement::Delete(_)
                    | Statement::Merge { .. }
            )
        };
        let cte_shapes = [
            "WITH ins AS (INSERT INTO t (a) VALUES (1) RETURNING a) SELECT * FROM ins",
            "WITH d AS (UPDATE t SET a = 1 RETURNING a) SELECT * FROM d",
            "SELECT * FROM (WITH x AS (INSERT INTO t VALUES (1) RETURNING 1) SELECT * FROM x) y",
        ];
        for sql in cte_shapes {
            let stmt = parse1(sql);
            assert!(
                !root_only(&stmt),
                "root-only match calls this a read: {sql}"
            );
            assert_eq!(
                classify(&stmt),
                SqlAccess::Mutates { nested: true },
                "{sql}"
            );
        }
    }
}
