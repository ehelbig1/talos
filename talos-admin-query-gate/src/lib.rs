//! # What SQL the platform-admin `query_paginated` tool runs
//!
//! `query_paginated` runs SQL its caller writes, across every tenant, on the
//! controller's pool (`talos_advanced_repository::AdvancedRepository::
//! execute_paginated_select`, inside `BEGIN READ ONLY` on a connection that is
//! closed afterwards). Until 2026-10-08 the statement was never parsed: rules
//! over its text decided what ran. This crate is the validation, out of the
//! MCP handler, in two layers asked in order by [`validate_paginated_query`]:
//!
//! 1. **The text rules** ([`text_rule_refusal`]) — the rules the handler has
//!    applied since MCP-627 / MCP-1002, unchanged: begins with `SELECT`, no
//!    `;`, no `UNION` / `INTERSECT` / `EXCEPT`, no comments, no `WITH`, no
//!    `EXPLAIN`, no word naming a table in [`BLOCKED_TABLES_LIST`], no word
//!    naming a system schema. Kept in front of the parsed gate; which of them
//!    the parsed gate makes redundant is recorded in
//!    `docs/engineering-log/packages/2026-10-08-sql-function-allow-list.md`,
//!    and removing any is a later decision.
//! 2. **The parsed gate** ([`parsed_refusal`]) — the statement as `sqlparser`
//!    reads it with the Postgres dialect:
//!    * it parses, and is exactly one statement;
//!    * it is a read (`talos_sql_classify::is_read_only`): no write, no
//!      data-modifying CTE, no `SELECT … INTO`, no `EXPLAIN`;
//!    * every function it calls is admitted by THE function allow list
//!      (`talos_workflow_job_protocol::is_allowed_sql_function`, through
//!      `talos_sql_classify::first_function_not_admitted` — the gate module
//!      SQL asks too);
//!    * every relation it reads is unqualified or `public.`-qualified, is not
//!      a system catalog (`pg_*`), and is not on [`BLOCKED_TABLES_LIST`].
//!
//! The parsed gate checks NAMES. What a name resolves to is the server's
//! business: an unqualified name is resolved on the session's `search_path`,
//! and a view reads its tables as its owner. The role the statement runs as
//! is what bounds that (a least-privilege role is the next package).
//!
//! The gate's verdicts over the shared SQL corpus are recorded in
//! `talos-sql-classify/corpus/query_paginated.snapshot` (`tests/sql_corpus.rs`).

use sqlparser::ast::{Ident, Statement};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;
use std::ops::ControlFlow;
use talos_sql_classify::ReadRelation;

/// The longest query the tool accepts, in bytes.
pub const MAX_QUERY_BYTES: usize = 10_000;

/// System schemas the text rules refuse by name.
pub const BLOCKED_SCHEMAS: &[&str] = &["pg_catalog", "information_schema", "pg_toast"];

/// Why `query_paginated` refuses a query. [`QueryRefusal::message`] is what
/// the caller is told; it names what was refused and never carries a parser
/// or database error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryRefusal {
    /// No query, or an empty one.
    Empty,
    /// Longer than [`MAX_QUERY_BYTES`].
    TooLong,
    // ── The text rules ──────────────────────────────────────────────────
    /// Does not begin with `SELECT`.
    NotSelect,
    /// Contains `;`.
    Semicolon,
    /// Contains `UNION`, `INTERSECT` or `EXCEPT`.
    SetOperation,
    /// Contains `--` or `/*`.
    Comment,
    /// Begins with `WITH `.
    Cte,
    /// Begins with `EXPLAIN`.
    Explain,
    /// Names a table in [`BLOCKED_TABLES_LIST`] anywhere in its text.
    BlockedTable(&'static str),
    /// Names a schema in [`BLOCKED_SCHEMAS`] anywhere in its text.
    BlockedSchema(&'static str),
    // ── The parsed gate ─────────────────────────────────────────────────
    /// `sqlparser` (Postgres dialect) does not parse it.
    Unparseable,
    /// It parses to this many statements, not one.
    NotOneStatement(usize),
    /// It parses, and is not a read.
    NotRead,
    /// It calls a function the allow list does not admit, spelled as
    /// written (`current_setting`, `public.f`, `"F"`).
    Function(String),
    /// It reads a relation the gate does not admit.
    Relation {
        /// The relation's name as written.
        name: String,
        /// Which rule refused it.
        rule: RelationRule,
    },
}

/// The rule that refused a relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationRule {
    /// Qualified by a schema other than `public`, or by more than a schema,
    /// or a name with a part that is not an identifier.
    NotPublic,
    /// A name beginning `pg_`: a system catalog or view, or an extension's
    /// (`pg_stat_statements`).
    SystemCatalog,
    /// On [`BLOCKED_TABLES_LIST`].
    Blocked,
    /// An unquoted relation named `only`: sqlparser 0.63 reads
    /// `FROM ONLY t` as a table named `ONLY` aliased `t`, where Postgres
    /// reads table `t`, so the name the gate would check is not the table the
    /// server reads.
    OnlyKeyword,
    /// `TABLE t`, which this gate has no shape for.
    TableCommand,
}

impl QueryRefusal {
    /// What the caller is told. The text rules keep the exact messages the
    /// handler gave before 2026-10-08.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            QueryRefusal::Empty => "Missing or empty 'query' parameter".to_string(),
            QueryRefusal::TooLong => "query must be ≤ 10 000 characters".to_string(),
            QueryRefusal::NotSelect => "Only SELECT queries are allowed".to_string(),
            QueryRefusal::Semicolon => "Query must not contain semicolons".to_string(),
            QueryRefusal::SetOperation => {
                "Query cannot contain UNION, INTERSECT, or EXCEPT clauses".to_string()
            }
            QueryRefusal::Comment => "Query cannot contain SQL comments".to_string(),
            QueryRefusal::Cte => "CTEs (WITH ... AS) are not allowed".to_string(),
            QueryRefusal::Explain => "EXPLAIN queries are not allowed".to_string(),
            QueryRefusal::BlockedTable(table) => {
                format!("Access to '{table}' is not permitted via query_paginated")
            }
            QueryRefusal::BlockedSchema(schema) => {
                format!("Access to '{schema}' schema is not permitted via query_paginated")
            }
            QueryRefusal::Unparseable => {
                "query_paginated could not parse this query as a Postgres statement".to_string()
            }
            QueryRefusal::NotOneStatement(n) => {
                format!("query_paginated runs exactly one statement; this query has {n}")
            }
            QueryRefusal::NotRead => "query_paginated runs only a query that reads: no \
                 INSERT / UPDATE / DELETE / MERGE, data-modifying CTE, SELECT … INTO or EXPLAIN"
                .to_string(),
            QueryRefusal::Function(name) => format!(
                "query_paginated: function `{name}` is not on the list of functions a query may \
                 call (talos_workflow_job_protocol::ALLOWED_SQL_FUNCTIONS; a bare or pg_catalog \
                 name of a function that changes nothing, reads nothing stored beyond its \
                 arguments and runs no SQL)"
            ),
            QueryRefusal::Relation { name, rule } => match rule {
                RelationRule::NotPublic => format!(
                    "query_paginated reads only tables in the public schema, named bare or \
                     public-qualified; '{name}' is not"
                ),
                RelationRule::SystemCatalog => format!(
                    "query_paginated does not read system catalogs or views (a name beginning \
                     pg_); '{name}' is one"
                ),
                RelationRule::Blocked => {
                    format!("Access to '{name}' is not permitted via query_paginated")
                }
                RelationRule::OnlyKeyword => {
                    "query_paginated does not support FROM ONLY; name the table alone".to_string()
                }
                RelationRule::TableCommand => {
                    "query_paginated does not support the TABLE command; use SELECT * FROM"
                        .to_string()
                }
            },
        }
    }
}

/// Validate a query for `query_paginated`: the length checks, the text rules,
/// then the parsed gate. Returns the query to run (trimmed, a trailing `;`
/// removed — none survives the text rules today) or the first refusal.
pub fn validate_paginated_query(query: &str) -> Result<&str, QueryRefusal> {
    if query.len() > MAX_QUERY_BYTES {
        return Err(QueryRefusal::TooLong);
    }
    if query.is_empty() {
        return Err(QueryRefusal::Empty);
    }
    let trimmed = query.trim();
    if let Some(refusal) = text_rule_refusal(trimmed) {
        return Err(refusal);
    }
    if let Some(refusal) = parsed_refusal(trimmed) {
        return Err(refusal);
    }
    Ok(trimmed.trim_end_matches(';'))
}

/// The text rules, as the handler applied them until 2026-10-08 (MCP-627,
/// MCP-1002), on the trimmed query. `None` when every rule passes.
#[must_use]
pub fn text_rule_refusal(trimmed: &str) -> Option<QueryRefusal> {
    let query_upper = trimmed.to_uppercase();
    if !query_upper.starts_with("SELECT") {
        return Some(QueryRefusal::NotSelect);
    }
    // Statement chaining.
    if trimmed.contains(';') {
        return Some(QueryRefusal::Semicolon);
    }
    if query_upper.contains("UNION")
        || query_upper.contains("INTERSECT")
        || query_upper.contains("EXCEPT")
    {
        return Some(QueryRefusal::SetOperation);
    }
    if trimmed.contains("--") || trimmed.contains("/*") {
        return Some(QueryRefusal::Comment);
    }
    // CTEs and EXPLAIN, which can reveal schema or bypass table restrictions.
    // (Unreachable behind the SELECT prefix rule; kept as the handler had it.)
    if query_upper.starts_with("WITH ") {
        return Some(QueryRefusal::Cte);
    }
    if query_upper.starts_with("EXPLAIN") {
        return Some(QueryRefusal::Explain);
    }
    if let Some(table) = blocked_table_in_query(trimmed) {
        return Some(QueryRefusal::BlockedTable(table));
    }
    // Same lowercase + dequote normalization as the table match.
    let unquoted = trimmed.to_lowercase().replace('"', " ");
    BLOCKED_SCHEMAS
        .iter()
        .find(|schema| unquoted.contains(*schema))
        .map(|schema| QueryRefusal::BlockedSchema(schema))
}

/// The parsed gate (2026-10-08) on its own: what it refuses in `query`, or
/// `None`. [`validate_paginated_query`] asks it after the text rules; the
/// corpus records both layers' verdicts separately.
#[must_use]
pub fn parsed_refusal(query: &str) -> Option<QueryRefusal> {
    let statements = match Parser::parse_sql(&PostgreSqlDialect {}, query) {
        Ok(statements) => statements,
        Err(_) => return Some(QueryRefusal::Unparseable),
    };
    let [statement] = statements.as_slice() else {
        return Some(QueryRefusal::NotOneStatement(statements.len()));
    };
    statement_refusal(statement)
}

fn statement_refusal(statement: &Statement) -> Option<QueryRefusal> {
    if !talos_sql_classify::is_read_only(statement) {
        return Some(QueryRefusal::NotRead);
    }
    if let Some(name) = talos_sql_classify::first_function_not_admitted(
        statement,
        talos_workflow_job_protocol::is_allowed_sql_function,
    ) {
        return Some(QueryRefusal::Function(name));
    }
    match talos_sql_classify::try_for_each_relation(statement, |relation| {
        match relation_refusal(relation) {
            Some(refusal) => ControlFlow::Break(refusal),
            None => ControlFlow::Continue(()),
        }
    }) {
        ControlFlow::Break(refusal) => Some(refusal),
        ControlFlow::Continue(()) => None,
    }
}

fn relation_refusal(relation: ReadRelation<'_>) -> Option<QueryRefusal> {
    let name = match relation {
        ReadRelation::Named(name) => name,
        ReadRelation::TableCommand => {
            return Some(QueryRefusal::Relation {
                name: "TABLE".to_string(),
                rule: RelationRule::TableCommand,
            })
        }
    };
    let refuse = |rule| {
        Some(QueryRefusal::Relation {
            name: name.to_string(),
            rule,
        })
    };
    let Some(parts) = name
        .0
        .iter()
        .map(|part| part.as_ident())
        .collect::<Option<Vec<&Ident>>>()
    else {
        return refuse(RelationRule::NotPublic);
    };
    let table = match parts.as_slice() {
        [table] => *table,
        [schema, table] if folded(schema) == "public" => *table,
        _ => return refuse(RelationRule::NotPublic),
    };
    // Compared without regard to case even when quoted: stricter than
    // Postgres, which would read `"USERS"` as a different table from `users`.
    let table_name = folded(table).to_ascii_lowercase();
    if table.quote_style.is_none() && table_name == "only" {
        return refuse(RelationRule::OnlyKeyword);
    }
    if table_name.starts_with("pg_") {
        return refuse(RelationRule::SystemCatalog);
    }
    if BLOCKED_TABLES_LIST.contains(&table_name.as_str()) {
        return refuse(RelationRule::Blocked);
    }
    None
}

/// An identifier as Postgres reads it: an unquoted one folded to lower case,
/// a quoted one as written.
fn folded(ident: &Ident) -> String {
    match ident.quote_style {
        None => ident.value.to_ascii_lowercase(),
        Some(_) => ident.value.clone(),
    }
}

/// MCP-1002 (2026-05-15): single source of truth for the
/// `query_paginated` blocklist of auth/credential/bearer-token tables.
/// Module-scoped so both the function-level runtime guard AND the
/// precompiled `BLOCKED_TABLE_RES` regex set reference the same
/// compile-time list. Pre-fix the list was duplicated between an outer
/// function-scope `const` and an inner `const TABLES` inside the
/// LazyLock initializer — a swap between the two would have escaped
/// the `debug_assert_eq!` length-only check.
pub const BLOCKED_TABLES_LIST: &[&str] = &[
    "user_sessions",
    "mcp_agents",
    "encryption_keys",
    "oauth_accounts",
    "oauth_credential",
    "refresh_tokens",
    "users",
    "secrets",
    "secret_audit_log",
    "totp_secrets",
    "auth_events",
    "admin_event_log",
    "workflow_approval_gates",
    // MCP-1002 (2026-05-15): four tables added to the blocklist —
    //   * `workflow_approval_gates` — the `token` column IS the bearer
    //     auth for `approval_gate_handler`. Anyone holding the
    //     64-hex-char token can approve/reject the corresponding
    //     workflow gate (no session, no API key). A platform admin
    //     listing rows from this table would gain consent-bypass over
    //     every pending approval gate across all tenants.
    //   * `api_keys` — `key_hash` is bcrypt'd but `key_prefix`,
    //     `user_id`, `scopes`, `expires_at`, `last_used_at` collectively
    //     form a reconnaissance set: who has admin scope across which
    //     tenants, which keys are stale-but-active, etc. Same blocklist
    //     class as the rest of the credential family.
    //   * `oauth_state_tokens` — `pkce_verifier` is short-lived (10 min
    //     TTL, consumed-on-first-use) credential material. Reading
    //     in-flight verifiers would let an attacker who's already
    //     intercepted the OAuth callback URL complete the
    //     code-for-token exchange.
    //   * `user_capability_grants` — cross-tenant elevation enumeration
    //     surface (the QUERY counterpart of the data MCP-998 closed on
    //     the GraphQL side). Same "list every elevated user
    //     platform-wide" reconnaissance shape, just via a different
    //     tool surface.
    // (Moved here from the `query_paginated` handler with the list,
    // 2026-10-08.)
    "api_keys",
    "oauth_state_tokens",
    "user_capability_grants",
    // MCP-1009 (2026-06-23): integration/webhook tables that still hold
    // credential-class material reachable cross-tenant by this
    // platform-admin-only tool. The OAuth *plaintext* token columns were
    // already dropped (migrations 20260310001300 + 036 + 20260413000002/3),
    // so this is NOT a plaintext leak — but the surviving columns are still
    // credential-class and no single role should bulk-exfiltrate them:
    //   * `slack_integrations` — `bot_token_enc` / `access_token_enc`
    //     (AES-256-GCM ciphertext, mig 018) + a still-PLAINTEXT
    //     `verification_token VARCHAR` (mig 004, never dropped).
    //   * `webhook_triggers` (renamed from `webhook_listeners` in mig 015)
    //     — still-PLAINTEXT `verification_token TEXT NOT NULL` (the inbound
    //     webhook bearer) + `signing_secret_enc` BYTEA / `signing_key_id`
    //     (mig 20260312000200; plaintext `signing_secret` dropped in
    //     20260408000002).
    //   * `google_calendar_watch_channels` — had a still-PLAINTEXT
    //     `verification_token TEXT NOT NULL` (the per-channel webhook secret,
    //     mig 010_watch_channel_security). DROPPED 2026-09-12 (migration
    //     20260912100000): channels moved to `integration_state` and the table
    //     had held zero rows with no writer. The deny-list entry is RETAINED as
    //     forward-protection, the `workspace_oci_settings` precedent below.
    //   * `workspace_oci_settings` — DROPPED as dead/never-wired schema
    //     (mig 20260627120000; it had `password_encrypted`/`password_nonce`
    //     columns but no crypto code ever populated them — OCI creds come from
    //     env vars). The deny-list entry is RETAINED as forward-protection: if
    //     the per-workspace-creds feature is ever rebuilt, it stays
    //     export-blocked by default.
    // Deliberately NOT added: `gmail_integrations` and
    // `google_calendar_integrations` — both plaintext AND encrypted token
    // columns were dropped from these (036/20260310001300 +
    // 20260413000002/3); no credential-class column survives (tokens now
    // live in `integration_state` / the `secrets` table, already blocked).
    "slack_integrations",
    "webhook_triggers",
    "google_calendar_watch_channels",
    "workspace_oci_settings",
];

/// MCP-627 / MCP-1002: the precompiled per-table word-boundary regex set
/// used by `query_paginated`'s blocklist guard. Compiled ONCE (fail-closed
/// at first use if a pattern can't compile — impossible in practice since
/// patterns are `regex::escape`d over `[a-z0-9_]` strings) and shared by
/// both the runtime guard and the unit tests so the test exercises the
/// real production matcher rather than a drifting copy (Talos testing
/// convention: extract, don't shadow).
pub static BLOCKED_TABLE_RES: std::sync::LazyLock<Vec<(&'static str, regex::Regex)>> =
    std::sync::LazyLock::new(|| {
        BLOCKED_TABLES_LIST
            .iter()
            .map(|t| {
                let pattern = format!(r"(?:^|[^a-z0-9_]){}(?:$|[^a-z0-9_])", regex::escape(t));
                let re = regex::Regex::new(&pattern)
                    .expect("BUG: BLOCKED_TABLES word-boundary regex must compile");
                (*t, re)
            })
            .collect()
    });

/// Returns `Some(table)` if `query` references a blocked credential/auth
/// table (after the same lowercase + dequote normalization the handler
/// applies), else `None`. Single source of truth for the blocklist match
/// so the `query_paginated` guard and its unit tests share one code path.
pub fn blocked_table_in_query(query: &str) -> Option<&'static str> {
    // Normalize: lowercase, then strip SQL quoted identifiers so "Users"
    // / "USERS" / `"users"` are all caught.
    let unquoted = query.to_lowercase().replace('"', " ");
    for (table, re) in BLOCKED_TABLE_RES.iter() {
        if re.is_match(&unquoted) {
            return Some(table);
        }
    }
    None
}

#[cfg(test)]
mod blocked_tables_tests {
    use super::{blocked_table_in_query, BLOCKED_TABLES_LIST, BLOCKED_TABLE_RES};

    /// The runtime guard's `debug_assert_eq!` only fires in debug builds;
    /// pin the regex-set / list lockstep here so a release build can't
    /// drift either (every list entry MUST get a compiled regex).
    #[test]
    fn regex_set_matches_list_length() {
        assert_eq!(
            BLOCKED_TABLE_RES.len(),
            BLOCKED_TABLES_LIST.len(),
            "every blocked table must have a compiled word-boundary regex"
        );
    }

    /// Every table in the canonical list must be caught when referenced
    /// in a representative SELECT — guards against a list entry whose
    /// regex somehow fails to match its own name.
    #[test]
    fn every_listed_table_is_blocked() {
        for t in BLOCKED_TABLES_LIST {
            let q = format!("SELECT * FROM {t} LIMIT 10");
            assert_eq!(
                blocked_table_in_query(&q),
                Some(*t),
                "blocklist must reject a query against {t}"
            );
        }
    }

    /// MCP-1009: the four newly-added integration/webhook credential
    /// tables must be rejected — including across casing and quoted-
    /// identifier bypass attempts the normalization is meant to defeat.
    #[test]
    fn mcp_1009_integration_tables_blocked() {
        let cases: &[(&str, &str)] = &[
            ("slack_integrations", "SELECT * FROM slack_integrations"),
            (
                "slack_integrations",
                r#"SELECT verification_token FROM "Slack_Integrations""#,
            ),
            ("webhook_triggers", "SELECT * FROM webhook_triggers"),
            (
                "webhook_triggers",
                "select signing_secret_enc from WEBHOOK_TRIGGERS where id=1",
            ),
            (
                "google_calendar_watch_channels",
                "SELECT verification_token FROM google_calendar_watch_channels",
            ),
            (
                "google_calendar_watch_channels",
                r#"SELECT * FROM "GOOGLE_CALENDAR_WATCH_CHANNELS""#,
            ),
            (
                "workspace_oci_settings",
                "SELECT password_encrypted FROM workspace_oci_settings",
            ),
            (
                "workspace_oci_settings",
                "select * from Workspace_OCI_Settings",
            ),
        ];
        for (expected, query) in cases {
            assert_eq!(
                blocked_table_in_query(query),
                Some(*expected),
                "query {query:?} must be blocked as {expected}"
            );
        }
    }

    /// Negative controls: the deliberately-NOT-blocked integration tables
    /// (no credential-class column survives the token-drop migrations) and
    /// an unrelated table must pass. A substring of a blocked name (e.g.
    /// `my_workspace_oci_settings_archive`) is intentionally NOT a
    /// word-boundary match and so is allowed.
    #[test]
    fn unrelated_and_dropped_token_tables_allowed() {
        for q in [
            "SELECT * FROM gmail_integrations",
            "SELECT * FROM google_calendar_integrations",
            "SELECT * FROM workflow_executions",
            "SELECT * FROM my_workspace_oci_settings_archive",
        ] {
            assert_eq!(
                blocked_table_in_query(q),
                None,
                "query {q:?} should NOT be blocked"
            );
        }
    }
}

#[cfg(test)]
mod parsed_gate_tests {
    use super::{parsed_refusal, validate_paginated_query, QueryRefusal, RelationRule};

    fn relation(sql: &str) -> Option<(String, RelationRule)> {
        match parsed_refusal(sql) {
            Some(QueryRefusal::Relation { name, rule }) => Some((name, rule)),
            None => None,
            other => panic!("expected a relation verdict for `{sql}`, got {other:?}"),
        }
    }

    /// A read of public tables that calls only listed functions passes.
    #[test]
    fn an_ordinary_read_passes() {
        for sql in [
            "SELECT 1",
            "SELECT id, status FROM workflow_executions WHERE created_at > now() - interval '1 day'",
            "SELECT count(*), max(created_at) FROM public.workflow_executions GROUP BY status",
            "SELECT * FROM t JOIN u ON t.id = u.t_id WHERE EXISTS (SELECT 1 FROM v WHERE v.id = t.id)",
            "WITH w AS (SELECT a FROM t) SELECT * FROM w",
            "SELECT * FROM \"only\"",
            "SELECT * FROM generate_series(1, 3) g",
            "SELECT pg_catalog.lower(name) FROM t",
        ] {
            assert_eq!(parsed_refusal(sql), None, "{sql}");
        }
    }

    /// Only a table in `public`, named bare or `public.`, is read.
    #[test]
    fn a_relation_outside_public_is_refused() {
        for (sql, name) in [
            ("SELECT * FROM other.t", "other.t"),
            (
                "SELECT * FROM information_schema.tables",
                "information_schema.tables",
            ),
            ("SELECT * FROM db.public.t", "db.public.t"),
            ("SELECT * FROM \"Public\".t", "\"Public\".t"),
            (
                "SELECT * FROM t WHERE a IN (SELECT a FROM other.u)",
                "other.u",
            ),
        ] {
            assert_eq!(
                relation(sql),
                Some((name.to_string(), RelationRule::NotPublic)),
                "{sql}"
            );
        }
        assert_eq!(relation("SELECT * FROM PUBLIC.t"), None);
    }

    /// A system catalog or view — any name beginning `pg_` — is refused,
    /// bare or qualified, in any position.
    #[test]
    fn a_system_catalog_is_refused() {
        for (sql, name, rule) in [
            (
                "SELECT * FROM pg_class",
                "pg_class",
                RelationRule::SystemCatalog,
            ),
            (
                "SELECT * FROM PG_AUTHID",
                "PG_AUTHID",
                RelationRule::SystemCatalog,
            ),
            (
                "SELECT * FROM \"pg_class\"",
                "\"pg_class\"",
                RelationRule::SystemCatalog,
            ),
            (
                "SELECT * FROM public.pg_stat_statements",
                "public.pg_stat_statements",
                RelationRule::SystemCatalog,
            ),
            (
                "SELECT * FROM pg_catalog.pg_class",
                "pg_catalog.pg_class",
                RelationRule::NotPublic,
            ),
            (
                "SELECT (SELECT count(*) FROM pg_roles) FROM t",
                "pg_roles",
                RelationRule::SystemCatalog,
            ),
        ] {
            assert_eq!(relation(sql), Some((name.to_string(), rule)), "{sql}");
        }
    }

    /// `BLOCKED_TABLES_LIST` is the one list of withheld tables, and the
    /// parsed gate asks it for every relation, however it is spelled.
    #[test]
    fn a_blocked_table_is_refused_by_the_parsed_gate() {
        for t in super::BLOCKED_TABLES_LIST {
            for sql in [
                format!("SELECT * FROM {t}"),
                format!("SELECT * FROM public.{t}"),
                format!("SELECT * FROM \"{t}\""),
                format!("SELECT * FROM {}", t.to_ascii_uppercase()),
                format!("SELECT * FROM x WHERE EXISTS (SELECT 1 FROM {t})"),
            ] {
                assert!(
                    matches!(relation(&sql), Some((_, RelationRule::Blocked))),
                    "{sql}"
                );
            }
        }
    }

    /// sqlparser reads `FROM ONLY t` as a table named ONLY; the gate refuses
    /// it rather than check a name the server does not read.
    #[test]
    fn from_only_is_refused() {
        assert_eq!(
            relation("SELECT * FROM ONLY users"),
            Some(("ONLY".to_string(), RelationRule::OnlyKeyword))
        );
        // `FROM ONLY (t)` parses as a call to a function named ONLY.
        assert_eq!(
            parsed_refusal("SELECT * FROM ONLY (users)"),
            Some(QueryRefusal::Function("only".to_string()))
        );
    }

    /// Only a function the allow list admits may be called.
    #[test]
    fn a_function_the_allow_list_does_not_admit_is_refused() {
        for (sql, name) in [
            (
                "SELECT current_setting('server_version')",
                "current_setting",
            ),
            ("SELECT pg_read_file('x')", "pg_read_file"),
            ("SELECT * FROM t WHERE a = public.lower(b)", "public.lower"),
            ("SELECT ts_stat('SELECT 1')", "ts_stat"),
            ("SELECT * FROM t, LATERAL my_func(t.a) f", "my_func"),
            (
                "SELECT * FROM XMLTABLE('/r' PASSING x COLUMNS a int PATH 'a')",
                "xmltable",
            ),
        ] {
            assert_eq!(
                parsed_refusal(sql),
                Some(QueryRefusal::Function(name.to_string())),
                "{sql}"
            );
        }
    }

    #[test]
    fn only_one_read_that_parses_is_run() {
        assert_eq!(parsed_refusal("SELEC 1"), Some(QueryRefusal::Unparseable));
        assert_eq!(
            parsed_refusal("SELECT 1; SELECT 2"),
            Some(QueryRefusal::NotOneStatement(2))
        );
        for sql in [
            "WITH x AS (INSERT INTO t (a) VALUES (1) RETURNING a) SELECT * FROM x",
            "SELECT * INTO new_table FROM t",
            "EXPLAIN SELECT 1",
            "DELETE FROM t",
        ] {
            assert_eq!(parsed_refusal(sql), Some(QueryRefusal::NotRead), "{sql}");
        }
    }

    /// The text rules run first and keep their messages; the parsed gate runs
    /// on what they admit.
    #[test]
    fn the_text_rules_run_before_the_parsed_gate() {
        assert_eq!(validate_paginated_query(""), Err(QueryRefusal::Empty));
        assert_eq!(
            validate_paginated_query(&"x".repeat(10_001)),
            Err(QueryRefusal::TooLong)
        );
        assert_eq!(
            validate_paginated_query("SELECT * FROM users"),
            Err(QueryRefusal::BlockedTable("users"))
        );
        assert_eq!(
            validate_paginated_query("SELECT * FROM pg_catalog.pg_class"),
            Err(QueryRefusal::BlockedSchema("pg_catalog"))
        );
        assert_eq!(
            validate_paginated_query("SELECT current_setting('x')"),
            Err(QueryRefusal::Function("current_setting".to_string()))
        );
        assert_eq!(
            validate_paginated_query("  SELECT a FROM t  "),
            Ok("SELECT a FROM t")
        );
        assert_eq!(
            QueryRefusal::BlockedTable("users").message(),
            "Access to 'users' is not permitted via query_paginated"
        );
    }
}
