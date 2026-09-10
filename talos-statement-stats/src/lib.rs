//! The one reader of `pg_stat_statements` (2026-09-10).
//!
//! `#786` turned the COLLECTION on — `shared_preload_libraries=pg_stat_statements`
//! in `docker-compose.yml` plus the guarded migration
//! `20260908120000_pg_stat_statements_when_preloaded.sql` — and shipped no
//! reader, so every statement this platform issues has been timed by the server
//! and read by nothing. This crate is the reader.
//!
//! # Why availability is a five-valued classification and not a `Result`
//!
//! The extension is OPTIONAL BY DESIGN. `shared_preload_libraries` is a
//! POSTMASTER GUC, so enabling it costs a database restart, and #786
//! deliberately did not change the Helm chart for that reason. On most
//! deployments the migration's no-op arm is what ran and this relation does not
//! exist. A reader that answers "no slow statements" there is the
//! misleading-report class (checks 74 / 76 / 79 / 81) in its quietest form: a
//! determinate negative over an instrument that was never asked.
//!
//! So [`StatementStatsRead`] separates, each MEASURED on a real server rather
//! than assumed:
//!
//! * [`StatementStatsRead::NotInstalled`] — no `pg_extension` row. The
//!   migration's no-op arm; the common case.
//! * [`StatementStatsRead::NotLoaded`] — extension row exists, the view raises
//!   `55000`. Reproduced in a throwaway `pgvector/pgvector:pg17` container with
//!   no preload: `CREATE EXTENSION` SUCCEEDS and the first read raises
//!   `55000: pg_stat_statements must be loaded via "shared_preload_libraries"`.
//! * [`StatementStatsRead::Unreadable`] — anything else. Never rendered as
//!   empty.
//! * [`StatementStatsRead::Available`] with rows — working.
//! * [`StatementStatsRead::Available`] with none — working, nothing tracked.
//!   Only reachable right after a reset.
//!
//! # Why the query text is sanitised, and why that is not paranoia
//!
//! `pg_stat_statements` NORMALISES CONSTANTS. Measured directly — two
//! statements differing only in an embedded string literal collapse to ONE
//! entry with `calls = 2`, and the sandbox's own CTE wrap normalises down to
//! `note = $1 … LIMIT $3`. Bind parameters and literals embedded in the SQL
//! text are treated identically, because jumbling replaces `Const` nodes and
//! does not care how the constant reached the parser.
//!
//! What it does NOT normalise is where the risk is, and all three were measured:
//!
//! 1. **IDENTIFIERS**, above all column ALIASES —
//!    `SELECT $1 AS "exfil-via-alias: card 4111-1111-1111-1111"` is stored
//!    verbatim, and the alias is arbitrary caller-chosen text.
//! 2. **COMMENTS** — `SELECT $1 /* anything at all */` is stored verbatim.
//! 3. **UTILITY statements** (`pg_stat_statements.track_utility` defaults ON)
//!    — stored as written. This deployment carries
//!    `SET LOCAL app.current_user_id = '<uuid>'` in the view right now, because
//!    `SET LOCAL` cannot bind parameters and
//!    `talos_tenancy::TenantReadScope::set_local_user_sql` formats the UUID in.
//!
//! So query text here is, in the general case, **arbitrary caller-authorable
//! bytes**. [`sanitize_query_text`] therefore maps every control character AND
//! every Unicode bidi/format control to a space, collapses whitespace and
//! truncates — not for confidentiality (the caller is a platform admin who can
//! already read every row) but for the INTEGRITY of the surface it lands in: a
//! `database`-world module must not be able to plant an ANSI escape, a
//! right-to-left override or a forged line break in an operator's console.
//!
//! This is deliberately NOT `talos_validation::reject_control_chars`. That
//! function REJECTS an input the platform is about to store; this one SANITISES
//! a value already on disk that cannot be rejected. Different question, so a
//! separate implementation rather than a second answer to one question.
//!
//! # Dependency posture
//!
//! Leaf: `sqlx`, `serde`, `serde_json`, `chrono`, `tracing`. It reads no
//! configuration — the guest-role fence is passed IN by the caller
//! ([`GuestAttribution`]) so this crate cannot become a second reader of
//! `TALOS_RPC_GUEST_ROLE` and disagree with `guest_role_for_query` about
//! whether the fence is on.

use serde::Serialize;

/// Hard cap on the sanitised query text of one row.
///
/// A `pg_stat_statements` entry can hold a very long statement, and part of it
/// is caller-authorable (see the module docs), so the cap is the bound on what
/// a guest module can push into one operator-facing field.
pub const MAX_QUERY_TEXT_CHARS: usize = 400;

/// Hard cap on rows returned, whatever the caller asks for.
pub const MAX_ROWS: i64 = 50;

/// Default rows returned.
pub const DEFAULT_ROWS: i64 = 20;

/// Postgres' own marker for "this role may not see that statement's text".
///
/// Not an error and not the statement: a non-superuser without
/// `pg_read_all_stats` gets this literal string in the `query` column for
/// every statement it did not itself issue. Measured on this deployment: as
/// `talos_app`, **239 of 252** rows read exactly this.
pub const PG_REDACTED_MARKER: &str = "<insufficient privilege>";

/// What the reader established about `pg_stat_statements`.
///
/// `#[must_use]`, with no `Into<Option>` and no `.ok()`: the whole point is
/// that a caller cannot collapse "not available" into "available and empty".
/// Same shape as `ExecutionLookup` (#748) and `GraphLookup` (#764).
#[derive(Debug)]
#[must_use]
pub enum StatementStatsRead {
    /// No `pg_extension` row. The migration's no-op arm ran, or an operator
    /// never applied it. NOT a fault.
    NotInstalled,
    /// The extension is installed and the library is not preloaded, so the
    /// view raises on every read (`SQLSTATE 55000`). The migration exists to
    /// PREVENT this state; it is still reachable by removing the preload from
    /// a server that already had the extension.
    NotLoaded,
    /// The read failed for a reason that is not one of the two above. The
    /// class is a closed compile-time token — the underlying error text is
    /// LOGGED, never returned, because a Postgres error message can quote the
    /// statement and the statement can be caller-authored.
    Unreadable(ReadFailure),
    /// The view answered.
    Available(Box<StatementReport>),
}

/// Closed set of read-failure classes. Never carries the driver's message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadFailure {
    /// `pg_extension` itself could not be read — the pool is down, or worse.
    CatalogUnreadable,
    /// The extension row exists but the view does not (a broken install, or a
    /// `search_path` that cannot see it).
    ViewMissing,
    /// The connecting role may not read the view at all (`42501`).
    Denied,
    /// Anything else.
    QueryFailed,
}

impl ReadFailure {
    /// Stable token for the response and the log.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CatalogUnreadable => "catalog_unreadable",
            Self::ViewMissing => "view_missing",
            Self::Denied => "denied",
            Self::QueryFailed => "query_failed",
        }
    }
}

/// Whether guest (sandbox) SQL is attributable in this view.
///
/// `talos.database.query` runs caller-authored SQL. It runs under
/// `SET LOCAL ROLE <guest_role>` ONLY when `TALOS_RPC_GUEST_ROLE` is set to a
/// valid identifier; otherwise it runs as the APP USER and is
/// **indistinguishable in this view from the controller's own statements**.
/// That is the default posture (`enforce_production_db_sandbox_posture` forces
/// the fence only in production), and it is why a report that renders a role
/// name without saying which of the two it is would assert provenance the
/// deployment does not support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestAttribution {
    /// `TALOS_RPC_GUEST_ROLE` is set to a valid identifier; sandbox SQL
    /// carries that role in `userid`.
    Fenced(String),
    /// Unset or invalid: sandbox SQL is attributed to the app user.
    Unfenced,
}

/// Which ordering the caller asked for. A closed set — the SQL for each is a
/// separate `&'static str`, so no caller text ever reaches a statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderBy {
    /// Total execution time. The default: it is what a cost question asks.
    TotalTime,
    /// Call count. The N+1 lens.
    Calls,
    /// Mean execution time per call. The missing-index lens.
    MeanTime,
}

impl OrderBy {
    /// Parse the tool argument. `None` for an unrecognised value so the caller
    /// can refuse rather than silently reorder.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "total_time" => Some(Self::TotalTime),
            "calls" => Some(Self::Calls),
            "mean_time" => Some(Self::MeanTime),
            _ => None,
        }
    }

    /// Stable token for the response.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TotalTime => "total_time",
            Self::Calls => "calls",
            Self::MeanTime => "mean_time",
        }
    }
}

/// One row of the report.
#[derive(Debug, Clone, Serialize)]
pub struct StatementRow {
    /// The Postgres ROLE the statement ran as — not a Talos user. Rendered as
    /// a name where the oid resolves, else `oid:<n>`.
    pub role: String,
    /// `pg_stat_statements.queryid`. Stable across restarts for one PG major,
    /// so an operator can track one statement over time.
    pub queryid: Option<i64>,
    pub calls: i64,
    pub total_exec_ms: f64,
    pub mean_exec_ms: f64,
    pub max_exec_ms: f64,
    /// Rows returned or affected, summed across `calls`.
    pub rows: i64,
    /// `rows / calls`. `1.0` at a high call count is the N+1 signature.
    pub rows_per_call: f64,
    pub shared_blks_hit: i64,
    pub shared_blks_read: i64,
    /// Sanitised and truncated. Absent when Postgres redacted it — see
    /// `text_redacted`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// True when Postgres itself withheld the text from the connecting role.
    /// The field exists so a redacted row is not read as a statement whose
    /// text happens to be `<insufficient privilege>`.
    pub text_redacted: bool,
}

/// Everything the report says about its own coverage.
///
/// Every field here exists because the numbers above it are meaningless
/// without one of them. `window_seconds` in particular: `pg_stat_statements`
/// counters run from the last reset, and they reset when the POSTMASTER
/// restarts unless `pg_stat_statements.save` carried them over — so a top-N
/// here can easily be a top-N over the last few minutes of boot traffic and
/// read as a top-N over the deployment's life.
#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    pub connecting_role: String,
    pub window_start: chrono::DateTime<chrono::Utc>,
    pub window_seconds: f64,
    pub postmaster_start: chrono::DateTime<chrono::Utc>,
    /// True when the window begins at the postmaster start, i.e. the counters
    /// are as old as the server and no longer.
    pub window_is_since_server_start: bool,
    /// Entries for THIS database.
    pub entries_this_database: i64,
    /// Entries across the whole cluster — the cap is cluster-wide, so a
    /// per-database count understates how close the instrument is to evicting.
    pub entries_cluster: i64,
    /// Cluster entries whose `dbid` names a database that no longer exists.
    ///
    /// They are dead weight against the SHARED cap and cannot be read back by
    /// anyone. Measured on the reference stack 2026-09-10: **1139 of 1793**
    /// (63%), all of them from the controller test harness's per-test
    /// `CREATE DATABASE … TEMPLATE` clones — an entry outlives the database
    /// that minted it. On a developer box that runs the integration suite
    /// repeatedly this is what pushes `entries_evicted` off zero and makes
    /// every top-N incomplete, so it is reported rather than left to be
    /// rediscovered.
    pub entries_for_dropped_databases: i64,
    /// `pg_stat_statements.max`. `None` when the GUC could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_entries: Option<i64>,
    /// Entries evicted since the last reset. **`None` is not zero**: it means
    /// this `pg_stat_statements` predates the `_info` view (1.9 / PG 14), so
    /// nothing can say whether eviction happened.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries_evicted: Option<i64>,
    /// True when `entries_evicted` is known and non-zero: the top-N is
    /// INCOMPLETE, because an evicted entry took its counters with it.
    pub top_n_may_be_incomplete: bool,
    /// `pg_stat_statements.track` — `top` misses statements nested inside
    /// functions and DO blocks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub track: Option<String>,
    /// `pg_stat_statements.track_utility`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub track_utility: Option<String>,
    /// Rows in this database whose text Postgres withheld from the connecting
    /// role.
    pub entries_text_redacted: i64,
    /// True when the response was cut to the row cap.
    pub truncated: bool,
    /// How the rows were ordered.
    pub order_by: &'static str,
}

/// The available report.
#[derive(Debug, Clone, Serialize)]
pub struct StatementReport {
    pub coverage: Coverage,
    pub rows: Vec<StatementRow>,
}

/// Options for [`read_statement_stats`].
#[derive(Debug, Clone, Copy)]
pub struct ReadOptions {
    pub order_by: OrderBy,
    /// Clamped to `1..=MAX_ROWS` by the reader.
    pub limit: i64,
}

impl Default for ReadOptions {
    fn default() -> Self {
        Self {
            order_by: OrderBy::TotalTime,
            limit: DEFAULT_ROWS,
        }
    }
}

// ── the sanitiser ───────────────────────────────────────────────────────

/// Map every control character and every Unicode bidi/format control to a
/// space, collapse whitespace runs, trim, and truncate on a CHAR boundary.
///
/// See the module docs for why: one of the three things `pg_stat_statements`
/// does not normalise is a column ALIAS, which is arbitrary caller text.
#[must_use]
pub fn sanitize_query_text(raw: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut pending_space = false;
    let mut emitted = 0usize;
    for ch in raw.chars() {
        if ch.is_control() || ch.is_whitespace() || is_bidi_or_format_control(ch) {
            // A leading run never fires `pending_space`, so the result is
            // left-trimmed; a trailing run never emits, so it is right-trimmed.
            if emitted > 0 {
                pending_space = true;
            }
            continue;
        }
        if pending_space {
            if emitted + 1 >= max_chars {
                out.push('…');
                return out;
            }
            out.push(' ');
            emitted += 1;
            pending_space = false;
        }
        if emitted + 1 > max_chars {
            out.push('…');
            return out;
        }
        out.push(ch);
        emitted += 1;
    }
    out
}

/// Unicode format/bidi controls that are NOT `char::is_control()` but reorder
/// or hide text in a terminal or a browser.
fn is_bidi_or_format_control(ch: char) -> bool {
    matches!(ch,
        '\u{200B}'..='\u{200F}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

// ── error classification ────────────────────────────────────────────────

/// Classify a failed read of the `pg_stat_statements` VIEW, from the SQLSTATE
/// the server returned — never from the message text, which can quote the
/// statement.
///
/// Both interesting codes were reproduced on a real server rather than read
/// out of a header (see the module docs).
#[must_use]
pub fn classify_view_error(err: &sqlx::Error) -> StatementStatsRead {
    let code = match err {
        sqlx::Error::Database(db) => db.code().map(|c| c.to_string()),
        _ => None,
    };
    match code.as_deref() {
        // object_not_in_prerequisite_state — the extension is installed and
        // the library is not preloaded.
        Some("55000") => StatementStatsRead::NotLoaded,
        // undefined_table — the extension row said it was there and the view
        // is not.
        Some("42P01") => StatementStatsRead::Unreadable(ReadFailure::ViewMissing),
        // insufficient_privilege on the view itself.
        Some("42501") => StatementStatsRead::Unreadable(ReadFailure::Denied),
        _ => StatementStatsRead::Unreadable(ReadFailure::QueryFailed),
    }
}

// ── the read ────────────────────────────────────────────────────────────

/// The column list every ordering shares. Deliberately the STABLE subset of
/// `pg_stat_statements` (1.8 and later): `toplevel` is 1.9+, and the
/// block-timing columns were RENAMED in 1.11 (`blk_read_time` →
/// `shared_blk_read_time`), so naming either would make this reader refuse a
/// server it could otherwise read.
const ROWS_SELECT: &str = "SELECT COALESCE(r.rolname, 'oid:' || s.userid::text) AS role, \
     s.queryid, s.query, s.calls, s.total_exec_time, s.mean_exec_time, \
     s.max_exec_time, s.rows, s.shared_blks_hit, s.shared_blks_read \
     FROM pg_stat_statements s \
     LEFT JOIN pg_roles r ON r.oid = s.userid \
     WHERE s.dbid = (SELECT oid FROM pg_database WHERE datname = current_database()) ";

/// Three separate statements rather than one with an interpolated ORDER BY:
/// the ordering is a closed set, and a closed set does not need string
/// building. The `queryid` tiebreaker is check 28/60's rule — two statements
/// with equal total time would otherwise be ordered by heap position, so the
/// same data would produce a different top-N on each call.
const ROWS_BY_TOTAL_TIME: &str = "ORDER BY s.total_exec_time DESC, s.queryid LIMIT $1";
const ROWS_BY_CALLS: &str = "ORDER BY s.calls DESC, s.queryid LIMIT $1";
const ROWS_BY_MEAN_TIME: &str = "ORDER BY s.mean_exec_time DESC, s.queryid LIMIT $1";

/// The availability probe AND the coverage read, in one round trip.
///
/// `current_setting(..., true)` (missing_ok) everywhere, so a server that has
/// the view but not the GUCs yields `None` rather than raising — the reader
/// must not turn a missing knob into a missing instrument.
const META_SQL: &str = "SELECT current_user::text AS connecting_role, \
     pg_postmaster_start_time() AS postmaster_start, \
     now() AS now_ts, \
     current_setting('pg_stat_statements.max', true) AS max_entries, \
     current_setting('pg_stat_statements.track', true) AS track, \
     current_setting('pg_stat_statements.track_utility', true) AS track_utility, \
     (SELECT count(*) FROM pg_stat_statements)::bigint AS entries_cluster, \
     (SELECT count(*) FROM pg_stat_statements s \
       WHERE NOT EXISTS (SELECT 1 FROM pg_database d WHERE d.oid = s.dbid) \
     )::bigint AS entries_dropped_dbs, \
     (SELECT count(*) FROM pg_stat_statements \
       WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database()) \
     )::bigint AS entries_db, \
     (SELECT count(*) FROM pg_stat_statements \
       WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database()) \
         AND query = '<insufficient privilege>' \
     )::bigint AS entries_redacted";

/// `pg_stat_statements_info` is 1.9+ (PG 14). A server below that is not
/// broken — it simply cannot say whether entries were evicted, and `None` is
/// what the report renders.
const INFO_SQL: &str =
    "SELECT dealloc::bigint AS dealloc, stats_reset FROM pg_stat_statements_info";

/// Read the report, or say precisely why there is none.
///
/// The extension's PRESENCE is established from `pg_extension` — a catalog
/// that always exists — rather than from the view raising `42P01`, so
/// "not installed" is a positive finding and not an error classification.
pub async fn read_statement_stats(pool: &sqlx::PgPool, opts: ReadOptions) -> StatementStatsRead {
    let installed: Result<Option<(String,)>, sqlx::Error> =
        sqlx::query_as("SELECT extversion FROM pg_extension WHERE extname = 'pg_stat_statements'")
            .fetch_optional(pool)
            .await;
    match installed {
        Ok(None) => return StatementStatsRead::NotInstalled,
        Err(e) => {
            tracing::warn!(
                target: "talos_statement_stats",
                event_kind = "statement_stats_catalog_unreadable",
                error = %e,
                "pg_extension could not be read; reporting the instrument as unreadable rather than absent"
            );
            return StatementStatsRead::Unreadable(ReadFailure::CatalogUnreadable);
        }
        Ok(Some(_)) => {}
    }

    let meta = match sqlx::query(META_SQL).fetch_one(pool).await {
        Ok(row) => row,
        Err(e) => {
            // The error text can quote the statement, and a statement can be
            // caller-authored — so it is LOGGED and never returned.
            tracing::warn!(
                target: "talos_statement_stats",
                event_kind = "statement_stats_unavailable",
                error = %e,
                "pg_stat_statements is installed but could not be read"
            );
            return classify_view_error(&e);
        }
    };

    let mut coverage = match build_coverage(&meta, opts, pool).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                target: "talos_statement_stats",
                event_kind = "statement_stats_decode_failed",
                error = %e,
                "pg_stat_statements meta row did not decode"
            );
            return StatementStatsRead::Unreadable(ReadFailure::QueryFailed);
        }
    };

    let limit = opts.limit.clamp(1, MAX_ROWS);
    let order = match opts.order_by {
        OrderBy::TotalTime => ROWS_BY_TOTAL_TIME,
        OrderBy::Calls => ROWS_BY_CALLS,
        OrderBy::MeanTime => ROWS_BY_MEAN_TIME,
    };
    let sql = format!("{ROWS_SELECT}{order}");
    let raw = match sqlx::query(&sql).bind(limit).fetch_all(pool).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                target: "talos_statement_stats",
                event_kind = "statement_stats_rows_failed",
                error = %e,
                "pg_stat_statements rows could not be read"
            );
            return classify_view_error(&e);
        }
    };

    let mut rows = Vec::with_capacity(raw.len());
    for row in &raw {
        match decode_row(row) {
            Ok(r) => rows.push(r),
            Err(e) => {
                tracing::warn!(
                    target: "talos_statement_stats",
                    event_kind = "statement_stats_row_undecodable",
                    error = %e,
                    "a pg_stat_statements row did not decode"
                );
                return StatementStatsRead::Unreadable(ReadFailure::QueryFailed);
            }
        }
    }

    coverage.truncated = (rows.len() as i64) >= limit && coverage.entries_this_database > limit;
    StatementStatsRead::Available(Box::new(StatementReport { coverage, rows }))
}

async fn build_coverage(
    meta: &sqlx::postgres::PgRow,
    opts: ReadOptions,
    pool: &sqlx::PgPool,
) -> Result<Coverage, sqlx::Error> {
    use sqlx::Row;
    let connecting_role: String = meta.try_get("connecting_role")?;
    let postmaster_start: chrono::DateTime<chrono::Utc> = meta.try_get("postmaster_start")?;
    let now_ts: chrono::DateTime<chrono::Utc> = meta.try_get("now_ts")?;
    let max_entries: Option<i64> = meta
        .try_get::<Option<String>, _>("max_entries")?
        .and_then(|s| s.parse::<i64>().ok());
    let track: Option<String> = meta.try_get("track")?;
    let track_utility: Option<String> = meta.try_get("track_utility")?;
    let entries_cluster: i64 = meta
        .try_get::<Option<i64>, _>("entries_cluster")?
        .unwrap_or(0);
    let entries_db: i64 = meta.try_get::<Option<i64>, _>("entries_db")?.unwrap_or(0);
    let entries_dropped: i64 = meta
        .try_get::<Option<i64>, _>("entries_dropped_dbs")?
        .unwrap_or(0);
    let entries_redacted: i64 = meta
        .try_get::<Option<i64>, _>("entries_redacted")?
        .unwrap_or(0);

    // `_info` is 1.9+ (PG 14). Its ABSENCE is a fact about the extension
    // VERSION, not a failure — and both it and a genuinely failed read render
    // `entries_evicted: None`, i.e. "nothing can tell you", which is not the
    // claim `0` makes. The two are separated in the LOG, because only one of
    // them is a fault.
    // allow-benign-default: the default is `None`, which the report renders as
    // NOT MEASURED and never as 0 — pinned by
    // `an_unknown_eviction_count_is_absent_not_zero`.
    type InfoRow = (Option<i64>, Option<chrono::DateTime<chrono::Utc>>);
    let (entries_evicted, stats_reset) = match sqlx::query_as::<_, InfoRow>(INFO_SQL)
        .fetch_optional(pool)
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => (None, None),
        Err(e) => {
            let absent =
                matches!(&e, sqlx::Error::Database(db) if db.code().as_deref() == Some("42P01"));
            if absent {
                tracing::debug!(
                    target: "talos_statement_stats",
                    event_kind = "statement_stats_info_view_absent",
                    "pg_stat_statements_info is absent (needs pg_stat_statements 1.9 / PG 14); eviction and reset time are reported as not measured"
                );
            } else {
                tracing::warn!(
                    target: "talos_statement_stats",
                    event_kind = "statement_stats_info_unreadable",
                    error = %e,
                    "pg_stat_statements_info could not be read; eviction and reset time are reported as not measured"
                );
            }
            (None, None)
        }
    };

    let window_start = stats_reset.unwrap_or(postmaster_start);
    let window_seconds = (now_ts - window_start).num_milliseconds() as f64 / 1000.0;
    Ok(Coverage {
        connecting_role,
        window_start,
        window_seconds,
        postmaster_start,
        // Sub-second tolerance: a reset that happens AT postmaster start (the
        // first generation with the library loaded) is the "since server
        // start" case, and comparing to the microsecond would call it false.
        window_is_since_server_start: (window_start - postmaster_start).num_milliseconds().abs()
            < 1000,
        entries_this_database: entries_db,
        entries_cluster,
        entries_for_dropped_databases: entries_dropped,
        max_entries,
        entries_evicted,
        top_n_may_be_incomplete: entries_evicted.is_some_and(|d| d > 0),
        track,
        track_utility,
        entries_text_redacted: entries_redacted,
        truncated: false,
        order_by: opts.order_by.as_str(),
    })
}

fn decode_row(row: &sqlx::postgres::PgRow) -> Result<StatementRow, sqlx::Error> {
    use sqlx::Row;
    let role: String = row.try_get("role")?;
    let queryid: Option<i64> = row.try_get("queryid")?;
    let raw_query: Option<String> = row.try_get("query")?;
    let calls: i64 = row.try_get::<Option<i64>, _>("calls")?.unwrap_or(0);
    let total: f64 = row
        .try_get::<Option<f64>, _>("total_exec_time")?
        .unwrap_or(0.0);
    let mean: f64 = row
        .try_get::<Option<f64>, _>("mean_exec_time")?
        .unwrap_or(0.0);
    let max: f64 = row
        .try_get::<Option<f64>, _>("max_exec_time")?
        .unwrap_or(0.0);
    let rows: i64 = row.try_get::<Option<i64>, _>("rows")?.unwrap_or(0);
    let hit: i64 = row
        .try_get::<Option<i64>, _>("shared_blks_hit")?
        .unwrap_or(0);
    let read: i64 = row
        .try_get::<Option<i64>, _>("shared_blks_read")?
        .unwrap_or(0);

    let text_redacted = raw_query.as_deref() == Some(PG_REDACTED_MARKER);
    let query = if text_redacted {
        None
    } else {
        raw_query.map(|q| sanitize_query_text(&q, MAX_QUERY_TEXT_CHARS))
    };
    Ok(StatementRow {
        role,
        queryid,
        calls,
        total_exec_ms: round2(total),
        mean_exec_ms: round3(mean),
        max_exec_ms: round3(max),
        rows,
        rows_per_call: if calls > 0 {
            round3(rows as f64 / calls as f64)
        } else {
            0.0
        },
        shared_blks_hit: hit,
        shared_blks_read: read,
        query,
        text_redacted,
    })
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}
fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

// ── the pure renderer ───────────────────────────────────────────────────

/// What an operator needs to know before reading the `query` field, so that a
/// statement's text is not over-trusted in either direction.
pub const QUERY_TEXT_DISCLOSURE: &str =
    "pg_stat_statements NORMALISES CONSTANTS — a literal embedded in the SQL text is replaced by \
     $N exactly like a bind parameter, so two calls differing only in a value are ONE entry. It \
     does NOT normalise identifiers (including column ALIASES), comments, or utility statements \
     (track_utility), so text here can carry caller-chosen strings and, for SET LOCAL, tenant \
     identifiers. Talos sanitises control characters and Unicode bidi controls out of this field \
     and truncates it; it does not and cannot redact its content.";

/// Render the read as the tool's machine-readable payload.
///
/// PURE — no pool, no clock, no env — so every arm including the three
/// unavailable ones is unit-testable. Checks 74b/79b's stated limit is why:
/// a guard at the READ cannot see an answer classified correctly and then
/// rendered wrong 200 lines later.
#[must_use]
pub fn render(read: &StatementStatsRead, guest: &GuestAttribution) -> serde_json::Value {
    let (available, mut body) = match read {
        StatementStatsRead::NotInstalled => (
            false,
            serde_json::json!({
                "reason": "not_installed",
                "note": "pg_stat_statements is not installed in this database, so NOTHING has been \
                         measured — this is not a report of zero slow statements. The extension is \
                         optional by design: shared_preload_libraries is a POSTMASTER GUC, so \
                         enabling it costs a database restart, and the migration \
                         20260908120000_pg_stat_statements_when_preloaded.sql deliberately no-ops \
                         where the preload is absent."
            }),
        ),
        StatementStatsRead::NotLoaded => (
            false,
            serde_json::json!({
                "reason": "not_loaded",
                "note": "pg_stat_statements is INSTALLED but the library is not in \
                         shared_preload_libraries, so the view raises on every read and nothing \
                         has been measured. CREATE EXTENSION succeeds without the preload, which \
                         is how a server reaches this state. Add \
                         shared_preload_libraries=pg_stat_statements and RESTART Postgres."
            }),
        ),
        StatementStatsRead::Unreadable(class) => (
            false,
            serde_json::json!({
                "reason": "unreadable",
                "failure_class": class.as_str(),
                "note": "pg_stat_statements is installed but could not be read, so this is NOT a \
                         report of zero slow statements. The underlying database error is in the \
                         controller log under event_kind=statement_stats_* — it is deliberately \
                         not returned here, because a Postgres error message can quote the \
                         statement and a statement can be caller-authored."
            }),
        ),
        StatementStatsRead::Available(report) => (
            true,
            serde_json::json!({
                "coverage": report.coverage,
                "statements": report.rows,
            }),
        ),
    };

    if let Some(obj) = body.as_object_mut() {
        obj.insert("available".into(), serde_json::Value::Bool(available));
        obj.insert(
            "guest_sql_attribution".into(),
            guest_attribution_json(guest),
        );
        if available {
            obj.insert(
                "query_text_disclosure".into(),
                serde_json::Value::String(QUERY_TEXT_DISCLOSURE.into()),
            );
        }
    }
    body
}

fn guest_attribution_json(guest: &GuestAttribution) -> serde_json::Value {
    match guest {
        GuestAttribution::Fenced(role) => serde_json::json!({
            "fenced": true,
            "role": role,
            "note": "TALOS_RPC_GUEST_ROLE is set, so sandbox SQL (talos.database.query) runs under \
                     SET LOCAL ROLE and carries that role here. A statement attributed to any \
                     other role was issued by the controller itself."
        }),
        GuestAttribution::Unfenced => serde_json::json!({
            "fenced": false,
            "role": serde_json::Value::Null,
            "note": "TALOS_RPC_GUEST_ROLE is unset or invalid, so sandbox SQL \
                     (talos.database.query) runs as the APP USER and is INDISTINGUISHABLE here \
                     from the controller's own statements. Do not read a role name on these rows \
                     as provenance. Set TALOS_RPC_GUEST_ROLE to a minimally-privileged role \
                     (migrations/20260522120000_talos_guest_role.sql) to separate them."
        }),
    }
}

/// One-line human summary. Kept beside [`render`] so the prose and the JSON
/// cannot disagree about availability.
#[must_use]
pub fn summary_line(read: &StatementStatsRead) -> String {
    match read {
        StatementStatsRead::NotInstalled => {
            "pg_stat_statements is NOT INSTALLED on this database — no statement was measured. \
             This is not a report of zero slow statements."
                .to_string()
        }
        StatementStatsRead::NotLoaded => {
            "pg_stat_statements is installed but NOT LOADED (shared_preload_libraries) — the view \
             raises on every read, so no statement was measured."
                .to_string()
        }
        StatementStatsRead::Unreadable(class) => format!(
            "pg_stat_statements could NOT BE READ ({}) — no statement was measured. See the \
             controller log for the database error.",
            class.as_str()
        ),
        StatementStatsRead::Available(report) => {
            let c = &report.coverage;
            format!(
                "{} statement(s) tracked for this database ({} cluster-wide) over the last {:.0}s{}, \
                 as role '{}'. Showing {} ordered by {}.{}{}",
                c.entries_this_database,
                c.entries_cluster,
                c.window_seconds,
                if c.window_is_since_server_start {
                    " (since this Postgres started — the counters are no older than the server)"
                } else {
                    ""
                },
                c.connecting_role,
                report.rows.len(),
                c.order_by,
                if c.top_n_may_be_incomplete {
                    " ⚠ entries have been EVICTED since the last reset, so this top-N is incomplete."
                } else {
                    ""
                },
                if c.entries_text_redacted > 0 {
                    " ⚠ Postgres withheld the text of some statements from this role \
                      (needs superuser or pg_read_all_stats)."
                } else {
                    ""
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_chars_and_bidi_controls_become_spaces() {
        let raw = "SELECT 1 AS \"a\u{1b}[31mb\u{202E}c\u{0}d\"";
        let out = sanitize_query_text(raw, 400);
        assert!(!out.contains('\u{1b}'), "ANSI escape survived: {out:?}");
        assert!(!out.contains('\u{202E}'), "RTL override survived: {out:?}");
        assert!(!out.contains('\u{0}'), "NUL survived: {out:?}");
        assert_eq!(out, "SELECT 1 AS \"a [31mb c d\"");
    }

    #[test]
    fn newlines_collapse_to_single_spaces_and_the_text_is_trimmed() {
        let raw = "  SELECT\n\n   a,\n\tb\nFROM t  ";
        assert_eq!(sanitize_query_text(raw, 400), "SELECT a, b FROM t");
    }

    #[test]
    fn truncation_lands_on_a_char_boundary_and_is_marked() {
        let raw = "SELECT 'ααααααααααααααααααααααα'";
        let out = sanitize_query_text(raw, 10);
        assert!(out.ends_with('…'), "no truncation marker: {out:?}");
        assert!(out.chars().count() <= 11, "too long: {out:?}");
        // The point of the assertion: it did not panic on a multi-byte char.
        assert!(out.starts_with("SELECT"));
    }

    #[test]
    fn an_empty_statement_sanitises_to_empty() {
        assert_eq!(sanitize_query_text("", 400), "");
        assert_eq!(sanitize_query_text("   \n\t ", 400), "");
    }

    #[test]
    fn order_by_is_a_closed_set() {
        assert_eq!(OrderBy::parse("total_time"), Some(OrderBy::TotalTime));
        assert_eq!(OrderBy::parse("calls"), Some(OrderBy::Calls));
        assert_eq!(OrderBy::parse("mean_time"), Some(OrderBy::MeanTime));
        // An unrecognised value must NOT silently become the default — the
        // caller refuses instead, so a typo cannot be read as a ranking.
        assert_eq!(OrderBy::parse("total time"), None);
        assert_eq!(OrderBy::parse("TOTAL_TIME"), None);
        assert_eq!(OrderBy::parse(""), None);
    }

    #[test]
    fn every_order_by_renders_a_distinct_ordered_statement_with_a_tiebreaker() {
        let mut seen = std::collections::BTreeSet::new();
        for o in [OrderBy::TotalTime, OrderBy::Calls, OrderBy::MeanTime] {
            let order = match o {
                OrderBy::TotalTime => ROWS_BY_TOTAL_TIME,
                OrderBy::Calls => ROWS_BY_CALLS,
                OrderBy::MeanTime => ROWS_BY_MEAN_TIME,
            };
            // Check 28/60: an ORDER BY with no unique tiebreaker gives a
            // different top-N on identical data.
            assert!(order.contains("s.queryid"), "no tiebreaker in {order:?}");
            assert!(order.ends_with("LIMIT $1"), "not bound-limited: {order:?}");
            assert!(seen.insert(order), "two orderings share a statement");
        }
    }

    fn sample_report(evicted: Option<i64>) -> StatementStatsRead {
        let now = chrono::Utc::now();
        StatementStatsRead::Available(Box::new(StatementReport {
            coverage: Coverage {
                connecting_role: "talos".into(),
                window_start: now,
                window_seconds: 60.0,
                postmaster_start: now,
                window_is_since_server_start: true,
                entries_this_database: 3,
                entries_cluster: 5,
                entries_for_dropped_databases: 0,
                max_entries: Some(5000),
                entries_evicted: evicted,
                top_n_may_be_incomplete: evicted.is_some_and(|d| d > 0),
                track: Some("top".into()),
                track_utility: Some("on".into()),
                entries_text_redacted: 0,
                truncated: false,
                order_by: "total_time",
            },
            rows: vec![],
        }))
    }

    #[test]
    fn every_unavailable_arm_says_available_false_and_names_a_distinct_reason() {
        let guest = GuestAttribution::Unfenced;
        let arms = [
            (StatementStatsRead::NotInstalled, "not_installed"),
            (StatementStatsRead::NotLoaded, "not_loaded"),
            (
                StatementStatsRead::Unreadable(ReadFailure::Denied),
                "unreadable",
            ),
        ];
        for (read, reason) in arms {
            let v = render(&read, &guest);
            assert_eq!(v["available"], serde_json::json!(false), "{reason}");
            assert_eq!(v["reason"], serde_json::json!(reason));
            // The load-bearing property: an unavailable arm must NOT carry an
            // empty statement list, which is what reads as "no slow
            // statements".
            assert!(v.get("statements").is_none(), "{reason} rendered a list");
            assert!(v.get("coverage").is_none(), "{reason} rendered coverage");
            let line = summary_line(&read);
            assert!(
                line.contains("no statement was measured"),
                "summary does not say nothing was measured: {line}"
            );
        }
    }

    #[test]
    fn an_available_but_empty_report_is_not_the_unavailable_shape() {
        // The distinction the whole crate exists for: "the instrument is
        // working and has nothing to show" must not render like "there is no
        // instrument".
        let v = render(&sample_report(Some(0)), &GuestAttribution::Unfenced);
        assert_eq!(v["available"], serde_json::json!(true));
        assert_eq!(v["statements"], serde_json::json!([]));
        assert!(v.get("reason").is_none());
        assert!(!summary_line(&sample_report(Some(0))).contains("no statement was measured"));
    }

    #[test]
    fn an_unreadable_read_names_its_class_and_never_the_driver_message() {
        let v = render(
            &StatementStatsRead::Unreadable(ReadFailure::ViewMissing),
            &GuestAttribution::Unfenced,
        );
        assert_eq!(v["failure_class"], serde_json::json!("view_missing"));
        let s = v.to_string();
        assert!(!s.contains("sqlx"), "driver detail leaked: {s}");
    }

    #[test]
    fn an_available_report_carries_coverage_and_the_text_disclosure() {
        let v = render(&sample_report(Some(0)), &GuestAttribution::Unfenced);
        assert_eq!(v["coverage"]["entries_this_database"], serde_json::json!(3));
        assert_eq!(v["coverage"]["max_entries"], serde_json::json!(5000));
        assert_eq!(v["coverage"]["entries_evicted"], serde_json::json!(0));
        assert_eq!(
            v["coverage"]["top_n_may_be_incomplete"],
            serde_json::json!(false)
        );
        let d = v["query_text_disclosure"].as_str().unwrap();
        assert!(d.contains("NORMALISES CONSTANTS"));
        assert!(d.contains("ALIASES"));
    }

    #[test]
    fn an_unknown_eviction_count_is_absent_not_zero() {
        let v = render(&sample_report(None), &GuestAttribution::Unfenced);
        // ABSENT, never 0: `0` claims the instrument evicted nothing, which is
        // exactly what a pre-1.9 pg_stat_statements cannot establish.
        assert!(
            v["coverage"].get("entries_evicted").is_none(),
            "an unknown eviction count rendered as a number"
        );
        assert_eq!(
            v["coverage"]["top_n_may_be_incomplete"],
            serde_json::json!(false)
        );
    }

    #[test]
    fn eviction_marks_the_top_n_incomplete_in_json_and_in_prose() {
        let read = sample_report(Some(7));
        let v = render(&read, &GuestAttribution::Unfenced);
        assert_eq!(v["coverage"]["entries_evicted"], serde_json::json!(7));
        assert_eq!(
            v["coverage"]["top_n_may_be_incomplete"],
            serde_json::json!(true)
        );
        assert!(summary_line(&read).contains("EVICTED"));
    }

    #[test]
    fn an_unfenced_deployment_says_sandbox_sql_is_not_attributable() {
        let v = render(&sample_report(Some(0)), &GuestAttribution::Unfenced);
        assert_eq!(
            v["guest_sql_attribution"]["fenced"],
            serde_json::json!(false)
        );
        assert!(v["guest_sql_attribution"]["role"].is_null());
        let note = v["guest_sql_attribution"]["note"].as_str().unwrap();
        assert!(note.contains("INDISTINGUISHABLE"), "{note}");
    }

    #[test]
    fn a_fenced_deployment_names_the_role() {
        let v = render(
            &sample_report(Some(0)),
            &GuestAttribution::Fenced("talos_guest".into()),
        );
        assert_eq!(
            v["guest_sql_attribution"]["fenced"],
            serde_json::json!(true)
        );
        assert_eq!(
            v["guest_sql_attribution"]["role"],
            serde_json::json!("talos_guest")
        );
    }

    #[test]
    fn the_guest_attribution_block_is_present_on_every_arm() {
        // A deployment whose instrument is absent still needs to be told
        // whether sandbox SQL would be attributable if it were present —
        // otherwise turning the extension on is followed by a second surprise.
        for read in [
            StatementStatsRead::NotInstalled,
            StatementStatsRead::NotLoaded,
            StatementStatsRead::Unreadable(ReadFailure::QueryFailed),
            sample_report(Some(0)),
        ] {
            let v = render(&read, &GuestAttribution::Unfenced);
            assert!(v.get("guest_sql_attribution").is_some());
        }
    }

    #[test]
    fn a_redacted_row_is_not_rendered_as_a_statement_whose_text_is_the_marker() {
        let redacted = StatementRow {
            role: "talos".into(),
            queryid: Some(1),
            calls: 1,
            total_exec_ms: 0.0,
            mean_exec_ms: 0.0,
            max_exec_ms: 0.0,
            rows: 0,
            rows_per_call: 0.0,
            shared_blks_hit: 0,
            shared_blks_read: 0,
            query: None,
            text_redacted: true,
        };
        let v = serde_json::to_value(&redacted).unwrap();
        assert!(v.get("query").is_none());
        assert_eq!(v["text_redacted"], serde_json::json!(true));
    }

    #[test]
    fn read_failure_tokens_are_distinct_and_stable() {
        let all = [
            ReadFailure::CatalogUnreadable,
            ReadFailure::ViewMissing,
            ReadFailure::Denied,
            ReadFailure::QueryFailed,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for f in all {
            assert!(seen.insert(f.as_str()), "duplicate token {}", f.as_str());
        }
        assert_eq!(ReadFailure::Denied.as_str(), "denied");
    }

    /// A minimal `sqlx::error::DatabaseError` so the SQLSTATE arms of
    /// [`classify_view_error`] can be driven without a server.
    ///
    /// This exists because those arms are the ONLY place a DEPLOYMENT FACT is
    /// asserted from an error, and they were a **measured mutation survivor**
    /// until it did: `55000 => NotInstalled` (a not-loaded server reported as
    /// never-installed) passed every unit and DB test, because the DB suite
    /// runs on a cluster that HAS the preload and so cannot produce `55000` at
    /// all. `sqlx::postgres::PgDatabaseError` has no public constructor, so a
    /// stub is the only way to reach them.
    #[derive(Debug)]
    struct StubDbError(&'static str);

    impl std::fmt::Display for StubDbError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            // Renders like a real `PgDatabaseError`, i.e. the MESSAGE — which
            // is what makes `the_sqlstate_arms_each_name_a_different_deployment_fact`
            // a real test of "decide from the SQLSTATE, never from the text":
            // every stub carries the not-loaded message, so a classifier that
            // read `to_string()` would call all four the same thing.
            write!(f, "{}", sqlx::error::DatabaseError::message(self))
        }
    }
    impl std::error::Error for StubDbError {}
    impl sqlx::error::DatabaseError for StubDbError {
        fn message(&self) -> &str {
            // Deliberately alarming: `classify_view_error` must decide from the
            // SQLSTATE and never from the text, so a message that names the
            // wrong state must not move the answer.
            "pg_stat_statements must be loaded via \"shared_preload_libraries\""
        }
        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            Some(std::borrow::Cow::Borrowed(self.0))
        }
        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }

    fn db_error(sqlstate: &'static str) -> sqlx::Error {
        sqlx::Error::Database(Box::new(StubDbError(sqlstate)))
    }

    #[test]
    fn the_sqlstate_arms_each_name_a_different_deployment_fact() {
        // 55000 (object_not_in_prerequisite_state) is the state a server
        // reaches by installing the extension without the preload — measured
        // on a real throwaway container, not read out of a header.
        assert!(matches!(
            classify_view_error(&db_error("55000")),
            StatementStatsRead::NotLoaded
        ));
        // 42P01 here means the extension row exists and its view does not,
        // which is a BROKEN INSTALL — never "never installed", which is what
        // `pg_extension` alone is allowed to say.
        assert!(matches!(
            classify_view_error(&db_error("42P01")),
            StatementStatsRead::Unreadable(ReadFailure::ViewMissing)
        ));
        assert!(matches!(
            classify_view_error(&db_error("42501")),
            StatementStatsRead::Unreadable(ReadFailure::Denied)
        ));
        // An unrecognised SQLSTATE must NOT be promoted to a deployment fact.
        assert!(matches!(
            classify_view_error(&db_error("08006")),
            StatementStatsRead::Unreadable(ReadFailure::QueryFailed)
        ));
    }

    #[test]
    fn a_not_loaded_classification_never_renders_as_never_installed() {
        // The two unavailable arms are NOT interchangeable: one tells the
        // operator to install an extension they already have, the other to
        // restart Postgres. Rendered end to end from the SQLSTATE.
        let v = render(
            &classify_view_error(&db_error("55000")),
            &GuestAttribution::Unfenced,
        );
        assert_eq!(v["reason"], serde_json::json!("not_loaded"));
        let note = v["note"].as_str().unwrap();
        assert!(note.contains("shared_preload_libraries"), "{note}");
        assert!(note.contains("RESTART"), "{note}");
    }

    #[test]
    fn a_non_database_error_is_query_failed_not_not_loaded() {
        // `classify_view_error` must not read a pool/protocol error as the
        // one deployment fact it is allowed to assert.
        let e = sqlx::Error::PoolTimedOut;
        assert!(matches!(
            classify_view_error(&e),
            StatementStatsRead::Unreadable(ReadFailure::QueryFailed)
        ));
    }
}
