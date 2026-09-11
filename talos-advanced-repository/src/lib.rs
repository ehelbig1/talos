/// AdvancedRepository — centralises all SQL for the advanced-features domain.
///
/// Follows the ExecutionRepository / WorkflowRepository pattern: plain struct,
/// `new(db_pool)`, all methods `pub async fn`, return `anyhow::Result<T>`.
/// Handlers in `mcp/advanced.rs` should be thin wrappers that call these
/// methods and format the JSON-RPC response.
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Row, Transaction};
use talos_tenancy::TenantReadScope;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Row DTOs
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ScratchSessionRow {
    pub name: String,
    pub world: String,
    pub updated_at: DateTime<Utc>,
    pub has_error: bool,
}

#[derive(Debug)]
pub struct ArchivedExecutionRow {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
}

#[derive(Debug)]
pub struct WasmModuleRow {
    pub name: String,
    pub capability_world: String,
    pub source_code: Option<String>,
}

#[derive(Debug)]
pub struct SandboxModuleRow {
    pub name: String,
    pub wasm_bytes: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct MarketplaceListingRow {
    pub module_id: Uuid,
    pub name: String,
    pub capability_world: String,
    pub version: String,
}

#[derive(Debug)]
pub struct TemplateSourceRow {
    pub code_template: String,
    pub wasm_bytes: Option<Vec<u8>>,
    pub config_schema: serde_json::Value,
    pub allowed_secrets: Vec<String>,
    pub allowed_hosts: Vec<String>,
}

/// What `install_from_marketplace` should do with a fetched
/// [`TemplateSourceRow`]. Pulled out as a pure decision so the handler
/// stays straight-line and the invariant ("never write a zero-byte
/// module") is unit-testable without a database — this is the 2026-04-27
/// regression class.
#[derive(Debug, PartialEq, Eq)]
pub enum InstallDispatch {
    /// Compiled WASM bytes are available — install as a runnable module.
    Wasm,
    /// Source only — install as a sandbox template (compiled on first use).
    Template,
    /// Neither bytes nor source — refuse with a publisher-actionable error.
    Reject,
}

impl InstallDispatch {
    pub fn from_source(src: &TemplateSourceRow) -> Self {
        if src.wasm_bytes.is_some() {
            Self::Wasm
        } else if !src.code_template.is_empty() {
            Self::Template
        } else {
            Self::Reject
        }
    }
}

/// Collapse `Some(empty_vec)` into `None`. The 2026-04-27 regression
/// landed because the publish path stored `wasm_bytes = vec![]` (compile
/// failed silently upstream) and the install accepted it as a runnable
/// module. Normalising at read time forces callers to treat the two
/// "no compiled bytes" shapes identically.
pub(crate) fn normalize_wasm_bytes(raw: Option<Vec<u8>>) -> Option<Vec<u8>> {
    raw.filter(|b| !b.is_empty())
}

#[derive(Debug)]
pub struct MarketplaceStats {
    pub total_listings: i64,
    pub total_downloads: i64,
    pub unique_publishers: i64,
    pub world_count: i64,
}

#[derive(Debug)]
pub struct MarketplaceTopModule {
    pub name: String,
    pub publisher_id: Uuid,
    pub downloads: i64,
    pub capability_world: String,
}

#[derive(Debug)]
pub struct PublishedModuleRow {
    pub listing_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub capability_world: String,
    pub version: String,
    pub downloads: i64,
    pub star_count: i32,
    pub verified: bool,
    pub tags: Vec<String>,
    pub published_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct NodeTemplateConfigRow {
    pub id: Uuid,
    pub name: String,
    pub config_schema: serde_json::Value,
    pub allowed_secrets: Vec<String>,
}

/// A draft the stale-draft sweep declined to archive because an enabled
/// parent dispatches into it — or because a parent that MENTIONS it could not
/// be read, which is not the same as "no parent does".
#[derive(Debug, Clone)]
pub struct SkippedChildDraft {
    /// The draft's workflow id.
    pub id: Uuid,
    /// The draft's name, as rendered to an operator.
    pub name: String,
    /// Enabled parents demonstrably dispatching into it. EMPTY when the only
    /// evidence is a parent whose graph could not be parsed — see `reason`.
    pub runs_as_child_of: Vec<String>,
    /// Operator-facing explanation, from
    /// [`talos_child_workflow_refs::ChildProtection::reason`].
    pub reason: String,
}

/// A stale draft the sweep left alone because a human visibly shaped it — or
/// because nothing in its graph could say whether a human shaped it.
///
/// The authored-INTENT half of the exclusion, mirroring `fix_all`'s
/// `substantive_drafts_skipped` bucket. Kept SEPARATE from
/// [`SkippedChildDraft`] because the two reasons are not interchangeable: one
/// says *somebody runs this*, the other says *somebody wrote this*, and an
/// operator deciding what to do next needs to know which.
#[derive(Debug, Clone)]
pub struct SkippedSubstantiveDraft {
    /// The draft's workflow id.
    pub id: Uuid,
    /// The draft's name, as rendered to an operator.
    pub name: String,
    /// Operator-facing explanation, from
    /// [`talos_draft_heuristics::DraftIntent::cleanup_block_reason`].
    pub reason: String,
}

/// What `session_start`'s auto-archive actually did.
///
/// A bare count cannot say "3 archived, 1 held back because the flagship runs
/// it" — and a sweep that silently declines to act is its own small misleading
/// report, one direction over from the one this change fixes.
#[derive(Debug, Default, Clone)]
pub struct StaleDraftArchiveOutcome {
    /// Rows actually moved to `status = 'archived'`.
    pub archived: u64,
    /// Candidates deliberately left alone because an enabled parent dispatches
    /// into them.
    pub skipped_children: Vec<SkippedChildDraft>,
    /// Candidates deliberately left alone because the draft carries markers of
    /// authored intent — the population `session_start` renders, in the SAME
    /// response, as "ready for `publish_version`".
    pub skipped_substantive: Vec<SkippedSubstantiveDraft>,
    /// Enabled parents whose graph could not be read during the scan. Every
    /// candidate such a parent mentions is in `skipped_children`.
    pub unreadable_parents: Vec<String>,
}

/// The classified candidate set: what the sweep may archive, and what it must
/// leave alone under which of the two reasons.
struct StaleDraftPartition {
    to_archive: Vec<Uuid>,
    skipped_children: Vec<SkippedChildDraft>,
    skipped_substantive: Vec<SkippedSubstantiveDraft>,
}

/// Apply BOTH auto-archive exclusions to a candidate set. Pure: the caller
/// owns the SELECT above it and the by-id UPDATE below it, so the archived set
/// is a subset of what this classified by construction.
///
/// Child FIRST, on its own evidence — the same order `fix_all`'s partition
/// uses. A draft that is both a live child and visibly shaped is reported as a
/// CHILD, because publishing it retires the second reason and leaves the first
/// standing, and an operator picking a next action needs the one that will
/// still be true afterwards.
fn partition_stale_draft_candidates(
    candidates: Vec<StaleDraftCandidate>,
    scan: &talos_child_workflow_refs::ChildReferenceScan,
) -> StaleDraftPartition {
    let mut partition = StaleDraftPartition {
        to_archive: Vec::with_capacity(candidates.len()),
        skipped_children: Vec::new(),
        skipped_substantive: Vec::new(),
    };
    for StaleDraftCandidate {
        id,
        name,
        graph_json,
    } in candidates
    {
        if let Some(protection) = scan.protection_for(id) {
            partition.skipped_children.push(SkippedChildDraft {
                id,
                name,
                runs_as_child_of: protection.parent_names().to_vec(),
                reason: protection.reason(),
            });
            continue;
        }
        // `cleanup_block_reason()` is `Some` for BOTH blocked arms —
        // "a human shaped this" and "nobody can read this" — with different
        // text, so the two never borrow each other's explanation.
        match talos_draft_heuristics::classify_draft_intent(graph_json.as_deref())
            .cleanup_block_reason()
        {
            Some(reason) => partition.skipped_substantive.push(SkippedSubstantiveDraft {
                id,
                name,
                reason: reason.to_string(),
            }),
            None => partition.to_archive.push(id),
        }
    }
    partition
}

/// One row of the auto-archive candidate scan, carried from the SELECT to the
/// classification so the UPDATE can be by-id over what was classified.
struct StaleDraftCandidate {
    id: Uuid,
    name: String,
    graph_json: Option<String>,
}

#[derive(Debug)]
pub struct DraftWorkflowRow {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub graph_json: Option<String>,
}

#[derive(Debug)]
pub struct PrevScheduledRow {
    pub id: Uuid,
    pub name: String,
    pub exec_count: i64,
}

/// How many candidates `get_frequently_executed_unscheduled` reads before the
/// child-reference exclusion runs.
///
/// Wider than [`FREQUENTLY_EXECUTED_RESULT_LIMIT`] on purpose: the exclusion
/// happens in Rust, so filtering a page of exactly ten would hand the operator
/// a short list every time a child was removed from it — an exclusion that
/// silently costs coverage.
pub const FREQUENTLY_EXECUTED_SCAN_LIMIT: i64 = 30;

/// How many suggestions `get_frequently_executed_unscheduled` returns.
pub const FREQUENTLY_EXECUTED_RESULT_LIMIT: usize = 10;

#[derive(Debug)]
pub struct NextScheduledRunRow {
    pub cron_expression: String,
    pub timezone: String,
    pub next_trigger_at: Option<DateTime<Utc>>,
    pub workflow_name: String,
}

#[derive(Debug)]
pub struct ApprovalGateRow {
    pub id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub status: String,
    pub continuation_workflow_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolved_by_type: Option<String>,
    pub resolved_by_note: Option<String>,
}

#[derive(Debug)]
pub struct ApprovalGateDetailRow {
    pub status: String,
    pub continuation_workflow_id: Option<Uuid>,
    pub payload: serde_json::Value,
}

#[derive(Debug)]
pub struct SlaThresholdRow {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub workflow_name: String,
    pub p95_latency_ms: Option<i64>,
    pub success_rate_pct: Option<f64>,
    pub notification_webhook: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct SlaThresholdConfigRow {
    pub notification_webhook: String,
    pub p95_latency_ms: Option<i64>,
    pub success_rate_pct: Option<f64>,
}

#[derive(Debug)]
pub struct SuspensionRow {
    pub id: Uuid,
    pub correlation_id: String,
    pub description: Option<String>,
    pub status: String,
    pub continuation_workflow_id: Option<Uuid>,
    pub callback_url: String,
    pub timeout_at: Option<DateTime<Utc>>,
    pub resumed_at: Option<DateTime<Utc>>,
    pub resumed_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct SuspensionDetailRow {
    pub id: Uuid,
    pub status: String,
    pub continuation_workflow_id: Option<Uuid>,
}

#[derive(Debug)]
pub struct PromoteWorkflowRow {
    pub name: String,
    pub graph_json: String,
    pub capabilities: Vec<String>,
    pub intent: Option<serde_json::Value>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Repository
// ─────────────────────────────────────────────────────────────────────────────

// ── Archive executions — the one retention path ───────────────────────────

/// Every column of `workflow_executions`, and therefore every column the
/// archive must be able to hold. **The single source of truth for the move.**
///
/// Both archival paths were wrong in opposite directions before this. The
/// background sweep used `INSERT INTO workflow_executions_archive SELECT *
/// FROM archived`, which is a **parse-time** error the moment the two
/// tables' column counts differ — `DELETE ... WHERE false RETURNING *`
/// raises it identically, so the sweep had returned `Err` on every daily
/// tick since 2026-03-26 and the caller discarded it. The manual
/// [`AdvancedRepository::archive_executions`] path enumerated columns
/// by hand and so parsed fine, with the opposite defect: it named 24 of 32
/// and **silently dropped eight**, including the encrypted output payload
/// (`output_data_enc` / `output_enc_key_id` / `output_data_format`) and the
/// tenancy pin (`org_id`). `list_archived_executions` selects six columns,
/// so that loss was unobservable from any surface.
///
/// Adding a column to `workflow_executions` now means adding it here AND to
/// the archive table in a migration. `archive_schema_parity_in_the_database`
/// (`controller/tests/execution_retention_tests.rs`) fails if either half is
/// forgotten — the gate the three hand-written `sync_archive_*` migrations
/// never had. `archived_at` is deliberately absent: it is the one column the
/// archive has that the live table does not (see the purge clock below).
pub const ARCHIVED_EXECUTION_COLUMNS: &[&str] = &[
    "id",
    "workflow_id",
    "user_id",
    "status",
    "started_at",
    "completed_at",
    "error_message",
    "created_at",
    "updated_at",
    "output_data",
    "checkpoint_data",
    "workflow_version_id",
    "is_test_execution",
    "checkpoint_encrypted",
    "checkpoint_nonce",
    "is_pinned",
    "pin_note",
    "priority",
    "replayed_from_id",
    "input_data",
    "actor_id",
    "provenance",
    "acknowledged_at",
    "acknowledgement_reason",
    "parent_execution_id",
    "root_execution_id",
    "output_data_enc",
    "output_enc_key_id",
    "output_data_format",
    "org_id",
    "checkpoint_seq",
    "epoch",
];

/// Statuses an execution must be in before it may be moved or purged.
///
/// Written out rather than expressed as "not queued" — the pre-change
/// cleanup DELETE used `status != 'queued'`, which is not a terminal test:
/// it takes `running`, `resuming` and `pending` rows too. Latent on this
/// fleet (0 in-flight rows, longest observed run 2h02m against a 30-day
/// window) but wrong in principle, and the purge leg must never be the
/// thing that deletes a live execution's record.
pub const TERMINAL_EXECUTION_STATUSES: &[&str] = &["completed", "failed", "cancelled"];

/// Rows moved or purged per statement. Matches the pre-change cleanup
/// batch size: bounded row locks and WAL on the first sweep after a long
/// outage, without an N+1.
const RETENTION_BATCH: i64 = 5000;

/// Upper bound on the number of batches ONE tick will issue per statement
/// family (2026-09-10). Before this cap every loop in this file ran to
/// exhaustion, so the first tick after a long outage — or after an operator
/// shortened a window — held the pool for as long as the backlog took.
/// 20 × 5000 = 100 000 rows per tier per 6-hourly tick; the reference fleet
/// writes ~5 000 executions / 30 days, so the cap binds only on a backlog,
/// and a backlog now drains ACROSS ticks instead of inside one.
///
/// Every sweep reports whether it stopped here ([`BatchedSweep::truncated`])
/// so the caller can tell "nothing left" from "stopped at the cap" — the two
/// were one number before, and one of them means the table is still growing.
///
/// Per-crate constant, deliberately: the five crates carrying a batched sweep
/// (`talos-memory`, `talos-auth`, `talos-secrets-manager`,
/// `talos-child-run-ledger`, this one) share no leaf dependency that could
/// host it, and adding a dependency edge for one integer is the wrong trade.
/// The value is the same in each and each says so.
const MAX_BATCHES_PER_SWEEP: u32 = 20;

/// Rows affected by one batched sweep, and whether it stopped at
/// [`MAX_BATCHES_PER_SWEEP`] with the last batch still FULL — i.e. there is
/// (probably) more to do next tick.
///
/// `#[must_use]`: dropping this drops the truncation verdict, and a sweep that
/// silently stops short of its backlog every tick is a table that grows while
/// the log says "swept".
#[must_use]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BatchedSweep {
    /// Rows moved or deleted by this sweep (sum over its batches).
    pub rows: u64,
    /// `true` when the sweep issued [`MAX_BATCHES_PER_SWEEP`] batches and the
    /// last one was full. `false` means the backlog was drained.
    pub truncated: bool,
}

/// Run `sql` — a DELETE / move statement whose ONLY bind is `$1 = days` and
/// whose row selection carries `LIMIT {RETENTION_BATCH}` — until a batch comes
/// back short or the per-tick cap is reached. The one loop every tier in this
/// file uses, so the cap cannot be forgotten on a new tier.
async fn run_batched(
    pool: &PgPool,
    sql: &str,
    days: i32,
    context: &'static str,
) -> Result<BatchedSweep> {
    let mut out = BatchedSweep::default();
    for batch in 0..MAX_BATCHES_PER_SWEEP {
        let n = sqlx::query(sql)
            .bind(days)
            .execute(pool)
            .await
            .map(|r| r.rows_affected())
            .context(context)?;
        out.rows += n;
        if n < RETENTION_BATCH as u64 {
            return Ok(out);
        }
        if batch + 1 == MAX_BATCHES_PER_SWEEP {
            out.truncated = true;
            return Ok(out);
        }
        // Yield between batches so a large sweep does not monopolise the
        // pool.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Ok(out)
}

/// The archival column list as SQL. Used verbatim on BOTH sides of the
/// `INSERT ... SELECT`, so the two halves cannot drift from each other.
///
/// Interpolating this into SQL is safe by construction: every element is a
/// compile-time literal in [`ARCHIVED_EXECUTION_COLUMNS`], never caller
/// input. Identifiers cannot be bind parameters, so there is no
/// parameterised alternative.
#[must_use]
pub fn archived_execution_column_sql() -> String {
    ARCHIVED_EXECUTION_COLUMNS.join(", ")
}

/// The archival move, as one atomic statement.
///
/// `extra_predicate` is appended to the victim selection; it is only ever a
/// compile-time literal from this module (the user-scoped path adds an
/// owner clause), never caller input.
///
/// **`execution_state` rides along (2026-09-10).** The table is written by the
/// `talos.state.write` subscriber, keyed `(execution_id, key)`, and carries
/// NO foreign key to `workflow_executions` — so the archival move, which
/// CASCADEs `execution_events` and `workflow_execution_logs`, left every
/// state row of every archived execution behind forever. A terminal
/// execution never reads its durable state again (resume is for in-flight
/// rows, and the victim predicate is terminal-only), so the rows are dead the
/// moment the move commits. They are deleted in the SAME statement, on the
/// SAME `victims` set, so an execution can never be archived with its state
/// left live nor have its state deleted while it stays live. The
/// data-modifying CTE runs to completion whether or not the outer INSERT
/// reads it (Postgres executes every `WITH` DML exactly once).
/// `rows_affected` is still the outer INSERT's count — the batch-termination
/// test above it is unchanged.
fn archive_move_sql(extra_predicate: &str) -> String {
    let cols = archived_execution_column_sql();
    let statuses = TERMINAL_EXECUTION_STATUSES
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "WITH victims AS ( \
             SELECT id FROM workflow_executions \
             WHERE status IN ({statuses}) \
               AND completed_at IS NOT NULL \
               AND completed_at < NOW() - make_interval(days => $1::int) \
               AND is_pinned = false \
               {extra_predicate} \
             ORDER BY completed_at \
             LIMIT {batch} \
         ), archived AS ( \
             DELETE FROM workflow_executions \
             WHERE id IN (SELECT id FROM victims) \
             RETURNING {cols} \
         ), state_gone AS ( \
             DELETE FROM execution_state \
             WHERE execution_id IN (SELECT id FROM victims) \
         ) \
         INSERT INTO workflow_executions_archive ({cols}) SELECT {cols} FROM archived",
        batch = RETENTION_BATCH
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// The retention PASS — one path, two tiers, one testable function
// ─────────────────────────────────────────────────────────────────────────────
//
// These three items exist because the two `tokio::spawn` bodies in
// `controller/src/bootstrap/background.rs` were UNTESTABLE, and that is not a
// stylistic complaint — it was measured. With the retention logic inline in the
// spawn blocks, two mutations of the WIRING survived the entire test suite:
//
//   * re-instating `if let Ok(_) = result` on the archival call — the exact
//     defect this whole change exists to remove, and the reason a broken sweep
//     went unnoticed for five months; and
//   * swapping the two windows, which silently turns the archive tier back into
//     a no-op at the shared default of 30 days — the original bug, reproduced.
//
// Both are now inside functions the tests drive:
//
//   * `resolve_retention_windows` decides WHICH window is which, so the caller
//     never holds two interchangeable integers. The window swap is no longer
//     expressible at the call site; performed here, it fails
//     `windows_are_not_interchangeable` and `each_window_governs_its_own_tier`.
//   * `run_retention_pass` runs both tiers and RECORDS what happened, including
//     failures. A swallow performed here fails
//     `an_unrunnable_archive_statement_is_reported_not_hidden`.
//   * `RetentionPassOutcome` is `#[must_use]`, so dropping it at the call site
//     is a clippy `unused_must_use` — and CI runs `-D warnings`. That half is a
//     compiler guarantee rather than a test, which is the stronger of the two.

/// The two windows of the one retention path, as NAMED fields.
///
/// Named, not positional, and built only by [`resolve_retention_windows`] —
/// `run_retention_pass(repo, a, b)` with two bare `i32`s is exactly the shape
/// that let a silent swap live at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionWindows {
    /// Days an execution stays in `workflow_executions` before being MOVED to
    /// the archive. Bounds the LIVE table, and the boundary at which
    /// `execution_events` / `workflow_execution_logs` /
    /// `execution_approval_tokens` CASCADE away.
    pub archive_after_days: i32,
    /// Days an ARCHIVED execution is kept, clocked on `archived_at`, before
    /// permanent deletion. Bounds the archive.
    pub purge_after_days: i32,
}

/// What resolving the windows decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetentionWindowDecision {
    /// Both windows are known; run the pass.
    Run(RetentionWindows),
    /// `system_settings.archive_after_days` could not be READ.
    ///
    /// #661's rule, preserved verbatim through the extraction: an unreadable
    /// setting is NOT an unset one. The sweep is periodic and idempotent, so
    /// the correct answer to "I cannot tell what the retention is" is to skip
    /// this pass and re-read next tick — never to sweep
    /// `workflow_executions` on a guess that may be far shorter than what the
    /// operator configured.
    SkipUnreadable(String),
}

/// Where the ARCHIVE window's live value came from. The purge window has no
/// such enum because it has no second source — see
/// [`RetentionPolicy::purge_window_is_env_only`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveWindowSource {
    /// A positive `system_settings.archive_after_days` override is in force.
    Database,
    /// No override row, or one that was non-positive and therefore ignored.
    Environment,
}

impl ArchiveWindowSource {
    /// The string the `get_archive_policy` tool has always printed. Kept as a
    /// method so the two spellings cannot drift.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::Environment => "environment",
        }
    }
}

/// The resolved retention policy WITH its provenance — the windows plus the
/// facts a report needs in order to say where each number came from.
///
/// # Why this exists rather than a second reader (#768)
///
/// `get_archive_policy` used to re-derive all of this in the MCP handler: its
/// own `talos_config::archive_after_days()` read, its own JSON parse, its own
/// `d > 0` filter. Two implementations of a decision this module's own doc
/// comment claims to own exclusively, and they had already drifted — the
/// handler's parse trimmed surrounding quotes off a string-valued setting and
/// this one did not, so a doubly-quoted override would have been honoured by
/// the REPORT and ignored by the SWEEP. (Measured 2026-09-06: `system_settings`
/// held ZERO rows, so the drift was latent.) The parse below is now the union
/// of the two, and it is the only one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// The two windows the retention pass actually runs under.
    pub windows: RetentionWindows,
    /// The `system_settings` override AS STORED, before the positivity filter.
    /// `None` when there is no row (or its JSON is not an integer). Reported
    /// so a non-positive override is visible rather than silently replaced.
    pub db_archive_setting: Option<i32>,
    /// The override AFTER the positivity filter — i.e. the value that actually
    /// governs, or `None` when the environment default won.
    pub db_archive_setting_effective: Option<i32>,
    /// What the environment would give, whether or not it won.
    pub env_archive_default: i32,
}

impl RetentionPolicy {
    /// Where the ARCHIVE window's live value came from.
    #[must_use]
    pub fn archive_source(&self) -> ArchiveWindowSource {
        if self.db_archive_setting_effective.is_some() {
            ArchiveWindowSource::Database
        } else {
            ArchiveWindowSource::Environment
        }
    }

    /// How long an execution is READABLE in total: the live tier plus the
    /// archive tier. This is the number an operator asking "how far back can I
    /// look?" wants, and it appeared in no tool response before #768 —
    /// `get_archive_policy` rendered the archive tier alone, while
    /// `EXECUTION_RETENTION_DAYS`'s NAME reads like the total it is not.
    ///
    /// Saturating: both inputs are `positive_env_or_default`-clamped or
    /// filtered positive, but the sum is reported to an operator and must not
    /// wrap on a hostile `system_settings` row.
    #[must_use]
    pub fn total_lifetime_days(&self) -> i32 {
        self.windows
            .archive_after_days
            .saturating_add(self.windows.purge_after_days)
    }

    /// The purge window has exactly one source, and a report that leaves this
    /// implicit invites the reading that `set_archive_policy` moves it.
    /// `set_archive_policy` writes ONE key, `archive_after_days`; nothing in
    /// this workspace writes a `system_settings` row for the purge tier.
    pub const fn purge_window_is_env_only(&self) -> bool {
        true
    }
}

/// What resolving the full policy decided. Same two-valued contract as
/// [`RetentionWindowDecision`] — an unreadable setting is NOT an unset one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetentionPolicyDecision {
    Resolved(RetentionPolicy),
    /// `system_settings.archive_after_days` could not be READ.
    Unreadable(String),
}

/// Resolve both windows AND their provenance: the DB override for the archive
/// tier where present, the env-derived defaults otherwise.
///
/// This function is the ONLY place that decides which configured number
/// governs which tier. [`resolve_retention_windows`] is a projection of it.
pub async fn resolve_retention_policy(pool: &PgPool) -> RetentionPolicyDecision {
    let env_archive_days = talos_config::archive_after_days();
    let purge_after_days = talos_config::execution_retention_days();

    let db_read = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT value FROM system_settings WHERE key = 'archive_after_days'",
    )
    .fetch_optional(pool)
    .await;

    let db_days: Option<i32> = match db_read {
        Ok(v) => v.and_then(|v| {
            v.as_i64()
                .map(|n| i32::try_from(n).unwrap_or(i32::MAX))
                // `trim_matches('"')` came from the handler's copy of this
                // parse; keeping it here is what makes the reporter and the
                // sweep agree instead of disagreeing silently. The shape it
                // covers is NARROWER than it looks and was measured, not
                // assumed: serde already strips the JSON delimiters, so
                // `'"45"'::jsonb` reaches `as_str()` as `45` and the trim is a
                // no-op. It bites only on a jsonb string whose CONTENT carries
                // quote characters (`'"\"45\""'::jsonb` -> `"45"`), which the
                // un-trimmed parse rejected and the trimmed one accepted.
                .or_else(|| v.as_str().and_then(|s| s.trim_matches('"').parse().ok()))
        }),
        Err(e) => return RetentionPolicyDecision::Unreadable(e.to_string()),
    };

    // MCP-758 / MCP-643: a non-positive override binds into
    // `make_interval(days => $1::int)` as "older than now" (or, negative, "older
    // than the future") and archives every completed execution on the next tick.
    // Ignore it loudly rather than obeying it.
    let db_days_effective = db_days.filter(|&d| d > 0);
    if let Some(d) = db_days {
        if d <= 0 {
            tracing::warn!(
                target: "talos_engine",
                event_kind = "archive_after_days_nonpositive_substituted",
                configured = d,
                fallback = env_archive_days,
                "system_settings.archive_after_days = {} is non-positive — ignored to \
                 prevent archiving every completed execution; falling back to the \
                 env-derived value",
                d
            );
        }
    }
    let archive_after_days = db_days_effective.unwrap_or(env_archive_days);

    RetentionPolicyDecision::Resolved(RetentionPolicy {
        windows: RetentionWindows {
            archive_after_days,
            purge_after_days,
        },
        db_archive_setting: db_days,
        db_archive_setting_effective: db_days_effective,
        env_archive_default: env_archive_days,
    })
}

/// Resolve just the two windows the retention pass runs under.
///
/// A thin projection of [`resolve_retention_policy`] — NOT a second
/// implementation. The pass has no use for provenance and must not be handed
/// four interchangeable integers where it needs two named ones.
pub async fn resolve_retention_windows(pool: &PgPool) -> RetentionWindowDecision {
    match resolve_retention_policy(pool).await {
        RetentionPolicyDecision::Resolved(p) => RetentionWindowDecision::Run(p.windows),
        RetentionPolicyDecision::Unreadable(e) => RetentionWindowDecision::SkipUnreadable(e),
    }
}

/// What one retention pass actually did.
///
/// `#[must_use]`: dropping this is dropping the answer to "did retention work",
/// which is the shape of the original defect. CI's `-D warnings` turns that
/// into a build failure.
#[must_use]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetentionPassOutcome {
    /// The windows this pass ran under, or `None` if it did not run.
    pub windows: Option<RetentionWindows>,
    /// Why the pass did not run at all.
    ///
    /// `Some(_)` means the archive window could not be READ and NOTHING was
    /// swept. Distinct from a pass that ran and found nothing, and distinct
    /// again from a pass whose statements failed.
    pub skipped_window: Option<String>,
    /// Executions MOVED from `workflow_executions` to the archive.
    pub archived: u64,
    /// Archived executions permanently deleted.
    pub purged: u64,
    /// Why the archival tier could not run, if it could not.
    ///
    /// `Some(_)` with `archived == 0` and `None` with `archived == 0` are
    /// DIFFERENT answers — "the move is broken" versus "nothing was old
    /// enough". Collapsing them is what hid a five-month outage.
    pub archive_error: Option<String>,
    /// Why the purge tier could not run, if it could not.
    pub purge_error: Option<String>,
    /// Child-run ledger rows permanently deleted (RFC 0012).
    ///
    /// A THIRD tier, not a third window: the ledger has no archive of its own,
    /// so it is trimmed at the TOTAL execution lifetime
    /// (`archive_after_days + purge_after_days`). Anything shorter would
    /// delete the evidence that a child ran while its parent is still
    /// readable in the archive.
    pub ledger_purged: u64,
    /// Why the ledger tier could not run, if it could not. Same rule as the
    /// two above: `Some(_)` with `0` and `None` with `0` are different
    /// answers, and collapsing them is what hid a five-month outage.
    pub ledger_purge_error: Option<String>,
    /// The archival tier stopped at [`MAX_BATCHES_PER_SWEEP`] with a full
    /// last batch — the live table is still over its window and the next
    /// tick continues. Reported rather than looped-to-exhaustion so a
    /// backlog costs many short holds on the pool, not one long one.
    pub archive_truncated: bool,
    /// Same verdict for the purge tier.
    pub purge_truncated: bool,
    /// Same verdict for the child-run ledger tier.
    pub ledger_truncated: bool,
    /// Tier FOUR (2026-09-10): the execution side tables that had a writer
    /// and no reaper — `llm_usage`, `judge_scores` (both clocked on the
    /// TOTAL execution lifetime, because `JUDGE_SCORE_MAX_WINDOW_DAYS` = 31
    /// is wider than the 30-day archive window and the weekly reports read
    /// across it) and orphaned `execution_state` rows left behind by
    /// executions archived BEFORE the move started deleting state.
    pub side_tables: Option<SideTableReap>,
    /// Why tier four could not run, if it could not.
    pub side_table_error: Option<String>,
    /// Tier FIVE (2026-09-10): the age-based audit-table reaper
    /// (`actor_action_log`, `module_update_history`, resolved `ops_alerts`),
    /// clocked on [`audit_table_retention_days`]. `admin_event_log` is NOT
    /// here: it carries the `prevent_audit_modification` trigger and is
    /// permanent by policy — see [`AuditTableReap`].
    pub audit_tables: Option<AuditTableReap>,
    /// Why tier five could not run, if it could not.
    pub audit_table_error: Option<String>,
    /// The retention tier five ran under (after the ≥ 30-day clamp), or
    /// `None` if the pass did not run.
    pub audit_retention_days: Option<i32>,
}

/// What tier four deleted. Each field is a separate table so a failure in
/// one statement (they run in sequence, and the first error aborts the tier)
/// leaves the counts of the tables that DID sweep visible.
#[must_use]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SideTableReap {
    /// `execution_state` rows whose execution is in neither the live table
    /// nor in flight — left behind before the archival move started
    /// deleting state, or written by a sandbox run that has no execution
    /// row. Age-guarded by [`ORPHAN_STATE_GRACE_DAYS`] so a row written a
    /// moment before its execution row commits is never mistaken for one.
    pub execution_state_orphans: u64,
    /// `llm_usage` rows older than the total execution lifetime.
    pub llm_usage: u64,
    /// `judge_scores` rows older than the total execution lifetime.
    pub judge_scores: u64,
    /// Any of the three stopped at the per-tick cap with a full last batch.
    pub truncated: bool,
}

/// What tier five deleted.
///
/// **What is deliberately NOT in this struct.** `admin_event_log`,
/// `auth_audit_log`, `secret_audit_log` and `audit_events` carry the
/// `prevent_audit_modification` BEFORE DELETE trigger (migration
/// `20260408000001`): a DELETE against any of them raises `42501` by security
/// policy. They are permanent, and this reaper does not fight the trigger.
#[must_use]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuditTableReap {
    /// `actor_action_log` rows older than the retention (clocked on
    /// `"timestamp"`).
    pub actor_action_log: u64,
    /// `module_update_history` rows older than the retention (`created_at`).
    pub module_update_history: u64,
    /// `ops_alerts` rows in `status = 'resolved'` whose `resolved_at` is
    /// older than the retention. Active (`new` / `acked`) alerts are never
    /// touched, however old.
    pub ops_alerts_resolved: u64,
    /// Any of the three stopped at the per-tick cap with a full last batch.
    pub truncated: bool,
}

/// Default for `TALOS_AUDIT_TABLE_RETENTION_DAYS`.
pub const DEFAULT_AUDIT_TABLE_RETENTION_DAYS: i32 = 180;

/// Floor for `TALOS_AUDIT_TABLE_RETENTION_DAYS`. A typo (`18` for `180`) must
/// not wipe six months of an actor's action history: any configured value
/// below this is raised to it, with a WARN naming both numbers.
pub const MIN_AUDIT_TABLE_RETENTION_DAYS: i32 = 30;

/// Age below which an `execution_state` row with no live execution is NOT
/// treated as an orphan. The state RPC can land a row in the same second the
/// execution row is being created; one day is three orders of magnitude of
/// margin over that.
pub const ORPHAN_STATE_GRACE_DAYS: i32 = 1;

/// Resolve tier five's window: `TALOS_AUDIT_TABLE_RETENTION_DAYS`, default
/// [`DEFAULT_AUDIT_TABLE_RETENTION_DAYS`], never below
/// [`MIN_AUDIT_TABLE_RETENTION_DAYS`]. Non-positive and unparseable values
/// fall to the default through `positive_env_or_default` (which warns);
/// values in `1..30` are clamped UP here (which also warns).
#[must_use]
pub fn audit_table_retention_days() -> i32 {
    let configured = talos_config::positive_env_or_default::<i32>(
        "TALOS_AUDIT_TABLE_RETENTION_DAYS",
        DEFAULT_AUDIT_TABLE_RETENTION_DAYS,
    );
    clamp_audit_table_retention_days(configured)
}

/// The clamp half of [`audit_table_retention_days`], separated so it can be
/// tested without touching the process environment.
#[must_use]
pub fn clamp_audit_table_retention_days(configured: i32) -> i32 {
    if configured < MIN_AUDIT_TABLE_RETENTION_DAYS {
        tracing::warn!(
            target: "talos_config",
            event_kind = "audit_table_retention_clamped",
            configured,
            floor = MIN_AUDIT_TABLE_RETENTION_DAYS,
            "TALOS_AUDIT_TABLE_RETENTION_DAYS={configured} is below the {MIN_AUDIT_TABLE_RETENTION_DAYS}-day floor; \
             using the floor so a typo cannot wipe an audit trail"
        );
        MIN_AUDIT_TABLE_RETENTION_DAYS
    } else {
        configured
    }
}

impl RetentionPassOutcome {
    /// Turn the pass self into log lines — the ONLY place the retention
    /// loop's result is reported. Lives on the self rather than inline in
    /// the `tokio::spawn` tick so that (a) forgetting to call it leaves a
    /// `#[must_use]` value unused, which CI's `-D warnings` refuses, and (b)
    /// dropping any branch here is caught by `retention_report_tests`, which
    /// installs a capturing subscriber and asserts on the emitted events.
    /// Before this extraction the identical five blocks sat inline in
    /// `background.rs`, and deleting the `archive_error` one — reinstating the
    /// exact swallow this change exists to remove — compiled and passed every
    /// test (measured).
    pub fn report(&self) {
        if let Some(e) = &self.skipped_window {
            tracing::error!(
                target: "talos_engine",
                event_kind = "archive_after_days_unreadable_skipped",
                error = %e,
                "could not READ system_settings.archive_after_days — SKIPPED this \
                 retention pass rather than sweeping workflow_executions on the \
                 env-derived default, which may be far shorter than the configured \
                 retention"
            );
        }
        if self.archived > 0 {
            tracing::info!(
                target: "talos_engine",
                event_kind = "executions_archived",
                count = self.archived,
                archive_after_days = self
                    .windows
                    .map_or(-1, |w| w.archive_after_days),
                "archived {} executions into workflow_executions_archive",
                self.archived
            );
        }
        if self.purged > 0 {
            tracing::info!(
                target: "talos_engine",
                event_kind = "archived_executions_purged",
                count = self.purged,
                purge_after_days = self
                    .windows
                    .map_or(-1, |w| w.purge_after_days),
                "purged {} archived executions past their retention window",
                self.purged
            );
        }
        if self.ledger_purged > 0 {
            tracing::info!(
                target: "talos_engine",
                event_kind = "child_run_ledger_purged",
                count = self.ledger_purged,
                retain_days = self
                    .windows
                    .map_or(-1, |w| w.archive_after_days.saturating_add(w.purge_after_days)),
                "purged {} child-run ledger rows past the total execution lifetime",
                self.ledger_purged
            );
        }
        // An unreported failure is how the five-month outage above
        // stayed invisible. Nothing else in the system can tell
        // "nothing was old enough" from "the move is broken".
        if let Some(e) = &self.archive_error {
            tracing::error!(
                target: "talos_engine",
                event_kind = "execution_archival_failed",
                error = %e,
                "execution archival FAILED — no executions are being moved to \
                 workflow_executions_archive; live-table growth is unbounded \
                 until this succeeds"
            );
        }
        if let Some(e) = &self.purge_error {
            tracing::error!(
                target: "talos_engine",
                event_kind = "archived_execution_purge_failed",
                error = %e,
                "archived-execution purge FAILED — the archive is NOT being \
                 trimmed and will grow without bound until this succeeds"
            );
        }
        if let Some(e) = &self.ledger_purge_error {
            tracing::error!(
                target: "talos_engine",
                event_kind = "child_run_ledger_purge_failed",
                error = %e,
                "child-run ledger purge FAILED — sub_workflow_runs is NOT being \
                 trimmed and will grow without bound until this succeeds"
            );
        }
        // Tier four / five (2026-09-10). Same rule as above: a count and an
        // error are different answers and both are reported.
        if let Some(s) = &self.side_tables {
            if s.execution_state_orphans + s.llm_usage + s.judge_scores > 0 {
                tracing::info!(
                    target: "talos_engine",
                    event_kind = "execution_side_tables_reaped",
                    execution_state_orphans = s.execution_state_orphans,
                    llm_usage = s.llm_usage,
                    judge_scores = s.judge_scores,
                    lifetime_days = self
                        .windows
                        .map_or(-1, |w| w.archive_after_days.saturating_add(w.purge_after_days)),
                    "reaped execution side-table rows past the total execution lifetime"
                );
            }
        }
        if let Some(e) = &self.side_table_error {
            tracing::error!(
                target: "talos_engine",
                event_kind = "execution_side_tables_reap_failed",
                error = %e,
                "execution side-table reap FAILED — llm_usage / judge_scores / orphaned \
                 execution_state are NOT being trimmed until this succeeds"
            );
        }
        if let Some(a) = &self.audit_tables {
            if a.actor_action_log + a.module_update_history + a.ops_alerts_resolved > 0 {
                tracing::info!(
                    target: "talos_engine",
                    event_kind = "audit_tables_reaped",
                    actor_action_log = a.actor_action_log,
                    module_update_history = a.module_update_history,
                    ops_alerts_resolved = a.ops_alerts_resolved,
                    retention_days = self.audit_retention_days.unwrap_or(-1),
                    "reaped audit-table rows past TALOS_AUDIT_TABLE_RETENTION_DAYS"
                );
            }
        }
        if let Some(e) = &self.audit_table_error {
            tracing::error!(
                target: "talos_engine",
                event_kind = "audit_tables_reap_failed",
                error = %e,
                "audit-table reap FAILED — actor_action_log / module_update_history / \
                 resolved ops_alerts are NOT being trimmed until this succeeds"
            );
        }
        // Truncation is INFO, not WARN: it means the cap did its job. It is
        // logged because "swept N" with a backlog behind it reads as "done".
        let truncated: Vec<&str> = [
            (self.archive_truncated, "archive"),
            (self.purge_truncated, "purge"),
            (self.ledger_truncated, "child_run_ledger"),
            (self.side_tables.is_some_and(|s| s.truncated), "side_tables"),
            (
                self.audit_tables.is_some_and(|a| a.truncated),
                "audit_tables",
            ),
        ]
        .into_iter()
        .filter_map(|(t, name)| t.then_some(name))
        .collect();
        if !truncated.is_empty() {
            tracing::info!(
                target: "talos_engine",
                event_kind = "retention_tier_truncated",
                truncated = true,
                tiers = ?truncated,
                max_batches = MAX_BATCHES_PER_SWEEP,
                batch = RETENTION_BATCH,
                "retention tier(s) stopped at the per-tick batch cap with a full last \
                 batch; the backlog continues next tick"
            );
        }
    }
}

impl RetentionPassOutcome {
    /// Did any tier fail?
    #[must_use]
    pub fn failed(&self) -> bool {
        self.archive_error.is_some()
            || self.purge_error.is_some()
            || self.ledger_purge_error.is_some()
            || self.side_table_error.is_some()
            || self.audit_table_error.is_some()
    }

    /// Did any tier stop at the per-tick batch cap with work left?
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.archive_truncated
            || self.purge_truncated
            || self.ledger_truncated
            || self.side_tables.is_some_and(|s| s.truncated)
            || self.audit_tables.is_some_and(|a| a.truncated)
    }
}

/// Run one full retention pass: archive, then purge.
///
/// Order matters and is not arbitrary — archiving first means a row that
/// becomes eligible for the archive during this pass is moved before the purge
/// looks at the archive, and because the purge is clocked on `archived_at` a
/// just-moved row can never be purged by the same pass whatever the windows.
///
/// Neither tier's failure aborts the other: a broken archive statement must not
/// also stop the archive from being trimmed, and both failures are reported.
pub async fn run_retention_pass(
    repo: &AdvancedRepository,
    windows: RetentionWindows,
) -> RetentionPassOutcome {
    run_retention_pass_with_audit_retention(repo, windows, audit_table_retention_days()).await
}

/// [`run_retention_pass`] with tier five's window passed in rather than read
/// from the environment — the form the tests drive, so the ≥ 30-day clamp
/// and the reaper can be exercised without touching process env.
pub async fn run_retention_pass_with_audit_retention(
    repo: &AdvancedRepository,
    windows: RetentionWindows,
    audit_retention_days: i32,
) -> RetentionPassOutcome {
    let audit_retention_days = clamp_audit_table_retention_days(audit_retention_days);
    let mut outcome = RetentionPassOutcome {
        windows: Some(windows),
        audit_retention_days: Some(audit_retention_days),
        ..RetentionPassOutcome::default()
    };

    match repo
        .sweep_archive_executions(windows.archive_after_days)
        .await
    {
        Ok(s) => {
            outcome.archived = s.rows;
            outcome.archive_truncated = s.truncated;
        }
        Err(e) => outcome.archive_error = Some(format!("{e:#}")),
    }
    match repo
        .purge_archived_executions(windows.purge_after_days)
        .await
    {
        Ok(s) => {
            outcome.purged = s.rows;
            outcome.purge_truncated = s.truncated;
        }
        Err(e) => outcome.purge_error = Some(format!("{e:#}")),
    }
    // RFC 0012's third tier. Clocked on the TOTAL lifetime, not on either
    // window alone: the ledger has no FK to `workflow_executions` (a CASCADE
    // would erase it at the archival move) and no archive of its own, so
    // `archive_after_days` would delete the record of a child run while its
    // parent is still readable in the archive. Its failure does not abort the
    // others and is reported like theirs.
    let total_lifetime_days = windows
        .archive_after_days
        .saturating_add(windows.purge_after_days);
    match repo.purge_child_run_ledger(total_lifetime_days).await {
        Ok(s) => {
            outcome.ledger_purged = s.rows;
            outcome.ledger_truncated = s.truncated;
        }
        Err(e) => outcome.ledger_purge_error = Some(format!("{e:#}")),
    }
    // Tier four (2026-09-10): the execution side tables, on the same total
    // lifetime and for the same reason — `llm_usage` and `judge_scores` have
    // no FK and no archive, and the weekly judge report reads a 31-day window
    // that the 30-day archive window would cut into.
    match repo.reap_execution_side_tables(total_lifetime_days).await {
        Ok(s) => outcome.side_tables = Some(s),
        Err(e) => outcome.side_table_error = Some(format!("{e:#}")),
    }
    // Tier five (2026-09-10): the age-based audit-table reaper, on its OWN
    // window — these tables are not keyed on an execution's lifetime.
    match repo.reap_audit_tables(audit_retention_days).await {
        Ok(a) => outcome.audit_tables = Some(a),
        Err(e) => outcome.audit_table_error = Some(format!("{e:#}")),
    }

    outcome
}

/// Resolve the windows from configuration and run one pass — **the entry point
/// `background.rs` calls, and the only one it may call.**
///
/// This exists so the spawn loop holds NO decision whatsoever. When the loop
/// matched on [`RetentionWindowDecision`] itself, a mutation that ignored
/// `SkipUnreadable` and swept on a fabricated 30/30 guess survived the entire
/// suite — the wiring could still choose wrongly, and no test could reach it.
/// Folding the skip into the outcome moves that choice in here, where
/// `an_unreadable_window_skips_the_whole_pass` drives it. The caller's only
/// remaining job is to log what came back.
///
/// The skip arm reports `archived == 0` / `purged == 0` because it genuinely
/// swept nothing: an unreadable window is not a short window (#661).
pub async fn run_retention_pass_from_config(
    repo: &AdvancedRepository,
    pool: &PgPool,
) -> RetentionPassOutcome {
    match resolve_retention_windows(pool).await {
        RetentionWindowDecision::Run(windows) => run_retention_pass(repo, windows).await,
        RetentionWindowDecision::SkipUnreadable(error) => RetentionPassOutcome {
            skipped_window: Some(error),
            ..RetentionPassOutcome::default()
        },
    }
}

pub struct AdvancedRepository {
    db_pool: PgPool,
}

impl AdvancedRepository {
    pub fn new(db_pool: PgPool) -> Self {
        Self { db_pool }
    }

    // ── Scratch sessions ──────────────────────────────────────────────────────
    //
    // RFC 0004 M4: `scratch_sessions` is the first table with RLS enforced
    // (migration 20260529160000). It's request-only (no worker access) and
    // every query lives in this file, so all paths are wired below. scratch
    // sessions are personal, so the scope carries the user with an empty org
    // list — the policy's `user_id = current_user_id` clause matches.
    // Each method runs on the scoped tx so the RLS policy sees the GUC.

    /// Open a per-user tenant-scoped transaction (sets app.current_user_id)
    /// so the scratch_sessions RLS policy enforces. Caller runs its query on
    /// the returned tx and commits.
    async fn user_scoped_tx(&self, user_id: Uuid) -> Result<Transaction<'_, Postgres>> {
        talos_db::begin_tenant_read_scoped(
            &self.db_pool,
            &TenantReadScope::new(user_id, Vec::new()),
        )
        .await
        .map_err(|e| anyhow!("open user-scoped tx: {e}"))
    }

    /// Create or update a scratch session (UPSERT by user_id + name).
    pub async fn upsert_scratch_session(
        &self,
        user_id: Uuid,
        name: &str,
        code: &str,
        world: &str,
    ) -> Result<()> {
        let mut tx = self.user_scoped_tx(user_id).await?;
        sqlx::query(
            "INSERT INTO scratch_sessions (user_id, name, code, world, updated_at) \
             VALUES ($1, $2, $3, $4, NOW()) \
             ON CONFLICT (user_id, name) DO UPDATE SET code = $3, world = $4, updated_at = NOW()",
        )
        .bind(user_id)
        .bind(name)
        .bind(code)
        .bind(world)
        .execute(&mut *tx)
        .await
        .context("upsert_scratch_session")?;
        tx.commit().await.context("commit upsert_scratch_session")
    }

    /// Update only the code field of an existing scratch session.
    pub async fn update_scratch_code(&self, code: &str, user_id: Uuid, name: &str) -> Result<()> {
        let mut tx = self.user_scoped_tx(user_id).await?;
        sqlx::query(
            "UPDATE scratch_sessions SET code = $1, updated_at = NOW() \
             WHERE user_id = $2 AND name = $3",
        )
        .bind(code)
        .bind(user_id)
        .bind(name)
        .execute(&mut *tx)
        .await
        .context("update_scratch_code")?;
        tx.commit().await.context("commit update_scratch_code")
    }

    /// Fetch (code, world) for a named scratch session.
    pub async fn get_scratch_session(
        &self,
        user_id: Uuid,
        name: &str,
    ) -> Result<Option<(String, String)>> {
        let mut tx = self.user_scoped_tx(user_id).await?;
        let row = sqlx::query_as::<_, (String, String)>(
            "SELECT code, world FROM scratch_sessions WHERE user_id = $1 AND name = $2",
        )
        .bind(user_id)
        .bind(name)
        .fetch_optional(&mut *tx)
        .await
        .context("get_scratch_session")?;
        tx.commit().await.context("commit get_scratch_session")?;
        Ok(row)
    }

    /// Persist a compilation/execution error on a scratch session.
    pub async fn update_scratch_error(&self, error: &str, user_id: Uuid, name: &str) -> Result<()> {
        let mut tx = self.user_scoped_tx(user_id).await?;
        sqlx::query(
            "UPDATE scratch_sessions SET last_error = $1, last_output = NULL, updated_at = NOW() \
             WHERE user_id = $2 AND name = $3",
        )
        .bind(error)
        .bind(user_id)
        .bind(name)
        .execute(&mut *tx)
        .await
        .context("update_scratch_error")?;
        tx.commit().await.context("commit update_scratch_error")
    }

    /// Persist a compilation warning where output is NULL but no full error (no_wasm_bytes path).
    pub async fn update_scratch_no_wasm(&self, msg: &str, user_id: Uuid, name: &str) -> Result<()> {
        let mut tx = self.user_scoped_tx(user_id).await?;
        sqlx::query(
            "UPDATE scratch_sessions SET last_error = $1, updated_at = NOW() \
             WHERE user_id = $2 AND name = $3",
        )
        .bind(msg)
        .bind(user_id)
        .bind(name)
        .execute(&mut *tx)
        .await
        .context("update_scratch_no_wasm")?;
        tx.commit().await.context("commit update_scratch_no_wasm")
    }

    /// Persist the successful output of a scratch session execution.
    pub async fn update_scratch_output(
        &self,
        output: &serde_json::Value,
        user_id: Uuid,
        name: &str,
    ) -> Result<()> {
        let mut tx = self.user_scoped_tx(user_id).await?;
        sqlx::query(
            "UPDATE scratch_sessions SET last_output = $1, last_error = NULL, updated_at = NOW() \
             WHERE user_id = $2 AND name = $3",
        )
        .bind(output)
        .bind(user_id)
        .bind(name)
        .execute(&mut *tx)
        .await
        .context("update_scratch_output")?;
        tx.commit().await.context("commit update_scratch_output")
    }

    /// List all scratch sessions for a user, ordered by most recently updated.
    pub async fn list_scratch_sessions(&self, user_id: Uuid) -> Result<Vec<ScratchSessionRow>> {
        let mut tx = self.user_scoped_tx(user_id).await?;
        let rows = sqlx::query(
            "SELECT name, world, updated_at, (last_error IS NOT NULL) as has_error \
             FROM scratch_sessions WHERE user_id = $1 ORDER BY updated_at DESC LIMIT 1000",
        )
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await
        .context("list_scratch_sessions")?;
        tx.commit().await.context("commit list_scratch_sessions")?;

        rows.into_iter()
            .map(|r| -> Result<ScratchSessionRow> {
                Ok(ScratchSessionRow {
                    name: r.try_get("name")?,
                    world: r.try_get("world")?,
                    updated_at: r.try_get("updated_at")?,
                    has_error: r.try_get::<Option<bool>, _>("has_error")?.unwrap_or(false),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Delete a named scratch session. Returns the number of rows affected.
    pub async fn delete_scratch_session(&self, user_id: Uuid, name: &str) -> Result<u64> {
        let mut tx = self.user_scoped_tx(user_id).await?;
        let affected = sqlx::query("DELETE FROM scratch_sessions WHERE user_id = $1 AND name = $2")
            .bind(user_id)
            .bind(name)
            .execute(&mut *tx)
            .await
            .map(|r| r.rows_affected())
            .context("delete_scratch_session")?;
        tx.commit().await.context("commit delete_scratch_session")?;
        Ok(affected)
    }

    // ── Archive policy ────────────────────────────────────────────────────────

    /// The retention policy — both windows and their provenance — through the
    /// ONE resolver the retention pass itself uses. Reporting surfaces call
    /// this; nothing outside [`resolve_retention_policy`] may re-read the envs
    /// or re-apply the positivity filter (#768).
    pub async fn resolve_retention_policy(&self) -> RetentionPolicyDecision {
        resolve_retention_policy(&self.db_pool).await
    }

    /// Read the archive_after_days setting from system_settings.
    pub async fn get_archive_policy(&self) -> Result<Option<serde_json::Value>> {
        sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT value FROM system_settings WHERE key = 'archive_after_days'",
        )
        .fetch_optional(&self.db_pool)
        .await
        .context("get_archive_policy")
    }

    /// Upsert the archive_after_days setting.
    pub async fn set_archive_policy(&self, days: i32) -> Result<()> {
        sqlx::query(
            "INSERT INTO system_settings (key, value, updated_at) \
             VALUES ('archive_after_days', $1::jsonb, NOW()) \
             ON CONFLICT (key) DO UPDATE SET value = $1::jsonb, updated_at = NOW()",
        )
        .bind(serde_json::json!(days))
        .execute(&self.db_pool)
        .await
        .map(|_| ())
        .context("set_archive_policy")
    }

    // ── Archive executions — the one retention path ───────────────────────────
    /// Move one user's old terminal executions into the archive.
    ///
    /// Backs the `archive_executions` MCP tool. The fleet-wide background
    /// sweep is [`sweep_archive_executions`](Self::sweep_archive_executions);
    /// both build their SQL from [`ARCHIVED_EXECUTION_COLUMNS`], so an
    /// execution archived by hand and one archived by the sweep are the
    /// same row.
    pub async fn archive_executions(&self, days: i32, user_id: Uuid) -> Result<u64> {
        // MCP-1062 (2026-05-15): refuse non-positive `days`. Sibling
        // caller-supplied-negative class as MCP-997. With
        // `make_interval(days => -N)` the predicate
        // `completed_at < NOW() - INTERVAL` becomes `< NOW() +
        // INTERVAL`, archiving every non-pinned completed / failed /
        // cancelled execution for the user — total purge.
        if days <= 0 {
            tracing::warn!(
                target: "talos_audit",
                days,
                %user_id,
                "archive_executions refused: days must be positive (would archive every non-pinned execution)"
            );
            return Ok(0);
        }
        // RFC 0005 S3: self-scope so the workflow_executions RLS policy
        // backstops the DELETE (only the caller's rows are archived).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let n = sqlx::query(&archive_move_sql("AND user_id = $2"))
            .bind(days)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map(|r| r.rows_affected())
            .context("archive_executions")?;
        tx.commit().await?;
        Ok(n)
    }

    /// Fleet-wide archival sweep: move every user's terminal executions
    /// older than `days` into the archive. Returns the number moved.
    ///
    /// Tier one of the one retention path. Batched, and each batch is a
    /// single CTE, so the DELETE and the INSERT commit together — an
    /// execution is never in neither table.
    ///
    /// **This returns `Err` rather than swallowing.** The pre-change caller
    /// wrote `if let Ok(r) = result`, which discarded a parse error that had
    /// been raised on every tick for five months; the whole defect was
    /// invisible because of that one line.
    pub async fn sweep_archive_executions(&self, days: i32) -> Result<BatchedSweep> {
        if days <= 0 {
            tracing::warn!(
                target: "talos_audit",
                days,
                "archival sweep refused: days must be positive (would archive every non-pinned execution)"
            );
            return Ok(BatchedSweep::default());
        }
        run_batched(
            &self.db_pool,
            &archive_move_sql(""),
            days,
            "sweep_archive_executions",
        )
        .await
    }

    /// Fleet-wide purge: delete archived executions kept longer than
    /// `days`. Returns the number deleted. Tier two of the one retention
    /// path — and the ONLY thing in the platform that permanently deletes
    /// an execution record.
    ///
    /// Three belts, each of which the pre-change plain-DELETE cleanup loop
    /// lacked:
    ///
    /// * clocked on `archived_at`, so `days` means "days kept in the
    ///   archive" and cannot select a row the archival sweep just moved;
    /// * `is_pinned = false`, so `pin_execution`'s promise survives the
    ///   whole path (the cleanup loop had no `is_pinned` reference at all);
    /// * terminal statuses only, so a `running` / `resuming` / `pending`
    ///   row can never be purged even if one somehow reached the archive.
    pub async fn purge_archived_executions(&self, days: i32) -> Result<BatchedSweep> {
        if days <= 0 {
            tracing::warn!(
                target: "talos_audit",
                days,
                "archive purge refused: days must be positive (would delete the whole archive)"
            );
            return Ok(BatchedSweep::default());
        }
        let statuses = TERMINAL_EXECUTION_STATUSES
            .iter()
            .map(|s| format!("'{s}'"))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "DELETE FROM workflow_executions_archive WHERE id IN ( \
                 SELECT id FROM workflow_executions_archive \
                 WHERE status IN ({statuses}) \
                   AND is_pinned = false \
                   AND archived_at < NOW() - make_interval(days => $1::int) \
                 ORDER BY archived_at, id \
                 LIMIT {batch} \
                 FOR UPDATE SKIP LOCKED \
             )",
            batch = RETENTION_BATCH
        );
        run_batched(&self.db_pool, &sql, days, "purge_archived_executions").await
    }

    /// Tier three of the retention path: trim the child-run ledger
    /// (`sub_workflow_runs`, RFC 0012).
    ///
    /// Delegates to [`talos_child_run_ledger::ChildRunLedger::purge_older_than`]
    /// — all of the ledger's SQL lives in that leaf crate — which carries the
    /// same three belts this file's `purge_archived_executions` carries: a
    /// positive-days guard, a pinned-parent exemption checked against BOTH
    /// execution tiers, and a `SKIP LOCKED` batch loop.
    ///
    /// `days` is the TOTAL execution lifetime, and the caller
    /// ([`run_retention_pass`]) is the one place that computes it.
    ///
    /// # Errors
    /// Any database failure, propagated rather than swallowed — the same
    /// reason the two tiers above propagate theirs.
    pub async fn purge_child_run_ledger(&self, days: i32) -> Result<BatchedSweep> {
        let purge = talos_child_run_ledger::ChildRunLedger::new(self.db_pool.clone())
            .purge_older_than(days)
            .await?;
        Ok(BatchedSweep {
            rows: purge.rows,
            truncated: purge.truncated,
        })
    }

    /// Tier four of the retention path (2026-09-10): the execution side
    /// tables that had a writer and no reaper.
    ///
    /// * `llm_usage` (clocked on `recorded_at`) and `judge_scores`
    ///   (`created_at`) are deleted past `days` = the TOTAL execution
    ///   lifetime. Neither has an FK to `workflow_executions` nor an archive,
    ///   and both are read by trailing-window reports — the widest,
    ///   `JUDGE_SCORE_MAX_WINDOW_DAYS` = 31, exceeds the 30-day archive
    ///   window, which is why they are NOT reaped at archival time. Rows with
    ///   `execution_id IS NULL` (controller-side scaffolding usage) age out on
    ///   the same clock, so nothing in either table is permanent.
    /// * `execution_state` rows with no LIVE execution and older than
    ///   [`ORPHAN_STATE_GRACE_DAYS`]: the population left behind by every
    ///   execution archived before the move started deleting state (see
    ///   [`archive_move_sql`]), plus any sandbox run that wrote state without
    ///   an execution row. `days` is not used for this statement.
    ///
    /// Statements run in sequence; the first `Err` aborts the tier and is
    /// propagated, with the counts of the tables that DID sweep lost for that
    /// tick — acceptable, since the next tick repeats them.
    pub async fn reap_execution_side_tables(&self, days: i32) -> Result<SideTableReap> {
        if days <= 0 {
            tracing::warn!(
                target: "talos_audit",
                days,
                "side-table reap refused: days must be positive (would delete every llm_usage / judge_scores row)"
            );
            return Ok(SideTableReap::default());
        }
        let llm_sql = format!(
            "DELETE FROM llm_usage WHERE id IN ( \
                 SELECT id FROM llm_usage \
                 WHERE recorded_at < NOW() - make_interval(days => $1::int) \
                 ORDER BY recorded_at, id \
                 LIMIT {batch} \
                 FOR UPDATE SKIP LOCKED \
             )",
            batch = RETENTION_BATCH
        );
        let judge_sql = format!(
            "DELETE FROM judge_scores WHERE id IN ( \
                 SELECT id FROM judge_scores \
                 WHERE created_at < NOW() - make_interval(days => $1::int) \
                 ORDER BY created_at, id \
                 LIMIT {batch} \
                 FOR UPDATE SKIP LOCKED \
             )",
            batch = RETENTION_BATCH
        );
        // Anti-join on the LIVE table only: an archived execution's state is
        // dead (terminal, never resumed), which is exactly why the archival
        // move deletes it — this statement is the backfill for rows archived
        // before it did, and the catch-all for rows with no execution at all.
        let orphan_sql = format!(
            "DELETE FROM execution_state WHERE (execution_id, key) IN ( \
                 SELECT es.execution_id, es.key FROM execution_state es \
                 WHERE es.updated_at < NOW() - make_interval(days => $1::int) \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM workflow_executions e WHERE e.id = es.execution_id \
                   ) \
                 ORDER BY es.execution_id, es.key \
                 LIMIT {batch} \
                 FOR UPDATE SKIP LOCKED \
             )",
            batch = RETENTION_BATCH
        );
        let llm = run_batched(&self.db_pool, &llm_sql, days, "reap_llm_usage").await?;
        let judge = run_batched(&self.db_pool, &judge_sql, days, "reap_judge_scores").await?;
        let orphans = run_batched(
            &self.db_pool,
            &orphan_sql,
            ORPHAN_STATE_GRACE_DAYS,
            "reap_execution_state_orphans",
        )
        .await?;
        Ok(SideTableReap {
            execution_state_orphans: orphans.rows,
            llm_usage: llm.rows,
            judge_scores: judge.rows,
            truncated: llm.truncated || judge.truncated || orphans.truncated,
        })
    }

    /// Tier five of the retention path (2026-09-10): age-based reaper for the
    /// audit-shaped tables that grow forever and are NOT immutable by policy.
    ///
    /// `days` is refused below [`MIN_AUDIT_TABLE_RETENTION_DAYS`] as a second
    /// belt under the env clamp in [`audit_table_retention_days`] — a caller
    /// that bypasses the clamp still cannot wipe an audit trail.
    ///
    /// **Not reaped, by design**: `admin_event_log` (and `auth_audit_log`,
    /// `secret_audit_log`, `audit_events`) carry `prevent_audit_modification`
    /// and refuse every DELETE with `42501`. This function never names them.
    pub async fn reap_audit_tables(&self, days: i32) -> Result<AuditTableReap> {
        if days < MIN_AUDIT_TABLE_RETENTION_DAYS {
            tracing::warn!(
                target: "talos_audit",
                days,
                floor = MIN_AUDIT_TABLE_RETENTION_DAYS,
                "audit-table reap refused: days is below the retention floor"
            );
            return Ok(AuditTableReap::default());
        }
        let action_sql = format!(
            "DELETE FROM actor_action_log WHERE id IN ( \
                 SELECT id FROM actor_action_log \
                 WHERE \"timestamp\" < NOW() - make_interval(days => $1::int) \
                 ORDER BY \"timestamp\", id \
                 LIMIT {batch} \
                 FOR UPDATE SKIP LOCKED \
             )",
            batch = RETENTION_BATCH
        );
        let history_sql = format!(
            "DELETE FROM module_update_history WHERE id IN ( \
                 SELECT id FROM module_update_history \
                 WHERE created_at < NOW() - make_interval(days => $1::int) \
                 ORDER BY created_at, id \
                 LIMIT {batch} \
                 FOR UPDATE SKIP LOCKED \
             )",
            batch = RETENTION_BATCH
        );
        let alerts_sql = format!(
            "DELETE FROM ops_alerts WHERE id IN ( \
                 SELECT id FROM ops_alerts \
                 WHERE status = 'resolved' \
                   AND resolved_at < NOW() - make_interval(days => $1::int) \
                 ORDER BY resolved_at, id \
                 LIMIT {batch} \
                 FOR UPDATE SKIP LOCKED \
             )",
            batch = RETENTION_BATCH
        );
        let actions =
            run_batched(&self.db_pool, &action_sql, days, "reap_actor_action_log").await?;
        let history = run_batched(
            &self.db_pool,
            &history_sql,
            days,
            "reap_module_update_history",
        )
        .await?;
        let alerts =
            run_batched(&self.db_pool, &alerts_sql, days, "reap_resolved_ops_alerts").await?;
        Ok(AuditTableReap {
            actor_action_log: actions.rows,
            module_update_history: history.rows,
            ops_alerts_resolved: alerts.rows,
            truncated: actions.truncated || history.truncated || alerts.truncated,
        })
    }

    /// List archived executions, optionally filtered by workflow_id.
    pub async fn list_archived_executions(
        &self,
        user_id: Uuid,
        workflow_id: Option<Uuid>,
        limit: i32,
    ) -> Result<Vec<ArchivedExecutionRow>> {
        let rows = if let Some(wf_id) = workflow_id {
            sqlx::query(
                "SELECT id, workflow_id, status, started_at, completed_at, error_message \
                 FROM workflow_executions_archive \
                 WHERE user_id = $1 AND workflow_id = $2 \
                 ORDER BY started_at DESC LIMIT $3",
            )
            .bind(user_id)
            .bind(wf_id)
            .bind(limit)
            .fetch_all(&self.db_pool)
            .await
        } else {
            sqlx::query(
                "SELECT id, workflow_id, status, started_at, completed_at, error_message \
                 FROM workflow_executions_archive \
                 WHERE user_id = $1 \
                 ORDER BY started_at DESC LIMIT $2",
            )
            .bind(user_id)
            .bind(limit)
            .fetch_all(&self.db_pool)
            .await
        }
        .context("list_archived_executions")?;

        rows.into_iter()
            .map(|r| -> Result<ArchivedExecutionRow> {
                Ok(ArchivedExecutionRow {
                    id: r.try_get("id")?,
                    workflow_id: r.try_get("workflow_id")?,
                    status: r.try_get("status")?,
                    started_at: r.try_get("started_at")?,
                    completed_at: r.try_get("completed_at")?,
                    error_message: r.try_get("error_message")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    // ── Marketplace ───────────────────────────────────────────────────────────

    /// Fetch WASM module info for marketplace publishing (ownership-checked).
    pub async fn get_wasm_module_for_marketplace(
        &self,
        module_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<WasmModuleRow>> {
        // Phase 4 prep: query the unified `modules` table with the 3-shape
        // id match. `source_code` is now first-class on the modules row;
        // the previous wasm_modules-only query missed catalog-installed
        // modules whose source lives elsewhere (returns NULL gracefully
        // for those, same as before).
        let row = sqlx::query(
            "SELECT name, capability_world, source_code \
               FROM modules \
              WHERE id = $1 \
                AND user_id = $2",
        )
        .bind(module_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_wasm_module_for_marketplace")?;

        row.map(|r| -> Result<WasmModuleRow> {
            Ok(WasmModuleRow {
                name: r.try_get("name")?,
                capability_world: r.try_get("capability_world")?,
                source_code: r.try_get::<Option<String>, _>("source_code")?,
            })
        })
        .transpose()
    }

    /// Fetch sandbox template info for marketplace publishing (ownership-checked).
    pub async fn get_sandbox_for_marketplace(
        &self,
        module_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<SandboxModuleRow>> {
        // Phase 4 prep: query the unified `modules` table. The legacy
        // `node_templates.precompiled_wasm` mapped to `modules.wasm_bytes`
        // (Phase 1.1 backfill); the new query reads it directly.
        let row = sqlx::query(
            "SELECT name, wasm_bytes \
               FROM modules \
              WHERE id = $1 \
                AND user_id = $2",
        )
        .bind(module_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_sandbox_for_marketplace")?;

        row.map(|r| -> Result<SandboxModuleRow> {
            Ok(SandboxModuleRow {
                name: r.try_get("name")?,
                wasm_bytes: r.try_get::<Option<Vec<u8>>, _>("wasm_bytes")?,
            })
        })
        .transpose()
    }

    /// Insert or update a marketplace listing. Returns the listing UUID.
    pub async fn publish_to_marketplace(
        &self,
        module_id: Uuid,
        user_id: Uuid,
        name: &str,
        description: &str,
        world: &str,
        version: &str,
        tags: &[String],
    ) -> Result<Uuid> {
        let row = sqlx::query(
            "INSERT INTO module_marketplace \
             (module_id, publisher_id, name, description, capability_world, version, tags) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (name, version) DO UPDATE SET \
             description = EXCLUDED.description, tags = EXCLUDED.tags, updated_at = NOW() \
             RETURNING id",
        )
        .bind(module_id)
        .bind(user_id)
        .bind(name)
        .bind(description)
        .bind(world)
        .bind(version)
        .bind(tags)
        .fetch_one(&self.db_pool)
        .await
        .context("publish_to_marketplace")?;

        Ok(row.try_get("id")?)
    }

    /// Fetch a marketplace listing by ID (must be public).
    pub async fn get_marketplace_listing(
        &self,
        listing_id: Uuid,
    ) -> Result<Option<MarketplaceListingRow>> {
        let row = sqlx::query(
            "SELECT m.module_id, m.name, m.capability_world, m.version \
             FROM module_marketplace m WHERE m.id = $1 AND m.is_public = true",
        )
        .bind(listing_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_marketplace_listing")?;

        row.map(|r| -> Result<MarketplaceListingRow> {
            Ok(MarketplaceListingRow {
                module_id: r.try_get("module_id")?,
                name: r.try_get("name")?,
                capability_world: r.try_get("capability_world")?,
                version: r.try_get("version")?,
            })
        })
        .transpose()
    }

    /// Fetch the full installable artifact for a marketplace source module —
    /// source, bytes, schema, and the security-relevant allowlists.
    ///
    /// Returns the same `TemplateSourceRow` shape as `get_template_source` so
    /// the install handler can branch on artifact availability without two
    /// parallel struct shapes drifting. `wasm_bytes` is normalised to `None`
    /// when the column is NULL OR empty (`vec![]`) — collapsing the two
    /// "no compiled bytes" cases means callers can't accidentally write a
    /// zero-byte module by forgetting to check `is_empty()`. This was the
    /// 2026-04-27 regression: the published listing's `wasm_bytes` was
    /// `Some(vec![])`, the install accepted it, the worker then failed
    /// with "failed to fetch wasm module from redis (not found)".
    pub async fn get_wasm_module_source(
        &self,
        module_id: Uuid,
    ) -> Result<Option<TemplateSourceRow>> {
        let row = sqlx::query(
            "SELECT source_code, wasm_bytes, config_schema, allowed_secrets, allowed_hosts \
               FROM modules \
              WHERE id = $1 \
              LIMIT 1",
        )
        .bind(module_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_wasm_module_source")?;

        row.map(|r| -> Result<TemplateSourceRow> {
            Ok(TemplateSourceRow {
                code_template: r
                    .try_get::<Option<String>, _>("source_code")?
                    .unwrap_or_default(),
                wasm_bytes: normalize_wasm_bytes(r.try_get::<Option<Vec<u8>>, _>("wasm_bytes")?),
                config_schema: r
                    .try_get::<Option<serde_json::Value>, _>("config_schema")?
                    .unwrap_or(serde_json::json!({})),
                allowed_secrets: r
                    .try_get::<Option<Vec<String>>, _>("allowed_secrets")?
                    .unwrap_or_default(),
                allowed_hosts: r
                    .try_get::<Option<Vec<String>>, _>("allowed_hosts")?
                    .unwrap_or_default(),
            })
        })
        .transpose()
    }

    /// Fetch a node template for marketplace installation.
    pub async fn get_template_source(&self, module_id: Uuid) -> Result<Option<TemplateSourceRow>> {
        // Phase 5: unified `modules` table. `source_code` replaces
        // `code_template`, `wasm_bytes` replaces `precompiled_wasm`.
        let row = sqlx::query(
            "SELECT source_code, wasm_bytes, config_schema, allowed_secrets, allowed_hosts \
             FROM modules \
             WHERE id = $1",
        )
        .bind(module_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_template_source")?;

        row.map(|r| -> Result<TemplateSourceRow> {
            Ok(TemplateSourceRow {
                // `modules.source_code` is nullable (catalog-only rows have NULL);
                // fall back to empty string to preserve the legacy non-null field shape.
                code_template: r
                    .try_get::<Option<String>, _>("source_code")?
                    .unwrap_or_default(),
                wasm_bytes: r.try_get::<Option<Vec<u8>>, _>("wasm_bytes")?,
                config_schema: r
                    .try_get::<Option<serde_json::Value>, _>("config_schema")?
                    .unwrap_or(serde_json::json!({})),
                allowed_secrets: r
                    .try_get::<Option<Vec<String>>, _>("allowed_secrets")?
                    .unwrap_or_default(),
                allowed_hosts: r
                    .try_get::<Option<Vec<String>>, _>("allowed_hosts")?
                    .unwrap_or_default(),
            })
        })
        .transpose()
    }

    /// Install a WASM module from the marketplace (atomic INSERT + download count increment).
    /// Returns the new module ID.
    ///
    /// The caller (handler in `mcp/advanced.rs`) is responsible for choosing
    /// this path only when `src.wasm_bytes.is_some()` — this method asserts
    /// the same invariant as a defence-in-depth check, since silently
    /// writing a NULL/empty `wasm_bytes` row produces the same prod
    /// regression class (worker errors with "module not found in redis").
    pub async fn install_wasm_from_marketplace(
        &self,
        user_id: Uuid,
        listing_id: Uuid,
        install_name: &str,
        world: &str,
        src: TemplateSourceRow,
    ) -> Result<Uuid> {
        // Defence in depth: the handler should have rejected this case, but
        // refuse here too rather than write a zero-byte module that the
        // worker cannot run. Treat this as an internal error (it's a bug
        // in the caller, not a user-facing condition).
        let wasm_bytes = src.wasm_bytes.ok_or_else(|| {
            anyhow!(
                "install_wasm_from_marketplace: wasm_bytes missing — caller should have routed \
                 to install_template_from_marketplace or rejected the listing"
            )
        })?;

        let new_module_id = Uuid::new_v4();
        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("install_wasm_from_marketplace begin")?;

        // Phase 5: write directly to the unified `modules` table. Marketplace
        // installs are user-owned sandbox modules (compiled on install).
        // allowed_secrets and allowed_hosts are propagated from the source
        // module's listing — without them, every vault:// header in the
        // module's config fails at runtime and `talos::core::http::fetch`
        // refuses to call the listed providers.
        sqlx::query(
            "INSERT INTO modules \
             (id, name, kind, capability_world, source_code, wasm_bytes, user_id, \
              allowed_secrets, allowed_hosts, compiled_at) \
             VALUES ($1, $2, 'sandbox', $3, $4, $5, $6, $7, $8, NOW())",
        )
        .bind(new_module_id)
        .bind(install_name)
        .bind(world)
        .bind(&src.code_template)
        .bind(&wasm_bytes)
        .bind(user_id)
        .bind(&src.allowed_secrets)
        .bind(&src.allowed_hosts)
        .execute(&mut *tx)
        .await
        .context("install_wasm_from_marketplace insert")?;

        sqlx::query("UPDATE module_marketplace SET downloads = downloads + 1 WHERE id = $1")
            .bind(listing_id)
            .execute(&mut *tx)
            .await
            .context("install_wasm_from_marketplace download count")?;

        tx.commit()
            .await
            .context("install_wasm_from_marketplace commit")?;

        Ok(new_module_id)
    }

    /// Install a sandbox template from the marketplace (atomic INSERT + download count increment).
    /// Returns the new template ID.
    ///
    /// `world` is the listing's `capability_world` — propagated explicitly so
    /// the new row records the same WIT world the publisher targeted. Without
    /// this the column defaulted to `minimal-node`, silently downgrading
    /// every source-only marketplace install (sibling regression to the WASM
    /// install path's lost allowlists, fixed in the same release).
    pub async fn install_template_from_marketplace(
        &self,
        user_id: Uuid,
        listing_id: Uuid,
        install_name: &str,
        world: &str,
        src: TemplateSourceRow,
    ) -> Result<Uuid> {
        let new_template_id = Uuid::new_v4();
        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("install_template_from_marketplace begin")?;

        // Phase 5: write directly to the unified `modules` table. Sandbox
        // template install: `kind='sandbox'` + source_code + optional wasm_bytes.
        sqlx::query(
            "INSERT INTO modules \
             (id, name, kind, capability_world, category, description, config_schema, \
              source_code, wasm_bytes, user_id, allowed_secrets, allowed_hosts) \
             VALUES ($1, $2, 'sandbox', $3, 'sandbox', 'Installed from marketplace', $4, $5, $6, $7, $8, $9)",
        )
        .bind(new_template_id)
        .bind(install_name)
        .bind(world)
        .bind(&src.config_schema)
        .bind(&src.code_template)
        .bind(&src.wasm_bytes)
        .bind(user_id)
        .bind(&src.allowed_secrets)
        .bind(&src.allowed_hosts)
        .execute(&mut *tx)
        .await
        .context("install_template_from_marketplace insert")?;

        sqlx::query("UPDATE module_marketplace SET downloads = downloads + 1 WHERE id = $1")
            .bind(listing_id)
            .execute(&mut *tx)
            .await
            .context("install_template_from_marketplace download count")?;

        tx.commit()
            .await
            .context("install_template_from_marketplace commit")?;

        Ok(new_template_id)
    }

    /// Aggregate marketplace statistics.
    pub async fn get_marketplace_stats(&self) -> Result<MarketplaceStats> {
        let row = sqlx::query(
            "SELECT \
                COUNT(*)::bigint AS total_listings, \
                COALESCE(SUM(downloads), 0)::bigint AS total_downloads, \
                COUNT(DISTINCT publisher_id)::bigint AS unique_publishers, \
                COUNT(DISTINCT capability_world)::bigint AS world_count \
             FROM module_marketplace WHERE is_public = true",
        )
        .fetch_one(&self.db_pool)
        .await
        .context("get_marketplace_stats")?;

        Ok(MarketplaceStats {
            total_listings: row
                .try_get::<Option<i64>, _>("total_listings")?
                .unwrap_or(0),
            total_downloads: row
                .try_get::<Option<i64>, _>("total_downloads")?
                .unwrap_or(0),
            unique_publishers: row
                .try_get::<Option<i64>, _>("unique_publishers")?
                .unwrap_or(0),
            world_count: row.try_get::<Option<i64>, _>("world_count")?.unwrap_or(0),
        })
    }

    /// Top 5 most-downloaded marketplace modules.
    ///
    /// Postgres default for `ORDER BY x DESC` is `NULLS FIRST`. The
    /// `module_marketplace.downloads` column allows NULL (catalog-seeded
    /// templates that have never been downloaded come in NULL, not 0), so
    /// pre-fix the NULL-download rows floated to the top and the real
    /// download leaders fell below LIMIT 5. The handler's `total_downloads`
    /// (from `SUM(downloads)`) and `top_modules[].downloads` could then
    /// disagree: total_downloads=3 with every top-5 entry showing 0.
    /// COALESCE both the sort key and the projection so NULL is treated
    /// as 0 consistently, and add a deterministic tie-break on `name` so
    /// the top-5 ordering is stable across calls.
    pub async fn get_marketplace_top_modules(&self) -> Result<Vec<MarketplaceTopModule>> {
        let rows = sqlx::query(
            "SELECT name, publisher_id, COALESCE(downloads, 0)::bigint AS downloads, capability_world \
             FROM module_marketplace WHERE is_public = true \
             ORDER BY COALESCE(downloads, 0) DESC, name ASC LIMIT 5",
        )
        .fetch_all(&self.db_pool)
        .await
        .context("get_marketplace_top_modules")?;

        rows.into_iter()
            .map(|r| -> Result<MarketplaceTopModule> {
                Ok(MarketplaceTopModule {
                    name: r.try_get::<Option<String>, _>("name")?.unwrap_or_default(),
                    publisher_id: r
                        .try_get::<Option<Uuid>, _>("publisher_id")?
                        .unwrap_or(Uuid::nil()),
                    downloads: r.try_get::<Option<i64>, _>("downloads")?.unwrap_or(0),
                    capability_world: r
                        .try_get::<Option<String>, _>("capability_world")?
                        .unwrap_or_default(),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// List public marketplace modules, optionally filtered by capability_world.
    ///
    /// Same i32→i64 type-mismatch fix applied to `get_marketplace_top_modules`:
    /// `module_marketplace.downloads` is Postgres INT4 (NOT NULL DEFAULT 0)
    /// but the projection reads it as i64. Without the explicit ::bigint cast
    /// the read fails and `.unwrap_or(0)` masks every download count to 0,
    /// so operators see "no popular modules" even when downloads exist.
    pub async fn list_published_modules(
        &self,
        world: Option<&str>,
        limit: i64,
    ) -> Result<Vec<PublishedModuleRow>> {
        let rows = sqlx::query(
            "SELECT id, name, description, capability_world, version, \
                    downloads::bigint AS downloads, tags, \
                    created_at, verified, star_count \
             FROM module_marketplace \
             WHERE is_public = true \
               AND ($1::text IS NULL OR capability_world = $1) \
             ORDER BY star_count DESC, downloads DESC, created_at DESC \
             LIMIT $2",
        )
        .bind(world)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await
        .context("list_published_modules")?;

        rows.into_iter()
            .map(|r| -> Result<PublishedModuleRow> {
                Ok(PublishedModuleRow {
                    listing_id: r.try_get::<Option<Uuid>, _>("id")?.unwrap_or(Uuid::nil()),
                    name: r.try_get::<Option<String>, _>("name")?.unwrap_or_default(),
                    description: r.try_get::<Option<String>, _>("description")?,
                    capability_world: r
                        .try_get::<Option<String>, _>("capability_world")?
                        .unwrap_or_default(),
                    version: r
                        .try_get::<Option<String>, _>("version")?
                        .unwrap_or_default(),
                    downloads: r.try_get::<Option<i64>, _>("downloads")?.unwrap_or(0),
                    star_count: r.try_get::<Option<i32>, _>("star_count")?.unwrap_or(0),
                    verified: r.try_get::<Option<bool>, _>("verified")?.unwrap_or(false),
                    tags: r
                        .try_get::<Option<Vec<String>>, _>("tags")?
                        .unwrap_or_default(),
                    published_at: r
                        .try_get::<Option<DateTime<Utc>>, _>("created_at")?
                        .unwrap_or_else(chrono::Utc::now),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Check whether a public listing exists.
    pub async fn check_listing_exists(&self, listing_id: Uuid) -> Result<bool> {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM module_marketplace WHERE id = $1 AND is_public = true)",
        )
        .bind(listing_id)
        .fetch_one(&self.db_pool)
        .await
        .context("check_listing_exists")
    }

    /// Insert a per-user star record (ON CONFLICT DO NOTHING). Returns true if a new star was
    /// inserted (false if the user already starred this listing).
    pub async fn insert_star(&self, user_id: Uuid, listing_id: Uuid) -> Result<bool> {
        let r = sqlx::query(
            "INSERT INTO module_marketplace_stars (user_id, listing_id) \
             VALUES ($1, $2) \
             ON CONFLICT (user_id, listing_id) DO NOTHING",
        )
        .bind(user_id)
        .bind(listing_id)
        .execute(&self.db_pool)
        .await
        .context("insert_star")?;

        Ok(r.rows_affected() > 0)
    }

    /// Read current star_count without modifying it (used when already starred).
    pub async fn get_star_count(&self, listing_id: Uuid) -> Result<i32> {
        sqlx::query_scalar::<_, i32>("SELECT star_count FROM module_marketplace WHERE id = $1")
            .bind(listing_id)
            .fetch_one(&self.db_pool)
            .await
            .context("get_star_count")
    }

    /// Atomically increment star_count and return the new value.
    pub async fn increment_star_count(&self, listing_id: Uuid) -> Result<Option<i32>> {
        let row = sqlx::query(
            "UPDATE module_marketplace \
             SET star_count = star_count + 1, updated_at = NOW() \
             WHERE id = $1 AND is_public = true \
             RETURNING star_count",
        )
        .bind(listing_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("increment_star_count")?;

        row.map(|r| -> Result<i32> { Ok(r.try_get::<Option<i32>, _>("star_count")?.unwrap_or(0)) })
            .transpose()
    }

    // ── Workflow operations ───────────────────────────────────────────────────

    /// Archive a workflow (set status = 'archived'). Returns rows affected.
    pub async fn archive_workflow(&self, wf_id: Uuid, user_id: Uuid) -> Result<u64> {
        // RFC 0005 S3: self-scope so the workflows RLS policy backstops the
        // UPDATE (USING-as-WITH-CHECK; the row stays owned by the caller).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let n = sqlx::query(
            "UPDATE workflows SET status = 'archived', updated_at = NOW() \
             WHERE id = $1 AND user_id = $2 AND status != 'archived'",
        )
        .bind(wf_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map(|r| r.rows_affected())
        .context("archive_workflow")?;
        tx.commit().await?;
        Ok(n)
    }

    /// Fetch (name, status) for a workflow (ownership-checked).
    pub async fn get_workflow_name_status(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<(String, Option<String>)>> {
        // RFC 0005 S3: self-scope (workflows RLS backstop).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let row = sqlx::query("SELECT name, status FROM workflows WHERE id = $1 AND user_id = $2")
            .bind(wf_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await
            .context("get_workflow_name_status")?;
        tx.commit().await?;

        row.map(|r| -> Result<(String, Option<String>)> {
            let name: String = r.try_get::<Option<String>, _>("name")?.unwrap_or_default();
            let status: Option<String> = r.try_get("status")?;
            Ok((name, status))
        })
        .transpose()
    }

    /// Set workflow status to 'active'.
    pub async fn activate_workflow(&self, wf_id: Uuid, user_id: Uuid) -> Result<()> {
        // RFC 0005 S3: self-scope (workflows RLS backstop on the UPDATE).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        sqlx::query("UPDATE workflows SET status = 'active' WHERE id = $1 AND user_id = $2")
            .bind(wf_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map(|_| ())
            .context("activate_workflow")?;
        tx.commit().await?;
        Ok(())
    }

    /// Create a workflow schedule.
    pub async fn create_workflow_schedule(
        &self,
        sid: Uuid,
        wf_id: Uuid,
        user_id: Uuid,
        cron: &str,
        timezone: &str,
        next_trigger_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO workflow_schedules \
             (id, workflow_id, user_id, cron_expression, timezone, is_enabled, next_trigger_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, true, $6, NOW())",
        )
        .bind(sid)
        .bind(wf_id)
        .bind(user_id)
        .bind(cron)
        .bind(timezone)
        .bind(next_trigger_at)
        .execute(&self.db_pool)
        .await
        .map(|_| ())
        .context("create_workflow_schedule")
    }

    /// Fetch source workflow fields needed for promotion.
    pub async fn get_source_workflow_for_promote(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<PromoteWorkflowRow>> {
        let row = sqlx::query(
            "SELECT name, graph_json, capabilities, intent FROM workflows \
             WHERE id = $1 AND user_id = $2",
        )
        .bind(wf_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_source_workflow_for_promote")?;

        row.map(|r| -> Result<PromoteWorkflowRow> {
            Ok(PromoteWorkflowRow {
                name: r.try_get::<Option<String>, _>("name")?.unwrap_or_default(),
                graph_json: r
                    .try_get::<Option<String>, _>("graph_json")?
                    .unwrap_or_else(|| r#"{"nodes":[],"edges":[]}"#.to_string()),
                capabilities: r
                    .try_get::<Option<Vec<String>>, _>("capabilities")?
                    .unwrap_or_default(),
                intent: r.try_get::<Option<serde_json::Value>, _>("intent")?,
            })
        })
        .transpose()
    }

    /// Insert a new (promoted) workflow record.
    pub async fn insert_promoted_workflow(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
        name: &str,
        graph_json: &str,
        capabilities: &[String],
        intent: Option<&serde_json::Value>,
    ) -> Result<()> {
        // RFC 0004: stamp org_id = the creator's personal org. RFC 0006 /
        // RFC 0005 S3: resolve that org in Rust so we can bind it AND scope
        // the write to it (`begin_org_scoped`), making the workflows org-pin
        // RLS WITH CHECK enforce once the fail-closed flip is on. NULL-tolerant:
        // no personal org → `begin_user_scoped` + NULL org (policy's
        // `org_id IS NULL → permit`). Latent while `TALOS_RLS_SET_ROLE` is off.
        let personal_org: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM organizations WHERE owner_id = $1 AND is_personal")
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await?;
        let mut tx = match personal_org {
            Some(org) => {
                talos_db::begin_org_scoped(
                    &self.db_pool,
                    &talos_tenancy::OrgScope::new(org, user_id),
                )
                .await?
            }
            None => talos_db::begin_user_scoped(&self.db_pool, user_id).await?,
        };
        sqlx::query(
            "INSERT INTO workflows \
             (id, user_id, name, module_uri, graph_json, capabilities, intent, status, \
              created_at, updated_at, org_id) \
             VALUES ($1, $2, $3, '', $4, $5, $6, 'draft', NOW(), NOW(), $7)",
        )
        .bind(wf_id)
        .bind(user_id)
        .bind(name)
        .bind(graph_json)
        .bind(capabilities)
        .bind(intent)
        .bind(personal_org)
        .execute(&mut *tx)
        .await
        .context("insert_promoted_workflow")?;
        tx.commit().await.context("commit insert_promoted_workflow")
    }

    // ── Config suggestions ────────────────────────────────────────────────────

    /// Fetch (name, graph_json) for a workflow (ownership-checked).
    pub async fn get_workflow_graph_and_name(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<(String, String)>> {
        let row =
            sqlx::query("SELECT name, graph_json FROM workflows WHERE id = $1 AND user_id = $2")
                .bind(wf_id)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await
                .context("get_workflow_graph_and_name")?;

        row.map(|r| -> Result<(String, String)> {
            let name: String = r.try_get("name")?;
            let graph: String = r.try_get("graph_json")?;
            Ok((name, graph))
        })
        .transpose()
    }

    /// Fetch id, name, config_schema, allowed_secrets for a batch of template IDs.
    pub async fn get_node_templates_for_config(
        &self,
        ids: &[Uuid],
    ) -> Result<Vec<NodeTemplateConfigRow>> {
        // Phase 5: unified `modules` table. Match on the canonical id OR
        // either legacy alias so graph_json blobs that still carry old
        // node_templates.id / wasm_modules.id keep resolving during
        // the migration window.
        let rows = sqlx::query(
            "SELECT id, name, config_schema, allowed_secrets \
             FROM modules \
             WHERE id = ANY($1)",
        )
        .bind(ids)
        .fetch_all(&self.db_pool)
        .await
        .context("get_node_templates_for_config")?;

        rows.into_iter()
            .map(|r| -> Result<NodeTemplateConfigRow> {
                Ok(NodeTemplateConfigRow {
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
                    config_schema: r
                        .try_get::<Option<serde_json::Value>, _>("config_schema")?
                        .unwrap_or(serde_json::json!({})),
                    allowed_secrets: r
                        .try_get::<Option<Vec<String>>, _>("allowed_secrets")?
                        .unwrap_or_default(),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Fetch all secret key_paths for a user (for vault cross-reference).
    pub async fn get_user_secret_paths(&self, user_id: Uuid) -> Result<Vec<String>> {
        sqlx::query_scalar::<_, String>(
            "SELECT key_path FROM secrets WHERE created_by = $1 LIMIT 10000",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await
        .context("get_user_secret_paths")
    }

    // ── Agent session start ───────────────────────────────────────────────────

    /// Count total workflows and those with embeddings for a user.
    /// Returns (total, embedded).
    pub async fn get_embedding_coverage(&self, user_id: Uuid) -> Result<(i64, i64)> {
        // RFC 0005 S3: self-scope (workflows RLS backstop for MCP callers).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let row = sqlx::query(
            "SELECT COUNT(*) as total, \
                    COUNT(*) FILTER (WHERE embedding IS NOT NULL) as embedded \
             FROM workflows WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .context("get_embedding_coverage")?;
        tx.commit().await?;

        Ok(row
            .map(|r| -> Result<(i64, i64)> {
                Ok((
                    r.try_get::<Option<i64>, _>("total")?.unwrap_or(0),
                    r.try_get::<Option<i64>, _>("embedded")?.unwrap_or(0),
                ))
            })
            .transpose()?
            .unwrap_or((0, 0)))
    }

    /// Fetch UUIDs of workflows that have no embedding (limit 100).
    pub async fn get_ids_without_embedding(&self, user_id: Uuid) -> Result<Vec<Uuid>> {
        // RFC 0005 S3: self-scope (workflows RLS backstop).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let rows = sqlx::query(
            "SELECT id FROM workflows WHERE user_id = $1 AND embedding IS NULL LIMIT 100",
        )
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await
        .context("get_ids_without_embedding")?;
        tx.commit().await?;

        rows.into_iter()
            .map(|r| r.try_get("id").map_err(Into::into))
            .collect::<Result<Vec<_>>>()
    }

    /// Fetch recent draft workflows with no executions (max 10).
    ///
    /// **Deliberately NOT child-aware, and this is the report half of the
    /// report/decision split.** It shares the sub-workflow-blind
    /// `NOT EXISTS (… workflow_executions …)` premise with
    /// [`Self::archive_stale_drafts_excluding_children`], so it can list a
    /// workflow an enabled parent runs daily — but its only consumer is
    /// `session_start`'s `in_progress_drafts` / `unpublished_substantive_drafts`
    /// display, which takes no destructive action. Until 2026-09-11 that
    /// display's worst advice was "publish it" — a no-op for a child, since a
    /// parent dispatches the `graph_json` COLUMN with no version join and no
    /// status filter — and it was the brief's `priority_action`, i.e. the
    /// first thing every session told the operator to do. The brief now runs
    /// [`Self::scan_child_parents_for`] over the listed ids and ANNOTATES a
    /// child (still listed — hiding it would be a different misleading
    /// report) rather than recommending the no-op. The exclusion in the
    /// archive method exists to keep a live child out of DELETE and ARCHIVE
    /// sets, not to hide it from an operator's list.
    ///
    /// Lint check 85 is FILE-scoped on leg (a), so the archive method above
    /// vouches for this file and leg (a) is silent here; leg (b) does not
    /// reach it because this is a SELECT. That is the check's stated limit
    /// made concrete by a live site rather than left hypothetical. There is
    /// deliberately no `allow-execution-blind-draft-path:` marker: leg (a)
    /// matches it file-globally, so adding one would blind the whole file
    /// including the destructive method beside it.
    /// Which of `candidates` an enabled, non-retired parent dispatches into
    /// (or MIGHT — an unreadable parent graph that mentions the id is reported
    /// as unknown, never as "no"). Thin wrapper over the one chokepoint,
    /// `talos_child_workflow_refs::scan_child_parents`, for callers that hold
    /// this repository and not a pool. An `Err` must be DISCLOSED by the
    /// caller, never defaulted to an empty scan — an empty scan reads as
    /// "nobody is anybody's child", which is the pre-fix behaviour.
    pub async fn scan_child_parents_for(
        &self,
        user_id: Uuid,
        candidates: &[Uuid],
    ) -> Result<talos_child_workflow_refs::ChildReferenceScan> {
        talos_child_workflow_refs::scan_child_parents(&self.db_pool, user_id, candidates)
            .await
            .context("child-reference scan for the session brief's draft list")
    }

    pub async fn get_draft_workflows(&self, user_id: Uuid) -> Result<Vec<DraftWorkflowRow>> {
        // RFC 0005 S3: self-scope (workflows + workflow_executions backstop).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let rows = sqlx::query(
            "SELECT w.id, w.name, w.created_at, w.graph_json::text AS graph_json \
             FROM workflows w \
             WHERE w.user_id = $1 \
               AND w.status = 'draft' \
               AND NOT EXISTS (SELECT 1 FROM workflow_executions we WHERE we.workflow_id = w.id) \
             ORDER BY w.updated_at DESC, w.id DESC LIMIT 10",
        )
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await
        .context("get_draft_workflows")?;
        tx.commit().await?;

        rows.into_iter()
            .map(|r| -> Result<DraftWorkflowRow> {
                Ok(DraftWorkflowRow {
                    id: r.try_get::<Option<Uuid>, _>("id")?.unwrap_or(Uuid::nil()),
                    name: r.try_get::<Option<String>, _>("name")?.unwrap_or_default(),
                    created_at: r
                        .try_get::<Option<DateTime<Utc>>, _>("created_at")?
                        .unwrap_or_else(chrono::Utc::now),
                    graph_json: r.try_get::<Option<String>, _>("graph_json")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Archive draft workflows with no executions older than `stale_days`,
    /// EXCEPT the ones an enabled parent dispatches into and the ones a human
    /// visibly shaped.
    ///
    /// # The two exclusions, and why they are both here
    ///
    /// This is the ONE chokepoint. Both exclusions are evaluated between the
    /// candidate SELECT and the UPDATE, each skipped id is reported under its
    /// OWN reason, and the write is by id over what survived — so the archived
    /// set is a subset of what was classified by construction.
    ///
    /// The child exclusion (#760) asks *does anything run this*. The
    /// substantive exclusion asks *did a human shape this*, and it closes the
    /// contradiction M-I fixed for `fix_all` in 2026-05 and left live here:
    /// `session_start` reads the draft display BEFORE it sweeps, so ONE
    /// response would list a draft under `unpublished_substantive_drafts` with
    /// `next_step: "publish_version with workflow_id=…"` and report it
    /// archived, in that order. Measured on pristine `origin/main`
    /// 2026-09-05: `auto_archived_stale_drafts: 1` beside that very
    /// recommendation.
    ///
    /// They run child-FIRST, matching `fix_all`'s partition: a draft that is
    /// both is reported as a child, because that is the reason that survives
    /// somebody publishing it.
    ///
    /// An UNREADABLE `graph_json` is held back too, under its own reason.
    /// `is_substantive_workflow` answers `false` for "no markers" and for
    /// "could not parse" alike; on a path that WRITES, those are not the same
    /// answer — the same UNKNOWN-is-not-NO rule the parent scan applies.
    ///
    /// # Deliberately NO force flag
    ///
    /// `fix_all` has had this exclusion since 2026-05 with no override: the
    /// escape hatch is an EXPLICIT operator action (`publish_version`, or
    /// `archive_workflow` / `batch_delete_workflows` naming the workflow).
    /// Mirrored here rather than adding an `include_substantive` — a flag that
    /// re-enables an unattended destructive sweep is the silent widening this
    /// change exists to prevent, and the skip is disclosed in every response
    /// so the draft cannot quietly acquire permanent immunity.
    ///
    /// # Why the exclusion is not optional
    ///
    /// The predicate this sweep is built on — *`status = 'draft'` and no
    /// `workflow_executions` row* — is blind to a sub-workflow by
    /// construction: `execute_subworkflow_graph` runs a child IN-PROCESS and
    /// records no execution row at all (measured 2026-09-05: zero rows
    /// carrying `parent_execution_id`, platform-wide). Measured live the same
    /// day, `cos-team-recall` — `pa-chief-of-staff`'s daily `team_gather`
    /// sub-workflow, which had run every day that week — matched this
    /// predicate exactly, and the hygiene report was simultaneously
    /// annotating it as that parent's child two sections above the line
    /// recommending its deletion.
    ///
    /// A draft's `status` is also not a runtime fact: the parent dispatches
    /// the child's `graph_json` COLUMN (`WorkflowGraphStore::get_graph`, no
    /// version join and no status predicate), so neither `publish_version`
    /// nor this archive changes how the parent runs it. That makes the archive
    /// non-breaking but not harmless — it removes a live workflow from every
    /// listing an operator manages it through, under the label "stale".
    ///
    /// # Shape
    ///
    /// SELECT the candidates, scan their parents, then UPDATE **by id**. The
    /// write is a subset of what was scanned by construction — the discipline
    /// `fix_all`'s stale-execution step learned in 2026-08-19, where a
    /// user-wide write sat behind a 25-row preview. The UPDATE re-asserts
    /// `status = 'draft'` and the no-executions predicate so a row that
    /// started running in between is left alone.
    ///
    /// # Errors
    ///
    /// A failed parent scan ABORTS the sweep rather than archiving without the
    /// exclusion: this is an automated, unattended write, and an empty index
    /// reads as "nobody is anybody's child".
    pub async fn archive_stale_drafts_excluding_children(
        &self,
        user_id: Uuid,
        stale_days: i32,
    ) -> Result<StaleDraftArchiveOutcome> {
        // MCP-1062 (2026-05-15): refuse non-positive `stale_days`.
        // Sibling caller-supplied-negative class as MCP-997. With
        // `make_interval(days => -N)` the `created_at <` predicate
        // flips to `< NOW() + INTERVAL`, archiving every empty draft
        // workflow for the user regardless of age.
        if stale_days <= 0 {
            tracing::warn!(
                target: "talos_audit",
                stale_days,
                %user_id,
                "archive_stale_drafts refused: stale_days must be positive (would archive every empty draft)"
            );
            return Ok(StaleDraftArchiveOutcome::default());
        }

        // RFC 0005 S3: self-scope (workflows RLS backstop).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let rows = sqlx::query(
            "SELECT id, name, graph_json FROM workflows \
             WHERE user_id = $1 \
               AND status = 'draft' \
               AND NOT EXISTS (SELECT 1 FROM workflow_executions we WHERE we.workflow_id = workflows.id) \
               AND created_at < NOW() - make_interval(days => $2::int)",
        )
        .bind(user_id)
        .bind(stale_days)
        .fetch_all(&mut *tx)
        .await
        .context("archive_stale_drafts candidate scan")?;
        tx.commit().await?;

        // `graph_json` is `text NOT NULL`, so a `None` here is projection
        // drift, not data — read it as `Option` and let `?` carry a real
        // schema error out (check 52). A NULL that somehow existed would
        // classify as `Unreadable` and be held back, which is the safe arm.
        let candidates: Vec<StaleDraftCandidate> = rows
            .into_iter()
            .map(|r| -> Result<StaleDraftCandidate> {
                Ok(StaleDraftCandidate {
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
                    graph_json: r.try_get::<Option<String>, _>("graph_json")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if candidates.is_empty() {
            return Ok(StaleDraftArchiveOutcome::default());
        }

        let candidate_ids: Vec<Uuid> = candidates.iter().map(|c| c.id).collect();
        let scan =
            talos_child_workflow_refs::scan_child_parents(&self.db_pool, user_id, &candidate_ids)
                .await
                .context("archive_stale_drafts child-reference scan")?;

        // BOTH exclusions, in one pure pass. Extracted so the classification
        // is unit-testable without a database AND so the write below stays
        // adjacent to `scan_child_parents` — lint check 86's leg (b) reads a
        // 40-line window from the destructive statement, and an inlined loop
        // this long pushes the chokepoint out of it. The right answer to a
        // window that no longer reaches is to move the code, not to add an
        // `allow-execution-blind-draft-path:` marker, which matches
        // file-globally and would blind leg (a) for the whole file.
        let StaleDraftPartition {
            to_archive,
            skipped_children,
            skipped_substantive,
        } = partition_stale_draft_candidates(candidates, &scan);

        let archived = if to_archive.is_empty() {
            0
        } else {
            let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
            let n = sqlx::query(
                "UPDATE workflows SET status = 'archived', updated_at = NOW() \
                 WHERE user_id = $1 \
                   AND id = ANY($2) \
                   AND status = 'draft' \
                   AND NOT EXISTS (SELECT 1 FROM workflow_executions we WHERE we.workflow_id = workflows.id)",
            )
            .bind(user_id)
            .bind(&to_archive)
            .execute(&mut *tx)
            .await
            .map(|r| r.rows_affected())
            .context("archive_stale_drafts")?;
            tx.commit().await?;
            n
        };

        if !skipped_children.is_empty() {
            tracing::info!(
                target: "talos_audit",
                %user_id,
                archived,
                skipped = skipped_children.len(),
                "archive_stale_drafts held back draft(s) an enabled parent dispatches into"
            );
        }
        if !skipped_substantive.is_empty() {
            tracing::info!(
                target: "talos_audit",
                %user_id,
                archived,
                skipped = skipped_substantive.len(),
                "archive_stale_drafts held back draft(s) a human visibly shaped"
            );
        }

        Ok(StaleDraftArchiveOutcome {
            archived,
            skipped_children,
            skipped_substantive,
            unreadable_parents: scan.unreadable_parents().to_vec(),
        })
    }

    /// Count workflows with no capability tags.
    pub async fn get_uncapabilized_count(&self, user_id: Uuid) -> Result<i64> {
        // RFC 0005 S3: self-scope (workflows RLS backstop).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let n = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM workflows \
             WHERE user_id = $1 AND (capabilities IS NULL OR capabilities = '{}')",
        )
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        .context("get_uncapabilized_count")?;
        tx.commit().await?;
        Ok(n)
    }

    /// Fetch UUIDs of workflows with no capability tags (limit 100).
    pub async fn get_ids_without_capabilities(&self, user_id: Uuid) -> Result<Vec<Uuid>> {
        // RFC 0005 S3: self-scope (workflows RLS backstop).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let rows = sqlx::query(
            "SELECT id FROM workflows WHERE user_id = $1 \
             AND (capabilities IS NULL OR capabilities = '{}') LIMIT 100",
        )
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await
        .context("get_ids_without_capabilities")?;
        tx.commit().await?;

        rows.into_iter()
            .map(|r| r.try_get("id").map_err(Into::into))
            .collect::<Result<Vec<_>>>()
    }

    /// Fetch the next upcoming scheduled run for a user. Returns full schedule
    /// metadata (cron, timezone, next_trigger_at, workflow name) so callers can
    /// distinguish "no schedule" from "next firing is hours/days out" without
    /// a follow-up query.
    ///
    /// Pre-r234 this read from a phantom `schedules` table which never existed
    /// in the schema (only `workflow_schedules` is created by migration
    /// `20260309000200_add_workflow_schedules.sql`). The query silently
    /// returned no rows, so session_start always reported next_scheduled_run
    /// as null even when active schedules existed (pain point #8 from
    /// aegix_dev_pain_points.md). All schedule queries are now unified on
    /// the canonical table — see also get_frequently_executed_unscheduled
    /// below.
    pub async fn get_next_scheduled_run(
        &self,
        user_id: Uuid,
    ) -> Result<Option<NextScheduledRunRow>> {
        let row = sqlx::query(
            "SELECT ws.cron_expression, ws.timezone, ws.next_trigger_at, w.name \
             FROM workflow_schedules ws JOIN workflows w ON w.id = ws.workflow_id \
             WHERE ws.user_id = $1 AND ws.is_enabled = true \
             ORDER BY ws.next_trigger_at ASC NULLS LAST LIMIT 1",
        )
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_next_scheduled_run")?;

        row.map(|r| -> Result<NextScheduledRunRow> {
            Ok(NextScheduledRunRow {
                cron_expression: r
                    .try_get::<Option<String>, _>("cron_expression")?
                    .unwrap_or_default(),
                timezone: r
                    .try_get::<Option<String>, _>("timezone")?
                    .unwrap_or_else(|| "UTC".to_string()),
                next_trigger_at: r.try_get::<Option<_>, _>("next_trigger_at")?,
                workflow_name: r.try_get::<Option<String>, _>("name")?.unwrap_or_default(),
            })
        })
        .transpose()
    }

    /// Count active (non-archived) workflows for a user.
    pub async fn get_active_workflow_count(&self, user_id: Uuid) -> Result<i64> {
        // RFC 0005 S3: self-scope (workflows RLS backstop).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let n = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM workflows WHERE user_id = $1 AND status = 'active'",
        )
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        .context("get_active_workflow_count")?;
        tx.commit().await?;
        Ok(n)
    }

    /// Count active workflow schedules for a user.
    pub async fn get_active_schedule_count(&self, user_id: Uuid) -> Result<i64> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM workflow_schedules WHERE user_id = $1 AND is_enabled = true",
        )
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await
        .context("get_active_schedule_count")
    }

    /// Count active workflows that have at least one enabled schedule attached.
    /// Distinct from [`get_active_schedule_count`], which counts schedule rows
    /// (a workflow may have multiple). Used by `schedule_health` to answer the
    /// question "how many of my active workflows are actually scheduled?" —
    /// the previously-published `active_workflows` field misleadingly counted
    /// every status='active' workflow regardless of schedule attachment.
    pub async fn get_active_workflows_with_schedule_count(&self, user_id: Uuid) -> Result<i64> {
        // Pre-fix this filtered `w.status = 'active'`, which excluded
        // workflows in `status='draft'` even though the scheduler
        // happily fires them and they're producing executions every
        // day. Discovered via MCP probe 2026-05-07: the user has 7
        // enabled schedules firing reliably but
        // `workflows_with_active_schedules` reported 0 because every
        // scheduled workflow was a draft (publish_version had never
        // been called). The lifecycle is `draft → active` on publish
        // (per migration 20260318000000), but operators frequently
        // skip that step for personal-use workflows. Loosen to
        // `status != 'archived'` so the metric matches the user's
        // mental model: "how many of my non-archived workflows have
        // an enabled schedule attached?"
        // RFC 0005 S3: self-scope (workflows RLS backstop).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let n = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(DISTINCT w.id) \
             FROM workflows w \
             JOIN workflow_schedules s ON s.workflow_id = w.id \
             WHERE w.user_id = $1 \
               AND w.status != 'archived' \
               AND s.is_enabled = true",
        )
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        .context("get_active_workflows_with_schedule_count")?;
        tx.commit().await?;
        Ok(n)
    }

    /// Workflows that ran ≥3 times in the last 60 days but have no active
    /// schedule. Used by session_start to surface workflows the operator may
    /// want to schedule.
    ///
    /// **Pre-r242 this was named `get_previously_scheduled_unscheduled`** —
    /// a misleading name because workflow_schedules deletes are HARD deletes
    /// (no audit/history table) so we have NO way to know whether a workflow
    /// was ever scheduled. The "previously" framing produced false positives
    /// for manual-trigger utilities (caught in prod 2026-04-29: discovery-call-synthesizer,
    /// ask, sanity-check were all flagged as "may have lost their trigger"
    /// despite never having had a schedule). r242 renamed for honesty +
    /// added two filters that cut the false-positive rate sharply:
    ///
    /// 1. **Sub-workflow exclusion** — workflows invoked via `sub_workflow`
    ///    nodes elsewhere are intentionally invoked, not scheduled. Catches
    ///    standups, reviews, ensemble peers, etc. automatically.
    /// 2. **`interactive` tag opt-out** — operator can stamp manual-trigger
    ///    utilities with the `interactive` tag (via `tag_workflow`) to
    ///    suppress this signal permanently.
    ///
    /// **The sub-workflow exclusion was DEAD for two years, and its own comment
    /// recorded the wrong lesson twice (#762).** r242 wrote the predicate as
    /// `node.kind == 'sub_workflow'` / `node.data.sub_workflow_id`; r243
    /// "corrected" it to `node.module_id == 'system:sub_workflow'` /
    /// `node.config.sub_workflow_id` and wrote down *"the lesson: verify the
    /// actual JSON shape via `get_workflow` before writing JSONB queries
    /// against it"* — having done exactly that and landed on a second shape the
    /// engine also does not write. r244 then fixed a real `::jsonb` cast bug on
    /// top, which made the query RUN, which is why nothing looked broken.
    ///
    /// **Measured on the live fleet 2026-09-05**, both predicates run as SQL
    /// against the real `graph_json` column:
    ///
    /// | predicate | matching nodes |
    /// |---|---|
    /// | r243's `module_id` + `config.sub_workflow_id` | **0** |
    /// | the engine's `type` + `data.*_workflow_id` | **6**, across 5 parents naming 4 children |
    ///
    /// So the filter r242 added to cut a false-positive rate had never excluded
    /// anything. r243's lesson was right in form and wrong in substance: reading
    /// ONE workflow's JSON tells you one node kind's shape, and the engine names
    /// a child through EIGHT distinct `data` keys across eight node kinds, one
    /// of which (`llm_dispatch`'s `routes`) is keyed by arbitrary class labels
    /// that no key-name rule can see at all. **The real lesson is that a
    /// hand-written predicate over `graph_json` is a second implementation of a
    /// question the engine already answers** — so the exclusion now runs through
    /// `talos_child_workflow_refs`, the ONE child-reference scan, which parses
    /// the graph with `talos_workflow_engine_core`'s own key set rather than
    /// restating it in SQL. `child_reference_shape_matches_the_engine_parser`
    /// pins it against that parser, not against a string.
    ///
    /// The exclusion runs in Rust AFTER a widened SQL page
    /// ([`FREQUENTLY_EXECUTED_SCAN_LIMIT`]) so removing a child does not
    /// under-fill the operator's list of ten; the scan is ONE query over that
    /// page, not one per row.
    ///
    /// Note this exclusion is **vacuous on the reference fleet today** and is
    /// stated as such rather than sold as a fix: `HAVING COUNT(we.id) >= 3`
    /// already excludes every pure child, since a child has no execution rows at
    /// all. It bites only a HYBRID — a workflow both dispatched as a child and
    /// triggered directly ≥3 times — of which there are currently zero.
    ///
    /// **r244 fixed a third bug**: `workflows.graph_json` is stored as TEXT
    /// (per `migrations/001_initial_schema.sql:5`), not JSONB. Applying any
    /// JSONB operator directly on the TEXT column errors with
    /// "function ... does not exist". That whole class is gone with the JSONB
    /// predicate it applied to.
    pub async fn get_frequently_executed_unscheduled(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<PrevScheduledRow>> {
        let rows = sqlx::query(
            "SELECT w.id, w.name, COUNT(we.id) AS exec_count \
             FROM workflows w \
             JOIN workflow_executions we ON we.workflow_id = w.id \
             WHERE w.user_id = $1 \
               AND we.started_at > NOW() - INTERVAL '60 days' \
               AND (w.status IS NULL OR w.status != 'archived') \
               AND NOT EXISTS ( \
                   SELECT 1 FROM workflow_schedules ws \
                   WHERE ws.workflow_id = w.id AND ws.is_enabled = true \
               ) \
               AND NOT (w.tags && ARRAY['interactive']::text[]) \
             GROUP BY w.id, w.name \
             HAVING COUNT(we.id) >= 3 \
             ORDER BY exec_count DESC, w.id LIMIT $2",
        )
        .bind(user_id)
        .bind(FREQUENTLY_EXECUTED_SCAN_LIMIT)
        .fetch_all(&self.db_pool)
        .await
        .context("get_frequently_executed_unscheduled")?;

        let candidates: Vec<PrevScheduledRow> = rows
            .into_iter()
            .map(|r| -> Result<PrevScheduledRow> {
                Ok(PrevScheduledRow {
                    id: r.try_get::<Option<Uuid>, _>("id")?.unwrap_or(Uuid::nil()),
                    name: r.try_get::<Option<String>, _>("name")?.unwrap_or_default(),
                    exec_count: r.try_get::<Option<i64>, _>("exec_count")?.unwrap_or(0),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        // ONE scan over the whole page — the exclusion the dead SQL predicate
        // was trying to express, run through the shared implementation.
        // Propagated, never defaulted: an empty scan reads as "nobody is
        // anybody's child", which is precisely the pre-#762 behaviour, and this
        // method's caller already swallows its `Err` into an empty list with a
        // warning, so a failure costs the operator a MISSING signal rather than
        // a wrong one.
        let ids: Vec<Uuid> = candidates.iter().map(|c| c.id).collect();
        let scan = talos_child_workflow_refs::scan_child_parents(&self.db_pool, user_id, &ids)
            .await
            .context("get_frequently_executed_unscheduled: child-reference scan")?;

        Ok(candidates
            .into_iter()
            // `parents_of`, not `protection_for`: this is a REPORT signal
            // ("consider scheduling this"), and holding back a suggestion on
            // the strength of a parent nobody could read would suppress advice
            // rather than a destructive act. An unreadable parent therefore
            // leaves the suggestion in place — the loud direction here.
            .filter(|c| scan.parents_of(c.id).is_empty())
            .take(FREQUENTLY_EXECUTED_RESULT_LIMIT)
            .collect())
    }

    // ── Approval gates ────────────────────────────────────────────────────────

    /// Check whether a workflow is owned by the given user.
    pub async fn check_workflow_ownership(&self, wf_id: Uuid, user_id: Uuid) -> Result<bool> {
        // RFC 0005 S3: self-scope (workflows RLS backstop).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM workflows WHERE id = $1 AND user_id = $2)",
        )
        .bind(wf_id)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        .context("check_workflow_ownership")?;
        tx.commit().await?;
        Ok(exists)
    }

    /// Insert a new approval gate. Returns the new gate UUID.
    ///
    /// MCP-1192 (2026-05-17): defense-in-depth bound on `expires_hours`
    /// at the repo function boundary. Pre-fix this function trusted
    /// callers to pre-validate; the MCP `handle_create_approval_gate`
    /// validator (1.0..=720.0 since MCP-326) was the only gate. A
    /// future caller forgetting validation would propagate raw f64 to
    /// `NOW() + INTERVAL '1 hour' * $7`:
    ///   - `f64::NAN` / `INFINITY` → Postgres "interval out of range"
    ///     error at request time, opaque to operator.
    ///   - Negative → `NOW() - N hours` → gate immediately expired;
    ///     operator sees success but every approve/reject call 404s.
    ///   - `f64::MAX` → Postgres "interval out of range" or DateTime
    ///     overflow.
    ///   - Zero → same-instant expiration, identical failure mode to
    ///     negative.
    /// Adding the gate here mirrors MCP-1183 / MCP-1184 cross-handler
    /// validation-drift discipline: when N callers must apply the
    /// same bound, push it into the canonical shared function so
    /// drift can't reintroduce the gap.
    /// 720.0 matches the MCP validator's upper bound (30 days).
    #[allow(clippy::too_many_arguments)]
    pub async fn create_approval_gate(
        &self,
        user_id: Uuid,
        title: &str,
        description: Option<&str>,
        payload: &serde_json::Value,
        token: &str,
        continuation_wf: Option<Uuid>,
        expires_hours: f64,
        webhook: Option<&str>,
    ) -> Result<Uuid> {
        if !expires_hours.is_finite() {
            anyhow::bail!(
                "create_approval_gate: expires_hours must be a finite number, got {expires_hours}"
            );
        }
        if !(0.0 < expires_hours && expires_hours <= 720.0) {
            anyhow::bail!(
                "create_approval_gate: expires_hours must be in (0, 720] hours, got {expires_hours}"
            );
        }
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO workflow_approval_gates \
                (user_id, title, description, payload, token, continuation_workflow_id, \
                 expires_at, notification_webhook) \
             VALUES ($1, $2, $3, $4::jsonb, $5, $6, NOW() + INTERVAL '1 hour' * $7, $8) \
             RETURNING id",
        )
        .bind(user_id)
        .bind(title)
        .bind(description)
        .bind(payload)
        .bind(token)
        .bind(continuation_wf)
        .bind(expires_hours)
        .bind(webhook)
        .fetch_one(&self.db_pool)
        .await
        .context("create_approval_gate")
    }

    /// Mark stale pending approval gates as 'expired'.
    pub async fn expire_stale_approval_gates(&self, user_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE workflow_approval_gates \
             SET status = 'expired' \
             WHERE status = 'pending' AND expires_at < NOW() AND user_id = $1",
        )
        .bind(user_id)
        .execute(&self.db_pool)
        .await
        .map(|_| ())
        .context("expire_stale_approval_gates")
    }

    /// List approval gates for a user, optionally filtered by status.
    pub async fn list_approval_gates(
        &self,
        user_id: Uuid,
        status: Option<&str>,
        limit: i32,
    ) -> Result<Vec<ApprovalGateRow>> {
        let rows = if let Some(st) = status {
            sqlx::query(
                "SELECT id, title, description, status, continuation_workflow_id, \
                        created_at, expires_at, resolved_at, resolved_by_type, resolved_by_note \
                 FROM workflow_approval_gates \
                 WHERE user_id = $1 AND status = $2 \
                 ORDER BY created_at DESC LIMIT $3",
            )
            .bind(user_id)
            .bind(st)
            .bind(limit)
            .fetch_all(&self.db_pool)
            .await
        } else {
            sqlx::query(
                "SELECT id, title, description, status, continuation_workflow_id, \
                        created_at, expires_at, resolved_at, resolved_by_type, resolved_by_note \
                 FROM workflow_approval_gates \
                 WHERE user_id = $1 \
                 ORDER BY created_at DESC LIMIT $2",
            )
            .bind(user_id)
            .bind(limit)
            .fetch_all(&self.db_pool)
            .await
        }
        .context("list_approval_gates")?;

        rows.into_iter()
            .map(|r| -> Result<ApprovalGateRow> {
                Ok(ApprovalGateRow {
                    id: r.try_get::<Option<Uuid>, _>("id")?.unwrap_or(Uuid::nil()),
                    title: r.try_get::<Option<String>, _>("title")?.unwrap_or_default(),
                    description: r.try_get::<Option<String>, _>("description")?,
                    status: r
                        .try_get::<Option<String>, _>("status")?
                        .unwrap_or_default(),
                    continuation_workflow_id: r
                        .try_get::<Option<Uuid>, _>("continuation_workflow_id")?,
                    created_at: r
                        .try_get::<Option<DateTime<Utc>>, _>("created_at")?
                        .unwrap_or_else(chrono::Utc::now),
                    expires_at: r
                        .try_get::<Option<DateTime<Utc>>, _>("expires_at")?
                        .unwrap_or_else(chrono::Utc::now),
                    resolved_at: r.try_get::<Option<DateTime<Utc>>, _>("resolved_at")?,
                    resolved_by_type: r.try_get::<Option<String>, _>("resolved_by_type")?,
                    resolved_by_note: r.try_get::<Option<String>, _>("resolved_by_note")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Fetch the detail fields needed to resolve an approval gate.
    pub async fn get_approval_gate(
        &self,
        gate_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<ApprovalGateDetailRow>> {
        let row = sqlx::query(
            "SELECT status, continuation_workflow_id, payload \
             FROM workflow_approval_gates \
             WHERE id = $1 AND user_id = $2",
        )
        .bind(gate_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_approval_gate")?;

        row.map(|r| -> Result<ApprovalGateDetailRow> {
            Ok(ApprovalGateDetailRow {
                status: r
                    .try_get::<Option<String>, _>("status")?
                    .unwrap_or_default(),
                continuation_workflow_id: r
                    .try_get::<Option<Uuid>, _>("continuation_workflow_id")?,
                payload: r
                    .try_get::<Option<serde_json::Value>, _>("payload")?
                    .unwrap_or(serde_json::json!({})),
            })
        })
        .transpose()
    }

    /// Resolve a PENDING approval gate (approve/reject). Returns rows affected —
    /// `0` means the gate was no longer `pending` (already resolved/cancelled/
    /// expired by a concurrent caller), so the caller MUST NOT fire the
    /// continuation workflow.
    ///
    /// The `AND status = 'pending'` guard makes resolution single-use at the DB
    /// layer, closing a TOCTOU window: the MCP handler reads the gate, checks
    /// `status == "pending"` in Rust, then calls this. Without the guard two
    /// concurrent approvals both pass the Rust check and both UPDATE + both fire
    /// the continuation (e.g. a payment runs twice). Mirrors the atomic guard the
    /// public webhook path and `cancel_approval_gate` already use.
    pub async fn resolve_approval_gate(
        &self,
        gate_id: Uuid,
        user_id: Uuid,
        status: &str,
        note: Option<&str>,
    ) -> Result<u64> {
        sqlx::query(
            "UPDATE workflow_approval_gates \
             SET status = $1, resolved_at = NOW(), resolved_by_type = 'mcp_agent', \
                 resolved_by_note = $2 \
             WHERE id = $3 AND user_id = $4 AND status = 'pending'",
        )
        .bind(status)
        .bind(note)
        .bind(gate_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await
        .map(|r| r.rows_affected())
        .context("resolve_approval_gate")
    }

    /// Cancel a pending approval gate. Returns rows affected.
    pub async fn cancel_approval_gate(&self, gate_id: Uuid, user_id: Uuid) -> Result<u64> {
        sqlx::query(
            "UPDATE workflow_approval_gates \
             SET status = 'cancelled', resolved_at = NOW(), resolved_by_type = 'mcp_agent' \
             WHERE id = $1 AND user_id = $2 AND status = 'pending'",
        )
        .bind(gate_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await
        .map(|r| r.rows_affected())
        .context("cancel_approval_gate")
    }

    /// Fetch (title, notification_webhook) for an approval gate (ownership-checked).
    pub async fn get_approval_gate_webhook(
        &self,
        gate_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<(String, Option<String>)>> {
        let row = sqlx::query(
            "SELECT title, notification_webhook \
             FROM workflow_approval_gates \
             WHERE id = $1 AND user_id = $2",
        )
        .bind(gate_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_approval_gate_webhook")?;

        row.map(|r| -> Result<(String, Option<String>)> {
            let title: String = r
                .try_get::<Option<String>, _>("title")?
                .unwrap_or_else(|| "Approval Required".to_string());
            let webhook: Option<String> = r.try_get("notification_webhook")?;
            Ok((title, webhook))
        })
        .transpose()
    }

    // ── Continuation-workflow helpers ─────────────────────────────────────────

    /// Insert a 'queued' workflow execution record.
    ///
    /// MCP-1205 (2026-05-17): bound + DLP-scrub the `payload` before
    /// binding to `workflow_executions.input_data`. This is the
    /// sibling JSONB column to `output_data` (MCP-1204) on the same
    /// table, written by the continuation-trigger path (approval-
    /// gate webhook / workflow-suspension resume). Pre-fix the
    /// caller-supplied `payload` (operator-resume body, webhook
    /// approval JSON, etc.) was bound raw with no size cap AND no
    /// DLP scrub:
    ///
    ///   - `redact_json` was never applied — webhook approval bodies
    ///     carrying secret-shaped tokens in comment fields landed in
    ///     the column unredacted, queryable via audit dashboards.
    ///   - No size cap — a 100 MiB approval-gate body (misbehaved
    ///     upstream / DoS attempt that survives the webhook router's
    ///     own cap) would pin controller heap during the JSON
    ///     serialise + bind.
    ///
    /// The 10 MiB ceiling matches the sibling `bound_execution_payload`
    /// applied at the output side in MCP-1204; the DLP scrub matches
    /// the canonical persistence-boundary discipline (MCP-466/481/
    /// 967/971/972 family).
    pub async fn insert_queued_execution(
        &self,
        exec_id: Uuid,
        wf_id: Uuid,
        user_id: Uuid,
        payload: &serde_json::Value,
    ) -> Result<()> {
        let bounded = talos_dlp_provider::bound_execution_payload(payload);
        let scrubbed = talos_dlp_provider::redact_json(&bounded);
        sqlx::query(
            "INSERT INTO workflow_executions \
                (id, workflow_id, user_id, status, input_data, started_at) \
             VALUES ($1, $2, $3, 'queued', $4::jsonb, NOW())",
        )
        .bind(exec_id)
        .bind(wf_id)
        .bind(user_id)
        .bind(&scrubbed)
        .execute(&self.db_pool)
        .await
        .map(|_| ())
        .context("insert_queued_execution")
    }

    /// Write back the continuation execution ID to an approval gate.
    pub async fn set_gate_execution_id(&self, gate_id: Uuid, exec_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE workflow_approval_gates SET continuation_execution_id = $1 WHERE id = $2",
        )
        .bind(exec_id)
        .bind(gate_id)
        .execute(&self.db_pool)
        .await
        .map(|_| ())
        .context("set_gate_execution_id")
    }

    /// Fetch graph_json for a workflow (ownership-checked).
    pub async fn get_workflow_graph_json(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<String>> {
        sqlx::query_scalar::<_, String>(
            "SELECT graph_json FROM workflows WHERE id = $1 AND user_id = $2",
        )
        .bind(wf_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_workflow_graph_json")
    }

    /// MCP-564: ownership-checked fetch of a workflow's bound actor_id.
    /// Returns Ok(None) if the workflow doesn't exist OR isn't owned by
    /// `user_id` OR has no bound actor. Used by `trigger_continuation_workflow`
    /// to gate dispatch on the actor's budget/status — the webhook /
    /// approval-resolve path was the last unguarded dispatch surface
    /// after the MCP-555/MCP-557 sweep covered scheduler / engine chains
    /// / retry.
    pub async fn get_workflow_actor_id(&self, wf_id: Uuid, user_id: Uuid) -> Result<Option<Uuid>> {
        let row: Option<(Option<Uuid>,)> =
            sqlx::query_as("SELECT actor_id FROM workflows WHERE id = $1 AND user_id = $2")
                .bind(wf_id)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await
                .context("get_workflow_actor_id")?;
        Ok(row.and_then(|r| r.0))
    }

    /// Fail a workflow execution with an error message.
    pub async fn fail_execution(&self, exec_id: Uuid, error: &str) -> Result<()> {
        // MCP-970 (2026-05-15): DLP-redact at the bind boundary.
        // Yet another `fail_execution` variant — sibling to MCP-967
        // (WorkflowRepository / ExecutionRepository),
        // MCP-968 (ActorRepository / module-execs / engine), and
        // MCP-969 (format!() drift sites). Four repository crates
        // own copies of this method shape — every one needs the
        // redact-before-bind discipline.
        //
        // MCP-1164 (2026-05-17): truncate-then-redact discipline,
        // sibling to MCP-1161 which closed the same gap on
        // `WorkflowRepository::mark_execution_failed`. THREE
        // repositories write to `workflow_executions.error_message`:
        // WorkflowRepository (fixed in MCP-1161), AdvancedRepository
        // (this site), ActorRepository (sibling fix in same commit).
        // The MCP-1161 audit noted "when retrofitting a discipline
        // to N columns on a table, sweep the related boundaries" —
        // this is the third sweep of the same `error_message` column
        // across the three writer crates. 4 KiB matches the MCP-1161
        // ceiling and the MCP-1160 sibling on webhook_request_log.
        let truncated: &str = if error.len() > 4096 {
            talos_text_util::truncate_at_char_boundary(error, 4096)
        } else {
            error
        };
        let redacted_error = talos_dlp_provider::redact_str(truncated);
        sqlx::query(
            "UPDATE workflow_executions \
             SET status = 'failed', error_message = $1, completed_at = NOW() \
             WHERE id = $2 AND status NOT IN ('completed', 'failed', 'cancelled', 'resuming')",
        )
        .bind(&redacted_error)
        .bind(exec_id)
        .execute(&self.db_pool)
        .await
        .map(|_| ())
        .context("fail_execution")
    }

    /// Cancel all still-running module_executions for a workflow execution.
    /// Called after marking a workflow as failed so parallel siblings are cleaned up.
    pub async fn cancel_running_module_executions(&self, execution_id: Uuid) -> Result<()> {
        let result = sqlx::query(
            "UPDATE module_executions \
             SET status = 'cancelled', completed_at = NOW(), \
                 error_message = 'Workflow failed — parallel sibling cancelled' \
             WHERE workflow_execution_id = $1 AND status = 'running'",
        )
        .bind(execution_id)
        .execute(&self.db_pool)
        .await
        .context("cancel_running_module_executions")?;
        tracing::info!(
            execution_id = %execution_id,
            cancelled = result.rows_affected(),
            "sibling cancellation UPDATE complete"
        );
        Ok(())
    }

    /// Transition a queued execution to 'running'.
    pub async fn set_execution_running(&self, exec_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE workflow_executions SET status = 'running', started_at = NOW() \
             WHERE id = $1 AND status = 'queued'",
        )
        .bind(exec_id)
        .execute(&self.db_pool)
        .await
        .map(|_| ())
        .context("set_execution_running")
    }

    // MCP-683 (2026-05-13): the former `complete_execution` method was
    // removed here. Pre-fix it wrote `output_data = $2` plaintext via
    // raw SQL — bypassing Phase A encryption for every continuation
    // workflow (its sole caller). The caller in
    // `talos_continuation_trigger` now routes through
    // `WorkflowRepository::with_encryption(...).mark_execution_{completed,waiting}`
    // (same fix shape as MCP-682). Leaving a stub here would tempt
    // future code to re-introduce the bypass; deletion makes the
    // regression fail-closed at the type level.

    // ── SLA thresholds ────────────────────────────────────────────────────────

    /// Verify workflow ownership (returns id if found).
    pub async fn verify_workflow_ownership_exists(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool> {
        let exists: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM workflows WHERE id = $1 AND user_id = $2")
                .bind(wf_id)
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await
                .context("verify_workflow_ownership_exists")?;
        Ok(exists.is_some())
    }

    /// Create or update an SLA threshold for a workflow.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_sla_threshold(
        &self,
        id: Uuid,
        wf_id: Uuid,
        user_id: Uuid,
        p95_latency_ms: Option<i64>,
        success_rate_pct: Option<f64>,
        webhook: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO workflow_sla_thresholds \
             (id, workflow_id, user_id, p95_latency_ms, success_rate_pct, notification_webhook) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (workflow_id, user_id) DO UPDATE SET \
                 p95_latency_ms       = EXCLUDED.p95_latency_ms, \
                 success_rate_pct     = EXCLUDED.success_rate_pct, \
                 notification_webhook = EXCLUDED.notification_webhook",
        )
        .bind(id)
        .bind(wf_id)
        .bind(user_id)
        .bind(p95_latency_ms)
        .bind(success_rate_pct)
        .bind(webhook)
        .execute(&self.db_pool)
        .await
        .map(|_| ())
        .context("upsert_sla_threshold")
    }

    /// List all SLA thresholds for a user (with workflow name).
    pub async fn list_sla_thresholds(&self, user_id: Uuid) -> Result<Vec<SlaThresholdRow>> {
        // RFC 0005 S3: self-scope so the workflows RLS policy backstops
        // the ownership JOIN (workflow_sla_thresholds has no policy itself).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let rows = sqlx::query(
            "SELECT t.id, t.workflow_id, w.name AS workflow_name, \
                    t.p95_latency_ms, t.success_rate_pct::float8 AS success_rate_pct, \
                    t.notification_webhook, t.created_at \
             FROM workflow_sla_thresholds t \
             JOIN workflows w ON w.id = t.workflow_id \
             WHERE t.user_id = $1 \
             ORDER BY t.created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await
        .context("list_sla_thresholds")?;
        tx.commit().await?;

        rows.into_iter()
            .map(|r| -> Result<SlaThresholdRow> {
                Ok(SlaThresholdRow {
                    id: r.try_get("id")?,
                    workflow_id: r.try_get("workflow_id")?,
                    workflow_name: r.try_get("workflow_name")?,
                    p95_latency_ms: r.try_get("p95_latency_ms")?,
                    success_rate_pct: r.try_get("success_rate_pct")?,
                    notification_webhook: r.try_get("notification_webhook")?,
                    created_at: r.try_get("created_at")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Fetch SLA threshold config for webhook testing.
    pub async fn get_sla_threshold(
        &self,
        wf_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<SlaThresholdConfigRow>> {
        let row = sqlx::query(
            "SELECT notification_webhook, p95_latency_ms, success_rate_pct \
             FROM workflow_sla_thresholds \
             WHERE workflow_id = $1 AND user_id = $2",
        )
        .bind(wf_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_sla_threshold")?;

        row.map(|r| -> Result<SlaThresholdConfigRow> {
            Ok(SlaThresholdConfigRow {
                notification_webhook: r
                    .try_get::<Option<String>, _>("notification_webhook")?
                    .unwrap_or_default(),
                p95_latency_ms: r.try_get::<Option<i64>, _>("p95_latency_ms")?,
                success_rate_pct: r.try_get::<Option<f64>, _>("success_rate_pct")?,
            })
        })
        .transpose()
    }

    // ── Built-in templates ────────────────────────────────────────────────────

    /// Remove stale system-published marketplace entries (sandbox/QA templates).
    /// Returns the number of entries removed.
    pub async fn remove_stale_system_marketplace(&self) -> Result<u64> {
        // Phase 5.1: unified `modules` table; canonical id match only.
        sqlx::query(
            "DELETE FROM module_marketplace mm
             WHERE mm.publisher_id = '00000000-0000-0000-0000-000000000000'::uuid
               AND EXISTS (
                   SELECT 1 FROM modules m
                   WHERE m.id = mm.module_id
                     AND (
                         m.user_id IS NOT NULL
                         OR m.name IS NULL
                         OR m.description IS NULL
                         OR m.description = ''
                     )
               )",
        )
        .execute(&self.db_pool)
        .await
        .map(|r| r.rows_affected())
        .context("remove_stale_system_marketplace")
    }

    /// Publish all system-seeded (first-party) templates not yet listed.
    /// Returns the number of entries published.
    pub async fn publish_system_templates(&self) -> Result<u64> {
        // Phase 5.1: unified `modules` table; canonical id dedup only.
        sqlx::query(
            "INSERT INTO module_marketplace
                 (id, module_id, publisher_id, name, description, capability_world,
                  version, is_public, tags, verified)
             SELECT
                 gen_random_uuid(), m.id,
                 '00000000-0000-0000-0000-000000000000'::uuid,
                 m.name, m.description, m.capability_world,
                 '1.0.0', true, ARRAY[]::text[], true
             FROM modules m
             WHERE m.user_id IS NULL
               AND m.kind = 'catalog'
               AND m.name IS NOT NULL
               AND m.description IS NOT NULL
               AND m.description != ''
               AND NOT EXISTS (
                   SELECT 1 FROM module_marketplace mm
                   WHERE mm.module_id = m.id
               )",
        )
        .execute(&self.db_pool)
        .await
        .map(|r| r.rows_affected())
        .context("publish_system_templates")
    }

    // ── Workflow suspensions ──────────────────────────────────────────────────

    /// Create a workflow suspension and return its UUID.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_suspension(
        &self,
        user_id: Uuid,
        correlation_id: &str,
        description: Option<&str>,
        continuation_wf: Option<Uuid>,
        state: Option<&serde_json::Value>,
        timeout_at: Option<DateTime<Utc>>,
        callback_url: &str,
    ) -> Result<Uuid> {
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO workflow_suspensions \
                (user_id, correlation_id, description, continuation_workflow_id, state, \
                 timeout_at, callback_url) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             RETURNING id",
        )
        .bind(user_id)
        .bind(correlation_id)
        .bind(description)
        .bind(continuation_wf)
        .bind(state)
        .bind(timeout_at)
        .bind(callback_url)
        .fetch_one(&self.db_pool)
        .await
        .context("create_suspension")
    }

    /// List workflow suspensions for a user, optionally filtered by status.
    pub async fn list_suspensions(
        &self,
        user_id: Uuid,
        status: Option<&str>,
    ) -> Result<Vec<SuspensionRow>> {
        let rows = if let Some(st) = status {
            sqlx::query(
                "SELECT id, correlation_id, description, status, continuation_workflow_id, \
                        callback_url, timeout_at, resumed_at, resumed_by, created_at \
                 FROM workflow_suspensions \
                 WHERE user_id = $1 AND status = $2 \
                 ORDER BY created_at DESC LIMIT 50",
            )
            .bind(user_id)
            .bind(st)
            .fetch_all(&self.db_pool)
            .await
        } else {
            sqlx::query(
                "SELECT id, correlation_id, description, status, continuation_workflow_id, \
                        callback_url, timeout_at, resumed_at, resumed_by, created_at \
                 FROM workflow_suspensions \
                 WHERE user_id = $1 \
                 ORDER BY created_at DESC LIMIT 50",
            )
            .bind(user_id)
            .fetch_all(&self.db_pool)
            .await
        }
        .context("list_suspensions")?;

        rows.into_iter()
            .map(|r| -> Result<SuspensionRow> {
                Ok(SuspensionRow {
                    id: r.try_get("id")?,
                    correlation_id: r.try_get("correlation_id")?,
                    description: r.try_get("description")?,
                    status: r.try_get("status")?,
                    continuation_workflow_id: r.try_get("continuation_workflow_id")?,
                    callback_url: r.try_get("callback_url")?,
                    timeout_at: r.try_get("timeout_at")?,
                    resumed_at: r.try_get("resumed_at")?,
                    resumed_by: r.try_get("resumed_by")?,
                    created_at: r.try_get("created_at")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Fetch a suspension by correlation_id (ownership-checked) for resumption.
    pub async fn get_suspension_by_correlation(
        &self,
        correlation_id: &str,
        user_id: Uuid,
    ) -> Result<Option<SuspensionDetailRow>> {
        let row = sqlx::query(
            "SELECT id, status, continuation_workflow_id \
             FROM workflow_suspensions \
             WHERE correlation_id = $1 AND user_id = $2",
        )
        .bind(correlation_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("get_suspension_by_correlation")?;

        row.map(|r| -> Result<SuspensionDetailRow> {
            Ok(SuspensionDetailRow {
                id: r.try_get("id")?,
                status: r.try_get("status")?,
                continuation_workflow_id: r.try_get("continuation_workflow_id")?,
            })
        })
        .transpose()
    }

    /// Mark a suspension as resumed with the given payload.
    pub async fn mark_suspension_resumed(
        &self,
        suspension_id: Uuid,
        payload: &serde_json::Value,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE workflow_suspensions \
             SET status='resumed', resumed_at=now(), resumed_by='mcp_tool', resumed_payload=$1 \
             WHERE id = $2",
        )
        .bind(payload)
        .bind(suspension_id)
        .execute(&self.db_pool)
        .await
        .map(|_| ())
        .context("mark_suspension_resumed")
    }

    /// Atomically claim a waiting suspension for the MCP resume path.
    ///
    /// Combines status check + state transition + payload write in a single
    /// `UPDATE ... WHERE status='waiting' RETURNING` so two concurrent
    /// `resume_workflow_by_correlation_id` calls from the same user cannot
    /// both pass the gate and double-fire the continuation workflow. Mirrors
    /// the atomic claim that the public `/api/callbacks/{correlation_id}`
    /// handler already uses; the MCP path previously did SELECT-check-fire-mark
    /// non-atomically.
    ///
    /// Returns `Ok(Some((id, continuation_workflow_id)))` on a successful claim,
    /// `Ok(None)` if the suspension is missing, owned by another user, or no
    /// longer in 'waiting' state.
    pub async fn claim_suspension_for_mcp_resume(
        &self,
        correlation_id: &str,
        user_id: Uuid,
        payload: &serde_json::Value,
    ) -> Result<Option<(Uuid, Option<Uuid>)>> {
        let row = sqlx::query(
            "UPDATE workflow_suspensions \
             SET status='resumed', resumed_at=now(), resumed_by='mcp_tool', resumed_payload=$1 \
             WHERE correlation_id = $2 AND user_id = $3 AND status = 'waiting' \
             RETURNING id, continuation_workflow_id",
        )
        .bind(payload)
        .bind(correlation_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("claim_suspension_for_mcp_resume")?;

        row.map(|r| -> Result<(Uuid, Option<Uuid>)> {
            Ok((r.try_get("id")?, r.try_get("continuation_workflow_id")?))
        })
        .transpose()
    }

    /// Cancel a waiting suspension by correlation_id. Returns rows affected.
    ///
    /// MCP-828 (2026-05-14): stamps `resumed_by='mcp_tool'` so the in-table
    /// audit trail mirrors every other state-transition path out of waiting
    /// (resume via MCP → `'mcp_tool'`, resume via public callback →
    /// `'callback_url'`, timeout expiry → `'timeout_expiry'`). Pre-fix the
    /// column was left NULL on cancel, so an audit query like
    /// `WHERE resumed_by='mcp_tool'` to surface MCP-driven state transitions
    /// silently missed every cancellation — `resumed_at` was already being
    /// stamped, so the row LOOKED like a resume to readers that didn't
    /// also project `status`. Same misleading-success class as MCP-737/738/800.
    pub async fn cancel_suspension(&self, correlation_id: &str, user_id: Uuid) -> Result<u64> {
        sqlx::query(
            "UPDATE workflow_suspensions \
             SET status='cancelled', resumed_at=now(), resumed_by='mcp_tool' \
             WHERE correlation_id = $1 AND user_id = $2 AND status = 'waiting'",
        )
        .bind(correlation_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await
        .map(|r| r.rows_affected())
        .context("cancel_suspension")
    }

    /// Execute a pre-validated SELECT statement wrapped in a pagination
    /// subquery and return the raw rows. Used **only** by `handle_query_paginated`
    /// in `mcp/advanced.rs` — that handler enforces all the safety invariants
    /// (admin-only auth, SELECT-only, no semicolons / UNION / INTERSECT /
    /// EXCEPT / CTEs / EXPLAIN / SQL comments, blocked-table list, blocked-schema
    /// list, cursor_column allowlisted to `[a-zA-Z0-9_]`).
    ///
    /// **CRITICAL — DO NOT CALL FROM ANYWHERE ELSE WITHOUT AUDITING THE
    /// VALIDATION STACK.** This method intentionally accepts a free-form SQL
    /// fragment because the alternative — a structured query DSL that mirrors
    /// arbitrary `SELECT` shapes — is materially worse than the current
    /// well-bounded inline shape. The repo owns only the immutable wrapper
    /// template (`SELECT * FROM (<base>) AS _paginated_subquery ...`) so that
    /// the pagination contract has exactly one home.
    ///
    /// `validated_base_query` MUST be a single `SELECT` statement that has
    /// already passed the handler's validation pipeline. `mode` carries the
    /// pre-validated cursor column or offset.
    pub async fn execute_paginated_select(
        &self,
        validated_base_query: &str,
        page_size: i64,
        mode: PaginationMode<'_>,
    ) -> Result<Vec<sqlx::postgres::PgRow>, sqlx::Error> {
        match mode {
            PaginationMode::Cursor { column, after } => {
                // The cursor `column` is already constrained to [a-zA-Z0-9_]
                // by the calling handler; double-quoting handles reserved words.
                let q = format!(
                    "SELECT * FROM ({}) AS _paginated_subquery \
                     WHERE CAST(\"{}\" AS text) > $2 ORDER BY \"{}\" ASC LIMIT $1",
                    validated_base_query, column, column
                );
                sqlx::query(&q)
                    .bind(page_size + 1)
                    .bind(after)
                    .fetch_all(&self.db_pool)
                    .await
            }
            PaginationMode::Offset { offset } => {
                // Generic paginator: the ORDER BY + any unique tiebreaker live in
                // the caller-supplied, pre-validated `validated_base_query`. The
                // Cursor mode above is the deterministic keyset path.
                // allow-offset-no-tiebreaker: caller-owned ORDER BY in base query
                let q = format!(
                    "SELECT * FROM ({}) AS _paginated_subquery LIMIT $1 OFFSET $2",
                    validated_base_query
                );
                sqlx::query(&q)
                    .bind(page_size + 1)
                    .bind(offset)
                    .fetch_all(&self.db_pool)
                    .await
            }
        }
    }

    // ── advanced.rs MCP-handler support ────────────────────────────────────

    /// Search marketplace listings with optional `query` (ILIKE name),
    /// `world_filter` (capability_world equality), and `tag_filter`.
    /// Builds the dynamic SQL inside the repo so the handler doesn't have to
    /// touch raw SQL — the variable shape is constrained to a fixed set of
    /// optional WHERE clauses.
    pub async fn search_marketplace(
        &self,
        filter: MarketplaceSearchFilter<'_>,
        limit: i64,
    ) -> Result<Vec<MarketplaceSearchRow>> {
        let mut sql = String::from(
            "SELECT id, module_id, publisher_id, name, description, capability_world, version, downloads, tags, created_at \
             FROM module_marketplace WHERE is_public = true",
        );
        let mut bind_idx = 0u32;
        let mut binds: Vec<String> = Vec::new();

        if let Some(q) = filter.query {
            if !q.is_empty() {
                bind_idx += 1;
                sql.push_str(&format!(" AND name ILIKE ${}", bind_idx));
                binds.push(format!("%{}%", q));
            }
        }
        if let Some(world) = filter.world {
            bind_idx += 1;
            sql.push_str(&format!(" AND capability_world = ${}", bind_idx));
            binds.push(world.to_string());
        }
        if let Some(tag) = filter.tag {
            bind_idx += 1;
            sql.push_str(&format!(" AND ${} = ANY(tags)", bind_idx));
            binds.push(tag.to_string());
        }
        bind_idx += 1;
        sql.push_str(&format!(" ORDER BY downloads DESC LIMIT ${}", bind_idx));

        let mut q = sqlx::query(&sql);
        for b in &binds {
            q = q.bind(b);
        }
        q = q.bind(limit);

        let rows = q.fetch_all(&self.db_pool).await?;
        rows.iter()
            .map(|r| -> Result<MarketplaceSearchRow> {
                Ok(MarketplaceSearchRow {
                    id: r.try_get("id")?,
                    module_id: r.try_get("module_id")?,
                    name: r.try_get("name")?,
                    description: r
                        .try_get::<Option<String>, _>("description")?
                        .unwrap_or_default(),
                    capability_world: r.try_get("capability_world")?,
                    version: r.try_get("version")?,
                    downloads: r.try_get("downloads")?,
                    tags: r.try_get("tags")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Find groups of workflows with duplicate names (top 10 most-duplicated
    /// groups), returning every member of each group with id + created_at.
    /// Used by `agent_session_start` for ghost-workflow detection.
    pub async fn find_workflow_duplicate_name_groups(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<WorkflowDuplicateGroupRow>> {
        let rows: Vec<(Uuid, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
            "SELECT id, name, created_at \
             FROM workflows \
             WHERE user_id = $1 \
               AND (status IS NULL OR status != 'archived') \
               AND name IN ( \
                 SELECT name FROM workflows \
                 WHERE user_id = $1 AND (status IS NULL OR status != 'archived') \
                 GROUP BY name HAVING COUNT(*) > 1 \
                 ORDER BY COUNT(*) DESC, name ASC \
                 LIMIT 10 \
               ) \
             ORDER BY name ASC, created_at ASC",
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, name, created_at)| WorkflowDuplicateGroupRow {
                id,
                name,
                created_at,
            })
            .collect())
    }

    /// Pinned modules with a flag indicating whether the user has the
    /// installed module row (true) or needs to call
    /// restore_pinned_modules (false). Distinct from the simpler version on
    /// ModuleRepository which checks `modules.wasm_bytes` presence — this
    /// variant checks for the user's per-install modules row.
    pub async fn list_pinned_modules_with_user_install_status(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<PinnedModuleInstallStatus>> {
        // Phase 5: modules.user_id + name is the new per-user install
        // signal. The old wasm_modules/node_templates join collapses to a
        // single lookup by (user_id, name).
        // RFC 0004 M4: user_module_pins is RLS-enforced — run on the
        // per-user scoped tx so the policy's user_id clause matches.
        let mut tx = self.user_scoped_tx(user_id).await?;
        let rows = sqlx::query(
            "SELECT pm.module_name, \
                    EXISTS( \
                        SELECT 1 FROM modules m \
                        WHERE m.user_id = $1 AND m.name = pm.module_name \
                    ) AS has_wasm \
             FROM user_module_pins pm \
             WHERE pm.user_id = $1 \
             ORDER BY pm.pinned_at ASC \
             LIMIT $2",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.iter()
            .map(|r| -> Result<PinnedModuleInstallStatus> {
                Ok(PinnedModuleInstallStatus {
                    module_name: r.try_get("module_name")?,
                    has_wasm: r.try_get::<Option<bool>, _>("has_wasm")?.unwrap_or(false),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Active actors with active-memory count subquery. Used by
    /// `agent_session_start` to surface persona context.
    pub async fn list_active_actors_with_memory_count(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<ActiveActorWithMemoryRow>> {
        let rows = sqlx::query(
            "SELECT id, name, description, status, max_capability_world, \
                    (SELECT COUNT(*) FROM actor_memory am \
                     WHERE am.actor_id = a.id \
                       AND (am.expires_at IS NULL OR am.expires_at > NOW())) AS memory_count \
             FROM actors a \
             WHERE a.user_id = $1 AND a.status != 'archived' \
             ORDER BY a.created_at DESC \
             LIMIT $2",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(|r| -> Result<ActiveActorWithMemoryRow> {
                Ok(ActiveActorWithMemoryRow {
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
                    description: r.try_get::<Option<String>, _>("description")?,
                    status: r
                        .try_get::<Option<String>, _>("status")?
                        .unwrap_or_else(|| "active".to_string()),
                    max_capability_world: r
                        .try_get::<Option<String>, _>("max_capability_world")?
                        .unwrap_or_else(|| "minimal-node".to_string()),
                    memory_count: r.try_get::<Option<i64>, _>("memory_count")?.unwrap_or(0),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Recent execution activity for the agent's session-start awareness.
    ///
    /// Returns up to `limit` workflow executions that are either:
    /// - currently `running` (regardless of age — surface long-running jobs
    ///   the agent kicked off and may have lost the response for), OR
    /// - reached a terminal state within the last `minutes_window` minutes
    ///   (so the agent that just reconnected can see what happened in the gap).
    ///
    /// Joined with `workflows` for the human-readable `name` so the agent
    /// can present the activity without a follow-up RTT.
    ///
    /// Designed to address the MCP-transport drop-response failure mode:
    /// long-running synchronous tools (test_workflow, call_workflow) where
    /// the server keeps executing past the client's read deadline. Without
    /// this, the agent thinks "session expired" → executes failed → retries
    /// → double-billed LLM calls + ghost work.
    pub async fn list_recent_executions_for_session_awareness(
        &self,
        user_id: Uuid,
        minutes_window: i32,
        limit: i64,
    ) -> Result<Vec<RecentExecutionRow>> {
        let rows = sqlx::query(
            "SELECT \
                we.id AS execution_id, \
                we.workflow_id, \
                COALESCE(w.name, '<deleted>') AS workflow_name, \
                we.status, \
                we.started_at, \
                we.completed_at, \
                CASE \
                    WHEN we.completed_at IS NOT NULL \
                    THEN ROUND(EXTRACT(EPOCH FROM (we.completed_at - we.started_at)) * 1000)::bigint \
                    ELSE NULL \
                END AS duration_ms \
             FROM workflow_executions we \
             LEFT JOIN workflows w ON w.id = we.workflow_id \
             WHERE we.user_id = $1 \
               AND ( \
                   we.status = 'running' \
                   OR we.completed_at >= NOW() - INTERVAL '1 minute' * $2 \
               ) \
             ORDER BY \
               CASE WHEN we.status = 'running' THEN 0 ELSE 1 END, \
               COALESCE(we.completed_at, we.started_at) DESC \
             LIMIT $3",
        )
        .bind(user_id)
        .bind(minutes_window)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(|r| -> Result<RecentExecutionRow> {
                Ok(RecentExecutionRow {
                    execution_id: r.try_get("execution_id")?,
                    workflow_id: r.try_get("workflow_id")?,
                    workflow_name: r
                        .try_get::<Option<String>, _>("workflow_name")?
                        .unwrap_or_default(),
                    status: r.try_get("status")?,
                    started_at: r.try_get::<Option<_>, _>("started_at")?,
                    completed_at: r.try_get::<Option<_>, _>("completed_at")?,
                    duration_ms: r.try_get::<Option<i64>, _>("duration_ms")?,
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Stuck executions: status = 'running' for more than `hours_threshold`
    /// hours. Returns hours-stuck as f64 (rounded server-side via EXTRACT).
    pub async fn list_stuck_executions(
        &self,
        user_id: Uuid,
        hours_threshold: i32,
        limit: i64,
    ) -> Result<Vec<StuckExecutionRow>> {
        // The `INTERVAL '1 hour' * $2` form binds the hours threshold safely
        // (vs concatenating into the literal). Note: PostgreSQL accepts
        // multiplying an interval by an integer.
        let rows = sqlx::query(
            "SELECT id, workflow_id, status, started_at, \
                    ROUND(EXTRACT(EPOCH FROM (NOW()-started_at))/3600, 1)::float8 AS hours_stuck \
             FROM workflow_executions \
             WHERE user_id = $1 AND status = 'running' \
               AND started_at < NOW() - INTERVAL '1 hour' * $2 \
             ORDER BY started_at ASC LIMIT $3",
        )
        .bind(user_id)
        .bind(hours_threshold)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        rows.iter()
            .map(|r| -> Result<StuckExecutionRow> {
                Ok(StuckExecutionRow {
                    execution_id: r.try_get("id")?,
                    workflow_id: r.try_get("workflow_id")?,
                    hours_stuck: r.try_get::<Option<f64>, _>("hours_stuck")?.unwrap_or(0.0),
                })
            })
            .collect::<Result<Vec<_>>>()
    }
}

/// Pagination mode for `execute_paginated_select`. The `column` field in
/// `Cursor` MUST already be validated against the `[a-zA-Z0-9_]` allowlist
/// by the calling handler — the repo string-formats it directly into the
/// wrapper SQL.
#[derive(Debug)]
pub enum PaginationMode<'a> {
    Cursor { column: &'a str, after: &'a str },
    Offset { offset: i64 },
}

/// Optional-filter struct for `search_marketplace`.
#[derive(Debug, Default)]
pub struct MarketplaceSearchFilter<'a> {
    pub query: Option<&'a str>,
    pub world: Option<&'a str>,
    pub tag: Option<&'a str>,
}

/// Marketplace listing row.
#[derive(Debug)]
pub struct MarketplaceSearchRow {
    pub id: Uuid,
    pub module_id: Uuid,
    pub name: String,
    pub description: String,
    pub capability_world: String,
    pub version: String,
    pub downloads: i32,
    pub tags: Vec<String>,
}

/// Duplicate-group member row.
#[derive(Debug)]
pub struct WorkflowDuplicateGroupRow {
    pub id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Pinned module install status (per-user wasm_modules row presence).
#[derive(Debug)]
pub struct PinnedModuleInstallStatus {
    pub module_name: String,
    pub has_wasm: bool,
}

/// Active-actor projection with active-memory count.
#[derive(Debug)]
pub struct ActiveActorWithMemoryRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    pub max_capability_world: String,
    pub memory_count: i64,
}

/// Stuck-execution row.
#[derive(Debug)]
pub struct StuckExecutionRow {
    pub execution_id: Uuid,
    pub workflow_id: Uuid,
    pub hours_stuck: f64,
}

/// Recent-execution row for the session_start MCP-transport-drop awareness.
/// Combines running + recently-completed in one shape; the `status` field
/// distinguishes them.
#[derive(Debug)]
pub struct RecentExecutionRow {
    pub execution_id: Uuid,
    pub workflow_id: Uuid,
    pub workflow_name: String,
    pub status: String,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub duration_ms: Option<i64>,
}

#[cfg(test)]
mod audit_retention_clamp_tests {
    use super::*;

    /// A typo (`18` for `180`) must not wipe six months of an actor's action
    /// history: the floor wins. Values at or above it pass through.
    #[test]
    fn the_audit_retention_floor_wins_over_a_short_window() {
        assert_eq!(
            clamp_audit_table_retention_days(1),
            MIN_AUDIT_TABLE_RETENTION_DAYS
        );
        assert_eq!(
            clamp_audit_table_retention_days(18),
            MIN_AUDIT_TABLE_RETENTION_DAYS
        );
        assert_eq!(
            clamp_audit_table_retention_days(29),
            MIN_AUDIT_TABLE_RETENTION_DAYS
        );
        assert_eq!(clamp_audit_table_retention_days(30), 30);
        assert_eq!(clamp_audit_table_retention_days(180), 180);
        assert_eq!(clamp_audit_table_retention_days(3650), 3650);
    }

    /// The default sits above the floor, so an unset env is never clamped.
    #[test]
    fn the_default_is_above_the_floor() {
        assert!(DEFAULT_AUDIT_TABLE_RETENTION_DAYS >= MIN_AUDIT_TABLE_RETENTION_DAYS);
    }

    /// `truncated()` and `failed()` see every tier, including the two added
    /// 2026-09-10 — a new tier that only one of them knows about is a report
    /// that lies in one direction.
    #[test]
    fn outcome_verdicts_cover_the_new_tiers() {
        let mut o = RetentionPassOutcome::default();
        assert!(!o.failed() && !o.truncated());
        o.side_table_error = Some("x".into());
        assert!(o.failed());
        let mut o = RetentionPassOutcome::default();
        o.audit_table_error = Some("x".into());
        assert!(o.failed());
        let mut o = RetentionPassOutcome::default();
        o.side_tables = Some(SideTableReap {
            truncated: true,
            ..SideTableReap::default()
        });
        assert!(o.truncated() && !o.failed());
        let mut o = RetentionPassOutcome::default();
        o.audit_tables = Some(AuditTableReap {
            truncated: true,
            ..AuditTableReap::default()
        });
        assert!(o.truncated() && !o.failed());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_row() -> TemplateSourceRow {
        TemplateSourceRow {
            code_template: String::new(),
            wasm_bytes: None,
            config_schema: serde_json::json!({}),
            allowed_secrets: vec![],
            allowed_hosts: vec![],
        }
    }

    #[test]
    fn normalize_wasm_bytes_collapses_empty_to_none() {
        assert_eq!(normalize_wasm_bytes(None), None);
        assert_eq!(normalize_wasm_bytes(Some(vec![])), None);
        assert_eq!(normalize_wasm_bytes(Some(vec![0x00])), Some(vec![0x00]));
    }

    #[test]
    fn dispatch_picks_wasm_when_bytes_present() {
        let mut row = empty_row();
        // wasm magic bytes — content is irrelevant, presence is what counts
        row.wasm_bytes = Some(vec![0x00, 0x61, 0x73, 0x6d]);
        assert_eq!(InstallDispatch::from_source(&row), InstallDispatch::Wasm);
    }

    #[test]
    fn dispatch_picks_template_when_only_source_present() {
        let mut row = empty_row();
        row.code_template =
            "fn run(_: String) -> Result<String, String> { Ok(String::new()) }".into();
        assert_eq!(
            InstallDispatch::from_source(&row),
            InstallDispatch::Template
        );
    }

    #[test]
    fn dispatch_rejects_when_neither_present() {
        assert_eq!(
            InstallDispatch::from_source(&empty_row()),
            InstallDispatch::Reject
        );
    }

    #[test]
    fn dispatch_prefers_wasm_when_both_present() {
        // Realistic case: a marketplace listing has both source AND a fresh
        // compile. Pick the bytes — recompiling on install is wasteful and
        // also blocked by the cargo-audit gate on locked-down hosts.
        let mut row = empty_row();
        row.wasm_bytes = Some(vec![0x01]);
        row.code_template =
            "fn run(_: String) -> Result<String, String> { Ok(String::new()) }".into();
        assert_eq!(InstallDispatch::from_source(&row), InstallDispatch::Wasm);
    }

    #[test]
    fn dispatch_rejects_a_normalised_zero_byte_row() {
        // Defence-in-depth: even if a future caller bypasses
        // normalize_wasm_bytes and stuffs an empty vec into the struct,
        // dispatch should not pick the Wasm path. Today this would still
        // pick Wasm (Some(empty) is_some()); document the shortcoming
        // and assert the safer behaviour after a manual normalise.
        let mut row = empty_row();
        row.wasm_bytes = Some(vec![]);
        // Manual normalise — what every caller MUST do, but the test
        // documents that the dispatch enum is downstream of this step.
        row.wasm_bytes = normalize_wasm_bytes(row.wasm_bytes);
        assert_eq!(InstallDispatch::from_source(&row), InstallDispatch::Reject);
    }
}

#[cfg(test)]
mod retention_report_tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Buf {
            self.clone()
        }
    }

    fn captured(outcome: &RetentionPassOutcome) -> String {
        let sink: Arc<Mutex<Vec<u8>>> = Arc::default();
        let sub = tracing_subscriber::fmt()
            .with_writer(Buf(Arc::clone(&sink)))
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish();
        tracing::subscriber::with_default(sub, || outcome.report());
        let bytes = sink.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    fn quiet() -> RetentionPassOutcome {
        RetentionPassOutcome::default()
    }

    /// Tiers four and five (2026-09-10) report like the first three: a
    /// failure is an ERROR event with its own `event_kind`, so deleting either
    /// branch of `report()` fails here rather than going quiet in production.
    #[test]
    fn a_failed_side_table_or_audit_reap_is_reported_at_error_level() {
        let out = captured(&RetentionPassOutcome {
            side_table_error: Some("boom".into()),
            ..quiet()
        });
        assert!(
            out.contains("ERROR") && out.contains("execution_side_tables_reap_failed"),
            "{out:?}"
        );
        let out = captured(&RetentionPassOutcome {
            audit_table_error: Some("boom".into()),
            ..quiet()
        });
        assert!(
            out.contains("ERROR") && out.contains("audit_tables_reap_failed"),
            "{out:?}"
        );
    }

    /// A tier that stopped at the per-tick cap says so — `truncated = true`
    /// at INFO, naming the tier — and a drained pass emits no such event.
    #[test]
    fn a_truncated_tier_is_named_at_info_and_a_drained_pass_is_silent_about_it() {
        let out = captured(&RetentionPassOutcome {
            archive_truncated: true,
            audit_tables: Some(AuditTableReap {
                truncated: true,
                ..AuditTableReap::default()
            }),
            ..quiet()
        });
        assert!(out.contains("retention_tier_truncated"), "{out:?}");
        assert!(out.contains("truncated=true"), "{out:?}");
        assert!(
            out.contains("archive") && out.contains("audit_tables"),
            "{out:?}"
        );
        assert!(
            !out.contains("ERROR"),
            "truncation is not a failure: {out:?}"
        );

        let out = captured(&quiet());
        assert!(!out.contains("retention_tier_truncated"), "{out:?}");
    }

    /// The M6 guard. Reinstating the historical swallow — dropping the
    /// `archive_error` branch — makes this fail.
    #[test]
    fn a_failed_archive_is_reported_at_error_level() {
        let out = captured(&RetentionPassOutcome {
            archive_error: Some("boom".into()),
            ..quiet()
        });
        assert!(out.contains("ERROR"), "no ERROR-level event: {out:?}");
        assert!(
            out.contains("execution_archival_failed"),
            "archive failure not reported: {out:?}"
        );
    }

    /// RFC 0012's third tier reports like the other two. Deleting the
    /// `ledger_purge_error` branch of `report()` makes this fail — the same
    /// guard shape the two tiers above carry, added WITH the tier rather than
    /// after the first silent outage.
    #[test]
    fn a_failed_ledger_purge_is_reported_at_error_level() {
        let out = captured(&RetentionPassOutcome {
            ledger_purge_error: Some("boom".into()),
            ..quiet()
        });
        assert!(out.contains("ERROR"), "no ERROR-level event: {out:?}");
        assert!(
            out.contains("child_run_ledger_purge_failed"),
            "ledger purge failure not reported: {out:?}"
        );
    }

    /// A ledger purge that DID something says so, and a `failed()` outcome
    /// includes the third tier — otherwise the retention loop's own
    /// "did retention work" answer is silent about a tier that did not.
    #[test]
    fn a_ledger_purge_is_counted_and_a_ledger_failure_counts_as_failed() {
        let out = captured(&RetentionPassOutcome {
            ledger_purged: 7,
            windows: Some(RetentionWindows {
                archive_after_days: 30,
                purge_after_days: 60,
            }),
            ..quiet()
        });
        assert!(
            out.contains("child_run_ledger_purged"),
            "a ledger purge that deleted rows must be reported: {out:?}"
        );
        assert!(
            out.contains("90"),
            "the reported retain_days must be the TOTAL lifetime (30 + 60): {out:?}"
        );
        assert!(!RetentionPassOutcome {
            ledger_purged: 7,
            ..quiet()
        }
        .failed());
        assert!(RetentionPassOutcome {
            ledger_purge_error: Some("boom".into()),
            ..quiet()
        }
        .failed());
    }

    #[test]
    fn a_failed_purge_is_reported_at_error_level() {
        let out = captured(&RetentionPassOutcome {
            purge_error: Some("boom".into()),
            ..quiet()
        });
        assert!(
            out.contains("ERROR") && out.contains("archived_execution_purge_failed"),
            "{out:?}"
        );
    }

    #[test]
    fn a_quiet_pass_reports_no_failure() {
        let out = captured(&quiet());
        assert!(
            !out.contains("_failed"),
            "a clean pass must not report a failure: {out:?}"
        );
    }
}

#[cfg(test)]
mod child_reference_shape_tests {
    //! The sub-workflow exclusion in `get_frequently_executed_unscheduled` must
    //! recognise the shape the ENGINE writes, pinned against the engine's own
    //! parser rather than against a string.
    //!
    //! r242 and r243 each hand-wrote a JSONB predicate for this and each got a
    //! different wrong answer; r243 recorded *"verify the actual JSON shape"* as
    //! the lesson while landing on a second shape the engine does not write.
    //! Measured live 2026-09-05: r243's predicate matched **0** nodes on the
    //! fleet, the engine's shape matched **6**. So a test asserting a string is
    //! the very thing that failed twice — these drive
    //! `ChildReferenceScan::build`, which parses through
    //! `talos_workflow_engine_core::child_workflow_ids_checked`, the same
    //! function the engine's dispatcher agrees with by construction.

    use talos_child_workflow_refs::{ChildReferenceScan, ParentGraphRow};
    use uuid::Uuid;

    fn parent(graph: &str) -> ParentGraphRow {
        ParentGraphRow {
            id: Uuid::new_v4(),
            name: "parent".into(),
            graph_json: Some(graph.to_string()),
        }
    }

    /// The shape the engine ACTUALLY writes: `type` on the node, the child id
    /// under `data`. Six nodes of this shape exist on the reference fleet.
    #[test]
    fn the_engine_node_shape_is_recognised() {
        let child = Uuid::new_v4();
        let graph = format!(
            r#"{{"nodes":[{{"id":"n","type":"system:sub_workflow","data":{{"sub_workflow_id":"{child}"}}}}],"edges":[]}}"#
        );
        let scan = ChildReferenceScan::build(&[parent(&graph)], &[child]);
        assert_eq!(
            scan.parents_of(child),
            ["parent".to_string()],
            "the exclusion must see the node kind the engine dispatches on"
        );
    }

    /// The DEAD predicate's shape — `module_id` on the node, the child id under
    /// `config` — is recognised by NOTHING, because the engine never writes it.
    /// This is the positive control the assertion above cannot supply on its
    /// own: without it, a scan that matched everything would also pass.
    #[test]
    fn the_dead_predicate_shape_is_not_the_engine_shape() {
        let child = Uuid::new_v4();
        let graph = format!(
            r#"{{"nodes":[{{"id":"n","module_id":"system:sub_workflow","config":{{"sub_workflow_id":"{child}"}}}}],"edges":[]}}"#
        );
        let scan = ChildReferenceScan::build(&[parent(&graph)], &[child]);
        assert!(
            scan.parents_of(child).is_empty(),
            "r243's shape names a child through `config`, which the engine's parser \
             does not read — this is why the SQL exclusion matched 0 nodes for two years"
        );
    }

    /// `llm_dispatch`'s route targets are object VALUES under arbitrary class
    /// labels. No key-name predicate — in SQL or otherwise — can see them, which
    /// is the structural reason this exclusion cannot be hand-written.
    #[test]
    fn a_route_target_no_key_rule_could_see_is_recognised() {
        let child = Uuid::new_v4();
        let graph = format!(
            r#"{{"nodes":[{{"id":"n","type":"system:llm_dispatch","data":{{"routes":{{"billing":"{child}"}}}}}}],"edges":[]}}"#
        );
        let scan = ChildReferenceScan::build(&[parent(&graph)], &[child]);
        assert_eq!(scan.parents_of(child), ["parent".to_string()]);
    }

    /// A graph that does not parse is UNKNOWN, and this REPORT path leaves the
    /// suggestion in place rather than suppressing it — the loud direction for
    /// advice, and the opposite of what a destructive path does with the same
    /// scan (`protection_for`). Pinned so the two are not "simplified" into one.
    #[test]
    fn an_unreadable_parent_does_not_suppress_the_suggestion() {
        let child = Uuid::new_v4();
        let broken = format!(r#"{{"nodes": [ "{child}" "#);
        let scan = ChildReferenceScan::build(&[parent(&broken)], &[child]);
        assert!(
            scan.parents_of(child).is_empty(),
            "the report accessor asserts no reference from a graph it could not read"
        );
        assert!(
            scan.protection_for(child).is_some(),
            "…while the DECISION accessor still holds it back — the two must not converge"
        );
    }
}
