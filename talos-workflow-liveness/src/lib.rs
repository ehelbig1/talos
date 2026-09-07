//! The one home for *"is this workflow live?"*.
//!
//! # Two columns for one fact
//!
//! `workflows` carries TWO liveness columns and they are not the same fact:
//!
//! * `is_enabled` (`boolean NOT NULL DEFAULT true`,
//!   `20260314001600_add_workflow_enabled.sql`) is the OPERATOR's toggle —
//!   `enable_workflow` / `disable_workflow`, i.e. pause and resume.
//! * `status` (`varchar(20) NOT NULL DEFAULT 'draft'`,
//!   `20260318000000_add_workflow_status.sql`) is the LIFECYCLE —
//!   `draft` → `active` → `archived`.
//!
//! Each has its own writer and neither writer touches the other column: the six
//! `UPDATE workflows SET status = 'archived'` sites never clear `is_enabled`, and
//! `set_workflow_enabled` never moves `status`. Measured on the reference fleet
//! 2026-09-07: **every one of the 8 archived rows still carries
//! `is_enabled = true`** (`active/t 17, archived/t 8, draft/t 11`). A reader that
//! picks ONE column therefore answers a question it was not asked — which is how
//! `get_platform_hygiene_report` came to recommend deleting eight workflows an
//! operator had already retired.
//!
//! The columns are deliberately NOT collapsed and there is no migration that
//! flips `is_enabled` on archived rows: the two writers record two different
//! operator acts, one timestamped column cannot say which happened, and a
//! backfill would relabel history as a pause that never occurred. The READER is
//! what changes. (Same argument as the readiness-timestamp pair in CLAUDE.md
//! §"Two columns for one fact".)
//!
//! # Two predicates, and the second one is not a weaker version of the first
//!
//! [`is_live`] — `status = 'active' AND is_enabled` — is what an operator means
//! by "live": published, and not paused.
//!
//! [`is_dispatchable`] — `status <> 'archived' AND is_enabled` — is what the
//! PLATFORM can still run. A DRAFT workflow really does execute: a parent
//! dispatches a child's `graph_json` column with no version join and no status
//! predicate, so `publish_version` changes nothing about how the parent runs it
//! (CLAUDE.md, "Does a child's `draft` status mean anything at runtime? No").
//! Measured on the reference fleet 2026-09-07: **4 draft workflows carry enabled
//! schedules and fire today**, so folding draft into "not live" for an
//! operational population would be wrong in the loud direction.
//!
//! Two existing sites already implemented `is_dispatchable` correctly and
//! independently — `talos_child_workflow_refs::scan_child_parents` (which decides
//! whether a delete is refused) and `list_enabled_graph_json_for_boot_warmup` —
//! and both now read it from here, so they cannot drift apart.
//!
//! # The Rust predicates are EXACT twins of the SQL
//!
//! [`live_sql`] / [`dispatchable_sql`] render the same comparisons the Rust
//! functions evaluate, including on an unrecognised `status` (there is no CHECK
//! constraint on that column, so `WorkflowLifecycle::Unknown` is a real state,
//! not a hypothetical one — one live query in this workspace still filters
//! `status = 'published'`, a value nothing has ever written). An unknown status
//! is therefore NOT live (`= 'active'` is false) and IS dispatchable
//! (`<> 'archived'` is true) on BOTH sides. That asymmetry is the SQL's, faithfully
//! mirrored rather than quietly "fixed" on one side; `rust_and_sql_agree_on_every_status`
//! pins it.
//!
//! # What this crate deliberately does NOT do
//!
//! It does not gate execution. Measured 2026-09-07 with a scratch row (an archived
//! workflow with an enabled schedule and an enabled webhook): the scheduler due
//! query, the post-due workflow load, the webhook dispatch read,
//! `resolve_by_capabilities` and `WorkflowGraphStore::get_graph` ALL return it —
//! no execution path in this workspace filters on `workflows.status` at all.
//! Closing that is a fleet-wide behaviour change with its own blast radius (those
//! 4 draft schedules among them), not a report fix, and it is recorded rather
//! than attempted.

/// `workflows.status` for a published workflow.
pub const STATUS_ACTIVE: &str = "active";
/// `workflows.status` for a workflow that has never been published.
pub const STATUS_DRAFT: &str = "draft";
/// `workflows.status` for a workflow an operator has retired.
pub const STATUS_ARCHIVED: &str = "archived";

/// The lifecycle half of the pair, four-valued because the column carries no
/// CHECK constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowLifecycle {
    Draft,
    Active,
    Archived,
    /// A value none of the three writers produces. Kept distinct rather than
    /// folded into `Draft`: "I do not recognise this" is not "it was never
    /// published", and a report that says the second about the first is the
    /// class this crate exists for.
    Unknown,
}

impl WorkflowLifecycle {
    /// Classify a raw `workflows.status`. Unrecognised values are
    /// [`WorkflowLifecycle::Unknown`], never silently one of the three.
    #[must_use]
    pub fn from_db_str(status: &str) -> Self {
        match status {
            STATUS_ACTIVE => Self::Active,
            STATUS_DRAFT => Self::Draft,
            STATUS_ARCHIVED => Self::Archived,
            _ => Self::Unknown,
        }
    }

    /// The token as it appears in the column, for a report that must echo it.
    /// [`WorkflowLifecycle::Unknown`] renders as `"unknown"`, which is a
    /// statement about the READER and is never written back to the column.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => STATUS_ACTIVE,
            Self::Draft => STATUS_DRAFT,
            Self::Archived => STATUS_ARCHIVED,
            Self::Unknown => "unknown",
        }
    }
}

/// Is this workflow LIVE — published and not paused?
///
/// The exact twin of [`live_sql`].
#[must_use]
pub fn is_live(status: &str, is_enabled: bool) -> bool {
    status == STATUS_ACTIVE && is_enabled
}

/// Can the PLATFORM still run this workflow — not retired, and not paused?
///
/// A draft counts: a draft child is dispatched from its `graph_json` column with
/// no status predicate, and 4 drafts on the reference fleet carry enabled
/// schedules. The exact twin of [`dispatchable_sql`].
#[must_use]
pub fn is_dispatchable(status: &str, is_enabled: bool) -> bool {
    status != STATUS_ARCHIVED && is_enabled
}

/// Has an operator retired this workflow?
#[must_use]
pub fn is_retired(status: &str) -> bool {
    status == STATUS_ARCHIVED
}

/// Why a workflow is not [`is_live`], as a phrase a report can print, or `None`
/// when it IS live.
///
/// Both axes are named, because "archived" and "paused" are different operator
/// acts and a row can be both.
#[must_use]
pub fn not_live_reason(status: &str, is_enabled: bool) -> Option<&'static str> {
    match (WorkflowLifecycle::from_db_str(status), is_enabled) {
        (WorkflowLifecycle::Active, true) => None,
        (WorkflowLifecycle::Active, false) => Some("paused (is_enabled = false)"),
        (WorkflowLifecycle::Archived, true) => Some("archived by an operator"),
        (WorkflowLifecycle::Archived, false) => Some("archived by an operator, and paused"),
        (WorkflowLifecycle::Draft, true) => Some("never published (status = 'draft')"),
        (WorkflowLifecycle::Draft, false) => Some("never published (status = 'draft'), and paused"),
        (WorkflowLifecycle::Unknown, true) => Some("unrecognised status value"),
        (WorkflowLifecycle::Unknown, false) => Some("unrecognised status value, and paused"),
    }
}

/// Render the SQL twin of [`is_live`], optionally table-qualified.
///
/// `alias` is a caller-authored table alias (`Some("w")` → `w.status = 'active'
/// AND w.is_enabled = true`). It never carries user input — every call site in
/// this workspace passes a literal — and the rest of the fragment is fixed text,
/// so nothing here is string-concatenated user data.
#[must_use]
pub fn live_sql(alias: Option<&str>) -> String {
    let q = qualifier(alias);
    format!("{q}status = '{STATUS_ACTIVE}' AND {q}is_enabled = true")
}

/// Render the SQL twin of [`is_dispatchable`], optionally table-qualified.
#[must_use]
pub fn dispatchable_sql(alias: Option<&str>) -> String {
    let q = qualifier(alias);
    format!("{q}status <> '{STATUS_ARCHIVED}' AND {q}is_enabled = true")
}

/// Render the SQL twin of [`is_retired`], optionally table-qualified.
#[must_use]
pub fn retired_sql(alias: Option<&str>) -> String {
    let q = qualifier(alias);
    format!("{q}status = '{STATUS_ARCHIVED}'")
}

fn qualifier(alias: Option<&str>) -> String {
    match alias {
        Some(a) => format!("{a}."),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The live fleet's shape: EVERY archived row carries `is_enabled = true`,
    /// so a reader that consults only `is_enabled` calls all 8 of them live.
    #[test]
    fn an_archived_row_that_is_still_enabled_is_not_live() {
        assert!(!is_live(STATUS_ARCHIVED, true));
        assert_eq!(
            not_live_reason(STATUS_ARCHIVED, true),
            Some("archived by an operator")
        );
        // …and it is not dispatchable either, which is what makes excluding it
        // from an operational population correct rather than merely tidier.
        assert!(!is_dispatchable(STATUS_ARCHIVED, true));
    }

    /// A DRAFT is not live and IS dispatchable, and the split is load-bearing:
    /// 4 drafts on the reference fleet carry enabled schedules, and a draft child
    /// is dispatched from its `graph_json` column with no status predicate.
    #[test]
    fn a_draft_is_not_live_but_is_dispatchable() {
        assert!(!is_live(STATUS_DRAFT, true));
        assert!(is_dispatchable(STATUS_DRAFT, true));
        assert_eq!(
            not_live_reason(STATUS_DRAFT, true),
            Some("never published (status = 'draft')")
        );
    }

    /// The operator's toggle is the OTHER axis, and it is reported as itself.
    #[test]
    fn a_paused_active_workflow_names_the_pause_not_the_lifecycle() {
        assert!(!is_live(STATUS_ACTIVE, false));
        assert!(!is_dispatchable(STATUS_ACTIVE, false));
        assert_eq!(
            not_live_reason(STATUS_ACTIVE, false),
            Some("paused (is_enabled = false)")
        );
        assert_eq!(not_live_reason(STATUS_ACTIVE, true), None);
    }

    /// There is no CHECK constraint on `workflows.status`, so an unrecognised
    /// value is a real state. It must not be folded into `draft`.
    #[test]
    fn an_unrecognised_status_is_its_own_answer() {
        assert_eq!(
            WorkflowLifecycle::from_db_str("published"),
            WorkflowLifecycle::Unknown
        );
        assert!(!is_live("published", true));
        assert_eq!(
            not_live_reason("published", true),
            Some("unrecognised status value")
        );
    }

    /// The Rust predicate and the SQL fragment must answer identically for every
    /// status a row can hold, including the unrecognised one — otherwise a report
    /// and the query behind it disagree, which is the defect one level up.
    ///
    /// The SQL side is EVALUATED here, not compared as a string: a tiny
    /// interpreter for the two shapes this crate emits.
    #[test]
    fn rust_and_sql_agree_on_every_status() {
        fn eval(fragment: &str, status: &str, is_enabled: bool) -> bool {
            // `<qual>status <op> '<lit>' AND <qual>is_enabled = true`
            let (lhs, rhs) = fragment.split_once(" AND ").expect("two conjuncts");
            let enabled_ok = rhs.ends_with("is_enabled = true") && is_enabled;
            let lit = lhs
                .split('\'')
                .nth(1)
                .expect("a quoted status literal in the fragment");
            let status_ok = if lhs.contains("<>") {
                status != lit
            } else {
                status == lit
            };
            status_ok && enabled_ok
        }

        for alias in [None, Some("w")] {
            let live = live_sql(alias);
            let disp = dispatchable_sql(alias);
            for status in [
                STATUS_ACTIVE,
                STATUS_DRAFT,
                STATUS_ARCHIVED,
                "published",
                "",
            ] {
                for enabled in [true, false] {
                    assert_eq!(
                        eval(&live, status, enabled),
                        is_live(status, enabled),
                        "live_sql disagrees with is_live at ({status:?}, {enabled})"
                    );
                    assert_eq!(
                        eval(&disp, status, enabled),
                        is_dispatchable(status, enabled),
                        "dispatchable_sql disagrees with is_dispatchable at ({status:?}, {enabled})"
                    );
                }
            }
        }
    }

    #[test]
    fn the_rendered_sql_is_table_qualified_on_request() {
        assert_eq!(
            live_sql(Some("w")),
            "w.status = 'active' AND w.is_enabled = true"
        );
        assert_eq!(
            dispatchable_sql(Some("w")),
            "w.status <> 'archived' AND w.is_enabled = true"
        );
        assert_eq!(retired_sql(None), "status = 'archived'");
    }
}
