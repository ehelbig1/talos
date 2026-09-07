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
//! # It now gates execution too — the NARROW gate (2026-09-07)
//!
//! The paragraph that used to sit here recorded that NO execution path in this
//! workspace filtered on `workflows.status`, and left it. Package 24 closed
//! that, and only that: every dispatch read refuses a workflow whose
//! `status = 'archived'`, through [`not_retired_sql`] / [`is_not_retired`], and
//! changes nothing else. A DRAFT still dispatches (4 drafts on the reference
//! fleet carry enabled schedules), and `is_enabled` keeps whatever meaning each
//! path already gave it — [`dispatchable_sql`] is deliberately NOT the predicate
//! used there, because it also requires `is_enabled` and the decision was
//! archived-only.
//!
//! [`not_retired_sql`] and [`dispatchable_sql`] are therefore NOT
//! interchangeable and the difference is a behaviour change, not a style
//! choice, and NOTHING greps for a confusion between them: check 87's window
//! looks for a LIVENESS predicate over BOTH columns, and this gate is one
//! column, so it does not see these sites at all. What pins the difference is
//! `not_retired_is_weaker_than_dispatchable` here, plus the DRAFT and PAUSED
//! controls in `controller/tests/archived_dispatch_gate_tests`.
//!
//! # A correction to what this file used to claim
//!
//! The paragraph replaced here said, flatly, that *"no execution path in this
//! workspace filters on `workflows.status` at all"*. That was wrong by one
//! site on the day it was written:
//! `talos_actor_repository::ActorRepository::get_workflow_graph_for_user` — the
//! handoff dispatch read — carried `AND (status IS NULL OR status != 'archived')`
//! in SQL. `handoff_to_actor` was therefore the ONE dispatch surface that
//! refused an archived workflow, while REPORTING the refusal as *"Workflow not
//! found or access denied"*, false on both clauses. An ALL-sites claim is worth
//! only as much as the enumeration behind it, and this crate is the file a
//! reader would trust for that claim.

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

/// May the PLATFORM still dispatch this workflow — i.e. has an operator NOT
/// retired it?
///
/// This is the NARROW gate (package 24, 2026-09-07) and the exact twin of
/// [`not_retired_sql`]. It is deliberately weaker than [`is_dispatchable`]:
/// it says nothing about `is_enabled`, because each dispatch path enforces
/// that flag (or does not) in its own way and the archived decision was taken
/// alone. A gate that quietly upgraded to [`is_dispatchable`] would stop four
/// live draft schedules and every path that has never consulted `is_enabled`
/// at all — a fleet-wide behaviour change wearing a one-word diff.
///
/// A DRAFT is not retired, and an UNRECOGNISED status is not retired either:
/// the column has no CHECK constraint, and refusing to dispatch a value the
/// reader merely does not recognise would be a determinate negative over a
/// state it cannot represent.
#[must_use]
pub fn is_not_retired(status: &str) -> bool {
    !is_retired(status)
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

/// Render the SQL twin of [`is_not_retired`], optionally table-qualified —
/// the NARROW dispatch gate.
///
/// Spelled `<>` rather than `NOT (status = '…')` because the negated form
/// reads as though it were NULL-safe and is not: `workflows.status` is
/// `NOT NULL` today, so the two are equivalent, and a fragment whose
/// correctness depends on a schema fact it does not state is one migration
/// away from being wrong quietly.
#[must_use]
pub fn not_retired_sql(alias: Option<&str>) -> String {
    let q = qualifier(alias);
    format!("{q}status <> '{STATUS_ARCHIVED}'")
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

    /// The NARROW gate and the DISPATCHABLE predicate are not interchangeable,
    /// and the gap is exactly the population package 24 was told not to touch:
    /// a paused (`is_enabled = false`) workflow is NOT dispatchable and IS
    /// not-retired. Swapping one for the other at a gate site is a behaviour
    /// change wearing a one-word diff, which is why they are pinned apart here
    /// rather than left to a reviewer's eye.
    #[test]
    fn not_retired_is_weaker_than_dispatchable() {
        // The whole difference: the pause axis.
        assert!(is_not_retired(STATUS_ACTIVE));
        assert!(!is_dispatchable(STATUS_ACTIVE, false));

        // A draft dispatches under the narrow gate — 4 drafts on the reference
        // fleet carry enabled schedules and fire today.
        assert!(is_not_retired(STATUS_DRAFT));
        // An unrecognised status is not retired: no CHECK constraint on the
        // column, and refusing a value the reader merely does not recognise is
        // a determinate negative over a state it cannot represent.
        assert!(is_not_retired("published"));
        // The one thing it does refuse.
        assert!(!is_not_retired(STATUS_ARCHIVED));
    }

    /// The Rust twin and the SQL twin of the NARROW gate must agree on every
    /// status, evaluated rather than string-compared — same standard
    /// `rust_and_sql_agree_on_every_status` holds the other two fragments to.
    #[test]
    fn rust_and_sql_agree_on_the_narrow_gate() {
        fn eval_not_retired(fragment: &str, status: &str) -> bool {
            let lit = fragment
                .split('\'')
                .nth(1)
                .expect("a quoted status literal in the fragment");
            assert!(fragment.contains("<>"), "the narrow gate is an inequality");
            status != lit
        }
        for alias in [None, Some("w")] {
            let frag = not_retired_sql(alias);
            for status in [
                STATUS_ACTIVE,
                STATUS_DRAFT,
                STATUS_ARCHIVED,
                "published",
                "",
            ] {
                assert_eq!(
                    eval_not_retired(&frag, status),
                    is_not_retired(status),
                    "not_retired_sql disagrees with is_not_retired at {status:?}"
                );
            }
        }
        assert_eq!(not_retired_sql(Some("w")), "w.status <> 'archived'");
        assert_eq!(not_retired_sql(None), "status <> 'archived'");
    }

    /// Every seeded `path` label must be distinct and non-empty — the list is
    /// what `talos-metrics` iterates, and a duplicate would silently collapse
    /// two paths into one series.
    #[test]
    fn every_dispatch_path_label_is_distinct() {
        use dispatch::DispatchPath;
        let mut seen = std::collections::BTreeSet::new();
        for p in DispatchPath::ALL {
            assert!(!p.as_str().is_empty());
            assert!(
                seen.insert(p.as_str()),
                "duplicate path label {}",
                p.as_str()
            );
        }
        assert_eq!(seen.len(), DispatchPath::ALL.len());
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

/// The NARROW dispatch gate's shared vocabulary: which paths enforce it, what a
/// refusal is called in the log, and what an operator-facing refusal says.
///
/// One home for all four, because the gate is applied in six crates that have
/// no edge between them. #760's `RefusalReason` split (a log spelling and a
/// metric spelling, paired by an exhaustive match) is the precedent; the
/// difference here is that this crate has no dependencies, so `talos-metrics`
/// imports [`DispatchPath::ALL`] to pre-seed the counter rather than keeping a
/// second copy of the list. `talos_rpc_write_ceiling_refusals_total`'s own
/// `RPC_WRITE_CEILING_SUBJECTS` doc records that it wanted exactly this and
/// could not have it (that crate depends on `talos-metrics`, so importing
/// would be a cycle). Here there is no cycle.
pub mod dispatch {
    /// `tracing` target every archived-dispatch refusal carries, so one grep
    /// finds all six paths.
    pub const REFUSAL_TARGET: &str = "talos_dispatch";

    /// `event_kind` field on every archived-dispatch refusal line.
    pub const REFUSAL_EVENT_KIND: &str = "dispatch_refused_archived";

    /// The `reason` label on `talos_dispatch_refused_total`.
    ///
    /// A single-valued label would be decoration; this one is not, because the
    /// label exists so a SECOND refusal reason (a future lifecycle value, or
    /// the `is_enabled` axis if a later decision folds it in here) cannot be
    /// added without deciding whether it is the same series. Only this value
    /// has an emitter today and only this value is seeded.
    pub const REFUSAL_REASON_ARCHIVED: &str = "archived";

    /// Which dispatch path refused. The `path` label on
    /// `talos_dispatch_refused_total`, and the closed set `talos-metrics`
    /// pre-seeds.
    ///
    /// **Every variant has a LIVE increment site.** Sites that enforce the
    /// gate in SQL instead — the chain fan-out, `resolve_by_capabilities`,
    /// `resolve_by_name` and the sub-workflow cache prefetch — deliberately
    /// have NO variant here: they choose among candidates rather than refusing
    /// a named workflow, so there is no per-request refusal to count, and a
    /// seeded label nothing increments is the defect check 58 exists for.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum DispatchPath {
        /// `talos-scheduler`, a due schedule's fire.
        Scheduler,
        /// `talos-webhooks`, an inbound webhook.
        Webhook,
        /// `ExecutionOrchestrationService::trigger` — MCP `trigger_workflow`
        /// and the GraphQL `triggerWorkflow` mutation.
        Trigger,
        /// MCP `call_workflow` (the synchronous inline-result path).
        CallWorkflow,
        /// MCP `bulk_trigger_workflow`.
        BulkTrigger,
        /// MCP `trigger_workflow_as_actors`.
        TriggerAsActors,
        /// MCP `enqueue_workflow` (the batch admission gate).
        Enqueue,
        /// `talos-continuation-trigger`, an approval/suspension resume and the
        /// Gmail push-notification workflow branch.
        Continuation,
        /// `WorkflowGraphStore::get_graph` — a parent node's child graph.
        SubWorkflow,
        /// `talos-execution-orchestration::retry`.
        Retry,
        /// `talos-execution-orchestration::replay`.
        Replay,
        /// `talos-actor-lifecycle-service::handoff`.
        Handoff,
    }

    impl DispatchPath {
        /// The complete, closed set — what `talos-metrics` seeds.
        pub const ALL: [DispatchPath; 12] = [
            DispatchPath::Scheduler,
            DispatchPath::Webhook,
            DispatchPath::Trigger,
            DispatchPath::CallWorkflow,
            DispatchPath::BulkTrigger,
            DispatchPath::TriggerAsActors,
            DispatchPath::Enqueue,
            DispatchPath::Continuation,
            DispatchPath::SubWorkflow,
            DispatchPath::Retry,
            DispatchPath::Replay,
            DispatchPath::Handoff,
        ];

        /// The `path` label value.
        #[must_use]
        pub fn as_str(self) -> &'static str {
            match self {
                Self::Scheduler => "scheduler",
                Self::Webhook => "webhook",
                Self::Trigger => "trigger",
                Self::CallWorkflow => "call_workflow",
                Self::BulkTrigger => "bulk_trigger",
                Self::TriggerAsActors => "trigger_as_actors",
                Self::Enqueue => "enqueue",
                Self::Continuation => "continuation",
                Self::SubWorkflow => "sub_workflow",
                Self::Retry => "retry",
                Self::Replay => "replay",
                Self::Handoff => "handoff",
            }
        }
    }

    /// What an AUTHENTICATED, operator-facing surface says when the gate
    /// refuses. One wording, so six crates cannot describe one policy six ways.
    ///
    /// Deliberately NOT used on the inbound-webhook path: that caller is not
    /// the operator, and telling it "this workflow is archived" hands an
    /// existence oracle to anyone who can guess a trigger id. The webhook
    /// answers exactly what it answers for a workflow that is not there, and
    /// the distinction is kept for the operator in the log and the counter —
    /// the same split `caller_facing_unauthorized` makes.
    #[must_use]
    pub fn archived_refusal_message(workflow_id: &str) -> String {
        format!(
            "Workflow {workflow_id} is archived and will not be dispatched. \
             Un-archive it (set status back to 'active') to run it again."
        )
    }
}
