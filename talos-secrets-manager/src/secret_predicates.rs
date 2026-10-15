//! Who may act on a `secrets` row — ONE rule for managing a secret and ONE
//! for reading it into a dispatch (security review 2026-10-14, C-2).
//!
//! Until this date each statement carried its own ownership clause, and they
//! disagreed: rotate / expiry / namespace / delete-by-id matched
//! `created_by` only, `update_secret` matched `owner_user_id` or the org, the
//! delete matched all three, and every dispatch read matched `owner_user_id`
//! OR `created_by`. A member who LEFT an org kept rotating, expiring and
//! deleting the org secrets they had created, and their dispatches kept
//! reading them, because `created_by` never changes.
//!
//! The rules, as SQL fragments built by macros so each statement stays one
//! `&'static str` literal (no `AssertSqlSafe`), each taking the bind that
//! carries the acting user:
//!
//! * **Manage** ([`may_manage_secret!`]) — see, change, rotate, expire,
//!   rename, delete, read the audit of. A personal row (`org_id IS NULL`) is
//!   its owner's; a legacy row with no owner is its creator's; an org row is
//!   any CURRENT member's (membership read from `organization_members` by the
//!   statement itself, so it is never older than the call).
//! * **Dispatch read** ([`may_dispatch_read_secret!`]) — global rows
//!   (`owner_user_id IS NULL`), and the user's OWN rows, an org row only while
//!   the user is still a member of its org. Other members' org secrets are
//!   NOT read into a dispatch: whether they should be is operator decision
//!   D-4 of the review, and this is the narrow option.
//!
//! The row-security policy on `secrets` (migration `20261014190000`) states
//! the same manage rule.

/// The "may manage" fragment. `$t` is the table qualifier (`""` or `"s."`),
/// `$u` the placeholder carrying the acting user (e.g. `"$2"`). With a third
/// argument `$orgs` — the placeholder of a `uuid[]` of the user's CURRENT
/// memberships, which every caller passing one resolves from
/// `organization_members` at call time — that array is the membership set;
/// without it the statement reads `organization_members` itself.
#[macro_export]
macro_rules! may_manage_secret {
    ($t:literal, $u:literal) => {
        $crate::may_manage_secret!(@rule $t, $u,
            concat!("IN (SELECT om.org_id FROM organization_members om WHERE om.user_id = ", $u, ")"))
    };
    ($t:literal, $u:literal, $orgs:literal) => {
        $crate::may_manage_secret!(@rule $t, $u, concat!("= ANY(", $orgs, ")"))
    };
    (@rule $t:literal, $u:literal, $member:expr) => {
        concat!(
            "(CASE WHEN ", $t, "org_id IS NULL THEN (", $t, "owner_user_id = ", $u,
            " OR (", $t, "owner_user_id IS NULL AND ", $t, "created_by = ", $u, ")) ",
            "ELSE ", $t, "org_id ", $member, " END)"
        )
    };
}

/// The "may read into a dispatch" fragment. `$u` is the placeholder carrying
/// the user the dispatch runs for.
#[macro_export]
macro_rules! may_dispatch_read_secret {
    ($u:literal) => {
        concat!(
            "(owner_user_id IS NULL OR (owner_user_id = ", $u,
            " AND (org_id IS NULL OR org_id IN (SELECT om.org_id FROM organization_members om WHERE om.user_id = ",
            $u, "))))"
        )
    };
}
