//! Which of these workflows is somebody's child?
//!
//! A sub-workflow runs IN-PROCESS (`execute_subworkflow_graph`) and records no
//! `workflow_executions` row — measured 2026-09-05: ZERO rows carrying
//! `parent_execution_id` across the live table and the archive, platform-wide.
//! So every predicate of the shape *"this workflow has no execution rows"* —
//! the hygiene report's `dormant_workflows` (30 days) and
//! `stale_draft_workflows` (7 days), and `session_start`'s auto-archive — sees
//! a workflow that runs daily as one that has never run, and each of those
//! predicates is attached to a destructive suggestion or a destructive action.
//!
//! This crate is the ONE answer to "who dispatches into whom", shared by every
//! surface that asks. It exists as a leaf rather than living in one repository
//! crate because its three consumers sit in three crates with no edge between
//! them — `talos-analytics-repository` (the hygiene report),
//! `talos-advanced-repository` (`session_start`'s auto-archive) and
//! `talos-workflow-repository` (the delete-time guard) — and a second copy of
//! this logic is precisely the class this repository lints for.
//!
//! # Report versus decision
//!
//! The two are NOT the same rule, and conflating them is how #758's fix stopped
//! one section short of the next:
//!
//! * A **report** row stays listed with [`ChildReferenceScan::parents_of`]
//!   rendered beside it. An operator asking *"what has no executions?"* should
//!   still see it, with the reason — hiding it would be a different misleading
//!   report.
//! * A **decision** (delete, archive, or a count under advice that names
//!   `batch_delete_workflows`) must EXCLUDE it, and must also exclude a
//!   candidate whose only evidence is a parent nobody could read — see
//!   [`ChildReferenceScan::protection_for`].
//!
//! # UNKNOWN is not EMPTY
//!
//! [`talos_workflow_engine_core::child_workflow_ids_checked`] returns `None`
//! for a graph that did not parse, distinct from `Some(vec![])` for one that
//! parsed and names nobody. This crate carries that distinction the whole way:
//! an unreadable parent contributes NOTHING to the index, is named in
//! [`ChildReferenceScan::unreadable_parents`], and — because the SQL prefilter
//! only ever returns a parent whose graph text MENTIONS one of the candidates —
//! the specific candidates it mentions are protected from a decision under
//! [`ChildProtection::MentionedByUnreadableParent`] rather than silently
//! reverting to deletable.

use std::collections::BTreeMap;
use uuid::Uuid;

/// Per-graph payload guard on the parent scan. A parent above this is never
/// transferred; it is reported as UNREADABLE (see [`ParentGraphRow::graph_json`])
/// rather than dropped, because a parent we declined to read is not a parent
/// that references nobody. Defensive: the largest graph observed is ~8 KB.
pub const MAX_PARENT_GRAPH_BYTES: i64 = 262_144;

/// One enabled workflow's graph, for the child-reference scan.
#[derive(Debug, Clone)]
pub struct ParentGraphRow {
    /// The parent's workflow id.
    pub id: Uuid,
    /// The parent's name, as rendered to an operator.
    pub name: String,
    /// The parent's `graph_json`, or `None` when the row exists but its body
    /// was over [`MAX_PARENT_GRAPH_BYTES`] and was never transferred. `None`
    /// is treated exactly like a graph that failed to parse: unknown, never
    /// empty.
    pub graph_json: Option<String>,
}

impl ParentGraphRow {
    /// The children this parent dispatches into, or `None` when its graph
    /// could not be read at all (absent body, or unparseable text).
    #[must_use]
    pub fn children(&self) -> Option<Vec<Uuid>> {
        talos_workflow_engine_core::child_workflow_ids_checked(self.graph_json.as_deref()?)
    }
}

/// Why a candidate must be kept out of a destructive decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildProtection {
    /// An enabled parent's graph NAMES this workflow through one of the eight
    /// child-dispatch `data` keys. Deleting it removes a node its parent runs.
    ReferencedBy(Vec<String>),
    /// An enabled parent's graph text MENTIONS this workflow's id, but that
    /// graph could not be read, so whether the mention is a real dispatch
    /// reference is UNKNOWN. Unknown is not "no": a decision declines, and a
    /// report says which parent it could not read.
    MentionedByUnreadableParent(Vec<String>),
}

impl ChildProtection {
    /// The parent names behind this protection, for rendering.
    #[must_use]
    pub fn parent_names(&self) -> &[String] {
        match self {
            Self::ReferencedBy(n) | Self::MentionedByUnreadableParent(n) => n,
        }
    }

    /// The same protection with `excluded` parent names removed, or `None`
    /// when nothing is left to protect it.
    ///
    /// The delete-time guard needs this: a parent that is ITSELF in the delete
    /// set is not a reason to refuse, or a retired workflow tree could never be
    /// removed in one call and the guard would be a trap rather than a
    /// safeguard.
    #[must_use]
    pub fn without_parents(self, excluded: &std::collections::HashSet<String>) -> Option<Self> {
        let (names, rebuild): (Vec<String>, fn(Vec<String>) -> Self) = match self {
            Self::ReferencedBy(n) => (n, Self::ReferencedBy),
            Self::MentionedByUnreadableParent(n) => (n, Self::MentionedByUnreadableParent),
        };
        let kept: Vec<String> = names
            .into_iter()
            .filter(|n| !excluded.contains(n))
            .collect();
        if kept.is_empty() {
            None
        } else {
            Some(rebuild(kept))
        }
    }

    /// Operator-facing reason, in the vocabulary the hygiene report already
    /// uses for the dormant list.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::ReferencedBy(names) => format!(
                "An enabled parent dispatches into this workflow as a sub-workflow ({}), \
                 which leaves no workflow_executions row — its silence in that table is the \
                 expected shape, not evidence of neglect. Removing it would remove a node \
                 its parent runs.",
                names.join(", ")
            ),
            Self::MentionedByUnreadableParent(names) => format!(
                "The graph of enabled workflow(s) {} could not be read, and this workflow's \
                 id appears in that text — so whether it is dispatched as a child is UNKNOWN. \
                 Held back from the automated action rather than treated as unreferenced.",
                names.join(", ")
            ),
        }
    }
}

/// The answer to "which of these candidates is somebody's child?", plus what
/// the scan could not read.
#[derive(Debug, Clone, Default)]
pub struct ChildReferenceScan {
    parents_by_child: BTreeMap<Uuid, Vec<String>>,
    unreadable_parents: Vec<String>,
    suspects_by_unreadable: BTreeMap<Uuid, Vec<String>>,
}

impl ChildReferenceScan {
    /// Build the scan from the parent rows a query returned, given the exact
    /// candidate set that query was scoped to.
    ///
    /// The candidate set is required, not optional: a parent whose graph could
    /// not be read is only in these rows because its TEXT mentioned one of the
    /// candidates, and matching those ids back against the raw text is what
    /// turns "some parent is unreadable" into "THESE candidates are in doubt".
    #[must_use]
    pub fn build(parents: &[ParentGraphRow], candidates: &[Uuid]) -> Self {
        let mut parents_by_child: BTreeMap<Uuid, Vec<String>> = BTreeMap::new();
        let mut unreadable_parents: Vec<String> = Vec::new();
        let mut suspects_by_unreadable: BTreeMap<Uuid, Vec<String>> = BTreeMap::new();

        for p in parents {
            let Some(children) = p.children() else {
                unreadable_parents.push(p.name.clone());
                // The body may be absent entirely (oversized). When it is
                // present-but-unparseable, say which candidates it mentions.
                if let Some(text) = p.graph_json.as_deref() {
                    for c in candidates {
                        if *c != p.id && text.contains(&c.to_string()) {
                            suspects_by_unreadable
                                .entry(*c)
                                .or_default()
                                .push(p.name.clone());
                        }
                    }
                } else {
                    // Body never transferred: we cannot narrow it to specific
                    // candidates, so EVERY candidate is in doubt. The scan is
                    // scoped by a mention prefilter, so this parent does
                    // mention at least one of them.
                    for c in candidates.iter().filter(|c| **c != p.id) {
                        suspects_by_unreadable
                            .entry(*c)
                            .or_default()
                            .push(p.name.clone());
                    }
                }
                continue;
            };
            for child in children {
                // A workflow that dispatches into ITSELF is not "somebody's
                // child" for this purpose — the protection exists for a
                // workflow whose runs are invisible because a DIFFERENT
                // workflow drives them, and a self-reference would make every
                // recursive workflow permanently undeletable.
                if child == p.id {
                    continue;
                }
                parents_by_child
                    .entry(child)
                    .or_default()
                    .push(p.name.clone());
            }
        }

        for names in parents_by_child.values_mut() {
            names.sort_unstable();
            names.dedup();
        }
        for names in suspects_by_unreadable.values_mut() {
            names.sort_unstable();
            names.dedup();
        }
        unreadable_parents.sort_unstable();
        unreadable_parents.dedup();

        Self {
            parents_by_child,
            unreadable_parents,
            suspects_by_unreadable,
        }
    }

    /// Enabled parents that dispatch into `child`, sorted and deduplicated.
    ///
    /// This is the REPORT answer: it names only parents whose graph was read.
    #[must_use]
    pub fn parents_of(&self, child: Uuid) -> &[String] {
        self.parents_by_child
            .get(&child)
            .map_or(&[][..], Vec::as_slice)
    }

    /// Names of parents whose graph could not be read, so a caller can say the
    /// scan was INCOMPLETE rather than present a partial index as a full one.
    #[must_use]
    pub fn unreadable_parents(&self) -> &[String] {
        &self.unreadable_parents
    }

    /// The DECISION answer: `Some` when `child` must be kept out of a delete
    /// or archive, whether because a parent demonstrably dispatches into it or
    /// because a parent that mentions it could not be read.
    #[must_use]
    pub fn protection_for(&self, child: Uuid) -> Option<ChildProtection> {
        if let Some(names) = self.parents_by_child.get(&child) {
            return Some(ChildProtection::ReferencedBy(names.clone()));
        }
        self.suspects_by_unreadable
            .get(&child)
            .map(|names| ChildProtection::MentionedByUnreadableParent(names.clone()))
    }
}

/// Read every ENABLED, non-archived workflow of `user_id` whose graph text
/// mentions one of `candidates`, and index who dispatches into whom.
///
/// # Why the query is scoped by the candidate list
///
/// The only graphs worth reading are the ones that mention a candidate. The
/// `LIKE` prefilter rides `idx_workflows_graph_json_trgm` and returns
/// single-digit rows in practice; an unscoped "read every enabled workflow's
/// graph" would be an unbounded payload on a large tenant, and capping THAT
/// with a `LIMIT` would silently drop parents — the failure direction that
/// puts a live child back under delete advice.
///
/// The `LIKE` is a PREFILTER ONLY. Membership is decided in Rust by parsing
/// the eight child-naming `data` keys, so a candidate's UUID appearing in an
/// unrelated field (a prompt, a config value) does not earn it a protection —
/// unless the graph could not be parsed at all, in which case the mention is
/// all we have and it counts (see [`ChildProtection`]).
///
/// # Errors
///
/// Propagates the `sqlx` error. Callers must NOT default a failure to an empty
/// scan: an empty index reads as "nobody is anybody's child", which is exactly
/// the pre-fix behaviour this exists to stop.
pub async fn scan_child_parents(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    candidates: &[Uuid],
) -> Result<ChildReferenceScan, sqlx::Error> {
    if candidates.is_empty() {
        return Ok(ChildReferenceScan::default());
    }
    // An oversized parent is RETURNED with a NULL body rather than filtered
    // out: dropping the row would hide the parent from `unreadable_parents`
    // and silently restore "this candidate is referenced by nobody".
    let rows: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT id, name, \
                CASE WHEN octet_length(graph_json) <= $3 THEN graph_json END AS graph_json \
         FROM workflows \
         WHERE user_id = $1 AND is_enabled = true AND status != 'archived' \
           AND EXISTS (SELECT 1 FROM unnest($2::uuid[]) c \
                       WHERE graph_json LIKE '%' || c::text || '%') \
         ORDER BY id",
    )
    .bind(user_id)
    .bind(candidates)
    .bind(MAX_PARENT_GRAPH_BYTES)
    .fetch_all(pool)
    .await?;

    let parents: Vec<ParentGraphRow> = rows
        .into_iter()
        .map(|(id, name, graph_json)| ParentGraphRow {
            id,
            name,
            graph_json,
        })
        .collect();
    Ok(ChildReferenceScan::build(&parents, candidates))
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "11111111-1111-4111-8111-111111111111";
    const B: &str = "22222222-2222-4222-8222-222222222222";

    fn parent(name: &str, graph: Option<&str>) -> ParentGraphRow {
        ParentGraphRow {
            id: Uuid::new_v4(),
            name: name.to_string(),
            graph_json: graph.map(ToString::to_string),
        }
    }

    fn sub_graph(child: &str) -> String {
        format!(
            r#"{{"nodes":[{{"id":"n","type":"system:sub_workflow","data":{{"sub_workflow_id":"{child}"}}}}],"edges":[]}}"#
        )
    }

    #[test]
    fn a_readable_parent_names_its_child() {
        let a: Uuid = A.parse().unwrap();
        let scan =
            ChildReferenceScan::build(&[parent("pa-chief-of-staff", Some(&sub_graph(A)))], &[a]);
        assert_eq!(scan.parents_of(a), ["pa-chief-of-staff".to_string()]);
        assert!(scan.unreadable_parents().is_empty());
        assert_eq!(
            scan.protection_for(a),
            Some(ChildProtection::ReferencedBy(vec![
                "pa-chief-of-staff".to_string()
            ]))
        );
    }

    /// The REPORT and the DECISION deliberately disagree here, and that is the
    /// whole point of the two accessors: an unreadable parent names nobody, so
    /// the report must not claim a parent relationship — but the candidate its
    /// text mentions is in doubt, so a delete must decline.
    #[test]
    fn an_unreadable_parent_protects_the_candidate_it_mentions() {
        let a: Uuid = A.parse().unwrap();
        let b: Uuid = B.parse().unwrap();
        // Mentions A only, and does not parse.
        let broken = format!(r#"{{"nodes": [ "{A}" "#);
        let scan = ChildReferenceScan::build(&[parent("half-written", Some(&broken))], &[a, b]);

        assert!(
            scan.parents_of(a).is_empty(),
            "an unreadable parent asserts no reference"
        );
        assert_eq!(scan.unreadable_parents(), ["half-written".to_string()]);
        assert_eq!(
            scan.protection_for(a),
            Some(ChildProtection::MentionedByUnreadableParent(vec![
                "half-written".to_string()
            ])),
            "UNKNOWN must protect a destructive decision, not expose it"
        );
        assert_eq!(
            scan.protection_for(b),
            None,
            "a candidate the unreadable parent does not even mention is not in doubt"
        );
    }

    /// An oversized parent's body is never transferred, so no candidate can be
    /// ruled out — every one it might mention is in doubt.
    #[test]
    fn an_oversized_parent_puts_every_candidate_in_doubt() {
        let a: Uuid = A.parse().unwrap();
        let b: Uuid = B.parse().unwrap();
        let scan = ChildReferenceScan::build(&[parent("enormous", None)], &[a, b]);
        assert_eq!(scan.unreadable_parents(), ["enormous".to_string()]);
        for id in [a, b] {
            assert!(
                matches!(
                    scan.protection_for(id),
                    Some(ChildProtection::MentionedByUnreadableParent(_))
                ),
                "a parent we declined to read is not a parent that references nobody"
            );
        }
    }

    #[test]
    fn a_self_reference_protects_nothing() {
        let id = Uuid::new_v4();
        let row = ParentGraphRow {
            id,
            name: "recursive".to_string(),
            graph_json: Some(sub_graph(&id.to_string())),
        };
        let scan = ChildReferenceScan::build(&[row], &[id]);
        assert!(scan.parents_of(id).is_empty());
        assert_eq!(scan.protection_for(id), None);
    }

    /// The eighth dispatch site, and the one no key-NAME convention can see:
    /// `llm_dispatch` route targets are the VALUES of an arbitrary label map.
    #[test]
    fn judge_and_route_targets_are_children_too() {
        let a: Uuid = A.parse().unwrap();
        let b: Uuid = B.parse().unwrap();
        let graph = format!(
            r#"{{"nodes":[
                 {{"id":"j","type":"system:judge","data":{{"judge_workflow_id":"{A}"}}}},
                 {{"id":"d","type":"system:llm_dispatch","data":{{"routes":{{"billing":"{B}"}}}}}}
               ],"edges":[]}}"#
        );
        let scan = ChildReferenceScan::build(&[parent("pa-daily-brief", Some(&graph))], &[a, b]);
        assert_eq!(scan.parents_of(a), ["pa-daily-brief".to_string()]);
        assert_eq!(scan.parents_of(b), ["pa-daily-brief".to_string()]);
    }

    #[test]
    fn duplicate_parent_names_are_collapsed_and_sorted() {
        let a: Uuid = A.parse().unwrap();
        let graph = format!(
            r#"{{"nodes":[
                 {{"id":"x","type":"system:judge","data":{{"judge_workflow_id":"{A}"}}}},
                 {{"id":"y","type":"system:sub_workflow","data":{{"sub_workflow_id":"{A}"}}}}
               ],"edges":[]}}"#
        );
        let scan = ChildReferenceScan::build(
            &[
                parent("zeta", Some(&graph)),
                parent("alpha", Some(&sub_graph(A))),
            ],
            &[a],
        );
        assert_eq!(
            scan.parents_of(a),
            ["alpha".to_string(), "zeta".to_string()],
            "one parent naming a child twice is one parent, and the order is stable"
        );
    }

    /// The live shape: one child, three parents that judge with it. The
    /// rendered list must be stable across runs and free of duplicates.
    /// (Ported from #758's `child_parent_index_tests` when that index moved
    /// here — the function moved, so its coverage moved with it.)
    #[test]
    fn parents_are_deduplicated_and_sorted_across_parents() {
        let judge = Uuid::new_v4();
        let graph = format!(
            r#"{{"nodes":[
                 {{"id":"a","type":"system:judge","data":{{"judge_workflow_id":"{judge}"}}}},
                 {{"id":"b","type":"system:judge","data":{{"judge_workflow_id":"{judge}"}}}}
               ],"edges":[]}}"#
        );
        let parents = vec![
            parent("pa-meeting-prep", Some(&graph)),
            parent("pa-chief-of-staff", Some(&graph)),
            parent("pa-daily-brief", Some(&graph)),
        ];
        let scan = ChildReferenceScan::build(&parents, &[judge]);
        assert_eq!(
            scan.parents_of(judge),
            [
                "pa-chief-of-staff".to_string(),
                "pa-daily-brief".to_string(),
                "pa-meeting-prep".to_string(),
            ],
            "one entry per parent, sorted, no duplicate from the two judge nodes"
        );
    }

    /// The control: a fleet of parseable graphs that name nobody reports NO
    /// unreadable parents — so `unreadable_parents` is not just echoing every
    /// name it was given.
    #[test]
    fn a_readable_graph_naming_nobody_is_not_reported_unreadable() {
        let child = Uuid::new_v4();
        let parents = vec![parent(
            "leaf",
            Some(r#"{"nodes":[{"id":"n","type":"module","data":{"module_id":"x"}}],"edges":[]}"#),
        )];
        let scan = ChildReferenceScan::build(&parents, &[child]);
        assert!(scan.parents_of(child).is_empty());
        assert!(scan.unreadable_parents().is_empty());
        assert_eq!(scan.protection_for(child), None);
    }

    /// `{}` parses as JSON but carries no `nodes` array, which
    /// `child_workflow_ids_checked` reports as UNKNOWN — not as a graph that
    /// names nobody.
    #[test]
    fn a_parsing_graph_with_no_nodes_array_is_unreadable() {
        let child = Uuid::new_v4();
        let scan = ChildReferenceScan::build(&[parent("also-broken", Some("{}"))], &[child]);
        assert_eq!(scan.unreadable_parents(), ["also-broken".to_string()]);
    }

    /// A parent being deleted in the same call is not a reason to refuse —
    /// otherwise a retired workflow tree is undeletable and the guard is a
    /// trap. The CONTROL is the second half: a surviving parent still refuses.
    #[test]
    fn a_parent_in_the_delete_set_stops_protecting() {
        let p = ChildProtection::ReferencedBy(vec!["doomed".into(), "alive".into()]);
        let mut both: std::collections::HashSet<String> = std::collections::HashSet::new();
        both.insert("doomed".to_string());
        assert_eq!(
            p.clone().without_parents(&both),
            Some(ChildProtection::ReferencedBy(vec!["alive".to_string()])),
            "a surviving parent still refuses"
        );
        both.insert("alive".to_string());
        assert_eq!(p.without_parents(&both), None);
        // The variant is preserved, so the reason text does not silently
        // change from "UNKNOWN" to "referenced" (or back) under filtering.
        let u = ChildProtection::MentionedByUnreadableParent(vec!["broken".into()]);
        assert!(matches!(
            u.without_parents(&std::collections::HashSet::new()),
            Some(ChildProtection::MentionedByUnreadableParent(_))
        ));
    }

    #[test]
    fn an_empty_scan_protects_nothing() {
        let scan = ChildReferenceScan::default();
        assert_eq!(scan.protection_for(A.parse().unwrap()), None);
        assert!(scan.unreadable_parents().is_empty());
    }
}
