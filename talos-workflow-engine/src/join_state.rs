//! Per-node join bookkeeping for the reactor.
//!
//! Every node waits on its incoming EDGES. Each edge resolves exactly once,
//! when its source node's fate is known, and resolves one of three ways (see
//! [`EdgeResolution`]). A node's fate is DECIDED exactly once:
//!
//! * **run** — every incoming edge has resolved and at least one resolved
//!   active, or the node is a `FanIn` whose early-ready join mode is
//!   satisfied by the edges resolved active so far;
//! * **skip** — every incoming edge has resolved and none resolved active.
//!
//! A decided node leaves the table, so a resolution that arrives later (a
//! slow parent of an early-ready fan-in) is a no-op rather than a second
//! enqueue.
//!
//! # Why this replaced a bare counter
//!
//! The reactor used to keep one `pending` counter per node and decide at the
//! moment the counter reached zero, using only the edge from the parent whose
//! completion happened to reach zero. So the decision depended on completion
//! ORDER: a merge node behind one live branch and one condition-false branch
//! ran when the false branch resolved first and silently never ran when it
//! resolved last (the skip decremented the merge's counter without enqueuing
//! it). A skip also cascaded exactly one level — grandchildren were
//! decremented, great-grandchildren were never touched and never appeared in
//! the results at all. Counting ACTIVE resolutions separately makes the
//! decision a function of the resolved set, not of the order it arrived in.
//!
//! Pure: no engine, no graph. The engine maps graph edges to resolutions
//! (`ParallelWorkflowEngine::release_successors`) and acts on the verdicts.

use std::collections::HashMap;

use petgraph::graph::NodeIndex;
use talos_workflow_engine_core::JoinMode;

/// How one incoming edge resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EdgeResolution {
    /// The edge carries the parent's committed output: a success whose edge
    /// condition held (or that had none), or a failure routed along an error
    /// edge.
    Active,
    /// A failure the parent's `continue_on_error` carries along the edge. It
    /// counts toward "at least one input arrived" once every edge has
    /// resolved, but never satisfies an early-ready join by itself — a
    /// failure must not win an `Any` race against a sibling still running.
    ActiveAfterFailure,
    /// The edge will never carry anything: a false condition, an error edge
    /// off a success, a success edge off a failure routed to error edges, or
    /// any edge out of a node that was itself skipped.
    Inactive,
}

/// What resolving one edge decided about its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a Run or Skip verdict must be acted on, or the node never resolves"]
pub(crate) enum JoinVerdict {
    /// Some incoming edge is still unresolved and no early-ready rule fired.
    Waiting,
    /// Decided now: enqueue the node.
    Run,
    /// Decided now: every incoming edge resolved inactive.
    Skip,
    /// The node was decided earlier (or never tracked); nothing to do.
    AlreadyDecided,
}

#[derive(Debug, Clone, Copy)]
struct Join {
    total: usize,
    unresolved: usize,
    active: usize,
    /// Active resolutions that may satisfy an early-ready join
    /// ([`EdgeResolution::Active`] only).
    early: usize,
}

/// The undecided nodes of one run and the state of their incoming edges.
#[derive(Debug, Default)]
pub(crate) struct Joins {
    undecided: HashMap<NodeIndex, Join>,
}

impl Joins {
    /// Track every node with its incoming edge count.
    pub(crate) fn new(incoming: impl IntoIterator<Item = (NodeIndex, usize)>) -> Self {
        Self {
            undecided: incoming
                .into_iter()
                .map(|(idx, total)| {
                    (
                        idx,
                        Join {
                            total,
                            unresolved: total,
                            active: 0,
                            early: 0,
                        },
                    )
                })
                .collect(),
        }
    }

    /// Mark `node` decided without an edge resolution — a seeded node on
    /// resume, or an interior pipeline-chain node that ran inside its chain.
    /// Returns whether it was still undecided.
    pub(crate) fn decide(&mut self, node: NodeIndex) -> bool {
        self.undecided.remove(&node).is_some()
    }

    /// Whether `node` is still waiting for its fate.
    #[cfg(test)]
    pub(crate) fn is_undecided(&self, node: NodeIndex) -> bool {
        self.undecided.contains_key(&node)
    }

    /// Resolve one incoming edge of a SEEDED parent without deciding the
    /// target. Seeding happens before the initial ready queue is built, and
    /// that queue is assembled in graph order by [`Self::take_initially_ready`]
    /// so the dispatch order of a resumed run does not depend on the
    /// iteration order of the seed map.
    ///
    /// A seeded parent's edges resolve ACTIVE: the resume path has only the
    /// parent's stored output, and — as before this table existed — it does
    /// not re-evaluate edge conditions against it (a seeded synthetic trigger
    /// carries none of the fields a condition names).
    pub(crate) fn resolve_seeded(&mut self, target: NodeIndex) {
        if let Some(join) = self.undecided.get_mut(&target) {
            join.unresolved = join.unresolved.saturating_sub(1);
            join.active += 1;
            join.early += 1;
        }
    }

    /// Decide and return, in `order`, every undecided node whose incoming
    /// edges have all resolved. Used once, to build the initial ready queue:
    /// roots (no incoming edges) and nodes whose every parent was seeded.
    pub(crate) fn take_initially_ready(
        &mut self,
        order: impl IntoIterator<Item = NodeIndex>,
    ) -> Vec<NodeIndex> {
        let mut ready = Vec::new();
        for idx in order {
            if self.undecided.get(&idx).is_some_and(|j| j.unresolved == 0) {
                self.undecided.remove(&idx);
                ready.push(idx);
            }
        }
        ready
    }

    /// Resolve one incoming edge of `target`.
    ///
    /// `early_join` is the target's `FanIn` join mode, or `None` for every
    /// other node kind (which always waits for all of its edges).
    pub(crate) fn resolve(
        &mut self,
        target: NodeIndex,
        resolution: EdgeResolution,
        early_join: Option<&JoinMode>,
    ) -> JoinVerdict {
        let Some(join) = self.undecided.get_mut(&target) else {
            return JoinVerdict::AlreadyDecided;
        };
        join.unresolved = join.unresolved.saturating_sub(1);
        match resolution {
            EdgeResolution::Active => {
                join.active += 1;
                join.early += 1;
            }
            EdgeResolution::ActiveAfterFailure => join.active += 1,
            EdgeResolution::Inactive => {}
        }
        let early_ready = join.unresolved > 0
            && early_join.is_some_and(|mode| early_join_satisfied(mode, join.early, join.total));
        let verdict = if early_ready || (join.unresolved == 0 && join.active > 0) {
            JoinVerdict::Run
        } else if join.unresolved == 0 {
            JoinVerdict::Skip
        } else {
            JoinVerdict::Waiting
        };
        if verdict != JoinVerdict::Waiting {
            self.undecided.remove(&target);
        }
        verdict
    }
}

/// Whether a `FanIn` join mode is satisfied by `early` active parents out of
/// `total` before every parent has resolved.
///
/// Counts ACTIVE parents, not merely resolved ones: a parent whose edge
/// resolved inactive (a false condition, a skipped branch) produced nothing
/// to join, so it cannot help satisfy "the first N results".
fn early_join_satisfied(mode: &JoinMode, early: usize, total: usize) -> bool {
    match mode {
        JoinMode::Any => early >= 1,
        JoinMode::Majority => early > total / 2,
        JoinMode::N(n) => early >= *n as usize,
        // `All`, and any variant added later (`JoinMode` is
        // `#[non_exhaustive]`): wait for every parent.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(i: u32) -> NodeIndex {
        NodeIndex::new(i as usize)
    }

    #[test]
    fn the_verdict_does_not_depend_on_resolution_order() {
        // A merge behind one live branch and one dead branch runs whichever
        // branch resolves first — the defect the counter had.
        for order in [
            [EdgeResolution::Active, EdgeResolution::Inactive],
            [EdgeResolution::Inactive, EdgeResolution::Active],
        ] {
            let mut joins = Joins::new([(n(0), 2)]);
            assert_eq!(joins.resolve(n(0), order[0], None), JoinVerdict::Waiting);
            assert_eq!(joins.resolve(n(0), order[1], None), JoinVerdict::Run);
        }
    }

    #[test]
    fn a_node_whose_every_edge_is_inactive_is_skipped() {
        let mut joins = Joins::new([(n(0), 2)]);
        assert_eq!(
            joins.resolve(n(0), EdgeResolution::Inactive, None),
            JoinVerdict::Waiting
        );
        assert_eq!(
            joins.resolve(n(0), EdgeResolution::Inactive, None),
            JoinVerdict::Skip
        );
        assert!(!joins.is_undecided(n(0)));
    }

    #[test]
    fn a_decided_node_ignores_later_resolutions() {
        let mut joins = Joins::new([(n(0), 3)]);
        assert_eq!(
            joins.resolve(n(0), EdgeResolution::Active, Some(&JoinMode::Any)),
            JoinVerdict::Run
        );
        // The two slow parents arrive after the early-ready decision: no
        // second enqueue, no skip, no underflow.
        for _ in 0..2 {
            assert_eq!(
                joins.resolve(n(0), EdgeResolution::Active, Some(&JoinMode::Any)),
                JoinVerdict::AlreadyDecided
            );
        }
    }

    #[test]
    fn an_early_join_counts_active_parents_not_resolved_ones() {
        // `Any` must not fire on a parent that produced nothing.
        let mut joins = Joins::new([(n(0), 3)]);
        assert_eq!(
            joins.resolve(n(0), EdgeResolution::Inactive, Some(&JoinMode::Any)),
            JoinVerdict::Waiting
        );
        assert_eq!(
            joins.resolve(n(0), EdgeResolution::Active, Some(&JoinMode::Any)),
            JoinVerdict::Run
        );

        // N(2) of 4: one inactive resolution plus one active is not two.
        let mut joins = Joins::new([(n(1), 4)]);
        let n2 = JoinMode::N(2);
        assert_eq!(
            joins.resolve(n(1), EdgeResolution::Active, Some(&n2)),
            JoinVerdict::Waiting
        );
        assert_eq!(
            joins.resolve(n(1), EdgeResolution::Inactive, Some(&n2)),
            JoinVerdict::Waiting
        );
        assert_eq!(
            joins.resolve(n(1), EdgeResolution::Active, Some(&n2)),
            JoinVerdict::Run
        );

        // Majority of 3 needs two active.
        let mut joins = Joins::new([(n(2), 3)]);
        assert_eq!(
            joins.resolve(n(2), EdgeResolution::Active, Some(&JoinMode::Majority)),
            JoinVerdict::Waiting
        );
        assert_eq!(
            joins.resolve(n(2), EdgeResolution::Active, Some(&JoinMode::Majority)),
            JoinVerdict::Run
        );
    }

    #[test]
    fn a_continued_failure_never_wins_an_early_join_but_still_counts_at_the_end() {
        let mut joins = Joins::new([(n(0), 2)]);
        assert_eq!(
            joins.resolve(
                n(0),
                EdgeResolution::ActiveAfterFailure,
                Some(&JoinMode::Any)
            ),
            JoinVerdict::Waiting,
            "a continue_on_error failure must not satisfy Any while a sibling runs"
        );
        assert_eq!(
            joins.resolve(n(0), EdgeResolution::Inactive, Some(&JoinMode::Any)),
            JoinVerdict::Run,
            "once every parent has resolved, the carried failure is an input"
        );
    }

    #[test]
    fn all_join_waits_for_every_parent_even_when_all_are_active() {
        let mut joins = Joins::new([(n(0), 2)]);
        assert_eq!(
            joins.resolve(n(0), EdgeResolution::Active, Some(&JoinMode::All)),
            JoinVerdict::Waiting
        );
        assert_eq!(
            joins.resolve(n(0), EdgeResolution::Active, Some(&JoinMode::All)),
            JoinVerdict::Run
        );
    }

    #[test]
    fn seeding_decides_nothing_and_the_initial_queue_follows_graph_order() {
        let mut joins = Joins::new([(n(0), 0), (n(1), 1), (n(2), 1), (n(3), 2)]);
        // n(0) is seeded (a resumed run's completed parent of 1 and 3).
        assert!(joins.decide(n(0)));
        joins.resolve_seeded(n(3));
        joins.resolve_seeded(n(1));
        // n(2)'s parent was not seeded: still waiting. n(3) has one of two.
        let ready = joins.take_initially_ready([n(0), n(1), n(2), n(3)]);
        assert_eq!(ready, vec![n(1)]);
        assert!(joins.is_undecided(n(2)));
        assert!(joins.is_undecided(n(3)));
        assert_eq!(
            joins.resolve(n(3), EdgeResolution::Inactive, None),
            JoinVerdict::Run,
            "the seeded parent's edge counted active"
        );
    }

    #[test]
    fn an_untracked_node_is_already_decided() {
        let mut joins = Joins::new([]);
        assert_eq!(
            joins.resolve(n(9), EdgeResolution::Active, None),
            JoinVerdict::AlreadyDecided
        );
    }
}
