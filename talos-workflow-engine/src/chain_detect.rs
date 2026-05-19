//! Linear-chain detection over the workflow DAG.
//!
//! A *linear chain* is a maximal sequence of nodes where each interior
//! node has in-degree = 1 and out-degree = 1. The executor batches
//! such chains through
//! [`NodeDispatcher::dispatch_chain`](talos_workflow_engine_core::NodeDispatcher::dispatch_chain)
//! so the whole chain runs in a single transport round-trip on one
//! sandbox — one of the engine's main throughput optimizations.
//!
//! This module owns the pure-graph-topology detection. It has no
//! engine dependency; only `petgraph` and the `EdgeLogic` edge label.

use std::collections::HashSet;

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use talos_workflow_engine_core::EdgeLogic;
use uuid::Uuid;

/// Detect all maximal linear chains in `graph`.
///
/// A linear chain is a maximal sequence of nodes `[v₀, v₁, …, vₙ]` where:
///
/// - Every interior node has in-degree = 1 and out-degree = 1.
/// - The source `v₀` can have any in-degree, but out-degree = 1.
/// - The sink `vₙ` can have any out-degree, but in-degree = 1.
///
/// Chains of length ≥ 2 benefit from pipeline dispatch: the worker
/// executes all steps in a single NATS round-trip without intermediate
/// serialisation.
///
/// Returns a `Vec` of chains, each chain being a `Vec<NodeIndex>` in
/// topological order (source → sink).
#[must_use]
pub fn detect_linear_chains(graph: &DiGraph<Uuid, EdgeLogic>) -> Vec<Vec<NodeIndex>> {
    // Find all potential chain *starts*: nodes with out-degree = 1 whose
    // predecessor either has out-degree ≠ 1 or is absent.
    let mut chain_starts: Vec<NodeIndex> = Vec::new();

    for idx in graph.node_indices() {
        let out_deg = graph.neighbors_directed(idx, Direction::Outgoing).count();
        if out_deg != 1 {
            continue; // Can't be an interior node or start of a 2+ chain.
        }
        let in_deg = graph.neighbors_directed(idx, Direction::Incoming).count();
        // A chain starts if:
        // - it has no predecessor (source), OR
        // - its predecessor has out-degree ≠ 1 (branches out, so chain starts here).
        if in_deg == 0 {
            chain_starts.push(idx);
        } else {
            let parent_out_deg = graph
                .neighbors_directed(idx, Direction::Incoming)
                .next()
                .map(|p| graph.neighbors_directed(p, Direction::Outgoing).count())
                .unwrap_or(0);
            if parent_out_deg != 1 {
                chain_starts.push(idx);
            }
        }
    }

    // Expand each start into its maximal chain.
    let mut visited: HashSet<NodeIndex> = HashSet::new();
    let mut chains: Vec<Vec<NodeIndex>> = Vec::new();

    for start in chain_starts {
        if visited.contains(&start) {
            continue;
        }

        let mut chain = vec![start];
        let mut current = start;

        loop {
            visited.insert(current);
            // Move to the single successor, if it qualifies as an interior node.
            let next = graph
                .neighbors_directed(current, Direction::Outgoing)
                .next();
            let Some(next_idx) = next else { break };

            let next_in_deg = graph
                .neighbors_directed(next_idx, Direction::Incoming)
                .count();
            let next_out_deg = graph
                .neighbors_directed(next_idx, Direction::Outgoing)
                .count();

            // The next node can continue the chain only if it has exactly one
            // incoming edge (from `current`). Out-degree can be anything for the
            // sink, but if it branches we stop — those children start new chains.
            if next_in_deg != 1 {
                break; // Fan-in: `next_idx` belongs to a different sub-graph.
            }
            chain.push(next_idx);
            current = next_idx;

            if next_out_deg != 1 {
                break; // Sink or fan-out — chain ends here.
            }
        }

        if chain.len() >= 2 {
            chains.push(chain);
        }
    }

    chains
}

#[cfg(test)]
mod proptests {
    //! Property-based invariants on [`detect_linear_chains`].
    //!
    //! Hand-rolled tests cover specific topology shapes (`A→B→C`,
    //! `A→{B,C}`, `{A,B}→C`, etc.) — the property tests below assert
    //! the structural guarantees that *any* random DAG output must
    //! satisfy. They protect the chain detector from regressions
    //! that fixed-input tests can miss.
    //!
    //! Strategy: generate `n ∈ 1..=12` nodes, then for each `(i, j)`
    //! with `i < j` flip a coin to add an edge `i → j`. Topological
    //! ordering is implied by the index ordering, so the result is
    //! always acyclic by construction.
    use std::collections::HashSet;

    use proptest::prelude::*;
    use uuid::Uuid;

    use super::*;

    fn arb_dag() -> impl Strategy<Value = (DiGraph<Uuid, EdgeLogic>, usize)> {
        // Bound the node count low — the detector is O(V + E) so
        // larger graphs only burn proptest budget without exercising
        // new branches. Up to 12 nodes is enough for chains-of-chains,
        // diamond patterns, fan-in/fan-out, and parallel chains.
        (1usize..=12usize)
            .prop_flat_map(|n| {
                // For each upper-triangular pair (i, j) decide
                // independently whether the edge exists. Edge probability
                // is uniform; vary by sampling.
                let edge_count = n * (n - 1) / 2;
                (
                    Just(n),
                    proptest::collection::vec(any::<bool>(), edge_count),
                )
            })
            .prop_map(|(n, edge_bits)| {
                let mut g: DiGraph<Uuid, EdgeLogic> = DiGraph::new();
                let nodes: Vec<NodeIndex> = (0..n).map(|_| g.add_node(Uuid::new_v4())).collect();
                let mut bit = 0;
                for i in 0..n {
                    for j in (i + 1)..n {
                        if edge_bits[bit] {
                            g.add_edge(
                                nodes[i],
                                nodes[j],
                                EdgeLogic {
                                    source_handle: "output".into(),
                                    target_handle: "input".into(),
                                    mapping: None,
                                    condition: None,
                                    edge_type: String::new(),
                                },
                            );
                        }
                        bit += 1;
                    }
                }
                (g, n)
            })
    }

    proptest! {
        /// Every chain has length ≥ 2. Length-1 "chains" are
        /// discarded by the detector — they would defeat the
        /// pipeline-batching optimisation (one round-trip per
        /// "chain" is the same as one per node).
        #[test]
        fn chains_have_minimum_length((g, _n) in arb_dag()) {
            let chains = detect_linear_chains(&g);
            for chain in &chains {
                prop_assert!(
                    chain.len() >= 2,
                    "chain too short: {:?}",
                    chain.iter().map(|i| i.index()).collect::<Vec<_>>()
                );
            }
        }

        /// Chains are pairwise disjoint. A node belonging to two
        /// chains would mean the engine dispatches it twice.
        #[test]
        fn chains_are_pairwise_disjoint((g, _n) in arb_dag()) {
            let chains = detect_linear_chains(&g);
            let mut seen: HashSet<NodeIndex> = HashSet::new();
            for chain in &chains {
                for &n in chain {
                    prop_assert!(
                        seen.insert(n),
                        "node {:?} appears in more than one chain",
                        n.index()
                    );
                }
            }
        }

        /// Every interior node of a chain has exactly one inbound
        /// edge AND exactly one outbound edge. Fan-out / fan-in
        /// inside a chain would defeat batching (each branch needs
        /// its own dispatch).
        #[test]
        fn chain_interiors_are_in1_out1((g, _n) in arb_dag()) {
            let chains = detect_linear_chains(&g);
            for chain in &chains {
                if chain.len() < 3 {
                    continue;
                }
                for &interior in &chain[1..chain.len() - 1] {
                    let in_deg = g
                        .neighbors_directed(interior, petgraph::Direction::Incoming)
                        .count();
                    let out_deg = g
                        .neighbors_directed(interior, petgraph::Direction::Outgoing)
                        .count();
                    prop_assert_eq!(
                        in_deg, 1,
                        "interior node {:?} has in_deg = {} ≠ 1",
                        interior.index(), in_deg
                    );
                    prop_assert_eq!(
                        out_deg, 1,
                        "interior node {:?} has out_deg = {} ≠ 1",
                        interior.index(), out_deg
                    );
                }
            }
        }

        /// Every interior chain edge `chain[i] → chain[i+1]` exists
        /// in the graph. A detector bug that joined non-adjacent
        /// nodes into a "chain" would hand the dispatcher a
        /// nonsensical pipeline order.
        #[test]
        fn chain_edges_exist_in_graph((g, _n) in arb_dag()) {
            let chains = detect_linear_chains(&g);
            for chain in &chains {
                for window in chain.windows(2) {
                    let (a, b) = (window[0], window[1]);
                    prop_assert!(
                        g.find_edge(a, b).is_some(),
                        "chain reports edge {:?} → {:?} that does not exist",
                        a.index(), b.index()
                    );
                }
            }
        }

        /// A node that fans out (out_degree > 1) cannot appear as a
        /// chain interior — it would have to dispatch to multiple
        /// downstream branches, which atomic chain dispatch can't
        /// model.
        #[test]
        fn fan_out_nodes_are_not_chain_interiors((g, _n) in arb_dag()) {
            let chains = detect_linear_chains(&g);
            for chain in &chains {
                if chain.len() < 3 {
                    continue;
                }
                for &interior in &chain[1..chain.len() - 1] {
                    let out_deg = g
                        .neighbors_directed(interior, petgraph::Direction::Outgoing)
                        .count();
                    prop_assert!(
                        out_deg <= 1,
                        "interior fan-out at {:?} (out_deg = {})",
                        interior.index(), out_deg
                    );
                }
            }
        }
    }
}
