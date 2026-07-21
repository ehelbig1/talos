//! Unit tests for `crate::engine`.
//!
//! Mounted as a sibling module via `#[cfg(test)] #[path =
//! "engine_tests.rs"] mod tests;` in `engine.rs` so this file behaves
//! like an inline `#[cfg(test)] mod tests { ... }` block — `use
//! super::*;` resolves to the engine module's items, including the
//! `pub(crate)` fields the tests need to assert on directly.

use super::*;
use talos_workflow_engine_core::EdgeLogic;

fn make_graph(edges: &[(usize, usize)], num_nodes: usize) -> DiGraph<Uuid, EdgeLogic> {
    let mut g: DiGraph<Uuid, EdgeLogic> = DiGraph::new();
    let nodes: Vec<NodeIndex> = (0..num_nodes).map(|_| g.add_node(Uuid::new_v4())).collect();
    for &(from, to) in edges {
        g.add_edge(
            nodes[from],
            nodes[to],
            EdgeLogic {
                source_handle: "output".to_string(),
                target_handle: "input".to_string(),
                mapping: None,
                condition: None,
                edge_type: Default::default(),
            },
        );
    }
    g
}

#[test]
fn linear_chain_simple_3_nodes() {
    // A → B → C
    let g = make_graph(&[(0, 1), (1, 2)], 3);
    let chains = detect_linear_chains(&g);
    assert_eq!(chains.len(), 1, "should detect exactly one chain");
    assert_eq!(chains[0].len(), 3, "chain should include all 3 nodes");
}

#[test]
fn no_chain_for_fork() {
    // A → B, A → C
    let g = make_graph(&[(0, 1), (0, 2)], 3);
    let chains = detect_linear_chains(&g);
    assert!(
        chains.is_empty(),
        "Fork has no 2+ linear chain: {:?}",
        chains
    );
}

#[test]
fn no_chain_for_join() {
    // A → C, B → C
    let g = make_graph(&[(0, 2), (1, 2)], 3);
    let chains = detect_linear_chains(&g);
    assert!(chains.is_empty(), "Join has no 2+ linear chain");
}

#[test]
fn chain_with_single_edge() {
    // A → B (trivial 2-node chain)
    let g = make_graph(&[(0, 1)], 2);
    let chains = detect_linear_chains(&g);
    assert_eq!(chains.len(), 1);
    assert_eq!(chains[0].len(), 2);
}

#[test]
fn single_node_no_chain() {
    let g = make_graph(&[], 1);
    let chains = detect_linear_chains(&g);
    assert!(chains.is_empty(), "Single node produces no chain");
}

#[test]
fn diamond_graph_no_full_chain() {
    // A → B → D, A → C → D
    // B and C each have in-degree=1, out-degree=1 — but D has in-degree=2
    let g = make_graph(&[(0, 1), (0, 2), (1, 3), (2, 3)], 4);
    let chains = detect_linear_chains(&g);
    // A→B could be a chain (A out-degree=2 breaks it), so no chain >= 2.
    // Actually A has out-degree=2, so neither B nor C's predecessors qualify
    // as chain starts... let's just verify no chain spans the diamond.
    for chain in &chains {
        assert!(chain.len() < 3, "No chain of length >=3 in diamond graph");
    }
}

#[test]
fn parallel_chains() {
    // A → B → C and D → E (two independent chains)
    let g = make_graph(&[(0, 1), (1, 2), (3, 4)], 5);
    let chains = detect_linear_chains(&g);
    assert_eq!(chains.len(), 2, "should find exactly 2 chains");
    let lengths: Vec<usize> = chains.iter().map(|c| c.len()).collect();
    assert!(lengths.contains(&3), "one chain of length 3");
    assert!(lengths.contains(&2), "one chain of length 2");
}

// ── collapse_subworkflow_output tests ───────────────────────────────────
// These tests pin the contract that judge/reflective-retry/ensemble rely on:
// a sub-workflow with exactly one terminal node returns that node's output
// directly; multiple terminals fall back to a label-keyed map.

/// Build an engine where nodes are laid out in index order, labels
/// are assigned by position, and edges are (`src_label`, `dst_label`) pairs.
/// Returns (engine, label -> uuid).
fn build_sub_engine(
    labels: &[&str],
    edges: &[(&str, &str)],
) -> (ParallelWorkflowEngine, HashMap<String, Uuid>) {
    let mut engine = ParallelWorkflowEngine::new();
    let mut label_to_uuid: HashMap<String, Uuid> = HashMap::new();
    let mut label_to_idx: HashMap<String, NodeIndex> = HashMap::new();
    for label in labels {
        let uuid = Uuid::new_v4();
        let idx = engine.graph.add_node(uuid);
        engine.node_labels.insert(uuid, label.to_string());
        label_to_uuid.insert(label.to_string(), uuid);
        label_to_idx.insert(label.to_string(), idx);
    }
    for (src, dst) in edges {
        let s = label_to_idx[*src];
        let d = label_to_idx[*dst];
        engine.graph.add_edge(
            s,
            d,
            EdgeLogic {
                source_handle: "output".to_string(),
                target_handle: "input".to_string(),
                mapping: None,
                condition: None,
                edge_type: Default::default(),
            },
        );
    }
    (engine, label_to_uuid)
}

#[test]
fn collapse_single_terminal_returns_unwrapped_output() {
    // Canonical judge case: one node, returns record shape — caller sees fields directly.
    let (engine, uuids) = build_sub_engine(&["judge"], &[]);
    let mut results = HashMap::new();
    results.insert(
        uuids["judge"],
        serde_json::json!({"score": 0.94, "passed": true, "reasoning": "ok", "feedback": "good"}),
    );
    let out = ParallelWorkflowEngine::collapse_subworkflow_output(&results, &engine);
    assert_eq!(out.get("score").and_then(|v| v.as_f64()), Some(0.94));
    assert_eq!(out.get("passed").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(out.get("reasoning").and_then(|v| v.as_str()), Some("ok"));
    assert_eq!(out.get("feedback").and_then(|v| v.as_str()), Some("good"));
}

#[test]
fn collapse_linear_chain_returns_only_terminal() {
    // A → B → C. Only C is terminal; its output is the sub-workflow output.
    let (engine, uuids) = build_sub_engine(&["a", "b", "c"], &[("a", "b"), ("b", "c")]);
    let mut results = HashMap::new();
    results.insert(uuids["a"], serde_json::json!({"stage": "a", "n": 1}));
    results.insert(uuids["b"], serde_json::json!({"stage": "b", "n": 2}));
    results.insert(uuids["c"], serde_json::json!({"stage": "c", "n": 3}));
    let out = ParallelWorkflowEngine::collapse_subworkflow_output(&results, &engine);
    assert_eq!(out.get("stage").and_then(|v| v.as_str()), Some("c"));
    assert_eq!(out.get("n").and_then(|v| v.as_i64()), Some(3));
}

#[test]
fn collapse_multiple_terminals_returns_label_keyed_map() {
    // Two independent terminals: fallback to label-keyed map.
    let (engine, uuids) = build_sub_engine(&["alpha", "beta"], &[]);
    let mut results = HashMap::new();
    results.insert(uuids["alpha"], serde_json::json!({"v": 1}));
    results.insert(uuids["beta"], serde_json::json!({"v": 2}));
    let out = ParallelWorkflowEngine::collapse_subworkflow_output(&results, &engine);
    assert_eq!(
        out.get("alpha")
            .and_then(|v| v.get("v"))
            .and_then(|v| v.as_i64()),
        Some(1)
    );
    assert_eq!(
        out.get("beta")
            .and_then(|v| v.get("v"))
            .and_then(|v| v.as_i64()),
        Some(2)
    );
}

#[test]
fn collapse_skips_trigger_and_skipped_nodes() {
    // Trigger + one skipped middle node + one real terminal.
    let (engine, uuids) = build_sub_engine(
        &["__trigger__", "skipped", "real"],
        &[("__trigger__", "skipped"), ("skipped", "real")],
    );
    let mut results = HashMap::new();
    results.insert(
        uuids["__trigger__"],
        serde_json::json!({"trigger": "ignored"}),
    );
    results.insert(
        uuids["skipped"],
        serde_json::json!({"__skipped": true, "noise": "x"}),
    );
    results.insert(uuids["real"], serde_json::json!({"answer": "42"}));
    let out = ParallelWorkflowEngine::collapse_subworkflow_output(&results, &engine);
    assert_eq!(out.get("answer").and_then(|v| v.as_str()), Some("42"));
    assert!(out.get("trigger").is_none(), "trigger must not leak");
    assert!(out.get("noise").is_none(), "skipped must not leak");
}

#[test]
fn collapse_strips_engine_envelope_on_terminal() {
    // unwrap_output recognises {input: X, score: ..., passed: ...} as a wrapper
    // when every inner key is also at the outer level. Terminal node output
    // should pass through unwrap_output.
    let (engine, uuids) = build_sub_engine(&["judge"], &[]);
    let mut results = HashMap::new();
    // Real-world shape: engine-wrapped output where inner fields are also hoisted.
    results.insert(
        uuids["judge"],
        serde_json::json!({
            "input": {"score": 0.7, "passed": true},
            "score": 0.7,
            "passed": true,
        }),
    );
    let out = ParallelWorkflowEngine::collapse_subworkflow_output(&results, &engine);
    assert_eq!(out.get("score").and_then(|v| v.as_f64()), Some(0.7));
    assert_eq!(out.get("passed").and_then(|v| v.as_bool()), Some(true));
}

#[test]
fn collapse_empty_results_returns_empty_object() {
    let (engine, _) = build_sub_engine(&["a"], &[]);
    let results: HashMap<Uuid, JsonValue> = HashMap::new();
    let out = ParallelWorkflowEngine::collapse_subworkflow_output(&results, &engine);
    assert_eq!(out, serde_json::Value::Object(serde_json::Map::new()));
}

#[test]
fn collapse_fork_non_terminal_shadows_do_not_overwrite_terminal() {
    // A → B (terminal). A is not a terminal. Both happen to emit a "score" field.
    // Terminal's fields must win — but since only one terminal exists, the map
    // is NOT the output shape; instead B's output is returned directly.
    let (engine, uuids) = build_sub_engine(&["a", "b"], &[("a", "b")]);
    let mut results = HashMap::new();
    results.insert(uuids["a"], serde_json::json!({"score": 0.1}));
    results.insert(uuids["b"], serde_json::json!({"score": 0.9}));
    let out = ParallelWorkflowEngine::collapse_subworkflow_output(&results, &engine);
    assert_eq!(out.get("score").and_then(|v| v.as_f64()), Some(0.9));
}

#[test]
fn collapse_diamond_two_terminals_returns_both_labels() {
    // A → {B, C}. Both B and C are terminals (no aggregator).
    let (engine, uuids) = build_sub_engine(&["a", "b", "c"], &[("a", "b"), ("a", "c")]);
    let mut results = HashMap::new();
    results.insert(uuids["a"], serde_json::json!({"stage": "a"}));
    results.insert(uuids["b"], serde_json::json!({"stage": "b"}));
    results.insert(uuids["c"], serde_json::json!({"stage": "c"}));
    let out = ParallelWorkflowEngine::collapse_subworkflow_output(&results, &engine);
    // Multiple terminals → label-keyed map including non-terminal a.
    assert_eq!(
        out.get("a")
            .and_then(|v| v.get("stage"))
            .and_then(|v| v.as_str()),
        Some("a")
    );
    assert_eq!(
        out.get("b")
            .and_then(|v| v.get("stage"))
            .and_then(|v| v.as_str()),
        Some("b")
    );
    assert_eq!(
        out.get("c")
            .and_then(|v| v.get("stage"))
            .and_then(|v| v.as_str()),
        Some("c")
    );
}

// Seal-output validation tests live in
// `talos-workflow-engine-core::secret_envelope` alongside the
// `validate_seal_output` pub fn, since the helper is a pure
// structural check that external dispatchers can also reuse.

#[test]
fn agent_loop_max_history_defaults_to_constant() {
    let engine = ParallelWorkflowEngine::new();
    assert_eq!(
        engine.agent_loop_max_history(),
        DEFAULT_AGENT_LOOP_MAX_HISTORY
    );
    assert_eq!(DEFAULT_AGENT_LOOP_MAX_HISTORY, 20);
}

#[test]
fn agent_loop_max_history_setter_round_trips() {
    let mut engine = ParallelWorkflowEngine::new();
    engine.set_agent_loop_max_history(5);
    assert_eq!(engine.agent_loop_max_history(), 5);
    engine.set_agent_loop_max_history(0);
    assert_eq!(engine.agent_loop_max_history(), 0);
}

#[test]
fn default_sandbox_root_is_under_temp_dir() {
    // Cross-platform default — derived from std::env::temp_dir() so
    // it works on Windows, sandboxed macOS apps, locked-down
    // containers, etc. Asserting `starts_with(temp_dir)` rather
    // than a literal "/tmp/..." string is the whole point of the
    // 2026-04 cross-platform fix.
    let root = crate::default_sandbox_root();
    assert!(
        root.starts_with(std::env::temp_dir()),
        "{:?} not under {:?}",
        root,
        std::env::temp_dir()
    );
    assert!(
        root.ends_with(crate::DEFAULT_SANDBOX_DIR_NAME),
        "{:?} doesn't end with {:?}",
        root,
        crate::DEFAULT_SANDBOX_DIR_NAME
    );
}

#[test]
fn engine_default_sandbox_root_uses_function() {
    // The engine's own default at construction time must match
    // `default_sandbox_root()`. Otherwise consumers reading the
    // setter docs ("default is `Some(default_sandbox_root())`") get
    // a different value than the engine actually uses.
    let engine = ParallelWorkflowEngine::new();
    let expected = Some(crate::default_sandbox_root().to_path_buf());
    assert_eq!(engine.sandbox_root, expected);
}

#[test]
fn unblock_child_on_failure_does_not_double_enqueue_early_ready_fanin() {
    // R2-1 regression: two error-edge parents into one `JoinMode::Any` fan-in
    // must enqueue the fan-in EXACTLY ONCE. Pre-fix the failure-path loop
    // decremented + enqueued without removing the `pending` entry on the
    // 0-transition, so the second parent's unblock re-enqueued the fan-in
    // (and its whole downstream subgraph) — an exactly-once violation.
    let mut engine = ParallelWorkflowEngine::new();
    let p1 = Uuid::new_v4();
    let p2 = Uuid::new_v4();
    let fanin = Uuid::new_v4();
    engine.add_node(p1, Some(Uuid::new_v4()), None, None);
    engine.add_node(p2, Some(Uuid::new_v4()), None, None);
    engine.add_node(
        fanin,
        None,
        None,
        Some(talos_workflow_engine_core::SystemNodeKind::FanIn {
            join_mode: talos_workflow_engine_core::JoinMode::Any,
            aggregation_expr: None,
        }),
    );
    let p1_idx = engine.node_map[&p1];
    let p2_idx = engine.node_map[&p2];
    let fanin_idx = engine.node_map[&fanin];
    for src in [p1_idx, p2_idx] {
        engine.graph.add_edge(
            src,
            fanin_idx,
            EdgeLogic {
                source_handle: "output".to_string(),
                target_handle: "input".to_string(),
                mapping: None,
                condition: None,
                edge_type: "error".to_string(),
            },
        );
    }

    let mut pending: HashMap<NodeIndex, usize> = HashMap::new();
    pending.insert(fanin_idx, 2); // two inbound parents
    let mut ready: VecDeque<NodeIndex> = VecDeque::new();

    // Both parents fail down the error edge (error-edge path applies early-ready).
    engine.unblock_child_on_failure(fanin_idx, &mut pending, &mut ready, true);
    engine.unblock_child_on_failure(fanin_idx, &mut pending, &mut ready, true);

    assert_eq!(
        ready.iter().filter(|&&n| n == fanin_idx).count(),
        1,
        "early-ready fan-in must be enqueued exactly once across two error-edge parents"
    );
    assert!(
        !pending.contains_key(&fanin_idx),
        "the fan-in's pending entry must be removed on the 0-transition so a late parent can't re-enter"
    );
}

#[test]
fn unblock_child_on_failure_removes_entry_on_all_join_zero_transition() {
    // The continue_on_error path does NOT apply early-ready (All-style wait),
    // but MUST still remove the entry on the genuine 0-transition so a later
    // error-edge parent can't re-enqueue the child.
    let mut engine = ParallelWorkflowEngine::new();
    let parent = Uuid::new_v4();
    let child = Uuid::new_v4();
    engine.add_node(parent, Some(Uuid::new_v4()), None, None);
    engine.add_node(child, Some(Uuid::new_v4()), None, None);
    let parent_idx = engine.node_map[&parent];
    let child_idx = engine.node_map[&child];
    engine.graph.add_edge(
        parent_idx,
        child_idx,
        EdgeLogic {
            source_handle: "output".to_string(),
            target_handle: "input".to_string(),
            mapping: None,
            condition: None,
            edge_type: Default::default(),
        },
    );

    let mut pending: HashMap<NodeIndex, usize> = HashMap::new();
    pending.insert(child_idx, 2);
    let mut ready: VecDeque<NodeIndex> = VecDeque::new();

    // First parent: 2 -> 1, not ready yet, not enqueued.
    engine.unblock_child_on_failure(child_idx, &mut pending, &mut ready, false);
    assert!(ready.is_empty(), "child must wait for the second parent");
    assert_eq!(pending.get(&child_idx).copied(), Some(1));

    // Second parent: 1 -> 0, enqueued once and entry removed.
    engine.unblock_child_on_failure(child_idx, &mut pending, &mut ready, false);
    assert_eq!(ready.iter().filter(|&&n| n == child_idx).count(), 1);
    assert!(!pending.contains_key(&child_idx));

    // A spurious third call (e.g. a late error-edge parent) must NOT re-enqueue.
    engine.unblock_child_on_failure(child_idx, &mut pending, &mut ready, false);
    assert_eq!(
        ready.iter().filter(|&&n| n == child_idx).count(),
        1,
        "a late parent must not re-enqueue an already-released child"
    );
}

#[test]
fn wait_handler_returns_none_for_non_wait_nodes() {
    // Sanity check: try_dispatch_wait must short-circuit cleanly
    // for any other SystemNodeKind (and for plain module nodes).
    // Otherwise the reactor would short-circuit incorrectly and
    // pause workflows that were never asked to.
    let mut engine = ParallelWorkflowEngine::new();
    let module_node = Uuid::new_v4();
    engine.add_node(module_node, Some(Uuid::new_v4()), None, None);
    assert!(engine
        .try_dispatch_wait(module_node, Uuid::new_v4())
        .is_none());

    let collect_node = Uuid::new_v4();
    engine.add_node(
        collect_node,
        None,
        None,
        Some(talos_workflow_engine_core::SystemNodeKind::Collect),
    );
    assert!(engine
        .try_dispatch_wait(collect_node, Uuid::new_v4())
        .is_none());
}

#[test]
fn wait_handler_returns_pause_envelope_with_message() {
    // Wait { message: Some(...) } produces a __waiting__ envelope
    // carrying the message — that's the signal the consumer's
    // CheckpointStore + resume orchestration relies on.
    let mut engine = ParallelWorkflowEngine::new();
    let wait_node = Uuid::new_v4();
    engine.add_node(
        wait_node,
        None,
        None,
        Some(talos_workflow_engine_core::SystemNodeKind::Wait {
            message: Some("approve please".into()),
        }),
    );
    let exec_id = Uuid::new_v4();
    let outcome = engine.try_dispatch_wait(wait_node, exec_id).expect("pause");
    let crate::scheduler_handlers::WaitOutcome::Pause { waiting_output } = outcome;
    assert_eq!(waiting_output["__waiting__"].as_bool(), Some(true));
    assert_eq!(waiting_output["message"].as_str(), Some("approve please"));
    assert_eq!(
        waiting_output["node_id"].as_str(),
        Some(wait_node.to_string().as_str())
    );
    assert_eq!(
        waiting_output["execution_id"].as_str(),
        Some(exec_id.to_string().as_str())
    );
}

#[test]
fn wait_handler_returns_pause_envelope_without_message() {
    // Wait { message: None } omits the message key rather than
    // emitting `"message": null` — keeps the envelope minimal.
    let mut engine = ParallelWorkflowEngine::new();
    let wait_node = Uuid::new_v4();
    engine.add_node(
        wait_node,
        None,
        None,
        Some(talos_workflow_engine_core::SystemNodeKind::Wait { message: None }),
    );
    let outcome = engine
        .try_dispatch_wait(wait_node, Uuid::new_v4())
        .expect("pause");
    let crate::scheduler_handlers::WaitOutcome::Pause { waiting_output } = outcome;
    assert_eq!(waiting_output["__waiting__"].as_bool(), Some(true));
    assert!(waiting_output.get("message").is_none());
}

#[cfg(feature = "llm-primitives")]
#[test]
fn inline_judge_passes_when_score_meets_threshold() {
    use talos_workflow_engine_test_utils::noop::StubExpressionEvaluator;

    let mut engine = ParallelWorkflowEngine::new();
    // The stub evaluator returns the configured JSON for every
    // expression — we don't care which expression the judge sees,
    // only that the dispatch handler parses the verdict and gates
    // on pass_threshold correctly.
    engine.set_expression_evaluator(Arc::new(StubExpressionEvaluator::new().with_json(
        serde_json::json!({
            "score": 0.9,
            "passed": true,
            "reasoning": "looks good",
            "feedback": "ship it",
        }),
    )));

    let parent = serde_json::json!({ "answer": "yes" });
    let out = engine.dispatch_inline_judge(parent.clone(), "score(answer)", Some(0.5), "error");

    assert_eq!(
        out.get("__judge_passed__").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        out.get("__judge_score__").and_then(|v| v.as_f64()),
        Some(0.9)
    );
    // Original parent inputs survive on the pass path so downstream
    // nodes see the value the judge approved.
    assert_eq!(out.get("answer").and_then(|v| v.as_str()), Some("yes"));
}

#[cfg(feature = "llm-primitives")]
#[test]
fn inline_judge_rejects_when_score_below_threshold() {
    use talos_workflow_engine_test_utils::noop::StubExpressionEvaluator;

    let mut engine = ParallelWorkflowEngine::new();
    engine.set_expression_evaluator(Arc::new(StubExpressionEvaluator::new().with_json(
        serde_json::json!({
            "score": 0.3,
            "passed": true,           // raw says pass, but threshold gates it
            "reasoning": "weak",
            "feedback": "try again",
        }),
    )));

    let parent = serde_json::json!({ "answer": "maybe" });
    let out = engine.dispatch_inline_judge(parent, "score(answer)", Some(0.7), "error");

    assert_eq!(out.get("__error").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        out.get("__judge_passed__").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert_eq!(
        out.get("__judge_score__").and_then(|v| v.as_f64()),
        Some(0.3)
    );
}

#[cfg(feature = "llm-primitives")]
#[test]
fn inline_judge_emits_error_envelope_when_no_evaluator_wired() {
    // No expression evaluator → eval_json fails → error envelope.
    // Important contract: the engine doesn't panic when the
    // evaluator is missing, even on the inline path.
    let engine = ParallelWorkflowEngine::new();
    let out = engine.dispatch_inline_judge(serde_json::json!({}), "anything", None, "error");
    assert_eq!(out.get("__error").and_then(|v| v.as_bool()), Some(true));
    assert!(
        out.get("error_message")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .contains("InlineJudge expression failed"),
        "unexpected envelope: {out}"
    );
}

#[test]
fn agent_loop_max_history_propagates_through_adapter_set() {
    // Sub-workflow dispatch closures clone an AdapterSet and
    // hydrate fresh engines from it. The cap MUST ride along or
    // sub-engines silently fall back to the default — exactly the
    // adapter-drop footgun documented in talos-workflow-engine/AGENTS.md.
    let mut engine = ParallelWorkflowEngine::new();
    engine.set_agent_loop_max_history(7);
    let cloned = engine.adapter_set().into_engine();
    assert_eq!(cloned.agent_loop_max_history(), 7);
}

#[test]
fn engine_limit_defaults_match_documented_constants() {
    // Anchor each engine field's default to the public DEFAULT_* const
    // it advertises in docs. Drift here would silently change behaviour
    // for downstream consumers reading the defaults from one source
    // and getting another.
    let engine = ParallelWorkflowEngine::new();
    assert_eq!(
        engine.max_prefetch_successors(),
        DEFAULT_MAX_PREFETCH_SUCCESSORS
    );
    assert_eq!(engine.max_workflow_nodes(), DEFAULT_MAX_WORKFLOW_NODES);
    assert_eq!(
        engine.max_node_output_bytes(),
        DEFAULT_MAX_NODE_OUTPUT_BYTES
    );
    assert_eq!(engine.max_fuel_per_node(), DEFAULT_MAX_FUEL_PER_NODE);
    // Sanity-pin the documented values too.
    assert_eq!(DEFAULT_MAX_PREFETCH_SUCCESSORS, 8);
    assert_eq!(DEFAULT_MAX_WORKFLOW_NODES, 500);
    assert_eq!(DEFAULT_MAX_NODE_OUTPUT_BYTES, 5 * 1024 * 1024);
    assert_eq!(DEFAULT_MAX_FUEL_PER_NODE, 50_000_000);
}

#[test]
fn engine_limit_setters_round_trip() {
    let mut engine = ParallelWorkflowEngine::new();
    engine.set_max_prefetch_successors(2);
    engine.set_max_workflow_nodes(10);
    engine.set_max_node_output_bytes(1024);
    engine.set_max_fuel_per_node(1_000);
    assert_eq!(engine.max_prefetch_successors(), 2);
    assert_eq!(engine.max_workflow_nodes(), 10);
    assert_eq!(engine.max_node_output_bytes(), 1024);
    assert_eq!(engine.max_fuel_per_node(), 1_000);
}

#[test]
fn engine_limits_propagate_through_adapter_set() {
    // Sub-workflow dispatch closures clone an `AdapterSet` and hydrate
    // fresh engines from it. Each new limit MUST ride along — without
    // this propagation, a parent's lowered `max_fuel_per_node` (etc.)
    // would silently revert to the default inside any agent-loop body
    // or sub-workflow invocation. Per the AGENTS.md "miss any one step
    // and sub-workflow dispatch silently drops the adapter" rule.
    let mut engine = ParallelWorkflowEngine::new();
    engine.set_max_prefetch_successors(3);
    engine.set_max_workflow_nodes(11);
    engine.set_max_node_output_bytes(2048);
    engine.set_max_fuel_per_node(7_000);
    let cloned = engine.adapter_set().into_engine();
    assert_eq!(cloned.max_prefetch_successors(), 3);
    assert_eq!(cloned.max_workflow_nodes(), 11);
    assert_eq!(cloned.max_node_output_bytes(), 2048);
    assert_eq!(cloned.max_fuel_per_node(), 7_000);
}

#[test]
fn add_node_respects_configured_max_workflow_nodes() {
    // Lock in that lowering the cap actually trims `add_node`. The
    // hardcoded 500 was a hidden ceiling for code-gen workflows; this
    // test ensures the new setter is wired into the gate.
    let mut engine = ParallelWorkflowEngine::new();
    engine.set_max_workflow_nodes(2);
    engine.add_node(Uuid::new_v4(), Some(Uuid::new_v4()), None, None);
    engine.add_node(Uuid::new_v4(), Some(Uuid::new_v4()), None, None);
    // Third add_node must be rejected.
    let third = Uuid::new_v4();
    engine.add_node(third, Some(Uuid::new_v4()), None, None);
    assert!(
        engine.node_map().get(&third).is_none(),
        "third add_node should have been dropped past the cap"
    );
    assert_eq!(engine.graph().node_count(), 2);
}

#[test]
fn into_engine_preserves_max_llm_tier() {
    use talos_workflow_engine_core::LlmTier;

    // Tier2 (external LLMs allowed) must survive sub-engine hydration. Regression:
    // `into_engine` dropped `max_llm_tier`, so every sub-workflow fell back to
    // `ParallelWorkflowEngine::new()`'s Tier1 default and lost external-LLM access
    // (judges / ensembles / sub-workflows broke for legitimately-tier-2 actors).
    let mut parent = ParallelWorkflowEngine::new();
    parent.set_max_llm_tier(LlmTier::Tier2);
    let child = parent.adapter_set().into_engine();
    assert_eq!(
        child.max_llm_tier,
        LlmTier::Tier2,
        "sub-engine must inherit the parent's Tier2 ceiling"
    );

    // Tier1 round-trips too — no accidental escalation to Tier2.
    let mut parent1 = ParallelWorkflowEngine::new();
    parent1.set_max_llm_tier(LlmTier::Tier1);
    assert_eq!(
        parent1.adapter_set().into_engine().max_llm_tier,
        LlmTier::Tier1,
        "sub-engine must inherit the parent's Tier1 ceiling"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// P1 — accumulated-context snapshot (build + memo)
// ─────────────────────────────────────────────────────────────────────────────

/// Build a `(node_labels, results)` pair for the accumulated-context helpers.
fn acc_fixture() -> (HashMap<Uuid, String>, HashMap<Uuid, JsonValue>, Uuid, Uuid) {
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let trig = Uuid::new_v4();
    let mut labels = HashMap::new();
    labels.insert(a, "fetch".to_string());
    labels.insert(b, "summarize".to_string());
    labels.insert(trig, "__trigger__".to_string());
    let mut results = HashMap::new();
    // `a` carries an internal `__meta` key that must be stripped from the value.
    results.insert(a, serde_json::json!({ "text": "hi", "__meta": 1 }));
    results.insert(b, serde_json::json!({ "summary": "ok" }));
    // Internal node — must be omitted entirely.
    results.insert(trig, serde_json::json!({ "seed": true }));
    (labels, results, a, b)
}

#[test]
fn build_accumulated_context_strips_and_omits() {
    let (labels, results, _a, _b) = acc_fixture();
    let acc = ParallelWorkflowEngine::build_accumulated_context(&labels, &results)
        .expect("non-empty accumulated context");
    let obj = acc.as_object().expect("object");
    // Internal node omitted entirely.
    assert!(!obj.contains_key("__trigger__"));
    // Labels are the keys.
    assert!(obj.contains_key("fetch"));
    assert!(obj.contains_key("summarize"));
    // `__`-prefixed keys stripped from the value, real keys preserved.
    let fetch = obj["fetch"].as_object().unwrap();
    assert_eq!(fetch.get("text"), Some(&serde_json::json!("hi")));
    assert!(
        !fetch.contains_key("__meta"),
        "internal key must be stripped"
    );
}

#[test]
fn build_accumulated_context_empty_is_none() {
    let labels: HashMap<Uuid, String> = HashMap::new();
    let results: HashMap<Uuid, JsonValue> = HashMap::new();
    assert!(ParallelWorkflowEngine::build_accumulated_context(&labels, &results).is_none());

    // A map containing only internal nodes also collapses to None.
    let trig = Uuid::new_v4();
    let mut labels = HashMap::new();
    labels.insert(trig, "__trigger__".to_string());
    let mut results = HashMap::new();
    results.insert(trig, serde_json::json!({ "seed": true }));
    assert!(
        ParallelWorkflowEngine::build_accumulated_context(&labels, &results).is_none(),
        "only-internal results must yield None"
    );
}

#[test]
fn memo_returns_same_content_as_direct_build() {
    let (labels, results, _a, _b) = acc_fixture();
    let direct = ParallelWorkflowEngine::build_accumulated_context(&labels, &results);
    let mut memo = None;
    let memoed =
        ParallelWorkflowEngine::build_accumulated_context_memo(&labels, &results, 1, &mut memo);
    // Byte-for-byte equivalent value.
    assert_eq!(
        direct.as_deref(),
        memoed.as_deref(),
        "memoized snapshot must equal a direct build"
    );
}

#[test]
fn memo_reuses_arc_on_unchanged_version_and_rebuilds_on_bump() {
    let (labels, results, _a, _b) = acc_fixture();
    let mut memo = None;

    let first =
        ParallelWorkflowEngine::build_accumulated_context_memo(&labels, &results, 7, &mut memo)
            .expect("some");
    // Same version → same allocation handed back (refcount bump, no rebuild).
    let again =
        ParallelWorkflowEngine::build_accumulated_context_memo(&labels, &results, 7, &mut memo)
            .expect("some");
    assert!(
        Arc::ptr_eq(&first, &again),
        "unchanged version must return the cached Arc, not rebuild"
    );

    // Bumped version → fresh build (distinct allocation), identical content.
    let rebuilt =
        ParallelWorkflowEngine::build_accumulated_context_memo(&labels, &results, 8, &mut memo)
            .expect("some");
    assert!(
        !Arc::ptr_eq(&first, &rebuilt),
        "version bump must trigger a rebuild"
    );
    assert_eq!(*first, *rebuilt, "rebuilt content must be unchanged");
}

// ─────────────────────────────────────────────────────────────────────────────
// P2 — per-execution module-artifact cache
// ─────────────────────────────────────────────────────────────────────────────

/// A `ModuleFetcher` that records how many times each `module_id` was fetched,
/// so a test can prove the per-execution cache elides redundant DB-shaped
/// round-trips. Local to the test module so the shared test-utils crate stays
/// untouched.
#[derive(Clone, Default)]
struct CountingFetcher {
    counts: Arc<dashmap::DashMap<Uuid, usize>>,
}

impl CountingFetcher {
    fn count_for(&self, module_id: Uuid) -> usize {
        self.counts.get(&module_id).map(|c| *c).unwrap_or(0)
    }
}

#[async_trait::async_trait]
impl ModuleFetcher for CountingFetcher {
    async fn fetch(
        &self,
        module_id: Uuid,
        _user_id: Uuid,
    ) -> Result<talos_workflow_engine_core::WasmModuleArtifact, talos_workflow_engine_core::BoxError>
    {
        *self.counts.entry(module_id).or_insert(0) += 1;
        Ok(talos_workflow_engine_core::WasmModuleArtifact {
            module_id,
            content_hash: format!("hash-{module_id}"),
            wasm_bytes: vec![0xAA, 0xBB, 0xCC],
            oci_url: None,
            max_fuel: 1_000_000,
            capability_world: "test".into(),
            allowed_hosts: vec![],
            allowed_methods: vec![],
            allowed_secrets: vec![],
            requires_approval_for: vec![],
            integration_name: None,
            config: None,
        })
    }

    async fn load_rate_limits(&self, _module_ids: &[Uuid]) -> HashMap<Uuid, i32> {
        HashMap::new()
    }
}

#[tokio::test]
async fn module_artifact_cache_dedupes_same_module_across_nodes() {
    let fetcher = CountingFetcher::default();
    let mut engine = ParallelWorkflowEngine::new();
    engine.set_user_id(Uuid::new_v4());
    engine.set_module_fetcher(Arc::new(fetcher.clone()));

    // Two distinct graph nodes that resolve to the SAME module_id, plus a
    // third node on a different module_id.
    let shared_module = Uuid::new_v4();
    let other_module = Uuid::new_v4();
    let n1 = Uuid::new_v4();
    let n2 = Uuid::new_v4();
    let n3 = Uuid::new_v4();
    engine.add_node(n1, Some(shared_module), None, None);
    engine.add_node(n2, Some(shared_module), None, None);
    engine.add_node(n3, Some(other_module), None, None);

    let a1 = engine.fetch_module(n1).await.expect("fetch n1");
    let a2 = engine.fetch_module(n2).await.expect("fetch n2");
    let a3 = engine.fetch_module(n3).await.expect("fetch n3");

    // The shared module was fetched from the backing store exactly once
    // despite two nodes dispatching it.
    assert_eq!(
        fetcher.count_for(shared_module),
        1,
        "shared module must hit the backing fetcher only once per execution"
    );
    assert_eq!(
        fetcher.count_for(other_module),
        1,
        "a distinct module is keyed separately and fetched on its own"
    );
    // Returned artifacts are content-equivalent for the shared module and
    // correctly distinct for the other module.
    assert_eq!(a1.content_hash, a2.content_hash);
    assert_eq!(a1.content_hash, format!("hash-{shared_module}"));
    assert_eq!(a3.content_hash, format!("hash-{other_module}"));
}

#[tokio::test]
async fn module_artifact_cache_is_per_engine_not_global() {
    // A second engine instance must not see the first engine's cached fetch:
    // the cache is scoped to the engine/run instance, so each run re-fetches.
    let fetcher = CountingFetcher::default();
    let module = Uuid::new_v4();
    let node = Uuid::new_v4();

    let mut engine_a = ParallelWorkflowEngine::new();
    engine_a.set_user_id(Uuid::new_v4());
    engine_a.set_module_fetcher(Arc::new(fetcher.clone()));
    engine_a.add_node(node, Some(module), None, None);
    let _ = engine_a.fetch_module(node).await.expect("fetch a");
    assert_eq!(fetcher.count_for(module), 1);

    // Fresh engine, same shared backing fetcher: a NEW per-execution cache, so
    // the module is fetched again (proves no cross-execution leak).
    let mut engine_b = ParallelWorkflowEngine::new();
    engine_b.set_user_id(Uuid::new_v4());
    engine_b.set_module_fetcher(Arc::new(fetcher.clone()));
    engine_b.add_node(node, Some(module), None, None);
    let _ = engine_b.fetch_module(node).await.expect("fetch b");
    assert_eq!(
        fetcher.count_for(module),
        2,
        "a separate engine instance must not reuse another run's artifact cache"
    );
}

/// Sub-workflow engines must NOT carry a persisting event sink.
///
/// `execute_subworkflow_graph` runs the inner engine under a synthetic
/// execution id with no `workflow_executions` row, so the FK-bound
/// `PostgresEventSink` would drop every event (regression round 5,
/// 2026-07-08). The fix detaches the sink via `clear_event_sink`; this
/// test locks in both halves: `adapter_set` PROPAGATES the parent sink
/// (so a normal sub-engine build would inherit it), and `clear_event_sink`
/// removes it.
#[tokio::test]
async fn sub_engine_event_sink_is_detachable() {
    use std::sync::Arc;
    use talos_workflow_engine_test_utils::capture::CaptureEventSink;

    let mut parent = ParallelWorkflowEngine::new();
    parent.set_event_sink(Arc::new(CaptureEventSink::new()));
    assert!(
        parent.event_sink.is_some(),
        "parent engine should hold the sink we just set"
    );

    // adapter_set + into_engine mirrors the sub-workflow build path; the
    // sink is inherited (this is exactly the pre-fix leak vector).
    let mut sub = parent.adapter_set().into_engine();
    assert!(
        sub.event_sink.is_some(),
        "sub-engine inherits the parent's event sink via adapter_set"
    );

    // The fix: execute_subworkflow_graph calls this before running.
    sub.clear_event_sink();
    assert!(
        sub.event_sink.is_none(),
        "clear_event_sink must detach the FK-doomed sink so inner events \
         aren't persisted under a synthetic execution id"
    );
}

// ---------------------------------------------------------------------------
// Adaptive fuel (Phase 2): resolve_node_max_fuel guard-mode semantics.
// ---------------------------------------------------------------------------

#[test]
fn resolve_node_max_fuel_guard_mode() {
    let mut engine = ParallelWorkflowEngine::new();
    engine.set_max_fuel_per_node(50_000_000);

    let brief = Uuid::new_v4();
    let other = Uuid::new_v4();
    engine.node_labels.insert(brief, "brief".to_string());
    engine.node_labels.insert(other, "other".to_string());

    let mut learned = HashMap::new();
    learned.insert("brief".to_string(), 8_000_000u64); // learned ceiling for `brief`
    engine.set_learned_fuel_ceilings(learned);

    // Learned ceiling RAISES a too-low module default (the daily-brief case).
    assert_eq!(
        engine.resolve_node_max_fuel(&brief, None, 1_400_000),
        8_000_000
    );

    // A deliberately-HIGHER explicit override is respected — guard mode never
    // lowers below a set value.
    assert_eq!(
        engine.resolve_node_max_fuel(&brief, Some(20_000_000), 1_400_000),
        20_000_000
    );

    // A baseline already above the learned ceiling is kept (never lowered).
    assert_eq!(
        engine.resolve_node_max_fuel(&brief, None, 12_000_000),
        12_000_000
    );

    // A node with NO learned entry behaves byte-for-byte like the old path:
    // config override > module default, clamped to the engine ceiling.
    assert_eq!(
        engine.resolve_node_max_fuel(&other, None, 2_000_000),
        2_000_000
    );
    assert_eq!(
        engine.resolve_node_max_fuel(&other, Some(3_000_000), 2_000_000),
        3_000_000
    );

    // The engine-wide ceiling always clamps the result.
    assert_eq!(
        engine.resolve_node_max_fuel(&brief, Some(60_000_000), 1_400_000),
        50_000_000
    );

    // Empty learned map ⇒ adaptive fully inert (default engine state).
    let plain = ParallelWorkflowEngine::new();
    let n = Uuid::new_v4();
    assert_eq!(plain.resolve_node_max_fuel(&n, None, 2_200_000), 2_200_000);
}

// ---------------------------------------------------------------------------
// Per-node max_fuel override precedence on the loop-body dispatch path.
// ---------------------------------------------------------------------------

#[test]
fn loop_body_max_fuel_override_honored() {
    // Reproduces the loop-body dispatch gap (`scheduler_handlers.rs`
    // `run_loop_iterations`): the body node's graph-JSON `data.max_fuel`
    // override must reach `resolve_node_max_fuel`, not the pre-fix hardcoded
    // `None`. Exercises the exact two production calls the dispatch site now
    // makes — `node_config_max_fuel(body)` feeding `resolve_node_max_fuel` —
    // so the test can't drift from the shipped logic.
    let mut engine = ParallelWorkflowEngine::new();
    engine.set_max_fuel_per_node(50_000_000);

    let body = Uuid::new_v4();
    // Body node `data` as it lands in `node_configs` at graph load.
    engine.node_configs.insert(
        body,
        serde_json::json!({ "max_fuel": 8_000_000, "label": "send" }),
    );

    // Module-row default is far lower (the pa-morning-dispatch 1.38M case).
    let module_default = 1_380_000u64;

    // Pre-fix behavior: a hardcoded `None` override lets the (lower) module-row
    // default win — the exact bug this change fixes.
    assert_eq!(
        engine.resolve_node_max_fuel(&body, None, module_default),
        module_default,
        "hardcoded None reproduces the pre-fix module-row-wins bug"
    );

    // Post-fix: the helper extracts the override and it wins.
    assert_eq!(engine.node_config_max_fuel(&body), Some(8_000_000));
    assert_eq!(
        engine.resolve_node_max_fuel(&body, engine.node_config_max_fuel(&body), module_default),
        8_000_000,
        "body node's data.max_fuel override must be honored"
    );

    // A body node with NO `max_fuel` in its config falls back to the module
    // default (byte-for-byte the old path for override-less bodies).
    let bare = Uuid::new_v4();
    engine
        .node_configs
        .insert(bare, serde_json::json!({ "label": "noop" }));
    assert_eq!(engine.node_config_max_fuel(&bare), None);
    assert_eq!(
        engine.resolve_node_max_fuel(&bare, engine.node_config_max_fuel(&bare), module_default),
        module_default
    );
}

// ---------------------------------------------------------------------------
// Scheduled-path divergence: a node's data.max_fuel override must survive the
// real graph parse and win over the module-row default. The scheduler bug was
// loading the DRAFT graph (which lacked the override) instead of the published
// active version (which carried it); feeding the graph WITH the override here
// proves fuel is honored once the correct graph is loaded — exercising the real
// `load_from_graph_json` parser + `resolve_node_max_fuel`, no shadowed logic.
// ---------------------------------------------------------------------------

#[test]
fn graph_node_max_fuel_override_survives_load() {
    let module_id = Uuid::new_v4();
    let compose_id = Uuid::new_v4();
    let send_id = Uuid::new_v4();

    // Mirrors the pa-morning-dispatch shape: a `compose` node carrying an
    // explicit `data.max_fuel` override, and a `send` node without one.
    let graph = serde_json::json!({
        "nodes": [
            {
                "id": compose_id.to_string(),
                "type": module_id.to_string(),
                "data": { "moduleId": module_id.to_string(), "max_fuel": 8_000_000, "label": "compose" }
            },
            {
                "id": send_id.to_string(),
                "type": module_id.to_string(),
                "data": { "moduleId": module_id.to_string(), "label": "send" }
            }
        ],
        "edges": [
            {
                "source": compose_id.to_string(),
                "target": send_id.to_string(),
                "sourceHandle": "output",
                "targetHandle": "input"
            }
        ]
    });

    let mut engine = ParallelWorkflowEngine::new();
    engine.set_max_fuel_per_node(50_000_000);
    engine
        .load_from_graph_json(&graph)
        .expect("graph should parse");

    let module_default = 1_380_000u64;

    // `compose` carried `data.max_fuel` — the override survives the parse into
    // node_configs and wins (the published-graph behavior manual triggers saw).
    assert_eq!(engine.node_config_max_fuel(&compose_id), Some(8_000_000));
    assert_eq!(
        engine.resolve_node_max_fuel(
            &compose_id,
            engine.node_config_max_fuel(&compose_id),
            module_default
        ),
        8_000_000
    );

    // `send` carried none — falls back to the module-row default (the draft-graph
    // behavior scheduled runs saw before the fix routed them to the published
    // graph).
    assert_eq!(engine.node_config_max_fuel(&send_id), None);
    assert_eq!(
        engine.resolve_node_max_fuel(
            &send_id,
            engine.node_config_max_fuel(&send_id),
            module_default
        ),
        module_default
    );
}
