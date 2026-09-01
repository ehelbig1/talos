//! What a boolean Rhai condition GOVERNS, and what happens when it cannot
//! be evaluated.
//!
//! # Why this exists
//!
//! The engine evaluates operator-authored Rhai in six places through one
//! primitive that returns `bool` and swallows every failure into `false`
//! ([`crate::engine::ParallelWorkflowEngine::eval_bool`] →
//! `talos_engine::rhai_helpers::evaluate_condition`). That primitive's own
//! comment defends the default as *"the only safe default — crashing on a bad
//! expression would take down legitimate workflows"*, which is true, and then
//! says *"Operators need a metric to alert on the rate"*, which was never
//! built.
//!
//! `false` is not one semantic. For five of the six call sites it is
//! CONSERVATIVE — do not take this branch, stop iterating, fail the check.
//! For the sixth, a node's `skip_condition`, `false` means "do not skip",
//! i.e. **RUN THE NODE**. A skip condition is how an author writes *"skip the
//! send node when this is a dry run"*, so a typo in that expression fires the
//! send, the workflow reports `completed`, and the only trace is one WARN
//! line indistinguishable from an expression that legitimately returned
//! false.
//!
//! Demonstrated live on a two-node workflow, both directions:
//!   * `input.should_skip == true` (wrong scope — the binding is bare, not
//!     under `input`) → the node RAN, workflow `completed`, nothing warned.
//!   * `should_skip == true` (correct scope) → the node was SKIPPED.
//!
//! # What this module does and deliberately does NOT do
//!
//! It does NOT flip the default. A skip condition that failed CLOSED would
//! SKIP the node — silently dropping work, which is its own harm — and would
//! change behaviour for every workflow with a valid-but-currently-false
//! condition. The failure is instead made VISIBLE: a labelled counter an
//! operator can alert on, plus a structured log naming the kind, the default
//! that was applied, and its consequence in one line.

use serde_json::Value as JsonValue;

/// What a boolean condition governs. Determines the documented meaning of
/// `false`, and therefore what an evaluation FAILURE silently does.
///
/// The `label()` values are the closed `kind` label set of
/// `talos_condition_eval_failures_total` and live in `talos_metrics` so the
/// pre-seed loop and the increment sites cannot drift apart
/// ([`talos_metrics::CONDITION_EVAL_KINDS`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConditionKind {
    /// A node's `skip_condition`. The ONE fail-open kind.
    Skip,
    /// An edge `condition` gating traversal to a child node.
    Edge,
    /// A `WhileLoop` system node's re-entry condition.
    WhileLoop,
    /// A `Loop` system node's per-iteration condition.
    Loop,
    /// A `FanIn` node's `aggregation_expr`.
    FanIn,
    /// A `Verify` node's assertion.
    Verify,
}

impl ConditionKind {
    /// Prometheus `kind` label. Always a compile-time constant — a
    /// caller-derived label value on a `CounterVec` is unbounded cardinality.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Skip => talos_metrics::CONDITION_EVAL_KIND_SKIP,
            Self::Edge => talos_metrics::CONDITION_EVAL_KIND_EDGE,
            Self::WhileLoop => talos_metrics::CONDITION_EVAL_KIND_WHILE_LOOP,
            Self::Loop => talos_metrics::CONDITION_EVAL_KIND_LOOP,
            Self::FanIn => talos_metrics::CONDITION_EVAL_KIND_FAN_IN,
            Self::Verify => talos_metrics::CONDITION_EVAL_KIND_VERIFY,
        }
    }

    /// `true` when the `false` default is PERMISSIVE — the guarded work
    /// happens anyway.
    ///
    /// Only [`ConditionKind::Skip`] is fail-open today. This is not a
    /// prediction about future kinds: it is the axis an operator triages on,
    /// so it travels on the log line beside the kind.
    pub(crate) const fn fails_open(self) -> bool {
        matches!(self, Self::Skip)
    }

    /// One clause naming what the applied default actually did, for the
    /// operator reading the log line. Never includes user data.
    pub(crate) const fn consequence(self) -> &'static str {
        match self {
            Self::Skip => "defaulted to false — the node was NOT skipped and RAN",
            Self::Edge => {
                "defaulted to false — the edge was not traversed and the child was skipped"
            }
            Self::WhileLoop | Self::Loop => "defaulted to false — the loop stopped iterating",
            Self::FanIn => "defaulted to false — the aggregation was marked failed",
            Self::Verify => "defaulted to false — the verification was marked failed",
        }
    }
}

/// Every variant, for exhaustiveness tests. Keep in sync with the enum; the
/// test below fails if a variant's label is missing from the metrics crate's
/// pre-seed list, which is the drift that would matter.
#[cfg(test)]
pub(crate) const ALL_CONDITION_KINDS: &[ConditionKind] = &[
    ConditionKind::Skip,
    ConditionKind::Edge,
    ConditionKind::WhileLoop,
    ConditionKind::Loop,
    ConditionKind::FanIn,
    ConditionKind::Verify,
];

impl crate::engine::ParallelWorkflowEngine {
    /// Evaluate a boolean condition, returning the evaluation ERROR rather
    /// than folding it into `false`.
    ///
    /// On failure this increments
    /// `talos_condition_eval_failures_total{kind}` and emits a structured
    /// `event_kind = "condition_eval_failed"` WARN naming the kind, whether
    /// the default is fail-open, and what it did. Callers then apply the
    /// default explicitly at their own site — see
    /// [`Self::eval_bool_kinded`], which is what five of the six sites want.
    ///
    /// # Not counted: a missing evaluator
    ///
    /// A bare `ParallelWorkflowEngine::new()` (test harnesses) has no
    /// `ExpressionEvaluator` wired. That is a WIRING misconfiguration, not an
    /// operator-authored expression that failed, so it returns `Ok(false)` —
    /// byte-identical to the historical `eval_bool` fallback — and does NOT
    /// touch the counter. Mixing the two would make the metric un-alertable:
    /// it would move on every test binary and on any code path a future
    /// refactor forgot to wire, drowning the signal it exists to carry.
    pub(crate) fn eval_condition(
        &self,
        kind: ConditionKind,
        expression: &str,
        context: &JsonValue,
    ) -> Result<bool, String> {
        let Some(evaluator) = self.expression_evaluator.as_ref() else {
            // Unchanged from `eval_bool`'s `.unwrap_or(false)`.
            return Ok(false);
        };
        match evaluator.try_eval_bool(expression, context) {
            Ok(result) => {
                tracing::info!(
                    target: "talos_workflow_engine",
                    condition_kind = kind.label(),
                    condition = expression,
                    result,
                    "Rhai condition evaluated"
                );
                Ok(result)
            }
            Err(e) => {
                let error = e.to_string();
                // Direct field mutation at the real site, deliberately NOT
                // behind a `record_*` helper: structural check 58 proves a
                // metric is INCREMENTED by a textual match, so a wrapper
                // reads as live even when nothing calls it. Inlining keeps
                // the proof honest.
                if let Some(m) = talos_metrics::global() {
                    m.condition_eval_failures_total
                        .with_label_values(&[kind.label()])
                        .inc();
                }
                // The condition text is operator-authored and safe to log
                // verbatim. The CONTEXT is upstream-node output — email
                // bodies, LLM output, API responses with PII — so it is
                // scrubbed, matching the DLP contract the `rhai_helpers`
                // warn site established (MCP-536). The `error` string is
                // Rhai's own and names positions and identifiers, not values.
                tracing::warn!(
                    target: "talos_workflow_engine",
                    event_kind = "condition_eval_failed",
                    condition_kind = kind.label(),
                    fail_open = kind.fails_open(),
                    consequence = kind.consequence(),
                    condition = expression,
                    context = %self.redact_json(context),
                    error = %error,
                    "Condition evaluation failed — silent default applied"
                );
                Err(error)
            }
        }
    }

    /// [`Self::eval_condition`] with the kind's documented default applied.
    ///
    /// Behaviourally identical to the historical `eval_bool` — the default is
    /// still `false` for every kind (see the module header for why flipping
    /// the fail-open one would be its own harm). What changed is that the
    /// failure is now counted and named instead of being one anonymous WARN.
    pub(crate) fn eval_bool_kinded(
        &self,
        kind: ConditionKind,
        expression: &str,
        context: &JsonValue,
    ) -> bool {
        self.eval_condition(kind, expression, context)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::ParallelWorkflowEngine;
    use std::collections::HashMap;
    use std::sync::Arc;
    use talos_workflow_engine_test_utils::noop::StubExpressionEvaluator;
    use uuid::Uuid;

    /// Serialises every test below that reads `condition_eval_failures_total`.
    ///
    /// The counter is PROCESS-GLOBAL and `cargo test` runs these in parallel
    /// in one binary, so two tests taking a before/after delta on the same
    /// series interleave and each sees the other's increment.
    ///
    /// **State the lock's actual scope rather than implying more.** A private
    /// mutex cannot serialise a whole test binary — it only serialises code
    /// that takes it. That is sufficient HERE, and only because every
    /// increment of this counter in this binary originates in
    /// `eval_condition`, which needs an `ExpressionEvaluator` whose
    /// `try_eval_bool` returns `Err`, and `StubExpressionEvaluator` does that
    /// only via `with_bool_error` — used nowhere outside this module. A
    /// future test elsewhere in the crate that errors an evaluator WOULD make
    /// these flaky; if you write one, take this lock or assert on a series
    /// your test alone touches.
    static COUNTER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take [`COUNTER_LOCK`], recovering from a poisoned mutex — a panic in
    /// one test must not cascade into "all the others failed too", which
    /// hides which assertion actually broke.
    fn counter_guard() -> std::sync::MutexGuard<'static, ()> {
        COUNTER_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Install the process-global metrics registry if this test binary has
    /// not already, and hand back the counter's CURRENT value for `kind`.
    ///
    /// Deltas, never absolutes: `set_global` is a one-shot `OnceLock`, so a
    /// sibling test may have installed the registry first and the pre-seed
    /// leaves every kind at 0 — but reading a delta keeps these tests correct
    /// regardless of ordering.
    ///
    /// Returned as `u64`: the counter is only ever `.inc()`ed, so its value is
    /// a small exact integer and comparing it as a float would be both
    /// clippy-noisy and misleading about the precision available.
    fn condition_failure_count(kind: ConditionKind) -> u64 {
        if talos_metrics::global().is_none() {
            // Ignore the race: whoever wins, `global()` is Some afterwards.
            let _ = talos_metrics::TalosMetrics::new().map(talos_metrics::set_global);
        }
        talos_metrics::global()
            .expect("global metrics registry installed")
            .condition_eval_failures_total
            .with_label_values(&[kind.label()])
            .get()
            .round() as u64
    }

    /// A single-node engine whose only node carries `__skip_condition`, wired
    /// to `evaluator`. Returns `(engine, node_id, node_idx)`.
    fn engine_with_skip_condition(
        condition: &str,
        evaluator: StubExpressionEvaluator,
    ) -> (ParallelWorkflowEngine, Uuid, petgraph::graph::NodeIndex) {
        let node_id = Uuid::new_v4();
        let mut engine = ParallelWorkflowEngine::new();
        engine.set_expression_evaluator(Arc::new(evaluator));
        engine.add_node(node_id, Some(Uuid::new_v4()), None, None);
        engine.node_configs.insert(
            node_id,
            serde_json::json!({ "__skip_condition": condition }),
        );
        let node_idx = engine.node_map[&node_id];
        (engine, node_id, node_idx)
    }

    /// THE DISTINGUISHING CASE.
    ///
    /// A skip condition that FAILED TO EVALUATE and one that cleanly returned
    /// `false` produce the identical control-flow outcome — the node runs —
    /// and that is deliberate (see the module header on why failing closed
    /// would be its own harm). What must NOT be identical is the evidence.
    /// Before this change the only difference was one WARN line with no kind,
    /// no node and no counter; a fail-open send could not be distinguished
    /// from a gate the author meant to be open.
    #[test]
    fn a_failed_skip_condition_is_distinguishable_from_one_that_returned_false() {
        let _guard = counter_guard();
        let before = condition_failure_count(ConditionKind::Skip);

        // (a) Evaluates cleanly to false: "do not skip" IS the author's
        //     intent. Node runs, and NOTHING is counted.
        let (engine, node_id, node_idx) = engine_with_skip_condition(
            "dry_run == true",
            StubExpressionEvaluator::new().with_bool(false),
        );
        let clean = engine.check_skip_condition(node_idx, node_id, Uuid::new_v4(), &HashMap::new());
        assert!(clean.is_none(), "a false skip condition must not skip");
        assert_eq!(
            condition_failure_count(ConditionKind::Skip),
            before,
            "a condition that evaluated cleanly to false must NOT be counted \
             as a failure — that would drown the fail-open signal in the \
             ordinary case"
        );

        // (b) Fails to evaluate: the node ALSO runs (unchanged behaviour),
        //     but the failure is now counted under its own kind.
        let (engine, node_id, node_idx) = engine_with_skip_condition(
            "input.dry_run == true", // wrong scope: `dry_run` binds bare
            StubExpressionEvaluator::new().with_bool_error("Variable not found: input"),
        );
        let broken =
            engine.check_skip_condition(node_idx, node_id, Uuid::new_v4(), &HashMap::new());
        assert!(
            broken.is_none(),
            "the default is deliberately NOT flipped: a broken skip condition \
             must still RUN the node, not silently drop the work"
        );
        assert_eq!(
            condition_failure_count(ConditionKind::Skip),
            before + 1,
            "a skip condition that could not be evaluated must move \
             talos_condition_eval_failures_total{{kind=\"skip_condition\"}} — \
             it is the only signal that a gated node ran ungated"
        );
    }

    /// A skip condition that evaluates cleanly to `true` still skips, and
    /// still counts nothing. Guards the obvious regression in the other
    /// direction: a change that counted every evaluation would make the
    /// counter useless for alerting.
    #[test]
    fn a_true_skip_condition_skips_and_counts_nothing() {
        let _guard = counter_guard();
        let before = condition_failure_count(ConditionKind::Skip);
        let (engine, node_id, node_idx) = engine_with_skip_condition(
            "dry_run == true",
            StubExpressionEvaluator::new().with_bool(true),
        );
        let out = engine.check_skip_condition(node_idx, node_id, Uuid::new_v4(), &HashMap::new());
        let out = out.expect("a true skip condition must skip the node");
        assert_eq!(out["__skipped"], serde_json::json!(true));
        assert_eq!(out["reason"], serde_json::json!("skip_condition"));
        assert_eq!(condition_failure_count(ConditionKind::Skip), before);
    }

    /// The kind label must reach the counter. A single unlabelled counter
    /// would make a fail-OPEN skip gate indistinguishable from a fail-CLOSED
    /// edge condition, which call for opposite remediations.
    #[test]
    fn each_kind_counts_on_its_own_series() {
        let _guard = counter_guard();
        let skip_before = condition_failure_count(ConditionKind::Skip);
        let edge_before = condition_failure_count(ConditionKind::Edge);

        let mut engine = ParallelWorkflowEngine::new();
        engine.set_expression_evaluator(Arc::new(
            StubExpressionEvaluator::new().with_bool_error("boom"),
        ));
        let ctx = serde_json::json!({});
        assert!(engine
            .eval_condition(ConditionKind::Edge, "x", &ctx)
            .is_err());

        assert_eq!(
            condition_failure_count(ConditionKind::Edge),
            edge_before + 1
        );
        assert_eq!(
            condition_failure_count(ConditionKind::Skip),
            skip_before,
            "an edge-condition failure must not be attributed to the \
             skip-condition series"
        );
    }

    /// A bare engine with no evaluator wired is a WIRING misconfiguration,
    /// not an operator-authored expression that failed. Counting it would
    /// move the series on every test binary and on any path a refactor forgot
    /// to wire, drowning the signal the counter exists to carry.
    #[test]
    fn a_missing_evaluator_returns_false_without_counting() {
        let _guard = counter_guard();
        let before = condition_failure_count(ConditionKind::Edge);
        let engine = ParallelWorkflowEngine::new();
        assert_eq!(
            engine.eval_condition(ConditionKind::Edge, "anything", &serde_json::json!({})),
            Ok(false),
            "unchanged from the historical eval_bool fallback"
        );
        assert_eq!(condition_failure_count(ConditionKind::Edge), before);
    }

    /// The drift that would matter: a new `ConditionKind` whose label is not
    /// in the metrics crate's pre-seed list exports a series that only
    /// appears after its FIRST failure — the absent-is-not-zero trap, on the
    /// exact counter meant to detect a silent fail-open.
    #[test]
    fn every_condition_kind_label_is_preseeded_in_metrics() {
        for kind in ALL_CONDITION_KINDS {
            assert!(
                talos_metrics::CONDITION_EVAL_KINDS.contains(&kind.label()),
                "ConditionKind::{kind:?} label {:?} is missing from \
                 talos_metrics::CONDITION_EVAL_KINDS — its series would be \
                 absent until the first failure",
                kind.label()
            );
        }
    }

    /// The reverse: a seeded label with no producing variant would advertise
    /// a wired signal that does not exist.
    #[test]
    fn every_preseeded_kind_has_a_producing_variant() {
        for seeded in talos_metrics::CONDITION_EVAL_KINDS {
            assert!(
                ALL_CONDITION_KINDS.iter().any(|k| k.label() == *seeded),
                "talos_metrics::CONDITION_EVAL_KINDS seeds {seeded:?} but no \
                 ConditionKind produces it — a series pre-seeded at 0 that \
                 nothing can ever increment"
            );
        }
    }

    #[test]
    fn skip_is_the_only_fail_open_kind() {
        let open: Vec<&str> = ALL_CONDITION_KINDS
            .iter()
            .filter(|k| k.fails_open())
            .map(|k| k.label())
            .collect();
        assert_eq!(
            open,
            vec![talos_metrics::CONDITION_EVAL_KIND_SKIP],
            "the fail-open set changed; if a new kind runs its guarded work \
             on an eval failure, say so here and in the module header"
        );
    }

    #[test]
    fn labels_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        for kind in ALL_CONDITION_KINDS {
            assert!(
                seen.insert(kind.label()),
                "duplicate label {:?} — two kinds sharing one series is the \
                 aggregation collapse this label exists to prevent",
                kind.label()
            );
        }
    }
}
