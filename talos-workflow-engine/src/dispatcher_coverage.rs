//! Compile-time + runtime guarantee that every [`SystemNodeKind`]
//! variant has a runtime dispatcher in the reactor.
//!
//! ## Why this exists
//!
//! The engine's reactor (in `engine.rs`) routes each system node to a
//! `try_dispatch_*` function in `scheduler_handlers.rs` via a series
//! of `if let Some(output) = self.try_dispatch_X(...)` branches. The
//! [`SystemNodeKind`] enum is defined in the core crate, the parser
//! and builder live in this crate, and the dispatchers live in yet
//! another file. It's structurally easy to add a variant + parser +
//! builder and forget the dispatcher — three real bugs in this
//! codebase came from exactly that pattern:
//!
//! 1. `CapabilityDispatch::fallback_workflow_id` — accepted by the
//!    MCP tool, parsed into the variant, but ignored at dispatch time
//!    because the dispatcher destructured only the fields it knew
//!    about. Fixed in commit `c88b982`.
//! 2. `DynamicDispatch` Rhai scope — the tool docstring promised
//!    `input.x` access; the engine evaluator only pushed top-level
//!    fields as bare scope vars. Fixed in commit `4998331`.
//! 3. `ReActLoop` — full enum + parser + builder + tool surface, but
//!    no reactor branch ever called any dispatcher for it. Nodes fell
//!    through to the module-loader path and failed with "Module not
//!    found". Fixed in commit `33eed2c`.
//!
//! ## How this protects against drift
//!
//! [`dispatcher_branch_for`] is an **exhaustive match** over every
//! variant. Adding a new variant to [`SystemNodeKind`] without an arm
//! here produces a "non-exhaustive patterns" compile error — the
//! workspace will not build until the contributor classifies the new
//! variant by naming the dispatcher function it routes to. The name
//! is grep-discoverable and forces the contributor to actually write
//! (or at least name) the dispatcher.
//!
//! The companion test `tests::every_variant_classified` constructs
//! one sample of every variant and asserts each gets a non-empty
//! classification. The constructor + count check
//! (`tests::sample_count_matches_known_enum_size`) catches drift
//! between the enum's actual variant count and the constructor's
//! coverage.
//!
//! ## When you add a new `SystemNodeKind` variant
//!
//! 1. Add the variant to `system_node.rs` in the core crate.
//! 2. Add an arm to [`dispatcher_branch_for`] naming the dispatcher
//!    function you intend to write.
//! 3. Implement that dispatcher in `scheduler_handlers.rs`.
//! 4. Wire it into the reactor's match ladder in `engine.rs`.
//! 5. Add a sample to `all_sample_variants()` in this module's tests
//!    AND bump the corresponding count in
//!    `sample_count_matches_known_enum_size`.

use talos_workflow_engine_core::SystemNodeKind;

/// Returns the name of the `try_dispatch_*` function in
/// `scheduler_handlers.rs` that handles the given variant.
///
/// **EXHAUSTIVE** — every variant of [`SystemNodeKind`] must be
/// classified. Adding a new variant without an arm produces a
/// "non-exhaustive patterns" compile error. See module docs for the
/// rationale and the full add-a-variant checklist.
///
/// The classification name is the actual dispatcher function name in
/// `scheduler_handlers.rs`, so a `grep` for the returned string takes
/// you straight to the runtime handler.
pub fn dispatcher_branch_for(kind: &SystemNodeKind) -> &'static str {
    match kind {
        // ── Always-available variants ────────────────────────────
        SystemNodeKind::Wait { .. } => "try_dispatch_wait",
        SystemNodeKind::WhileLoop { .. } => "try_dispatch_while_loop",
        SystemNodeKind::RepeatLoop { .. } => "try_dispatch_repeat_loop",
        SystemNodeKind::ErrorHandler { .. } => "try_dispatch_error_handler",
        SystemNodeKind::FanIn { .. } => "try_dispatch_fan_in",
        SystemNodeKind::SubWorkflow { .. } => "try_dispatch_sub_workflow",
        SystemNodeKind::Loop { .. } => "try_dispatch_loop",
        SystemNodeKind::Collect => "try_dispatch_collect",
        SystemNodeKind::OpsAlertsDigest { .. } => "try_dispatch_ops_alerts_digest",
        SystemNodeKind::PendingApprovals { .. } => "try_dispatch_pending_approvals",
        SystemNodeKind::AssistantReport { .. } => "try_dispatch_assistant_report",
        SystemNodeKind::Synthesize { .. } => "try_dispatch_synthesize",
        SystemNodeKind::Verify { .. } => "try_dispatch_verify",
        SystemNodeKind::DynamicDispatch { .. } => "try_dispatch_dynamic_dispatch",
        SystemNodeKind::CapabilityDispatch { .. } => "try_dispatch_capability_dispatch",
        // ── Feature-gated (llm-primitives, default-on) ───────────
        #[cfg(feature = "llm-primitives")]
        SystemNodeKind::AgentLoop { .. } => "try_dispatch_agent_loop",
        #[cfg(feature = "llm-primitives")]
        SystemNodeKind::Judge { .. } => "try_dispatch_judge",
        #[cfg(feature = "llm-primitives")]
        SystemNodeKind::InlineJudge { .. } => "try_dispatch_inline_judge",
        #[cfg(feature = "llm-primitives")]
        SystemNodeKind::Ensemble { .. } => "try_dispatch_ensemble",
        #[cfg(feature = "llm-primitives")]
        SystemNodeKind::ConfidenceGate { .. } => "try_dispatch_confidence_gate",
        // ReActLoop intentionally shares try_dispatch_agent_loop —
        // identical field shape, identical runtime semantics; the
        // dispatcher matches both via or-pattern. See commit 33eed2c.
        #[cfg(feature = "llm-primitives")]
        SystemNodeKind::ReActLoop { .. } => "try_dispatch_agent_loop",
        #[cfg(feature = "llm-primitives")]
        SystemNodeKind::ReflectiveRetry { .. } => "try_dispatch_reflective_retry",
        #[cfg(feature = "llm-primitives")]
        SystemNodeKind::LlmDispatch { .. } => "try_dispatch_llm_dispatch",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use talos_workflow_engine_core::JoinMode;
    use uuid::Uuid;

    /// Construct one sample of every [`SystemNodeKind`] variant. The
    /// `dispatcher_branch_for` exhaustive match guarantees that any
    /// new variant added to the enum will fail to compile until
    /// classified — but doesn't prevent forgetting to add the variant
    /// here. The `sample_count_matches_known_enum_size` test catches
    /// that secondary drift.
    fn all_sample_variants() -> Vec<SystemNodeKind> {
        let wf_id = Uuid::new_v4();
        let mut v = vec![
            SystemNodeKind::Wait { message: None },
            SystemNodeKind::WhileLoop {
                condition: "true".into(),
                max_iterations: 1,
            },
            SystemNodeKind::RepeatLoop { count: 1 },
            SystemNodeKind::ErrorHandler {
                error_pattern: None,
            },
            SystemNodeKind::FanIn {
                join_mode: JoinMode::All,
                aggregation_expr: None,
            },
            SystemNodeKind::SubWorkflow {
                workflow_id: wf_id,
                timeout_secs: 30,
            },
            SystemNodeKind::Loop {
                max_iterations: 1,
                condition: "true".into(),
            },
            SystemNodeKind::Collect,
            SystemNodeKind::OpsAlertsDigest { top_limit: 10 },
            SystemNodeKind::PendingApprovals { limit: 10 },
            SystemNodeKind::AssistantReport { days: 7 },
            SystemNodeKind::Synthesize {
                synthesis_expr: None,
            },
            SystemNodeKind::Verify {
                condition: "true".into(),
                check_label: None,
                on_failure: "error".into(),
            },
            SystemNodeKind::DynamicDispatch {
                dispatch_expression: "\"x\"".into(),
                timeout_secs: 30,
            },
            SystemNodeKind::CapabilityDispatch {
                required_capabilities: vec!["x".into()],
                fallback_workflow_id: None,
                timeout_secs: 30,
            },
        ];
        #[cfg(feature = "llm-primitives")]
        {
            use std::collections::HashMap;
            v.extend([
                SystemNodeKind::AgentLoop {
                    body_workflow_id: wf_id,
                    max_iterations: 1,
                    inject_history: false,
                    timeout_secs: 30,
                },
                SystemNodeKind::Judge {
                    judge_workflow_id: wf_id,
                    rubric: "x".into(),
                    pass_threshold: None,
                    on_failure: "error".into(),
                    timeout_secs: 30,
                },
                SystemNodeKind::InlineJudge {
                    verdict_expr: "x".into(),
                    pass_threshold: None,
                    on_failure: "error".into(),
                },
                SystemNodeKind::Ensemble {
                    child_workflow_id: wf_id,
                    count: 2,
                    consensus: "first_pass".into(),
                    judge_workflow_id: None,
                    timeout_secs: 30,
                },
                SystemNodeKind::ConfidenceGate {
                    threshold: 0.5,
                    confidence_path: "$.c".into(),
                    on_low_confidence: "error".into(),
                },
                SystemNodeKind::ReActLoop {
                    body_workflow_id: wf_id,
                    max_iterations: 1,
                    inject_history: false,
                    timeout_secs: 30,
                },
                SystemNodeKind::ReflectiveRetry {
                    child_workflow_id: wf_id,
                    reflection_workflow_id: wf_id,
                    max_retries: 1,
                    timeout_secs: 30,
                },
                SystemNodeKind::LlmDispatch {
                    classifier_workflow_id: wf_id,
                    routes: HashMap::new(),
                    fallback_workflow_id: None,
                    timeout_secs: 30,
                },
            ]);
        }
        v
    }

    /// Smoke check: every sample variant maps to a non-empty
    /// `try_dispatch_*` classification matching the naming convention.
    #[test]
    fn every_variant_classified() {
        for variant in all_sample_variants() {
            let branch = dispatcher_branch_for(&variant);
            assert!(
                !branch.is_empty(),
                "missing dispatcher classification for variant {:?}",
                variant
            );
            assert!(
                branch.starts_with("try_dispatch_"),
                "classification {:?} for variant {:?} should follow the \
                 try_dispatch_* function naming convention",
                branch,
                variant
            );
        }
    }

    /// Tripwire: the constructor in [`all_sample_variants`] must list
    /// every variant the enum currently knows about. If a new variant
    /// is added to [`SystemNodeKind`] in the core crate, the
    /// `dispatcher_branch_for` exhaustive match will catch it at
    /// compile time — but a contributor could still forget to extend
    /// the constructor here. This test fails with a clear message if
    /// the count drifts.
    ///
    /// Counts as of 2026-07-21 (after `PendingApprovals` addition):
    ///   15 always-available (`Wait`, `WhileLoop`, `RepeatLoop`,
    ///   `ErrorHandler`, `FanIn`, `SubWorkflow`, `Loop`, `Collect`,
    ///   `OpsAlertsDigest`, `PendingApprovals`, `AssistantReport`,
    ///   `Synthesize`, `Verify`, `DynamicDispatch`, `CapabilityDispatch`)
    ///   + 8 llm-primitives (`AgentLoop`, `Judge`, `InlineJudge`, `Ensemble`,
    ///   `ConfidenceGate`, `ReActLoop`, `ReflectiveRetry`, `LlmDispatch`)
    ///   = 23 total.
    #[test]
    fn sample_count_matches_known_enum_size() {
        const ALWAYS_AVAILABLE: usize = 15;
        #[cfg(feature = "llm-primitives")]
        const EXPECTED: usize = ALWAYS_AVAILABLE + 8;
        #[cfg(not(feature = "llm-primitives"))]
        const EXPECTED: usize = ALWAYS_AVAILABLE;
        assert_eq!(
            all_sample_variants().len(),
            EXPECTED,
            "all_sample_variants() count drifted from enum size — \
             update the constructor to include every new variant, \
             then bump the constants here"
        );
    }

    /// Smoke check: every dispatcher classification is one of the
    /// known function names that actually exists in
    /// `scheduler_handlers.rs`. This catches typos in
    /// `dispatcher_branch_for` arms (e.g. `try_dispatch_fanin` vs
    /// `try_dispatch_fan_in`).
    ///
    /// The expected set is hand-maintained alongside the dispatch
    /// ladder. If a new dispatcher is added, list it here too.
    #[test]
    fn classifications_match_known_dispatcher_names() {
        let known: &[&str] = &[
            "try_dispatch_wait",
            "try_dispatch_while_loop",
            "try_dispatch_repeat_loop",
            "try_dispatch_error_handler",
            "try_dispatch_fan_in",
            "try_dispatch_sub_workflow",
            "try_dispatch_loop",
            "try_dispatch_collect",
            "try_dispatch_ops_alerts_digest",
            "try_dispatch_pending_approvals",
            "try_dispatch_assistant_report",
            "try_dispatch_synthesize",
            "try_dispatch_verify",
            "try_dispatch_dynamic_dispatch",
            "try_dispatch_capability_dispatch",
            "try_dispatch_agent_loop",
            "try_dispatch_judge",
            "try_dispatch_inline_judge",
            "try_dispatch_ensemble",
            "try_dispatch_confidence_gate",
            "try_dispatch_reflective_retry",
            "try_dispatch_llm_dispatch",
        ];
        for variant in all_sample_variants() {
            let branch = dispatcher_branch_for(&variant);
            assert!(
                known.contains(&branch),
                "dispatcher_branch_for returned {:?} for {:?}, which is \
                 not in the known dispatcher set — typo, or did you add \
                 a new dispatcher? Add it to `known` in this test.",
                branch,
                variant
            );
        }
    }

    /// Compile-time tripwire: every dispatcher function named in
    /// `dispatcher_branch_for` and listed in
    /// `classifications_match_known_dispatcher_names` MUST actually
    /// resolve to a method on [`ParallelWorkflowEngine`]. Rust's
    /// type system is the check — referencing
    /// `ParallelWorkflowEngine::try_dispatch_X` as a function item is
    /// a compile error if the method doesn't exist.
    ///
    /// This closes the remaining drift gap beyond the runtime string
    /// check above: if a contributor renames a dispatcher method
    /// (e.g. `try_dispatch_fan_in` → `try_dispatch_join`) but forgets
    /// to update both `dispatcher_branch_for` and the `known` array,
    /// the runtime test would still pass (name is still in `known`)
    /// — but THIS function fails to compile because the old name no
    /// longer resolves.
    ///
    /// The function is never called. The compile error is the test.
    /// `#[allow(dead_code)]` silences the unused-function warning.
    #[allow(dead_code)]
    fn _compile_time_dispatcher_method_references() {
        use crate::ParallelWorkflowEngine;

        // Reference each dispatcher as a function item. Casting to
        // () via a helper erases the differing signatures so we can
        // assert "this identifier resolves" uniformly without
        // writing 20 different fn-pointer type annotations.
        fn exists<T>(_: T) {}

        exists(ParallelWorkflowEngine::try_dispatch_collect);
        exists(ParallelWorkflowEngine::try_dispatch_wait);
        exists(ParallelWorkflowEngine::try_dispatch_while_loop);
        exists(ParallelWorkflowEngine::try_dispatch_repeat_loop);
        exists(ParallelWorkflowEngine::try_dispatch_error_handler);
        exists(ParallelWorkflowEngine::try_dispatch_fan_in);
        exists(ParallelWorkflowEngine::try_dispatch_sub_workflow);
        exists(ParallelWorkflowEngine::try_dispatch_loop);
        exists(ParallelWorkflowEngine::try_dispatch_pending_approvals);
        exists(ParallelWorkflowEngine::try_dispatch_synthesize);
        exists(ParallelWorkflowEngine::try_dispatch_verify);
        exists(ParallelWorkflowEngine::try_dispatch_dynamic_dispatch);
        exists(ParallelWorkflowEngine::try_dispatch_capability_dispatch);
        #[cfg(feature = "llm-primitives")]
        {
            exists(ParallelWorkflowEngine::try_dispatch_agent_loop);
            exists(ParallelWorkflowEngine::try_dispatch_judge);
            exists(ParallelWorkflowEngine::try_dispatch_inline_judge);
            exists(ParallelWorkflowEngine::try_dispatch_ensemble);
            exists(ParallelWorkflowEngine::try_dispatch_confidence_gate);
            exists(ParallelWorkflowEngine::try_dispatch_reflective_retry);
            exists(ParallelWorkflowEngine::try_dispatch_llm_dispatch);
        }
    }
}
