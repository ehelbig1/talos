//! Controller-side [`ExpressionEvaluator`] impl wrapping [`rhai_helpers`].
//!
//! The trait itself lives in [`talos_workflow_engine_core`]; this adapter
//! delegates every method to the existing thread-local-`rhai::Engine`
//! helpers so there's a single sandbox-configuration site for the
//! controller and no duplicate scope-flattening logic.
//!
//! [`rhai_helpers`]: crate::rhai_helpers

use serde_json::Value as JsonValue;
use talos_workflow_engine_core::{BoxError, ExpressionEvaluator};

use crate::rhai_helpers;

/// Rhai-backed implementation. A unit struct because the underlying
/// engine is a thread-local — no per-instance state to carry.
#[derive(Debug, Default)]
pub struct RhaiEvaluator;

impl RhaiEvaluator {
    /// Build a new evaluator. Cheap (unit struct); the `rhai::Engine`
    /// itself is lazy-initialized per thread on first use.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ExpressionEvaluator for RhaiEvaluator {
    fn eval_bool(&self, expression: &str, context: &JsonValue) -> bool {
        rhai_helpers::evaluate_condition(expression, context)
    }

    fn try_eval_bool(&self, expression: &str, context: &JsonValue) -> Result<bool, BoxError> {
        rhai_helpers::evaluate_condition_with_error(expression, context)
            .map_err(|e| -> BoxError { e.into() })
    }

    fn eval_i64(&self, expression: &str, context: &JsonValue) -> Option<i64> {
        rhai_helpers::evaluate_rhai_to_i64(expression, context)
    }

    fn eval_json(&self, expression: &str, context: &JsonValue) -> Result<JsonValue, BoxError> {
        rhai_helpers::evaluate_expression(expression, context).map_err(|e| -> BoxError { e.into() })
    }
}
