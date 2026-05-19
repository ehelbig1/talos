//! Pluggable expression evaluator for edge conditions + retry-delay
//! expressions + `Synthesize` node output transforms.
//!
//! Impls wrap a scripting engine (the reference implementation uses
//! `rhai`) and expose just the four evaluation shapes the workflow
//! executor needs:
//! a boolean eval (error-as-false and error-as-Err variants), a numeric
//! eval (retry delay), and a free-form JSON eval (synthesis).
//!
//! # Sandboxing contract
//!
//! Expressions on the hot path are operator-authored but workflow-
//! scoped — a malicious or pathological expression must not be able to
//! stall the engine, exhaust memory, or call out to the filesystem /
//! network. Impls MUST enforce at minimum:
//!
//! * An **operation / instruction cap** (the rhai default here is
//!   1 000 ops) to bound evaluation latency.
//! * A **recursion / call-depth cap** (16).
//! * **No dynamic code execution** — `eval`-style primitives in the
//!   host language MUST be disabled so a stored expression cannot
//!   bypass validation by constructing code at runtime.
//! * **No module / import resolver** — expressions cannot pull in
//!   external source or host-provided libraries.
//!
//! A reference `rhai`-backed adapter implementing all four lives in
//! the sibling `talos-workflow-engine` crate.

use serde_json::Value as JsonValue;

use crate::BoxError;

/// Evaluate workflow expressions against a JSON context.
pub trait ExpressionEvaluator: Send + Sync {
    /// Evaluate `expression` as a boolean, returning `false` on any
    /// error (syntax, type mismatch, non-bool result, timeout).
    ///
    /// This "lenient" shape is used at **dispatch-time edge gating**
    /// where an expression that fails to compile should treat the
    /// edge as not-satisfied rather than aborting the whole workflow.
    /// Impls SHOULD log the error at `warn!` level for observability.
    fn eval_bool(&self, expression: &str, context: &JsonValue) -> bool;

    /// Evaluate `expression` as a boolean and propagate errors.
    ///
    /// Used by user-facing tools (e.g. a "test this condition"
    /// MCP handler) that want to display a syntax error rather than
    /// silently returning `false`.
    fn try_eval_bool(&self, expression: &str, context: &JsonValue) -> Result<bool, BoxError>;

    /// Evaluate `expression` as a signed integer (i64). Returns
    /// `None` when the expression fails to evaluate or does not
    /// produce a numeric result.
    ///
    /// Used by retry-delay expressions to compute a dynamic backoff
    /// from error output. Impls SHOULD coerce float results via
    /// truncation-to-i64 so `expr = 2.5 * attempt_num` works.
    fn eval_i64(&self, expression: &str, context: &JsonValue) -> Option<i64>;

    /// Evaluate `expression` and return the result as an arbitrary
    /// `JsonValue`. Used by `Synthesize` nodes to transform collected
    /// parent outputs into a new node-output shape.
    fn eval_json(&self, expression: &str, context: &JsonValue) -> Result<JsonValue, BoxError>;
}
