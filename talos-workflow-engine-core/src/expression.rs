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
//! * **`print` / `debug` output discarded** — the host language's
//!   console builtins must not reach the process's stdout. Expression
//!   scopes are full of upstream-node output (post-interpolation
//!   secrets, email bodies), and stdout is the container log, i.e.
//!   past every DLP boundary the persistence path applies. Discard the
//!   output rather than disabling the call, so an expression that
//!   already contains one keeps evaluating to the same result.
//!
//! **The enforcement of this contract lives in `talos-rhai-sandbox`**
//! (`sandboxed_engine(SandboxProfile::…)`), which is the ONLY sanctioned
//! way to construct an engine that will evaluate an expression. Do NOT
//! hand-roll a config from this list: it was documented here and
//! re-typed at four call sites, which had already drifted apart by
//! 2026-07-29 (two of them missing the print/debug discard entirely, one
//! missing every depth/size cap). Structural lint check 63 now fails on
//! any `rhai::Engine::new()` outside that crate. A reference `rhai`-backed
//! adapter implementing all four evaluation shapes lives in the sibling
//! `talos-workflow-engine` crate.

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
