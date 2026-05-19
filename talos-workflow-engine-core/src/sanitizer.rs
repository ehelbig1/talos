//! Pluggable output sanitization before persistence.
//!
//! Module outputs routinely contain secrets that the module picked up
//! from a header (`Authorization: Bearer ...`) or from an API response
//! body. Persisting those verbatim to a workflow-level audit log is a
//! secret-disclosure hazard. The executor runs every stored output
//! through an [`OutputSanitizer`] before writing to the DB; the
//! concrete scrubbing policy (regex allowlist, DLP classifier, token-
//! shape match) is the impl's concern.
//!
//! # Two scrubbing shapes
//!
//! Real-world policies split along two lines:
//!
//! 1. **Stateless scrubs** apply to every output regardless of which
//!    node produced it — patterns like "mask anything that looks like
//!    `sk-...` or `Bearer ey...`". These are the [`redact_str`] and
//!    [`redact_json`] methods on this trait.
//! 2. **Execution-scoped scrubs** learn from node configs at run start
//!    (e.g. if node A declared `{"api_key": "vault://stripe/key"}`,
//!    the resolved value for that execution must never appear in
//!    node B's output). These live on [`ExecutionSanitizer`], built
//!    once per run via [`OutputSanitizer::new_execution`].
//!
//! Both shapes exist because a realistic DLP implementation typically
//! splits this way — stateless pattern-match scrubbing and per-run
//! dynamic redaction are independent concerns. Simpler impls may
//! return a no-op [`ExecutionSanitizer`] from `new_execution`; the
//! trait is designed so a "just use regexes" consumer doesn't have to
//! implement the stateful half meaningfully.
//!
//! [`redact_str`]: OutputSanitizer::redact_str
//! [`redact_json`]: OutputSanitizer::redact_json

use serde_json::Value as JsonValue;

/// Stateless + execution-scoped output scrubbing policy.
pub trait OutputSanitizer: Send + Sync {
    /// Redact secrets from a free-form string — applied to error
    /// messages, module log lines, anything that isn't structured
    /// JSON. Impls typically run regex-based pattern matchers here.
    fn redact_str(&self, s: &str) -> String;

    /// Redact secrets from a structured JSON payload — applied to
    /// node output and aggregated workflow results before persistence.
    /// The returned value SHOULD have the same shape as the input
    /// (same keys, same array lengths) with sensitive string / number
    /// leaves replaced; callers rely on output shape for later
    /// templating.
    fn redact_json(&self, v: &JsonValue) -> JsonValue;

    /// Build an execution-scoped sanitizer from the workflow's
    /// resolved node configs. Called **once per run** at run start;
    /// the returned sanitizer lives for the whole run and is applied
    /// to every node-level error message. `node_configs` is the
    /// slice of `data`/`config` objects from each node in the graph.
    fn new_execution(&self, node_configs: &[JsonValue]) -> Box<dyn ExecutionSanitizer>;
}

/// Per-run sanitizer that carries state derived from the workflow's
/// resolved node configs.
pub trait ExecutionSanitizer: Send + Sync {
    /// Scrub a per-node error message. Typically more aggressive than
    /// [`OutputSanitizer::redact_str`] because it knows the exact
    /// vault paths + config shapes this run touched.
    fn redact_error(&self, s: &str) -> String;

    /// Scrub a per-node output payload. Applied to every stored
    /// node-level output before persistence, **in addition to**
    /// [`OutputSanitizer::redact_json`] — `redact_output` catches
    /// values the execution-scoped pass learned from node configs
    /// (vault refs, resolved secrets), while `redact_json` catches
    /// globally-matching patterns (API key shapes, tokens).
    fn redact_output(&self, v: &JsonValue) -> JsonValue;
}
