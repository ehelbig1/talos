//! Policy impls that do nothing. Use these when a test doesn't care
//! about the trait's output but the engine requires one to be wired.

use std::collections::HashMap;

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use talos_workflow_engine_core::{
    BoxError, ExecutionSanitizer, ExpressionEvaluator, OutputSanitizer, RetryClassifier,
    SecretEnvelope,
};

// ─────────────────────────────────────────────────────────────────────────────
// PassthroughSanitizer
// ─────────────────────────────────────────────────────────────────────────────

/// [`OutputSanitizer`] that returns every input unchanged. Use when
/// the test doesn't care about DLP behavior and wants output + error
/// strings to compare byte-for-byte against expected values.
#[derive(Clone, Debug, Default)]
pub struct PassthroughSanitizer;

impl PassthroughSanitizer {
    /// Build a new passthrough sanitizer.
    pub const fn new() -> Self {
        Self
    }
}

impl OutputSanitizer for PassthroughSanitizer {
    fn redact_str(&self, s: &str) -> String {
        s.to_string()
    }

    fn redact_json(&self, v: &JsonValue) -> JsonValue {
        v.clone()
    }

    fn new_execution(&self, _node_configs: &[JsonValue]) -> Box<dyn ExecutionSanitizer> {
        Box::new(PassthroughExecutionSanitizer)
    }
}

/// Per-run passthrough sanitizer. Returned by
/// [`PassthroughSanitizer::new_execution`].
#[derive(Debug)]
pub struct PassthroughExecutionSanitizer;

impl ExecutionSanitizer for PassthroughExecutionSanitizer {
    fn redact_error(&self, s: &str) -> String {
        s.to_string()
    }

    fn redact_output(&self, v: &JsonValue) -> JsonValue {
        v.clone()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EverythingTransientClassifier / NothingTransientClassifier
// ─────────────────────────────────────────────────────────────────────────────

/// [`RetryClassifier`] that classifies every error as transient. Use
/// when testing retry-on-everything behavior.
#[derive(Clone, Debug, Default)]
pub struct EverythingTransientClassifier;

impl EverythingTransientClassifier {
    /// Build a new instance.
    pub const fn new() -> Self {
        Self
    }
}

impl RetryClassifier for EverythingTransientClassifier {
    fn classify(&self, _error: &str) -> String {
        "test_transient".to_string()
    }

    fn is_transient(&self, _class: &str) -> bool {
        true
    }
}

/// [`RetryClassifier`] that treats every error as permanent. Use when
/// testing the "skip retries" fast path.
#[derive(Clone, Debug, Default)]
pub struct NothingTransientClassifier;

impl NothingTransientClassifier {
    /// Build a new instance.
    pub const fn new() -> Self {
        Self
    }
}

impl RetryClassifier for NothingTransientClassifier {
    fn classify(&self, _error: &str) -> String {
        "test_permanent".to_string()
    }

    fn is_transient(&self, _class: &str) -> bool {
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StubExpressionEvaluator
// ─────────────────────────────────────────────────────────────────────────────

/// [`ExpressionEvaluator`] that returns configured constants for every
/// expression, regardless of input. Use when the engine needs an
/// evaluator but the test has no edge conditions worth exercising.
///
/// Construct with `StubExpressionEvaluator::default()` (all-false /
/// no-retry / empty-json), or the `with_*` builders:
///
/// ```
/// use talos_workflow_engine_test_utils::noop::StubExpressionEvaluator;
///
/// // Make every `eval_bool` return true — useful when testing a code
/// // path behind an `if condition` edge.
/// let eval = StubExpressionEvaluator::new().with_bool(true);
/// ```
#[derive(Clone, Debug)]
#[allow(clippy::struct_field_names)] // the `_value` suffix is intentional
pub struct StubExpressionEvaluator {
    bool_value: bool,
    i64_value: Option<i64>,
    json_value: JsonValue,
}

impl Default for StubExpressionEvaluator {
    fn default() -> Self {
        Self {
            bool_value: false,
            i64_value: None,
            json_value: JsonValue::Null,
        }
    }
}

impl StubExpressionEvaluator {
    /// Build a new evaluator with default return values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the value returned by `eval_bool` / `try_eval_bool`.
    pub fn with_bool(mut self, value: bool) -> Self {
        self.bool_value = value;
        self
    }

    /// Set the value returned by `eval_i64`.
    pub fn with_i64(mut self, value: i64) -> Self {
        self.i64_value = Some(value);
        self
    }

    /// Set the value returned by `eval_json`.
    pub fn with_json(mut self, value: JsonValue) -> Self {
        self.json_value = value;
        self
    }
}

impl ExpressionEvaluator for StubExpressionEvaluator {
    fn eval_bool(&self, _expression: &str, _context: &JsonValue) -> bool {
        self.bool_value
    }

    fn try_eval_bool(&self, _expression: &str, _context: &JsonValue) -> Result<bool, BoxError> {
        Ok(self.bool_value)
    }

    fn eval_i64(&self, _expression: &str, _context: &JsonValue) -> Option<i64> {
        self.i64_value
    }

    fn eval_json(&self, _expression: &str, _context: &JsonValue) -> Result<JsonValue, BoxError> {
        Ok(self.json_value.clone())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NoopSecretEnvelope
// ─────────────────────────────────────────────────────────────────────────────

/// [`SecretEnvelope`] that seals every input to the empty-empty
/// sentinel — returns `(Vec::new(), Vec::new())` on every call.
///
/// The engine's structural validator accepts `(empty, empty)` as the
/// documented "nothing to seal" sentinel and forwards a node's
/// dispatch with no secrets. This impl is therefore useful for
/// **in-process executors** that never cross a trust boundary, for
/// **unit tests** that don't care about secrets plumbing, and for
/// **CI runs** that shouldn't depend on a shared signing key.
///
/// # Not for production use
///
/// `NoopSecretEnvelope` is deliberately safe-by-empty, not safe-by-
/// encryption. If your workers actually need secrets on the wire,
/// this envelope will dispatch nodes with an empty secrets map —
/// those nodes will then fail at secrets-access time. The failure
/// mode is "node cannot find its secrets," not "plaintext secrets
/// on the wire." Do not wire this into a production controller.
///
/// # Example
///
/// ```
/// use std::sync::Arc;
/// use talos_workflow_engine_core::SecretEnvelope;
/// use talos_workflow_engine_test_utils::noop::NoopSecretEnvelope;
///
/// let envelope: Arc<dyn SecretEnvelope> = Arc::new(NoopSecretEnvelope);
/// // Feed into `ParallelWorkflowEngine::set_secret_envelope(envelope)`
/// // for in-process tests / no-secrets workflows.
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopSecretEnvelope;

#[async_trait]
impl SecretEnvelope for NoopSecretEnvelope {
    async fn seal(
        &self,
        _secrets: &HashMap<String, String>,
        _shared_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), BoxError> {
        Ok((Vec::new(), Vec::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_sanitizer_is_identity() {
        let s = PassthroughSanitizer::new();
        assert_eq!(s.redact_str("hello sk-secret"), "hello sk-secret");
        let v = serde_json::json!({ "api_key": "sk-live-xyz" });
        assert_eq!(s.redact_json(&v), v);

        let exec = s.new_execution(&[]);
        assert_eq!(exec.redact_error("boom"), "boom");
        assert_eq!(exec.redact_output(&v), v);
    }

    #[test]
    fn everything_transient_classifier_retries() {
        let c = EverythingTransientClassifier::new();
        let class = c.classify("connection reset");
        assert!(c.is_transient(&class));
    }

    #[test]
    fn nothing_transient_classifier_skips_retries() {
        let c = NothingTransientClassifier::new();
        let class = c.classify("auth failed");
        assert!(!c.is_transient(&class));
    }

    #[test]
    fn stub_expression_evaluator_returns_configured() {
        let eval = StubExpressionEvaluator::new()
            .with_bool(true)
            .with_i64(42)
            .with_json(serde_json::json!({ "k": "v" }));

        assert!(eval.eval_bool("x > 0", &JsonValue::Null));
        assert!(eval.try_eval_bool("x > 0", &JsonValue::Null).unwrap());
        assert_eq!(eval.eval_i64("delay", &JsonValue::Null), Some(42));
        assert_eq!(
            eval.eval_json("anything", &JsonValue::Null).unwrap(),
            serde_json::json!({ "k": "v" })
        );
    }
}
