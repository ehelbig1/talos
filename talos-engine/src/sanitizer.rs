//! Controller-side [`OutputSanitizer`] impl wrapping the DLP module
//! and `talos_dlp::ExecutionContext`.
//!
//! The trait lives in [`talos_workflow_engine_core`]; this adapter keeps
//! the existing two-layer scrub (stateless regex-based top-level
//! redaction via [`crate::dlp`] + per-run `ExecutionContext` learned
//! from node configs) behind the new abstract interface.

use serde_json::Value as JsonValue;
use talos_workflow_engine_core::{ExecutionSanitizer, OutputSanitizer};

/// DLP-backed sanitizer. Unit struct — the underlying `DlpService`
/// is a process-wide `LazyLock` so there's no per-instance state.
#[derive(Debug, Default)]
pub struct DlpSanitizer;

impl DlpSanitizer {
    /// Build a new sanitizer. Cheap (unit struct); the DLP provider
    /// is lazy-initialized on first redaction call.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl OutputSanitizer for DlpSanitizer {
    fn redact_str(&self, s: &str) -> String {
        talos_dlp_provider::redact_str(s)
    }

    fn redact_json(&self, v: &JsonValue) -> JsonValue {
        talos_dlp_provider::redact_json(v)
    }

    fn new_execution(&self, node_configs: &[JsonValue]) -> Box<dyn ExecutionSanitizer> {
        Box::new(DlpExecutionSanitizer {
            inner: talos_dlp::ExecutionContext::from_node_configs(node_configs.iter()),
        })
    }
}

/// Per-run sanitizer — wraps `talos_dlp::ExecutionContext` so its
/// learned-from-configs rules are applied to every node-level error
/// message within a single workflow execution.
pub struct DlpExecutionSanitizer {
    inner: talos_dlp::ExecutionContext,
}

impl std::fmt::Debug for DlpExecutionSanitizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `ExecutionContext` holds regex patterns derived from resolved
        // secret values — `Debug`ing them would be a secret leak. Don't.
        f.debug_struct("DlpExecutionSanitizer")
            .field("inner", &"<redacted>")
            .finish()
    }
}

impl ExecutionSanitizer for DlpExecutionSanitizer {
    fn redact_error(&self, s: &str) -> String {
        self.inner.redact_error(s)
    }

    fn redact_output(&self, v: &JsonValue) -> JsonValue {
        self.inner.redact_output(v)
    }
}
