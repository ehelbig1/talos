//! Controller-side [`RetryClassifier`] impl wrapping
//! [`retry_intelligence`].
//!
//! The trait lives in [`talos_workflow_engine_core`]; this adapter threads
//! the existing Talos heuristic (pattern matching on error-message
//! substrings) behind the abstract interface so the engine is
//! decoupled from the specific classifier module.
//!
//! [`retry_intelligence`]: talos_retry_intelligence

use talos_workflow_engine_core::RetryClassifier;

/// Default Talos classifier — delegates to
/// [`retry_intelligence::classify_error`] and
/// [`retry_intelligence::is_transient_error_type`].
#[derive(Debug, Default)]
pub struct HeuristicRetryClassifier;

impl HeuristicRetryClassifier {
    /// Build a new classifier. Cheap (unit struct); no state.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl RetryClassifier for HeuristicRetryClassifier {
    fn classify(&self, error: &str) -> String {
        talos_retry_intelligence::classify_error(error)
    }

    fn is_transient(&self, class: &str) -> bool {
        talos_retry_intelligence::is_transient_error_type(class)
    }
}
