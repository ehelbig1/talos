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

    fn retry_cap(&self, class: &str) -> Option<u32> {
        talos_retry_intelligence::retry_cap_for(class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 0014 P4a: the production classifier carries the retry cap and the
    /// ceiling reading end to end, from the marked message the worker stamps.
    #[test]
    fn inference_timeouts_reach_the_production_classifier() {
        let c = HeuristicRetryClassifier::new();
        let msg = |token: &str| {
            format!(
                "Component returned error: LLM provider 'ollama' timed out: the host \
                 stopped waiting. [reason_class={token}]"
            )
        };
        let idle = c.classify(&msg("inference-idle-timeout"));
        assert!(c.is_transient(&idle));
        assert_eq!(c.retry_cap(&idle), Some(1));

        let first = c.classify(&msg("inference-first-byte-timeout"));
        assert!(c.is_transient(&first));
        assert_eq!(c.retry_cap(&first), None);

        let ceiling = c.classify(&msg("inference-ceiling-timeout"));
        assert!(!c.is_transient(&ceiling));
    }
}
