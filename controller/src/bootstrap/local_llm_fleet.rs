//! The controller's local-inference series and the fleet queue:
//!
//! * RFC 0014 P3b: install the fleet-wide queue against the controller's
//!   Redis, recording into `talos_local_llm_fleet_admission_total`;
//! * RFC 0014 P4a: count the controller's local exchanges cut by a progress
//!   deadline into `talos_local_llm_timeouts_total{kind}`.

use std::sync::Arc;

use talos_local_inference::fleet::FleetOutcome;
use talos_local_inference::stream::StallKind;
use talos_metrics::{LocalLlmFleetOutcome, LocalLlmTimeoutKind};

/// Install the queue for the backend the controller's `OllamaClient` calls.
/// Never fatal: every failure leaves the controller on its own gate.
pub(crate) async fn install(client: &redis::Client, ollama_url: &str) {
    talos_local_inference::fleet::install(
        client.clone(),
        ollama_url,
        Some(Arc::new(|outcome| {
            talos_metrics::record_local_llm_fleet_admission(metric_outcome(outcome));
        })),
    )
    .await;
}

/// Count local LLM timeouts by kind. Call once at boot, independent of Redis.
pub(crate) fn install_timeout_series() {
    talos_local_inference::stream::set_timeout_sink(Arc::new(|kind| {
        talos_metrics::record_local_llm_timeout(metric_kind(kind));
    }));
}

/// Exhaustive, so a new kind fails to compile until it has a series.
fn metric_kind(kind: StallKind) -> LocalLlmTimeoutKind {
    match kind {
        StallKind::FirstByte => LocalLlmTimeoutKind::FirstByte,
        StallKind::Idle => LocalLlmTimeoutKind::Idle,
        StallKind::Ceiling => LocalLlmTimeoutKind::Ceiling,
    }
}

/// Exhaustive, so a new outcome fails to compile until it has a series.
fn metric_outcome(outcome: FleetOutcome) -> LocalLlmFleetOutcome {
    match outcome {
        FleetOutcome::Leased => LocalLlmFleetOutcome::Leased,
        FleetOutcome::WaitExpired => LocalLlmFleetOutcome::WaitExpired,
        FleetOutcome::Unavailable => LocalLlmFleetOutcome::Unavailable,
        FleetOutcome::LeaseLost => LocalLlmFleetOutcome::LeaseLost,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two enums are duplicated across crates (layering); the controller's
    /// series must carry the worker's label strings.
    #[test]
    fn the_metric_labels_equal_the_queue_labels() {
        assert_eq!(FleetOutcome::ALL.len(), LocalLlmFleetOutcome::ALL.len());
        for o in FleetOutcome::ALL {
            assert_eq!(metric_outcome(o).as_str(), o.as_str());
        }
    }

    #[test]
    fn the_timeout_labels_equal_the_stall_kinds() {
        assert_eq!(StallKind::ALL.len(), LocalLlmTimeoutKind::ALL.len());
        for k in StallKind::ALL {
            assert_eq!(metric_kind(k).as_str(), k.as_str());
        }
    }
}
