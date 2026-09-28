//! The controller's half of RFC 0014 P3b: install the fleet-wide
//! local-inference queue against the controller's Redis, recording into
//! `talos_local_llm_fleet_admission_total`.

use std::sync::Arc;

use talos_local_inference::fleet::FleetOutcome;
use talos_metrics::LocalLlmFleetOutcome;

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
}
