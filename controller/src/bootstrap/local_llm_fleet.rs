//! The controller's local-inference series and the fleet queue:
//!
//! * RFC 0014 P3b: install the fleet-wide queue against the controller's
//!   Redis, recording into `talos_local_llm_fleet_admission_total`;
//! * RFC 0014 P4a: count the controller's local exchanges cut by a progress
//!   deadline into `talos_local_llm_timeouts_total{kind}`;
//! * RFC 0014 P4b: queue depth at arrival and model switches, into
//!   `talos_local_llm_fleet_queue_ahead` and
//!   `talos_local_llm_fleet_model_switches_total`.

use std::sync::Arc;

use talos_local_inference::fleet::{FleetEvent, FleetOutcome};
use talos_local_inference::stream::StallKind;
use talos_metrics::{LocalLlmFleetOutcome, LocalLlmTimeoutKind};

/// Install the queue for the backend the controller's `OllamaClient` calls.
/// Never fatal: every failure leaves the controller on its own gate.
pub(crate) async fn install(client: &redis::Client, ollama_url: &str) {
    talos_local_inference::fleet::install(
        client.clone(),
        ollama_url,
        Some(Arc::new(|event| {
            if let Some(m) = talos_metrics::global() {
                record_fleet_event(m, event);
            }
        })),
    )
    .await;
}

/// Every fleet event into its controller series. Takes the registry so a test
/// can drive it with a fresh one; production passes the global.
fn record_fleet_event(m: &talos_metrics::TalosMetrics, event: FleetEvent) {
    match event {
        FleetEvent::Outcome(outcome) => {
            talos_metrics::record_local_llm_fleet_admission_on(m, metric_outcome(outcome));
        }
        FleetEvent::Arrival { ahead } => talos_metrics::record_local_llm_fleet_arrival_on(m, ahead),
        FleetEvent::ModelSwitch => talos_metrics::record_local_llm_fleet_model_switch_on(m),
    }
}

/// Count local LLM timeouts by kind. Call once at boot, independent of Redis.
pub(crate) fn install_timeout_series() {
    talos_local_inference::stream::set_timeout_sink(Arc::new(|kind| {
        if let Some(m) = talos_metrics::global() {
            talos_metrics::record_local_llm_timeout_on(m, metric_kind(kind));
        }
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

    /// Each fleet event moves the series it names, and only that one.
    #[test]
    fn each_fleet_event_moves_its_series() {
        let m = talos_metrics::TalosMetrics::new().unwrap();
        record_fleet_event(&m, FleetEvent::Outcome(FleetOutcome::Unavailable));
        record_fleet_event(&m, FleetEvent::Arrival { ahead: 3 });
        record_fleet_event(&m, FleetEvent::ModelSwitch);
        let out = m.render_prometheus().expect("render");
        assert!(out.contains("talos_local_llm_fleet_admission_total{outcome=\"unavailable\"} 1"));
        assert!(out.contains("talos_local_llm_fleet_admission_total{outcome=\"leased\"} 0"));
        assert!(out.contains("talos_local_llm_fleet_queue_ahead_count 1"));
        assert!(out.contains("talos_local_llm_fleet_queue_ahead_bucket{le=\"2\"} 0"));
        assert!(out.contains("talos_local_llm_fleet_queue_ahead_bucket{le=\"3\"} 1"));
        assert!(out.contains("talos_local_llm_fleet_model_switches_total 1"));
    }

    /// The two processes' queue-depth histograms share one set of buckets.
    #[test]
    fn the_queue_depth_buckets_match_the_workers() {
        assert_eq!(
            talos_metrics::LOCAL_LLM_QUEUE_AHEAD_BUCKETS,
            talos_local_inference::fleet::QUEUE_AHEAD_BUCKETS
        );
    }

    #[test]
    fn the_timeout_labels_equal_the_stall_kinds() {
        assert_eq!(StallKind::ALL.len(), LocalLlmTimeoutKind::ALL.len());
        for k in StallKind::ALL {
            assert_eq!(metric_kind(k).as_str(), k.as_str());
        }
    }
}
