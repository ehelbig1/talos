//! The worker's local-inference series and the fleet queue:
//!
//! * RFC 0014 P3b: install the fleet-wide queue (`talos_local_inference::fleet`)
//!   against the worker's Redis, with `wasm_llm_fleet_admission_total{outcome}`;
//! * RFC 0014 P4a: count every local exchange cut by a progress deadline, by
//!   which one fired, as `wasm_llm_timeouts_total{kind}`;
//! * RFC 0014 P4b: how many calls were ahead of each arriving call
//!   (`wasm_llm_fleet_queue_ahead`) and how often an admission switched model
//!   (`wasm_llm_fleet_model_switches_total`).
//!
//! The counter is built from the process-global meter rather than held on
//! [`crate::metrics::RuntimeMetrics`]: the queue is installed at boot, before
//! any runtime exists, and outlives every one. With no meter provider
//! configured the instrument is a no-op, like every other worker series.

use std::sync::Arc;

use opentelemetry::{global, KeyValue};
use talos_local_inference::fleet::{FleetEvent, FleetOutcome, FleetSink, QUEUE_AHEAD_BUCKETS};
use talos_local_inference::stream::StallKind;

/// Install the fleet queue for this worker's local backend (`OLLAMA_URL`).
/// Never fatal: every failure leaves calls on the worker's own gate.
pub async fn install(client: redis::Client) {
    talos_local_inference::fleet::install(
        client,
        crate::host::local_llm_backend_url(),
        Some(fleet_sink()),
    )
    .await;
}

/// → `wasm_llm_fleet_admission_total{outcome}`, every outcome pre-seeded at 0
/// (absent is not zero: `increase(...) > 0` over an absent series matches
/// nothing, so "never fell back" and "not installed" would read the same).
///
/// SECURITY: `outcome` is `FleetOutcome::as_str`, a closed compile-time set.
///
/// Deliberately NOT alerted on: `leased` is the queue working, and
/// `unavailable` / `wait_expired` / `lease_lost` degrade to the process gate
/// or to ungated, never to a refusal. There is no baseline yet.
///
/// Plus, RFC 0014 P4b:
/// * `wasm_llm_fleet_queue_ahead` — a histogram of how many calls were ahead
///   of each arriving call (0 = admitted at once). Per ARRIVAL, not sampled,
///   so a herd shorter than any scrape interval is still recorded. Not seeded:
///   a histogram needs no first observation.
/// * `wasm_llm_fleet_model_switches_total` — admissions for a different model
///   than the previous admission to the backend, by any process. No model
///   label (model names are not a closed set). Seeded at 0.
fn fleet_sink() -> Arc<FleetSink> {
    let meter = global::meter("talos-wasm-runtime");
    let counter = meter
        .u64_counter("wasm.llm.fleet_admission")
        .with_description(
            "Local-LLM fleet-wide admission outcomes by outcome \
             (leased | wait_expired | unavailable | lease_lost)",
        )
        .build();
    for outcome in FleetOutcome::ALL {
        counter.add(0, &[KeyValue::new("outcome", outcome.as_str())]);
    }
    let ahead = meter
        .u64_histogram("wasm.llm.fleet_queue_ahead")
        .with_description(
            "Local-LLM calls ahead of each call when it joined the fleet queue \
             (0 = admitted at once)",
        )
        .with_boundaries(QUEUE_AHEAD_BUCKETS.to_vec())
        .build();
    let switches = meter
        .u64_counter("wasm.llm.fleet_model_switches")
        .with_description(
            "Local-LLM admissions for a different model than the previous \
             admission to the same backend, by any process",
        )
        .build();
    switches.add(0, &[]);
    Arc::new(move |event: FleetEvent| match event {
        FleetEvent::Outcome(outcome) => {
            counter.add(1, &[KeyValue::new("outcome", outcome.as_str())]);
        }
        FleetEvent::Arrival { ahead: n } => ahead.record(n, &[]),
        FleetEvent::ModelSwitch => switches.add(1, &[]),
    })
}

/// → `wasm_llm_timeouts_total{kind}`, `kind` ∈ `first_byte | idle | ceiling`,
/// every kind pre-seeded at 0. Counted at the exchange's one deadline site, so
/// a timeout the guest swallows is still counted. Call once at boot,
/// independent of Redis.
///
/// SECURITY: `kind` is `StallKind::as_str`, a closed compile-time set.
///
/// Deliberately NOT alerted on: no baseline yet. This is the series that says
/// whether first-byte, idle or ceiling timeouts happen at all.
pub fn install_timeout_series() {
    let counter = global::meter("talos-wasm-runtime")
        .u64_counter("wasm.llm.timeouts")
        .with_description(
            "Local-LLM exchanges cut by a progress deadline, by kind \
             (first_byte | idle | ceiling)",
        )
        .build();
    for kind in StallKind::ALL {
        counter.add(0, &[KeyValue::new("kind", kind.as_str())]);
    }
    talos_local_inference::stream::set_timeout_sink(Arc::new(move |kind: StallKind| {
        counter.add(1, &[KeyValue::new("kind", kind.as_str())]);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::{get_prometheus_metrics, init_telemetry_for_tests};

    fn value(series_prefix: &str) -> f64 {
        get_prometheus_metrics()
            .lines()
            .find(|l| l.starts_with(series_prefix))
            .and_then(|l| l.rsplit(' ').next()?.parse().ok())
            .unwrap_or(-1.0)
    }

    /// Each fleet event reaches the series it names (RFC 0014 P3b/P4b).
    /// Delta-based: the exporter is process-global.
    #[test]
    fn each_fleet_event_moves_its_series() {
        init_telemetry_for_tests();
        let sink = fleet_sink();
        let switches = value("wasm_llm_fleet_model_switches_total");
        let arrivals = value("wasm_llm_fleet_queue_ahead_count");
        let unavailable = value("wasm_llm_fleet_admission_total{outcome=\"unavailable\"");
        assert!(switches >= 0.0, "switch counter is not seeded");
        assert!(unavailable >= 0.0, "admission outcomes are not seeded");

        sink(FleetEvent::ModelSwitch);
        sink(FleetEvent::Arrival { ahead: 2 });
        sink(FleetEvent::Outcome(FleetOutcome::Unavailable));

        assert_eq!(value("wasm_llm_fleet_model_switches_total"), switches + 1.0);
        assert_eq!(
            value("wasm_llm_fleet_queue_ahead_count"),
            arrivals.max(0.0) + 1.0
        );
        assert_eq!(
            value("wasm_llm_fleet_admission_total{outcome=\"unavailable\""),
            unavailable + 1.0
        );
    }
}
