//! The worker's half of RFC 0014 P3b: install the fleet-wide local-inference
//! queue (`talos_local_inference::fleet`) against the worker's Redis, with
//! `wasm_llm_fleet_admission_total{outcome}` as its series.
//!
//! The counter is built from the process-global meter rather than held on
//! [`crate::metrics::RuntimeMetrics`]: the queue is installed at boot, before
//! any runtime exists, and outlives every one. With no meter provider
//! configured the instrument is a no-op, like every other worker series.

use std::sync::Arc;

use opentelemetry::{global, KeyValue};
use talos_local_inference::fleet::{FleetOutcome, FleetSink};

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
fn fleet_sink() -> Arc<FleetSink> {
    let counter = global::meter("talos-wasm-runtime")
        .u64_counter("wasm.llm.fleet_admission")
        .with_description(
            "Local-LLM fleet-wide admission outcomes by outcome \
             (leased | wait_expired | unavailable | lease_lost)",
        )
        .build();
    for outcome in FleetOutcome::ALL {
        counter.add(0, &[KeyValue::new("outcome", outcome.as_str())]);
    }
    Arc::new(move |outcome: FleetOutcome| {
        counter.add(1, &[KeyValue::new("outcome", outcome.as_str())]);
    })
}
