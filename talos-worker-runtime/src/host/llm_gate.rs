//! The worker's local-LLM gate.
//!
//! The gate itself — its measured queueing curve, why it queues rather than
//! refuses, and what it does NOT bound — lives in `talos_local_inference::gate`
//! since RFC 0014 P3a, where the controller's `OllamaClient` takes it too. This
//! module adds the worker's one difference: a call that QUEUES records its wait
//! on the job's [`InferenceWaitLedger`] (RFC 0014 P2a), so the job's deadlines
//! stand still while it lasts and the controller hears about it.

use std::time::Duration;

#[cfg(test)]
pub(crate) use talos_local_inference::gate::{acquire_reporting_from, Ungated};
pub(crate) use talos_local_inference::gate::{
    LocalLlmSlot, QueueWaitObserver, GATE_OUTCOME_LABELS,
};

use crate::inference_wait::InferenceWaitLedger;

impl QueueWaitObserver for InferenceWaitLedger {
    fn begin_wait(&self) -> impl std::future::Future<Output = ()> + Send {
        InferenceWaitLedger::begin_wait(self)
    }
    fn end_wait(&self) -> impl std::future::Future<Output = ()> + Send {
        InferenceWaitLedger::end_wait(self)
    }
}

/// Take a local-LLM slot on this worker's gate, recording a queued wait on
/// `wait` — the job's ledger. **Call this BEFORE starting the exchange's
/// deadlines**: queue time is not the call's own service time.
pub(crate) async fn acquire_local_llm_slot(
    wait: Option<&InferenceWaitLedger>,
) -> (LocalLlmSlot, Duration) {
    talos_local_inference::gate::acquire_process_slot(wait).await
}

#[cfg(test)]
#[path = "llm_gate_tests.rs"]
mod llm_gate_tests;
