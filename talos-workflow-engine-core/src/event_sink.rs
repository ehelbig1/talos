//! Pluggable fire-and-forget sink for per-node execution events.
//!
//! The executor emits lifecycle events (`node_started`, `node_completed`,
//! `node_failed`, `node_retrying`, `loop_iteration`, etc.) as it runs. An
//! [`EventSink`] is the consumer's hook to persist, forward, or ignore
//! those events — typical impls are a Postgres INSERT, an append-only
//! log, an in-memory capture for tests, or a no-op.
//!
//! # Fire-and-forget is the default
//!
//! The executor typically spawns `emit` calls onto its async runtime
//! so events never block the dispatch loop, and a stuck sink never
//! stalls a job. A small number of ordering-critical sites call
//! `sink.emit(event).await` directly — impls used on that path must
//! be fast and local. The helper that wraps the common spawn pattern
//! lives next to the executor (it depends on a specific async
//! runtime), not in this crate.

use async_trait::async_trait;
use uuid::Uuid;

/// One event written to the execution-events log.
///
/// `event_type` and `status` are free-form strings because backing
/// stores often evolve their taxonomy over time without a matching
/// Rust enum — impls that want validation can do so at emit time.
///
/// Extending this struct is a breaking change for external
/// constructors (typically custom dispatchers emitting events). A
/// [`Default`] impl is provided so callers can use struct-update
/// syntax (`NodeEventWrite { execution_id, event_type, ..Default::default() }`)
/// and remain forward-compatible.
#[derive(Debug, Clone, Default)]
pub struct NodeEventWrite {
    /// Parent workflow execution id.
    pub execution_id: Uuid,
    /// Event category (e.g. `"node_started"`, `"node_completed"`,
    /// `"node_failed"`, `"node_retrying"`, `"loop_iteration"`,
    /// `"node_skipped"`, `"retry_skipped"`, `"node_input"`).
    pub event_type: String,
    /// Node that produced the event, or `None` for workflow-level events.
    pub node_id: Option<Uuid>,
    /// Coarse status (`"Running"`, `"Completed"`, `"Failed"`, `"Skipped"`,
    /// `"Input"`).
    pub status: String,
    /// Optional human-readable detail — an error summary on
    /// `node_failed`, a retry reason on `node_retrying`, etc.
    pub log_message: Option<String>,
    /// Loop iteration counter for events emitted from a repeating body
    /// (`AgentLoop`, `ReActLoop`, `WhileLoop`). `None` for one-shot
    /// events.
    pub iteration_index: Option<i32>,
    /// Stable error-classification tag when the event describes a
    /// classifier decision, `None` otherwise.
    ///
    /// Populated today on `retry_skipped` events with the tag the
    /// [`RetryClassifier`](crate::RetryClassifier) produced (e.g.
    /// `"auth"`, `"invalid_input"`, `"unknown"`) so downstream
    /// analysis tooling can surface *why* an explicit `retry_count`
    /// was short-circuited without string-parsing `log_message`.
    /// Other event types currently leave this `None`; future variants
    /// may populate it consistently with `event_type`.
    pub error_class: Option<String>,
    /// MONOTONIC elapsed milliseconds for the node this event closes,
    /// measured by the emitter with [`std::time::Instant`], or `None`
    /// when the emitter measured nothing.
    ///
    /// Only meaningful on `node_completed` / `node_failed`; every other
    /// event type leaves it `None`.
    ///
    /// # `None` is not zero
    ///
    /// The backing store derives a wall-clock duration
    /// (`this event's timestamp - the matching node_started's`) when
    /// this field is `None`, and labels the result as wall clock. That
    /// derivation is the ONLY value available for emitters that never
    /// started a timer — the synthetic `node_started` + `node_completed`
    /// pairs written after the fact for in-process system nodes, and the
    /// evaluation paths that report an unmeasured `0`. Do NOT bind a
    /// placeholder here to "fill the column": a stored `0` is
    /// indistinguishable from a genuine sub-millisecond duration, of
    /// which this table already holds real examples. Use
    /// [`NodeEventWrite::monotonic_ms`] rather than converting by hand.
    pub duration_ms: Option<i64>,
}

impl NodeEventWrite {
    /// Convert an engine-measured `u64` millisecond count into the
    /// `Option<i64>` this struct's `duration_ms` field expects.
    ///
    /// Two conversions, both load-bearing:
    ///
    /// * **`0` means UNKNOWN, not instantaneous.** That is the documented
    ///   contract of
    ///   [`NodeCompletionContext::wall_time_ms`](crate::NodeCompletionContext),
    ///   whose `0` marks "the engine didn't record a start time". Mapping
    ///   it to `None` hands the row back to the store's wall-clock
    ///   derivation, reproducing the pre-existing behaviour for those
    ///   paths exactly, instead of storing a real-looking `0 ms`.
    /// * **Saturating, not casting.** `u64` values above `i64::MAX` have
    ///   no `i64` representation; a raw `as` cast would wrap to a
    ///   negative duration. Such a value cannot arise from a real
    ///   dispatch, which is precisely why it must not be allowed to
    ///   produce a plausible-looking negative one if it ever does.
    #[must_use]
    pub fn monotonic_ms(elapsed_ms: u64) -> Option<i64> {
        if elapsed_ms == 0 {
            return None;
        }
        Some(i64::try_from(elapsed_ms).unwrap_or(i64::MAX))
    }
}

/// Persist or forward per-node execution events.
///
/// # Emission paths
///
/// The executor calls [`emit`](Self::emit) in two distinct patterns:
///
/// 1. **Fire-and-forget** (the common case): the executor hands the
///    emit to a runtime-specific spawn helper that detaches it into
///    its own task. A slow impl here is harmless; the dispatch loop
///    never waits.
/// 2. **Synchronous** on a handful of ordering-critical sites
///    (`node_completed` / `node_failed`), where the executor awaits
///    `emit` directly before routing to child nodes so observers see a
///    causally consistent timeline. **Impls used on this path MUST be
///    fast and local** — a network round-trip per event will stall the
///    dispatch loop under load.
///
/// # Error handling
///
/// Impls are responsible for their own error handling (logging,
/// dropping, retrying). The method returns `()` rather than `Result`
/// because no caller acts on the outcome — an event-persistence
/// failure is an observability concern, not a workflow concern.
///
/// # Authorization
///
/// Impls do **not** validate that `event.execution_id` belongs to any
/// particular user or tenant; the caller owns authorization. Backing
/// stores with tenant isolation should enforce it at the storage
/// layer (foreign-key scope, row-level security), not at the event
/// write.
#[async_trait]
pub trait EventSink: Send + Sync {
    /// Emit `event`. See the trait-level docs for the two emission
    /// paths and their latency expectations.
    async fn emit(&self, event: NodeEventWrite);
}

#[cfg(test)]
mod tests {
    use super::NodeEventWrite;

    /// THE TRAP THIS CHANGE EXISTS TO AVOID.
    ///
    /// `NodeCompletionContext::wall_time_ms` documents `0` as "the
    /// engine didn't record a start time", explicitly to be read as
    /// unknown "rather than 'instantaneous'". Four engine sites pass a
    /// literal `0` for exactly that reason (system-node rejection
    /// envelopes plus the verify / confidence-gate / dynamic-dispatch
    /// failure branches).
    ///
    /// Binding that sentinel as a value would store a real-looking
    /// `0 ms` — the same defect #707 caught with the pipeline path's
    /// `0` on `module_executions`. It is worse on `execution_events`,
    /// because a genuine `0` is already reachable there: the trigger's
    /// `::bigint` cast truncates sub-millisecond derivations, and 19
    /// such rows existed in the 7-day window when this was written
    /// (measured gaps 0.307–0.490 ms). A sentinel stored as a
    /// measurement would be indistinguishable from those.
    #[test]
    fn zero_wall_time_is_unknown_not_zero() {
        assert_eq!(
            NodeEventWrite::monotonic_ms(0),
            None,
            "a 0 sentinel must fall back to the store's derivation, never \
             be stored as a 0 ms measurement"
        );
    }

    #[test]
    fn a_real_measurement_survives_unchanged() {
        assert_eq!(NodeEventWrite::monotonic_ms(1), Some(1));
        assert_eq!(NodeEventWrite::monotonic_ms(1234), Some(1234));
        // The suspend-inflated worst case #707 found, as monotonic ms.
        assert_eq!(NodeEventWrite::monotonic_ms(105_483), Some(105_483));
    }

    /// Saturating, not casting: `u64::MAX as i64` is `-1`, and a
    /// negative duration would be rendered to a user as a bar of
    /// nonsense width rather than rejected.
    #[test]
    fn an_out_of_range_measurement_saturates_rather_than_wrapping() {
        assert_eq!(NodeEventWrite::monotonic_ms(u64::MAX), Some(i64::MAX));
        let above_i64 = (i64::MAX as u64) + 1;
        assert_eq!(NodeEventWrite::monotonic_ms(above_i64), Some(i64::MAX));
        // The boundary itself is representable and must not saturate.
        assert_eq!(
            NodeEventWrite::monotonic_ms(i64::MAX as u64),
            Some(i64::MAX)
        );
        for v in [0_u64, 1, 42, u64::MAX] {
            if let Some(ms) = NodeEventWrite::monotonic_ms(v) {
                assert!(ms > 0, "a bound duration must never be <= 0, got {ms}");
            }
        }
    }

    /// `Default` must keep the field `None` so struct-update
    /// constructions (`..Default::default()`) never accidentally claim
    /// a measurement.
    #[test]
    fn default_claims_no_measurement() {
        assert_eq!(NodeEventWrite::default().duration_ms, None);
    }
}
