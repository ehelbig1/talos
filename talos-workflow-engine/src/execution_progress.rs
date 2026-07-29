//! Shared, allocation-light progress snapshot for the reactor loop —
//! the plumbing that lets the wall-clock timeout say *where the time
//! went*.
//!
//! # Why this exists
//!
//! The workflow-level cap in [`crate::engine`] wraps the whole reactor
//! future in `tokio::time::timeout`. When it fires, the timeout site
//! holds only the configured `secs` — the reactor's local state (which
//! nodes were dispatched and never came back) is buried inside a future
//! that just got dropped. The resulting error,
//! `"workflow execution timed out after 180 seconds"`, named nothing.
//!
//! That cost a full diagnostic cycle on every occurrence: the flagship
//! `pa-chief-of-staff` briefing timed out twice in production and the
//! culprit node had to be reconstructed from node-timing archaeology
//! across eleven prior successful runs. The information was *present*
//! in the reactor at the moment of the timeout and simply had nowhere
//! to go.
//!
//! [`ExecutionProgress`] is that somewhere: a cheap `Arc` handle the
//! engine holds as a field. The reactor writes to it at node **start**
//! and node **finish** only; the timeout site (which has `&self` at all
//! four `run_*` entry points) reads it after the deadline fires.
//!
//! # What the snapshot covers
//!
//! * **In-flight set** — nodes handed off to a transport and awaited in
//!   the reactor's `FuturesUnordered` pool: worker-dispatched module
//!   nodes (the flagship's `synthesize` among them) and pipeline chains
//!   (rendered `head+N`). These are the kinds that can hang on
//!   something outside the engine, which is what a wall-clock timeout
//!   is actually about.
//! * **Completed count** — *every* node kind, counted at the two commit
//!   chokepoints (`commit_result!` and `route_system_node_output`) plus
//!   the dispatch-pool completion branch. One caveat worth knowing when
//!   reading the number: a pipeline CHAIN completes as a single unit
//!   (one future, one commit), so an `a→b→c` chain contributes 1, not 3.
//!   The count is "dispatch units completed"; on chain-bearing graphs it
//!   reads low against the node total.
//!
//! System nodes that are `.await`ed inline in the reactor body (judge,
//! ensemble, `sub_workflow`, …) are therefore counted when they finish
//! but do not appear in the in-flight set while running — a timeout
//! parked on one renders `in flight: none tracked`, whose wording names
//! that gap explicitly rather than implying the engine was idle (see
//! [`render_attribution`]). Widening this would
//! mean pairing a start/finish marker across ~20 handler sites, each
//! with its own error/pause branch; a missed pairing would leave a
//! phantom node named in the error forever, which is worse than the
//! honest gap. Deliberate scope, not an oversight.
//!
//! # Cost model
//!
//! * Hot path touches: exactly two per node — one `DashMap::insert` at
//!   dispatch, one `DashMap::remove` + one relaxed `fetch_add` at
//!   completion. Nothing per poll, nothing per loop iteration.
//! * One `String` clone per node start (the label). The dispatch site
//!   next to it already clones an `Arc` dispatcher, builds a JSON
//!   envelope, and allocates three `String`s for the `node_started`
//!   event — this is noise against that.
//! * Sharded `DashMap`, so concurrently-completing nodes do not
//!   serialise on a single mutex.
//!
//! # DLP discipline
//!
//! The rendered attribution carries **node labels and timings only**.
//! Node config values and node output are never read here and must
//! never be added — the string flows into `workflow_executions.
//! error_message`, the operator digest preview, and the failure
//! webhook. Node labels are operator-authored graph identifiers and
//! already appear verbatim in engine error text (see the
//! `node '{label}' failed: …` wrapper in `engine_completion`), so this
//! introduces no new class of content into those channels.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

/// Most in-flight nodes rendered before collapsing the tail into
/// `+N more`.
///
/// Bounds the message length: the operator digest previews
/// `error_message` at 200 chars, so an unbounded fan-out (a 40-way
/// parallel graph that stalls) would push the useful part — the
/// longest-running node — off the end of the preview.
pub(crate) const MAX_RENDERED_IN_FLIGHT: usize = 5;

/// Per-label render cap. Labels are operator-authored and usually
/// short; this only guards against a pathological one.
pub(crate) const MAX_RENDERED_LABEL_CHARS: usize = 64;

/// Cloneable handle to a single run's progress snapshot.
///
/// `Clone` is an `Arc` refcount bump. Default-constructed on
/// [`ParallelWorkflowEngine::new`](crate::ParallelWorkflowEngine::new)
/// and reset at the top of every reactor run, so an engine handle
/// reused across runs never reports a stale predecessor's nodes.
#[derive(Clone, Default)]
pub(crate) struct ExecutionProgress {
    inner: Arc<ProgressInner>,
}

#[derive(Default)]
struct ProgressInner {
    /// Nodes dispatched but not yet completed: `node_id -> (label, started_at)`.
    in_flight: dashmap::DashMap<Uuid, (String, Instant)>,
    /// Count of nodes that reached completion (success or failure).
    completed: AtomicUsize,
}

impl ExecutionProgress {
    /// Clear all state. Called once at the top of the reactor loop so a
    /// reused engine handle starts each run from zero.
    pub(crate) fn reset(&self) {
        self.inner.in_flight.clear();
        self.inner.completed.store(0, Ordering::Relaxed);
    }

    /// Record that `node_id` (rendered as `label`) has been dispatched.
    pub(crate) fn mark_started(&self, node_id: Uuid, label: String) {
        self.inner
            .in_flight
            .insert(node_id, (label, Instant::now()));
    }

    /// Record that `node_id` completed (success or failure alike — the
    /// timeout only cares whether the node is still outstanding).
    ///
    /// Idempotent: a node that was never marked started still bumps the
    /// completed counter, which is the correct accounting for the
    /// locally-computed node kinds (skip / fan-in / collect) that never
    /// enter the in-flight pool.
    pub(crate) fn mark_finished(&self, node_id: Uuid) {
        self.inner.in_flight.remove(&node_id);
        self.inner.completed.fetch_add(1, Ordering::Relaxed);
    }

    /// Render the DLP-safe attribution suffix for a timeout message.
    ///
    /// Returns the empty string when the run produced no observations at
    /// all (nothing started, nothing completed) so the message stays
    /// byte-identical to the pre-attribution format on paths where the
    /// progress handle was never written — a `Default` handle can never
    /// fabricate a claim.
    pub(crate) fn describe(&self) -> String {
        let now = Instant::now();
        let in_flight: Vec<(String, u64)> = self
            .inner
            .in_flight
            .iter()
            .map(|e| {
                let (label, started) = e.value();
                (
                    label.clone(),
                    now.saturating_duration_since(*started).as_millis() as u64,
                )
            })
            .collect();
        render_attribution(in_flight, self.inner.completed.load(Ordering::Relaxed))
    }
}

/// Pure renderer — split out from [`ExecutionProgress::describe`] so the
/// exact message format is unit-testable without a live reactor or a
/// controllable clock.
///
/// Ordering is longest-running first (the node most likely responsible
/// for the timeout leads), tie-broken by label so the output is
/// deterministic regardless of `DashMap` shard iteration order.
pub(crate) fn render_attribution(mut in_flight: Vec<(String, u64)>, completed: usize) -> String {
    if in_flight.is_empty() && completed == 0 {
        return String::new();
    }

    in_flight.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let noun = if completed == 1 { "node" } else { "nodes" };

    if in_flight.is_empty() {
        // Every DISPATCHED node came back, yet the reactor still ran out
        // of wall clock. A bare "in flight: none" would read as "the
        // engine sat idle" — which is exactly the misleading-error class
        // this attribution exists to kill, and it is wrong: the tracked
        // set covers worker-dispatched nodes and pipeline chains only, so
        // an inline-awaited system node (judge / loop / sub-workflow /
        // ensemble / agent-loop) holding the clock lands here. Name the
        // gap instead of implying its absence. See the module header for
        // why the tracked set is scoped the way it is.
        return format!(
            " (in flight: none tracked — an inline system node \
             (judge/loop/sub-workflow) or graph overhead held the clock; \
             {completed} {noun} completed)"
        );
    }

    let overflow = in_flight.len().saturating_sub(MAX_RENDERED_IN_FLIGHT);
    let mut parts: Vec<String> = in_flight
        .iter()
        .take(MAX_RENDERED_IN_FLIGHT)
        .map(|(label, elapsed_ms)| {
            format!("{} {}", truncate_label(label), render_elapsed(*elapsed_ms))
        })
        .collect();
    if overflow > 0 {
        parts.push(format!("+{overflow} more"));
    }
    let rendered = parts.join(", ");

    format!(" (in flight: {rendered}; {completed} {noun} completed)")
}

/// `1234ms` under a second, whole seconds above — matches how the
/// operator reads node timings elsewhere without inventing precision.
fn render_elapsed(elapsed_ms: u64) -> String {
    if elapsed_ms < 1000 {
        format!("{elapsed_ms}ms")
    } else {
        format!("{}s", elapsed_ms / 1000)
    }
}

/// Char-boundary-safe truncation (a byte slice here would panic on a
/// multi-byte label — see the byte-slice UTF-8 panic class).
fn truncate_label(label: &str) -> String {
    if label.chars().count() <= MAX_RENDERED_LABEL_CHARS {
        return label.to_string();
    }
    let head: String = label.chars().take(MAX_RENDERED_LABEL_CHARS).collect();
    format!("{head}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_progress_renders_nothing() {
        // A Default handle that was never written must not append any
        // clause — the message stays byte-identical to the old format.
        assert_eq!(render_attribution(vec![], 0), "");
        assert_eq!(ExecutionProgress::default().describe(), "");
    }

    #[test]
    fn single_in_flight_node_pins_the_message_format() {
        assert_eq!(
            render_attribution(vec![("synthesize".to_string(), 173_000)], 4),
            " (in flight: synthesize 173s; 4 nodes completed)"
        );
    }

    #[test]
    fn multiple_in_flight_sorted_longest_first() {
        let out = render_attribution(
            vec![
                ("fetch".to_string(), 12_000),
                ("synthesize".to_string(), 173_000),
                ("compose".to_string(), 40_000),
            ],
            2,
        );
        assert_eq!(
            out,
            " (in flight: synthesize 173s, compose 40s, fetch 12s; 2 nodes completed)"
        );
    }

    #[test]
    fn equal_elapsed_ties_break_on_label_for_determinism() {
        let out = render_attribution(
            vec![("zeta".to_string(), 5_000), ("alpha".to_string(), 5_000)],
            0,
        );
        assert_eq!(out, " (in flight: alpha 5s, zeta 5s; 0 nodes completed)");
    }

    #[test]
    fn sub_second_elapsed_renders_millis() {
        assert_eq!(
            render_attribution(vec![("quick".to_string(), 250)], 1),
            " (in flight: quick 250ms; 1 node completed)"
        );
    }

    #[test]
    fn nothing_in_flight_names_the_tracking_gap_instead_of_implying_idleness() {
        // The tracked set is worker-dispatched nodes + pipeline chains
        // only, so an inline-awaited system node holding the clock lands
        // in this branch. "in flight: none" alone would tell an operator
        // the engine hung with nothing running — a fresh instance of the
        // misleading-error class this whole feature exists to close.
        let out = render_attribution(vec![], 7);
        assert_eq!(
            out,
            " (in flight: none tracked — an inline system node \
             (judge/loop/sub-workflow) or graph overhead held the clock; \
             7 nodes completed)"
        );
        assert!(out.contains("none tracked"), "{out}");
        assert!(out.contains("7 nodes completed"), "{out}");
    }

    #[test]
    fn the_no_tracked_node_clause_fits_the_digest_preview() {
        // `latest_error_preview` in the operator digest caps at 200 BYTES.
        // This branch's clause is the longest fixed text the attribution
        // can emit, so it must leave room for the base message or the
        // completed-count gets truncated away behind an ellipsis.
        let base = "workflow execution timed out after 420 seconds";
        let full = format!("{base}{}", render_attribution(vec![], 12));
        assert!(
            full.len() <= 200,
            "clause + base is {} bytes, over the 200-byte digest preview: {full}",
            full.len()
        );
    }

    #[test]
    fn in_flight_list_is_capped_with_an_overflow_marker() {
        // Message-length bound: a wide fan-out must not push the
        // longest-running node out of the 200-char digest preview.
        let wide: Vec<(String, u64)> = (0..12)
            .map(|i| (format!("n{i:02}"), (12 - i) as u64 * 1000))
            .collect();
        let out = render_attribution(wide, 3);
        assert_eq!(
            out,
            " (in flight: n00 12s, n01 11s, n02 10s, n03 9s, n04 8s, +7 more; 3 nodes completed)"
        );
        assert!(!out.contains("n05"), "tail must collapse, got: {out}");
    }

    #[test]
    fn long_label_is_truncated_on_a_char_boundary() {
        let label = "é".repeat(MAX_RENDERED_LABEL_CHARS + 20);
        let out = render_attribution(vec![(label, 1_000)], 0);
        assert!(out.contains('…'), "expected ellipsis, got: {out}");
        // Char-count cap, not byte-count — a byte slice would panic here.
        assert!(out.chars().filter(|c| *c == 'é').count() == MAX_RENDERED_LABEL_CHARS);
    }

    #[test]
    fn mark_started_and_finished_track_the_in_flight_set() {
        let p = ExecutionProgress::default();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        p.mark_started(a, "alpha".to_string());
        p.mark_started(b, "beta".to_string());
        p.mark_finished(a);

        let out = p.describe();
        assert!(out.contains("beta"), "beta must still be in flight: {out}");
        assert!(!out.contains("alpha"), "alpha completed: {out}");
        assert!(out.contains("1 node completed"), "{out}");
    }

    #[test]
    fn reset_clears_a_reused_handle() {
        let p = ExecutionProgress::default();
        p.mark_started(Uuid::new_v4(), "stale".to_string());
        p.mark_finished(Uuid::new_v4());
        p.reset();
        assert_eq!(
            p.describe(),
            "",
            "a reset handle must not report the previous run's nodes"
        );
    }

    #[test]
    fn finishing_an_unstarted_node_still_counts_it() {
        // Locally-computed kinds (skip / fan-in / collect) never enter
        // the in-flight pool but do complete.
        let p = ExecutionProgress::default();
        p.mark_finished(Uuid::new_v4());
        let out = p.describe();
        assert!(out.contains("none tracked"), "{out}");
        assert!(out.ends_with("1 node completed)"), "{out}");
    }
}
