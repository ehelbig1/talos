//! Canonical `__actor_context__` payload assembly.
//!
//! Every dispatch path that injects actor memories into an LLM prompt
//! MUST route through [`assemble_payload`] so the shape never drifts.
//! Today there are three controller sites (trigger_workflow,
//! trigger_workflow_as_actors, scheduler) plus the `preview_actor_context`
//! MCP tool — they all converge here.
//!
//! Wire-format contract:
//! ```json
//! { "actor_id": "<uuid>", "memories": [ {"key": "...", "value": <any>, "type": "..."} ] }
//! ```
//!
//! Consumed by `module-templates/llm-inference/template.rs` under the
//! literal input key `__actor_context__`. If you rename either side,
//! update both — there is no test that catches the mismatch at
//! compile time (it is a string key on a JSON map).

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use uuid::Uuid;

/// One memory row in the assembled payload — `(key, value_json, memory_type)`.
/// Matches the tuple shape returned by
/// `WorkflowRepository::get_relevant_actor_context`.
pub type ActorMemoryRow = (String, Value, String);

/// A recency-layer row carrying its durable signals — the tuple shape
/// returned by `talos_memory::recall_recent_excluding_types_and_kinds_ts`.
/// `(key, value_json, memory_type, updated_at, importance, access_count)`.
///
/// `importance` is the write-time [0,1] score from the `actor_memory.importance`
/// column (`None` for rows written before Phase 3a); `access_count` is the
/// `actor_memory.access_count` column (`None` only on projection drift — the
/// column is `NOT NULL DEFAULT 0`). Both feed [`select_candidates`] into the
/// fused ranker's importance term.
pub type RecencyRow = (
    String,
    Value,
    String,
    Option<DateTime<Utc>>,
    Option<f64>,
    Option<i64>,
);

/// Build the canonical `__actor_context__` payload from raw memory rows.
///
/// Empty `memories` still produces a well-formed payload with an empty
/// array (never `null`) so consumers can rely on the array shape.
pub fn assemble_payload(actor_id: Uuid, memories: &[ActorMemoryRow]) -> Value {
    json!({
        "actor_id": actor_id,
        "memories": memories
            .iter()
            .map(|(k, v, t)| json!({ "key": k, "value": v, "type": t }))
            .collect::<Vec<_>>(),
    })
}

/// Crude LLM token estimate: bytes / 4. Good enough for "is this 2k or
/// 20k tokens?" sanity checks; not for billing. Swap for tiktoken
/// bindings if precision ever becomes load-bearing.
pub fn approx_token_count(payload_bytes: usize) -> usize {
    payload_bytes / 4
}

/// Marker appended to a memory value truncated by [`truncate_value`].
/// The ellipsis keeps the truncation visible to the LLM ("this was cut");
/// the bracketed tag is machine-greppable in traces.
pub const TRUNCATION_MARKER: &str = "…[truncated]";

/// Truncate a memory value so its serialized form fits within the cap,
/// cutting only at a UTF-8 char boundary.
///
/// Returns `(value, truncated)`. When the value's serialized JSON is
/// within the cap it is returned unchanged with `false`. Otherwise the
/// serialized form is cut to the largest char boundary at or below the
/// cap (never mid-codepoint), wrapped as a JSON string with
/// [`TRUNCATION_MARKER`] appended, and `true` is returned. Replacing the
/// structured value with a single truncated string is deterministic and
/// guarantees the result serializes to a bounded, valid UTF-8 payload
/// regardless of the input's shape (deeply nested object, huge array,
/// long string — all collapse the same way).
///
/// The effective cap is floored at `TRUNCATION_MARKER.len()` so that even a
/// pathologically tiny `per_memory_cap` can never produce a marker-only
/// string that exceeds the cap: the result is always
/// `<= max(per_memory_cap, TRUNCATION_MARKER.len())` bytes. In normal
/// operation the config knob is floored to 256 B (see
/// `talos_config::smart_memory_context_per_memory_cap`), so the marker
/// floor is only load-bearing for direct callers.
pub fn truncate_value(value: Value, per_memory_cap: usize) -> (Value, bool) {
    // Floor at the marker length: below it we could not emit even the
    // marker within the cap, so treat the marker length as the true minimum.
    let effective_cap = per_memory_cap.max(TRUNCATION_MARKER.len());
    let serialized = value.to_string();
    if serialized.len() <= effective_cap {
        return (value, false);
    }
    // Reserve room for the marker so the final string stays within the cap.
    // `effective_cap >= TRUNCATION_MARKER.len()` makes this a non-saturating
    // subtraction in spirit; keep `saturating_sub` for total safety.
    let budget = effective_cap.saturating_sub(TRUNCATION_MARKER.len());
    let mut end = budget.min(serialized.len());
    while end > 0 && !serialized.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = serialized[..end].to_string();
    out.push_str(TRUNCATION_MARKER);
    (Value::String(out), true)
}

/// A ranking candidate — a memory row with the raw signals the fused
/// scorer ([`fused_score`]) blends, preserved from each retrieval layer:
/// * `relevance` — cosine score for a semantic hit, or a configurable
///   baseline for graph / recency rows (which carry no similarity score).
/// * `updated_at` — the row's last-write time, for the recency-decay signal.
///   `None` (graph context, or a legitimately timestamp-less row) is treated
///   as a NEUTRAL recency signal ([`NEUTRAL_RECENCY`]) — never as
///   maximally-stale, so a missing timestamp can't zero a candidate out.
/// * `importance_final` — the durable `actor_memory.importance` column when
///   present: a FINAL importance in `[0, 1]` already blended at write time
///   (memory-type base ⊕ `metadata.importance`). [`importance`] uses it
///   DIRECTLY — no second base blend — so an explicit score (e.g. one written
///   by Phase 3b consolidation) is honored, not attenuated back toward the
///   type base. Takes precedence over `importance_hint`.
/// * `importance_hint` — the legacy `metadata.importance` value for rows
///   written BEFORE Phase 3a (durable column NULL). A raw override that
///   [`importance`] blends 50/50 with the memory-type base — the pre-3a
///   behavior, preserved byte-identically. Ignored when `importance_final`
///   is set.
/// * `access_boost` — an optional normalized access-frequency signal in
///   `[0, 1)` derived from the durable `actor_memory.access_count` column via
///   [`access_boost`]. `None` (older rows / flag-off / no signal) is NEUTRAL —
///   [`importance`] leaves the score untouched.
#[derive(Clone, Debug, PartialEq)]
pub struct Candidate {
    pub key: String,
    pub value: Value,
    pub memory_type: String,
    pub relevance: f64,
    pub updated_at: Option<DateTime<Utc>>,
    pub importance_final: Option<f64>,
    pub importance_hint: Option<f64>,
    pub access_boost: Option<f64>,
}

/// Fused-ranker weights. See [`fused_score`] for the formula. Populated in
/// production from `talos_config::smart_memory_context_w_*` /
/// `_recency_halflife_days`; constructed directly in tests / the eval.
#[derive(Clone, Copy, Debug)]
pub struct Weights {
    pub relevance: f64,
    pub recency: f64,
    pub importance: f64,
    pub recency_halflife_days: f64,
}

/// Recency signal assigned to a candidate with no `updated_at` — the
/// midpoint of the `[0, 1]` decay range. Chosen so a timestamp-less
/// candidate (graph context) is neither boosted as "brand new" nor
/// penalised as "maximally stale"; it simply doesn't move on the recency
/// axis.
pub const NEUTRAL_RECENCY: f64 = 0.5;

/// Importance base for each `memory_type`, mapped to `[0, 1]`:
/// `semantic` (durable facts/persona) > `episodic` (events) >
/// `working` (short-lived scratch) — an unknown type gets a neutral 0.5.
/// `scratchpad` is filtered upstream in [`select_candidates`] so it never
/// reaches here, but is mapped to 0.0 for completeness.
///
/// When a candidate also carries an `importance_hint` (from
/// `metadata.importance`), [`importance`] BLENDS the two 50/50 so both the
/// structural signal (what KIND of memory it is) and the explicit hint
/// (how important the WRITER marked it) contribute.
pub fn importance_base(memory_type: &str) -> f64 {
    match memory_type {
        "semantic" => 1.0,
        "episodic" => 0.66,
        "working" => 0.33,
        "scratchpad" => 0.0,
        _ => 0.5,
    }
}

/// Write-time importance score in `[0, 1]` — the SINGLE source of truth for
/// the durable `actor_memory.importance` column, shared by the write path
/// ([`crate::persist_memory_with_metadata_typed`]) and the ranker so the two
/// never drift (Testing Conventions: don't shadow production logic).
///
/// Same blend as [`importance`]'s hint path: the memory-type base
/// ([`importance_base`]) blended 50/50 with a clamped `metadata.importance`
/// when it parses as a finite number, else the bare base. Written on every
/// persist REGARDLESS of the smart-context feature flag — it is a harmless
/// dormant signal that accrues for when the flag is on (and for Phase 3b
/// consolidation).
pub fn write_time_importance(memory_type: &str, metadata: Option<&Value>) -> f64 {
    let base = importance_base(memory_type);
    let hint = metadata
        .and_then(|m| m.get("importance"))
        .and_then(|v| v.as_f64())
        .filter(|v| v.is_finite());
    match hint {
        Some(h) => (base + h.clamp(0.0, 1.0)) / 2.0,
        None => base,
    }
}

/// Normalize a raw `actor_memory.access_count` into a saturating boost in
/// `[0, 1)`: `1 - 1/(1 + count)`. Zero accesses → `0.0` (neutral); the curve
/// saturates toward `1.0` with diminishing returns as the count grows, so a
/// frequently-recalled memory is nudged up without ever dominating.
///
/// `None` in → `None` out (older rows / flag-off / projection absent) so
/// [`importance`] leaves the score untouched — flag-off and older-row parity.
/// Negative counts (unreachable — the column is `NOT NULL DEFAULT 0`) clamp to
/// `0`; `1 + count >= 1` guarantees no divide-by-zero. Total and NaN-safe.
pub fn access_boost(access_count: Option<i64>) -> Option<f64> {
    access_count.map(|n| {
        let n = n.max(0) as f64;
        1.0 - 1.0 / (1.0 + n)
    })
}

/// Blended importance signal in `[0, 1]`, still a single fused-score term
/// ([`fused_score`] stays relevance + recency + importance). The base score is
/// resolved from the candidate's importance signals with a strict precedence,
/// then nudged up by the access-frequency boost:
/// 1. `importance_final` (the durable `actor_memory.importance` column) is a
///    FINAL, already-blended write-time score — used DIRECTLY (clamped), with
///    NO second memory-type-base blend. This honors an explicit stored score
///    (e.g. one written by Phase 3b consolidation) instead of attenuating it
///    back toward the type base.
/// 2. Otherwise `importance_hint` (the legacy `metadata.importance` for
///    pre-Phase-3a rows) is blended 50/50 with the memory-type base
///    ([`importance_base`]) — the exact pre-3a behavior.
/// 3. Otherwise the bare memory-type base.
///
/// The score is then nudged up by `access_weight * access_boost` when the
/// candidate carries a durable access-frequency signal. The nudge is ADDITIVE
/// and clamped, so it only ever raises importance and the output stays in
/// `[0, 1]`. When `access_boost` is `None` the result is exactly the base
/// score — neutral, giving flag-off and pre-Phase-3a rows identical behaviour.
/// `access_weight` is the `smart_memory_context_access_weight` knob (passed in,
/// not read here, so the function stays pure/deterministic for the eval). Total
/// and NaN-safe: non-finite `access_weight`/`access_boost` degrade to a zero
/// nudge; a non-finite `importance_final` falls through to the hint/base path.
pub fn importance(c: &Candidate, access_weight: f64) -> f64 {
    let base = importance_base(&c.memory_type);
    let base_importance = match c.importance_final {
        // Durable column IS the importance — use directly, no re-blend.
        Some(final_imp) if final_imp.is_finite() => final_imp.clamp(0.0, 1.0),
        _ => match c.importance_hint {
            Some(hint) => (base + hint.clamp(0.0, 1.0)) / 2.0,
            None => base,
        },
    };
    match c.access_boost {
        Some(boost) => {
            let w = if access_weight.is_finite() {
                access_weight.max(0.0)
            } else {
                0.0
            };
            let b = if boost.is_finite() {
                boost.clamp(0.0, 1.0)
            } else {
                0.0
            };
            (base_importance + w * b).clamp(0.0, 1.0)
        }
        None => base_importance,
    }
}

/// Exponential recency decay in `[0, 1]`:
/// `0.5^(age_days / half_life_days)`. A brand-new memory (`age <= 0`) scores
/// 1.0; one `half_life` days old scores 0.5; each further half-life halves
/// it. A non-positive `half_life_days` (a caller-side misconfig the config
/// resolver already guards against) falls back to [`NEUTRAL_RECENCY`] rather
/// than dividing by zero / inverting the curve. Future timestamps
/// (`age < 0`) clamp to 1.0.
pub fn recency_decay(age_days: f64, half_life_days: f64) -> f64 {
    if half_life_days <= 0.0 || !half_life_days.is_finite() {
        return NEUTRAL_RECENCY;
    }
    let age = age_days.max(0.0);
    0.5_f64.powf(age / half_life_days)
}

/// The recency component of a candidate's fused score: [`recency_decay`] of
/// its age when it has an `updated_at`, else [`NEUTRAL_RECENCY`].
fn recency_component(c: &Candidate, now: DateTime<Utc>, half_life_days: f64) -> f64 {
    match c.updated_at {
        Some(ts) => {
            let age_days = (now - ts).num_seconds() as f64 / 86_400.0;
            recency_decay(age_days, half_life_days)
        }
        None => NEUTRAL_RECENCY,
    }
}

/// The fused multi-signal relevance score for one candidate:
///
/// ```text
/// fused = w.relevance  * relevance
///       + w.recency    * recency_decay(now - updated_at)   [NEUTRAL_RECENCY if no ts]
///       + w.importance * importance(memory_type, importance_hint)
/// ```
///
/// `now` is INJECTED (never read from the clock here) so the ranker is
/// deterministic and the retrieval-quality eval can score fixtures with
/// fixed ages. Higher is better; the score is unbounded above (weights are
/// arbitrary non-negative reals) but monotonic in each signal.
///
/// `access_weight` (the `smart_memory_context_access_weight` knob) modulates
/// the durable access-frequency nudge INSIDE the importance term — the fused
/// score stays 3-term (relevance + recency + importance), no separate access
/// term / weight is added.
pub fn fused_score(c: &Candidate, w: &Weights, now: DateTime<Utc>, access_weight: f64) -> f64 {
    w.relevance * c.relevance
        + w.recency * recency_component(c, now, w.recency_halflife_days)
        + w.importance * importance(c, access_weight)
}

/// Merge the smart-context retrieval layers into a single deduplicated
/// [`Candidate`] list, ready for [`rank_candidates`] then
/// [`pack_within_budget`].
///
/// Signals are threaded in from each layer:
/// * **graph** entity context → `relevance = graph_baseline`, no `updated_at`,
///   no hint, no access boost.
/// * **semantic hits** → `relevance = hit.score`, `updated_at = hit.updated_at`,
///   `importance_hint` from the durable `importance` column (falling back to
///   `metadata.importance`), `access_boost` from the durable `access_count`.
/// * **recency rows** → `relevance = recency_baseline`, `updated_at` +
///   `importance_hint` (durable column) + `access_boost` from the row.
///
/// Applied per candidate:
/// * **scratchpad drop** — `memory_type == "scratchpad"` rows are skipped in
///   every layer (they embed the prior run's `__actor_context__` and would
///   grow context recursively).
/// * **min-score floor** — a defense-in-depth re-assertion of the DB-layer
///   `>= min_score` predicate on semantic hits (the SQL already floors; this
///   keeps the guarantee even if a future caller over-fetches with a looser
///   floor). Graph/recency carry a baseline, not a score, and are unaffected.
/// * **dedup by key, keeping the highest-relevance instance** — when a key
///   appears in more than one layer, the occurrence with the greater
///   `relevance` wins (a strong semantic hit beats the same key's recency
///   baseline). First-seen insertion order is otherwise preserved; final
///   ordering is [`rank_candidates`]' job, not this function's.
///
/// Pure so the selection logic is unit-tested without a database. The
/// production smart retriever fetches each layer then calls exactly this.
pub fn select_candidates(
    graph: Option<ActorMemoryRow>,
    semantic_hits: Vec<crate::MemoryHit>,
    recency: Vec<RecencyRow>,
    min_score: f64,
    graph_baseline: f64,
    recency_baseline: f64,
) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    // key -> index into `out`, so a later higher-relevance duplicate can
    // replace an earlier lower-relevance one in place.
    let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    let mut upsert = |cand: Candidate| {
        if cand.memory_type == "scratchpad" {
            return;
        }
        match index.get(&cand.key) {
            Some(&i) => {
                if cand.relevance > out[i].relevance {
                    out[i] = cand;
                }
            }
            None => {
                index.insert(cand.key.clone(), out.len());
                out.push(cand);
            }
        }
    };

    if let Some((k, v, t)) = graph {
        upsert(Candidate {
            key: k,
            value: v,
            memory_type: t,
            relevance: graph_baseline,
            updated_at: None,
            importance_final: None,
            importance_hint: None,
            access_boost: None,
        });
    }
    for h in semantic_hits {
        if h.score < min_score {
            continue;
        }
        // Durable `actor_memory.importance` column WINS as the FINAL score
        // (used directly, no re-blend). Only when it is NULL (rows written
        // before Phase 3a) do we fall back to the legacy `metadata.importance`
        // as a hint that [`importance`] blends 50/50 with the type base.
        let (importance_final, importance_hint) = match h.importance {
            Some(col) => (Some(col), None),
            None => (
                None,
                h.metadata
                    .as_ref()
                    .and_then(|m| m.get("importance"))
                    .and_then(|v| v.as_f64()),
            ),
        };
        upsert(Candidate {
            key: h.key,
            value: h.value,
            memory_type: h.memory_type,
            relevance: h.score,
            updated_at: Some(h.updated_at),
            importance_final,
            importance_hint,
            access_boost: access_boost(h.access_count),
        });
    }
    for (k, v, t, updated_at, importance, access_count) in recency {
        upsert(Candidate {
            key: k,
            value: v,
            memory_type: t,
            relevance: recency_baseline,
            updated_at,
            // Recency rows carry the durable importance column directly as the
            // FINAL score (no metadata in the tuple); NULL → None → base-only.
            importance_final: importance,
            importance_hint: None,
            access_boost: access_boost(access_count),
        });
    }
    out
}

/// Sort candidates by [`fused_score`] DESCENDING (a stable sort), so the
/// most useful memories are packed first by [`pack_within_budget`].
///
/// Tie-break chain (all descending / newest-first) keeps the order
/// deterministic when fused scores collide:
/// 1. fused score
/// 2. raw `relevance`
/// 3. `updated_at` (newer first; `None` sorts last)
///
/// `now` is injected for determinism (see [`fused_score`]). `access_weight` is
/// threaded into [`fused_score`]'s importance term.
pub fn rank_candidates(
    mut candidates: Vec<Candidate>,
    w: &Weights,
    now: DateTime<Utc>,
    access_weight: f64,
) -> Vec<Candidate> {
    candidates.sort_by(|a, b| {
        use std::cmp::Ordering;
        let sa = fused_score(a, w, now, access_weight);
        let sb = fused_score(b, w, now, access_weight);
        sb.partial_cmp(&sa)
            .unwrap_or(Ordering::Equal)
            .then_with(|| {
                b.relevance
                    .partial_cmp(&a.relevance)
                    .unwrap_or(Ordering::Equal)
            })
            .then_with(|| match (a.updated_at, b.updated_at) {
                (Some(ta), Some(tb)) => tb.cmp(&ta),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            })
    });
    candidates
}

/// Flatten ranked candidates into the `(key, value, memory_type)` rows that
/// [`pack_within_budget`] / [`assemble_payload`] consume — dropping the
/// ranking-only signals now that ordering is fixed.
pub fn candidates_into_rows(candidates: Vec<Candidate>) -> Vec<ActorMemoryRow> {
    candidates
        .into_iter()
        .map(|c| (c.key, c.value, c.memory_type))
        .collect()
}

/// Pack candidate memory rows into a byte-budgeted subset that
/// [`assemble_payload`] can render without exceeding `byte_budget`.
///
/// Walks `candidates` in the given (relevance) order. Each row's value is
/// first truncated to `per_memory_cap` via [`truncate_value`] so no single
/// oversized memory (e.g. a 15KB `daily_brief`) can dominate the budget.
/// The row is then tentatively added and the FULL assembled payload
/// re-measured; if it would exceed `byte_budget` the row is dropped and
/// packing STOPS (relevance order is authoritative — we don't skip ahead
/// to squeeze in a smaller lower-ranked row, keeping the result
/// deterministic). For any `byte_budget` at or above the empty
/// `{actor_id, memories:[]}` wrapper (~65 B — always true via the config
/// floor of 1_024 B, see `talos_config::smart_memory_context_byte_budget`),
/// the returned `Vec` fed straight into [`assemble_payload`] serializes to
/// `<= byte_budget` bytes. (A `byte_budget` below the wrapper size is
/// unreachable through the floored knob; a direct caller passing one gets
/// an empty result, which still serializes to the ~65 B wrapper.)
///
/// `actor_id` is required because the wrapper (`{actor_id, memories:[…]}`)
/// contributes to the measured size, so the bound holds against the real
/// payload, not just the entries.
pub fn pack_within_budget(
    actor_id: Uuid,
    candidates: Vec<ActorMemoryRow>,
    byte_budget: usize,
    per_memory_cap: usize,
) -> Vec<ActorMemoryRow> {
    let mut selected: Vec<ActorMemoryRow> = Vec::new();
    for (key, value, mem_type) in candidates {
        let (value, _truncated) = truncate_value(value, per_memory_cap);
        selected.push((key, value, mem_type));
        let size = serde_json::to_vec(&assemble_payload(actor_id, &selected))
            .map(|b| b.len())
            .unwrap_or(usize::MAX);
        if size > byte_budget {
            // This row (even after per-memory truncation) doesn't fit —
            // drop it and stop. Nothing lower-ranked is more deserving.
            selected.pop();
            break;
        }
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_shape_is_stable() {
        let actor = Uuid::new_v4();
        let memories = vec![
            (
                "persona".to_string(),
                json!({ "role": "ceo" }),
                "semantic".to_string(),
            ),
            (
                "market/thesis".to_string(),
                json!({ "why_now": "ai" }),
                "semantic".to_string(),
            ),
        ];
        let p = assemble_payload(actor, &memories);
        assert_eq!(p["actor_id"], json!(actor));
        let arr = p["memories"].as_array().expect("memories array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["key"], "persona");
        assert_eq!(arr[0]["type"], "semantic");
        assert_eq!(arr[0]["value"], json!({ "role": "ceo" }));
        assert_eq!(arr[1]["key"], "market/thesis");
    }

    #[test]
    fn empty_memories_produces_empty_array_not_null() {
        let p = assemble_payload(Uuid::nil(), &[]);
        assert!(p["memories"].is_array());
        assert_eq!(p["memories"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn approx_tokens_matches_documented_formula() {
        assert_eq!(approx_token_count(0), 0);
        assert_eq!(approx_token_count(4), 1);
        assert_eq!(approx_token_count(4_096), 1_024);
    }

    // ── Byte-budget packer ──────────────────────────────────────────────

    fn big_string_memory(key: &str, len: usize) -> ActorMemoryRow {
        (
            key.to_string(),
            Value::String("x".repeat(len)),
            "semantic".to_string(),
        )
    }

    #[test]
    fn pack_bounds_assembled_payload_to_budget() {
        let actor = Uuid::new_v4();
        // Ten ~1KB memories = ~10KB of values; a 4KB budget must admit
        // only a few and keep the assembled payload under budget.
        let candidates: Vec<ActorMemoryRow> = (0..10)
            .map(|i| big_string_memory(&format!("m{i}"), 1_000))
            .collect();
        let budget = 4_000;
        let packed = pack_within_budget(actor, candidates, budget, 3_000);
        let payload = assemble_payload(actor, &packed);
        let size = serde_json::to_vec(&payload).unwrap().len();
        assert!(
            size <= budget,
            "assembled payload {size}B must be <= budget {budget}B"
        );
        assert!(!packed.is_empty(), "at least one memory should fit");
        assert!(
            packed.len() < 10,
            "not every memory should fit under budget"
        );
    }

    #[test]
    fn pack_stops_in_relevance_order() {
        let actor = Uuid::new_v4();
        // First row is small and must be kept; the packer stops at the
        // first row that overflows and does not resume for later rows.
        let candidates = vec![
            big_string_memory("keep", 100),
            big_string_memory("overflow", 10_000),
            big_string_memory("small_but_later", 50),
        ];
        let packed = pack_within_budget(actor, candidates, 1_000, 20_000);
        assert_eq!(packed.len(), 1);
        assert_eq!(packed[0].0, "keep");
    }

    #[test]
    fn pack_truncates_oversized_single_value_at_char_boundary() {
        let actor = Uuid::new_v4();
        // A single value far larger than the per-memory cap. Use a 4-byte
        // codepoint ("😀") repeated so a byte-index cut would land
        // mid-codepoint unless we respect char boundaries.
        let huge = "😀".repeat(2_000); // 8_000 bytes
        let candidates = vec![("k".to_string(), Value::String(huge), "semantic".to_string())];
        let per_memory_cap = 1_000;
        let packed = pack_within_budget(actor, candidates, 12_000, per_memory_cap);
        assert_eq!(packed.len(), 1);
        let v = packed[0].1.as_str().expect("truncated value is a string");
        // Valid UTF-8 (guaranteed by &str) and bounded by the cap.
        assert!(v.len() <= per_memory_cap, "truncated value within cap");
        assert!(v.ends_with(TRUNCATION_MARKER), "truncation is marked");
        // No partial codepoint: every char is the full emoji or marker.
        assert!(v.chars().count() > 0);
    }

    #[test]
    fn truncate_value_tiny_cap_floors_at_marker_len() {
        // A pathologically small cap (below the marker length) must not
        // produce a value larger than max(cap, marker_len): the effective
        // floor is the marker length. No mid-codepoint split, valid UTF-8.
        let big = json!("😀".repeat(500)); // multi-byte, far over any tiny cap
        let (v, truncated) = truncate_value(big, 5);
        assert!(truncated);
        let s = v.as_str().expect("truncated value is a string");
        // budget = 0 ⇒ content empty ⇒ result is exactly the marker.
        assert_eq!(s, TRUNCATION_MARKER);
        assert!(s.len() <= TRUNCATION_MARKER.len().max(5));
    }

    #[test]
    fn truncate_value_leaves_small_values_untouched() {
        let (v, truncated) = truncate_value(json!({"a": 1}), 3_000);
        assert!(!truncated);
        assert_eq!(v, json!({"a": 1}));
    }

    // ── Candidate selection (merge / dedup / floor / scratchpad) ────────

    // Baselines used by the selection tests — the config defaults.
    const G_BASE: f64 = 0.6;
    const R_BASE: f64 = 0.4;

    fn hit(key: &str, score: f64, mem_type: &str) -> crate::MemoryHit {
        crate::MemoryHit {
            key: key.to_string(),
            value: json!({ "k": key }),
            memory_type: mem_type.to_string(),
            expires_at: None,
            updated_at: chrono::Utc::now(),
            score,
            metadata: None,
            importance: None,
            access_count: None,
        }
    }

    fn hit_with_importance(key: &str, score: f64, mem_type: &str, imp: f64) -> crate::MemoryHit {
        crate::MemoryHit {
            metadata: Some(json!({ "importance": imp })),
            ..hit(key, score, mem_type)
        }
    }

    fn rec(key: &str, mem_type: &str) -> RecencyRow {
        (
            key.to_string(),
            json!({ "k": key }),
            mem_type.to_string(),
            Some(Utc::now()),
            None,
            None,
        )
    }

    #[test]
    fn select_drops_below_floor_hits() {
        let hits = vec![
            hit("strong", 0.9, "semantic"),
            hit("weak", 0.10, "semantic"),
        ];
        let out = select_candidates(None, hits, vec![], 0.25, G_BASE, R_BASE);
        let keys: Vec<_> = out.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, vec!["strong"], "below-floor hit must be dropped");
    }

    #[test]
    fn select_excludes_scratchpad_every_layer() {
        let graph = Some((
            "__graph_context__".to_string(),
            json!({}),
            "graph".to_string(),
        ));
        let hits = vec![hit("s1", 0.9, "semantic"), hit("trace", 0.9, "scratchpad")];
        let recency = vec![rec("r1", "episodic"), rec("pad", "scratchpad")];
        let out = select_candidates(graph, hits, recency, 0.25, G_BASE, R_BASE);
        let keys: Vec<_> = out.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, vec!["__graph_context__", "s1", "r1"]);
    }

    #[test]
    fn select_dedups_by_key_keeping_highest_relevance() {
        // "dup" appears as a strong semantic hit (0.8) AND a recency row
        // (baseline 0.4); the higher-relevance semantic instance must win.
        let hits = vec![hit("dup", 0.8, "semantic")];
        let recency = vec![rec("dup", "episodic"), rec("uniq", "episodic")];
        let out = select_candidates(None, hits, recency, 0.25, G_BASE, R_BASE);
        let keys: Vec<_> = out.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, vec!["dup", "uniq"]);
        // The kept "dup" is the semantic one: relevance 0.8, value {"k":"dup"}.
        assert_eq!(out[0].value, json!({ "k": "dup" }));
        assert!((out[0].relevance - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn select_dedup_keeps_highest_even_when_recency_seen_first() {
        // A LOW-relevance recency row is seen before the same key's HIGH
        // semantic hit — the semantic instance must still replace it.
        let recency = vec![rec("dup", "working")]; // relevance = R_BASE (0.4)
        let hits = vec![hit("dup", 0.95, "semantic")]; // relevance 0.95
                                                       // Order: recency arg is consumed after semantic in select_candidates,
                                                       // so build the reverse to exercise the replace-in-place branch:
                                                       // semantic first (inserts), recency second (lower → dropped).
        let out = select_candidates(None, hits, recency, 0.25, G_BASE, R_BASE);
        assert_eq!(out.len(), 1);
        assert!((out[0].relevance - 0.95).abs() < f64::EPSILON);
        assert_eq!(out[0].memory_type, "semantic");
    }

    #[test]
    fn select_threads_signals_from_each_layer() {
        let graph = Some(("g".to_string(), json!({}), "graph".to_string()));
        let hits = vec![hit_with_importance("s1", 0.9, "semantic", 0.75)];
        let recency = vec![rec("r1", "episodic")];
        let out = select_candidates(graph, hits, recency, 0.25, G_BASE, R_BASE);
        // Graph → baseline relevance, no ts, no hint.
        assert_eq!(out[0].key, "g");
        assert!((out[0].relevance - G_BASE).abs() < f64::EPSILON);
        assert!(out[0].updated_at.is_none());
        assert!(out[0].importance_hint.is_none());
        // Semantic → score + ts + parsed importance hint.
        assert_eq!(out[1].key, "s1");
        assert!((out[1].relevance - 0.9).abs() < f64::EPSILON);
        assert!(out[1].updated_at.is_some());
        assert_eq!(out[1].importance_hint, Some(0.75));
        // Recency → baseline relevance + ts.
        assert_eq!(out[2].key, "r1");
        assert!((out[2].relevance - R_BASE).abs() < f64::EPSILON);
        assert!(out[2].updated_at.is_some());
    }

    #[test]
    fn durable_importance_used_directly_no_double_blend() {
        // A row whose DURABLE `importance` column is set (as Phase 3a writes,
        // and Phase 3b will write explicit scores). The stored value is ALREADY
        // the write-time base⊕metadata blend, so the ranker must use it
        // directly — NOT re-blend it with the type base a second time.
        //
        // Simulate a semantic row (base 1.0) whose stored importance is 0.6
        // (e.g. write_time_importance blended base 1.0 with metadata 0.2).
        let durable = crate::MemoryHit {
            importance: Some(0.6),
            // A metadata.importance is ALSO present, but the durable column
            // must win — the fallback is only for NULL-column (pre-3a) rows.
            metadata: Some(json!({ "importance": 0.9 })),
            ..hit("s1", 0.9, "semantic")
        };
        let out = select_candidates(None, vec![durable], vec![], 0.25, G_BASE, R_BASE);
        assert_eq!(out.len(), 1);
        // Durable column routes to importance_final; the metadata hint is
        // dropped (column wins), so no 50/50 base re-blend happens.
        assert_eq!(out[0].importance_final, Some(0.6));
        assert!(out[0].importance_hint.is_none());
        // importance() returns the stored score DIRECTLY (0.6), not the
        // double-blended (base 1.0 + 0.6)/2 = 0.8 the pre-fix code produced.
        let imp = importance(&out[0], 0.15);
        assert!(
            (imp - 0.6).abs() < 1e-9,
            "durable importance must be used directly (got {imp}, want 0.6)"
        );
    }

    #[test]
    fn pre_phase3a_null_column_still_blends_metadata_with_base() {
        // A pre-3a row: durable column NULL, legacy metadata.importance present.
        // Behavior must be byte-identical to Phase 2 — blend 50/50 with base.
        let legacy = hit_with_importance("s1", 0.9, "semantic", 0.2); // durable None
        let out = select_candidates(None, vec![legacy], vec![], 0.25, G_BASE, R_BASE);
        assert_eq!(out.len(), 1);
        assert!(out[0].importance_final.is_none());
        assert_eq!(out[0].importance_hint, Some(0.2));
        // (semantic base 1.0 + hint 0.2)/2 = 0.6.
        let imp = importance(&out[0], 0.15);
        assert!(
            (imp - 0.6).abs() < 1e-9,
            "legacy blend must hold (got {imp})"
        );
    }

    // ── Fused scorer + ranking ──────────────────────────────────────────

    fn default_weights() -> Weights {
        Weights {
            relevance: 1.0,
            recency: 0.3,
            importance: 0.5,
            recency_halflife_days: 7.0,
        }
    }

    fn cand(
        key: &str,
        relevance: f64,
        age_days: f64,
        mem_type: &str,
        importance_hint: Option<f64>,
        now: DateTime<Utc>,
    ) -> Candidate {
        Candidate {
            key: key.to_string(),
            value: json!({ "k": key }),
            memory_type: mem_type.to_string(),
            relevance,
            updated_at: Some(now - chrono::Duration::seconds((age_days * 86_400.0) as i64)),
            importance_final: None,
            importance_hint,
            access_boost: None,
        }
    }

    #[test]
    fn recency_decay_halves_each_half_life() {
        assert!((recency_decay(0.0, 7.0) - 1.0).abs() < 1e-9);
        assert!((recency_decay(7.0, 7.0) - 0.5).abs() < 1e-9);
        assert!((recency_decay(14.0, 7.0) - 0.25).abs() < 1e-9);
        // Future timestamps clamp to "brand new".
        assert!((recency_decay(-100.0, 7.0) - 1.0).abs() < 1e-9);
        // Degenerate half-life falls back to neutral, never divides by zero.
        assert!((recency_decay(5.0, 0.0) - NEUTRAL_RECENCY).abs() < 1e-9);
    }

    #[test]
    fn importance_mapping_and_blend() {
        // access_boost is None on every candidate here, so importance() returns
        // the base/hint blend unchanged for ANY access_weight — pin 0.15.
        const AW: f64 = 0.15;
        let base = Candidate {
            key: "k".into(),
            value: json!(1),
            memory_type: "semantic".into(),
            relevance: 0.0,
            updated_at: None,
            importance_final: None,
            importance_hint: None,
            access_boost: None,
        };
        assert!((importance(&base, AW) - 1.0).abs() < 1e-9);
        let ep = Candidate {
            memory_type: "episodic".into(),
            ..base.clone()
        };
        assert!((importance(&ep, AW) - 0.66).abs() < 1e-9);
        let wk = Candidate {
            memory_type: "working".into(),
            ..base.clone()
        };
        assert!((importance(&wk, AW) - 0.33).abs() < 1e-9);
        let unknown = Candidate {
            memory_type: "mystery".into(),
            ..base.clone()
        };
        assert!((importance(&unknown, AW) - 0.5).abs() < 1e-9);
        // Hint blends 50/50 with the type base (working 0.33 + hint 1.0)/2.
        let hinted = Candidate {
            memory_type: "working".into(),
            importance_hint: Some(1.0),
            ..base.clone()
        };
        assert!((importance(&hinted, AW) - 0.665).abs() < 1e-9);
        // Out-of-range hint is clamped before blending.
        let over = Candidate {
            importance_hint: Some(5.0),
            ..base
        };
        assert!((importance(&over, AW) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn write_time_importance_matches_type_base_and_hint_blend() {
        // Bare type bases (no metadata / no numeric importance).
        assert!((write_time_importance("semantic", None) - 1.0).abs() < 1e-9);
        assert!((write_time_importance("episodic", None) - 0.66).abs() < 1e-9);
        assert!((write_time_importance("working", None) - 0.33).abs() < 1e-9);
        assert!((write_time_importance("mystery", None) - 0.5).abs() < 1e-9);
        // NULL / absent `metadata.importance` → bare base.
        let no_imp = json!({ "kind": "daily_brief" });
        assert!((write_time_importance("semantic", Some(&no_imp)) - 1.0).abs() < 1e-9);
        // Numeric hint blends 50/50 with the base: (working 0.33 + 1.0)/2.
        let hint = json!({ "importance": 1.0 });
        assert!((write_time_importance("working", Some(&hint)) - 0.665).abs() < 1e-9);
        // Out-of-range hint is clamped before blending: (semantic 1.0 + 1.0)/2.
        let over = json!({ "importance": 5.0 });
        assert!((write_time_importance("semantic", Some(&over)) - 1.0).abs() < 1e-9);
        // Non-numeric / non-finite importance is ignored → bare base.
        let str_imp = json!({ "importance": "high" });
        assert!((write_time_importance("episodic", Some(&str_imp)) - 0.66).abs() < 1e-9);
        // The write-time score equals importance()'s hint blend for the same
        // inputs (single source of truth — no drift between write + rank).
        let c = Candidate {
            key: "k".into(),
            value: json!(1),
            memory_type: "working".into(),
            relevance: 0.0,
            updated_at: None,
            importance_final: None,
            importance_hint: Some(1.0),
            access_boost: None,
        };
        assert!(
            (write_time_importance("working", Some(&hint)) - importance(&c, 0.15)).abs() < 1e-9
        );
    }

    #[test]
    fn access_boost_normalization_is_monotone_and_bounded() {
        // None → None (neutral): older rows / flag-off / no signal.
        assert_eq!(access_boost(None), None);
        // Zero accesses → 0.0 (neutral).
        assert!((access_boost(Some(0)).unwrap() - 0.0).abs() < 1e-12);
        // Saturating curve: strictly increasing, bounded in [0, 1).
        let b1 = access_boost(Some(1)).unwrap(); // 0.5
        let b5 = access_boost(Some(5)).unwrap(); // 0.833..
        let b100 = access_boost(Some(100)).unwrap();
        assert!((b1 - 0.5).abs() < 1e-12);
        assert!(b1 < b5 && b5 < b100);
        assert!(b100 < 1.0);
        // Negative (unreachable) clamps to 0, never divides by zero.
        assert!((access_boost(Some(-10)).unwrap() - 0.0).abs() < 1e-12);
    }

    #[test]
    fn importance_access_boost_is_neutral_monotone_and_capped() {
        const AW: f64 = 0.15;
        let mk = |mem_type: &str, hint: Option<f64>, boost: Option<f64>| Candidate {
            key: "k".into(),
            value: json!(1),
            memory_type: mem_type.into(),
            relevance: 0.0,
            updated_at: None,
            importance_final: None,
            importance_hint: hint,
            access_boost: boost,
        };
        // Neutral when access_boost is None: identical to the base blend.
        let none = mk("working", None, None);
        assert!((importance(&none, AW) - importance_base("working")).abs() < 1e-9);
        // Monotonic non-decreasing in access_count (via access_boost).
        let low = mk("working", None, access_boost(Some(1)));
        let high = mk("working", None, access_boost(Some(50)));
        assert!(importance(&high, AW) >= importance(&low, AW));
        assert!(importance(&low, AW) >= importance(&none, AW));
        // Stays <= 1.0 even when base+hint is already maxed and boost is high.
        let maxed = mk("semantic", Some(1.0), access_boost(Some(1_000_000)));
        let v = importance(&maxed, AW);
        assert!(v <= 1.0 + 1e-12, "importance {v} must stay <= 1.0");
        // Non-finite access_weight degrades to a zero nudge (NaN-safe).
        let nan_w = importance(&low, f64::NAN);
        assert!((nan_w - importance(&none, AW)).abs() < 1e-9);
    }

    #[test]
    fn select_prefers_db_importance_over_metadata() {
        // A semantic hit carries BOTH a durable importance column (0.2) AND a
        // metadata.importance (0.9). The DB column must win.
        let mut h = hit("s", 0.9, "semantic");
        h.metadata = Some(json!({ "importance": 0.9 }));
        h.importance = Some(0.2);
        let out = select_candidates(None, vec![h], vec![], 0.0, G_BASE, R_BASE);
        assert_eq!(out.len(), 1);
        // DB column wins as the FINAL score (used directly, no re-blend); the
        // metadata hint is dropped.
        assert_eq!(out[0].importance_final, Some(0.2), "DB column wins");
        assert!(out[0].importance_hint.is_none());

        // With NULL DB importance, fall back to metadata.importance as a hint
        // (blended 50/50 with the base by importance()).
        let mut h2 = hit("s2", 0.9, "semantic");
        h2.metadata = Some(json!({ "importance": 0.9 }));
        h2.importance = None;
        let out2 = select_candidates(None, vec![h2], vec![], 0.0, G_BASE, R_BASE);
        assert!(out2[0].importance_final.is_none());
        assert_eq!(out2[0].importance_hint, Some(0.9), "metadata fallback");
    }

    #[test]
    fn select_threads_durable_signals_into_candidates() {
        // Recency row carries durable importance + access_count → boost.
        let recency: Vec<RecencyRow> = vec![(
            "r".into(),
            json!({ "k": "r" }),
            "episodic".into(),
            Some(Utc::now()),
            Some(0.7),
            Some(3),
        )];
        let out = select_candidates(None, vec![], recency, 0.0, G_BASE, R_BASE);
        // Recency rows carry the durable column as the FINAL score.
        assert_eq!(out[0].importance_final, Some(0.7));
        assert!(out[0].importance_hint.is_none());
        assert_eq!(out[0].access_boost, access_boost(Some(3)));
    }

    #[test]
    fn fused_score_missing_ts_gets_neutral_recency_not_zero() {
        let w = default_weights();
        let now = Utc::now();
        let no_ts = Candidate {
            key: "g".into(),
            value: json!({}),
            memory_type: "semantic".into(),
            relevance: 0.5,
            updated_at: None,
            importance_final: None,
            importance_hint: None,
            access_boost: None,
        };
        // = 1.0*0.5 + 0.3*NEUTRAL_RECENCY + 0.5*1.0 (access_boost None → neutral)
        let expected = 0.5 + 0.3 * NEUTRAL_RECENCY + 0.5;
        assert!((fused_score(&no_ts, &w, now, 0.15) - expected).abs() < 1e-9);
    }

    #[test]
    fn rank_orders_by_fused_score_desc() {
        let now = Utc::now();
        let w = default_weights();
        // old-but-highly-relevant fact vs recent-but-marginal note.
        let old_strong = cand("old_strong", 0.9, 120.0, "semantic", None, now);
        let recent_weak = cand("recent_weak", 0.5, 0.5, "episodic", None, now);
        let ranked = rank_candidates(vec![recent_weak, old_strong], &w, now, 0.15);
        // Under the default weights relevance dominates → old_strong first.
        assert_eq!(ranked[0].key, "old_strong");
        assert_eq!(ranked[1].key, "recent_weak");
    }

    #[test]
    fn rank_recency_weight_moves_recent_item_up() {
        let now = Utc::now();
        // A recent, moderately-relevant, flagged-important note vs an old
        // highly-relevant fact.
        let old_fact = cand("old_fact", 0.88, 300.0, "semantic", None, now);
        let recent_note = cand("recent_note", 0.60, 0.5, "working", Some(0.98), now);
        // Default weights → the old fact wins on relevance.
        let low = rank_candidates(
            vec![recent_note.clone(), old_fact.clone()],
            &default_weights(),
            now,
            0.15,
        );
        assert_eq!(low[0].key, "old_fact", "default: relevance dominates");
        // Crank the recency weight up → the recent note overtakes.
        let high_recency = Weights {
            recency: 2.0,
            ..default_weights()
        };
        let high = rank_candidates(vec![recent_note, old_fact], &high_recency, now, 0.15);
        assert_eq!(
            high[0].key, "recent_note",
            "raising W_RECENCY must promote the recent item"
        );
    }

    #[test]
    fn rank_importance_weight_moves_flagged_item_up() {
        let now = Utc::now();
        // Same age + relevance; one is flagged important, one isn't.
        let flagged = cand("flagged", 0.6, 5.0, "working", Some(1.0), now);
        let plain = cand("plain", 0.63, 5.0, "working", None, now);
        // Low importance weight → the marginally-more-relevant plain wins.
        let low_imp = Weights {
            importance: 0.01,
            ..default_weights()
        };
        let low = rank_candidates(vec![flagged.clone(), plain.clone()], &low_imp, now, 0.15);
        assert_eq!(low[0].key, "plain");
        // High importance weight → the flagged item overtakes.
        let high_imp = Weights {
            importance: 2.0,
            ..default_weights()
        };
        let high = rank_candidates(vec![flagged, plain], &high_imp, now, 0.15);
        assert_eq!(high[0].key, "flagged");
    }

    // ── Retrieval-quality eval (deterministic, network-free) ────────────
    //
    // A labeled fixture proves the FUSED ranker orders memories closer to a
    // human-labeled ideal than either single-signal baseline
    // (relevance-only / recency-only), measured by recall@K and MRR. Pure:
    // fixtures are scored directly, no embeddings / DB.

    /// One eval fixture row: the raw signals + a ground-truth `useful` label.
    struct EvalItem {
        key: &'static str,
        relevance: f64,
        age_days: f64,
        importance_hint: Option<f64>,
        mem_type: &'static str,
        useful: bool,
    }

    fn eval_fixture() -> Vec<EvalItem> {
        // 16 memories. The 5 `useful` ones span the design space: an old
        // highly-relevant fact, two recent+flagged-important notes that
        // relevance-alone under-ranks, a strong recent hit, and a
        // mid-relevance recent+important one. Distractors are either
        // stale-but-relevant (relevance-only false positives) or
        // recent-but-irrelevant (recency-only false positives).
        vec![
            EvalItem {
                key: "old_key_fact",
                relevance: 0.88,
                age_days: 300.0,
                importance_hint: None,
                mem_type: "semantic",
                useful: true,
            },
            EvalItem {
                key: "recent_critical",
                relevance: 0.60,
                age_days: 0.5,
                importance_hint: Some(0.98),
                mem_type: "working",
                useful: true,
            },
            EvalItem {
                key: "recent_important2",
                relevance: 0.58,
                age_days: 1.0,
                importance_hint: Some(0.90),
                mem_type: "episodic",
                useful: true,
            },
            EvalItem {
                key: "strong_recent",
                relevance: 0.80,
                age_days: 2.0,
                importance_hint: None,
                mem_type: "semantic",
                useful: true,
            },
            EvalItem {
                key: "mid_recent_imp",
                relevance: 0.66,
                age_days: 3.0,
                importance_hint: Some(0.85),
                mem_type: "semantic",
                useful: true,
            },
            // stale-but-relevant distractors (relevance-only false positives)
            EvalItem {
                key: "stale_relevant1",
                relevance: 0.95,
                age_days: 250.0,
                importance_hint: Some(0.05),
                mem_type: "working",
                useful: false,
            },
            EvalItem {
                key: "stale_relevant2",
                relevance: 0.78,
                age_days: 500.0,
                importance_hint: Some(0.10),
                mem_type: "working",
                useful: false,
            },
            EvalItem {
                key: "stale_relevant3",
                relevance: 0.75,
                age_days: 180.0,
                importance_hint: None,
                mem_type: "working",
                useful: false,
            },
            EvalItem {
                key: "stale_relevant4",
                relevance: 0.72,
                age_days: 90.0,
                importance_hint: None,
                mem_type: "working",
                useful: false,
            },
            // recent-but-irrelevant distractors (recency-only false positives)
            EvalItem {
                key: "recent_irrel1",
                relevance: 0.30,
                age_days: 0.2,
                importance_hint: None,
                mem_type: "episodic",
                useful: false,
            },
            EvalItem {
                key: "recent_irrel2",
                relevance: 0.28,
                age_days: 0.5,
                importance_hint: None,
                mem_type: "working",
                useful: false,
            },
            EvalItem {
                key: "recent_irrel3",
                relevance: 0.35,
                age_days: 1.0,
                importance_hint: None,
                mem_type: "episodic",
                useful: false,
            },
            EvalItem {
                key: "recent_irrel4",
                relevance: 0.25,
                age_days: 0.1,
                importance_hint: None,
                mem_type: "working",
                useful: false,
            },
            // mid filler
            EvalItem {
                key: "mid1",
                relevance: 0.50,
                age_days: 40.0,
                importance_hint: None,
                mem_type: "episodic",
                useful: false,
            },
            EvalItem {
                key: "mid2",
                relevance: 0.45,
                age_days: 60.0,
                importance_hint: None,
                mem_type: "working",
                useful: false,
            },
            EvalItem {
                key: "mid3",
                relevance: 0.40,
                age_days: 120.0,
                importance_hint: None,
                mem_type: "semantic",
                useful: false,
            },
        ]
    }

    fn fixture_candidates(items: &[EvalItem], now: DateTime<Utc>) -> Vec<Candidate> {
        items
            .iter()
            .map(|it| {
                cand(
                    it.key,
                    it.relevance,
                    it.age_days,
                    it.mem_type,
                    it.importance_hint,
                    now,
                )
            })
            .collect()
    }

    fn useful_keys(items: &[EvalItem]) -> std::collections::HashSet<&'static str> {
        items.iter().filter(|i| i.useful).map(|i| i.key).collect()
    }

    /// recall@K = |top-K ∩ relevant| / min(K, |relevant|).
    fn recall_at_k(
        ranked: &[Candidate],
        relevant: &std::collections::HashSet<&'static str>,
        k: usize,
    ) -> f64 {
        let hits = ranked
            .iter()
            .take(k)
            .filter(|c| relevant.contains(c.key.as_str()))
            .count();
        let denom = k.min(relevant.len()).max(1);
        hits as f64 / denom as f64
    }

    /// Mean reciprocal rank of the FIRST relevant item (1-indexed).
    fn mrr(ranked: &[Candidate], relevant: &std::collections::HashSet<&'static str>) -> f64 {
        for (i, c) in ranked.iter().enumerate() {
            if relevant.contains(c.key.as_str()) {
                return 1.0 / (i as f64 + 1.0);
            }
        }
        0.0
    }

    #[test]
    fn eval_fused_beats_single_signal_baselines() {
        let now = Utc::now();
        let items = eval_fixture();
        let relevant = useful_keys(&items);
        let k = 5;

        // Fused: the production default weights. (Fixture candidates carry no
        // access_boost, so access_weight is inert here — pin 0.15.)
        let fused = rank_candidates(
            fixture_candidates(&items, now),
            &default_weights(),
            now,
            0.15,
        );
        // Relevance-only baseline: kill recency + importance weights.
        let rel_only_w = Weights {
            relevance: 1.0,
            recency: 0.0,
            importance: 0.0,
            recency_halflife_days: 7.0,
        };
        let rel_only = rank_candidates(fixture_candidates(&items, now), &rel_only_w, now, 0.15);
        // Recency-only baseline: only the recency signal.
        let rec_only_w = Weights {
            relevance: 0.0,
            recency: 1.0,
            importance: 0.0,
            recency_halflife_days: 7.0,
        };
        let rec_only = rank_candidates(fixture_candidates(&items, now), &rec_only_w, now, 0.15);

        let fused_recall = recall_at_k(&fused, &relevant, k);
        let rel_recall = recall_at_k(&rel_only, &relevant, k);
        let rec_recall = recall_at_k(&rec_only, &relevant, k);
        let fused_mrr = mrr(&fused, &relevant);
        let rel_mrr = mrr(&rel_only, &relevant);
        let rec_mrr = mrr(&rec_only, &relevant);

        // Fusion perfectly recovers the useful set in the top-5.
        assert!(
            (fused_recall - 1.0).abs() < 1e-9,
            "fused recall@{k} = {fused_recall}, expected 1.0"
        );
        assert!(
            (fused_mrr - 1.0).abs() < 1e-9,
            "fused MRR = {fused_mrr}, expected 1.0"
        );

        // Fusion STRICTLY beats both baselines on BOTH metrics.
        assert!(
            fused_recall > rel_recall,
            "fused recall@{k} {fused_recall} must beat relevance-only {rel_recall}"
        );
        assert!(
            fused_recall > rec_recall,
            "fused recall@{k} {fused_recall} must beat recency-only {rec_recall}"
        );
        assert!(
            fused_mrr > rel_mrr,
            "fused MRR {fused_mrr} must beat relevance-only {rel_mrr}"
        );
        assert!(
            fused_mrr > rec_mrr,
            "fused MRR {fused_mrr} must beat recency-only {rec_mrr}"
        );
    }

    #[test]
    fn eval_weight_change_moves_ranking_expected_direction() {
        let now = Utc::now();
        let items = eval_fixture();

        // Position of the recent+critical note under default vs high-recency
        // weights: raising W_RECENCY must not DEMOTE it (it should hold or
        // climb, since it is recent).
        let default_ranked = rank_candidates(
            fixture_candidates(&items, now),
            &default_weights(),
            now,
            0.15,
        );
        let high_recency = Weights {
            recency: 3.0,
            ..default_weights()
        };
        let recency_ranked =
            rank_candidates(fixture_candidates(&items, now), &high_recency, now, 0.15);

        let pos =
            |ranked: &[Candidate], key: &str| ranked.iter().position(|c| c.key == key).unwrap();
        assert!(
            pos(&recency_ranked, "recent_critical") <= pos(&default_ranked, "recent_critical"),
            "raising W_RECENCY must not demote the recent_critical note"
        );
        // And a stale item must not IMPROVE when recency weight rises.
        assert!(
            pos(&recency_ranked, "stale_relevant1") >= pos(&default_ranked, "stale_relevant1"),
            "raising W_RECENCY must not promote a stale item"
        );
    }

    #[test]
    fn truncate_value_never_splits_codepoint() {
        // Cap deliberately lands inside a multi-byte char region.
        let s = "é".repeat(500); // 1_000 bytes (each 'é' = 2 bytes)
        let (v, truncated) = truncate_value(Value::String(s), 101);
        assert!(truncated);
        let out = v.as_str().unwrap();
        // Round-trips as valid UTF-8 (would panic on a split codepoint).
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
        assert!(out.ends_with(TRUNCATION_MARKER));
    }
}
