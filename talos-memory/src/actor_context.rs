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

/// A recency-layer row carrying its `updated_at` — the tuple shape returned
/// by `talos_memory::recall_recent_excluding_types_and_kinds_ts`.
/// `(key, value_json, memory_type, updated_at)`.
pub type RecencyRow = (String, Value, String, Option<DateTime<Utc>>);

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
/// * `importance_hint` — an optional `metadata.importance` override in
///   `[0, 1]`, blended with the memory-type base by [`importance`].
#[derive(Clone, Debug, PartialEq)]
pub struct Candidate {
    pub key: String,
    pub value: Value,
    pub memory_type: String,
    pub relevance: f64,
    pub updated_at: Option<DateTime<Utc>>,
    pub importance_hint: Option<f64>,
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

/// Blended importance signal in `[0, 1]`: the memory-type base
/// ([`importance_base`]) blended 50/50 with the clamped `importance_hint`
/// when one is present, else the base alone.
pub fn importance(c: &Candidate) -> f64 {
    let base = importance_base(&c.memory_type);
    match c.importance_hint {
        Some(hint) => (base + hint.clamp(0.0, 1.0)) / 2.0,
        None => base,
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
pub fn fused_score(c: &Candidate, w: &Weights, now: DateTime<Utc>) -> f64 {
    w.relevance * c.relevance
        + w.recency * recency_component(c, now, w.recency_halflife_days)
        + w.importance * importance(c)
}

/// Merge the smart-context retrieval layers into a single deduplicated
/// [`Candidate`] list, ready for [`rank_candidates`] then
/// [`pack_within_budget`].
///
/// Signals are threaded in from each layer:
/// * **graph** entity context → `relevance = graph_baseline`, no `updated_at`,
///   no hint.
/// * **semantic hits** → `relevance = hit.score`, `updated_at = hit.updated_at`,
///   `importance_hint` from `metadata.importance` when it parses as a number.
/// * **recency rows** → `relevance = recency_baseline`, `updated_at` from the
///   row, no hint.
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
            importance_hint: None,
        });
    }
    for h in semantic_hits {
        if h.score < min_score {
            continue;
        }
        let importance_hint = h
            .metadata
            .as_ref()
            .and_then(|m| m.get("importance"))
            .and_then(|v| v.as_f64());
        upsert(Candidate {
            key: h.key,
            value: h.value,
            memory_type: h.memory_type,
            relevance: h.score,
            updated_at: Some(h.updated_at),
            importance_hint,
        });
    }
    for (k, v, t, updated_at) in recency {
        upsert(Candidate {
            key: k,
            value: v,
            memory_type: t,
            relevance: recency_baseline,
            updated_at,
            importance_hint: None,
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
/// `now` is injected for determinism (see [`fused_score`]).
pub fn rank_candidates(
    mut candidates: Vec<Candidate>,
    w: &Weights,
    now: DateTime<Utc>,
) -> Vec<Candidate> {
    candidates.sort_by(|a, b| {
        use std::cmp::Ordering;
        let sa = fused_score(a, w, now);
        let sb = fused_score(b, w, now);
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
            importance_hint,
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
        let base = Candidate {
            key: "k".into(),
            value: json!(1),
            memory_type: "semantic".into(),
            relevance: 0.0,
            updated_at: None,
            importance_hint: None,
        };
        assert!((importance(&base) - 1.0).abs() < 1e-9);
        let ep = Candidate {
            memory_type: "episodic".into(),
            ..base.clone()
        };
        assert!((importance(&ep) - 0.66).abs() < 1e-9);
        let wk = Candidate {
            memory_type: "working".into(),
            ..base.clone()
        };
        assert!((importance(&wk) - 0.33).abs() < 1e-9);
        let unknown = Candidate {
            memory_type: "mystery".into(),
            ..base.clone()
        };
        assert!((importance(&unknown) - 0.5).abs() < 1e-9);
        // Hint blends 50/50 with the type base (working 0.33 + hint 1.0)/2.
        let hinted = Candidate {
            memory_type: "working".into(),
            importance_hint: Some(1.0),
            ..base.clone()
        };
        assert!((importance(&hinted) - 0.665).abs() < 1e-9);
        // Out-of-range hint is clamped before blending.
        let over = Candidate {
            importance_hint: Some(5.0),
            ..base
        };
        assert!((importance(&over) - 1.0).abs() < 1e-9);
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
            importance_hint: None,
        };
        // = 1.0*0.5 + 0.3*NEUTRAL_RECENCY + 0.5*1.0
        let expected = 0.5 + 0.3 * NEUTRAL_RECENCY + 0.5;
        assert!((fused_score(&no_ts, &w, now) - expected).abs() < 1e-9);
    }

    #[test]
    fn rank_orders_by_fused_score_desc() {
        let now = Utc::now();
        let w = default_weights();
        // old-but-highly-relevant fact vs recent-but-marginal note.
        let old_strong = cand("old_strong", 0.9, 120.0, "semantic", None, now);
        let recent_weak = cand("recent_weak", 0.5, 0.5, "episodic", None, now);
        let ranked = rank_candidates(vec![recent_weak, old_strong], &w, now);
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
        );
        assert_eq!(low[0].key, "old_fact", "default: relevance dominates");
        // Crank the recency weight up → the recent note overtakes.
        let high_recency = Weights {
            recency: 2.0,
            ..default_weights()
        };
        let high = rank_candidates(vec![recent_note, old_fact], &high_recency, now);
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
        let low = rank_candidates(vec![flagged.clone(), plain.clone()], &low_imp, now);
        assert_eq!(low[0].key, "plain");
        // High importance weight → the flagged item overtakes.
        let high_imp = Weights {
            importance: 2.0,
            ..default_weights()
        };
        let high = rank_candidates(vec![flagged, plain], &high_imp, now);
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

        // Fused: the production default weights.
        let fused = rank_candidates(fixture_candidates(&items, now), &default_weights(), now);
        // Relevance-only baseline: kill recency + importance weights.
        let rel_only_w = Weights {
            relevance: 1.0,
            recency: 0.0,
            importance: 0.0,
            recency_halflife_days: 7.0,
        };
        let rel_only = rank_candidates(fixture_candidates(&items, now), &rel_only_w, now);
        // Recency-only baseline: only the recency signal.
        let rec_only_w = Weights {
            relevance: 0.0,
            recency: 1.0,
            importance: 0.0,
            recency_halflife_days: 7.0,
        };
        let rec_only = rank_candidates(fixture_candidates(&items, now), &rec_only_w, now);

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
        let default_ranked =
            rank_candidates(fixture_candidates(&items, now), &default_weights(), now);
        let high_recency = Weights {
            recency: 3.0,
            ..default_weights()
        };
        let recency_ranked = rank_candidates(fixture_candidates(&items, now), &high_recency, now);

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
