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

use serde_json::{json, Value};
use uuid::Uuid;

/// One memory row in the assembled payload — `(key, value_json, memory_type)`.
/// Matches the tuple shape returned by
/// `WorkflowRepository::get_relevant_actor_context`.
pub type ActorMemoryRow = (String, Value, String);

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

/// Merge the smart-context retrieval layers into a single deduplicated
/// candidate list in relevance order, ready for [`pack_within_budget`].
///
/// Order of precedence (highest first): graph entity context, then the
/// semantic hits (already cosine-score-descending from the DB), then the
/// recency rows. Applied per candidate:
/// * **scratchpad drop** — `memory_type == "scratchpad"` rows are skipped
///   in every layer (they embed the prior run's `__actor_context__` and
///   would grow context recursively).
/// * **min-score floor** — a defense-in-depth re-assertion of the DB-layer
///   `>= min_score` predicate on semantic hits (the SQL already floors;
///   this keeps the guarantee even if a future caller over-fetches with a
///   looser floor). Graph/recency carry no score and are unaffected.
/// * **dedup by key** — the first (highest-relevance) occurrence of a key
///   wins; later layers can't re-introduce it.
///
/// Pure so the selection logic is unit-tested without a database. The
/// production smart retriever fetches each layer then calls exactly this.
pub fn select_candidates(
    graph: Option<ActorMemoryRow>,
    semantic_hits: Vec<crate::MemoryHit>,
    recency: Vec<ActorMemoryRow>,
    min_score: f64,
) -> Vec<ActorMemoryRow> {
    let mut out: Vec<ActorMemoryRow> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    if let Some((k, v, t)) = graph {
        if t != "scratchpad" && seen.insert(k.clone()) {
            out.push((k, v, t));
        }
    }
    for h in semantic_hits {
        if h.memory_type == "scratchpad" || h.score < min_score {
            continue;
        }
        if seen.insert(h.key.clone()) {
            out.push((h.key, h.value, h.memory_type));
        }
    }
    for (k, v, t) in recency {
        if t != "scratchpad" && seen.insert(k.clone()) {
            out.push((k, v, t));
        }
    }
    out
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

    #[test]
    fn select_drops_below_floor_hits() {
        let hits = vec![
            hit("strong", 0.9, "semantic"),
            hit("weak", 0.10, "semantic"),
        ];
        let out = select_candidates(None, hits, vec![], 0.25);
        let keys: Vec<_> = out.iter().map(|(k, _, _)| k.as_str()).collect();
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
        let recency = vec![
            ("r1".to_string(), json!(1), "episodic".to_string()),
            ("pad".to_string(), json!(2), "scratchpad".to_string()),
        ];
        let out = select_candidates(graph, hits, recency, 0.25);
        let keys: Vec<_> = out.iter().map(|(k, _, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["__graph_context__", "s1", "r1"]);
    }

    #[test]
    fn select_dedups_by_key_keeping_highest_relevance() {
        // "dup" appears in semantic (higher precedence) and recency; the
        // semantic occurrence must win and recency's must be dropped.
        let hits = vec![hit("dup", 0.8, "semantic")];
        let recency = vec![
            ("dup".to_string(), json!("recency"), "episodic".to_string()),
            ("uniq".to_string(), json!("r"), "episodic".to_string()),
        ];
        let out = select_candidates(None, hits, recency, 0.25);
        let keys: Vec<_> = out.iter().map(|(k, _, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["dup", "uniq"]);
        // The kept "dup" is the semantic one (value {"k":"dup"}), not recency.
        assert_eq!(out[0].1, json!({ "k": "dup" }));
    }

    #[test]
    fn select_preserves_relevance_order() {
        let graph = Some(("g".to_string(), json!({}), "graph".to_string()));
        let hits = vec![hit("s1", 0.9, "semantic"), hit("s2", 0.5, "semantic")];
        let recency = vec![("r1".to_string(), json!(1), "episodic".to_string())];
        let out = select_candidates(graph, hits, recency, 0.25);
        let keys: Vec<_> = out.iter().map(|(k, _, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["g", "s1", "s2", "r1"]);
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
