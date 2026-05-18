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
}
