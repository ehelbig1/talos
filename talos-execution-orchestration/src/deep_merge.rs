//! Recursive JSON deep-merge for `replay_with_input`.
//!
//! Semantics:
//!
//! * Both sides are objects → recurse, replacing any leaf the override
//!   provides while keeping fields from `base` that the override
//!   doesn't mention.
//! * Either side is a non-object (string / number / array / bool /
//!   null) → the override wins, replacing the whole base subtree.
//!
//! This matches the `replay_execution_with_input` contract: callers
//! provide a partial overlay, NOT a full replacement; arrays are
//! treated as opaque values (we don't index-merge them).
//!
//! Pure function — no I/O, no allocation beyond what `serde_json`
//! does internally. Safe to call from tight loops.

use serde_json::Value;

/// MCP-560: maximum recursion depth when merging caller-supplied JSON
/// overrides over a stored trigger input. Without this, the
/// `replay_execution_with_input` path takes a 1 MB byte-capped
/// override (REPLAY_OVERRIDE_MAX_BYTES in replay.rs:32) but a
/// `{"a":{"a":...}}` nesting is roughly 6-8 bytes per level — at
/// 1 MB, ~125-170k levels. That's well past the tokio worker
/// thread's 2 MB stack and would crash the controller for ALL
/// users on every replay-with-input call that uses such an override.
///
/// 128 matches `talos-workflow-validation::MAX_SCHEMA_DEPTH`
/// (MCP-558), `talos-dlp-provider::MAX_DLP_REDACT_DEPTH` (MCP-559),
/// and `talos-memory`'s `MAX_CANONICAL_DEPTH`. All four fail-closed
/// depth limits on user-controlled JSON tree-walkers share one
/// ceiling so a future change can't drift one site out of sync.
pub const MAX_MERGE_DEPTH: usize = 128;

pub fn deep_merge(base: &mut Value, overrides: &Value) {
    deep_merge_depth(base, overrides, 0);
}

fn deep_merge_depth(base: &mut Value, overrides: &Value, depth: usize) {
    if depth > MAX_MERGE_DEPTH {
        // MCP-560: stop recursing. Past the cap, treat the override
        // as opaque-replace (consistent with the existing
        // "either side is a non-object → override wins" branch
        // below). This is the SAFE failure mode for replay: the
        // override's content beyond depth 128 is still applied
        // verbatim, just not further merged with `base`. Logged
        // once at TRACE because this path runs on every replay
        // attempt and a louder level would amplify a flood.
        tracing::trace!(
            target: "talos_execution_orchestration",
            event_kind = "deep_merge_depth_capped",
            depth,
            max = MAX_MERGE_DEPTH,
            "deep_merge recursion bailed at max depth — replacing rather than merging deeper subtree"
        );
        *base = overrides.clone();
        return;
    }
    if let (Some(base_obj), Some(over_obj)) = (base.as_object_mut(), overrides.as_object()) {
        for (k, v) in over_obj {
            deep_merge_depth(base_obj.entry(k).or_insert(Value::Null), v, depth + 1);
        }
    } else {
        *base = overrides.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn override_replaces_leaf() {
        let mut base = json!({"a": 1, "b": 2});
        deep_merge(&mut base, &json!({"a": 99}));
        assert_eq!(base, json!({"a": 99, "b": 2}));
    }

    #[test]
    fn override_adds_new_field() {
        let mut base = json!({"a": 1});
        deep_merge(&mut base, &json!({"b": 2}));
        assert_eq!(base, json!({"a": 1, "b": 2}));
    }

    #[test]
    fn override_recurses_into_nested_objects() {
        let mut base = json!({"outer": {"inner": 1, "kept": "yes"}});
        deep_merge(&mut base, &json!({"outer": {"inner": 99}}));
        assert_eq!(base, json!({"outer": {"inner": 99, "kept": "yes"}}));
    }

    #[test]
    fn array_override_replaces_whole_array() {
        // Arrays are NOT index-merged — we treat them as opaque values.
        // This is the historical behaviour of the inline `deep_merge`
        // in executions.rs and callers of `replay_with_input` rely on it.
        let mut base = json!({"tags": ["a", "b", "c"]});
        deep_merge(&mut base, &json!({"tags": ["x"]}));
        assert_eq!(base, json!({"tags": ["x"]}));
    }

    #[test]
    fn null_override_replaces_object() {
        // Override is a non-object; whole subtree is replaced.
        let mut base = json!({"data": {"a": 1, "b": 2}});
        deep_merge(&mut base, &json!({"data": null}));
        assert_eq!(base, json!({"data": null}));
    }

    #[test]
    fn object_override_replaces_scalar() {
        let mut base = json!({"data": "old"});
        deep_merge(&mut base, &json!({"data": {"new": 1}}));
        assert_eq!(base, json!({"data": {"new": 1}}));
    }

    #[test]
    fn empty_override_is_noop() {
        let mut base = json!({"a": 1, "b": {"c": 2}});
        deep_merge(&mut base, &json!({}));
        assert_eq!(base, json!({"a": 1, "b": {"c": 2}}));
    }

    #[test]
    fn fully_disjoint_keys_preserve_both_sides() {
        let mut base = json!({"a": 1});
        deep_merge(&mut base, &json!({"b": 2, "c": {"d": 3}}));
        assert_eq!(base, json!({"a": 1, "b": 2, "c": {"d": 3}}));
    }

    #[test]
    fn three_levels_deep_merge() {
        let mut base = json!({"l1": {"l2": {"l3": 1, "kept": true}}});
        deep_merge(&mut base, &json!({"l1": {"l2": {"l3": 99}}}));
        assert_eq!(base, json!({"l1": {"l2": {"l3": 99, "kept": true}}}));
    }

    // MCP-560: tripwire — confirm deep_merge bails at MAX_MERGE_DEPTH
    // instead of stack-overflowing on a pathologically nested override.
    // A 1 MB replay-input override could nest ~125-170k levels of
    // `{"a":{"a":...}}`; well past the tokio worker thread's 2 MB
    // stack. Pre-fix, every replay_with_input that included such
    // an override would crash the controller for ALL users.
    #[test]
    fn deep_merge_bails_on_deep_nesting() {
        // Build a nested object override past MAX_MERGE_DEPTH.
        let mut overrides = json!("deep_value");
        for _ in 0..(super::MAX_MERGE_DEPTH + 20) {
            overrides = json!({ "x": overrides });
        }
        let mut base = json!({});
        // MUST NOT panic. Past the depth cap, the override's
        // remaining subtree is opaque-replaced into `base`.
        deep_merge(&mut base, &overrides);
        // Sanity: shallow merges still work.
        let mut shallow_base = json!({"a": 1, "b": {"c": 2}});
        deep_merge(&mut shallow_base, &json!({"b": {"c": 99, "d": 3}}));
        assert_eq!(shallow_base, json!({"a": 1, "b": {"c": 99, "d": 3}}));
    }
}
