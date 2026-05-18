use rhai::{Dynamic, Engine, Scope};
use serde_json::Value as JsonValue;

// Runtime decode is now the same helper used by the write-time decoders
// in MCP node-config setters and the migration that scrubbed existing
// stored expressions. Single source of truth in `talos-text-util`.
use talos_text_util::decode_html_entities;

/// MCP-1139 (2026-05-16): bare-string error heuristic, capped + single-pass.
///
/// Previously inlined identically at two sites (`evaluate_condition` and
/// `evaluate_condition_with_error`, the MCP-465 sibling pair). Each
/// inline call had two issues:
///   1. `s.to_lowercase()` was invoked TWICE per check — the heap clone
///      happened on the same input back-to-back ("error" branch then
///      "failed" branch), doubling the per-clone alloc + bytewise lower-
///      case walk on workflow context strings.
///   2. No cap on `s.len()`. `context` here is upstream-node output;
///      modules emitting multi-MB string payloads (raw HTML scraped
///      pages, full file contents, dense JSON-as-string) ran the full
///      `to_lowercase` clone twice per conditional eval. Rhai
///      conditionals are evaluated on EVERY out-edge of branching nodes,
///      so a single execution with a 1 MB upstream string scaled to
///      ~edges × 2 MB of heap churn.
///
/// Cap at 4 KiB matches the MCP-1135/1138 sibling sweep. The substrings
/// "error" / "failed" are short by construction; if neither appears in
/// the first paragraph the upstream context isn't an "error-shaped"
/// string in any practical sense (the heuristic is for bare error
/// messages of the shape `"Error: timeout"`, not multi-MB blobs whose
/// content happens to mention the word).
fn looks_like_error_string(s: &str) -> bool {
    const MAX_BYTES: usize = 4096;
    let scan: &str = if s.len() <= MAX_BYTES {
        s
    } else {
        let mut end = MAX_BYTES;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        &s[..end]
    };
    let lower = scan.to_lowercase();
    lower.contains("error") || lower.contains("failed")
}

// Thread-local Rhai engine, created once per thread and reused.
// Rhai's Engine is not Send+Sync, so we use thread_local instead of a static.
thread_local! {
    static RHAI_ENGINE: Engine = {
        let mut engine = Engine::new();
        // Safety limits to prevent runaway scripts
        engine.set_max_operations(1000);
        engine.set_max_call_levels(16);
        engine.set_max_string_size(65536);
        engine.set_max_array_size(500);
        engine.set_max_map_size(500);
        // SECURITY: disable dynamic code execution inside approval conditions.
        // eval() allows arbitrary Rhai code from a string — blocked here so a
        // stored condition like eval("some_dynamic_expr") cannot be used to
        // bypass the save-time syntax check.
        engine.disable_symbol("eval");
        // SECURITY: no module resolver — `import` statements fail at evaluation
        // time. Engine::new() sets no resolver by default; this makes the intent
        // explicit and guards against future Engine::new() behaviour changes.
        engine.set_module_resolver(rhai::module_resolvers::DummyModuleResolver);
        engine
    };
}

/// Helper function to evaluate Rhai conditions using JSON context.
pub fn evaluate_condition(condition: &str, context: &JsonValue) -> bool {
    let decoded = decode_html_entities(condition);
    let condition = decoded.as_ref();
    RHAI_ENGINE.with(|engine| {
        let mut scope = Scope::new();

        // Map JSON fields into script scope for easy access.
        // Also flatten nested "input" and "config" objects so bare variable
        // names like `score` work even when the context is wrapped as
        // `{"config": {...}, "input": {"score": 75}}`.
        //
        // Error state variables: `is_error` (bool) and `error_message` (String)
        // are injected so conditions can branch on error status, e.g.
        //   `is_error == true`  or  `error_message.contains("timeout")`
        let mut detected_error = false;
        let mut detected_error_message = String::new();

        if let JsonValue::Object(map) = context {
            // Detect error state from the context JSON:
            // 1. An `__error` or `error` field indicates an error.
            // 2. If the context only contains a string that looks like an error.
            for key in &["__error", "error"] {
                if let Some(val) = map.get(*key) {
                    // Only treat as an error if the value is a non-empty, non-null value.
                    // Templates like database-query always emit {"error": null} on success,
                    // so key presence alone is not sufficient.
                    match val {
                        JsonValue::Null => {}
                        JsonValue::String(s) if s.is_empty() => {}
                        JsonValue::Bool(false) => {}
                        JsonValue::String(s) => {
                            detected_error = true;
                            detected_error_message = s.clone();
                            break;
                        }
                        other => {
                            detected_error = true;
                            detected_error_message = other.to_string();
                            break;
                        }
                    }
                }
            }

            for (key, val) in map {
                if let Ok(dynamic) = rhai::serde::to_dynamic(val) {
                    scope.push_dynamic(key, dynamic);
                }
                // Flatten common nested objects
                if key == "input" || key == "config" {
                    if let JsonValue::Object(inner) = val {
                        for (inner_key, inner_val) in inner {
                            // Don't overwrite existing top-level keys
                            if !map.contains_key(inner_key) {
                                if let Ok(d) = rhai::serde::to_dynamic(inner_val) {
                                    scope.push_dynamic(inner_key, d);
                                }
                            }
                        }
                    }
                }
            }
        } else if let JsonValue::String(s) = context {
            // A bare error string as context also counts as an error.
            // MCP-1139: capped, single-pass heuristic.
            if looks_like_error_string(s) {
                detected_error = true;
                detected_error_message = s.clone();
            }
        }

        // Inject error state variables into scope
        scope.push("is_error", detected_error);
        scope.push("error_message", detected_error_message);

        // Also provide the whole context as 'ctx' for more complex pathing.
        if let Ok(ctx_dynamic) = rhai::serde::to_dynamic(context) {
            scope.push_dynamic("ctx", ctx_dynamic.clone());
            scope.push_dynamic("inputs", ctx_dynamic);
        }

        match engine.eval_with_scope::<bool>(&mut scope, condition) {
            Ok(res) => {
                tracing::info!(
                    condition = condition,
                    result = res,
                    "Rhai condition evaluated"
                );
                res
            }
            Err(e) => {
                // L-30: Rhai eval failures silently route the workflow as
                // if the condition were `false` (the only safe default —
                // crashing on a bad expression would take down legitimate
                // workflows). Operators need a metric to alert on the
                // rate so a regression after a refactor surfaces.
                //
                // MCP-536: DLP-scrub the context before logging. The
                // context is the merged JSON output of prior nodes —
                // email bodies, LLM outputs, API responses with PII,
                // and (rarely) accidental token leakage. Operator-
                // authored `condition` is fine to log verbatim; the
                // user-data `context` is not.
                let scrubbed_context = talos_dlp_provider::redact_json(context);
                tracing::warn!(
                    target: "talos_engine",
                    event_kind = "rhai_eval_error",
                    eval_kind = "condition",
                    condition = condition,
                    context = %scrubbed_context,
                    error = %e,
                    "Condition evaluation error — defaulted to false"
                );
                false
            }
        }
    })
}

/// Evaluate a Rhai condition and return `Ok(bool)` or `Err(error_string)`.
///
/// Unlike [`evaluate_condition`] which returns `false` on error, this variant
/// propagates the error message so callers (like the MCP `test_condition` tool
/// AND `talos-actor-policies::rhai_eval::evaluate`) can display / log it.
///
/// MCP-465: this is NOT only a preview helper — actor approval policies
/// evaluate their `trigger_condition` through this exact path at runtime.
/// Any divergence from `evaluate_condition` (the edge evaluator) is a real
/// production-semantics bug, not just a UX wart. Keep the two in lockstep.
pub fn evaluate_condition_with_error(condition: &str, context: &JsonValue) -> Result<bool, String> {
    let decoded = decode_html_entities(condition);
    let condition = decoded.as_ref();
    RHAI_ENGINE.with(|engine| {
        let mut scope = Scope::new();

        // MCP-465: mirror `evaluate_condition` exactly.
        // Previous implementation diverged in two ways that surfaced as
        // preview-vs-runtime drift AND as wrong behavior in actor-policy
        // evaluation:
        //   1. Only checked the `error` key, not `__error` — workflows
        //      that surface module failures via `__error` (the canonical
        //      engine envelope key) made conditions like `is_error`
        //      stay false in preview/policies even though the real
        //      edge evaluator flagged them.
        //   2. Used `if !scope.contains("is_error")` to inject the
        //      heuristic, which inverted precedence: payload-provided
        //      values won over heuristic detection. The real evaluator
        //      pushes unconditionally so the heuristic wins.
        // Both fixed below; structure now matches `evaluate_condition`.
        let mut detected_error = false;
        let mut detected_error_message = String::new();
        if let JsonValue::Object(map) = context {
            for key in &["__error", "error"] {
                if let Some(val) = map.get(*key) {
                    match val {
                        JsonValue::Null => {}
                        JsonValue::String(s) if s.is_empty() => {}
                        JsonValue::Bool(false) => {}
                        JsonValue::String(s) => {
                            detected_error = true;
                            detected_error_message = s.clone();
                            break;
                        }
                        other => {
                            detected_error = true;
                            detected_error_message = other.to_string();
                            break;
                        }
                    }
                }
            }

            for (key, val) in map {
                if let Ok(dynamic) = rhai::serde::to_dynamic(val) {
                    scope.push_dynamic(key, dynamic);
                }
                if key == "input" || key == "config" {
                    if let JsonValue::Object(inner) = val {
                        for (inner_key, inner_val) in inner {
                            if !map.contains_key(inner_key) {
                                if let Ok(d) = rhai::serde::to_dynamic(inner_val) {
                                    scope.push_dynamic(inner_key, d);
                                }
                            }
                        }
                    }
                }
            }
        } else if let JsonValue::String(s) = context {
            // MCP-1139: capped, single-pass heuristic (sibling of the
            // `evaluate_condition` site above, MCP-465 lockstep
            // constraint). Both call paths share the same helper.
            if looks_like_error_string(s) {
                detected_error = true;
                detected_error_message = s.clone();
            }
        }

        // Push heuristic values unconditionally — Rhai's scope lookup
        // walks back-to-front, so this layer wins over any payload key
        // pushed in the for-loop above. Matches `evaluate_condition`.
        scope.push("is_error", detected_error);
        scope.push("error_message", detected_error_message);

        if let Ok(ctx_dynamic) = rhai::serde::to_dynamic(context) {
            scope.push_dynamic("ctx", ctx_dynamic.clone());
            scope.push_dynamic("inputs", ctx_dynamic);
        }

        engine
            .eval_with_scope::<bool>(&mut scope, condition)
            .map_err(|e| e.to_string())
    })
}

/// Evaluate a Rhai expression against a JSON context and return an `i64` result.
///
/// Used by `retry_delay_expression` to compute custom backoff delays from error output.
/// Returns `None` if the expression fails to evaluate or does not return a numeric value.
pub fn evaluate_rhai_to_i64(expression: &str, context: &JsonValue) -> Option<i64> {
    let decoded = decode_html_entities(expression);
    let expression = decoded.as_ref();
    RHAI_ENGINE.with(|engine| {
        let mut scope = Scope::new();

        if let JsonValue::Object(map) = context {
            for (key, val) in map {
                if let Ok(dynamic) = rhai::serde::to_dynamic(val) {
                    scope.push_dynamic(key, dynamic);
                }
                // Flatten nested objects (input, config) same as evaluate_condition
                if key == "input" || key == "config" {
                    if let JsonValue::Object(inner) = val {
                        for (inner_key, inner_val) in inner {
                            if !map.contains_key(inner_key) {
                                if let Ok(d) = rhai::serde::to_dynamic(inner_val) {
                                    scope.push_dynamic(inner_key, d);
                                }
                            }
                        }
                    }
                }
                // If "error" contains JSON (possibly prefixed with text like
                // "Component returned error: {...}"), extract and flatten its fields.
                if key == "error" {
                    if let JsonValue::String(s) = val {
                        // Try parsing the whole string first, then look for embedded JSON
                        let json_str = if s.starts_with('{') {
                            Some(s.as_str())
                        } else {
                            // Find the first '{' and try parsing from there
                            s.find('{').map(|idx| &s[idx..])
                        };
                        if let Some(json_candidate) = json_str {
                            if let Ok(JsonValue::Object(err_obj)) =
                                serde_json::from_str::<JsonValue>(json_candidate)
                            {
                                for (err_key, err_val) in &err_obj {
                                    if !map.contains_key(err_key) {
                                        if let Ok(d) = rhai::serde::to_dynamic(err_val) {
                                            scope.push_dynamic(err_key, d);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Ok(ctx_dynamic) = rhai::serde::to_dynamic(context) {
            scope.push_dynamic("ctx", ctx_dynamic.clone());
            scope.push_dynamic("inputs", ctx_dynamic);
        }

        match engine.eval_with_scope::<Dynamic>(&mut scope, expression) {
            Ok(val) => {
                if let Ok(i) = val.as_int() {
                    Some(i)
                } else if let Ok(f) = val.as_float() {
                    Some(f as i64)
                } else {
                    tracing::warn!(
                        expression = expression,
                        "retry_delay_expression did not return a numeric value"
                    );
                    None
                }
            }
            Err(e) => {
                // L-30: structured event so operators can dashboard
                // retry-delay misconfigurations.
                tracing::warn!(
                    target: "talos_engine",
                    event_kind = "rhai_eval_error",
                    eval_kind = "retry_delay",
                    expression = expression,
                    error = %e,
                    "retry_delay_expression evaluation error"
                );
                None
            }
        }
    })
}

/// Helper function to extract a value from JSON using a Rhai expression as a path.
pub fn extract_json_path(path: &str, context: &JsonValue) -> Option<JsonValue> {
    RHAI_ENGINE.with(|engine| {
        let mut scope = Scope::new();

        // Map JSON fields into script scope.
        if let JsonValue::Object(map) = context {
            for (key, val) in map {
                if let Ok(dynamic) = rhai::serde::to_dynamic(val) {
                    scope.push_dynamic(key, dynamic);
                }
            }
        }

        if let Ok(ctx_dynamic) = rhai::serde::to_dynamic(context) {
            scope.push_dynamic("ctx", ctx_dynamic.clone());
            scope.push_dynamic("inputs", ctx_dynamic);
        }

        engine
            .eval_with_scope::<Dynamic>(&mut scope, path)
            .ok()
            .and_then(|d| rhai::serde::from_dynamic(&d).ok())
    })
}

/// Evaluate a Rhai expression against a JSON context and return the result as a `JsonValue`.
///
/// Used by the `Synthesize` node kind to transform collected parent outputs.
/// The expression receives all top-level context fields as scope variables plus:
///   - `ctx` / `inputs` — the full context as a dynamic object
///
/// Returns `Err` with the Rhai error message if evaluation fails.
pub fn evaluate_expression(expression: &str, context: &JsonValue) -> Result<JsonValue, String> {
    let decoded = decode_html_entities(expression);
    let expression = decoded.as_ref();
    RHAI_ENGINE.with(|engine| {
        let mut scope = Scope::new();

        if let JsonValue::Object(map) = context {
            for (key, val) in map {
                if let Ok(dynamic) = rhai::serde::to_dynamic(val) {
                    scope.push_dynamic(key, dynamic);
                }
            }
        }

        if let Ok(ctx_dynamic) = rhai::serde::to_dynamic(context) {
            scope.push_dynamic("ctx", ctx_dynamic.clone());
            scope.push_dynamic("inputs", ctx_dynamic);
        }

        engine
            .eval_with_scope::<Dynamic>(&mut scope, expression)
            .map_err(|e| e.to_string())
            .and_then(|d| rhai::serde::from_dynamic(&d).map_err(|e| e.to_string()))
    })
}

#[cfg(test)]
mod html_entity_decode_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decode_passthrough_when_no_entities() {
        // The cheap-path optimization (Borrowed) only fires when there's no
        // `&` at all. Inputs containing `&&` will hit the replace path, but
        // since none of the patterns match, the output equals the input.
        let no_amp = "status != 401";
        assert!(matches!(
            decode_html_entities(no_amp),
            std::borrow::Cow::Borrowed(_)
        ));
        assert_eq!(decode_html_entities(no_amp).as_ref(), no_amp);

        // Bare `&&` (Rhai logical-AND) is not an entity and is preserved.
        let bare_double_amp = "status != 401 && status != 403";
        assert_eq!(
            decode_html_entities(bare_double_amp).as_ref(),
            bare_double_amp
        );
    }

    #[test]
    fn decode_amp_lt_gt() {
        assert_eq!(
            decode_html_entities("status != 401 &amp;&amp; status != 403").as_ref(),
            "status != 401 && status != 403"
        );
        assert_eq!(decode_html_entities("a &lt; b").as_ref(), "a < b");
        assert_eq!(decode_html_entities("a &gt;= b").as_ref(), "a >= b");
    }

    #[test]
    fn decode_quote_apos_numeric() {
        assert_eq!(
            decode_html_entities("name == &quot;foo&quot;").as_ref(),
            "name == \"foo\""
        );
        assert_eq!(
            decode_html_entities("name == &apos;foo&apos;").as_ref(),
            "name == 'foo'"
        );
        assert_eq!(
            decode_html_entities("name == &#39;foo&#39;").as_ref(),
            "name == 'foo'"
        );
    }

    /// The user's reported bug: an encoded retry_condition silently failed
    /// to parse and the safe-default ("retry on any error") fired. With the
    /// decode in place, the expression evaluates to the intended boolean.
    #[test]
    fn evaluate_condition_decodes_html_entities() {
        let ctx = json!({"status": 500});
        // 500 != 401 AND 500 != 403 → true (i.e., should retry)
        assert!(evaluate_condition(
            "status != 401 &amp;&amp; status != 403",
            &ctx
        ));
        // status == 401 → both clauses false
        let ctx = json!({"status": 401});
        assert!(!evaluate_condition(
            "status != 401 &amp;&amp; status != 403",
            &ctx
        ));
    }

    #[test]
    fn evaluate_rhai_to_i64_decodes_html_entities() {
        let ctx = json!({"x": 5});
        // (5 < 10) ? 100 : 200 with `<` encoded as `&lt;`
        assert_eq!(
            evaluate_rhai_to_i64("if x &lt; 10 { 100 } else { 200 }", &ctx),
            Some(100)
        );
    }

    // MCP-465: parity tests between `evaluate_condition` (edge evaluator,
    // returns bool, fails to false) and `evaluate_condition_with_error`
    // (used by both the `test_condition` MCP preview AND by
    // `talos-actor-policies::evaluate` at runtime). Before the fix these
    // diverged on `__error` handling and on heuristic precedence.

    #[test]
    fn with_error_detects_double_underscore_error_key() {
        // Real evaluator iterates ["__error", "error"]; preview path used
        // to only check "error", missing the canonical engine envelope.
        let ctx = json!({ "__error": "module timeout after 30s" });
        assert!(evaluate_condition("is_error", &ctx));
        assert_eq!(
            evaluate_condition_with_error("is_error", &ctx),
            Ok(true),
            "preview/policy path must agree with edge evaluator on __error",
        );
        assert_eq!(
            evaluate_condition_with_error(
                r#"error_message.contains("timeout")"#,
                &ctx,
            ),
            Ok(true),
        );
    }

    #[test]
    fn with_error_treats_null_error_as_success() {
        // `{"error": null}` is the success envelope database-query emits.
        // Must NOT trip is_error.
        let ctx = json!({ "error": null });
        assert!(!evaluate_condition("is_error", &ctx));
        assert_eq!(
            evaluate_condition_with_error("is_error", &ctx),
            Ok(false),
        );
    }

    #[test]
    fn with_error_heuristic_overrides_payload_is_error() {
        // Pre-fix bug: payload-provided `is_error: false` won over the
        // heuristic that detected an error in `__error`. That meant a
        // module could mask itself as "not an error" by emitting
        // `{"is_error": false, "__error": "boom"}` and the preview
        // would say `is_error == false`, but the edge evaluator at
        // runtime would route as error.
        let ctx = json!({
            "is_error": false,
            "__error": "boom",
        });
        // Real evaluator: heuristic wins → is_error becomes true.
        assert!(evaluate_condition("is_error", &ctx));
        // Preview must agree.
        assert_eq!(
            evaluate_condition_with_error("is_error", &ctx),
            Ok(true),
            "heuristic must override payload is_error in preview/policy path",
        );
    }

    #[test]
    fn with_error_non_string_error_value_counts_as_error() {
        // `{"error": {"code": 500}}` — non-string error value should
        // still trigger is_error in both evaluators.
        let ctx = json!({ "error": { "code": 500, "msg": "fail" } });
        assert!(evaluate_condition("is_error", &ctx));
        assert_eq!(
            evaluate_condition_with_error("is_error", &ctx),
            Ok(true),
        );
    }
}

/// MCP-1139 (2026-05-16): bare-string error heuristic.
#[cfg(test)]
mod looks_like_error_string_tests {
    use super::looks_like_error_string;

    #[test]
    fn matches_short_error_phrases() {
        assert!(looks_like_error_string("Error: timeout"));
        assert!(looks_like_error_string("HTTP request failed"));
        assert!(looks_like_error_string("ERROR")); // case-insensitive via lowercase
        assert!(looks_like_error_string("Connection FAILED"));
    }

    #[test]
    fn rejects_clean_strings() {
        assert!(!looks_like_error_string(""));
        assert!(!looks_like_error_string("ok"));
        assert!(!looks_like_error_string("Response received successfully"));
    }

    #[test]
    fn matches_when_token_in_first_4kib() {
        // Token at byte 0 of a 1 MB string → match.
        let mut s = String::with_capacity(1_000_000);
        s.push_str("Error: upstream timed out\n");
        s.push_str(&"x".repeat(1_000_000 - s.len()));
        assert!(looks_like_error_string(&s));
    }

    #[test]
    fn skips_token_buried_past_cap() {
        // Token at byte 8000 (past the 4 KiB cap) → no match. This
        // trades off matching pathological-position tokens for bounded
        // per-call cost. Real-world error messages put the token
        // early; the heuristic is for `"Error: ..."` shape, not for
        // megabyte-long payloads that happen to mention "error" deep
        // inside their body.
        let mut s = "x".repeat(8000);
        s.push_str("error: never matched");
        assert!(!looks_like_error_string(&s));
    }

    #[test]
    fn handles_utf8_boundary_at_cap() {
        // Multi-byte UTF-8 char straddling byte 4096 must not panic.
        // The '€' is 3 bytes; place a chain so one boundary lands on a
        // continuation byte.
        let prefix = "x".repeat(4094); // bytes 0..4094 ASCII
        let mut s = String::from(prefix);
        s.push('€'); // 3 bytes: starts at 4094, ends at 4097 — boundary 4095 + 4096 are inside the char
        s.push_str(" error after"); // ASCII tail
        // Walk-back from 4096 to 4094 lands on the start of '€' — &s[..4094]
        // doesn't contain "error", so we expect false (no match).
        // The point of this test is that we DON'T panic.
        let _ = looks_like_error_string(&s);
    }

    #[test]
    fn handles_megabyte_input_without_alloc_explosion() {
        // Smoke test: 5 MB input should return quickly because we cap
        // the lowercase clone at 4 KiB. If this test ever hangs the
        // cap got dropped accidentally.
        let s = "x".repeat(5 * 1024 * 1024);
        assert!(!looks_like_error_string(&s));
    }
}
