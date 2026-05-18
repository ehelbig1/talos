//! Rhai expression evaluation scoped to actor-policy trigger conditions.
//!
//! Reuses the existing thread-local sandboxed engine from
//! `talos_engine::rhai_helpers` so we inherit its security posture:
//! - `max_operations` cap
//! - `eval` / `import` disabled
//! - `DummyModuleResolver`
//!
//! The only thing we add on top is a narrow context scope populated
//! from `PolicyEvent::to_rhai_context()`.

use anyhow::Result;

use talos_engine::rhai_helpers::evaluate_condition_with_error;

use super::types::PolicyEvent;

/// Compile-time syntax + safety check for a user-supplied trigger
/// condition. Called from `handle_add_approval_policy` so broken
/// expressions don't land in the DB where they'd silently evaluate to
/// false forever at runtime.
///
/// Matches the existing validation in `mcp/actor.rs` for
/// `trigger_condition` — disallow `eval` and `import`, and ensure the
/// expression compiles.
// MCP-908 (2026-05-14): wired into `talos_mcp_handlers::actor::
// handle_add_approval_policy` so the MCP-510 word-boundary improvements
// (matching `eval(` only when preceded by a non-identifier byte —
// preventing false-positives on `retrieval_count` / `important_field` /
// `level` etc.) flow into the live policy-save path. Pre-fix the
// handler re-implemented the eval/import/syntax trio inline with
// simple substring matching, which diverged from the canonical
// helper. Future callers (e.g. a GraphQL `addActorApprovalPolicy`
// mutation) can re-use this same helper.
pub fn validate_expression(expr: &str) -> Result<()> {
    // MCP-510: word-boundary checks instead of bare `contains`.
    // Pre-fix `expr.contains("eval")` flagged legitimate identifiers
    // that just happened to contain the substring:
    //   * `retrieval_count > 0`   — contains "eval" inside "retrieval"
    //   * `important_field == 1`  — contains "import" inside "important"
    //   * `level > 5`             — contains "evel" (false-near; passes)
    // Operators writing such conditions got "may not use 'eval'" errors
    // that made no sense given their source. The sandboxed engine
    // already disables `eval` / `import` (see module doc); this check
    // is operator-feedback belt-and-suspenders and shouldn't be more
    // restrictive than the engine itself.
    //
    // `eval` is a Rhai function — match `<non-ident><eval><whitespace>*(`.
    // `import` is a Rhai keyword — match `<non-ident><import><non-ident>`.
    if contains_function_call(expr, "eval") {
        anyhow::bail!(
            "trigger_condition may not call eval() — approval conditions must be pure Rhai expressions"
        );
    }
    if contains_keyword(expr, "import") {
        anyhow::bail!(
            "trigger_condition may not use the 'import' keyword — approval conditions must be pure Rhai expressions"
        );
    }
    // Quick parse round-trip. We evaluate against an empty context —
    // any runtime variable lookup returns "not found" which is fine
    // for a syntax-only check.
    let dummy_ctx = serde_json::json!({});
    match evaluate_condition_with_error(expr, &dummy_ctx) {
        Ok(_) => Ok(()),
        // Allow runtime "variable not found" — that's expected in a
        // no-context compile check. Only reject genuine syntax errors.
        Err(e) if is_syntax_error(&e) => Err(anyhow::anyhow!(
            "trigger_condition is not valid Rhai syntax: {e}"
        )),
        Err(_) => Ok(()),
    }
}

/// `true` when `expr` contains a call to `fname` outside of identifier
/// context. Detects `eval(...)` but NOT `retrieval(...)` or
/// `my_eval_value > 0`. `fname` must be ASCII.
fn contains_function_call(expr: &str, fname: &str) -> bool {
    let bytes = expr.as_bytes();
    let flen = fname.len();
    let mut search_from = 0;
    while let Some(rel_idx) = expr[search_from..].find(fname) {
        let start = search_from + rel_idx;
        let end = start + flen;
        // Left boundary: previous byte must not be an identifier char.
        let left_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
        // Right boundary: skip whitespace, then require `(`.
        let mut probe = end;
        while probe < bytes.len() && (bytes[probe] as char).is_ascii_whitespace() {
            probe += 1;
        }
        let right_ok = probe < bytes.len() && bytes[probe] == b'(';
        if left_ok && right_ok {
            return true;
        }
        search_from = start + 1; // continue scanning
    }
    false
}

/// `true` when `expr` contains `kw` as a standalone keyword (both
/// boundaries non-identifier). Detects `import "foo"` but NOT
/// `important_field == 1`. `kw` must be ASCII.
fn contains_keyword(expr: &str, kw: &str) -> bool {
    let bytes = expr.as_bytes();
    let klen = kw.len();
    let mut search_from = 0;
    while let Some(rel_idx) = expr[search_from..].find(kw) {
        let start = search_from + rel_idx;
        let end = start + klen;
        let left_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
        let right_ok = end >= bytes.len() || !is_ident_byte(bytes[end]);
        if left_ok && right_ok {
            return true;
        }
        search_from = start + 1;
    }
    false
}

#[inline]
fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Evaluate a custom Rhai expression against a policy event.
/// Fails closed: any evaluation error (syntax, variable-not-found,
/// operation limit) returns `false`. Callers must not treat errors as
/// policy matches — that would turn a broken expression into a live
/// block.
pub fn evaluate(expr: &str, event: &PolicyEvent) -> bool {
    let ctx = event.to_rhai_context();
    match evaluate_condition_with_error(expr, &ctx) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                target: "actor_policies",
                expr = %expr,
                error = %e,
                event = event.kind(),
                "Rhai policy expression evaluation failed — treating as not-matched (fail closed)"
            );
            false
        }
    }
}

#[allow(dead_code)]
fn is_syntax_error(msg: &str) -> bool {
    let lower = msg.to_lowercase();
    lower.contains("parse")
        || lower.contains("syntax")
        || lower.contains("unexpected")
        || lower.contains("expecting")
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn sample_event() -> PolicyEvent {
        PolicyEvent::PublishVersion {
            actor_id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
        }
    }

    #[test]
    fn validate_rejects_eval() {
        assert!(validate_expression("eval(\"true\")").is_err());
    }

    #[test]
    fn validate_rejects_import() {
        assert!(validate_expression("import \"foo\" as f; true").is_err());
    }

    #[test]
    fn validate_accepts_simple() {
        assert!(validate_expression("event == \"publish_version\"").is_ok());
    }

    #[test]
    fn validate_rejects_syntax_error() {
        assert!(validate_expression("this is not rhai !@#").is_err());
    }

    #[test]
    fn evaluate_matches_on_event_string() {
        assert!(evaluate(r#"event == "publish_version""#, &sample_event()));
    }

    #[test]
    fn evaluate_fails_closed_on_unknown_variable() {
        // References an undefined variable — should evaluate to false,
        // NOT propagate an error.
        assert!(!evaluate("undefined_var == true", &sample_event()));
    }

    #[test]
    fn evaluate_fails_closed_on_broken_syntax() {
        // Persisted syntax errors shouldn't panic or match.
        assert!(!evaluate("this is not rhai", &sample_event()));
    }

    /// MCP-510: pre-fix `expr.contains("eval")` rejected any expression
    /// with the substring "eval" anywhere — including legitimate
    /// identifiers like `retrieval_count` or `level`. Operators got a
    /// "may not use 'eval'" error that made no sense given their input.
    #[test]
    fn validate_allows_identifier_containing_eval_substring() {
        // `retrieval_count` literally contains the bytes "eval" at
        // positions 3-6, but isn't a call to eval(). Must pass.
        assert!(validate_expression("retrieval_count > 0").is_ok());
        // `level` contains "eve" — close-but-not-equal substring;
        // historically also a near-miss for the bare contains check.
        assert!(validate_expression("level > 5").is_ok());
        // Real call must still be rejected.
        assert!(validate_expression("eval(\"true\")").is_err());
        // Whitespace between name and paren must still be caught.
        assert!(validate_expression("eval (\"true\")").is_err());
    }

    /// MCP-510: same surface for `import`. The keyword check now uses
    /// word boundaries so `important_field` no longer trips the gate.
    #[test]
    fn validate_allows_identifier_containing_import_substring() {
        assert!(validate_expression("important_field == 1").is_ok());
        assert!(validate_expression("imports_pending == 0").is_ok());
        // The real keyword form still fails.
        assert!(validate_expression("import \"foo\" as f; true").is_err());
    }

    /// MCP-510: regression for the function-call vs name-substring
    /// distinction. `eval_count` is an identifier that ends with the
    /// substring "eval" — but a call like `eval_count(...)` is NOT a
    /// call to `eval`, it's a call to `eval_count`. Must pass.
    /// (Conversely, `eval(...)` with a real boundary must fail.)
    #[test]
    fn validate_distinguishes_eval_call_from_eval_prefixed_call() {
        assert!(validate_expression("eval_count(items) > 0").is_ok());
        assert!(validate_expression("eval(\"1+1\") > 0").is_err());
    }
}
