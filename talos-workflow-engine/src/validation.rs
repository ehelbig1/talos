//! Lightweight schema validators.
//!
//! These are invoked at graph-load time and dispatch time to reject
//! malformed per-node configuration before it reaches a worker. They
//! intentionally cover only structural checks a regex engine can
//! express — semantic validation (is this secret path allowlisted?
//! does this URL match a capability scope?) lives in the worker's
//! sandbox.

/// Validate config values against `pattern` constraints in the
/// `config_schema`.
///
/// Walks `properties` and, for each string property whose schema
/// carries a `pattern` field, checks that the config value matches the
/// regex. Returns `Err` on the first mismatch with a human-readable
/// message; unparseable patterns are logged and skipped (fail-open
/// rather than failing every call on a broken schema).
///
/// # Errors
///
/// Returns `Err(String)` naming the offending config key and pattern
/// when a value does not match. Typical consumer use is
/// `validate_config_patterns(schema, config).map_err(WorkflowEngineError::load_graph)?`.
pub fn validate_config_patterns(
    schema: &serde_json::Value,
    config: &serde_json::Value,
) -> Result<(), String> {
    let properties = match schema.get("properties").and_then(|p| p.as_object()) {
        Some(p) => p,
        None => return Ok(()), // No schema or no properties — skip validation.
    };
    let config_obj = match config.as_object() {
        Some(o) => o,
        None => return Ok(()),
    };

    // MCP-H2: cap operator-authored `pattern` length BEFORE attempting
    // to compile. Rust's regex crate is linear-time (no ReDoS in the
    // exponential sense) but compile cost is O(pattern_size), so a
    // 1 MB literal pattern loaded from a workflow's `config_schema`
    // burns CPU on every graph load. 1 KiB matches the workspace
    // ceiling for operator-supplied regex literals (logger filters,
    // host allowlists, etc.).
    const MAX_PATTERN_LEN: usize = 1024;
    for (key, prop_schema) in properties {
        if let Some(pattern) = prop_schema.get("pattern").and_then(|p| p.as_str()) {
            if pattern.len() > MAX_PATTERN_LEN {
                return Err(format!(
                    "Config key '{}' pattern exceeds {} byte limit",
                    key, MAX_PATTERN_LEN
                ));
            }
            if let Some(value) = config_obj.get(key).and_then(|v| v.as_str()) {
                // MCP-H2: fail CLOSED on regex compile error. Pre-fix
                // a malformed pattern logged a warn and `continue`d,
                // making schema regex bugs invisible to validation
                // callers — every config value would pass even if the
                // schema author intended a strict match. Surface the
                // error so the operator notices on graph load /
                // dispatch and fixes the schema.
                let re = regex::Regex::new(pattern).map_err(|e| {
                    format!(
                        "Config key '{}' pattern is not a valid regex: {}",
                        key, e
                    )
                })?;
                if !re.is_match(value) {
                    return Err(format!(
                        "Config key '{}' value does not match required pattern '{}'",
                        key, pattern
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Cap individual string field lengths on a node output to prevent
/// unbounded LLM-generated outputs from consuming excessive memory
/// when cloned into downstream node inputs and the final aggregated
/// result.
///
/// `__`-prefixed keys are intentionally *not* stripped — several are
/// load-bearing internally (`__memory_write__`, `__fuel_consumed__`,
/// etc.).
pub(crate) fn sanitize_node_output(output: &mut serde_json::Value) {
    /// 10 KiB per string field. A workflow with hundreds of nodes and
    /// unbounded per-field strings can easily OOM the controller.
    const MAX_STRING_FIELD_BYTES: usize = 10240;

    if let Some(obj) = output.as_object_mut() {
        for val in obj.values_mut() {
            if let Some(s) = val.as_str() {
                if s.len() > MAX_STRING_FIELD_BYTES {
                    *val = serde_json::Value::String(format!(
                        "{}...[truncated at {}B]",
                        &s[..MAX_STRING_FIELD_BYTES],
                        MAX_STRING_FIELD_BYTES
                    ));
                }
            }
        }
    }
}
