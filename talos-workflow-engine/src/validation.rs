//! Lightweight schema validators.
//!
//! These are invoked at graph-load time and dispatch time to reject
//! malformed per-node configuration before it reaches a worker. They
//! intentionally cover only structural checks a regex engine can
//! express — semantic validation (is this secret path allowlisted?
//! does this URL match a capability scope?) lives in the worker's
//! sandbox.

use std::sync::LazyLock;

use dashmap::DashMap;

/// Memoized compile cache for `validate_config_patterns`. Keyed by
/// the exact `pattern` string (each value ≤ `MAX_PATTERN_LEN` bytes via the
/// gate inside `validate_config_patterns`).
///
/// 2026-05-28 audit Perf#5: pre-fix every graph load + every dispatch
/// re-compiled every property's regex. A workflow with N nodes × M
/// keyed patterns × P graph loads pays O(N × M × P) regex compiles.
///
/// Stores `Result<Regex, String>` so a malformed pattern's error
/// is cached too — second-load doesn't re-pay the parse cost just to
/// produce the same error.
static PATTERN_CACHE: LazyLock<DashMap<String, Result<regex::Regex, String>>> =
    LazyLock::new(DashMap::new);

/// Entry-count cap on `PATTERN_CACHE`. The patterns come from user-created
/// workflow/module `config_schema`s, NOT just operators — so the original
/// "well-bounded by the workflow set" assumption doesn't hold against an
/// attacker submitting many distinct patterns (each ≤1 KiB string + a compiled
/// Regex). This is the holdout from the MCP-1146 cache-bounding sweep, which
/// already capped the CSRF-grace / bcrypt-verify / refresh-rate caches.
const PATTERN_CACHE_MAX_ENTRIES: usize = 10_000;

/// Compile a regex via the memoizing cache. Returns the compiled
/// regex on success, or a clone of the cached error string on failure.
fn cached_regex(pattern: &str) -> Result<regex::Regex, String> {
    if let Some(entry) = PATTERN_CACHE.get(pattern) {
        return entry.clone();
    }
    let result = regex::Regex::new(pattern).map_err(|e| e.to_string());
    // Bound the cache. Unlike the TTL-backed caches (CSRF grace / bcrypt /
    // refresh-rate) there's no sweep — a compiled regex never expires — so
    // skip-on-full would permanently stop caching hot patterns once an attacker
    // filled it. A clear-on-full generational reset is the self-healing
    // equivalent: memory stays bounded and the working set recompiles +
    // repopulates. Racy overshoot between the len() check and insert is
    // acceptable (defense-in-depth, not a strict boundary).
    if PATTERN_CACHE.len() >= PATTERN_CACHE_MAX_ENTRIES {
        tracing::warn!(
            target: "talos_workflow_engine",
            event_kind = "pattern_cache_cap_hit",
            size = PATTERN_CACHE.len(),
            cap = PATTERN_CACHE_MAX_ENTRIES,
            "regex pattern cache at capacity; clearing (working set will recompile + repopulate)"
        );
        PATTERN_CACHE.clear();
    }
    PATTERN_CACHE.insert(pattern.to_string(), result.clone());
    result
}

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
                // Perf#5 follow-up: route through the memoizing cache
                // so repeated graph loads of the same workflow don't
                // re-pay the O(pattern_size) compile cost per-key
                // per-dispatch.
                let re = cached_regex(pattern).map_err(|e| {
                    format!("Config key '{}' pattern is not a valid regex: {}", key, e)
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

#[cfg(test)]
mod cache_bound_tests {
    use super::{cached_regex, PATTERN_CACHE, PATTERN_CACHE_MAX_ENTRIES};

    /// The memo cache must never exceed its cap, even when fed far more
    /// distinct patterns than the cap allows (the attacker-submits-many-
    /// distinct-config_schema-patterns vector). Correctness is preserved
    /// across the clear-on-full reset.
    #[test]
    fn pattern_cache_stays_bounded_under_distinct_pattern_flood() {
        PATTERN_CACHE.clear();
        for i in 0..(PATTERN_CACHE_MAX_ENTRIES + 500) {
            let _ = cached_regex(&format!("^pat_{i}$"));
            assert!(
                PATTERN_CACHE.len() <= PATTERN_CACHE_MAX_ENTRIES,
                "PATTERN_CACHE exceeded cap at i={i}: len={}",
                PATTERN_CACHE.len()
            );
        }
        // Compilation still works after the reset(s).
        assert!(cached_regex("^abc$").is_ok());
        assert!(cached_regex("(unclosed").is_err());
        PATTERN_CACHE.clear();
    }
}
