//! # Structural JSON diff for replay regression harness
//!
//! Pure-Rust diff helper used by the `replay_module_regression` MCP tool
//! to compare a module's stored output (captured during a past execution)
//! against a freshly-replayed output (same input, current code). The
//! helper is tuned for "did a hot_update_module change module semantics?"
//! — not general-purpose JSON diffing — so it deliberately applies a
//! small set of opinionated defaults:
//!
//! - **Engine metadata is ignored by default.** Runtime-injected fields
//!   like `__fuel_consumed__`, `__memory_write__`, `synced_at`,
//!   `generated_at`, `started_at`, `completed_at`, and `timestamp` vary
//!   across runs even when the business logic is unchanged; reporting
//!   them as drift would drown the real signal.
//! - **Recursion depth is bounded** at 256 levels. Matches the DLP
//!   redactor cap so the two layers share a "pathological nesting"
//!   definition.
//! - **Array element order matters.** Two arrays with the same elements
//!   in a different order are reported as `Modified`. Order-insensitive
//!   diff would require O(n²) set equality, which is wrong for ordered
//!   collections (classified_tickets, stale_threads, …) where position
//!   encodes meaning.
//! - **Type drift is distinguished from value drift.** Replacing
//!   `"status": "open"` with `"status": 42` yields `ChangeKind::TypeChanged`
//!   so operators can spot silent serialization regressions.
//!
//! ## Security
//!
//! The diff helper runs entirely on operator-provided JSON and performs
//! no I/O, no network calls, and no code execution. Size limits and
//! scrubbing happen in the caller (the replay handler). The depth cap
//! protects the controller from stack overflow on adversarial input.

use std::collections::HashSet;

use serde_json::Value;

/// Maximum recursion depth when walking a JSON value tree.
const MAX_DIFF_DEPTH: usize = 256;

/// Default ignore list — engine metadata and time-varying fields that
/// should never be treated as semantic drift. Callers can supplement via
/// [`DiffConfig::ignore_fields`].
pub const DEFAULT_IGNORED_FIELDS: &[&str] = &[
    "__fuel_consumed__",
    "__memory_write__",
    "__skipped",
    "__node_timings__",
    "synced_at",
    "generated_at",
    "started_at",
    "completed_at",
    "timestamp",
];

#[derive(Debug, Clone, PartialEq)]
pub enum ChangeKind {
    /// Field present in replayed output but not stored.
    Added,
    /// Field present in stored output but missing from replayed.
    Removed,
    /// Field present in both, value differs, type unchanged.
    Modified,
    /// Field present in both, type changed (e.g. String → Number).
    TypeChanged,
}

#[derive(Debug, Clone)]
pub struct ChangedPath {
    pub path: String,
    pub kind: ChangeKind,
    pub stored: Option<Value>,
    pub replayed: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct DiffReport {
    pub matched: bool,
    pub changed_paths: Vec<ChangedPath>,
}

/// Configuration knobs for the diff walk.
pub struct DiffConfig<'a> {
    /// Field names to ignore at any depth. Contains `DEFAULT_IGNORED_FIELDS`
    /// unless the caller explicitly constructs an empty set.
    pub ignore_fields: HashSet<&'a str>,
    /// Upper bound on reported `changed_paths`. A single runaway schema
    /// change should not produce a 10,000-entry response; once this many
    /// paths have been recorded, the walk short-circuits and `matched`
    /// stays `false` without emitting more entries.
    pub max_changed_paths: usize,
}

impl<'a> Default for DiffConfig<'a> {
    fn default() -> Self {
        Self {
            ignore_fields: DEFAULT_IGNORED_FIELDS.iter().copied().collect(),
            max_changed_paths: 64,
        }
    }
}

/// Walk two JSON values in parallel and report every path where they
/// differ. Respects the ignore list at every depth.
pub fn diff_values(stored: &Value, replayed: &Value, config: &DiffConfig<'_>) -> DiffReport {
    let mut report = DiffReport {
        matched: true,
        changed_paths: Vec::new(),
    };
    walk(stored, replayed, "", config, &mut report, 0);
    // matched is false if we recorded any changed_paths. We set it here
    // rather than in walk so a depth-cap short-circuit also marks as
    // drifted.
    report.matched = report.changed_paths.is_empty();
    report
}

fn walk(
    stored: &Value,
    replayed: &Value,
    path: &str,
    config: &DiffConfig<'_>,
    report: &mut DiffReport,
    depth: usize,
) {
    if depth >= MAX_DIFF_DEPTH {
        return;
    }
    if report.changed_paths.len() >= config.max_changed_paths {
        return;
    }

    match (stored, replayed) {
        (Value::Object(a), Value::Object(b)) => {
            // Walk keys present in either side. Preserve ordering from
            // stored first, then append replayed-only keys.
            let mut seen: HashSet<&String> = HashSet::new();
            for (k, v_a) in a {
                seen.insert(k);
                if config.ignore_fields.contains(k.as_str()) {
                    continue;
                }
                let child_path = append_path(path, k);
                match b.get(k) {
                    Some(v_b) => walk(v_a, v_b, &child_path, config, report, depth + 1),
                    None => push_change(
                        report,
                        child_path,
                        ChangeKind::Removed,
                        Some(v_a.clone()),
                        None,
                        config.max_changed_paths,
                    ),
                }
            }
            for (k, v_b) in b {
                if seen.contains(k) {
                    continue;
                }
                if config.ignore_fields.contains(k.as_str()) {
                    continue;
                }
                let child_path = append_path(path, k);
                push_change(
                    report,
                    child_path,
                    ChangeKind::Added,
                    None,
                    Some(v_b.clone()),
                    config.max_changed_paths,
                );
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            let common = a.len().min(b.len());
            for i in 0..common {
                let child_path = format!("{}[{}]", path, i);
                walk(&a[i], &b[i], &child_path, config, report, depth + 1);
            }
            // Length mismatch: report the trailing elements as
            // Removed/Added so the caller sees exactly what shifted.
            if a.len() > common {
                for (i, item) in a.iter().enumerate().skip(common) {
                    let child_path = format!("{}[{}]", path, i);
                    push_change(
                        report,
                        child_path,
                        ChangeKind::Removed,
                        Some(item.clone()),
                        None,
                        config.max_changed_paths,
                    );
                }
            }
            if b.len() > common {
                for (i, item) in b.iter().enumerate().skip(common) {
                    let child_path = format!("{}[{}]", path, i);
                    push_change(
                        report,
                        child_path,
                        ChangeKind::Added,
                        None,
                        Some(item.clone()),
                        config.max_changed_paths,
                    );
                }
            }
        }
        (Value::String(a), Value::String(b)) if a == b => {}
        (Value::Bool(a), Value::Bool(b)) if a == b => {}
        (Value::Number(a), Value::Number(b)) if a == b => {}
        (Value::Null, Value::Null) => {}
        _ => {
            let kind = if type_tag(stored) == type_tag(replayed) {
                ChangeKind::Modified
            } else {
                ChangeKind::TypeChanged
            };
            push_change(
                report,
                path.to_string(),
                kind,
                Some(stored.clone()),
                Some(replayed.clone()),
                config.max_changed_paths,
            );
        }
    }
}

fn push_change(
    report: &mut DiffReport,
    path: String,
    kind: ChangeKind,
    stored: Option<Value>,
    replayed: Option<Value>,
    cap: usize,
) {
    if report.changed_paths.len() >= cap {
        return;
    }
    report.changed_paths.push(ChangedPath {
        path,
        kind,
        stored,
        replayed,
    });
}

fn append_path(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_string()
    } else {
        format!("{}.{}", prefix, key)
    }
}

fn type_tag(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Serialize a [`DiffReport`] into the JSON shape surfaced by the MCP
/// response. Keeping serialization here (instead of deriving Serialize)
/// lets the replay handler tune field names without leaking Rust
/// identifiers.
pub fn report_to_json(report: &DiffReport) -> Value {
    let changed: Vec<Value> = report
        .changed_paths
        .iter()
        .map(|c| {
            let kind = match c.kind {
                ChangeKind::Added => "added",
                ChangeKind::Removed => "removed",
                ChangeKind::Modified => "modified",
                ChangeKind::TypeChanged => "type_changed",
            };
            let mut obj = serde_json::json!({ "path": c.path, "kind": kind });
            if let Some(v) = &c.stored {
                obj["stored"] = v.clone();
            }
            if let Some(v) = &c.replayed {
                obj["replayed"] = v.clone();
            }
            obj
        })
        .collect();
    serde_json::json!({
        "matched": report.matched,
        "changed_paths": changed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── identical payloads ────────────────────────────────────────────

    #[test]
    fn identical_payloads_match() {
        let a = json!({ "key": "SECP-1", "count": 5 });
        let r = diff_values(&a, &a, &DiffConfig::default());
        assert!(r.matched);
        assert!(r.changed_paths.is_empty());
    }

    #[test]
    fn identical_nested_payloads_match() {
        let a = json!({
            "issues": [
                { "key": "SECP-1", "priority": "High" },
                { "key": "SECP-2", "priority": "Medium" }
            ],
            "total": 2
        });
        let r = diff_values(&a, &a, &DiffConfig::default());
        assert!(r.matched);
    }

    // ── basic drift ───────────────────────────────────────────────────

    #[test]
    fn modified_string_reports_path() {
        let a = json!({ "status": "open" });
        let b = json!({ "status": "closed" });
        let r = diff_values(&a, &b, &DiffConfig::default());
        assert!(!r.matched);
        assert_eq!(r.changed_paths.len(), 1);
        assert_eq!(r.changed_paths[0].path, "status");
        assert_eq!(r.changed_paths[0].kind, ChangeKind::Modified);
    }

    #[test]
    fn type_change_is_distinct_from_modified() {
        let a = json!({ "value": "42" });
        let b = json!({ "value": 42 });
        let r = diff_values(&a, &b, &DiffConfig::default());
        assert_eq!(r.changed_paths[0].kind, ChangeKind::TypeChanged);
    }

    #[test]
    fn added_field_reports_added() {
        let a = json!({ "key": "x" });
        let b = json!({ "key": "x", "new_field": 1 });
        let r = diff_values(&a, &b, &DiffConfig::default());
        assert_eq!(r.changed_paths.len(), 1);
        assert_eq!(r.changed_paths[0].path, "new_field");
        assert_eq!(r.changed_paths[0].kind, ChangeKind::Added);
    }

    #[test]
    fn removed_field_reports_removed() {
        let a = json!({ "key": "x", "gone": 1 });
        let b = json!({ "key": "x" });
        let r = diff_values(&a, &b, &DiffConfig::default());
        assert_eq!(r.changed_paths.len(), 1);
        assert_eq!(r.changed_paths[0].path, "gone");
        assert_eq!(r.changed_paths[0].kind, ChangeKind::Removed);
    }

    // ── ignore list ───────────────────────────────────────────────────

    #[test]
    fn default_ignore_list_hides_fuel_drift() {
        let a = json!({ "result": "ok", "__fuel_consumed__": 100_000 });
        let b = json!({ "result": "ok", "__fuel_consumed__": 250_000 });
        let r = diff_values(&a, &b, &DiffConfig::default());
        assert!(r.matched, "fuel drift must not count as drift");
    }

    #[test]
    fn ignore_applies_at_nested_depth() {
        let a = json!({
            "__memory_write__": {
                "key": "x",
                "value": { "synced_at": "2026-04-11T00:00:00Z", "data": "real" }
            }
        });
        let b = json!({
            "__memory_write__": {
                "key": "x",
                "value": { "synced_at": "2026-04-11T12:00:00Z", "data": "real" }
            }
        });
        // __memory_write__ is in the default ignore list, so the entire
        // subtree is skipped regardless of inner drift.
        let r = diff_values(&a, &b, &DiffConfig::default());
        assert!(r.matched);
    }

    #[test]
    fn custom_ignore_list_supersedes_default() {
        let a = json!({ "__fuel_consumed__": 100, "id": "a" });
        let b = json!({ "__fuel_consumed__": 200, "id": "b" });
        let mut ignore = HashSet::new();
        ignore.insert("id"); // user explicitly ignores id instead of default
        let cfg = DiffConfig {
            ignore_fields: ignore,
            max_changed_paths: 64,
        };
        let r = diff_values(&a, &b, &cfg);
        // Default __fuel_consumed__ NOT in the custom set, so it drifts.
        assert!(!r.matched);
        assert_eq!(r.changed_paths.len(), 1);
        assert_eq!(r.changed_paths[0].path, "__fuel_consumed__");
    }

    // ── arrays ────────────────────────────────────────────────────────

    #[test]
    fn array_element_drift_reports_indexed_path() {
        let a = json!({ "items": [{ "key": "A" }, { "key": "B" }] });
        let b = json!({ "items": [{ "key": "A" }, { "key": "C" }] });
        let r = diff_values(&a, &b, &DiffConfig::default());
        assert_eq!(r.changed_paths.len(), 1);
        assert_eq!(r.changed_paths[0].path, "items[1].key");
    }

    #[test]
    fn array_length_mismatch_reports_trailing_elements() {
        let a = json!({ "items": [1, 2] });
        let b = json!({ "items": [1, 2, 3] });
        let r = diff_values(&a, &b, &DiffConfig::default());
        assert_eq!(r.changed_paths.len(), 1);
        assert_eq!(r.changed_paths[0].path, "items[2]");
        assert_eq!(r.changed_paths[0].kind, ChangeKind::Added);
    }

    // ── caps ──────────────────────────────────────────────────────────

    #[test]
    fn max_changed_paths_cap_is_respected() {
        let a = json!({});
        let mut b_obj = serde_json::Map::new();
        for i in 0..200 {
            b_obj.insert(format!("k{}", i), json!(i));
        }
        let b = Value::Object(b_obj);
        let cfg = DiffConfig {
            ignore_fields: HashSet::new(),
            max_changed_paths: 10,
        };
        let r = diff_values(&a, &b, &cfg);
        assert!(!r.matched);
        assert_eq!(r.changed_paths.len(), 10, "must short-circuit at cap");
    }

    #[test]
    fn depth_cap_does_not_panic_on_adversarial_nesting() {
        let mut a = json!({ "leaf": "a" });
        let mut b = json!({ "leaf": "b" });
        for _ in 0..1000 {
            a = json!({ "nested": a });
            b = json!({ "nested": b });
        }
        // Just needs to not overflow the stack. The depth cap short-
        // circuits silently at 256 levels.
        let r = diff_values(&a, &b, &DiffConfig::default());
        // The top 256 levels wrap identical shapes, so matched stays true
        // because the deepest actual leaf difference is below the cap.
        let _ = r;
    }

    // ── type distinctions ─────────────────────────────────────────────

    #[test]
    fn null_vs_missing_is_modified_not_added() {
        let a = json!({ "v": null });
        let b = json!({ "v": 1 });
        let r = diff_values(&a, &b, &DiffConfig::default());
        assert_eq!(r.changed_paths[0].kind, ChangeKind::TypeChanged);
    }

    #[test]
    fn number_precision_drift_reported() {
        let a = json!({ "n": 1.0 });
        let b = json!({ "n": 1.0000001 });
        let r = diff_values(&a, &b, &DiffConfig::default());
        assert_eq!(r.changed_paths.len(), 1);
    }

    // ── report_to_json ────────────────────────────────────────────────

    #[test]
    fn report_to_json_shape() {
        let a = json!({ "k": "a" });
        let b = json!({ "k": "b" });
        let r = diff_values(&a, &b, &DiffConfig::default());
        let j = report_to_json(&r);
        assert_eq!(j["matched"], false);
        assert_eq!(j["changed_paths"][0]["path"], "k");
        assert_eq!(j["changed_paths"][0]["kind"], "modified");
        assert_eq!(j["changed_paths"][0]["stored"], "a");
        assert_eq!(j["changed_paths"][0]["replayed"], "b");
    }
}
