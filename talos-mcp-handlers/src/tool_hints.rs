//! Authoring-hint ↔ tool-schema conformance.
//!
//! Many handlers return *authoring hints* — `{"action", "tool", "args",
//! "note"}` objects under `next_steps_checklist` / `improvement_actions` /
//! `remediation_steps` / `fix_commands` — that tell the caller which tool to
//! call next and with which arguments. They are the platform's own guidance,
//! and a caller copy-pastes them verbatim.
//!
//! A hint is therefore a SECOND, hand-maintained copy of a tool's API, and it
//! drifts silently: nothing type-checks a `serde_json::json!` literal against
//! the tool schema it describes. The failure mode is worse than no hint at
//! all — `add_node_to_workflow` told callers to call `add_edge` with
//! `source_node_id` / `target_node_id` when `add_edge` declares `source` /
//! `target`, so the suggested call failed and taught the wrong API. The name
//! was not universally wrong: `duplicate_node` and `copy_node` genuinely
//! declare `source_node_id`, which is exactly why a blind rename would have
//! broken two working tools.
//!
//! This module is the enforcement point. The schemas are reachable in-crate
//! (every handler module exposes `pub fn tool_schemas()`), so the class is
//! checkable rather than the instances being patchable one at a time:
//!
//! * [`hint_defects`] walks any handler response and reports every hint whose
//!   `tool` is not a declared tool, or whose `args` carry a key that tool does
//!   not declare. Handlers whose hint construction is a pure function are
//!   covered dynamically by feeding the built value through it.
//! * `every_tool_literal_in_crate_sources_names_a_declared_tool` and
//!   `every_literal_hint_args_key_is_declared_by_the_tool_it_names` cover the
//!   same two properties for EVERY hint in the crate — including ones built
//!   inline inside an async DB-backed handler that no unit test can reach — by
//!   scanning this crate's own sources for `"tool": "<literal>"` and the
//!   literal keys of the `args` block beneath it.
//!
//! **Both legs were run against the ORIGINAL tree before being trusted** — a
//! `git show HEAD:talos-mcp-handlers/src/*.rs` dump, not a synthetic edit.
//! On it the tool leg reports **12** undeclared names with 0 false positives
//! (`advanced.rs` ×2 — `get_execution_history`, `create_alert_rule`;
//! `workflows.rs` ×10 — six `set_secret`, removed from MCP by MCP-1201, plus
//! `update_workflow_graph`, two `reinstall_module_from_catalog` variants, and
//! one field holding prose rather than a tool name), and the args leg pairs
//! **20** hints and reports exactly **2** — `add_edge(source_node_id)` and
//! `add_edge(target_node_id)`, the defect this module exists for. Both are 0
//! on the fixed tree, and both fire again on that defect reintroduced by
//! mutation. Two further undeclared names (`get_workflow_raw_json`,
//! `get_execution_delta` — deprecated aliases that still dispatch but are not
//! in `tools/list`, so a client driven by `tools/list` cannot call them) were
//! found in dependency crates by the dynamic leg.
//!
//! An earlier, weaker version of the source scan also reported `cycle` — a
//! `contains("cycle")` call ARGUMENT read as a value. That is why the scanner
//! now takes only value-position literals, pinned by
//! `tool_literal_scanner_reads_value_position_only`.
//!
//! **Stated limits, measured rather than assumed.**
//! * The source scan is TEXTUAL and per-line. A tool name assembled at
//!   runtime, or read from a constant in another file, is invisible; so is a
//!   `"tool":` whose value is a variable. All are the safe direction (a miss,
//!   never a false accusation).
//! * It covers only THIS crate's `src/`. Hints built in
//!   `talos-workflow-creation-helpers`, `talos-failure-analysis-service` and
//!   `talos-hygiene-service` are covered instead by the dynamic leg, which
//!   calls their pure builders — an inventory that can go stale if one of
//!   those crates grows a hint behind a DB-backed path.
//! * The args leg sees only LITERAL keys, and pairs an args block with the
//!   nearest tool literal at most 12 lines above it. Every one of the 22
//!   pairings on this tree was hand-verified; a hint that splits the two
//!   further apart, or builds its args map in Rust, is not checked.
//! * `hint_defects` proves an args key is DECLARED, never that it is
//!   correctly typed. It deliberately does NOT require every `required` key to
//!   be present: several hints are legitimately partial — the add-node
//!   checklist names `update_node_config(workflow_id, node_id)` and leaves
//!   `config` for the caller to fill in — so a required-keys leg would fire on
//!   correct guidance.
//! * A hint that names a real tool with real parameters can still be *wrong
//!   advice*. This checks the suggested call is well-formed, never that it is
//!   the right call.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use serde_json::Value;

/// The canonical list of this crate's static tool-schema modules.
///
/// Single source of truth for schema introspection. `static_tool_count()` in
/// `lib.rs` deliberately keeps its own independent sum rather than delegating
/// here — `advertised_count_matches_static_tool_count` compares the two, and a
/// pin whose expected value is derived from the pinned value proves nothing.
pub(crate) fn all_static_schema_modules() -> Vec<(&'static str, Vec<Value>)> {
    vec![
        ("advanced", crate::advanced::tool_schemas()),
        ("platform", crate::platform::tool_schemas()),
        ("search", crate::search::tool_schemas()),
        ("workflows", crate::workflows::tool_schemas()),
        ("modules", crate::modules::tool_schemas()),
        ("sandbox", crate::sandbox::tool_schemas()),
        ("executions", crate::executions::tool_schemas()),
        ("actor", crate::actor::tool_schemas()),
        ("analytics", crate::analytics::tool_schemas()),
        ("secrets", crate::secrets::tool_schemas()),
        ("schedules", crate::schedules::tool_schemas()),
        ("versions", crate::versions::tool_schemas()),
        ("webhooks", crate::webhooks::tool_schemas()),
        ("graph", crate::graph::tool_schemas()),
        ("knowledge_graph", crate::knowledge_graph::tool_schemas()),
        ("alerts", crate::alerts::tool_schemas()),
        ("ops_alerts", crate::ops_alerts::tool_schemas()),
        ("schemas", crate::schemas::tool_schemas()),
        ("ollama", crate::ollama::tool_schemas()),
        ("ml", crate::ml::tool_schemas()),
        ("evaluation", crate::evaluation::tool_schemas()),
    ]
}

/// Declared tool name → the set of property names its `inputSchema` declares.
///
/// Built once from the live schemas, so it can never disagree with what
/// `tools/list` advertises.
pub fn declared_tool_params() -> &'static BTreeMap<String, BTreeSet<String>> {
    static PARAMS: LazyLock<BTreeMap<String, BTreeSet<String>>> = LazyLock::new(|| {
        let mut map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (_module, schemas) in all_static_schema_modules() {
            for schema in schemas {
                let Some(name) = schema.get("name").and_then(|n| n.as_str()) else {
                    continue;
                };
                let props = schema
                    .get("inputSchema")
                    .and_then(|s| s.get("properties"))
                    .and_then(|p| p.as_object())
                    .map(|obj| obj.keys().cloned().collect::<BTreeSet<String>>())
                    .unwrap_or_default();
                map.insert(name.to_string(), props);
            }
        }
        map
    });
    &PARAMS
}

/// True when `name` is a tool this server advertises in `tools/list`.
///
/// Catalog-template tools are registered dynamically and are NOT included —
/// no authoring hint names one, and treating an unknown name as declared would
/// defeat the check.
pub fn is_declared_tool(name: &str) -> bool {
    declared_tool_params().contains_key(name)
}

/// What is wrong with one authoring hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HintDefect {
    /// `tool` names something `tools/list` does not advertise. The caller gets
    /// -32601 (or, through a proxy, "tool not found") if they follow it.
    UnknownTool { tool: String },
    /// `args` carries a key the named tool does not declare. The caller's
    /// copy-pasted call is rejected or silently ignores the argument.
    UndeclaredArg { tool: String, arg: String },
}

impl std::fmt::Display for HintDefect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HintDefect::UnknownTool { tool } => {
                write!(f, "hint names undeclared tool `{tool}`")
            }
            HintDefect::UndeclaredArg { tool, arg } => {
                write!(f, "hint for `{tool}` passes undeclared arg `{arg}`")
            }
        }
    }
}

/// Argument-bearing keys used by authoring hints across the platform.
///
/// `args` is the house name; `arguments` and `prefilled_args` are older
/// spellings still emitted by the hygiene and advanced surfaces. All three are
/// checked so a rename can't slip a hint past this.
const ARG_KEYS: &[&str] = &["args", "arguments", "prefilled_args"];

/// Every conformance defect in `value`, found by walking it recursively.
///
/// A *hint* is any JSON object with a string `tool` field. An empty or null
/// `tool` is the platform's "no tool can do this — do it in the dashboard"
/// sentinel (see MCP-1201, secret writes) and is deliberately not a defect.
pub fn hint_defects(value: &Value) -> Vec<HintDefect> {
    let mut out = Vec::new();
    collect_hint_defects(value, &mut out);
    out
}

fn collect_hint_defects(value: &Value, out: &mut Vec<HintDefect>) {
    match value {
        Value::Object(map) => {
            if let Some(tool) = map.get("tool").and_then(|t| t.as_str()) {
                if !tool.is_empty() {
                    if is_declared_tool(tool) {
                        let declared = &declared_tool_params()[tool];
                        for key in ARG_KEYS {
                            if let Some(args) = map.get(*key).and_then(|a| a.as_object()) {
                                for arg in args.keys() {
                                    if !declared.contains(arg.as_str()) {
                                        out.push(HintDefect::UndeclaredArg {
                                            tool: tool.to_string(),
                                            arg: arg.clone(),
                                        });
                                    }
                                }
                            }
                        }
                    } else {
                        out.push(HintDefect::UnknownTool {
                            tool: tool.to_string(),
                        });
                    }
                }
            }
            for v in map.values() {
                collect_hint_defects(v, out);
            }
        }
        Value::Array(items) => {
            for v in items {
                collect_hint_defects(v, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src_dir() -> std::path::PathBuf {
        // Same-crate source introspection: CARGO_MANIFEST_DIR is this crate's
        // root at compile time, so the path survives workspace relocation.
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
    }

    /// Every double-quoted literal in VALUE position after a `"tool":` key on
    /// one source line.
    ///
    /// Written to capture BOTH arms of the `"tool": if c { "a" } else { "b" }`
    /// shape a handler uses, which is why it does not stop at the first
    /// literal. A literal whose preceding non-space character is `(` or `,` is
    /// a CALL ARGUMENT, not a value — `if issue.contains("cycle") { … }` would
    /// otherwise report `cycle` as an undeclared tool, which it observably did
    /// on first run.
    fn tool_literals_on_line(line: &str) -> Vec<String> {
        let trimmed = line.trim_start();
        // Comment lines quote the banned names when explaining them.
        if trimmed.starts_with("//") {
            return Vec::new();
        }
        let Some(idx) = line.find("\"tool\":") else {
            return Vec::new();
        };
        let scan_from = idx + "\"tool\":".len();
        let mut cursor = scan_from;
        let mut out = Vec::new();
        while let Some(open) = line[cursor..].find('"') {
            let open = cursor + open;
            let Some(close) = line[open + 1..].find('"') else {
                break;
            };
            let close = open + 1 + close;
            let preceding = line[scan_from..open].trim_end().chars().next_back();
            if !matches!(preceding, Some('(') | Some(',')) {
                out.push(line[open + 1..close].to_string());
            }
            cursor = close + 1;
        }
        out
    }

    /// The scanner's own behaviour, pinned. Its two failure directions are a
    /// MISS (a real hint it does not see) and a FALSE POSITIVE (a call
    /// argument read as a tool name); both are exercised here.
    #[test]
    fn tool_literal_scanner_reads_value_position_only() {
        assert_eq!(
            tool_literals_on_line(r#"    "tool": "add_edge","#),
            vec!["add_edge".to_string()]
        );
        // Both arms of a conditional tool name are hints and both are checked.
        assert_eq!(
            tool_literals_on_line(r#""tool": if c { "remove_edge" } else { "swap_node_module" },"#),
            vec!["remove_edge".to_string(), "swap_node_module".to_string()]
        );
        // A call argument in the condition is NOT a tool name.
        assert_eq!(
            tool_literals_on_line(
                r#""tool": if issue.contains("cycle") { "remove_edge" } else { "swap_node_module" },"#
            ),
            vec!["remove_edge".to_string(), "swap_node_module".to_string()]
        );
        // Comments explaining the rule must not self-report.
        assert!(tool_literals_on_line(r#"    // "tool": "set_secret" was removed"#).is_empty());
        // A non-literal tool value yields nothing to check — a stated limit.
        assert!(tool_literals_on_line(r#"    "tool": null,"#).is_empty());
        assert!(tool_literals_on_line(r#"    "tool": tool_name,"#).is_empty());
        // A line with no `tool` key is not scanned at all.
        assert!(tool_literals_on_line(r#"    "action": "add_edge","#).is_empty());
    }

    /// A hint's literal `args` keys, paired with the tool literal above them.
    ///
    /// The args block is a Rust expression, so only LITERAL keys are visible —
    /// but every authoring hint in this crate writes its keys as literals, so
    /// this reaches the shape that actually broke (`add_edge` with
    /// `source_node_id`). Pairing is positional: an args block is attributed to
    /// the nearest `"tool": "<literal>"` at most `MAX_PAIR_DISTANCE` lines
    /// above it, and each tool literal claims at most one args block, which
    /// bounds mis-pairing across adjacent hint objects.
    fn hint_arg_keys_in_source(source: &str) -> Vec<(usize, String, Vec<String>)> {
        const MAX_PAIR_DISTANCE: usize = 12;
        let lines: Vec<&str> = source.lines().collect();
        let mut out = Vec::new();
        let mut pending: Option<(usize, String)> = None;

        for (i, line) in lines.iter().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            let tools = tool_literals_on_line(line);
            if tools.len() == 1 {
                pending = Some((i, tools[0].clone()));
                continue;
            }
            if !tools.is_empty() {
                // A conditional tool name can't be attributed to one args
                // block; drop the pairing rather than guess.
                pending = None;
                continue;
            }

            let Some(key_pos) = ARG_KEYS
                .iter()
                .find_map(|k| line.find(&format!("\"{k}\":")).map(|p| p + k.len() + 3))
            else {
                continue;
            };
            let Some((tool_line, tool)) = pending.clone() else {
                continue;
            };
            if i.saturating_sub(tool_line) > MAX_PAIR_DISTANCE {
                pending = None;
                continue;
            }
            if !line[key_pos..].trim_start().starts_with('{') {
                continue;
            }
            pending = None;
            out.push((i + 1, tool, arg_keys_from(&lines, i, key_pos)));
        }
        out
    }

    /// Literal keys at brace-depth 1 of the args object that opens on
    /// `lines[start]` at or after `open_at`. Textual brace counting; a brace
    /// inside a string literal would end the block early, which loses keys
    /// (a miss, never a false accusation).
    fn arg_keys_from(lines: &[&str], start: usize, open_at: usize) -> Vec<String> {
        let mut depth = 0usize;
        let mut keys = Vec::new();
        for (n, line) in lines.iter().enumerate().skip(start) {
            let slice = if n == start { &line[open_at..] } else { line };
            let mut chars = slice.char_indices().peekable();
            while let Some((idx, ch)) = chars.next() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            return keys;
                        }
                    }
                    '"' if depth == 1 => {
                        let after = &slice[idx + 1..];
                        if let Some(close) = after.find('"') {
                            let lit = &after[..close];
                            if after[close + 1..].trim_start().starts_with(':') {
                                keys.push(lit.to_string());
                            }
                            // Skip past the literal we just consumed.
                            while let Some((j, _)) = chars.peek() {
                                if *j <= idx + close + 1 {
                                    chars.next();
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        keys
    }

    /// The `args` half of the class, statically, for the literal-key hints
    /// this crate writes inline. Complements
    /// `add_node_checklist_conforms_to_the_schemas_it_names`, which proves the
    /// same property dynamically through the real builder.
    #[test]
    fn every_literal_hint_args_key_is_declared_by_the_tool_it_names() {
        let mut checked = 0usize;
        let mut offenders: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(src_dir()).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let file_name = path
                .file_name()
                .and_then(|s| s.to_str())
                .expect("utf8 file name")
                .to_string();
            if file_name == "tool_hints.rs" {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("read source file");
            for (line, tool, keys) in hint_arg_keys_in_source(&source) {
                let Some(declared) = declared_tool_params().get(&tool) else {
                    continue; // the tool-name leg owns this case
                };
                for key in keys {
                    checked += 1;
                    if !declared.contains(&key) {
                        offenders.push(format!("{file_name}:{line} → {tool}(`{key}`)"));
                    }
                }
            }
        }
        assert!(
            checked >= 15,
            "args extraction found only {checked} literal keys — extraction looks broken"
        );
        assert!(
            offenders.is_empty(),
            "authoring hints passing arguments the named tool does not declare — a caller \
             copy-pasting them gets a rejected call. Fix the HINT, never the tool's schema:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// The `tool` half of the class, for EVERY hint in this crate — including
    /// the ones built inline inside async DB-backed handlers that no unit test
    /// can construct. See the module docs for what this cannot see.
    /// Scan one directory of Rust sources for `"tool": "<literal>"` hints.
    /// Returns (files scanned, literals scanned, offenders). Parameterised by
    /// directory so the SAME code can be pointed at a pre-fix tree to prove
    /// the check actually fires.
    fn scan_tool_literals(dir: &std::path::Path) -> (usize, usize, Vec<String>) {
        let mut scanned_files = 0usize;
        let mut scanned_literals = 0usize;
        let mut offenders: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let file_name = path
                .file_name()
                .and_then(|s| s.to_str())
                .expect("utf8 file name")
                .to_string();
            // This file's own literals are the check's vocabulary, not hints.
            if file_name == "tool_hints.rs" {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("read source file");
            scanned_files += 1;
            for (i, line) in source.lines().enumerate() {
                for lit in tool_literals_on_line(line) {
                    if lit.is_empty() {
                        continue;
                    }
                    scanned_literals += 1;
                    if !is_declared_tool(&lit) {
                        offenders.push(format!("{}:{} → `{}`", file_name, i + 1, lit));
                    }
                }
            }
        }
        (scanned_files, scanned_literals, offenders)
    }

    /// The `tool` half of the class, for EVERY hint in this crate — including
    /// the ones built inline inside async DB-backed handlers that no unit test
    /// can construct. See the module docs for what this cannot see.
    #[test]
    fn every_tool_literal_in_crate_sources_names_a_declared_tool() {
        let (scanned_files, scanned_literals, offenders) = scan_tool_literals(&src_dir());

        // Tripwire: if the extraction silently stops matching (a rustfmt
        // change, a rename of the `tool` key) this test would pass over
        // nothing at all and read as green. Both counts are floors well under
        // the live values (21 schema modules, ~60 hint literals).
        assert!(
            scanned_files >= 15,
            "source scan found only {scanned_files} .rs files — extraction looks broken"
        );
        assert!(
            scanned_literals >= 30,
            "source scan found only {scanned_literals} `\"tool\": \"…\"` literals — \
             extraction looks broken (did the key name change?)"
        );

        assert!(
            offenders.is_empty(),
            "authoring hints naming tools this server does not advertise — a caller \
             following them gets -32601. Fix the HINT, never the tool's schema:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// The reproduction, pinned against the real schema rather than against a
    /// re-derivation of it: `add_edge` takes `source`/`target`, and
    /// `source_node_id` is a legitimate parameter of OTHER tools, so the fix
    /// is per-tool and a blind rename would break those.
    #[test]
    fn add_edge_declares_source_and_target_not_source_node_id() {
        let params = declared_tool_params()
            .get("add_edge")
            .expect("add_edge must be an advertised tool");
        assert!(params.contains("source"), "add_edge declares `source`");
        assert!(params.contains("target"), "add_edge declares `target`");
        assert!(
            !params.contains("source_node_id"),
            "add_edge does NOT declare `source_node_id` — hints must not suggest it"
        );

        // …and the name IS declared elsewhere, so the fix is not a rename.
        for tool in ["duplicate_node", "copy_node"] {
            assert!(
                declared_tool_params()
                    .get(tool)
                    .map(|p| p.contains("source_node_id"))
                    .unwrap_or(false),
                "{tool} legitimately declares `source_node_id`"
            );
        }
    }

    /// The defect this module exists to catch, expressed as the exact hint
    /// `handle_add_node_to_workflow` used to emit.
    #[test]
    fn the_original_add_edge_hint_is_reported_as_a_defect() {
        let bad = serde_json::json!({
            "next_steps_checklist": [{
                "step": 1,
                "action": "Wire into graph",
                "tool": "add_edge",
                "args": { "workflow_id": "w", "source_node_id": "a", "target_node_id": "b" },
            }]
        });
        let defects = hint_defects(&bad);
        assert_eq!(
            defects,
            vec![
                HintDefect::UndeclaredArg {
                    tool: "add_edge".into(),
                    arg: "source_node_id".into()
                },
                HintDefect::UndeclaredArg {
                    tool: "add_edge".into(),
                    arg: "target_node_id".into()
                },
            ],
            "the pre-fix hint must be reported"
        );
    }

    #[test]
    fn unknown_tool_and_sentinel_tool_are_distinguished() {
        let unknown = serde_json::json!({ "tool": "reinstall_module_from_catalog" });
        assert_eq!(
            hint_defects(&unknown),
            vec![HintDefect::UnknownTool {
                tool: "reinstall_module_from_catalog".into()
            }]
        );
        // MCP-1201: `null` / "" mean "no MCP tool can do this".
        assert!(hint_defects(&serde_json::json!({ "tool": null })).is_empty());
        assert!(hint_defects(&serde_json::json!({ "tool": "" })).is_empty());
    }

    /// The `args` half, for every hint reachable through a pure builder.
    #[test]
    fn add_node_checklist_conforms_to_the_schemas_it_names() {
        let wf = uuid::Uuid::nil();
        let node = "my_node";
        // Every branch of the builder, not just the default one.
        for (module_id, config_empty, connected) in [
            ("8aa34ddb-3b15-494f-a6be-3fb9a2980572", true, false),
            ("8aa34ddb-3b15-494f-a6be-3fb9a2980572", false, true),
            ("condition", true, false),
            ("", true, true),
        ] {
            let checklist = crate::workflows::build_add_node_checklist(
                &wf.to_string(),
                node,
                module_id,
                config_empty,
                connected,
            );
            let as_value = Value::Array(checklist);
            assert!(
                hint_defects(&as_value).is_empty(),
                "add_node_to_workflow checklist (module_id={module_id}, \
                 config_empty={config_empty}, connected={connected}) drifted: {:?}",
                hint_defects(&as_value)
            );
        }
    }

    /// Same, for the three hint builders that live in dependency crates and so
    /// are invisible to the source scan above.
    #[test]
    fn cross_crate_hint_builders_conform_to_the_schemas_they_name() {
        // talos-failure-analysis-service: remediation playbooks. Drive EVERY
        // bucket, including the fall-through, so no arm is left unscanned.
        //
        // The list was DRIFTED when the reason_class buckets were added
        // (2026-09): six entries — `compile_error`, `parse_error`,
        // `permission_denied`, `not_found`, `server_error`, `rate_limited` —
        // were names `classify_error` has never emitted, so they all landed on
        // the `_` fall-through and this test passed VACUOUSLY for them, while
        // seven real buckets (`module_compile_error`, `json_parse`,
        // `http_401`, `http_403`, `http_404`, `http_5xx`, `rate_limit`) were
        // never scanned at all. Corrected below and kept in sync with
        // `remediation_steps`' own match arms.
        let buckets = [
            // Prose-matched buckets.
            "output_schema_violation",
            "host_not_allowed",
            "module_compile_error",
            "json_parse",
            "fuel_exhausted",
            "timeout",
            "http_401",
            "http_403",
            "http_404",
            "http_5xx",
            "missing_secret",
            "rate_limit",
            "wasm_trap",
            "network_error",
            "config_error",
            "auth_error",
            "database_error",
            "unclassified",
            // Host-stamped `[reason_class=…]` denial buckets. Every tool these
            // name is checked to EXIST here — which is the guard that stops a
            // playbook prescribing a tool that was removed (six hints once
            // named `set_secret`, deleted by MCP-1201).
            "circuit_open",
            "execution_cancelled",
            "response_too_large",
            "request_too_large",
            "invalid_url",
            "insecure_scheme",
            "capability_world_denied",
            "ssrf_blocked",
            "egress_tier_denied",
            "write_ceiling_denied",
            "method_not_allowed",
            "egress_budget_exceeded",
            "introspection_denied",
            // The fall-through.
            "an_unmatched_bucket_name",
        ];
        for bucket in buckets {
            let steps = Value::Array(talos_failure_analysis_service::remediation_steps(
                bucket,
                "some_node",
            ));
            assert!(
                hint_defects(&steps).is_empty(),
                "remediation_steps({bucket}) drifted: {:?}",
                hint_defects(&steps)
            );
        }

        // talos-workflow-creation-helpers: create_workflow response.
        let resp = talos_workflow_creation_helpers::build_create_workflow_response(
            talos_workflow_creation_helpers::CreateResponseInputs {
                workflow_id: uuid::Uuid::nil(),
                workflow_name: "wf".into(),
                node_count: 1,
                edge_count: 0,
                ascii_graph: String::new(),
                ready_to_run: true,
                graph_is_empty: false,
                missing_config: vec![serde_json::json!("n1")],
                required_secrets: ["anthropic/api_key".to_string()].into_iter().collect(),
                description_warning: None,
                name_collision_warning: None,
                vault_warnings: vec![],
            },
        );
        assert!(
            hint_defects(&resp).is_empty(),
            "build_create_workflow_response drifted: {:?}",
            hint_defects(&resp)
        );

        // talos-hygiene-service: the untyped-Value fix commands. Note these
        // use the `arguments` spelling, not `args` — covered because ARG_KEYS
        // carries all three spellings in use across the platform.
        let fixes = Value::Array(talos_hygiene_service::build_typed_scaffold_fix_commands(&[
            talos_analytics_repository::UntypedValueModuleRow {
                id: uuid::Uuid::nil(),
                name: "legacy-parser".into(),
            },
        ]));
        assert!(
            hint_defects(&fixes).is_empty(),
            "build_typed_scaffold_fix_commands drifted: {:?}",
            hint_defects(&fixes)
        );
    }
}
