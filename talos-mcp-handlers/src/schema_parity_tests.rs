//! Schema ↔ dispatch parity + well-formedness tests (2026-07-01 review).
//!
//! Three drift classes these kill at PR time:
//!
//! 1. **Advertised-but-undispatchable**: a tool in some module's
//!    `tool_schemas()` with no dispatch arm anywhere → the LLM calls it
//!    and gets -32601. Parity previously held only because someone
//!    diffed the two lists by hand.
//! 2. **Malformed static schema**: one non-`type: object` inputSchema
//!    makes Zod-based clients drop the ENTIRE tools/list (the 2026-04-23
//!    incident — defensively normalized for *catalog* schemas in
//!    `handle_tools_list`, but a malformed *static* literal would still
//!    ship).
//! 3. **Unregistered module**: a new `tool_schemas()` module that never
//!    gets added to `static_tool_count()` / these tests (the exact drift
//!    `handle_get_platform_info` had before `static_tool_count()`).
//!
//! Extraction note: dispatch-arm names are pulled from each module's
//! `dispatch` fn source as an OVER-approximation (every identifier-shaped
//! string literal in the fn body). Extra captures only weaken test 1,
//! never fail it spuriously; a real arm can't be missed. Dispatch-only
//! names (deprecated `agent_*` aliases, or-pattern aliases) are
//! deliberately allowed.

use std::collections::{BTreeMap, BTreeSet};

/// The canonical static-schema module list. Must stay in lockstep with
/// `static_tool_count()` in lib.rs — `every_tool_schemas_module_is_registered`
/// enforces the filesystem side (a `tool_schemas` fn in a file not listed
/// here fails), and `advertised_count_matches_static_tool_count` enforces
/// the lib.rs side.
fn all_static_schemas() -> Vec<(&'static str, Vec<serde_json::Value>)> {
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
        ("schemas", crate::schemas::tool_schemas()),
        ("ollama", crate::ollama::tool_schemas()),
        ("ml", crate::ml::tool_schemas()),
    ]
}

fn src_dir() -> std::path::PathBuf {
    // Same-crate source introspection: CARGO_MANIFEST_DIR is this crate's
    // root at compile time, so the path survives workspace relocation
    // (the PR #190 relocation class applies to CROSS-crate hardcoded
    // paths, not self-reads).
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Every identifier-shaped string literal inside `fn dispatch`'s body.
/// Over-approximate by design — see module docs.
fn dispatch_literals(source: &str) -> BTreeSet<String> {
    let Some(start) = source.find("pub async fn dispatch(") else {
        return BTreeSet::new();
    };
    // Walk braces from the fn's opening brace to its close.
    let body_start = match source[start..].find('{') {
        Some(off) => start + off,
        None => return BTreeSet::new(),
    };
    let mut depth = 0usize;
    let mut end = source.len();
    for (i, ch) in source[body_start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = body_start + i;
                    break;
                }
            }
            _ => {}
        }
    }
    let body = &source[body_start..end];

    let mut names = BTreeSet::new();
    let mut rest = body;
    while let Some(q) = rest.find('"') {
        let after = &rest[q + 1..];
        let Some(close) = after.find('"') else { break };
        let lit = &after[..close];
        if !lit.is_empty()
            && lit
                .chars()
                .next()
                .map(|c| c.is_ascii_lowercase())
                .unwrap_or(false)
            && lit
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        {
            names.insert(lit.to_string());
        }
        rest = &after[close + 1..];
    }
    names
}

fn all_dispatch_literals() -> BTreeSet<String> {
    let mut all = BTreeSet::new();
    for entry in std::fs::read_dir(src_dir()).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read source file");
        all.extend(dispatch_literals(&source));
    }
    all
}

/// Drift class 3: a module defining `pub fn tool_schemas` that isn't in
/// `all_static_schemas()` (and therefore almost certainly not in
/// `static_tool_count()` either).
#[test]
fn every_tool_schemas_module_is_registered() {
    let mut on_disk = BTreeSet::new();
    for entry in std::fs::read_dir(src_dir()).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read source file");
        // Line-start match so this test file's own string literal doesn't
        // count itself as a schema module.
        if source.lines().any(|l| l.starts_with("pub fn tool_schemas")) {
            on_disk.insert(
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .expect("utf8 file stem")
                    .to_string(),
            );
        }
    }
    let registered: BTreeSet<String> = all_static_schemas()
        .iter()
        .map(|(m, _)| m.to_string())
        .collect();
    assert_eq!(
        on_disk, registered,
        "modules defining tool_schemas() must be registered in \
         all_static_schemas() AND lib.rs::static_tool_count(); \
         on-disk-only = missing registration, registered-only = stale entry"
    );
}

/// Free consistency check against the canonical counter in lib.rs.
#[test]
fn advertised_count_matches_static_tool_count() {
    let advertised: usize = all_static_schemas().iter().map(|(_, v)| v.len()).sum();
    assert_eq!(
        advertised,
        crate::static_tool_count(),
        "all_static_schemas() and lib.rs::static_tool_count() disagree — \
         one of them is missing a module"
    );
}

/// Drift class 2: schema well-formedness. One malformed static schema
/// wipes the whole tools/list for Zod-validating clients.
#[test]
fn every_static_schema_is_well_formed_and_uniquely_named() {
    let mut seen: BTreeMap<String, &'static str> = BTreeMap::new();
    for (module, schemas) in all_static_schemas() {
        assert!(
            !schemas.is_empty(),
            "{module}::tool_schemas() returned an empty list"
        );
        for schema in &schemas {
            let name = schema
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or_else(|| panic!("{module}: tool schema missing string `name`: {schema}"));
            assert!(!name.is_empty(), "{module}: empty tool name");
            if let Some(prev) = seen.insert(name.to_string(), module) {
                panic!("duplicate tool name `{name}` advertised by both `{prev}` and `{module}`");
            }
            let desc = schema.get("description").and_then(|d| d.as_str());
            assert!(
                desc.map(|d| !d.trim().is_empty()).unwrap_or(false),
                "{module}::{name}: missing/empty description"
            );
            let input = schema.get("inputSchema").unwrap_or_else(|| {
                panic!("{module}::{name}: missing inputSchema (Zod-wipeout class)")
            });
            assert_eq!(
                input.get("type").and_then(|t| t.as_str()),
                Some("object"),
                "{module}::{name}: inputSchema.type must be \"object\" (Zod-wipeout class)"
            );
            assert!(
                input
                    .get("properties")
                    .map(|p| p.is_object())
                    .unwrap_or(false),
                "{module}::{name}: inputSchema.properties must be a JSON object"
            );
        }
    }
}

/// Drift class 1: every advertised tool must have a dispatch arm
/// somewhere in the crate.
#[test]
fn every_advertised_tool_has_a_dispatch_arm() {
    let dispatchable = all_dispatch_literals();
    assert!(
        dispatchable.len() > 100,
        "dispatch-literal extraction looks broken (only {} names) — \
         did the dispatch fn signature change shape?",
        dispatchable.len()
    );
    let mut orphans = Vec::new();
    for (module, schemas) in all_static_schemas() {
        for schema in &schemas {
            let name = schema
                .get("name")
                .and_then(|n| n.as_str())
                .expect("well-formedness test covers this");
            if !dispatchable.contains(name) {
                orphans.push(format!("{module}::{name}"));
            }
        }
    }
    assert!(
        orphans.is_empty(),
        "advertised tools with NO dispatch arm (clients get -32601): {orphans:?}"
    );
}
