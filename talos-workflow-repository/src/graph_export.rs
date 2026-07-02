//! Pure (SQL-free) helpers: workflow-graph JSON manipulation and
//! platform export/import remapping, plus their unit tests.

use crate::*;

/// Pure: extract candidate module-id UUIDs from a workflow graph `Value`.
///
/// Iterates `graph.nodes[*].type` and parses the string as a UUID. Any
/// non-UUID type (`"system:approval"`, custom strings, etc.) is silently
/// skipped — non-UUID types cannot be modules, so the filter is correct.
///
/// This is the `Value`-shaped sibling of
/// [`talos_workflow_authorization::extract_graph_module_ids`]
/// (which takes a `&str`); both `import_workflow` and `export_workflow`
/// already have the parsed `Value` in hand and don't need a re-parse.
pub fn extract_module_ids_from_graph_value(graph: &serde_json::Value) -> Vec<Uuid> {
    graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .map(|nodes| {
            nodes
                .iter()
                .filter_map(|n| {
                    n.get("type")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse::<Uuid>().ok())
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Pure: detect whether a graph node is a `sub_workflow` system node.
///
/// Two recognized shapes (both currently emitted by different code paths):
///   * `node.kind == "sub_workflow"` (legacy)
///   * `node.type == "system:sub_workflow"` (canonical post-r228)
///
/// Returns `true` for either; downstream extractors must accept both
/// until the legacy form is purged from stored graphs.
pub fn is_sub_workflow_node(node: &serde_json::Value) -> bool {
    node.get("kind").and_then(|k| k.as_str()) == Some("sub_workflow")
        || node.get("type").and_then(|t| t.as_str()) == Some("system:sub_workflow")
}

/// Pure: collect the `sub_workflow_id` data field from every
/// `sub_workflow` system node in the graph, as raw string values.
///
/// Returns an empty `Vec` for graphs with no sub_workflow nodes or no
/// `nodes` array. Order matches `nodes[]` order.
pub fn extract_sub_workflow_id_strings(graph: &serde_json::Value) -> Vec<String> {
    graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .map(|nodes| {
            nodes
                .iter()
                .filter(|n| is_sub_workflow_node(n))
                .filter_map(|n| {
                    n.get("data")
                        .and_then(|d| d.get("sub_workflow_id"))
                        .and_then(|v| v.as_str())
                        .map(String::from)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Pure: like [`extract_sub_workflow_id_strings`] but parses each id as
/// a UUID and silently drops any that don't parse. Use when downstream
/// code needs typed UUIDs (e.g. cross-workflow-stats lookups).
pub fn extract_sub_workflow_uuids(graph: &serde_json::Value) -> Vec<Uuid> {
    extract_sub_workflow_id_strings(graph)
        .into_iter()
        .filter_map(|s| s.parse::<Uuid>().ok())
        .collect()
}

/// Mutate `graph` in place: remove every edge whose `(source, target)`
/// endpoints match the supplied pair. Returns `true` iff at least one
/// edge was removed.
///
/// Replaces the duplicated `edges.retain(|e| !(src == source && tgt == target))`
/// pattern in handle_remove_edge and the `remove_edge` branch of
/// handle_update_node_config.
pub fn remove_edge_by_endpoints(graph: &mut serde_json::Value, source: &str, target: &str) -> bool {
    let Some(edges) = graph.get_mut("edges").and_then(|e| e.as_array_mut()) else {
        return false;
    };
    let before = edges.len();
    edges.retain(|e| {
        let src = e.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let tgt = e.get("target").and_then(|v| v.as_str()).unwrap_or("");
        !(src == source && tgt == target)
    });
    edges.len() < before
}

/// Mutate `graph` in place: remove every edge whose `source` or `target`
/// references `node_id`. Returns the list of removed `(source, target)`
/// endpoint pairs in their original order — callers use this for the
/// audit-trace summary in remove-node responses.
pub fn remove_edges_connected_to_node(
    graph: &mut serde_json::Value,
    node_id: &str,
) -> Vec<(String, String)> {
    let mut removed: Vec<(String, String)> = Vec::new();
    let Some(edges) = graph.get_mut("edges").and_then(|e| e.as_array_mut()) else {
        return removed;
    };
    edges.retain(|e| {
        let src = e.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let tgt = e.get("target").and_then(|v| v.as_str()).unwrap_or("");
        let connected = src == node_id || tgt == node_id;
        if connected {
            removed.push((src.to_string(), tgt.to_string()));
        }
        !connected
    });
    removed
}

/// Pure: locate a node within a workflow graph by its string `id`.
///
/// Iterates `graph.nodes[]` and returns the first entry whose `id`
/// field matches `node_id`. Returns `None` if `nodes` is missing,
/// not an array, or no entry matches.
pub fn find_node_by_id<'a>(
    graph: &'a serde_json::Value,
    node_id: &str,
) -> Option<&'a serde_json::Value> {
    graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .and_then(|nodes| {
            nodes
                .iter()
                .find(|n| n.get("id").and_then(|v| v.as_str()) == Some(node_id))
        })
}

/// Pure: true iff `graph.nodes[]` contains a node with the given `id`.
///
/// Equivalent to `find_node_by_id(graph, id).is_some()` but reads
/// nicer at sites that only need the boolean check (e.g. validating
/// that a new node id is unique before insertion).
pub fn graph_contains_node_id(graph: &serde_json::Value, node_id: &str) -> bool {
    find_node_by_id(graph, node_id).is_some()
}

/// Pure: locate a node in an already-extracted node slice by string `id`.
///
/// Sibling to [`find_node_by_id`] for callers that have already pulled
/// the `nodes` array out of the graph (e.g. because they need to mutate
/// the slice, iterate twice, or count entries) and don't want to re-pay
/// the `graph.get("nodes").as_array()` lookup just to do an id match.
///
/// Returns `None` when no entry's `id` field stringifies to `node_id`.
/// Skips entries whose `id` is missing or non-string (impossible in
/// well-formed graphs but cheap to be defensive).
pub fn find_node_in_array<'a>(
    nodes: &'a [serde_json::Value],
    node_id: &str,
) -> Option<&'a serde_json::Value> {
    nodes
        .iter()
        .find(|n| n.get("id").and_then(|v| v.as_str()) == Some(node_id))
}

/// Pure: collect the `node.id` string of every node, in document order.
///
/// Returns a `Vec<String>` (owned) so callers can move into a `HashSet`,
/// `HashMap` keys, etc. without lifetime gymnastics. Skips nodes whose
/// `id` field is missing or non-string. Returns an empty Vec if `nodes`
/// is missing or not an array.
///
/// Sibling helpers:
///   * [`extract_module_ids_from_graph_value`] — `Vec<Uuid>` from `type`
///   * [`extract_node_type_strings`] — `HashSet<String>` from `type`
pub fn extract_node_id_strings(graph: &serde_json::Value) -> Vec<String> {
    graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .map(|nodes| {
            nodes
                .iter()
                .filter_map(|n| n.get("id").and_then(|v| v.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Pure: collect the set of `node.type` strings from a workflow graph.
///
/// Iterates `graph.nodes[*].type` and collects every `as_str()` value
/// into a `HashSet<String>`. Unlike
/// [`extract_module_ids_from_graph_value`], this preserves *all* node
/// types (including `system:*` strings), which is what the
/// similarity-comparison handlers want — two workflows that both use
/// `system:judge` should overlap on that shared structural element,
/// not just on UUID-typed module nodes.
pub fn extract_node_type_strings(graph: &serde_json::Value) -> std::collections::HashSet<String> {
    graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .map(|nodes| {
            nodes
                .iter()
                .filter_map(|n| n.get("type").and_then(|v| v.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Workflow row returned by `list_user_workflows_with_schedule` — flat shape
/// with the joined schedule fields inlined for downstream JSON building.
#[derive(Debug)]
pub struct WorkflowExportRow {
    pub id: Uuid,
    pub name: String,
    pub graph_json: String,
    pub is_enabled: bool,
    pub cron_expression: Option<String>,
    pub timezone: String,
    pub schedule_enabled: bool,
}

/// Pure: walk the graph JSONs of every export row and collect the set
/// of UUIDs referenced as node `type` (compiled module ids) or
/// `data.moduleId` (UI-provided module pointer).
///
/// Used by `handle_export_platform_state` to build the `module_manifest`
/// — the import path uses the manifest to remap instance-local module
/// UUIDs onto the target instance's equivalents (BUG-59). Pure over a
/// slice of [`WorkflowExportRow`]; malformed graph JSONs are skipped
/// silently rather than failing the export.
///
/// Order is non-deterministic (HashSet → Vec) — callers that need a
/// stable order should sort.
pub fn collect_referenced_module_uuids(rows: &[WorkflowExportRow]) -> Vec<Uuid> {
    let mut referenced: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
    for w in rows {
        let Ok(graph) = serde_json::from_str::<serde_json::Value>(&w.graph_json) else {
            continue;
        };
        let Some(nodes) = graph.get("nodes").and_then(|v| v.as_array()) else {
            continue;
        };
        for node in nodes {
            // node.type — compiled module reference (ignores "system:*" labels
            // that can't parse as UUID).
            if let Some(s) = node.get("type").and_then(|v| v.as_str()) {
                if let Ok(uid) = Uuid::parse_str(s) {
                    referenced.insert(uid);
                }
            }
            // node.data.moduleId — UI-side module pointer (preferred over
            // node.type by some workflow editors).
            if let Some(mid) = node
                .get("data")
                .and_then(|d| d.get("moduleId"))
                .and_then(|v| v.as_str())
            {
                if let Ok(uid) = Uuid::parse_str(mid) {
                    referenced.insert(uid);
                }
            }
        }
    }
    referenced.into_iter().collect()
}

/// Outcome of [`remap_graph_module_uuids`] — the rewritten graph plus
/// per-call counters the import handler accumulates across workflows.
#[derive(Debug, Clone)]
pub struct GraphRemapOutcome {
    /// The graph JSON with module UUIDs rewritten in-place where a remap
    /// existed. On parse failure this is the input serialized via
    /// `Value::to_string()` — same fallback as the pre-extraction path.
    pub graph_json: String,
    /// Count of node positions whose `type` was successfully rewritten
    /// to a current-instance UUID. Does not double-count the optional
    /// `data.moduleId` rewrites — those mirror `type` and are
    /// best-effort by design.
    pub remapped_count: usize,
    /// Module names that appeared in `old_to_name` but had no entry in
    /// `name_to_new` (the target instance doesn't have that template
    /// installed). Caller surfaces these as warnings telling the
    /// operator to re-run `install_module_from_catalog`.
    pub unresolved_module_names: Vec<String>,
}

/// Pure: extract the `module_manifest` section from an import payload as a
/// `old_uuid → module_name` map.
///
/// Counterpart to the export-side `module_manifest` written by
/// `handle_export_platform_state`. Tolerates missing or malformed sections
/// (returns empty map) — the caller treats an empty map as "no remap
/// needed". Manifest entries without a `name` field are skipped silently.
pub fn extract_old_uuid_to_name_from_manifest(
    manifest: &serde_json::Value,
) -> std::collections::HashMap<String, String> {
    manifest
        .get("module_manifest")
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(uuid_str, entry)| {
                    let name = entry.get("name").and_then(|v| v.as_str())?.to_string();
                    Some((uuid_str.clone(), name))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Pure: collapse a list of current-instance template rows (id, name,
/// user_id) into a `name → id` lookup, keeping the FIRST insertion per
/// name. Callers MUST pass rows pre-ordered with user-installed
/// templates first (`ORDER BY user_id IS NULL ASC`) so that user-
/// installed templates win over system fallbacks for any name collision.
///
/// Used by [`handle_import_platform_state`] to build the target side of
/// the BUG-59 UUID remap. The `Option<Uuid>` user_id slot is ignored —
/// the ordering invariant lives in the SQL, not this fn.
pub fn build_name_to_new_uuid_map(
    rows: Vec<(Uuid, String, Option<Uuid>)>,
) -> std::collections::HashMap<String, Uuid> {
    let mut map: std::collections::HashMap<String, Uuid> = std::collections::HashMap::new();
    for (id, name, _user_id) in rows {
        map.entry(name).or_insert(id);
    }
    map
}

/// Parsed schedule fields from a manifest workflow entry. Borrows from
/// the input — caller passes these directly to the upsert call.
#[derive(Debug, Clone)]
pub struct ImportedSchedule<'a> {
    pub cron_expression: &'a str,
    pub timezone: &'a str,
    pub is_enabled: bool,
}

/// Pure: parse a manifest workflow's `schedule` field into the typed
/// fields needed by `upsert_workflow_schedule`.
///
/// Returns:
/// * `Some(...)` when `cron_expression` is present and non-empty.
/// * `None` when `cron_expression` is missing or empty — the import
///   path skips the schedule write entirely. Manifests written by the
///   export side never produce empty cron values; this branch defends
///   against hand-crafted manifests with the schedule object present
///   but the cron field stripped.
///
/// Defaults: `timezone` → `"UTC"`, `is_enabled` → `true`. Both match
/// the pre-extraction handler behavior verbatim.
pub fn parse_imported_schedule(schedule: &serde_json::Value) -> Option<ImportedSchedule<'_>> {
    let cron = schedule.get("cron_expression").and_then(|v| v.as_str())?;
    if cron.is_empty() {
        return None;
    }
    let timezone = schedule
        .get("timezone")
        .and_then(|v| v.as_str())
        .unwrap_or("UTC");
    let is_enabled = schedule
        .get("is_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    Some(ImportedSchedule {
        cron_expression: cron,
        timezone,
        is_enabled,
    })
}

/// Outcome of [`preview_module_remap`] — the dry-run counterpart to
/// [`remap_graph_module_uuids`]. No graph mutation; just the resolved/
/// unresolved counts and a formatted-name list ready for the JSON-RPC
/// response.
#[derive(Debug, Clone, Default)]
pub struct ModuleRemapPreview {
    /// Number of source-instance module UUIDs that will rewrite cleanly
    /// onto a current-instance equivalent.
    pub remapped: usize,
    /// Pre-formatted "<name>' (uuid: <old_uuid>)" strings for source-
    /// instance modules with no current-instance match. The format is
    /// the public dry-run response shape — operators paste these into
    /// `install_module_from_catalog` invocations.
    pub unresolved: Vec<String>,
}

/// Pure: dry-run preview of [`remap_graph_module_uuids`] across the full
/// `module_manifest`. Walks every (old_uuid, name) entry and bins it as
/// remappable or unresolved.
pub fn preview_module_remap(
    old_to_name: &std::collections::HashMap<String, String>,
    name_to_new: &std::collections::HashMap<String, Uuid>,
) -> ModuleRemapPreview {
    let mut remapped = 0usize;
    let mut unresolved: Vec<String> = Vec::new();
    for (old_uuid, name) in old_to_name {
        if name_to_new.contains_key(name.as_str()) {
            remapped += 1;
        } else {
            unresolved.push(format!("'{}' (uuid: {})", name, old_uuid));
        }
    }
    ModuleRemapPreview {
        remapped,
        unresolved,
    }
}

/// Pure: surface dry-run-only warnings about an imported workflow array.
/// Per-entry checks: a non-empty `name` field and a present `graph_json`
/// field. The output strings match the pre-extraction handler verbatim
/// so existing operator scripts that grep dry-run warnings keep working.
pub fn preview_dry_run_workflow_warnings(workflows: &[serde_json::Value]) -> Vec<String> {
    let mut warnings = Vec::new();
    for (i, wf) in workflows.iter().enumerate() {
        let name = wf.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() {
            warnings.push(format!("Workflow at index {} has no name", i));
        }
        if wf.get("graph_json").is_none() {
            warnings.push(format!("Workflow '{}' has no graph_json", name));
        }
    }
    warnings
}

/// Pure: rewrite module UUIDs in a workflow graph from the source-instance
/// IDs (recorded in the export manifest) onto the target instance's
/// equivalents.
///
/// Inputs:
/// * `graph` — the workflow graph JSON. Mutated through a clone — the
///   caller's value is not modified.
/// * `old_to_name` — `module_manifest` from the export: old UUID string →
///   module name.
/// * `name_to_new` — current-instance lookup: module name → new UUID.
///
/// Behavior:
/// * Walks `nodes[*].type` and `nodes[*].data.moduleId`. Each is rewritten
///   when both the old → name mapping AND the name → new UUID mapping
///   exist.
/// * Counts only `type` rewrites in `remapped_count` (mirrors pre-
///   extraction handler — `data.moduleId` rewrites were not counted).
/// * Names with no current-instance match are returned in
///   `unresolved_module_names`.
/// * Empty `old_to_name` short-circuits to the input verbatim with zero
///   counts — saves a clone for instances with no module manifest at all.
///
/// Note: this is BUG-59 territory — workflows imported from another
/// instance reference UUIDs that don't exist locally. Without remap, the
/// workflow loads but every node fails at dispatch with "module not
/// found".
pub fn remap_graph_module_uuids(
    graph: &serde_json::Value,
    old_to_name: &std::collections::HashMap<String, String>,
    name_to_new: &std::collections::HashMap<String, Uuid>,
) -> GraphRemapOutcome {
    if old_to_name.is_empty() {
        return GraphRemapOutcome {
            graph_json: graph.to_string(),
            remapped_count: 0,
            unresolved_module_names: vec![],
        };
    }

    let mut remapped_count = 0usize;
    let mut unresolved: Vec<String> = Vec::new();
    let mut graph = graph.clone();

    if let Some(nodes) = graph.get_mut("nodes").and_then(|v| v.as_array_mut()) {
        for node in nodes.iter_mut() {
            // Rewrite node.type — primary module pointer; counted in
            // remapped_count.
            if let Some(type_str) = node
                .get("type")
                .and_then(|v| v.as_str())
                .map(str::to_string)
            {
                if let Some(mod_name) = old_to_name.get(&type_str) {
                    if let Some(&new_uuid) = name_to_new.get(mod_name.as_str()) {
                        node["type"] = serde_json::json!(new_uuid.to_string());
                        remapped_count += 1;
                    } else {
                        unresolved.push(mod_name.clone());
                    }
                }
            }
            // Rewrite node.data.moduleId — UI-side pointer; mirrors `type`,
            // best-effort, not counted.
            if let Some(mid) = node
                .get("data")
                .and_then(|d| d.get("moduleId"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
            {
                if let Some(mod_name) = old_to_name.get(&mid) {
                    if let Some(&new_uuid) = name_to_new.get(mod_name.as_str()) {
                        if let Some(data) = node.get_mut("data") {
                            data["moduleId"] = serde_json::json!(new_uuid.to_string());
                        }
                    }
                }
            }
        }
    }

    GraphRemapOutcome {
        graph_json: serde_json::to_string(&graph).unwrap_or_else(|_| graph.to_string()),
        remapped_count,
        unresolved_module_names: unresolved,
    }
}

/// Pure: project a [`WorkflowExportRow`] into the JSON shape used by
/// the export manifest. Schedule fields collapse into a nested object
/// when a cron expression is present; absent otherwise (matches
/// pre-extraction handler behavior — operators reading the manifest
/// can grep for `schedule` to find scheduled workflows).
pub fn project_exported_workflow(row: &WorkflowExportRow) -> serde_json::Value {
    let graph_json: serde_json::Value =
        serde_json::from_str(&row.graph_json).unwrap_or(serde_json::json!({}));
    let mut obj = serde_json::json!({
        "id": row.id.to_string(),
        "name": row.name,
        "graph_json": graph_json,
        "is_enabled": row.is_enabled,
    });
    if let Some(cron_expression) = row.cron_expression.as_ref() {
        obj["schedule"] = serde_json::json!({
            "cron_expression": cron_expression,
            "timezone": row.timezone,
            "is_enabled": row.schedule_enabled,
        });
    }
    obj
}

#[cfg(test)]
mod export_helpers_tests {
    use super::*;

    fn row(graph: serde_json::Value, cron: Option<&str>) -> WorkflowExportRow {
        WorkflowExportRow {
            id: Uuid::new_v4(),
            name: "wf".into(),
            graph_json: graph.to_string(),
            is_enabled: true,
            cron_expression: cron.map(String::from),
            timezone: "UTC".into(),
            schedule_enabled: cron.is_some(),
        }
    }

    #[test]
    fn collect_uuids_picks_up_node_type_uuid() {
        let mid = Uuid::new_v4();
        let r = row(
            serde_json::json!({"nodes": [{"id": "n1", "type": mid.to_string()}]}),
            None,
        );
        let out = collect_referenced_module_uuids(&[r]);
        assert_eq!(out, vec![mid]);
    }

    #[test]
    fn collect_uuids_picks_up_data_module_id() {
        let mid = Uuid::new_v4();
        let r = row(
            serde_json::json!({
                "nodes": [{"id": "n1", "data": {"moduleId": mid.to_string()}}]
            }),
            None,
        );
        let out = collect_referenced_module_uuids(&[r]);
        assert_eq!(out, vec![mid]);
    }

    #[test]
    fn collect_uuids_skips_system_node_types() {
        let r = row(
            serde_json::json!({
                "nodes": [
                    {"id": "n1", "type": "system:judge"},
                    {"id": "n2", "type": "system:collect"},
                ]
            }),
            None,
        );
        assert!(collect_referenced_module_uuids(&[r]).is_empty());
    }

    #[test]
    fn collect_uuids_dedups_across_workflows() {
        let mid = Uuid::new_v4();
        let r1 = row(
            serde_json::json!({"nodes": [{"id": "n1", "type": mid.to_string()}]}),
            None,
        );
        let r2 = row(
            serde_json::json!({"nodes": [{"id": "n2", "type": mid.to_string()}]}),
            None,
        );
        let out = collect_referenced_module_uuids(&[r1, r2]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], mid);
    }

    #[test]
    fn collect_uuids_skips_malformed_graphs_without_failing() {
        let r1 = WorkflowExportRow {
            id: Uuid::new_v4(),
            name: "bad".into(),
            graph_json: "not json".into(),
            is_enabled: true,
            cron_expression: None,
            timezone: "UTC".into(),
            schedule_enabled: false,
        };
        let r2 = row(serde_json::json!({"nodes": "wrong-shape"}), None);
        assert!(collect_referenced_module_uuids(&[r1, r2]).is_empty());
    }

    #[test]
    fn project_exported_workflow_omits_schedule_when_no_cron() {
        let mid = Uuid::new_v4();
        let r = row(
            serde_json::json!({"nodes": [{"id": "n1", "type": mid.to_string()}]}),
            None,
        );
        let out = project_exported_workflow(&r);
        assert!(out.get("schedule").is_none(), "got: {}", out);
        assert_eq!(out["is_enabled"], serde_json::json!(true));
    }

    #[test]
    fn project_exported_workflow_includes_schedule_when_cron_set() {
        let r = row(serde_json::json!({"nodes": []}), Some("0 0 * * *"));
        let out = project_exported_workflow(&r);
        let schedule = out.get("schedule").expect("schedule field");
        assert_eq!(schedule["cron_expression"], serde_json::json!("0 0 * * *"));
        assert_eq!(schedule["timezone"], serde_json::json!("UTC"));
        assert_eq!(schedule["is_enabled"], serde_json::json!(true));
    }

    #[test]
    fn project_exported_workflow_handles_malformed_graph_gracefully() {
        let r = WorkflowExportRow {
            id: Uuid::new_v4(),
            name: "bad".into(),
            graph_json: "not json".into(),
            is_enabled: false,
            cron_expression: None,
            timezone: "UTC".into(),
            schedule_enabled: false,
        };
        let out = project_exported_workflow(&r);
        // graph_json defaults to {} on parse failure — same behavior as
        // pre-extraction inline code.
        assert_eq!(out["graph_json"], serde_json::json!({}));
        assert_eq!(out["is_enabled"], serde_json::json!(false));
    }

    // ── remap_graph_module_uuids tests ────────────────────────────────────

    #[test]
    fn remap_short_circuits_when_manifest_empty() {
        let graph = serde_json::json!({
            "nodes": [{"id": "n1", "type": Uuid::new_v4().to_string()}]
        });
        let out = remap_graph_module_uuids(&graph, &HashMap::new(), &HashMap::new());
        assert_eq!(out.remapped_count, 0);
        assert!(out.unresolved_module_names.is_empty());
        // Pre-extraction behavior: empty manifest returns input verbatim.
        assert_eq!(out.graph_json, graph.to_string());
    }

    #[test]
    fn remap_rewrites_node_type_when_both_maps_have_match() {
        let old_id = Uuid::new_v4();
        let new_id = Uuid::new_v4();
        let graph = serde_json::json!({
            "nodes": [{"id": "n1", "type": old_id.to_string()}]
        });
        let old_to_name = HashMap::from([(old_id.to_string(), "slack".to_string())]);
        let name_to_new = HashMap::from([("slack".to_string(), new_id)]);
        let out = remap_graph_module_uuids(&graph, &old_to_name, &name_to_new);
        assert_eq!(out.remapped_count, 1);
        assert!(out.unresolved_module_names.is_empty());
        // The rewritten graph carries the new UUID.
        let rewritten: serde_json::Value = serde_json::from_str(&out.graph_json).unwrap();
        assert_eq!(
            rewritten["nodes"][0]["type"],
            serde_json::json!(new_id.to_string())
        );
    }

    #[test]
    fn remap_records_unresolved_when_target_lacks_install() {
        let old_id = Uuid::new_v4();
        let graph = serde_json::json!({
            "nodes": [{"id": "n1", "type": old_id.to_string()}]
        });
        let old_to_name = HashMap::from([(old_id.to_string(), "missing-module".to_string())]);
        let name_to_new: HashMap<String, Uuid> = HashMap::new();
        let out = remap_graph_module_uuids(&graph, &old_to_name, &name_to_new);
        assert_eq!(out.remapped_count, 0);
        assert_eq!(
            out.unresolved_module_names,
            vec!["missing-module".to_string()]
        );
        // Source UUID is preserved when no target — caller surfaces a warning.
        let rewritten: serde_json::Value = serde_json::from_str(&out.graph_json).unwrap();
        assert_eq!(
            rewritten["nodes"][0]["type"],
            serde_json::json!(old_id.to_string())
        );
    }

    #[test]
    fn remap_rewrites_data_module_id_without_double_count() {
        let old_id = Uuid::new_v4();
        let new_id = Uuid::new_v4();
        let graph = serde_json::json!({
            "nodes": [{
                "id": "n1",
                "type": old_id.to_string(),
                "data": {"moduleId": old_id.to_string()}
            }]
        });
        let old_to_name = HashMap::from([(old_id.to_string(), "slack".to_string())]);
        let name_to_new = HashMap::from([("slack".to_string(), new_id)]);
        let out = remap_graph_module_uuids(&graph, &old_to_name, &name_to_new);
        // remapped_count counts only `type`, not data.moduleId — matches
        // pre-extraction behavior.
        assert_eq!(out.remapped_count, 1);
        let rewritten: serde_json::Value = serde_json::from_str(&out.graph_json).unwrap();
        assert_eq!(
            rewritten["nodes"][0]["type"],
            serde_json::json!(new_id.to_string())
        );
        assert_eq!(
            rewritten["nodes"][0]["data"]["moduleId"],
            serde_json::json!(new_id.to_string())
        );
    }

    #[test]
    fn remap_preserves_unrelated_node_keys() {
        let old_id = Uuid::new_v4();
        let new_id = Uuid::new_v4();
        let graph = serde_json::json!({
            "nodes": [{
                "id": "n1",
                "type": old_id.to_string(),
                "label": "Custom label",
                "data": {"moduleId": old_id.to_string(), "config": {"k": "v"}}
            }],
            "edges": [{"from": "n1", "to": "n2"}]
        });
        let old_to_name = HashMap::from([(old_id.to_string(), "slack".to_string())]);
        let name_to_new = HashMap::from([("slack".to_string(), new_id)]);
        let out = remap_graph_module_uuids(&graph, &old_to_name, &name_to_new);
        let rewritten: serde_json::Value = serde_json::from_str(&out.graph_json).unwrap();
        // Non-touched fields preserved verbatim.
        assert_eq!(
            rewritten["nodes"][0]["label"],
            serde_json::json!("Custom label")
        );
        assert_eq!(
            rewritten["nodes"][0]["data"]["config"],
            serde_json::json!({"k": "v"})
        );
        assert_eq!(rewritten["edges"][0]["from"], serde_json::json!("n1"));
    }

    // ── extract_old_uuid_to_name_from_manifest tests ─────────────────────

    #[test]
    fn extract_uuid_name_returns_empty_when_section_missing() {
        let manifest = serde_json::json!({"workflows": []});
        assert!(extract_old_uuid_to_name_from_manifest(&manifest).is_empty());
    }

    #[test]
    fn extract_uuid_name_skips_entries_without_name() {
        let id1 = Uuid::new_v4().to_string();
        let id2 = Uuid::new_v4().to_string();
        let manifest = serde_json::json!({
            "module_manifest": {
                id1.clone(): {"name": "slack", "source": "template"},
                id2.clone(): {"source": "template"}, // no name → skipped
            }
        });
        let out = extract_old_uuid_to_name_from_manifest(&manifest);
        assert_eq!(out.get(&id1), Some(&"slack".to_string()));
        assert!(!out.contains_key(&id2));
    }

    #[test]
    fn extract_uuid_name_returns_empty_when_section_not_object() {
        let manifest = serde_json::json!({"module_manifest": "not-an-object"});
        assert!(extract_old_uuid_to_name_from_manifest(&manifest).is_empty());
    }

    // ── build_name_to_new_uuid_map tests ──────────────────────────────────

    #[test]
    fn build_name_uuid_map_first_insertion_wins() {
        // Caller ordering: user-installed first (Some(user_id)), system
        // fallback second (None). build_* keeps the first.
        let user_id = Uuid::new_v4();
        let user_template = Uuid::new_v4();
        let system_template = Uuid::new_v4();
        let rows = vec![
            (user_template, "slack".to_string(), Some(user_id)),
            (system_template, "slack".to_string(), None),
        ];
        let out = build_name_to_new_uuid_map(rows);
        assert_eq!(out.get("slack"), Some(&user_template));
    }

    #[test]
    fn build_name_uuid_map_handles_distinct_names() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let rows = vec![
            (id1, "slack".to_string(), None),
            (id2, "http".to_string(), None),
        ];
        let out = build_name_to_new_uuid_map(rows);
        assert_eq!(out.len(), 2);
        assert_eq!(out["slack"], id1);
        assert_eq!(out["http"], id2);
    }

    #[test]
    fn build_name_uuid_map_empty_input() {
        assert!(build_name_to_new_uuid_map(vec![]).is_empty());
    }

    // ── preview_dry_run_workflow_warnings tests ────────────────────────────

    #[test]
    fn dry_run_warnings_flags_missing_name_with_index() {
        let workflows = vec![
            serde_json::json!({"name": "ok", "graph_json": {}}),
            serde_json::json!({"graph_json": {}}),
        ];
        let warnings = preview_dry_run_workflow_warnings(&workflows);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("index 1"));
    }

    #[test]
    fn dry_run_warnings_flags_missing_graph_json() {
        let workflows = vec![serde_json::json!({"name": "MyFlow"})];
        let warnings = preview_dry_run_workflow_warnings(&workflows);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("'MyFlow'"));
        assert!(warnings[0].contains("graph_json"));
    }

    #[test]
    fn dry_run_warnings_clean_input_yields_no_warnings() {
        let workflows = vec![
            serde_json::json!({"name": "a", "graph_json": {}}),
            serde_json::json!({"name": "b", "graph_json": {"nodes": []}}),
        ];
        assert!(preview_dry_run_workflow_warnings(&workflows).is_empty());
    }

    // ── preview_module_remap tests ─────────────────────────────────────────

    #[test]
    fn preview_remap_counts_resolvable_and_lists_unresolvable() {
        let id1 = Uuid::new_v4().to_string();
        let id2 = Uuid::new_v4().to_string();
        let new_id = Uuid::new_v4();
        let old_to_name = HashMap::from([
            (id1.clone(), "slack".to_string()),
            (id2.clone(), "missing".to_string()),
        ]);
        let name_to_new = HashMap::from([("slack".to_string(), new_id)]);
        let preview = preview_module_remap(&old_to_name, &name_to_new);
        assert_eq!(preview.remapped, 1);
        assert_eq!(preview.unresolved.len(), 1);
        assert!(preview.unresolved[0].contains("'missing'"));
        assert!(preview.unresolved[0].contains(&id2));
    }

    #[test]
    fn preview_remap_empty_inputs() {
        let p = preview_module_remap(&HashMap::new(), &HashMap::new());
        assert_eq!(p.remapped, 0);
        assert!(p.unresolved.is_empty());
    }

    // ── parse_imported_schedule tests ──────────────────────────────────────

    #[test]
    fn parse_schedule_returns_none_when_cron_missing() {
        let schedule = serde_json::json!({"timezone": "UTC", "is_enabled": true});
        assert!(parse_imported_schedule(&schedule).is_none());
    }

    #[test]
    fn parse_schedule_returns_none_when_cron_empty() {
        let schedule = serde_json::json!({"cron_expression": "", "timezone": "UTC"});
        assert!(parse_imported_schedule(&schedule).is_none());
    }

    #[test]
    fn parse_schedule_uses_default_timezone_and_enabled() {
        let schedule = serde_json::json!({"cron_expression": "0 0 * * *"});
        let parsed = parse_imported_schedule(&schedule).expect("parsed");
        assert_eq!(parsed.cron_expression, "0 0 * * *");
        assert_eq!(parsed.timezone, "UTC");
        assert!(parsed.is_enabled);
    }

    #[test]
    fn parse_schedule_honors_explicit_disabled_flag() {
        let schedule = serde_json::json!({"cron_expression": "*/5 * * * *", "is_enabled": false});
        let parsed = parse_imported_schedule(&schedule).expect("parsed");
        assert!(!parsed.is_enabled);
    }

    #[test]
    fn parse_schedule_passes_through_explicit_timezone() {
        let schedule = serde_json::json!({
            "cron_expression": "0 12 * * *",
            "timezone": "America/Los_Angeles",
        });
        let parsed = parse_imported_schedule(&schedule).expect("parsed");
        assert_eq!(parsed.timezone, "America/Los_Angeles");
    }

    #[test]
    fn remap_handles_unknown_old_uuid_in_graph_silently() {
        // Node references an old UUID that's NOT in old_to_name (orphan).
        // Pre-extraction behavior: pass through, no warning.
        let orphan_id = Uuid::new_v4();
        let graph = serde_json::json!({
            "nodes": [{"id": "n1", "type": orphan_id.to_string()}]
        });
        let old_to_name = HashMap::from([(Uuid::new_v4().to_string(), "other".to_string())]);
        let name_to_new = HashMap::from([("other".to_string(), Uuid::new_v4())]);
        let out = remap_graph_module_uuids(&graph, &old_to_name, &name_to_new);
        assert_eq!(out.remapped_count, 0);
        assert!(out.unresolved_module_names.is_empty());
    }

    // -- format_pgvector_literal --

    #[test]
    fn pgvector_literal_empty() {
        assert_eq!(format_pgvector_literal(&[]), "[]");
    }

    #[test]
    fn pgvector_literal_round_trip() {
        let s = format_pgvector_literal(&[0.1, -0.2, 1.0]);
        assert_eq!(s, "[0.1,-0.2,1]");
    }

    // -- compute_keyword_match_score --

    fn pat(w: &str) -> String {
        format!("%{}%", w)
    }

    #[test]
    fn score_name_match_weighted_3() {
        let words = vec![pat("foo")];
        let s = compute_keyword_match_score("FooBar", None, &[], None, &words);
        assert_eq!(s, 3);
    }

    #[test]
    fn score_description_weighted_2() {
        let words = vec![pat("alpha")];
        let s = compute_keyword_match_score("x", Some("contains alpha here"), &[], None, &words);
        assert_eq!(s, 2);
    }

    #[test]
    fn score_capability_weighted_2() {
        let words = vec![pat("http")];
        let caps = vec!["HTTP_FETCH".to_string(), "redis".to_string()];
        let s = compute_keyword_match_score("x", None, &caps, None, &words);
        assert_eq!(s, 2);
    }

    #[test]
    fn score_intent_weighted_1() {
        let words = vec![pat("search")];
        let intent = serde_json::json!({"goal": "user search query"});
        let s = compute_keyword_match_score("x", None, &[], Some(&intent), &words);
        assert_eq!(s, 1);
    }

    #[test]
    fn score_aggregates_all_fields_and_words() {
        // Two words, both hitting name (+3) and description (+2) → 10.
        let words = vec![pat("alpha"), pat("beta")];
        let s = compute_keyword_match_score(
            "alpha and beta",
            Some("alpha-beta soup"),
            &[],
            None,
            &words,
        );
        assert_eq!(s, 10);
    }

    #[test]
    fn score_no_match_zero() {
        let words = vec![pat("missing")];
        let s = compute_keyword_match_score("foo", Some("bar"), &[], None, &words);
        assert_eq!(s, 0);
    }

    #[test]
    fn score_case_insensitive() {
        // Lowercased words searching uppercased fields still match.
        let words = vec![pat("foo")];
        let s = compute_keyword_match_score("FOO", Some("FOO BAR"), &[], None, &words);
        assert_eq!(s, 5);
    }

    #[test]
    fn score_strips_outer_percent_markers() {
        // Patterns from the handler arrive wrapped in `%`; the helper trims them.
        let words = vec!["%foo%".to_string()];
        let s = compute_keyword_match_score("foo", None, &[], None, &words);
        assert_eq!(s, 3);
    }

    // -- sanitize_module_cargo_name --

    #[test]
    fn cargo_name_lowercases_alphanumerics() {
        assert_eq!(sanitize_module_cargo_name("FooBar2"), "foobar2");
    }

    #[test]
    fn cargo_name_replaces_specials_with_dash() {
        assert_eq!(
            sanitize_module_cargo_name("My Cool/Module v1.0"),
            "my-cool-module-v1-0"
        );
    }

    #[test]
    fn cargo_name_trims_leading_trailing_dashes() {
        assert_eq!(sanitize_module_cargo_name("!!foo!!"), "foo");
    }

    #[test]
    fn cargo_name_empty_when_all_specials() {
        assert_eq!(sanitize_module_cargo_name("!!!"), "");
    }

    // -- extract_bundle_module_metadata --

    #[test]
    fn bundle_meta_full_fields() {
        let v = serde_json::json!({
            "source_code": "fn main() {}",
            "name": "MyMod",
            "capability_world": "http-node",
        });
        let m = extract_bundle_module_metadata(&v);
        assert_eq!(m.source, Some("fn main() {}"));
        assert_eq!(m.mod_name, "MyMod");
        assert_eq!(m.cap_world, "http-node");
    }

    #[test]
    fn bundle_meta_falls_back_to_code_template() {
        let v = serde_json::json!({
            "code_template": "fn main() {}",
        });
        let m = extract_bundle_module_metadata(&v);
        assert_eq!(m.source, Some("fn main() {}"));
    }

    #[test]
    fn bundle_meta_source_code_wins_over_code_template() {
        let v = serde_json::json!({
            "source_code": "primary",
            "code_template": "secondary",
        });
        let m = extract_bundle_module_metadata(&v);
        assert_eq!(m.source, Some("primary"));
    }

    #[test]
    fn bundle_meta_defaults_when_missing() {
        let v = serde_json::json!({});
        let m = extract_bundle_module_metadata(&v);
        assert_eq!(m.source, None);
        assert_eq!(m.mod_name, "imported-module");
        assert_eq!(m.cap_world, "minimal-node");
    }

    // -- extract_module_ids_from_graph_value --

    #[test]
    fn graph_value_extracts_uuid_typed_nodes() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let graph = serde_json::json!({
            "nodes": [
                {"id": "n1", "type": id1.to_string()},
                {"id": "n2", "type": id2.to_string()},
            ]
        });
        let out = extract_module_ids_from_graph_value(&graph);
        assert_eq!(out, vec![id1, id2]);
    }

    #[test]
    fn graph_value_skips_non_uuid_types() {
        let id = Uuid::new_v4();
        let graph = serde_json::json!({
            "nodes": [
                {"id": "n0", "type": "system:approval"},
                {"id": "n1", "type": id.to_string()},
                {"id": "n2", "type": "not-a-uuid"},
            ]
        });
        let out = extract_module_ids_from_graph_value(&graph);
        assert_eq!(out, vec![id]);
    }

    #[test]
    fn graph_value_empty_when_no_nodes() {
        let graph = serde_json::json!({});
        assert!(extract_module_ids_from_graph_value(&graph).is_empty());
    }

    // -- module_export_info_to_json --

    fn export_info(with_src: bool, with_tpl: bool, cap: Option<&str>) -> ModuleExportInfo {
        ModuleExportInfo {
            id: Uuid::nil(),
            name: "MyMod".into(),
            category: "core".into(),
            capability_world: cap.map(|s| s.to_string()),
            source_code: with_src.then(|| "fn main() {}".to_string()),
            code_template: with_tpl.then(|| "TEMPLATE".to_string()),
        }
    }

    #[test]
    fn export_json_emits_required_fields() {
        let info = export_info(false, false, Some("http-node"));
        let v = module_export_info_to_json(&info);
        assert_eq!(
            v.get("id").and_then(|s| s.as_str()),
            Some(Uuid::nil().to_string().as_str())
        );
        assert_eq!(v.get("name").and_then(|s| s.as_str()), Some("MyMod"));
        assert_eq!(v.get("category").and_then(|s| s.as_str()), Some("core"));
        assert_eq!(
            v.get("capability_world").and_then(|s| s.as_str()),
            Some("http-node")
        );
        assert!(v.get("source_code").is_none());
        assert!(v.get("code_template").is_none());
    }

    #[test]
    fn export_json_includes_source_when_present() {
        let info = export_info(true, false, None);
        let v = module_export_info_to_json(&info);
        assert_eq!(
            v.get("source_code").and_then(|s| s.as_str()),
            Some("fn main() {}")
        );
        assert!(v.get("code_template").is_none());
    }

    #[test]
    fn export_json_includes_both_source_and_template() {
        let info = export_info(true, true, Some("minimal-node"));
        let v = module_export_info_to_json(&info);
        assert!(v.get("source_code").is_some());
        assert!(v.get("code_template").is_some());
    }

    // -- extract_node_type_strings --

    #[test]
    fn node_type_strings_collects_all_types() {
        let id = Uuid::new_v4();
        let graph = serde_json::json!({
            "nodes": [
                {"id": "n1", "type": id.to_string()},
                {"id": "n2", "type": "system:judge"},
                {"id": "n3", "type": "system:collect"},
            ]
        });
        let out = extract_node_type_strings(&graph);
        assert!(out.contains(&id.to_string()));
        assert!(out.contains("system:judge"));
        assert!(out.contains("system:collect"));
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn node_type_strings_dedupes_repeated_types() {
        let graph = serde_json::json!({
            "nodes": [
                {"id": "a", "type": "system:judge"},
                {"id": "b", "type": "system:judge"},
                {"id": "c", "type": "system:judge"},
            ]
        });
        let out = extract_node_type_strings(&graph);
        assert_eq!(out.len(), 1);
        assert!(out.contains("system:judge"));
    }

    #[test]
    fn node_type_strings_empty_when_no_nodes() {
        let graph = serde_json::json!({});
        assert!(extract_node_type_strings(&graph).is_empty());
    }

    #[test]
    fn node_type_strings_skips_non_string_type() {
        let graph = serde_json::json!({
            "nodes": [
                {"id": "a", "type": null},
                {"id": "b"}, // missing type
                {"id": "c", "type": "system:judge"},
            ]
        });
        let out = extract_node_type_strings(&graph);
        assert_eq!(out.len(), 1);
        assert!(out.contains("system:judge"));
    }

    // -- WorkflowExecStats helpers --

    fn stats(total: i64, succeeded: i64, avg: Option<f64>) -> WorkflowExecStats {
        WorkflowExecStats {
            total,
            succeeded,
            failed: total - succeeded,
            running: 0,
            avg_duration_secs: avg,
        }
    }

    #[test]
    fn exec_stats_empty_zeroes_all_fields() {
        let s = WorkflowExecStats::empty();
        assert_eq!(s.total, 0);
        assert_eq!(s.succeeded, 0);
        assert_eq!(s.failed, 0);
        assert_eq!(s.running, 0);
        assert_eq!(s.avg_duration_secs, None);
    }

    #[test]
    fn success_rate_zero_when_no_runs() {
        assert_eq!(WorkflowExecStats::empty().success_rate_percent(), 0.0);
    }

    #[test]
    fn success_rate_full_when_all_succeed() {
        assert_eq!(stats(10, 10, None).success_rate_percent(), 100.0);
    }

    #[test]
    fn success_rate_proportional() {
        assert_eq!(stats(4, 1, None).success_rate_percent(), 25.0);
        assert_eq!(stats(8, 2, None).success_rate_percent(), 25.0);
    }

    #[test]
    fn stats_to_json_emits_canonical_shape() {
        let v = stats(10, 7, Some(1.5)).to_json(30);
        assert_eq!(v.get("period_days").and_then(|x| x.as_i64()), Some(30));
        assert_eq!(v.get("total_executions").and_then(|x| x.as_i64()), Some(10));
        assert_eq!(v.get("succeeded").and_then(|x| x.as_i64()), Some(7));
        assert_eq!(v.get("failed").and_then(|x| x.as_i64()), Some(3));
        // MCP-19: success_rate_percent emits a JSON number, not a string.
        assert_eq!(
            v.get("success_rate_percent").and_then(|x| x.as_f64()),
            Some(70.0)
        );
        assert_eq!(
            v.get("avg_duration_secs").and_then(|x| x.as_f64()),
            Some(1.5)
        );
    }

    #[test]
    fn stats_to_json_handles_zero_total() {
        let v = WorkflowExecStats::empty().to_json(7);
        assert_eq!(v.get("total_executions").and_then(|x| x.as_i64()), Some(0));
        // MCP-19: numeric output, not string.
        assert_eq!(
            v.get("success_rate_percent").and_then(|x| x.as_f64()),
            Some(0.0)
        );
        assert!(v
            .get("avg_duration_secs")
            .map(|x| x.is_null())
            .unwrap_or(false));
    }

    // -- find_node_by_id / graph_contains_node_id --

    #[test]
    fn finds_node_by_string_id() {
        let graph = serde_json::json!({
            "nodes": [
                {"id": "n1", "type": "minimal"},
                {"id": "n2", "type": "http"},
            ]
        });
        let node = find_node_by_id(&graph, "n2").unwrap();
        assert_eq!(node.get("type").and_then(|v| v.as_str()), Some("http"));
    }

    #[test]
    fn find_returns_none_when_id_absent() {
        let graph = serde_json::json!({
            "nodes": [{"id": "n1"}]
        });
        assert!(find_node_by_id(&graph, "missing").is_none());
    }

    #[test]
    fn find_returns_none_when_no_nodes_field() {
        let graph = serde_json::json!({"edges": []});
        assert!(find_node_by_id(&graph, "anything").is_none());
    }

    #[test]
    fn find_skips_node_without_string_id() {
        let graph = serde_json::json!({
            "nodes": [
                {"id": 42},          // numeric id — not a string
                {"id": "real"},
            ]
        });
        // Numeric ids aren't strings — non-matching, then matches "real".
        assert!(find_node_by_id(&graph, "real").is_some());
        assert!(find_node_by_id(&graph, "42").is_none());
    }

    #[test]
    fn graph_contains_matches_find_existence() {
        let graph = serde_json::json!({
            "nodes": [{"id": "first"}]
        });
        assert!(graph_contains_node_id(&graph, "first"));
        assert!(!graph_contains_node_id(&graph, "second"));
    }

    // -- find_node_in_array --

    #[test]
    fn find_node_in_array_matches_first_id() {
        let nodes = vec![
            serde_json::json!({"id": "a", "kind": "src"}),
            serde_json::json!({"id": "b", "kind": "tgt"}),
        ];
        let n = find_node_in_array(&nodes, "b").unwrap();
        assert_eq!(n.get("kind").and_then(|v| v.as_str()), Some("tgt"));
    }

    #[test]
    fn find_node_in_array_returns_none_on_miss() {
        let nodes = vec![serde_json::json!({"id": "only"})];
        assert!(find_node_in_array(&nodes, "missing").is_none());
    }

    #[test]
    fn find_node_in_array_skips_non_string_ids() {
        let nodes = vec![
            serde_json::json!({"id": 42}),
            serde_json::json!({"id": null}),
            serde_json::json!({"id": "real"}),
        ];
        assert!(find_node_in_array(&nodes, "real").is_some());
        assert!(find_node_in_array(&nodes, "42").is_none());
    }

    #[test]
    fn find_node_in_array_empty_slice_is_none() {
        let nodes: Vec<serde_json::Value> = Vec::new();
        assert!(find_node_in_array(&nodes, "anything").is_none());
    }

    // -- remove_edge_by_endpoints --

    #[test]
    fn remove_edge_by_endpoints_drops_match() {
        let mut graph = serde_json::json!({
            "edges": [
                {"source": "a", "target": "b"},
                {"source": "b", "target": "c"},
            ]
        });
        let removed = remove_edge_by_endpoints(&mut graph, "a", "b");
        assert!(removed);
        let edges = graph.get("edges").unwrap().as_array().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].get("source").and_then(|v| v.as_str()), Some("b"));
    }

    #[test]
    fn remove_edge_by_endpoints_no_match_returns_false() {
        let mut graph = serde_json::json!({
            "edges": [{"source": "a", "target": "b"}]
        });
        let removed = remove_edge_by_endpoints(&mut graph, "x", "y");
        assert!(!removed);
        assert_eq!(graph.get("edges").unwrap().as_array().unwrap().len(), 1);
    }

    #[test]
    fn remove_edge_by_endpoints_handles_missing_edges_field() {
        let mut graph = serde_json::json!({"nodes": []});
        assert!(!remove_edge_by_endpoints(&mut graph, "a", "b"));
    }

    #[test]
    fn remove_edge_by_endpoints_only_drops_exact_pair() {
        // (a,b) must match BOTH source and target — partial matches stay.
        let mut graph = serde_json::json!({
            "edges": [
                {"source": "a", "target": "x"},  // wrong target
                {"source": "y", "target": "b"},  // wrong source
                {"source": "a", "target": "b"},  // exact match
            ]
        });
        assert!(remove_edge_by_endpoints(&mut graph, "a", "b"));
        assert_eq!(graph.get("edges").unwrap().as_array().unwrap().len(), 2);
    }

    // -- remove_edges_connected_to_node --

    #[test]
    fn remove_edges_connected_to_node_strips_in_and_out() {
        let mut graph = serde_json::json!({
            "edges": [
                {"source": "a", "target": "b"},  // outgoing
                {"source": "b", "target": "c"},  // outgoing
                {"source": "x", "target": "a"},  // incoming
                {"source": "y", "target": "z"},  // unrelated
            ]
        });
        let removed = remove_edges_connected_to_node(&mut graph, "a");
        assert_eq!(removed.len(), 2);
        assert!(removed.contains(&("a".to_string(), "b".to_string())));
        assert!(removed.contains(&("x".to_string(), "a".to_string())));
        let remaining = graph.get("edges").unwrap().as_array().unwrap();
        assert_eq!(remaining.len(), 2);
    }

    #[test]
    fn remove_edges_connected_to_node_empty_when_no_match() {
        let mut graph = serde_json::json!({
            "edges": [
                {"source": "x", "target": "y"},
            ]
        });
        let removed = remove_edges_connected_to_node(&mut graph, "missing");
        assert!(removed.is_empty());
    }

    #[test]
    fn remove_edges_connected_to_node_handles_missing_edges_field() {
        let mut graph = serde_json::json!({"nodes": []});
        assert!(remove_edges_connected_to_node(&mut graph, "a").is_empty());
    }

    // -- is_sub_workflow_node --

    #[test]
    fn is_sub_workflow_matches_canonical_type() {
        let n = serde_json::json!({"type": "system:sub_workflow"});
        assert!(is_sub_workflow_node(&n));
    }

    #[test]
    fn is_sub_workflow_matches_legacy_kind() {
        let n = serde_json::json!({"kind": "sub_workflow"});
        assert!(is_sub_workflow_node(&n));
    }

    #[test]
    fn is_sub_workflow_rejects_other_system_nodes() {
        let n = serde_json::json!({"type": "system:judge"});
        assert!(!is_sub_workflow_node(&n));
    }

    #[test]
    fn is_sub_workflow_rejects_module_node() {
        let n = serde_json::json!({"type": "550e8400-e29b-41d4-a716-446655440000"});
        assert!(!is_sub_workflow_node(&n));
    }

    // -- extract_sub_workflow_id_strings / _uuids --

    #[test]
    fn extracts_id_string_from_data_field() {
        let id = Uuid::new_v4().to_string();
        let graph = serde_json::json!({
            "nodes": [
                {"type": "system:sub_workflow", "data": {"sub_workflow_id": id.clone()}},
                {"type": "system:judge"},
            ]
        });
        let out = extract_sub_workflow_id_strings(&graph);
        assert_eq!(out, vec![id]);
    }

    #[test]
    fn extracts_uuids_filters_unparseable() {
        let valid = Uuid::new_v4();
        let graph = serde_json::json!({
            "nodes": [
                {"type": "system:sub_workflow", "data": {"sub_workflow_id": valid.to_string()}},
                {"type": "system:sub_workflow", "data": {"sub_workflow_id": "not-a-uuid"}},
            ]
        });
        let out = extract_sub_workflow_uuids(&graph);
        assert_eq!(out, vec![valid]);
    }

    #[test]
    fn extracts_empty_when_no_sub_workflow_nodes() {
        let graph = serde_json::json!({
            "nodes": [{"type": "system:judge"}, {"type": "system:collect"}]
        });
        assert!(extract_sub_workflow_id_strings(&graph).is_empty());
    }

    #[test]
    fn extracts_handles_legacy_kind_too() {
        let id = Uuid::new_v4().to_string();
        let graph = serde_json::json!({
            "nodes": [
                {"kind": "sub_workflow", "data": {"sub_workflow_id": id.clone()}},
            ]
        });
        let out = extract_sub_workflow_id_strings(&graph);
        assert_eq!(out, vec![id]);
    }

    #[test]
    fn extracts_skips_nodes_missing_data_field() {
        // Sub-workflow node without a data.sub_workflow_id: silently dropped.
        let graph = serde_json::json!({
            "nodes": [{"type": "system:sub_workflow"}]
        });
        assert!(extract_sub_workflow_id_strings(&graph).is_empty());
    }

    // -- extract_node_id_strings --

    #[test]
    fn node_id_strings_preserves_document_order() {
        let graph = serde_json::json!({
            "nodes": [
                {"id": "alpha"},
                {"id": "bravo"},
                {"id": "charlie"},
            ]
        });
        let out = extract_node_id_strings(&graph);
        assert_eq!(out, vec!["alpha", "bravo", "charlie"]);
    }

    #[test]
    fn node_id_strings_skips_missing_or_non_string_id() {
        let graph = serde_json::json!({
            "nodes": [
                {"id": "real"},
                {"id": 42},          // numeric — skipped
                {},                   // no id — skipped
                {"id": "another"},
            ]
        });
        let out = extract_node_id_strings(&graph);
        assert_eq!(out, vec!["real", "another"]);
    }

    #[test]
    fn node_id_strings_empty_when_no_nodes_field() {
        assert!(extract_node_id_strings(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn node_id_strings_collects_into_hashset_via_into_iter() {
        // The returned Vec is movable into a HashSet for callers that
        // want set semantics — covers the analytics.rs use case.
        let graph = serde_json::json!({
            "nodes": [{"id": "a"}, {"id": "b"}, {"id": "a"}]
        });
        let set: std::collections::HashSet<String> =
            extract_node_id_strings(&graph).into_iter().collect();
        assert_eq!(set.len(), 2);
    }
}
