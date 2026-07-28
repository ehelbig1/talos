//! Twinned-workflow divergence detection — pure graph analysis for the
//! hygiene report. Sibling of [`crate::graph_heuristics`]: no DB, no IO,
//! every function here is testable from a string fixture.
//!
//! ## Why this exists
//!
//! Twice in one week a defect was fixed on ONE instance of a duplicated
//! workflow and left live on its twin: `pa-inbox-organizer-work` got the
//! `coverage_judge` leaf while `pa-inbox-organizer` stayed broken, and days
//! later the same manual sync had to be repeated for a judge verdict fix.
//! The standing rule ("a defect fixed on one instance of a duplicated
//! workflow is not fixed — grep the twins") had nothing enforcing it. This
//! module is the advisory enforcement: it pairs twins by NAME, diffs their
//! graphs, and grades the differences so only the incident class earns a
//! recommendation.
//!
//! ## What it can and cannot see (honesty contract)
//!
//! * Pairing is a **name heuristic**. Twins named disjointly (`inbox-home`
//!   vs `inbox-office`) are invisible to it. It never claims "no twins
//!   diverged" — only "no divergence found among the pairs it could see".
//! * **No config values are ever emitted** — key names and encoded byte
//!   lengths only. Node configs hold prompts, account identifiers and
//!   `vault://` paths; the report is operator-facing and must stay tight
//!   and injection-free. A byte-length difference proves the values differ;
//!   equal lengths prove nothing about semantic equality.
//! * Divergence is not automatically a bug. Real twins legitimately differ
//!   in ONE classifier module and in their auth/prompt configs. Those land
//!   as info/detail grade and never raise a recommendation (no wolf-crying).

use std::collections::{BTreeMap, BTreeSet};

/// Node/`data` keys whose divergence between twins is the incident class:
/// control logic that decides whether work happens, is retried, is judged
/// passing, or is considered fresh. A difference here means one twin is
/// making a different DECISION than the other — exactly the
/// `verdict_expr`-drift case that had to be hand-synced.
///
/// Matched on the LAST path segment, so both a node-level `retry_count`
/// and a `data.retry_count` count. Deliberately a FIXED list: an
/// open-ended "anything that looks like logic" rule would drag prompts and
/// thresholds-by-another-name into recommendation grade and train
/// operators to ignore the section.
const CONTROL_LOGIC_KEYS: &[&str] = &[
    "verdict_expr",
    "skip_condition",
    "retry_condition",
    "retry_count",
    "retry_backoff_ms",
    "continue_on_error",
    "requires_fresh",
    "on_stale",
    "needs_memory",
    "max_fuel",
    "timeout_secs",
    "pass_threshold",
    "on_failure",
];

/// React-Flow presentation keys. Two twins laid out differently on the
/// canvas are not diverged in any sense an operator cares about, and
/// including them would bury the real findings under coordinate noise.
const PRESENTATION_KEYS: &[&str] = &[
    "position",
    "positionAbsolute",
    "width",
    "height",
    "selected",
    "dragging",
    "style",
    "measured",
    "zIndex",
    "handleBounds",
    "sourcePosition",
    "targetPosition",
    "dragHandle",
    "resizing",
    "focusable",
    "deletable",
    "draggable",
    "connectable",
    "parentId",
    "extent",
    "expandParent",
    "ariaLabel",
];

/// Minimum length of the name suffix that makes two workflows twins
/// (separator + at least one character). Blocks the degenerate `a` / `a-`
/// pairing while allowing the observed `x` / `x-work` convention.
const MIN_SUFFIX_LEN: usize = 2;

/// One workflow graph offered to the analyzer. Deliberately a plain
/// owned-string struct rather than the repository row type so this module
/// stays dependency-free and its tests need no DB types.
#[derive(Debug, Clone)]
pub struct TwinCandidate {
    /// Workflow id, stringified by the caller (only ever echoed back).
    pub id: String,
    /// Workflow name — the ONLY pairing signal.
    pub name: String,
    /// Raw `graph_json` text. Malformed content is fail-soft (counted,
    /// never panics, never sinks the report).
    pub graph_json: String,
}

/// Which side of a pair a finding was observed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The base (shorter-named) workflow.
    A,
    /// The suffixed variant.
    B,
}

impl Side {
    fn label(self) -> &'static str {
        match self {
            Side::A => "a",
            Side::B => "b",
        }
    }

    fn other(self) -> Side {
        match self {
            Side::A => Side::B,
            Side::B => Side::A,
        }
    }
}

/// Recommendation-grade: a node or edge exists in one twin and not the
/// other. THE incident (`coverage_judge` present in one organizer only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructuralFinding {
    /// Node present on `present_in`, absent from the other side.
    MissingNode {
        /// Node id, in the id space of the side that HAS it.
        node: String,
        /// Side the node was found on.
        present_in: Side,
    },
    /// Edge between two matched nodes present on `present_in` only.
    /// Endpoints are always expressed in side A's id space so both twins'
    /// edges are comparable.
    MissingEdge {
        /// Source node id (A-side id space).
        source: String,
        /// Target node id (A-side id space).
        target: String,
        /// Side the edge was found on.
        present_in: Side,
    },
}

/// Recommendation-grade config divergence on a matched node: a key from
/// [`CONTROL_LOGIC_KEYS`]. Values are NEVER carried — only the encoded
/// byte length of each side (`None` = key absent on that side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlLogicFinding {
    /// Matched node, named in A's id space.
    pub node: String,
    /// Key path (`retry_count` or `data.verdict_expr`).
    pub key: String,
    /// Compact-JSON byte length of A's value; `None` when A lacks the key.
    pub a_len: Option<usize>,
    /// Compact-JSON byte length of B's value; `None` when B lacks the key.
    pub b_len: Option<usize>,
}

/// Detail-grade config divergence: every other key. Expected between real
/// twins (auth headers, prompts, account ids) and never recommendation
/// grade. Same value-free contract as [`ControlLogicFinding`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceFinding {
    /// Matched node, named in A's id space.
    pub node: String,
    /// Key path.
    pub key: String,
    /// Compact-JSON byte length of A's value; `None` when A lacks the key.
    pub a_len: Option<usize>,
    /// Compact-JSON byte length of B's value; `None` when B lacks the key.
    pub b_len: Option<usize>,
}

/// Info-grade: matched nodes run different modules / system kinds. The
/// real organizers legitimately do this (hybrid-classify vs LLM
/// inference), so it is reported without values and without escalating to
/// a recommendation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeMismatch {
    /// Matched node, named in A's id space.
    pub node: String,
    /// `"type"` or `"kind"`.
    pub field: String,
}

/// Everything found for one twin pair.
#[derive(Debug, Clone)]
pub struct TwinPair {
    /// Base workflow (id, name).
    pub a: (String, String),
    /// Suffixed variant (id, name).
    pub b: (String, String),
    /// The name suffix that made them a pair (e.g. `-work`).
    pub suffix: String,
    /// Recommendation-grade structural findings.
    pub structural: Vec<StructuralFinding>,
    /// Recommendation-grade control-logic findings.
    pub control_logic: Vec<ControlLogicFinding>,
    /// Detail-grade per-instance config divergence (expected).
    pub instance: Vec<InstanceFinding>,
    /// Info-grade module/kind mismatches on matched nodes.
    pub type_mismatches: Vec<TypeMismatch>,
    /// How many nodes were matched across the pair.
    pub matched_nodes: usize,
    /// A-side node ids with no counterpart.
    pub unmatched_a: Vec<String>,
    /// B-side node ids with no counterpart.
    pub unmatched_b: Vec<String>,
}

impl TwinPair {
    /// True when the pair carries at least one recommendation-grade
    /// finding. Detail/info grade alone deliberately does NOT qualify.
    pub fn is_recommendation_grade(&self) -> bool {
        !self.structural.is_empty() || !self.control_logic.is_empty()
    }
}

/// Result of a whole-fleet twin scan.
#[derive(Debug, Clone, Default)]
pub struct TwinAnalysis {
    /// Every detected pair, including clean ones (a clean pair is
    /// evidence the check ran, not noise).
    pub pairs: Vec<TwinPair>,
    /// Graphs whose `graph_json` could not be parsed into a node list.
    /// They are excluded from pairing entirely — counted so the caller can
    /// qualify an empty finding list.
    pub unparsable_graphs: usize,
}

impl TwinAnalysis {
    /// Pairs carrying recommendation-grade findings.
    pub fn diverged_pairs(&self) -> impl Iterator<Item = &TwinPair> {
        self.pairs.iter().filter(|p| p.is_recommendation_grade())
    }
}

// ---------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------

struct ParsedNode<'a> {
    id: &'a str,
    type_label: Option<&'a str>,
    kind: Option<&'a str>,
    /// Flattened comparable config: node-level keys plus `data.<k>`.
    keys: BTreeMap<String, &'a serde_json::Value>,
}

struct ParsedGraph<'a> {
    nodes: Vec<ParsedNode<'a>>,
    edges: Vec<(&'a str, &'a str)>,
}

/// Parse one graph. Returns `None` (→ counted as unparsable) when the JSON
/// is malformed, has no `nodes` array, or any node lacks a string `id` —
/// without a stable id there is nothing to match on and a partial diff
/// would be worse than no diff.
fn parse_graph_value(doc: &serde_json::Value) -> Option<ParsedGraph<'_>> {
    let node_vals = doc.get("nodes")?.as_array()?;
    let mut nodes = Vec::with_capacity(node_vals.len());
    for n in node_vals {
        let obj = n.as_object()?;
        let id = obj.get("id")?.as_str()?;
        if id.is_empty() {
            return None;
        }
        let mut keys: BTreeMap<String, &serde_json::Value> = BTreeMap::new();
        for (k, v) in obj {
            if k == "id" || k == "type" || k == "kind" || k == "data" {
                continue;
            }
            if PRESENTATION_KEYS.contains(&k.as_str()) {
                continue;
            }
            keys.insert(k.clone(), v);
        }
        if let Some(data) = obj.get("data").and_then(|d| d.as_object()) {
            for (k, v) in data {
                if PRESENTATION_KEYS.contains(&k.as_str()) {
                    continue;
                }
                keys.insert(format!("data.{k}"), v);
            }
        }
        nodes.push(ParsedNode {
            id,
            type_label: obj.get("type").and_then(|v| v.as_str()),
            kind: obj.get("kind").and_then(|v| v.as_str()),
            keys,
        });
    }

    // Edges are best-effort: an entry without string endpoints is ignored
    // rather than sinking the whole graph — the node diff is still useful.
    let mut edges = Vec::new();
    if let Some(edge_vals) = doc.get("edges").and_then(|e| e.as_array()) {
        for e in edge_vals {
            let (Some(s), Some(t)) = (
                e.get("source").and_then(|v| v.as_str()),
                e.get("target").and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            edges.push((s, t));
        }
    }

    Some(ParsedGraph { nodes, edges })
}

// ---------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------

/// True when `suffix` is a valid twin-name suffix: separator-led
/// (`-`/`_`) and at least [`MIN_SUFFIX_LEN`] characters, so `x` / `x-work`
/// pairs while `x` / `xy` and `x` / `x-` do not.
fn is_twin_suffix(suffix: &str) -> bool {
    suffix.len() >= MIN_SUFFIX_LEN && (suffix.starts_with('-') || suffix.starts_with('_'))
}

/// THE THREE-WAY RULE: each name pairs with its NEAREST present ancestor —
/// the LONGEST other name that it extends by a valid suffix.
///
/// * `x`, `x-work`, `x-team` → `(x, x-work)` and `(x, x-team)`. The two
///   variants are NOT paired with each other: neither name is a prefix of
///   the other, so no suffix relationship exists.
/// * `x`, `x-work`, `x-work-team` → `(x, x-work)` and
///   `(x-work, x-work-team)`. `x-work-team` extends BOTH, and the nearest
///   (longest) ancestor is the more likely true twin.
///
/// Consequence worth knowing: each name has at most ONE ancestor, so a
/// base with N variants yields N pairs, not N², and the whole scan is
/// bounded by `candidates - 1` pairs.
fn nearest_ancestor(name: &str, names: &[&str]) -> Option<usize> {
    let mut best: Option<usize> = None;
    for (i, cand) in names.iter().enumerate() {
        if *cand == name {
            continue;
        }
        let Some(suffix) = name.strip_prefix(cand) else {
            continue;
        };
        if !is_twin_suffix(suffix) {
            continue;
        }
        match best {
            Some(b) if names[b].len() >= cand.len() => {}
            _ => best = Some(i),
        }
    }
    best
}

/// Node-id suffixes to try when matching across a pair. Real twins carry
/// the workflow suffix on their node ids with a possibly DIFFERENT
/// separator (`pa-inbox-organizer-work` holds `classify_work`), so the raw
/// suffix and both separator forms of its stem are all candidates.
fn node_suffix_candidates(name_suffix: &str) -> Vec<String> {
    let stem = &name_suffix[1..];
    let mut out = vec![name_suffix.to_string()];
    for sep in ['-', '_'] {
        let candidate = format!("{sep}{stem}");
        if !out.contains(&candidate) {
            out.push(candidate);
        }
    }
    out
}

// ---------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------

fn encoded_len(v: &serde_json::Value) -> usize {
    serde_json::to_string(v).map(|s| s.len()).unwrap_or(0)
}

fn leaf_key(key: &str) -> &str {
    key.rsplit('.').next().unwrap_or(key)
}

fn degrees<'a>(graph: &ParsedGraph<'a>) -> BTreeMap<&'a str, (usize, usize)> {
    let mut d: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for n in &graph.nodes {
        d.entry(n.id).or_insert((0, 0));
    }
    for (s, t) in &graph.edges {
        d.entry(s).or_insert((0, 0)).1 += 1;
        d.entry(t).or_insert((0, 0)).0 += 1;
    }
    d
}

/// Match B's nodes onto A's in three passes. Returns `b_id -> a_id`.
///
/// 1. exact id equality (nodes the author didn't rename);
/// 2. suffix-stripped equality (`classify_work` → `classify`) — run AFTER
///    the exact pass so a graph containing both `classify` and
///    `classify_work` can't have the stripped form steal the exact match;
/// 3. `(type, kind, in-degree, out-degree)` signature, accepted only when
///    the signature is UNIQUE among the leftovers on BOTH sides. A
///    non-unique signature stays unmatched — an arbitrary pick would
///    invent structural findings.
fn match_nodes<'a>(
    a: &ParsedGraph<'a>,
    b: &ParsedGraph<'a>,
    name_suffix: &str,
) -> BTreeMap<&'a str, &'a str> {
    let a_ids: BTreeSet<&str> = a.nodes.iter().map(|n| n.id).collect();
    let mut matched: BTreeMap<&str, &str> = BTreeMap::new();
    let mut used_a: BTreeSet<&str> = BTreeSet::new();

    // Pass 1 — exact ids.
    for n in &b.nodes {
        if a_ids.contains(n.id) {
            matched.insert(n.id, n.id);
            used_a.insert(n.id);
        }
    }

    // Pass 2 — strip the twin suffix off B's node ids.
    let suffixes = node_suffix_candidates(name_suffix);
    for n in &b.nodes {
        if matched.contains_key(n.id) {
            continue;
        }
        for s in &suffixes {
            let Some(stripped) = n.id.strip_suffix(s.as_str()) else {
                continue;
            };
            if stripped.is_empty() || used_a.contains(stripped) {
                continue;
            }
            if let Some(a_id) = a_ids.get(stripped) {
                matched.insert(n.id, a_id);
                used_a.insert(a_id);
                break;
            }
        }
    }

    // Pass 3 — unique (type, kind, in-degree, out-degree) signature.
    let a_deg = degrees(a);
    let b_deg = degrees(b);
    let signature = |n: &ParsedNode<'_>, deg: &BTreeMap<&str, (usize, usize)>| {
        let (in_d, out_d) = deg.get(n.id).copied().unwrap_or((0, 0));
        (
            n.type_label.unwrap_or("").to_string(),
            n.kind.unwrap_or("").to_string(),
            in_d,
            out_d,
        )
    };
    let mut a_by_sig: BTreeMap<(String, String, usize, usize), Vec<&str>> = BTreeMap::new();
    for n in &a.nodes {
        if used_a.contains(n.id) {
            continue;
        }
        a_by_sig.entry(signature(n, &a_deg)).or_default().push(n.id);
    }
    let mut b_by_sig: BTreeMap<(String, String, usize, usize), Vec<&str>> = BTreeMap::new();
    for n in &b.nodes {
        if matched.contains_key(n.id) {
            continue;
        }
        b_by_sig.entry(signature(n, &b_deg)).or_default().push(n.id);
    }
    for (sig, b_ids) in b_by_sig {
        if b_ids.len() != 1 {
            continue;
        }
        let Some(a_ids_for_sig) = a_by_sig.get(&sig) else {
            continue;
        };
        if a_ids_for_sig.len() != 1 {
            continue;
        }
        matched.insert(b_ids[0], a_ids_for_sig[0]);
        used_a.insert(a_ids_for_sig[0]);
    }

    matched
}

fn compare_pair(
    a_ref: (String, String),
    b_ref: (String, String),
    suffix: &str,
    a: &ParsedGraph<'_>,
    b: &ParsedGraph<'_>,
) -> TwinPair {
    let matched = match_nodes(a, b, suffix);
    let matched_a: BTreeSet<&str> = matched.values().copied().collect();

    let mut structural: Vec<StructuralFinding> = Vec::new();
    let mut unmatched_a: Vec<String> = Vec::new();
    let mut unmatched_b: Vec<String> = Vec::new();

    for n in &a.nodes {
        if !matched_a.contains(n.id) {
            unmatched_a.push(n.id.to_string());
            structural.push(StructuralFinding::MissingNode {
                node: n.id.to_string(),
                present_in: Side::A,
            });
        }
    }
    for n in &b.nodes {
        if !matched.contains_key(n.id) {
            unmatched_b.push(n.id.to_string());
            structural.push(StructuralFinding::MissingNode {
                node: n.id.to_string(),
                present_in: Side::B,
            });
        }
    }

    // Edges, canonicalised into A's id space. Edges touching an unmatched
    // node are skipped — the missing NODE is already reported and a
    // derived "missing edge" would just double-count the same defect.
    let a_edges: BTreeSet<(&str, &str)> = a
        .edges
        .iter()
        .filter(|(s, t)| matched_a.contains(s) && matched_a.contains(t))
        .copied()
        .collect();
    let b_edges: BTreeSet<(&str, &str)> = b
        .edges
        .iter()
        .filter_map(|(s, t)| Some((*matched.get(s)?, *matched.get(t)?)))
        .collect();
    for e in a_edges.difference(&b_edges) {
        structural.push(StructuralFinding::MissingEdge {
            source: e.0.to_string(),
            target: e.1.to_string(),
            present_in: Side::A,
        });
    }
    for e in b_edges.difference(&a_edges) {
        structural.push(StructuralFinding::MissingEdge {
            source: e.0.to_string(),
            target: e.1.to_string(),
            present_in: Side::B,
        });
    }

    // Config diff over matched nodes.
    let a_by_id: BTreeMap<&str, &ParsedNode<'_>> = a.nodes.iter().map(|n| (n.id, n)).collect();
    let mut control_logic: Vec<ControlLogicFinding> = Vec::new();
    let mut instance: Vec<InstanceFinding> = Vec::new();
    let mut type_mismatches: Vec<TypeMismatch> = Vec::new();

    for b_node in &b.nodes {
        let Some(a_id) = matched.get(b_node.id) else {
            continue;
        };
        let Some(a_node) = a_by_id.get(a_id) else {
            continue;
        };
        if a_node.type_label != b_node.type_label {
            type_mismatches.push(TypeMismatch {
                node: a_id.to_string(),
                field: "type".to_string(),
            });
        }
        if a_node.kind != b_node.kind {
            type_mismatches.push(TypeMismatch {
                node: a_id.to_string(),
                field: "kind".to_string(),
            });
        }
        let all_keys: BTreeSet<&String> = a_node.keys.keys().chain(b_node.keys.keys()).collect();
        for key in all_keys {
            let av = a_node.keys.get(key);
            let bv = b_node.keys.get(key);
            if av.copied() == bv.copied() {
                continue;
            }
            let a_len = av.map(|v| encoded_len(v));
            let b_len = bv.map(|v| encoded_len(v));
            if CONTROL_LOGIC_KEYS.contains(&leaf_key(key)) {
                control_logic.push(ControlLogicFinding {
                    node: a_id.to_string(),
                    key: key.clone(),
                    a_len,
                    b_len,
                });
            } else {
                instance.push(InstanceFinding {
                    node: a_id.to_string(),
                    key: key.clone(),
                    a_len,
                    b_len,
                });
            }
        }
    }

    // Deterministic output ordering — the report is diffed by operators
    // across runs, so insertion order (hash/graph order) is not enough.
    structural.sort_by_key(|f| match f {
        StructuralFinding::MissingNode { node, present_in } => {
            (0, node.clone(), String::new(), present_in.label())
        }
        StructuralFinding::MissingEdge {
            source,
            target,
            present_in,
        } => (1, source.clone(), target.clone(), present_in.label()),
    });
    control_logic.sort_by(|x, y| (&x.node, &x.key).cmp(&(&y.node, &y.key)));
    instance.sort_by(|x, y| (&x.node, &x.key).cmp(&(&y.node, &y.key)));
    type_mismatches.sort_by(|x, y| (&x.node, &x.field).cmp(&(&y.node, &y.field)));
    unmatched_a.sort();
    unmatched_b.sort();

    TwinPair {
        a: a_ref,
        b: b_ref,
        suffix: suffix.to_string(),
        structural,
        control_logic,
        instance,
        type_mismatches,
        matched_nodes: matched.len(),
        unmatched_a,
        unmatched_b,
    }
}

/// Pair every candidate with its nearest ancestor and diff each pair.
///
/// Fail-soft throughout: an unparsable graph is counted and dropped
/// (taking its would-be pair with it), never panicking and never failing
/// the surrounding hygiene report.
pub fn analyze_twins(candidates: &[TwinCandidate]) -> TwinAnalysis {
    let docs: Vec<Option<serde_json::Value>> = candidates
        .iter()
        .map(|c| serde_json::from_str::<serde_json::Value>(&c.graph_json).ok())
        .collect();
    let graphs: Vec<Option<ParsedGraph<'_>>> = docs
        .iter()
        .map(|d| d.as_ref().and_then(parse_graph_value))
        .collect();
    let unparsable_graphs = graphs.iter().filter(|g| g.is_none()).count();

    let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
    let mut pairs = Vec::new();
    for (i, cand) in candidates.iter().enumerate() {
        let Some(base_idx) = nearest_ancestor(&cand.name, &names) else {
            continue;
        };
        // A duplicate name resolves to whichever row the caller ordered
        // first; a name is never its own ancestor.
        if base_idx == i {
            continue;
        }
        let (Some(a_graph), Some(b_graph)) = (&graphs[base_idx], &graphs[i]) else {
            continue;
        };
        let suffix = cand.name[candidates[base_idx].name.len()..].to_string();
        pairs.push(compare_pair(
            (
                candidates[base_idx].id.clone(),
                candidates[base_idx].name.clone(),
            ),
            (cand.id.clone(), cand.name.clone()),
            &suffix,
            a_graph,
            b_graph,
        ));
    }

    TwinAnalysis {
        pairs,
        unparsable_graphs,
    }
}

// ---------------------------------------------------------------------
// Report rendering
// ---------------------------------------------------------------------

/// Per-pair render cap on the DETAIL-grade list. Instance divergence is
/// the expected, unbounded-in-principle part of the payload (every prompt
/// and account key on every matched node), and the hygiene report is one
/// MCP response. The signal lists (structural / control-logic) are never
/// capped, and the full count is always reported alongside, so the cap can
/// hide entries but never hide the fact that entries were hidden.
const MAX_RENDERED_INSTANCE_KEYS: usize = 25;

fn structural_json(f: &StructuralFinding) -> serde_json::Value {
    match f {
        StructuralFinding::MissingNode { node, present_in } => serde_json::json!({
            "finding": "missing_node",
            "node": node,
            "present_in": present_in.label(),
            "missing_from": present_in.other().label(),
        }),
        StructuralFinding::MissingEdge {
            source,
            target,
            present_in,
        } => serde_json::json!({
            "finding": "missing_edge",
            "source": source,
            "target": target,
            "present_in": present_in.label(),
            "missing_from": present_in.other().label(),
        }),
    }
}

fn pair_json(p: &TwinPair) -> serde_json::Value {
    serde_json::json!({
        "a": { "id": p.a.0, "name": p.a.1 },
        "b": { "id": p.b.0, "name": p.b.1 },
        "name_suffix": p.suffix,
        "matched_nodes": p.matched_nodes,
        "unmatched": { "a": p.unmatched_a, "b": p.unmatched_b },
        "structural": p.structural.iter().map(structural_json).collect::<Vec<_>>(),
        "control_logic": p.control_logic.iter().map(|f| serde_json::json!({
            "node": f.node, "key": f.key, "a_len": f.a_len, "b_len": f.b_len,
        })).collect::<Vec<_>>(),
        "instance_keys": p.instance.iter().take(MAX_RENDERED_INSTANCE_KEYS).map(|f| serde_json::json!({
            "node": f.node, "key": f.key, "a_len": f.a_len, "b_len": f.b_len,
        })).collect::<Vec<_>>(),
        "instance_keys_total": p.instance.len(),
        "instance_keys_omitted": p.instance.len().saturating_sub(MAX_RENDERED_INSTANCE_KEYS),
        "type_mismatches": p.type_mismatches.iter().map(|f| serde_json::json!({
            "node": f.node, "field": f.field,
        })).collect::<Vec<_>>(),
        "recommendation_grade": p.is_recommendation_grade(),
    })
}

/// Render the `workflow_twins` report section.
///
/// `truncated` / `skipped_oversized` come from the repository scan and are
/// surfaced verbatim: with either set, an empty finding list means "no
/// divergence among the graphs examined", NOT "no twin diverged". The note
/// says so in the section itself so the qualifier travels with the data.
pub fn twins_section(
    analysis: &TwinAnalysis,
    truncated: bool,
    skipped_oversized: i64,
) -> serde_json::Value {
    let diverged: Vec<&TwinPair> = analysis.diverged_pairs().collect();
    let structural_count: usize = analysis.pairs.iter().map(|p| p.structural.len()).sum();
    let control_logic_count: usize = analysis.pairs.iter().map(|p| p.control_logic.len()).sum();
    let instance_count: usize = analysis.pairs.iter().map(|p| p.instance.len()).sum();

    let mut note = String::from(
        "Twins are detected by NAME only: one workflow's name must be the other's plus a \
         '-' or '_'-led suffix (e.g. x / x-work), and each variant is paired with its nearest \
         such ancestor. Twins named disjointly are invisible to this check. Instance keys \
         (auth, prompts, account ids) are EXPECTED to differ between twins and never raise a \
         recommendation; neither does a module/kind mismatch, which real twins have by design. \
         Config VALUES are never reported — only key names and encoded byte lengths, which show \
         that two values differ but say nothing about semantic equivalence.",
    );
    if truncated || skipped_oversized > 0 || analysis.unparsable_graphs > 0 {
        note.push_str(&format!(
            " Coverage was incomplete this run (truncated={truncated}, \
             skipped_oversized={skipped_oversized}, unparsable_graphs={}), so an empty finding \
             list does NOT prove that no twin diverged.",
            analysis.unparsable_graphs
        ));
    }

    serde_json::json!({
        "pairs": analysis.pairs.iter().map(pair_json).collect::<Vec<_>>(),
        "pairs_count": analysis.pairs.len(),
        "diverged_pairs_count": diverged.len(),
        "structural_findings_count": structural_count,
        "control_logic_findings_count": control_logic_count,
        "instance_key_count": instance_count,
        "unparsable_graphs": analysis.unparsable_graphs,
        "skipped_oversized": skipped_oversized,
        "truncated": truncated,
        "note": note,
    })
}

/// The ONE recommendation this feature can emit — and only when a pair
/// carries structural or control-logic divergence. Detail-grade findings
/// alone return `None`: twins that differ solely in prompts and auth are
/// the normal, healthy state and an operator trained to dismiss this
/// entry would dismiss the real one too.
pub fn twin_recommendation(analysis: &TwinAnalysis) -> Option<serde_json::Value> {
    let diverged: Vec<&TwinPair> = analysis.diverged_pairs().collect();
    if diverged.is_empty() {
        return None;
    }
    let detail: Vec<String> = diverged
        .iter()
        .map(|p| {
            format!(
                "{} ↔ {} ({} structural, {} control-logic)",
                p.a.1,
                p.b.1,
                p.structural.len(),
                p.control_logic.len()
            )
        })
        .collect();
    Some(serde_json::json!({
        "priority": "high",
        "category": "consistency",
        "action": format!(
            "{} twin workflow pair(s) have diverged in structure or control logic — a fix applied \
             to one may be missing from the other: {}. Review each difference in the \
             `workflow_twins` report section and decide whether it is intentional; if not, apply \
             the missing change to the lagging twin. (Pairs are matched by name suffix; module \
             and prompt/auth differences are expected and are NOT counted here.)",
            diverged.len(),
            detail.join("; ")
        ),
        "affected_count": diverged.len(),
        "diverged_pairs": diverged.iter().map(|p| serde_json::json!({
            "a": p.a.1, "b": p.b.1,
        })).collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // Fixtures — TRIMMED models of the real pa-inbox-organizer twins:
    // suffixed node ids, one legitimately divergent classifier module,
    // per-instance auth/prompt config, and a coverage_judge leaf.
    // -----------------------------------------------------------------

    fn base_graph() -> serde_json::Value {
        serde_json::json!({
            "nodes": [
                {"id": "fetch", "type": "mod-gmail", "data": {
                    "AUTH_HEADER": "vault://oauth/personal", "MAX_RESULTS": 25}},
                {"id": "classify", "type": "mod-hybrid-classify", "data": {
                    "SYSTEM_PROMPT": "sort personal mail", "max_fuel": 8000000}},
                {"id": "route", "kind": "dispatch", "data": {"skip_condition": "count == 0"}},
                {"id": "label", "type": "mod-modify-labels", "data": {"LABEL_PREFIX": "PA/"}},
                {"id": "coverage_judge", "kind": "inline_judge", "data": {
                    "verdict_expr": "covered >= total", "pass_threshold": 0.9}},
                {"id": "report", "kind": "assistant_report", "data": {}}
            ],
            "edges": [
                {"source": "fetch", "target": "classify"},
                {"source": "classify", "target": "route"},
                {"source": "route", "target": "label"},
                {"source": "label", "target": "coverage_judge"},
                {"source": "coverage_judge", "target": "report"}
            ]
        })
    }

    fn variant_graph() -> serde_json::Value {
        serde_json::json!({
            "nodes": [
                {"id": "fetch_work", "type": "mod-gmail", "data": {
                    "AUTH_HEADER": "vault://oauth/work-account", "MAX_RESULTS": 25}},
                // Legitimately different module (info-grade), different prompt.
                {"id": "classify_work", "type": "mod-llm-inference", "data": {
                    "SYSTEM_PROMPT": "sort work mail", "max_fuel": 8000000}},
                {"id": "route_work", "kind": "dispatch", "data": {"skip_condition": "count == 0"}},
                {"id": "label_work", "type": "mod-modify-labels", "data": {"LABEL_PREFIX": "PA/"}},
                {"id": "coverage_judge_work", "kind": "inline_judge", "data": {
                    "verdict_expr": "covered >= total", "pass_threshold": 0.9}},
                {"id": "report_work", "kind": "assistant_report", "data": {}}
            ],
            "edges": [
                {"source": "fetch_work", "target": "classify_work"},
                {"source": "classify_work", "target": "route_work"},
                {"source": "route_work", "target": "label_work"},
                {"source": "label_work", "target": "coverage_judge_work"},
                {"source": "coverage_judge_work", "target": "report_work"}
            ]
        })
    }

    fn candidates(pairs: Vec<(&str, serde_json::Value)>) -> Vec<TwinCandidate> {
        pairs
            .into_iter()
            .enumerate()
            .map(|(i, (name, g))| TwinCandidate {
                id: format!("00000000-0000-0000-0000-00000000000{i}"),
                name: name.to_string(),
                graph_json: g.to_string(),
            })
            .collect()
    }

    fn organizers(base: serde_json::Value, variant: serde_json::Value) -> Vec<TwinCandidate> {
        candidates(vec![
            ("pa-inbox-organizer", base),
            ("pa-inbox-organizer-work", variant),
        ])
    }

    /// Drop a node (and its incident edges) from a fixture graph.
    fn without_node(mut g: serde_json::Value, node_id: &str) -> serde_json::Value {
        let nodes = g["nodes"].as_array().unwrap().clone();
        g["nodes"] = serde_json::Value::Array(
            nodes
                .into_iter()
                .filter(|n| n["id"].as_str() != Some(node_id))
                .collect(),
        );
        let edges = g["edges"].as_array().unwrap().clone();
        g["edges"] = serde_json::Value::Array(
            edges
                .into_iter()
                .filter(|e| {
                    e["source"].as_str() != Some(node_id) && e["target"].as_str() != Some(node_id)
                })
                .collect(),
        );
        g
    }

    // -----------------------------------------------------------------
    // THE INCIDENT — the two real defects that motivated this module.
    // -----------------------------------------------------------------

    /// Incident A: a fix (the coverage_judge leaf) applied to one twin and
    /// not the other must produce a structural finding NAMING the node.
    #[test]
    fn incident_missing_coverage_judge_is_structural() {
        let broken = without_node(variant_graph(), "coverage_judge_work");
        let analysis = analyze_twins(&organizers(base_graph(), broken));
        assert_eq!(analysis.pairs.len(), 1);
        let p = &analysis.pairs[0];
        assert!(p.is_recommendation_grade());
        assert!(
            p.structural.contains(&StructuralFinding::MissingNode {
                node: "coverage_judge".to_string(),
                present_in: Side::A,
            }),
            "expected coverage_judge to be reported missing from the twin: {:?}",
            p.structural
        );
        assert_eq!(p.unmatched_a, vec!["coverage_judge".to_string()]);
        // Edges INCIDENT to the missing node are deliberately suppressed —
        // they restate the same defect and would inflate the count.
        assert!(
            !p.structural.iter().any(|f| matches!(
                f,
                StructuralFinding::MissingEdge { target, .. } if target == "coverage_judge"
            )),
            "edges incident to the missing node must not double-count it"
        );
        assert!(twin_recommendation(&analysis).is_some());
    }

    /// Incident B: judge verdict_expr drift must be recommendation-grade
    /// control logic (not filed away as an expected instance difference).
    #[test]
    fn incident_verdict_expr_drift_is_control_logic() {
        let mut variant = variant_graph();
        variant["nodes"][4]["data"]["verdict_expr"] =
            serde_json::json!("covered >= total - 1 || override");
        let analysis = analyze_twins(&organizers(base_graph(), variant));
        let p = &analysis.pairs[0];
        assert!(p.structural.is_empty(), "structure is unchanged");
        let f = p
            .control_logic
            .iter()
            .find(|f| f.key == "data.verdict_expr")
            .expect("verdict_expr divergence must be control-logic grade");
        assert_eq!(f.node, "coverage_judge");
        assert!(f.a_len.is_some() && f.b_len.is_some() && f.a_len != f.b_len);
        assert!(p.is_recommendation_grade());
        assert!(twin_recommendation(&analysis).is_some());
    }

    // -----------------------------------------------------------------
    // Grading
    // -----------------------------------------------------------------

    #[test]
    fn in_sync_twins_are_listed_with_no_recommendation() {
        let analysis = analyze_twins(&organizers(base_graph(), variant_graph()));
        assert_eq!(analysis.pairs.len(), 1);
        let p = &analysis.pairs[0];
        assert_eq!(p.matched_nodes, 6);
        assert!(p.structural.is_empty());
        assert!(p.control_logic.is_empty());
        // Legit divergence: the classifier module + auth/prompt configs.
        assert!(!p.type_mismatches.is_empty());
        assert!(!p.instance.is_empty());
        assert!(!p.is_recommendation_grade());
        assert!(twin_recommendation(&analysis).is_none());
        // The pair is still LISTED — a clean pair is evidence the check ran.
        let section = twins_section(&analysis, false, 0);
        assert_eq!(section["pairs_count"], 1);
        assert_eq!(section["diverged_pairs_count"], 0);
    }

    #[test]
    fn identical_twins_have_zero_findings_but_are_still_paired() {
        // Same graph on both sides, node ids included.
        let analysis = analyze_twins(&organizers(base_graph(), base_graph()));
        let p = &analysis.pairs[0];
        assert_eq!(p.matched_nodes, 6);
        assert!(p.structural.is_empty());
        assert!(p.control_logic.is_empty());
        assert!(p.instance.is_empty());
        assert!(p.type_mismatches.is_empty());
        assert_eq!(twins_section(&analysis, false, 0)["pairs_count"], 1);
    }

    #[test]
    fn module_swap_alone_is_info_grade_only() {
        let mut variant = variant_graph();
        // Make prompts/auth identical so ONLY the module differs.
        variant["nodes"][0]["data"]["AUTH_HEADER"] = serde_json::json!("vault://oauth/personal");
        variant["nodes"][1]["data"]["SYSTEM_PROMPT"] = serde_json::json!("sort personal mail");
        let analysis = analyze_twins(&organizers(base_graph(), variant));
        let p = &analysis.pairs[0];
        assert_eq!(
            p.type_mismatches,
            vec![TypeMismatch {
                node: "classify".to_string(),
                field: "type".to_string()
            }]
        );
        assert!(!p.is_recommendation_grade());
        assert!(twin_recommendation(&analysis).is_none());
    }

    #[test]
    fn instance_keys_never_reach_recommendation_grade() {
        let mut variant = variant_graph();
        variant["nodes"][3]["data"]["LABEL_PREFIX"] = serde_json::json!("WORK/");
        let analysis = analyze_twins(&organizers(base_graph(), variant));
        let p = &analysis.pairs[0];
        assert!(p
            .instance
            .iter()
            .any(|f| f.node == "label" && f.key == "data.LABEL_PREFIX"));
        assert!(!p.is_recommendation_grade());
    }

    #[test]
    fn node_level_control_key_is_graded_by_leaf_name() {
        let mut variant = variant_graph();
        variant["nodes"][0]["retry_count"] = serde_json::json!(3);
        let analysis = analyze_twins(&organizers(base_graph(), variant));
        let p = &analysis.pairs[0];
        let f = p
            .control_logic
            .iter()
            .find(|f| f.key == "retry_count")
            .expect("node-level retry_count is control logic");
        assert_eq!(f.a_len, None, "absent on A");
        assert!(f.b_len.is_some());
    }

    /// The fuller shape of the incident: the lagging twin not only lacks
    /// the judge, it routes AROUND the gap. That rewiring edge has two
    /// matched endpoints, so it is reported on top of the missing node.
    #[test]
    fn rewiring_around_a_missing_node_is_reported() {
        let mut broken = without_node(variant_graph(), "coverage_judge_work");
        broken["edges"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"source": "label_work", "target": "report_work"}));
        let analysis = analyze_twins(&organizers(base_graph(), broken));
        let p = &analysis.pairs[0];
        assert!(
            p.structural.contains(&StructuralFinding::MissingEdge {
                source: "label".to_string(),
                target: "report".to_string(),
                present_in: Side::B,
            }),
            "expected the twin's route-around edge: {:?}",
            p.structural
        );
    }

    #[test]
    fn missing_edge_between_matched_nodes_is_structural() {
        let mut variant = variant_graph();
        let edges = variant["edges"].as_array().unwrap().clone();
        variant["edges"] = serde_json::Value::Array(
            edges
                .into_iter()
                .filter(|e| e["source"].as_str() != Some("route_work"))
                .collect(),
        );
        let analysis = analyze_twins(&organizers(base_graph(), variant));
        let p = &analysis.pairs[0];
        assert!(p.structural.contains(&StructuralFinding::MissingEdge {
            source: "route".to_string(),
            target: "label".to_string(),
            present_in: Side::A,
        }));
    }

    // -----------------------------------------------------------------
    // Pairing rules
    // -----------------------------------------------------------------

    #[test]
    fn unrelated_names_are_not_paired() {
        let c = candidates(vec![
            ("pa-daily-brief", base_graph()),
            ("pa-meeting-prep", base_graph()),
        ]);
        assert!(analyze_twins(&c).pairs.is_empty());
    }

    #[test]
    fn suffix_must_be_separator_led_and_non_degenerate() {
        // 'x' vs 'xy' — no separator, not twins.
        assert!(
            analyze_twins(&candidates(vec![("x", base_graph()), ("xy", base_graph())]))
                .pairs
                .is_empty()
        );
        // 'x' vs 'x-' — separator only, degenerate, not twins.
        assert!(
            analyze_twins(&candidates(vec![("x", base_graph()), ("x-", base_graph())]))
                .pairs
                .is_empty()
        );
        // 'x' vs 'x-work' — the real convention, paired.
        assert_eq!(
            analyze_twins(&candidates(vec![
                ("x", base_graph()),
                ("x-work", base_graph())
            ]))
            .pairs
            .len(),
            1
        );
        // Underscore separator pairs too.
        assert_eq!(
            analyze_twins(&candidates(vec![
                ("x", base_graph()),
                ("x_work", base_graph())
            ]))
            .pairs
            .len(),
            1
        );
    }

    /// THE THREE-WAY RULE, pinned: siblings pair with the base, never with
    /// each other.
    #[test]
    fn three_way_variants_pair_with_the_base_only() {
        let c = candidates(vec![
            ("x", base_graph()),
            ("x-team", base_graph()),
            ("x-work", base_graph()),
        ]);
        let analysis = analyze_twins(&c);
        let mut seen: Vec<(String, String)> = analysis
            .pairs
            .iter()
            .map(|p| (p.a.1.clone(), p.b.1.clone()))
            .collect();
        seen.sort();
        assert_eq!(
            seen,
            vec![
                ("x".to_string(), "x-team".to_string()),
                ("x".to_string(), "x-work".to_string()),
            ]
        );
    }

    /// …and a nested variant pairs with its NEAREST ancestor, not the root.
    #[test]
    fn nested_variant_pairs_with_nearest_ancestor() {
        let c = candidates(vec![
            ("x", base_graph()),
            ("x-work", base_graph()),
            ("x-work-team", base_graph()),
        ]);
        let analysis = analyze_twins(&c);
        let mut seen: Vec<(String, String)> = analysis
            .pairs
            .iter()
            .map(|p| (p.a.1.clone(), p.b.1.clone()))
            .collect();
        seen.sort();
        assert_eq!(
            seen,
            vec![
                ("x".to_string(), "x-work".to_string()),
                ("x-work".to_string(), "x-work-team".to_string()),
            ]
        );
    }

    /// Bound: with one base and N variants the scan is O(N) pairs, not N².
    #[test]
    fn many_same_prefix_workflows_yield_at_most_n_minus_one_pairs() {
        let mut rows: Vec<(String, serde_json::Value)> = vec![("wf".to_string(), base_graph())];
        for i in 0..40 {
            rows.push((format!("wf-{i:02}"), base_graph()));
        }
        let c = candidates(rows.iter().map(|(n, g)| (n.as_str(), g.clone())).collect());
        let analysis = analyze_twins(&c);
        assert_eq!(analysis.pairs.len(), rows.len() - 1);
    }

    // -----------------------------------------------------------------
    // Node matching
    // -----------------------------------------------------------------

    #[test]
    fn unsuffixed_node_ids_match_exactly() {
        // A twin whose author did NOT rename node ids still matches.
        let analysis = analyze_twins(&organizers(base_graph(), base_graph()));
        assert_eq!(analysis.pairs[0].matched_nodes, 6);
    }

    #[test]
    fn exact_match_wins_over_suffix_stripping() {
        // B holds BOTH `classify` and `classify_work`. The exact-id pass
        // must claim `classify`, leaving `classify_work` to be reported as
        // an extra node — not silently stealing the match.
        let mut variant = base_graph();
        variant["nodes"].as_array_mut().unwrap().push(
            serde_json::json!({"id": "classify_work", "type": "mod-llm-inference", "data": {}}),
        );
        let analysis = analyze_twins(&organizers(base_graph(), variant));
        let p = &analysis.pairs[0];
        assert_eq!(p.unmatched_b, vec!["classify_work".to_string()]);
        assert!(p.type_mismatches.is_empty(), "classify matched classify");
    }

    #[test]
    fn renamed_node_falls_back_to_signature_match() {
        let mut variant = variant_graph();
        // Rename one node beyond any suffix relationship; its (type, kind,
        // degree) signature is unique, so it still matches.
        variant["nodes"][3]["id"] = serde_json::json!("apply_labels_v2");
        for e in variant["edges"].as_array_mut().unwrap() {
            if e["source"] == "label_work" {
                e["source"] = serde_json::json!("apply_labels_v2");
            }
            if e["target"] == "label_work" {
                e["target"] = serde_json::json!("apply_labels_v2");
            }
        }
        let analysis = analyze_twins(&organizers(base_graph(), variant));
        let p = &analysis.pairs[0];
        assert_eq!(p.matched_nodes, 6, "signature fallback matched the rename");
        assert!(p.structural.is_empty());
    }

    #[test]
    fn ambiguous_signature_stays_unmatched_rather_than_guessing() {
        // Two identically-shaped extra nodes on each side, unmatchable by
        // id. Guessing would invent findings; they stay unmatched.
        let mut a = base_graph();
        let mut b = variant_graph();
        for (g, sfx) in [(&mut a, ""), (&mut b, "_work")] {
            let arr = g["nodes"].as_array_mut().unwrap();
            arr.push(
                serde_json::json!({"id": format!("extra1{sfx}x"), "type": "mod-echo", "data": {}}),
            );
            arr.push(
                serde_json::json!({"id": format!("extra2{sfx}x"), "type": "mod-echo", "data": {}}),
            );
        }
        let analysis = analyze_twins(&organizers(a, b));
        let p = &analysis.pairs[0];
        assert_eq!(p.matched_nodes, 6);
        assert_eq!(p.unmatched_a.len(), 2);
        assert_eq!(p.unmatched_b.len(), 2);
    }

    // -----------------------------------------------------------------
    // Fail-soft / hostile input
    // -----------------------------------------------------------------

    #[test]
    fn malformed_graph_json_is_counted_and_never_panics() {
        for bad in [
            "",
            "not json",
            "{}",
            "[]",
            "null",
            r#"{"nodes": "oops"}"#,
            r#"{"nodes": [{"no_id": 1}]}"#,
            r#"{"nodes": [{"id": ""}]}"#,
            r#"{"nodes": [1,2,3]}"#,
            r#"{"nodes": [], "edges": "oops"}"#,
        ] {
            let c = vec![
                TwinCandidate {
                    id: "1".into(),
                    name: "wf".into(),
                    graph_json: base_graph().to_string(),
                },
                TwinCandidate {
                    id: "2".into(),
                    name: "wf-work".into(),
                    graph_json: bad.to_string(),
                },
            ];
            let analysis = analyze_twins(&c);
            if bad.contains("\"edges\": \"oops\"") {
                // Parsable graph with a bogus edges field: nodes still diff.
                assert_eq!(analysis.unparsable_graphs, 0, "input: {bad}");
                assert_eq!(analysis.pairs.len(), 1, "input: {bad}");
            } else {
                assert_eq!(analysis.unparsable_graphs, 1, "input: {bad}");
                assert!(analysis.pairs.is_empty(), "input: {bad}");
            }
            // The section renders and admits the gap.
            let s = twins_section(&analysis, false, 0);
            assert!(s["note"].as_str().unwrap().len() > 100);
        }
    }

    #[test]
    fn unicode_names_do_not_panic_or_mispair() {
        let c = candidates(vec![
            ("流程", base_graph()),
            ("流程-仕事", base_graph()),
            ("流程x", base_graph()),
        ]);
        let analysis = analyze_twins(&c);
        assert_eq!(analysis.pairs.len(), 1);
        assert_eq!(analysis.pairs[0].b.1, "流程-仕事");
    }

    #[test]
    fn empty_input_is_empty_analysis() {
        let analysis = analyze_twins(&[]);
        assert!(analysis.pairs.is_empty());
        assert_eq!(analysis.unparsable_graphs, 0);
        assert!(twin_recommendation(&analysis).is_none());
    }

    // -----------------------------------------------------------------
    // Report contract
    // -----------------------------------------------------------------

    /// SECURITY: the section must never carry a config VALUE. Every
    /// fixture value below is unique enough that a leak would show up as a
    /// substring of the rendered JSON.
    #[test]
    fn section_never_contains_config_values() {
        let mut variant = variant_graph();
        variant["nodes"][0]["data"]["AUTH_HEADER"] = serde_json::json!("vault://oauth/SECRETPATH");
        variant["nodes"][1]["data"]["SYSTEM_PROMPT"] = serde_json::json!("LEAKCANARYPROMPT");
        variant["nodes"][4]["data"]["verdict_expr"] = serde_json::json!("LEAKCANARYEXPR");
        let analysis = analyze_twins(&organizers(base_graph(), variant));
        let rendered = serde_json::to_string(&serde_json::json!({
            "section": twins_section(&analysis, true, 2),
            "recommendation": twin_recommendation(&analysis),
        }))
        .unwrap();
        for leak in [
            "LEAKCANARYPROMPT",
            "LEAKCANARYEXPR",
            "SECRETPATH",
            "vault://",
            "sort personal mail",
            "covered >= total",
            "PA/",
        ] {
            assert!(
                !rendered.contains(leak),
                "config value {leak:?} leaked into the report"
            );
        }
        // Key NAMES are present — that's the whole point.
        assert!(rendered.contains("data.verdict_expr"));
        assert!(rendered.contains("data.AUTH_HEADER"));
    }

    /// The detail-grade render cap must be self-declaring: hidden entries
    /// are still counted, so the section can never read as "only 25 keys
    /// differ" when 60 do.
    #[test]
    fn instance_key_render_cap_reports_what_it_hid() {
        let mut variant = variant_graph();
        for i in 0..60 {
            variant["nodes"][0]["data"][format!("K{i:02}")] = serde_json::json!(i);
        }
        let analysis = analyze_twins(&organizers(base_graph(), variant));
        let p = &analysis.pairs[0];
        assert!(p.instance.len() >= 60);
        let rendered = pair_json(p);
        assert_eq!(
            rendered["instance_keys"].as_array().unwrap().len(),
            MAX_RENDERED_INSTANCE_KEYS
        );
        assert_eq!(rendered["instance_keys_total"], p.instance.len());
        assert_eq!(
            rendered["instance_keys_omitted"],
            p.instance.len() - MAX_RENDERED_INSTANCE_KEYS
        );
        // The section-level count is the FULL count, not the rendered one.
        let s = twins_section(&analysis, false, 0);
        assert_eq!(s["instance_key_count"], p.instance.len());
        // Still not a recommendation: instance keys are expected to differ.
        assert!(twin_recommendation(&analysis).is_none());
    }

    #[test]
    fn section_counts_and_flags_are_faithful() {
        let broken = without_node(variant_graph(), "coverage_judge_work");
        let analysis = analyze_twins(&organizers(base_graph(), broken));
        let s = twins_section(&analysis, true, 3);
        assert_eq!(s["pairs_count"], 1);
        assert_eq!(s["diverged_pairs_count"], 1);
        assert_eq!(s["truncated"], true);
        assert_eq!(s["skipped_oversized"], 3);
        assert_eq!(
            s["structural_findings_count"],
            analysis.pairs[0].structural.len()
        );
        let note = s["note"].as_str().unwrap();
        assert!(note.contains("does NOT prove"), "truncation must be owned");
        assert!(
            note.contains("NAME only"),
            "heuristic limits must be stated"
        );
    }

    #[test]
    fn clean_run_note_omits_the_incomplete_coverage_clause() {
        let analysis = analyze_twins(&organizers(base_graph(), variant_graph()));
        let s = twins_section(&analysis, false, 0);
        let note = s["note"].as_str().unwrap();
        assert!(!note.contains("does NOT prove"));
        assert!(note.contains("NAME only"));
    }

    #[test]
    fn recommendation_names_the_pairs() {
        let broken = without_node(variant_graph(), "coverage_judge_work");
        let analysis = analyze_twins(&organizers(base_graph(), broken));
        let r = twin_recommendation(&analysis).unwrap();
        let action = r["action"].as_str().unwrap();
        assert!(action.contains("pa-inbox-organizer ↔ pa-inbox-organizer-work"));
        assert_eq!(r["priority"], "high");
        assert_eq!(r["affected_count"], 1);
    }

    #[test]
    fn findings_are_deterministically_ordered() {
        let broken = without_node(variant_graph(), "coverage_judge_work");
        let first = twins_section(
            &analyze_twins(&organizers(base_graph(), broken.clone())),
            false,
            0,
        );
        let second = twins_section(&analyze_twins(&organizers(base_graph(), broken)), false, 0);
        assert_eq!(first, second);
    }
}
