/// MCP-11: canonical list of node-config fields whose contents are
/// Rhai expressions and should therefore be HTML-entity-decoded
/// before being persisted to `workflows.graph_json` /
/// `workflow_versions.graph_json`. Centralised here so write-time
/// decoders (MCP node-config setters), the runtime decoder
/// (`talos-engine::rhai_helpers`), and the one-shot data migration
/// all agree on the field set.
///
/// Edge-level: `condition` (the conditional-edge expression) is also
/// Rhai. Walked separately by `decode_rhai_in_graph` since edges live
/// alongside nodes in `graph_json`.
pub const RHAI_EXPRESSION_FIELDS: &[&str] = &[
    "retry_condition",
    "retry_delay_expression",
    "skip_condition",
    "synthesis_expr",
    "expression",
    "synthesize_expression",
];

/// MCP-11: walk a parsed `graph_json` (as `serde_json::Value`) in-place
/// and apply `decode_html_entities` to every Rhai-expression field
/// listed in `RHAI_EXPRESSION_FIELDS`, plus every edge's `condition`
/// field. Returns the number of decoded sites — useful for migration
/// telemetry and zero-change-fast-path detection.
///
/// Decoded locations:
///   * `graph.nodes[*].{retry_condition,retry_delay_expression,skip_condition,synthesis_expr,expression,synthesize_expression}`
///   * `graph.nodes[*].data.{<same set>}`
///   * `graph.edges[*].condition`
///
/// The dual node-vs-data location is intentional: most fields live in
/// the top-level node object (next to `retry_count`), but
/// `synthesis_expr` and a few module-config Rhai fields live inside
/// `data`. We walk both rather than guess.
///
/// Operates on borrowed `&mut Value` so the caller can decide whether
/// to clone first or mutate in place. Idempotent: a second pass on
/// already-decoded input is a no-op (modulo unicode-form `&` literals,
/// which are preserved unchanged).
pub fn decode_rhai_in_graph(graph: &mut serde_json::Value) -> usize {
    let mut decoded_sites: usize = 0;
    if let Some(nodes) = graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
        for node in nodes.iter_mut() {
            decoded_sites += decode_rhai_in_object(node);
            if let Some(data) = node.get_mut("data") {
                decoded_sites += decode_rhai_in_object(data);
            }
        }
    }
    if let Some(edges) = graph.get_mut("edges").and_then(|e| e.as_array_mut()) {
        for edge in edges.iter_mut() {
            if let Some(cond) = edge.get_mut("condition") {
                if let Some(s) = cond.as_str() {
                    let decoded = decode_html_entities(s);
                    if decoded.as_ref() != s {
                        *cond = serde_json::Value::String(decoded.into_owned());
                        decoded_sites += 1;
                    }
                }
            }
        }
    }
    decoded_sites
}

/// Decode every Rhai-expression field in a single object. Used by
/// `decode_rhai_in_graph` for both top-level node objects and their
/// `data` sub-object.
fn decode_rhai_in_object(obj: &mut serde_json::Value) -> usize {
    let mut decoded_sites: usize = 0;
    let Some(map) = obj.as_object_mut() else {
        return 0;
    };
    for &field in RHAI_EXPRESSION_FIELDS {
        if let Some(v) = map.get_mut(field) {
            if let Some(s) = v.as_str() {
                let decoded = decode_html_entities(s);
                if decoded.as_ref() != s {
                    *v = serde_json::Value::String(decoded.into_owned());
                    decoded_sites += 1;
                }
            }
        }
    }
    decoded_sites
}

#[cfg(test)]
mod decode_rhai_in_graph_tests {
    use super::decode_rhai_in_graph;
    use serde_json::json;

    #[test]
    fn decodes_top_level_retry_condition() {
        let mut g = json!({
            "nodes": [{
                "id": "n1",
                "retry_condition": "status != 401 &amp;&amp; status != 403"
            }],
            "edges": []
        });
        let sites = decode_rhai_in_graph(&mut g);
        assert_eq!(sites, 1);
        assert_eq!(
            g["nodes"][0]["retry_condition"].as_str().unwrap(),
            "status != 401 && status != 403"
        );
    }

    #[test]
    fn decodes_synthesis_expr_inside_data() {
        let mut g = json!({
            "nodes": [{
                "id": "n1",
                "data": {"synthesis_expr": "items.len() &lt; 10"}
            }],
            "edges": []
        });
        let sites = decode_rhai_in_graph(&mut g);
        assert_eq!(sites, 1);
        assert_eq!(
            g["nodes"][0]["data"]["synthesis_expr"].as_str().unwrap(),
            "items.len() < 10"
        );
    }

    #[test]
    fn decodes_edge_condition() {
        let mut g = json!({
            "nodes": [],
            "edges": [{"source":"a","target":"b","condition":"score &gt;= 80"}]
        });
        let sites = decode_rhai_in_graph(&mut g);
        assert_eq!(sites, 1);
        assert_eq!(
            g["edges"][0]["condition"].as_str().unwrap(),
            "score >= 80"
        );
    }

    #[test]
    fn idempotent_on_canonical_input() {
        let mut g = json!({
            "nodes": [{
                "id": "n1",
                "retry_condition": "status != 401 && status != 403"
            }],
            "edges": []
        });
        let g_orig = g.clone();
        let sites = decode_rhai_in_graph(&mut g);
        assert_eq!(sites, 0, "no decoded sites when input is canonical");
        assert_eq!(g, g_orig);
    }

    #[test]
    fn ignores_non_rhai_string_fields() {
        // A user might have a literal `&amp;` in a string-literal context
        // like a name or description. Only fields in the canonical Rhai
        // list are touched.
        let mut g = json!({
            "nodes": [{
                "id": "n1",
                "data": {"description": "Robert &amp; Sons"}
            }],
            "edges": []
        });
        let sites = decode_rhai_in_graph(&mut g);
        assert_eq!(sites, 0);
        assert_eq!(
            g["nodes"][0]["data"]["description"].as_str().unwrap(),
            "Robert &amp; Sons"
        );
    }

    #[test]
    fn counts_multi_site_decode() {
        let mut g = json!({
            "nodes": [
                {"id": "n1", "retry_condition": "a &amp;&amp; b", "skip_condition": "c &lt; 5"},
                {"id": "n2", "data": {"synthesis_expr": "x &gt; 0"}},
            ],
            "edges": [{"source":"n1","target":"n2","condition":"y &amp;&amp; z"}]
        });
        let sites = decode_rhai_in_graph(&mut g);
        assert_eq!(sites, 4);
    }

    #[test]
    fn empty_graph_is_zero() {
        let mut g = json!({"nodes": [], "edges": []});
        assert_eq!(decode_rhai_in_graph(&mut g), 0);
    }

    #[test]
    fn missing_keys_are_safe() {
        let mut g = json!({});
        assert_eq!(decode_rhai_in_graph(&mut g), 0);
    }

    #[test]
    fn non_string_rhai_field_is_left_alone() {
        // If retry_condition is mistakenly stored as a number or bool,
        // we don't crash — we just skip it.
        let mut g = json!({
            "nodes": [{"id": "n1", "retry_condition": 42, "skip_condition": null}],
            "edges": []
        });
        let sites = decode_rhai_in_graph(&mut g);
        assert_eq!(sites, 0);
    }
}

/// Defensively decode the small set of HTML entities that LLM clients
/// commonly inject when they re-serialize JSON containing operators like
/// `&&` or `<` — `serde_json` escapes `<` to `<` in some contexts and
/// LLMs sometimes round-trip operators as `&amp;&amp;` or `&lt;`. Workflow
/// authors typing the canonical form occasionally end up with the encoded
/// form via copy/paste from rendered HTML or markdown.
///
/// Rhai itself does not understand these entities, so without a decode the
/// expression fails to parse and the safe-default fallback fires
/// (retry-everything / skip-nothing) — masking the bug as "engine ignored
/// my condition" (the daily-brief incident, fixed engine-side in `8b2c3f3`).
///
/// This helper is now the single source of truth used by:
///   * the runtime decode in `talos-engine::rhai_helpers`
///     (`evaluate_condition` / `evaluate_skip_condition` / etc.)
///   * the write-time decode in MCP node-config setters and
///     workflow-creation helpers (so freshly-stored `retry_condition` /
///     `skip_condition` / `retry_delay_expression` / `expression` /
///     `synthesis_expr` is canonical)
///   * the one-shot data migration that decodes existing rows in
///     `workflows.graph_json` and `workflow_versions.graph_json`.
///
/// Returns a `Cow::Borrowed` for the common case (no `&` in the input)
/// so callers don't pay for an allocation when the string is already
/// canonical. The borrow case fires on every Rhai evaluation in steady
/// state — keeping it allocation-free matters for hot-path evaluators.
pub fn decode_html_entities(s: &str) -> std::borrow::Cow<'_, str> {
    // Stage 1 fast path: no `&` at all → nothing to decode.
    if !s.contains('&') {
        return std::borrow::Cow::Borrowed(s);
    }
    // MCP-635 (2026-05-12): stage 2 fast path. Rhai conditions
    // routinely use `&&` (logical AND), which makes `contains('&')`
    // true even when there's no HTML entity to decode. Pre-fix the
    // function fell into the 6-`replace` chain — each `str::replace`
    // unconditionally allocates a new String, so a clean
    // `status != 401 && status != 403` paid 6 allocations to produce
    // the same string back. On a workflow with 100 conditions × 10k
    // executions/hour that's 6M wasted allocations/hour.
    //
    // Short-circuit BEFORE the replace chain by checking each entity
    // pattern explicitly. Six O(n) substring searches but ZERO
    // allocations on the (very common) no-entities-present path.
    if !s.contains("&amp;")
        && !s.contains("&lt;")
        && !s.contains("&gt;")
        && !s.contains("&quot;")
        && !s.contains("&apos;")
        && !s.contains("&#39;")
    {
        return std::borrow::Cow::Borrowed(s);
    }
    std::borrow::Cow::Owned(
        s.replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&#39;", "'"),
    )
}

#[cfg(test)]
mod decode_html_entities_tests {
    use super::decode_html_entities;
    use std::borrow::Cow;

    #[test]
    fn passthrough_borrowed_when_no_ampersand() {
        let no_amp = "status >= 200 || status < 300";
        let cow = decode_html_entities(no_amp);
        assert!(matches!(cow, Cow::Borrowed(_)));
        assert_eq!(cow.as_ref(), no_amp);
    }

    /// MCP-635: Rhai's `&&` operator makes `contains('&')` true even
    /// when there's no entity to decode. The stage-2 short-circuit
    /// MUST return a Cow::Borrowed for these inputs — otherwise every
    /// Rhai condition evaluation pays 6 String allocations.
    #[test]
    fn passthrough_borrowed_when_rhai_logical_and() {
        let s = "status != 401 && status != 403";
        let cow = decode_html_entities(s);
        assert!(
            matches!(cow, Cow::Borrowed(_)),
            "&& with no entities must NOT allocate; got Owned",
        );
        assert_eq!(cow.as_ref(), s);
    }

    /// MCP-635: same Cow::Borrowed contract for `&|` and similar
    /// `&`-containing patterns that aren't HTML entities.
    #[test]
    fn passthrough_borrowed_when_ampersand_not_an_entity() {
        for s in [
            "a & b",
            "field=value&other=value2",
            "url?a=1&b=2&c=3",
            "&xyz; not_a_known_entity",
        ] {
            let cow = decode_html_entities(s);
            assert!(
                matches!(cow, Cow::Borrowed(_)),
                "{s:?} must NOT allocate; got Owned",
            );
            assert_eq!(cow.as_ref(), s);
        }
    }

    #[test]
    fn decodes_amp() {
        assert_eq!(
            decode_html_entities("status != 401 &amp;&amp; status != 403").as_ref(),
            "status != 401 && status != 403"
        );
    }

    #[test]
    fn decodes_lt_and_gt() {
        assert_eq!(decode_html_entities("a &lt; b &gt; c").as_ref(), "a < b > c");
    }

    #[test]
    fn decodes_quotes_and_apos() {
        assert_eq!(
            decode_html_entities("&quot;hello&quot; &apos;x&apos; &#39;y&#39;").as_ref(),
            r#""hello" 'x' 'y'"#
        );
    }

    #[test]
    fn empty_string_is_borrowed() {
        let cow = decode_html_entities("");
        assert!(matches!(cow, Cow::Borrowed(_)));
        assert_eq!(cow.as_ref(), "");
    }

    #[test]
    fn idempotent_on_already_decoded() {
        let canonical = "status != 401 && status != 403";
        let once = decode_html_entities(canonical);
        let twice = decode_html_entities(once.as_ref());
        assert_eq!(twice.as_ref(), canonical);
    }
}

// Small UTF-8-safe truncation helper. Slicing a `&str` by raw byte index
// (`&s[..N]`) panics when the cut lands inside a multi-byte character —
// which is what bit aegix-ceo's /watch-semgrep workflow on 2026-04-29 (an
// em-dash crossing byte 4096 in the engine's input-preview path, fixed in
// engine commit e45e04e + controller r247).
//
// Walks back from `max_bytes` to the nearest UTF-8 boundary using stable
// `is_char_boundary`. (`floor_char_boundary` would be cleaner but is still
// unstable as of Rust 1.95 nightly — issue #93743.) Returns the borrowed
// safe slice; callers wrap it in `format!`/`to_string` if they need an
// owned value.
//
// `max_bytes >= s.len()` returns the original slice unchanged — no
// allocation, no work.
pub fn truncate_at_char_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// MCP-1030 (2026-05-15): bounded preview helper for reflecting caller-
/// supplied content into operator-facing error messages.
///
/// Returns a `Cow::Borrowed(s)` when `s.len() <= max_bytes` (the common
/// case — short typo'd inputs stay zero-alloc). Otherwise returns
/// `Cow::Owned(format!("{trimmed}…"))` where `trimmed` is `s` truncated
/// at the largest char boundary ≤ `max_bytes - 3` (the `…` codepoint
/// is 3 UTF-8 bytes, so the entire returned slice fits in
/// `max_bytes` bytes regardless of input).
///
/// Use this anywhere an error message echoes caller-supplied content —
/// without a cap, a multi-MB caller-input becomes a multi-MB error
/// response. Sibling reflection-class defense to MCP-1022
/// (validate_optional_string's allowlist-violation reflection cap)
/// and MCP-1029 (capability_world sandbox reflections).
///
/// Panics in debug builds if `max_bytes < 4` because the `…` marker
/// requires at least 3 bytes plus 1 for a meaningful prefix.
pub fn bounded_preview(s: &str, max_bytes: usize) -> std::borrow::Cow<'_, str> {
    debug_assert!(
        max_bytes >= 4,
        "bounded_preview requires max_bytes >= 4 to leave room for the … marker",
    );
    if s.len() <= max_bytes {
        return std::borrow::Cow::Borrowed(s);
    }
    // Leave room for the 3-byte … marker.
    let cut = max_bytes.saturating_sub(3);
    let prefix = truncate_at_char_boundary(s, cut);
    std::borrow::Cow::Owned(format!("{prefix}…"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_original_when_under_cap() {
        assert_eq!(truncate_at_char_boundary("hello", 100), "hello");
        assert_eq!(truncate_at_char_boundary("hello", 5), "hello");
    }

    #[test]
    fn truncates_ascii_at_exact_boundary() {
        assert_eq!(truncate_at_char_boundary("abcdef", 3), "abc");
    }

    #[test]
    fn walks_back_from_mid_multibyte_char() {
        // "café" = c(1) + a(1) + f(1) + é(2 bytes: 0xC3 0xA9) = 5 bytes.
        // max_bytes=4 lands inside é's 2-byte sequence — must walk back to 3.
        let s = "café";
        assert_eq!(truncate_at_char_boundary(s, 4), "caf");
        assert_eq!(truncate_at_char_boundary(s, 5), "café");
        assert_eq!(truncate_at_char_boundary(s, 3), "caf");
    }

    #[test]
    fn handles_em_dash_at_boundary() {
        // "a—b" = a(1) + em-dash(3 bytes: 0xE2 0x80 0x94) + b(1) = 5 bytes.
        let s = "a—b";
        assert_eq!(truncate_at_char_boundary(s, 1), "a");
        assert_eq!(truncate_at_char_boundary(s, 2), "a"); // mid-em-dash → walk back
        assert_eq!(truncate_at_char_boundary(s, 3), "a");
        assert_eq!(truncate_at_char_boundary(s, 4), "a—");
        assert_eq!(truncate_at_char_boundary(s, 5), "a—b");
    }

    #[test]
    fn empty_string_is_safe() {
        assert_eq!(truncate_at_char_boundary("", 0), "");
        assert_eq!(truncate_at_char_boundary("", 100), "");
    }

    #[test]
    fn zero_max_bytes_returns_empty() {
        assert_eq!(truncate_at_char_boundary("hello", 0), "");
        assert_eq!(truncate_at_char_boundary("café", 0), "");
    }

    // ── MCP-1030: bounded_preview tests ────────────────────────

    #[test]
    fn bounded_preview_short_input_borrows() {
        let cow = bounded_preview("hello", 64);
        assert!(matches!(cow, std::borrow::Cow::Borrowed(_)));
        assert_eq!(cow.as_ref(), "hello");
    }

    #[test]
    fn bounded_preview_at_cap_borrows() {
        let exactly = "a".repeat(64);
        let cow = bounded_preview(&exactly, 64);
        assert!(matches!(cow, std::borrow::Cow::Borrowed(_)));
        assert_eq!(cow.as_ref(), exactly.as_str());
    }

    #[test]
    fn bounded_preview_oversize_truncates_with_ellipsis() {
        let big = "x".repeat(1000);
        let cow = bounded_preview(&big, 64);
        assert!(matches!(cow, std::borrow::Cow::Owned(_)));
        assert!(cow.ends_with('…'));
        assert!(cow.len() <= 64);
    }

    #[test]
    fn bounded_preview_walks_back_from_mid_codepoint() {
        // "x"×60 + "é" = 60 + 2 = 62 bytes; preview at 64 borrows.
        // Now build something that forces truncation at a boundary.
        let s = "x".repeat(200);
        let cow = bounded_preview(&s, 32);
        assert!(matches!(cow, std::borrow::Cow::Owned(_)));
        assert!(cow.len() <= 32);
        assert!(cow.ends_with('…'));
    }

    #[test]
    fn bounded_preview_empty_input_borrows_empty() {
        let cow = bounded_preview("", 64);
        assert!(matches!(cow, std::borrow::Cow::Borrowed(_)));
        assert_eq!(cow.as_ref(), "");
    }
}
