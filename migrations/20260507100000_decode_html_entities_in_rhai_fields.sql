-- MCP-11: one-shot decode of HTML entities in stored Rhai expressions
--
-- Background: LLM clients (and humans copy-pasting from rendered HTML
-- or markdown) sometimes inject `&amp;`/`&lt;`/`&gt;`/`&quot;`/`&apos;`/`&#39;`
-- into the Rhai-expression fields of a workflow's `graph_json`. The Rhai
-- engine doesn't understand HTML entities, so the expression silently
-- fails to parse and the safe-default fallback fires
-- (retry-everything / skip-nothing). Engine commit `8b2c3f3` shipped a
-- runtime decoder, but the JSON-API responses (`get_workflow`,
-- `get_workflow_raw_json`) still surface the encoded form to operators
-- inspecting the workflow.
--
-- This migration normalises the at-rest form. The write-time decoder
-- in `talos-mcp-handlers/src/graph.rs::canonicalise_rhai_in_graph_json`
-- prevents new encoded values from being written; this one-shot pass
-- cleans up everything that's already been persisted.
--
-- Field set (must match `talos_text_util::RHAI_EXPRESSION_FIELDS`):
--   * `retry_condition`
--   * `retry_delay_expression`
--   * `skip_condition`
--   * `synthesis_expr`
--   * `expression`
--   * `synthesize_expression`
-- Plus per-edge `condition`.
--
-- Looked-for locations per node:
--   * top-level (e.g. `n.retry_condition` next to `n.retry_count`)
--   * inside `data` (e.g. `n.data.synthesis_expr`)
-- We rewrite both since the codebase historically used both shapes.
--
-- Risk per the backlog item: a literal `&amp;` inside a string-literal
-- Rhai context (`if msg.contains("&amp;") {...}`) would be mutated.
-- Acceptable per backlog rationale ("this is code, not data") and the
-- field set is restricted to known Rhai-expression keys, never
-- arbitrary description / name strings.
--
-- Per-row error isolation: PL/pgSQL FOR loops with nested BEGIN/EXCEPTION
-- blocks so one malformed graph_json doesn't abort the whole batch.

-- ── helper: decode a single string ──────────────────────────────────
CREATE OR REPLACE FUNCTION pg_temp.decode_html_entities(s TEXT) RETURNS TEXT AS $$
BEGIN
    IF s IS NULL OR position('&' in s) = 0 THEN
        RETURN s;
    END IF;
    RETURN replace(replace(replace(replace(replace(replace(s,
        '&amp;', '&'),
        '&lt;', '<'),
        '&gt;', '>'),
        '&quot;', '"'),
        '&apos;', ''''),
        '&#39;', '''');
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ── helper: decode every Rhai field in a graph_json document ────────
-- Mirrors talos_text_util::decode_rhai_in_graph: walks nodes (top
-- level + .data) and edges (.condition). Returns the rewritten graph
-- and the number of decoded sites; caller decides whether to write back.
CREATE OR REPLACE FUNCTION pg_temp.decode_rhai_in_graph(g JSONB)
RETURNS TABLE (new_graph JSONB, decoded_sites INT) AS $$
DECLARE
    fields TEXT[] := ARRAY[
        'retry_condition',
        'retry_delay_expression',
        'skip_condition',
        'synthesis_expr',
        'expression',
        'synthesize_expression'
    ];
    f TEXT;
    sites INT := 0;
    new_nodes JSONB;
    new_edges JSONB;
BEGIN
    -- Walk nodes: rewrite top-level + nested .data Rhai fields.
    IF jsonb_typeof(g -> 'nodes') = 'array' THEN
        new_nodes := COALESCE((
            SELECT jsonb_agg(
                (
                    SELECT jsonb_object_agg(k, decoded_v)
                    FROM (
                        -- Decode each known field at top level
                        SELECT k, CASE
                            WHEN k = ANY(fields)
                                 AND jsonb_typeof(v) = 'string'
                                 AND pg_temp.decode_html_entities(v #>> '{}') IS DISTINCT FROM (v #>> '{}')
                            THEN to_jsonb(pg_temp.decode_html_entities(v #>> '{}'))
                            -- Walk into .data and decode Rhai fields there too
                            WHEN k = 'data' AND jsonb_typeof(v) = 'object'
                            THEN (
                                SELECT jsonb_object_agg(dk, CASE
                                    WHEN dk = ANY(fields)
                                         AND jsonb_typeof(dv) = 'string'
                                         AND pg_temp.decode_html_entities(dv #>> '{}') IS DISTINCT FROM (dv #>> '{}')
                                    THEN to_jsonb(pg_temp.decode_html_entities(dv #>> '{}'))
                                    ELSE dv
                                END)
                                FROM jsonb_each(v) AS d(dk, dv)
                            )
                            ELSE v
                        END AS decoded_v
                        FROM jsonb_each(n) AS e(k, v)
                    ) AS t
                )
            )
            FROM jsonb_array_elements(g -> 'nodes') AS n
        ), '[]'::jsonb);
    ELSE
        new_nodes := g -> 'nodes';
    END IF;

    -- Walk edges: rewrite .condition only.
    IF jsonb_typeof(g -> 'edges') = 'array' THEN
        new_edges := COALESCE((
            SELECT jsonb_agg(
                CASE
                    WHEN jsonb_typeof(e -> 'condition') = 'string'
                         AND pg_temp.decode_html_entities((e -> 'condition') #>> '{}')
                             IS DISTINCT FROM ((e -> 'condition') #>> '{}')
                    THEN e || jsonb_build_object('condition',
                        pg_temp.decode_html_entities((e -> 'condition') #>> '{}'))
                    ELSE e
                END
            )
            FROM jsonb_array_elements(g -> 'edges') AS e
        ), '[]'::jsonb);
    ELSE
        new_edges := g -> 'edges';
    END IF;

    new_graph := g;
    IF new_nodes IS NOT NULL THEN
        new_graph := jsonb_set(new_graph, '{nodes}', new_nodes, false);
    END IF;
    IF new_edges IS NOT NULL THEN
        new_graph := jsonb_set(new_graph, '{edges}', new_edges, false);
    END IF;

    -- Count decoded sites by stringifying both forms (sufficient for
    -- telemetry — we just need a non-zero count to tell whether the
    -- rewrite changed anything).
    sites := CASE WHEN new_graph::text IS DISTINCT FROM g::text THEN 1 ELSE 0 END;

    RETURN QUERY SELECT new_graph, sites;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ── Step 1: rewrite workflows.graph_json (TEXT column) ──────────────
DO $$
DECLARE
    r RECORD;
    rewrote INT := 0;
    skipped INT := 0;
    failed INT := 0;
    res RECORD;
BEGIN
    FOR r IN
        SELECT w.id, w.graph_json::jsonb AS gj
        FROM workflows w
        WHERE w.graph_json IS NOT NULL
          AND w.graph_json LIKE '%&%' -- cheap pre-filter: skip rows with no `&` at all
    LOOP
        BEGIN
            SELECT * INTO res FROM pg_temp.decode_rhai_in_graph(r.gj);
            IF res.decoded_sites > 0 THEN
                UPDATE workflows
                   SET graph_json = res.new_graph::text,
                       updated_at = NOW()
                 WHERE id = r.id;
                rewrote := rewrote + 1;
            ELSE
                skipped := skipped + 1;
            END IF;
        EXCEPTION WHEN OTHERS THEN
            failed := failed + 1;
            RAISE WARNING 'MCP-11 Rhai decode failed for workflow %: % (SQLSTATE %)',
                          r.id, SQLERRM, SQLSTATE;
        END;
    END LOOP;
    RAISE NOTICE 'MCP-11 workflows rewrite: rewrote=%, unchanged=%, failed=%',
                 rewrote, skipped, failed;
END
$$ LANGUAGE plpgsql;

-- ── Step 2: rewrite workflow_versions.graph_json (JSONB column) ─────
DO $$
DECLARE
    r RECORD;
    rewrote INT := 0;
    skipped INT := 0;
    failed INT := 0;
    res RECORD;
BEGIN
    FOR r IN
        SELECT wv.id, wv.graph_json AS gj
        FROM workflow_versions wv
        WHERE wv.graph_json IS NOT NULL
          AND wv.graph_json::text LIKE '%&%'
    LOOP
        BEGIN
            SELECT * INTO res FROM pg_temp.decode_rhai_in_graph(r.gj);
            IF res.decoded_sites > 0 THEN
                UPDATE workflow_versions
                   SET graph_json = res.new_graph
                 WHERE id = r.id;
                rewrote := rewrote + 1;
            ELSE
                skipped := skipped + 1;
            END IF;
        EXCEPTION WHEN OTHERS THEN
            failed := failed + 1;
            RAISE WARNING 'MCP-11 Rhai decode failed for workflow_version %: % (SQLSTATE %)',
                          r.id, SQLERRM, SQLSTATE;
        END;
    END LOOP;
    RAISE NOTICE 'MCP-11 workflow_versions rewrite: rewrote=%, unchanged=%, failed=%',
                 rewrote, skipped, failed;
END
$$ LANGUAGE plpgsql;
