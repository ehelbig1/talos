-- Phase 4 — graph_json legacy ID rewrite
--
-- Rewrites every node `type` UUID in `workflows.graph_json` and
-- `workflow_versions.graph_json` from a legacy alias
-- (`modules.legacy_template_id` or `modules.legacy_wasm_module_id`)
-- to the canonical `modules.id`. Refs that are already canonical or
-- orphan (no modules row at all) are left alone.
--
-- Audit at draft time (2026-04-23):
--   - workflows: 12 UUID node refs across 9 rows. 11 legacy_template_id, 1 canonical.
--   - workflow_versions: 9 UUID node refs across 7 rows. 6 legacy_template_id, 3 orphan
--     (inactive ship-fetch-github v2/v3/v4 — modules deleted historically).
--   - 0 legacy_wasm_module_id refs (kept in the rewrite logic for completeness).
--
-- Hash/signature recomputation: skipped intentionally. graph_signature is
-- structurally NULL across all rows; graph_hash is not verified at runtime
-- (workflow_signing.rs functions are defined but never called). If hash
-- enforcement is ever turned on, a follow-up migration will need to
-- recompute hashes for rewritten rows.
--
-- Per-row error isolation: PL/pgSQL FOR loops with nested BEGIN/EXCEPTION
-- blocks so one malformed graph_json doesn't abort the whole batch.
--
-- ⚠ WARNING ⚠
--   This migration is GATED on the Phase 4 readiness criteria
--   (total_reads > 100 AND miss_new == 0 AND uptime_days >= 7 in the
--   operator tool `get_module_unification_status`). Do NOT apply until
--   the gate is green AND the remaining ~12 admin/discovery readers
--   listed in docs/module-entity-consolidation.md "Phase 4 prerequisites"
--   are migrated. Otherwise post-rewrite reads via legacy aliases will
--   break (the aliases will no longer match anything in graph_json).
--
--   Until ready, this file lives in migrations/ but the recommended
--   safety check is to verify `MIGRATION_PHASE` constant in
--   controller/src/mcp/modules.rs is at least "4.0" before applying.

-- ── Step 1: rewrite workflows.graph_json (TEXT) ─────────────────────
-- workflows.graph_json is stored as TEXT. We cast to jsonb for
-- manipulation, rewrite per-node, then cast back to text.

DO $$
DECLARE
    r RECORD;
    new_nodes JSONB;
    new_graph JSONB;
    rewrote INT := 0;
    skipped INT := 0;
    failed INT := 0;
BEGIN
    FOR r IN
        SELECT w.id, w.graph_json::jsonb AS gj
        FROM workflows w
        WHERE jsonb_typeof(w.graph_json::jsonb -> 'nodes') = 'array'
    LOOP
        BEGIN
            -- Walk each node and rewrite its `type` field if it points
            -- at a legacy alias. ID-shape match is left-tight (try
            -- legacy_template_id first since the audit shows that's
            -- the dominant path; fall back to legacy_wasm_module_id).
            new_nodes := COALESCE((
                SELECT jsonb_agg(
                    CASE
                        WHEN (n ->> 'type') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                             AND m.id IS NOT NULL
                             AND m.id::text != (n ->> 'type')
                        THEN n || jsonb_build_object('type', m.id::text)
                        ELSE n
                    END
                )
                FROM jsonb_array_elements(r.gj -> 'nodes') AS n
                LEFT JOIN modules m
                       ON m.legacy_template_id::text = (n ->> 'type')
                       OR m.legacy_wasm_module_id::text = (n ->> 'type')
            ), '[]'::jsonb);

            new_graph := jsonb_set(r.gj, '{nodes}', new_nodes, false);

            IF new_graph::text != r.gj::text THEN
                UPDATE workflows
                   SET graph_json = new_graph::text,
                       updated_at = NOW()
                 WHERE id = r.id;
                rewrote := rewrote + 1;
            ELSE
                skipped := skipped + 1;
            END IF;
        EXCEPTION WHEN OTHERS THEN
            failed := failed + 1;
            RAISE WARNING 'Phase 4 graph rewrite failed for workflow %: % (SQLSTATE %)',
                          r.id, SQLERRM, SQLSTATE;
        END;
    END LOOP;

    RAISE NOTICE 'Phase 4 workflows rewrite: rewrote=%, unchanged=%, failed=%',
                 rewrote, skipped, failed;
END
$$ LANGUAGE plpgsql;

-- ── Step 2: rewrite workflow_versions.graph_json (JSONB) ────────────
-- workflow_versions.graph_json is already JSONB. Same rewrite logic,
-- but INACTIVE versions with orphan refs (modules deleted historically)
-- are left untouched — they're frozen historical state. The rewrite
-- only fires when the alias resolves to a live modules row.

DO $$
DECLARE
    r RECORD;
    new_nodes JSONB;
    new_graph JSONB;
    rewrote INT := 0;
    skipped INT := 0;
    failed INT := 0;
BEGIN
    FOR r IN
        SELECT wv.id, wv.graph_json AS gj
        FROM workflow_versions wv
        WHERE jsonb_typeof(wv.graph_json -> 'nodes') = 'array'
    LOOP
        BEGIN
            new_nodes := COALESCE((
                SELECT jsonb_agg(
                    CASE
                        WHEN (n ->> 'type') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                             AND m.id IS NOT NULL
                             AND m.id::text != (n ->> 'type')
                        THEN n || jsonb_build_object('type', m.id::text)
                        ELSE n
                    END
                )
                FROM jsonb_array_elements(r.gj -> 'nodes') AS n
                LEFT JOIN modules m
                       ON m.legacy_template_id::text = (n ->> 'type')
                       OR m.legacy_wasm_module_id::text = (n ->> 'type')
            ), '[]'::jsonb);

            new_graph := jsonb_set(r.gj, '{nodes}', new_nodes, false);

            IF new_graph::text != r.gj::text THEN
                UPDATE workflow_versions
                   SET graph_json = new_graph,
                       updated_at = NOW()
                 WHERE id = r.id;
                rewrote := rewrote + 1;
            ELSE
                skipped := skipped + 1;
            END IF;
        EXCEPTION WHEN OTHERS THEN
            failed := failed + 1;
            RAISE WARNING 'Phase 4 graph rewrite failed for workflow_version %: % (SQLSTATE %)',
                          r.id, SQLERRM, SQLSTATE;
        END;
    END LOOP;

    RAISE NOTICE 'Phase 4 workflow_versions rewrite: rewrote=%, unchanged=%, failed=%',
                 rewrote, skipped, failed;
END
$$ LANGUAGE plpgsql;

-- ── Step 3: post-rewrite assertion ──────────────────────────────────
-- After this migration, a SELECT that classifies remaining refs should
-- show only `canonical` and `ORPHAN` (no `legacy_*` rows). If anything
-- still classifies as `legacy_template_id` or `legacy_wasm_module_id`,
-- the rewrite missed something — the post-Phase-4 column drop will
-- then break those workflows. Fail closed if the assertion fails.

DO $$
DECLARE
    leftover_count INT;
BEGIN
    SELECT COUNT(*) INTO leftover_count
    FROM (
        SELECT (n ->> 'type')::uuid AS node_type
        FROM workflows w,
             jsonb_array_elements(w.graph_json::jsonb -> 'nodes') AS n
        WHERE jsonb_typeof(w.graph_json::jsonb -> 'nodes') = 'array'
          AND (n ->> 'type') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        UNION ALL
        SELECT (n ->> 'type')::uuid
        FROM workflow_versions wv,
             jsonb_array_elements(wv.graph_json -> 'nodes') AS n
        WHERE jsonb_typeof(wv.graph_json -> 'nodes') = 'array'
          AND (n ->> 'type') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    ) refs
    JOIN modules m
      ON m.legacy_template_id = refs.node_type
      OR m.legacy_wasm_module_id = refs.node_type
    WHERE NOT EXISTS (SELECT 1 FROM modules m2 WHERE m2.id = refs.node_type);

    IF leftover_count > 0 THEN
        RAISE EXCEPTION 'Phase 4 graph rewrite assertion failed: % node refs still resolve via legacy aliases. Investigate before dropping legacy_template_id / legacy_wasm_module_id columns.', leftover_count;
    END IF;

    RAISE NOTICE 'Phase 4 graph rewrite assertion passed: zero remaining legacy-alias refs.';
END
$$ LANGUAGE plpgsql;
