#!/usr/bin/env bash
#
# Phase 0.1 of module entity unification (docs/module-entity-consolidation.md):
# walk every workflow's graph_json, regex out UUIDs, and classify each one
# as `wasm_modules.id` / `node_templates.id` / `modules.id` / unresolvable.
#
# Output: a per-workflow report listing dangling refs (UUIDs that don't
# resolve to any of the three module tables). Phase 4's graph_json rewrite
# step needs every reference to resolve; un-resolvable refs block cutover
# and require manual intervention.
#
# Run via `make audit-module-refs`. Read-only — does NOT mutate any tables.

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

# Prefer the running Postgres in docker; fall back to a local socket if
# the user is running migrations against a non-Docker DB.
PSQL_RUN="${PSQL_RUN:-docker compose exec -T postgres psql -U talos -d talos}"

echo "📊 graph_json module-reference audit (read-only)"
echo

cat <<'SQL' | $PSQL_RUN
WITH workflow_uuids AS (
    -- Pull every UUID-looking substring out of every workflow's graph_json.
    -- regexp_matches with the 'g' flag yields one row per match.
    SELECT
        w.id AS workflow_id,
        w.name AS workflow_name,
        (regexp_matches(
            w.graph_json,
            '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            'g'
        ))[1]::uuid AS uuid_ref
    FROM workflows w
    WHERE (w.status IS NULL OR w.status != 'archived')
      AND w.graph_json IS NOT NULL
),
classified AS (
    -- For each UUID, ask: does it resolve to any module table?
    SELECT
        u.workflow_id,
        u.workflow_name,
        u.uuid_ref,
        EXISTS (SELECT 1 FROM wasm_modules    WHERE id = u.uuid_ref)        AS in_wasm_modules,
        EXISTS (SELECT 1 FROM node_templates  WHERE id = u.uuid_ref)        AS in_node_templates,
        EXISTS (SELECT 1 FROM modules         WHERE id = u.uuid_ref)        AS in_modules,
        EXISTS (SELECT 1 FROM modules         WHERE legacy_template_id    = u.uuid_ref) AS in_modules_via_legacy_t,
        EXISTS (SELECT 1 FROM modules         WHERE legacy_wasm_module_id = u.uuid_ref) AS in_modules_via_legacy_w,
        EXISTS (SELECT 1 FROM workflows       WHERE id = u.uuid_ref)        AS is_workflow_id,
        EXISTS (SELECT 1 FROM users           WHERE id = u.uuid_ref)        AS is_user_id,
        EXISTS (SELECT 1 FROM actors          WHERE id = u.uuid_ref)        AS is_actor_id
    FROM workflow_uuids u
),
summary AS (
    SELECT
        COUNT(*)                                  AS total_uuids,
        COUNT(*) FILTER (WHERE in_modules)        AS resolves_to_modules,
        COUNT(*) FILTER (WHERE in_modules_via_legacy_t OR in_modules_via_legacy_w) AS resolves_via_legacy,
        COUNT(*) FILTER (WHERE in_wasm_modules)   AS resolves_to_wasm_modules,
        COUNT(*) FILTER (WHERE in_node_templates) AS resolves_to_node_templates,
        COUNT(*) FILTER (
            WHERE NOT in_modules
              AND NOT in_modules_via_legacy_t
              AND NOT in_modules_via_legacy_w
              AND NOT in_wasm_modules
              AND NOT in_node_templates
              AND NOT is_workflow_id
              AND NOT is_user_id
              AND NOT is_actor_id
        ) AS dangling_uuids
    FROM classified
)
SELECT * FROM summary;
SQL

echo
echo "─── Dangling refs (top 30; UUID does not resolve to any known table) ───"
cat <<'SQL' | $PSQL_RUN
WITH workflow_uuids AS (
    SELECT
        w.id AS workflow_id,
        w.name AS workflow_name,
        (regexp_matches(
            w.graph_json,
            '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            'g'
        ))[1]::uuid AS uuid_ref
    FROM workflows w
    WHERE (w.status IS NULL OR w.status != 'archived')
      AND w.graph_json IS NOT NULL
)
SELECT
    LEFT(workflow_name, 40) AS workflow,
    uuid_ref
FROM workflow_uuids u
WHERE NOT EXISTS (SELECT 1 FROM modules m       WHERE m.id = u.uuid_ref)
  AND NOT EXISTS (SELECT 1 FROM modules m       WHERE m.legacy_template_id    = u.uuid_ref)
  AND NOT EXISTS (SELECT 1 FROM modules m       WHERE m.legacy_wasm_module_id = u.uuid_ref)
  AND NOT EXISTS (SELECT 1 FROM wasm_modules    WHERE id = u.uuid_ref)
  AND NOT EXISTS (SELECT 1 FROM node_templates  WHERE id = u.uuid_ref)
  AND NOT EXISTS (SELECT 1 FROM workflows       WHERE id = u.uuid_ref)
  AND NOT EXISTS (SELECT 1 FROM users           WHERE id = u.uuid_ref)
  AND NOT EXISTS (SELECT 1 FROM actors          WHERE id = u.uuid_ref)
ORDER BY workflow_name
LIMIT 30;
SQL

echo
echo "✓ Audit complete. Phase 4 cutover blocked until 'dangling_uuids' = 0 (or all entries are intentional non-module refs)."
