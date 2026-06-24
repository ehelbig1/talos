-- Adds a GIN trigram index on workflows.graph_json so the module-reference
-- LIKE scans become indexable instead of full sequential scans.
--
-- FINDING P4 (Medium): several hot paths filter workflows by whether their
-- serialized graph contains a module/workflow UUID using a leading-wildcard
-- predicate:  graph_json LIKE '%' || <id> || '%'
-- A leading wildcard defeats a btree index, so every one of these did a full
-- sequential scan over the workflows table. pg_trgm's gin_trgm_ops makes
-- `LIKE '%substr%'` indexable (the planner extracts trigrams from the literal
-- and probes the GIN index).
--
-- workflows.graph_json is a TEXT column (declared in 001_initial_schema.sql;
-- the ::jsonb / ::text casts elsewhere in the codebase are projection casts,
-- not the storage type), so we index the column directly with gin_trgm_ops.
--
-- Query sites accelerated:
--   talos-module-repository/src/lib.rs
--     :375-382  get_module_ref_counts            (graph_json LIKE '%' || $2 || '%')
--     :986      find_referenced_modules ranking  (w.graph_json LIKE '%' || target_id || '%')
--     :1025     find_unreferenced_modules        (w.graph_json LIKE '%' || m.id || '%')
--     :1117     find_referenced_modules_in_workflows (w.graph_json::text LIKE '%' || m.id || '%')
--   talos-analytics-repository/src/lib.rs
--     :3384     orphaned-module hygiene          (w.graph_json LIKE '%' || m.id || '%')
--
-- No CONCURRENTLY: sqlx runs each migration inside a transaction (CLAUDE.md
-- migration rule + lint check 30), and CREATE INDEX CONCURRENTLY cannot run
-- in a transaction block.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS idx_workflows_graph_json_trgm
    ON workflows USING gin (graph_json gin_trgm_ops);
