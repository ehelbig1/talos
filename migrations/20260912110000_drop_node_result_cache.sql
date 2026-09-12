-- Drop `node_result_cache`: the table behind a cache nothing ever called.
--
-- `talos-node-cache` (271 lines) was extracted in May 2026 with a controller
-- shim reading "Re-export for future use; not yet wired into the engine".
-- Measured 2026-09-12: the crate has ZERO constructors anywhere in the
-- workspace (`NodeResultCache::new` is called by nothing), the table holds
-- zero rows, and `pg_stat_statements` has never recorded a statement over it
-- since the 2026-09-10 postmaster start. Two bug fixes had been made to it
-- while dead (MCP-695 zero-TTL, MCP-1117 bool-env footgun), and
-- `docs/configuration-reference.md` listed `TALOS_NODE_CACHE` as a live knob
-- for "both" processes — a documented control that controlled nothing. The
-- crate, its shim and the doc row go with this table (the `talos-jobs` /
-- `talos-db-monitor` precedent, package K).
--
-- Zero rows, no inbound FK, no policy, 4 indexes; in the schema baseline, so
-- this is the tail dropping a baseline object. `IF EXISTS` for idempotency.

DROP TABLE IF EXISTS node_result_cache;
