-- Drop eleven tables that nothing in the workspace reads or writes.
--
-- Measured 2026-09-12 by sweeping every `public` table against every non-test
-- Rust source file in the workspace (INSERT/UPDATE/DELETE = writer,
-- FROM/JOIN = reader) and against the live reference database:
--
--   table                          created by                      rows  writers  readers
--   circuit_breaker_metrics        20260329000000_new_modules_tables  0     0       0   (docs/backlog.md already proposed the drop, 2026-08-11)
--   compilation_cache              001_initial_schema                 0     0       0
--   feature_flags                  20260329000000_new_modules_tables  0     0       0
--   idempotency_keys               20260329000000_new_modules_tables  0     0       0   (the worker's idempotency store is in-process — talos-idempotency)
--   key_rotation_events            20260312001100_add_secrets_rotation 0    0       0   (rotation audit goes to secret_audit_log, e.g. MASTER_KEY_ROTATED)
--   mcp_crate_allowlist            20260312000400_add_mcp_crate_allowlist 0  0      0   (the dependency allowlist is compiled into talos-compilation)
--   secrets_rotation_log           20260329000000_new_modules_tables  0     0       0
--   tenant_quotas                  20260329000000_new_modules_tables  0     0       0   (budgets are actor_budget_policies; nothing ever read a quota)
--   webhook_processed_events       20260329000000_new_modules_tables  0     0       0   (webhook dedup keys on the verified signature in Redis)
--   workflow_nodes                 001_initial_schema                 0     0       0   (graphs live in workflows.graph_json; talos-registry's comment already
--                                                                                       said "that table has no INSERT writer anywhere in the workspace")
--   google_calendar_watch_channels 005_google_calendar_integration    0     0       3   (channels moved to integration_state; the three readers were a
--                                                                                       query_paginated deny-list entry — RETAINED as forward-protection —
--                                                                                       and a WASM-cache eviction exemption that could never match, removed
--                                                                                       in the same change)
--
-- None has a dependent view, an inbound foreign key, an RLS policy or a row on
-- the reference fleet; each is in the schema baseline, so this is the
-- post-cutpoint tail dropping baseline objects (the 20260911120000 /
-- 20260911160000 precedent). `IF EXISTS` for idempotency. Indexes and the
-- one `updated_at` trigger go with their tables.
--
-- NOT dropped, deliberately: `schema_audit_log` (2 020 rows, written by the
-- `log_schema_changes` DDL event trigger on every migration — a live
-- change-management record that the SOC 2 collector now exports) and the
-- four written-but-unread audit tables (`oauth_audit_log`,
-- `gmail_integration_audit_log`, `slack_integration_audit_log`,
-- `module_marketplace_stars`), which HAVE writers.

DROP TABLE IF EXISTS circuit_breaker_metrics;
DROP TABLE IF EXISTS compilation_cache;
DROP TABLE IF EXISTS feature_flags;
DROP TABLE IF EXISTS idempotency_keys;
DROP TABLE IF EXISTS key_rotation_events;
DROP TABLE IF EXISTS mcp_crate_allowlist;
DROP TABLE IF EXISTS secrets_rotation_log;
DROP TABLE IF EXISTS tenant_quotas;
DROP TABLE IF EXISTS webhook_processed_events;
DROP TABLE IF EXISTS workflow_nodes;
DROP TABLE IF EXISTS google_calendar_watch_channels;
