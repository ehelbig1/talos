-- Tombstone columns for module-execution payload retention.
--
-- WHY THESE COLUMNS EXIST AT ALL
-- ------------------------------
-- `module_executions` is the only execution-history table in the schema with
-- no retention bound of any kind. Measured on the dev fleet 2026-08-27:
--
--   module_executions      130 MB   oldest row 50 days   bounded by NOTHING
--   execution_events       112 MB   oldest row 30 days   CASCADE from workflow_executions
--   workflow_executions    107 MB   oldest row 30 days   6-hourly retention DELETE
--   module_execution_logs   37 MB                        CASCADE from module_executions
--
-- 82 MB of the 130 MB is TOAST, essentially all of it the two AEAD payload
-- columns (`input_data_enc` 71 MB, `output_data_enc` 10 MB;
-- `trigger_metadata_enc` is empty on every row).
--
-- `controller/src/bootstrap/background.rs` already DELETES the whole PARENT
-- row after `EXECUTION_RETENTION_DAYS` (default 30) and CASCADEs
-- `execution_events` with it. `module_executions.workflow_execution_id` has NO
-- foreign key, so the child simply orphans and is kept forever — 7,656 rows
-- (15 MB of payload) on the dev fleet already outlive a parent that no longer
-- exists. That is an omission, not a considered decision.
--
-- WHY A TOMBSTONE IS REQUIRED, AND NOT OPTIONAL
-- ---------------------------------------------
-- Nulling an AEAD payload is IRREVERSIBLE. There is no decrypt-and-restore;
-- recovery means a backup restore. So the one thing a later reader must never
-- have to guess is whether a NULL payload was pruned or was never written.
--
-- That ambiguity is not hypothetical here — it is already the majority case.
-- 22,370 of 36,065 rows have `output_data_enc IS NULL` and NEVER HAD an output:
-- they are the residue of the ledger-finalizer outage relabelled by
-- `20260812120000_relabel_unfinalized_module_executions.sql`, where the sweep
-- had no output to write. Without a tombstone, a pruned row and one of those
-- rows are byte-identical, and every future reader inherits the ambiguity.
-- (This is [[absent-is-not-zero]] in a bytea column.)
--
--   payload_pruned_at IS NULL      -> this row was never pruned. A NULL payload
--                                     means the payload was never written.
--   payload_pruned_at IS NOT NULL  -> the retention sweep cleared this row at
--                                     that instant.
--   pruned_input_bytes  /          -> what was there, per slot, so the per-slot
--   pruned_output_bytes             question stays answerable too. NULL means
--                                     that slot held nothing at prune time —
--                                     which is the common case for
--                                     `pruned_output_bytes`, since the 21,873
--                                     `timeout` rows never had an output.
--
-- Sizes only. No payload content, no plaintext, no module name, no tenant
-- identifier — the value is already derivable from the row it sits on.
--
-- WHY NOT REUSE AN EXISTING COLUMN
-- --------------------------------
-- Two candidates were rejected for concrete reasons, not taste:
--
--  * `payload_format` — it drives AEAD dispatch (`read_module_payload`, and the
--    `payload_format <> $1` predicate of `re_encrypt_module_payloads_to_org`
--    and `dek_migration_status`). A sentinel value there would silently change
--    which rows the per-org DEK migration sweeps.
--  * a seventh `status` value — rejected for the same reason
--    `20260812120000` rejected it: `status` is what every reader in the
--    workspace switches on, and the CHECK constraint admits exactly six.
--
-- `error_type` is the precedent this follows: a DISPLAY column with no routing
-- behaviour behind it, read by `ModuleExecutionService::get_execution` /
-- `get_module_executions` -> GraphQL `ModuleExecution` -> `moduleExecutions`.
-- These three columns are wired to that same reader in the same change, so the
-- values are not written into a void.
--
-- COST
-- ----
-- Three nullable columns add no bytes to an unpruned row (NULL bitmap only) and
-- 16 bytes to a pruned one. At the 22,319 rows the first sweep would touch that
-- is ~357 KB, against ~42 MB of TOAST released.
--
-- WHAT THIS MIGRATION DOES NOT DO
-- -------------------------------
-- It does not prune anything, and it does not enable anything. It adds three
-- columns that are NULL on all 36,065 existing rows, which is exactly the
-- "never pruned" reading. The sweep that writes them is opt-in
-- (`MODULE_PAYLOAD_RETENTION_ENABLED`, default off) and is documented with a
-- stated precondition for turning it on.
--
-- allow-actor-memory-sql: not actor_memory — this is module_executions.

ALTER TABLE module_executions
    ADD COLUMN IF NOT EXISTS payload_pruned_at   timestamptz,
    ADD COLUMN IF NOT EXISTS pruned_input_bytes  integer,
    ADD COLUMN IF NOT EXISTS pruned_output_bytes integer;

COMMENT ON COLUMN module_executions.payload_pruned_at IS
    'Set by the opt-in payload-retention sweep when this row''s AEAD payloads were cleared. NULL means never pruned, so a NULL payload on such a row was never written. Irreversible: there is no decrypt-and-restore.';
COMMENT ON COLUMN module_executions.pruned_input_bytes IS
    'octet_length(input_data_enc) at prune time. NULL when the row was never pruned OR the slot was empty.';
COMMENT ON COLUMN module_executions.pruned_output_bytes IS
    'octet_length(output_data_enc) at prune time. NULL when the row was never pruned OR the slot was empty (the common case: 21,873 timeout rows never had an output).';

-- Partial index on the tombstone. Deliberately partial: the sweep's own
-- predicate excludes already-pruned rows via the payload IS NOT NULL test, so
-- this index exists for the READ side (an operator asking "what has retention
-- taken?") and for the sweep's reporting counters. A full-table index here
-- would cost ~800 KB to answer a question about a minority of rows.
--
-- No CONCURRENTLY: sqlx wraps migrations in a transaction (lint check 30).
CREATE INDEX IF NOT EXISTS idx_module_executions_payload_pruned
    ON module_executions (payload_pruned_at DESC)
    WHERE payload_pruned_at IS NOT NULL;
