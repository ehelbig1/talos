-- `secret_audit_log` names the secret it is about by the hash of its path,
-- and dispatch reads are recorded (security review 2026-10-14, C-4).
--
-- CLAUDE.md said "Audit logs record `key_hash` (SHA-256 of path)" of a column
-- that did not exist: the log was keyed by `secret_id` alone, and once a
-- secret was deleted its history named nothing. Every audit insert now
-- stores `key_hash` (hex SHA-256 of `key_path`, read from the secret row at
-- insert time — audit rows are written before a delete), and every secret a
-- dispatch is handed gets a `dispatch_read` row (actor_type `dispatch`).
--
-- Replaces 20261014191000, which did the same with a backfill and never applied on
-- the reference deployment (removed; see
-- docs/engineering-log/packages/2026-10-15-audit-key-hash-no-backfill.md).
--
-- No backfill. `secret_audit_log` is append-only: `trg_secret_audit_log_immutable`
-- (20260408000001) refuses every UPDATE, so a backfill fails on any database
-- that holds an audit row — it passed CI only because a test database holds
-- none (a row trigger does not fire on zero rows), and it stopped the reference
-- deployment's migrate (2026-10-15). Rewriting history is also what the policy
-- exists to forbid. Rows written before this column stay NULL; while their
-- secret exists they are attributed through `secret_id`, as they always were.
-- Index: an operator's question is "who read this path, when".

ALTER TABLE secret_audit_log ADD COLUMN IF NOT EXISTS key_hash TEXT;

CREATE INDEX IF NOT EXISTS idx_secret_audit_log_key_hash
    ON secret_audit_log (key_hash, "timestamp")
    WHERE key_hash IS NOT NULL;

COMMENT ON COLUMN secret_audit_log.key_hash IS
    'hex SHA-256 of the secret''s key_path at the time of the event; '
    'attributes the row after the secret is deleted. Never the value.';
