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
-- Backfill: the rows whose secret still exists. A row whose secret is gone
-- has no path to hash and stays NULL.
-- Index: an operator's question is "who read this path, when".

ALTER TABLE secret_audit_log ADD COLUMN IF NOT EXISTS key_hash TEXT;

UPDATE secret_audit_log l
SET key_hash = encode(sha256(convert_to(s.key_path, 'UTF8')), 'hex')
FROM secrets s
WHERE s.id = l.secret_id AND l.key_hash IS NULL;

CREATE INDEX IF NOT EXISTS idx_secret_audit_log_key_hash
    ON secret_audit_log (key_hash, "timestamp")
    WHERE key_hash IS NOT NULL;

COMMENT ON COLUMN secret_audit_log.key_hash IS
    'hex SHA-256 of the secret''s key_path at the time of the event; '
    'attributes the row after the secret is deleted. Never the value.';
