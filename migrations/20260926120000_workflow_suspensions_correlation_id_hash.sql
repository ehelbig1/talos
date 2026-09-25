-- Key the suspension-callback lookup on a digest of the correlation id, not
-- the raw capability (the approval-gate pattern, 20260608140000).
--
-- POST /api/callbacks/<correlation_id> authenticates purely on the URL: the
-- correlation id IS the bearer token. The handler looked it up with
-- `WHERE correlation_id = $1`, a byte-level comparison on the raw secret. It
-- now looks up `WHERE correlation_id_hash = $1` and constant-time compares the
-- full id after fetch. STORED generated column: existing rows are backfilled
-- by the column add and every writer stays correct with no change. The
-- expression matches `talos_text_util::sha256_hex` byte-for-byte.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE workflow_suspensions
    ADD COLUMN IF NOT EXISTS correlation_id_hash TEXT
    GENERATED ALWAYS AS (encode(digest(correlation_id, 'sha256'), 'hex')) STORED;

CREATE INDEX IF NOT EXISTS idx_suspensions_correlation_id_hash_waiting
    ON workflow_suspensions (correlation_id_hash) WHERE status = 'waiting';
