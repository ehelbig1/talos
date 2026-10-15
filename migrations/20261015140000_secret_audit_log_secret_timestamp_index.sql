-- One secret's audit history, newest first, by index (security review
-- 2026-10-15, C2-3). `get_audit_log` reads `WHERE secret_id = $1 ORDER BY
-- timestamp DESC LIMIT n`; the table had `(secret_id)` and `(timestamp)`
-- apart, and since 2026-10-14 it gains one `dispatch_read` row per secret a
-- dispatch is handed, so a busy secret's history is the read that grows.
-- An index only: the table is append-only (immutability trigger), and no
-- row is rewritten (check 105).
CREATE INDEX IF NOT EXISTS idx_secret_audit_log_secret_timestamp
    ON secret_audit_log (secret_id, "timestamp" DESC);
