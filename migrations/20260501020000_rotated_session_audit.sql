-- Token-reuse detection: when a refresh token is rotated, record its
-- lookup_hash here so a future refresh attempt with that same token
-- can be flagged as token reuse.
--
-- Threat model: stolen refresh token. Attacker uses the stolen token
-- BEFORE the legitimate client refreshes — succeeds, gets a new
-- token, the old session is deleted. The legitimate client's next
-- refresh attempt then fails with "Invalid or expired refresh token"
-- because the old session row is gone.
--
-- Without this table that failure is indistinguishable from a stale
-- bookmark, network retry, or post-logout reuse. With it, the failed
-- refresh path can SELECT this audit table and recognise that the
-- token in question was VALID until recently — i.e. someone else
-- already used it. The handler then revokes every session for the
-- affected user and emits a security alert.
--
-- Storage shape:
--   - lookup_hash (PK): SHA-256 of the original refresh token bytes,
--     identical to the user_sessions.refresh_token_lookup_hash that
--     was deleted on rotation. PK gives O(1) lookup on the failure path.
--   - user_id: who to alarm + revoke when reuse is detected.
--   - rotated_at: when the legitimate rotation happened (forensics).
--   - expires_at: when this audit row is no longer interesting.
--     Set to the original refresh token's expiry (7d) — beyond that
--     the token would have expired anyway, so reuse detection is moot.
--
-- The cleanup_expired_sessions background task should also DELETE
-- rows where expires_at < NOW() to bound table growth.

CREATE TABLE IF NOT EXISTS rotated_session_audit (
    lookup_hash TEXT PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rotated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS rotated_session_audit_user_id_idx
    ON rotated_session_audit (user_id);

CREATE INDEX IF NOT EXISTS rotated_session_audit_expires_at_idx
    ON rotated_session_audit (expires_at);
