-- Memory read grants: a bearer token that reads ONE key of ONE actor's
-- memory, and nothing else.
--
-- Why. A coding session was meant to read one approved document held under
-- one memory key. The only credential it could be given was MCP access, which
-- reads any key of any actor the user owns, reads every execution's outputs,
-- writes memory and changes workflows. "May read only this" was an
-- instruction to the session, not a fact about what it held.
--
-- A grant is the narrow credential. The scope is this row: `actor_id` and the
-- exact `memory_key`, fixed when the owner mints it. Nothing a holder sends
-- can widen it; the request carries the token and no other input.
--
-- HASH-ONLY AT REST, like execution_approval_tokens and
-- workflow_action_tokens: the raw 256-bit token is shown once, when the grant
-- is made. A read of this table yields nothing usable.
--
-- BOUNDED. `expires_at` is always set (24 hours unless the owner asks for
-- more, seven days at most). `max_reads`, when set, is enforced in the same
-- conditional UPDATE that counts the read, so two reads at once cannot both
-- take the last one. `revoked_at` ends a grant early.
--
-- AUDITED. `read_count` and `last_read_at` are written by every read, so the
-- owner can see whether, and how often, a grant was used. The row is kept for
-- 30 days past its expiry for that reason; the mint sweeps older ones.
--
-- ON DELETE CASCADE from actors and users: a grant to memory that no longer
-- has an owner is dead.

CREATE TABLE IF NOT EXISTS memory_read_grants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    actor_id uuid NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    memory_key text NOT NULL CHECK (char_length(memory_key) BETWEEN 1 AND 500),
    token_hash text NOT NULL UNIQUE,
    label text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 160),
    max_reads integer CHECK (max_reads IS NULL OR max_reads BETWEEN 1 AND 1000),
    read_count integer NOT NULL DEFAULT 0,
    last_read_at timestamptz,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- "My grants", newest first (the list tool, and the per-user live-grant cap).
CREATE INDEX IF NOT EXISTS idx_memory_read_grants_owner
    ON memory_read_grants (user_id, created_at DESC);

-- The mint sweeps rows long past their expiry; keep that a range scan.
CREATE INDEX IF NOT EXISTS idx_memory_read_grants_expiry
    ON memory_read_grants (expires_at);

-- `talos_admin_read` (the platform-admin query tool's role) is given NO grant
-- on this table, and the table is in BLOCKED_TABLES_LIST: hashes of bearer
-- tokens, like the other token tables withheld on 2026-10-09.
