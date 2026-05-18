-- integration_state: platform-level primitive for integration-scoped persistent state.
--
-- Purpose: let any integration (gcal, gmail, jira, ...) store data without
-- adding per-integration tables to the core schema. Rows are scoped by
-- (integration_name, user_id, key) and hold an opaque JSONB value. Four
-- generic indexed slots (str_1, str_2, ts_1, int_1) let integrations pick
-- what to index at write time without install-time DDL.
--
-- Security:
--   - All reads/writes MUST be scoped by (integration_name, user_id) at the
--     subscriber level; the WIT host function derives both from the executing
--     module's context so guest code can't forge them.
--   - 64 KiB value cap enforced at the RPC layer (mirrors actor_memory).
--   - 10k rows per (integration, user) enforced at the RPC layer to prevent
--     runaway integrations from filling disk.
--
-- Performance:
--   - Primary lookup is (integration_name, user_id, key) — covered by the
--     UNIQUE constraint's backing index.
--   - Each indexed slot is a partial index (WHERE slot IS NOT NULL) so empty
--     slots carry zero index cost.
--   - Expires-at index is partial on NON-NULL so the sweep-expired task is a
--     single index range scan.
--
-- Lifecycle: dropping an integration = DELETE WHERE integration_name = 'x'.
-- No table drop required, no migration to un-ship the integration.

CREATE TABLE IF NOT EXISTS integration_state (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_name  TEXT NOT NULL,
    user_id           UUID NOT NULL,
    key               TEXT NOT NULL,
    value             JSONB NOT NULL,
    expires_at        TIMESTAMPTZ,

    -- Generic indexed slots. Integrations document in their own codebase
    -- which slot maps to which logical field. Intentionally bounded to
    -- 4 columns total — if an integration needs >4 indexed fields, that's
    -- a signal the integration has outgrown this primitive and warrants
    -- its own table (e.g. a future gcal-specific table via a migration).
    idx_str_1         TEXT,
    idx_str_2         TEXT,
    idx_ts_1          TIMESTAMPTZ,
    idx_int_1         BIGINT,

    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT integration_state_key_unique
        UNIQUE (integration_name, user_id, key),
    CONSTRAINT integration_state_name_not_empty
        CHECK (length(integration_name) > 0 AND length(integration_name) <= 64),
    CONSTRAINT integration_state_key_not_empty
        CHECK (length(key) > 0 AND length(key) <= 256)
);

-- Partial indexes on each indexed slot. Always composite with
-- integration_name so queries within one integration are fully covered
-- without scanning rows from other integrations.
CREATE INDEX IF NOT EXISTS integration_state_str1_idx
    ON integration_state (integration_name, idx_str_1)
    WHERE idx_str_1 IS NOT NULL;

CREATE INDEX IF NOT EXISTS integration_state_str2_idx
    ON integration_state (integration_name, idx_str_2)
    WHERE idx_str_2 IS NOT NULL;

CREATE INDEX IF NOT EXISTS integration_state_ts1_idx
    ON integration_state (integration_name, idx_ts_1)
    WHERE idx_ts_1 IS NOT NULL;

CREATE INDEX IF NOT EXISTS integration_state_int1_idx
    ON integration_state (integration_name, idx_int_1)
    WHERE idx_int_1 IS NOT NULL;

-- Expiry sweep index. Partial so rows without TTL carry zero index cost.
CREATE INDEX IF NOT EXISTS integration_state_expires_idx
    ON integration_state (expires_at)
    WHERE expires_at IS NOT NULL;

-- Per-user listing index (rare-ish queries: "show all integration state for
-- this user"; used by account deletion + debugging tools).
CREATE INDEX IF NOT EXISTS integration_state_user_idx
    ON integration_state (user_id, integration_name);

-- Auto-update updated_at on any mutation so the row carries its own
-- last-touched timestamp without requiring every caller to set it.
CREATE OR REPLACE FUNCTION integration_state_touch_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS integration_state_touch_updated_at_trigger ON integration_state;
CREATE TRIGGER integration_state_touch_updated_at_trigger
    BEFORE UPDATE ON integration_state
    FOR EACH ROW
    EXECUTE FUNCTION integration_state_touch_updated_at();
