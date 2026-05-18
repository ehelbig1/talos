-- M T6-1: distinguish "platform admin" (cross-tenant operator) from
-- "any org admin". Pre-fix, `is_platform_admin` was implemented as
-- `EXISTS(SELECT 1 FROM organization_members WHERE user_id = $1 AND
-- role IN ('owner','admin'))`, which conflated:
--   1. an admin of org-A subscribing to platform-wide DLQ events and
--      receiving raw payloads from org-B's webhooks (cross-tenant
--      data leak under realistic multi-tenant deploys), with
--   2. a platform operator who legitimately needs cross-tenant
--      visibility (capability-ceiling grant/revoke, marketplace
--      publish, master-key rotation, etc.).
--
-- This migration adds an explicit `users.is_platform_admin` boolean
-- so operators can be designated independently of any organisation
-- role. The backfill seeds existing org owner/admin users into the
-- new role so single-tenant deploys (the current Aegix shape)
-- preserve their behaviour unchanged — the founder/primary user
-- continues to pass `require_platform_admin` checks. Multi-tenant
-- operators must explicitly clear / re-set this flag for org
-- owners/admins who should NOT have cross-tenant powers.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS is_platform_admin BOOLEAN NOT NULL DEFAULT FALSE;

-- Backfill: any user who currently holds owner/admin role in any
-- organisation gets the platform_admin flag, preserving today's
-- "any org admin = platform admin" behaviour for continuity. Run
-- inside a transaction (sqlx wraps each migration anyway, but the
-- WITH-CTE single-statement form makes the intent explicit).
UPDATE users
SET is_platform_admin = TRUE
WHERE id IN (
    SELECT DISTINCT user_id
    FROM organization_members
    WHERE role IN ('owner', 'admin')
);

-- Helper index: dlq_updates and other admin-gated subscriptions hit
-- this column on every connection; a partial index on TRUE keeps
-- the lookup O(log N_admins) without bloating the users table.
CREATE INDEX IF NOT EXISTS idx_users_is_platform_admin
    ON users (id)
    WHERE is_platform_admin = TRUE;
