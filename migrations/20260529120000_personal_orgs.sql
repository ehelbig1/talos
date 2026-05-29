-- RFC 0004 (Tenant = Organization) — M1: personal-org foundation.
--
-- Under the org-as-tenant model every resource belongs to an
-- organization; "personal" (non-team) resources live in the user's
-- PERSONAL org. This migration makes every existing user have exactly
-- one personal org + owner membership, and adds the column that marks
-- one. Purely additive and idempotent — no resource table is touched
-- here (that is M2), and RLS is NOT enabled (M4, alongside the GUC).

-- 1. Mark personal organizations.
ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS is_personal BOOLEAN NOT NULL DEFAULT false;

-- 2. Invariant: at most one personal org per owner. Partial unique
--    index doubles as the backfill's idempotency guard and prevents a
--    future signup path from creating duplicates.
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_personal_org_per_owner
    ON organizations (owner_id)
    WHERE is_personal;

-- 3. Backfill: create a personal org for every user that lacks one.
--    Slug is derived from the user's UUID (globally unique, satisfies
--    the 3–100 lowercase-alnum-hyphen slug rule: `user-` + 32 hex = 37
--    chars). Set-based INSERT is safe here — there is no per-row failure
--    mode (gen_random_uuid + a constant-shaped slug from a unique id),
--    and ON CONFLICT covers a re-run.
INSERT INTO organizations (id, name, slug, owner_id, is_personal)
SELECT
    gen_random_uuid(),
    'Personal',
    'user-' || replace(u.id::text, '-', ''),
    u.id,
    true
FROM users u
WHERE NOT EXISTS (
    SELECT 1 FROM organizations o
    WHERE o.owner_id = u.id AND o.is_personal
)
ON CONFLICT (slug) DO NOTHING;

-- 4. Owner membership for each personal org (mirrors create_org's
--    owner-member insert). Idempotent via the existing UNIQUE(org_id,
--    user_id) on organization_members.
INSERT INTO organization_members (org_id, user_id, role, invited_by)
SELECT o.id, o.owner_id, 'owner', NULL
FROM organizations o
WHERE o.is_personal
  AND NOT EXISTS (
      SELECT 1 FROM organization_members m
      WHERE m.org_id = o.id AND m.user_id = o.owner_id
  )
ON CONFLICT (org_id, user_id) DO NOTHING;
