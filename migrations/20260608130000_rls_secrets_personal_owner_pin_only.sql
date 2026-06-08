-- RFC 0006 decision (b), 2026-06-08 — scope the secrets owner pin to PERSONAL
-- secrets only.
--
-- Migration 20260608120000 (Option B) added an `owner_user_id =
-- app.current_user_id` pin to EVERY secret write. Implementing the S3 write
-- wiring surfaced that `update_secret` / `delete_secret` deliberately let any
-- ORG MEMBER (not just the owner) manage an org-shared secret — the same
-- collaborative model already chosen for `workflows` / `actors`. A blanket owner
-- pin conflicts with that (it would reject a non-owner member's write once
-- enforcement is on) and would orphan org-shared secrets when their creator
-- offboards.
--
-- Resolution (b): the owner pin applies ONLY to PERSONAL secrets
-- (`org_id IS NULL`). ORG-SHARED secrets (`org_id IS NOT NULL`) are governed by
-- the org pin + membership/RBAC, exactly like workflows/actors. So:
--   * personal secret  → org pin permits (NULL) + owner pin ENFORCES
--   * org-shared secret → org pin ENFORCES (active org) + owner pin SKIPPED
--
-- Still rollout-safe (every clause is `<GUC> unset → permit`); supersedes the
-- 20260608120000 WITH CHECK (ALTER POLICY redefines wholesale). Idempotent.

ALTER POLICY secrets_tenant_isolation ON secrets
WITH CHECK (
    -- Org pin: a write lands in the active org (or is org-less / unwired).
    (
        NULLIF(current_setting('app.current_org_id', true), '') IS NULL
        OR org_id IS NULL
        OR org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
    )
    -- Owner pin — PERSONAL secrets only. Org-shared rows (org_id IS NOT NULL)
    -- short-circuit to TRUE here, leaving them governed by the org pin above.
    AND (
        org_id IS NOT NULL
        OR NULLIF(current_setting('app.current_user_id', true), '') IS NULL
        OR owner_user_id IS NULL
        OR owner_user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    )
);
