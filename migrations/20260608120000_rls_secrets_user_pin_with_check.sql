-- RFC 0006 Option B — pin `secrets` WRITES to the acting user, not just the org.
--
-- Migration 20260602120000 gave `secrets_tenant_isolation` an ORG-based
-- WITH CHECK (a write must land in the active org — `app.current_org_id`).
-- For an enterprise posture we ALSO require the row to be OWNED by the acting
-- user (`owner_user_id = app.current_user_id`), so that within a single org one
-- user cannot forge / overwrite a secret owned by another user. `secrets`
-- carries per-user DEK lineage, so it is the one org-scoped table where per-user
-- write ownership is a true security invariant. `workflows` / `actors` stay
-- org-pinned only (collaborative, RBAC-governed — user-pinning would break
-- legitimate intra-org collaboration, e.g. an org admin editing a member's
-- workflow). See docs/rfcs/0006-org-scoped-write-isolation-pins-org-not-user.md.
--
-- ROLLOUT-SAFE BY CONSTRUCTION (same shape as 20260602120000): every clause is
-- "<GUC> unset → permit", so this can only RESTRICT a write that runs with the
-- GUC set. The wired write path is `begin_org_scoped`, which now sets
-- `app.current_user_id` alongside `app.current_org_id`
-- (talos-tenancy::OrgScope::set_local_org_sql). The decrypt / engine /
-- not-yet-wired write paths set no user GUC and stay permitted. The
-- `owner_user_id IS NULL → permit` clause keeps org-shared (ownerless) secrets
-- writable, mirroring the org pin's `org_id IS NULL` clause. Net effect is
-- latent until RLS enforcement (`TALOS_RLS_SET_ROLE`) is enabled AND secret
-- writes are wired through `begin_org_scoped` — exactly the staged S3 rollout.
--
-- ALTER POLICY redefines the WITH CHECK wholesale, so the org clause is
-- re-stated here. Idempotent (re-running redefines to the same predicate).

ALTER POLICY secrets_tenant_isolation ON secrets
WITH CHECK (
    -- Org pin (re-stated from 20260602120000): write lands in the active org.
    (
        NULLIF(current_setting('app.current_org_id', true), '') IS NULL
        OR org_id IS NULL
        OR org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
    )
    -- Per-user owner pin (RFC 0006 Option B): the new row must be owned by the
    -- acting user. `owner_user_id` is the canonical owner (backfilled from
    -- `created_by` in 20260410100005).
    AND (
        NULLIF(current_setting('app.current_user_id', true), '') IS NULL
        OR owner_user_id IS NULL
        OR owner_user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    )
);
