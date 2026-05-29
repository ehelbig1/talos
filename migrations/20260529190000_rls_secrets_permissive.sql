-- RFC 0004/0005 S2: enable RLS on `secrets` in PERMISSIVE-WHEN-UNSET mode.
--
-- secrets is the highest-sensitivity table, but also a HOT one: its
-- VALUE-decrypt path runs at execution time (worker→controller RPC,
-- vault:// resolution, LLM-key fetch) with no request context. So like
-- workflows it uses the permissive rollout — the user-facing METADATA
-- reads (GraphQL secret(key_path) → get_secret_metadata, secrets list →
-- list_secrets_paginated) are wired in this PR to a tenant-scoped tx and
-- get the RLS backstop ENFORCED; the decrypt path and write/admin paths
-- stay permissive (unchanged) until the S3 dual-role/unit-of-work work.
--
-- The policy mirrors get_secret_metadata's app-layer ownership filter:
-- secrets are owned via owner_user_id / created_by (NOT a `user_id`
-- column) or shared via org_id. NULLIF(...,'') handles the
-- pooled-connection GUC reset-to-'' case (talos-db RLS tests).
--
-- Safe in both role configs (non-superuser enforces wired reads;
-- superuser bypasses + the existing app-layer WHERE still scopes; boot
-- guard flags the latter).

ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE secrets FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS secrets_tenant_isolation ON secrets;
CREATE POLICY secrets_tenant_isolation ON secrets
USING (
    -- transition: un-wired path (decrypt / writes / admin / reset-to-'')
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    -- wired path → enforce the ownership/org match
    OR owner_user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR created_by = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR org_id = ANY(
         string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[]
       )
);
