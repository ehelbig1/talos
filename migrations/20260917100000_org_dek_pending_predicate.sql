-- Package CE (2026-09-17): one predicate for "this row is not yet under its
-- organization's ACTIVE root DEK".
--
-- The four per-org re-encrypt sweeps (secrets, actor_memory, execution
-- outputs, module payloads) and `dek_migration_status` selected
-- `format <> 4`: a row still on the global DEK. A v4 row under an org DEK that
-- has since been ROTATED (inactive) was deliberately skipped, so a rotated key
-- stayed load-bearing for every row it had ever encrypted and the status read
-- 0 pending over those rows. With org-DEK rotation now reachable
-- (`rotateOrgDek`), "pending" means: the row's key is not the org's ACTIVE
-- DEK. That covers every non-v4 row too, without a format clause: v0–v3 rows
-- are sealed under the GLOBAL DEK (`org_id IS NULL`), which never matches, and
-- `encrypt_value_aad_v4_org` is the only writer of an org DEK's id and always
-- writes format 4. Five statements ask the question, so it has one home here rather than five inline
-- copies that could drift.
--
-- `encryption_keys` carries no RLS; the sweeps and the status read run on the
-- controller's own pool. STABLE + a single SQL statement, so the planner
-- inlines it; each call is one primary-key probe of a table holding one row
-- per DEK generation.

CREATE OR REPLACE FUNCTION talos_org_dek_pending(
    p_key_id uuid,
    p_org_id uuid
) RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
    SELECT NOT EXISTS (
            SELECT 1
              FROM encryption_keys k
             WHERE k.id = p_key_id
               AND k.org_id = p_org_id
               AND k.active
        )
$$;

COMMENT ON FUNCTION talos_org_dek_pending(uuid, uuid) IS
    'True when an encrypted row belonging to p_org_id is not under that org''s active root DEK: still on the global DEK, or under a rotated or foreign org DEK. The per-org re-encrypt sweeps and dek_migration_status select on it.';
