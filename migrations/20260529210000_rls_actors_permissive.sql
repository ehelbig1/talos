-- RFC 0004/0005 S2: enable RLS on `actors` in PERMISSIVE-WHEN-UNSET mode.
--
-- actors is a definition table owned by user_id (and auto-stamped with
-- org_id from the owner's personal org — migration 20260529140000), but
-- it is read by cross-cutting internal subsystems WITHOUT a request user
-- context: the engine's `apply_actor_to_engine(actor_id)` (stamps the
-- LLM-tier ceiling), the scheduler / module-bound dispatch, clone,
-- handoff, suggest_actor_for_task. So like workflows / secrets /
-- workflow_executions it uses the permissive rollout: the user-facing
-- GraphQL reads (`actors` list, `actor` detail) are wired in this PR to a
-- tenant-scoped tx and get the RLS backstop ENFORCED; the internal
-- readers stay permissive until the S3 dual-role work.
--
-- Policy: actors are PERSONAL — every user-facing read filters
-- `a.user_id = $me` only (no org-shared read path exists). The policy
-- mirrors that via the user_id clause; the org clause is kept for
-- uniformity with the other tables' policies and is effectively a no-op
-- here (an actor's org_id is its owner's PERSONAL org, which is only ever
-- in that one owner's accessible-org set — never another user's — so it
-- can only match the owner anyway). NULLIF(...,'') handles the
-- pooled-connection GUC reset-to-'' case.
--
-- Safe in both role configs (non-superuser enforces the wired reads;
-- superuser bypasses + the existing app-layer WHERE still scopes; boot
-- guard flags the latter).

ALTER TABLE actors ENABLE ROW LEVEL SECURITY;
ALTER TABLE actors FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS actors_tenant_isolation ON actors;
CREATE POLICY actors_tenant_isolation ON actors
USING (
    -- transition: un-wired path (engine / scheduler / clone / reset-to-'')
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    -- wired path → enforce the owner match
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    -- uniformity (no-op for personal actors; see header)
    OR org_id = ANY(
         string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[]
       )
);
