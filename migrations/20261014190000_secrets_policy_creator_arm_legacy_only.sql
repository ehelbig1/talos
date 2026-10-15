-- The secrets row-security policy credits a secret's CREATOR only on a legacy
-- row that has no owner (security review 2026-10-14, C-2).
--
-- The policy's USING admitted `created_by = current_user_id` on every row, so
-- it agreed with the hole the app layer had: a member who left an org kept
-- the org secrets they had created, because `created_by` never changes. The
-- app layer now decides through one rule (`talos_secrets_manager`
-- `may_manage_secret!` / `may_dispatch_read_secret!`); this policy is its
-- backstop and must not be the looser of the two on the creator arm.
--
-- Unchanged, deliberately: the owner arm still admits an org row's owner and
-- the org arm reads `app.current_org_ids`. The by-id statements open a session
-- scoped to the user alone (no org GUC), so dropping the owner arm for org
-- rows here would refuse an owner's rotate of a secret in their own personal
-- org. The app rule refuses a departed member; this backstop does not yet.
--
-- Measured on the reference deployment: no row has `owner_user_id IS NULL`,
-- and no row's creator differs from its owner, so no row changes visibility.

ALTER POLICY secrets_tenant_isolation ON secrets
USING (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR owner_user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR (
        owner_user_id IS NULL
        AND created_by = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    )
    OR org_id = ANY(
         string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[]
       )
);
