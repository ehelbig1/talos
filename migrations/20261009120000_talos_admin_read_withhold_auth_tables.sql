-- Withhold six authentication-adjacent tables from `talos_admin_read`, the
-- role the platform-admin `query_paginated` tool runs as
-- (2026-10-09; docs/engineering-log/packages/2026-10-09-query-paginated-withhold-auth-tables.md).
--
-- 20261008200000_talos_admin_read_role.sql granted SELECT on every public
-- table the tool could read at the time. These six are now withheld: each is
-- added to BLOCKED_TABLES_LIST (talos-admin-query-gate) in the same change, so
-- the gate refuses a statement naming one, and here the role loses its grant,
-- so Postgres refuses one the gate did not see.
--
-- * auth_audit_log              — every user's sign-in history: emails, IP
--                                 addresses, user agents.
-- * integration_credentials     — where every user's OAuth tokens sit in the
--                                 vault, by provider and account.
-- * execution_approval_tokens,
--   ops_alert_correction_tokens,
--   workflow_action_tokens,
--   worker_provisioning_tokens  — hashes of bearer tokens; nothing an admin
--                                 query needs, and no reason to hand them out.
--
-- A database where the role does not exist (a managed Postgres where the
-- earlier migration could not create it) has nothing to revoke. On one where
-- an operator ran the earlier migration's GRANT statements by hand, these
-- REVOKEs are the statements to run after them.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'talos_admin_read') THEN
        RETURN;
    END IF;
    REVOKE ALL ON TABLE
        public.auth_audit_log,
        public.integration_credentials,
        public.execution_approval_tokens,
        public.ops_alert_correction_tokens,
        public.workflow_action_tokens,
        public.worker_provisioning_tokens
    FROM talos_admin_read;
END$$;
