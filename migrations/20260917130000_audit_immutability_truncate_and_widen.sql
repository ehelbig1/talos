-- Package CG (2026-09-17): the immutability triggers did not bind TRUNCATE,
-- and four audit-shaped tables carried no trigger at all.
--
-- `prevent_audit_modification` was installed BEFORE DELETE OR UPDATE ... FOR
-- EACH ROW on three tables. TRUNCATE fires NO row-level trigger, so it emptied
-- an audit table with nothing raised — reproduced against this exact trigger
-- shape on a throwaway database: DELETE raised 42501, TRUNCATE left 0 rows. A
-- BEFORE TRUNCATE ... FOR EACH STATEMENT trigger refuses it, and it binds the
-- table OWNER too (also reproduced).
--
-- Reachability, measured before writing this: TRUNCATE is DDL, so both sandbox
-- fences refuse it (the worker validator's is_ddl and the controller's
-- Query/Insert/Update/Delete/Merge classifier), and `talos_app` — the role the
-- RLS path runs as — holds no TRUNCATE grant. It is reachable only from the
-- owner/pool role: an operator's psql, or anything holding that credential.
--
-- STATED LIMIT, not a claim this migration can make go away: a SUPERUSER
-- bypasses every trigger with `SET session_replication_role = replica`
-- (reproduced), and any owner can DROP or DISABLE a trigger. This is
-- defence-in-depth against a stray or scripted TRUNCATE, not a bound on a
-- superuser — docs/THREAT_MODEL.md has said the triggers do not bind one
-- since before this migration, and still does.
--
-- The four tables gaining full immutability were audit-shaped with no trigger:
-- schema_audit_log (2 280 rows, the DDL event trigger's record and SOC 2 CC8.1
-- evidence), oauth_audit_log (1), gmail_integration_audit_log and
-- slack_integration_audit_log (0 each).
--
-- Their incoming FKs are dropped in the same statement batch, and that is
-- REQUIRED rather than tidy-up: an ON DELETE CASCADE / SET NULL into a table
-- whose trigger refuses DELETE/UPDATE makes the PARENT row undeletable —
-- deleting a user would have failed on oauth/gmail/slack, and deleting a Gmail
-- or Slack integration would have failed too. That is regression #264/#266
-- exactly, which is why lint check 47 forbids the combination; its table list
-- grows with this migration. An audit row keeps its parent id as a plain
-- historical reference, as `secret_audit_log` and `admin_event_log` already do
-- (neither has ever had an FK to users), and outlives the parent by design.

-- 1. The three tables that already refuse UPDATE and DELETE now refuse TRUNCATE.
CREATE OR REPLACE TRIGGER trg_secret_audit_log_immutable_truncate
    BEFORE TRUNCATE ON secret_audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION prevent_audit_modification();
CREATE OR REPLACE TRIGGER trg_auth_audit_log_immutable_truncate
    BEFORE TRUNCATE ON auth_audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION prevent_audit_modification();
CREATE OR REPLACE TRIGGER trg_admin_event_log_immutable_truncate
    BEFORE TRUNCATE ON admin_event_log
    FOR EACH STATEMENT EXECUTE FUNCTION prevent_audit_modification();

-- 2. The four audit-shaped tables that carried no trigger: drop the FKs that
--    would abort a parent delete, then make them append-only on all three
--    operations.
ALTER TABLE oauth_audit_log DROP CONSTRAINT IF EXISTS oauth_audit_log_user_id_fkey;
ALTER TABLE gmail_integration_audit_log
    DROP CONSTRAINT IF EXISTS gmail_integration_audit_log_user_id_fkey;
ALTER TABLE gmail_integration_audit_log
    DROP CONSTRAINT IF EXISTS gmail_integration_audit_log_integration_id_fkey;
ALTER TABLE slack_integration_audit_log
    DROP CONSTRAINT IF EXISTS slack_integration_audit_log_user_id_fkey;
ALTER TABLE slack_integration_audit_log
    DROP CONSTRAINT IF EXISTS slack_integration_audit_log_integration_id_fkey;

CREATE OR REPLACE TRIGGER trg_schema_audit_log_immutable
    BEFORE DELETE OR UPDATE ON schema_audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();
CREATE OR REPLACE TRIGGER trg_schema_audit_log_immutable_truncate
    BEFORE TRUNCATE ON schema_audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION prevent_audit_modification();

CREATE OR REPLACE TRIGGER trg_oauth_audit_log_immutable
    BEFORE DELETE OR UPDATE ON oauth_audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();
CREATE OR REPLACE TRIGGER trg_oauth_audit_log_immutable_truncate
    BEFORE TRUNCATE ON oauth_audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION prevent_audit_modification();

CREATE OR REPLACE TRIGGER trg_gmail_integration_audit_log_immutable
    BEFORE DELETE OR UPDATE ON gmail_integration_audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();
CREATE OR REPLACE TRIGGER trg_gmail_integration_audit_log_immutable_truncate
    BEFORE TRUNCATE ON gmail_integration_audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION prevent_audit_modification();

CREATE OR REPLACE TRIGGER trg_slack_integration_audit_log_immutable
    BEFORE DELETE OR UPDATE ON slack_integration_audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();
CREATE OR REPLACE TRIGGER trg_slack_integration_audit_log_immutable_truncate
    BEFORE TRUNCATE ON slack_integration_audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION prevent_audit_modification();
