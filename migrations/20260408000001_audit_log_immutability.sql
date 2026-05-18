-- Audit log immutability: prevent UPDATE and DELETE on all audit tables.
--
-- Uses trigger-based enforcement so the protection applies regardless of DB role
-- (including the application user, DBA connections, and SQL injection vectors).
-- The trigger fires BEFORE UPDATE OR DELETE and raises an exception with
-- SQLSTATE 42501 (insufficient_privilege) so callers receive a clear error.
--
-- Tables protected:
--   audit_events      — primary audit ledger (security_and_audit_improvements)
--   auth_audit_log    — login/logout events (users_and_auth)
--   secret_audit_log  — secret access events (initial_schema)
--   admin_event_log   — admin action events (admin_event_log migration)
--
-- Note: The trigger does NOT block the initial INSERT (append-only is the intent).
-- Superusers can still DROP the trigger if needed for emergency data correction,
-- but that action itself is logged by PostgreSQL's statement audit log.
-- For additional hardening, enable postgresql.conf audit_log or pgaudit extension.

CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        'Audit records are immutable — % on % is not permitted. '
        'Audit tables are append-only by security policy.',
        TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

-- audit_events
CREATE TRIGGER trg_audit_events_immutable
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_modification();

-- auth_audit_log
CREATE TRIGGER trg_auth_audit_log_immutable
    BEFORE UPDATE OR DELETE ON auth_audit_log
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_modification();

-- secret_audit_log
CREATE TRIGGER trg_secret_audit_log_immutable
    BEFORE UPDATE OR DELETE ON secret_audit_log
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_modification();

-- admin_event_log
CREATE TRIGGER trg_admin_event_log_immutable
    BEFORE UPDATE OR DELETE ON admin_event_log
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_modification();
