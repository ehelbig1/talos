-- Audit table for schema changes (DDL statements)
CREATE TABLE IF NOT EXISTS schema_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    schema_name TEXT,
    object_type TEXT,
    object_name TEXT,
    command_tag TEXT,
    client_addr INET,
    client_port INTEGER,
    db_user TEXT,
    application_name TEXT,
    query TEXT
);

-- Note: In Postgres, capturing DDL events usually requires event triggers.
-- Here we create an event trigger to capture any schema changes.
-- Event triggers require superuser privileges, so we check if we can create it.
DO $$ 
BEGIN
    -- Only create if the event trigger doesn't exist
    IF NOT EXISTS (SELECT 1 FROM pg_event_trigger WHERE evtname = 'log_schema_changes') THEN
        CREATE OR REPLACE FUNCTION audit_schema_change()
        RETURNS event_trigger AS $body$
        BEGIN
            INSERT INTO schema_audit_log (
                schema_name,
                object_type,
                object_name,
                command_tag,
                client_addr,
                client_port,
                db_user,
                application_name,
                query
            ) VALUES (
                current_schema(),
                tg_tag,
                '', -- object_name not easily available in all trigger contexts without pg_stat_activity
                tg_tag,
                inet_client_addr(),
                inet_client_port(),
                current_user,
                current_setting('application_name'),
                current_query()
            );
        EXCEPTION WHEN OTHERS THEN
            -- Silent failure to not block the DDL operation
        END;
        $body$ LANGUAGE plpgsql;

        -- Create the event trigger
        CREATE EVENT TRIGGER log_schema_changes
        ON ddl_command_end
        EXECUTE FUNCTION audit_schema_change();
    END IF;
END $$;
