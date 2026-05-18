-- Migration 015: Terminology clarification — rename tables to match their actual semantics
--
-- Problem: Three naming issues existed in the schema:
--  1. "node_executions" implied workflow-canvas-node execution, but these are standalone
--     module runs triggered by webhooks / manual / schedule.
--  2. "webhook_listeners" implied passive observation, but these are active trigger configs.
--  3. The request-log column "listener_id" referenced the old listener concept.
--
-- Renames applied:
--   node_executions       → module_executions
--   node_execution_logs   → module_execution_logs
--   webhook_listeners     → webhook_triggers
--   webhook_request_log.listener_id → trigger_id

-- ============================================================
-- 1. node_executions → module_executions
-- ============================================================
ALTER TABLE node_executions RENAME TO module_executions;
ALTER TABLE node_execution_logs RENAME TO module_execution_logs;

-- Update foreign key column name in module_execution_logs
-- (execution_id references module_executions.id — column stays "execution_id", no rename needed)

-- Rename indexes on module_executions
ALTER INDEX idx_node_executions_module_id         RENAME TO idx_module_executions_module_id;
ALTER INDEX idx_node_executions_user_id           RENAME TO idx_module_executions_user_id;
ALTER INDEX idx_node_executions_status            RENAME TO idx_module_executions_status;
ALTER INDEX idx_node_executions_started_at        RENAME TO idx_module_executions_started_at;
ALTER INDEX idx_node_executions_user_started      RENAME TO idx_module_executions_user_started;
ALTER INDEX idx_node_executions_trigger           RENAME TO idx_module_executions_trigger;
ALTER INDEX idx_node_executions_module_recent     RENAME TO idx_module_executions_module_recent;
ALTER INDEX idx_node_executions_log_count         RENAME TO idx_module_executions_log_count;

-- Rename indexes on module_execution_logs
ALTER INDEX idx_node_execution_logs_execution_id  RENAME TO idx_module_execution_logs_execution_id;
ALTER INDEX idx_node_execution_logs_created_at    RENAME TO idx_module_execution_logs_created_at;
ALTER INDEX idx_node_execution_logs_level         RENAME TO idx_module_execution_logs_level;

-- Drop old triggers (now attached to renamed table)
DROP TRIGGER IF EXISTS trigger_node_execution_updated_at ON module_executions;
DROP TRIGGER IF EXISTS trigger_node_execution_duration   ON module_executions;
DROP TRIGGER IF EXISTS log_count_enforce_limit           ON module_execution_logs;

-- Drop old functions
DROP FUNCTION IF EXISTS update_node_execution_updated_at();
DROP FUNCTION IF EXISTS calculate_node_execution_duration();
DROP FUNCTION IF EXISTS increment_and_check_log_count();

-- Recreate updated_at function + trigger
CREATE OR REPLACE FUNCTION update_module_execution_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_module_execution_updated_at
    BEFORE UPDATE ON module_executions
    FOR EACH ROW
    EXECUTE FUNCTION update_module_execution_updated_at();

-- Recreate duration function + trigger
CREATE OR REPLACE FUNCTION calculate_module_execution_duration()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.completed_at IS NOT NULL AND OLD.completed_at IS NULL THEN
        NEW.duration_ms := EXTRACT(EPOCH FROM (NEW.completed_at - NEW.started_at)) * 1000;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_module_execution_duration
    BEFORE UPDATE ON module_executions
    FOR EACH ROW
    EXECUTE FUNCTION calculate_module_execution_duration();

-- Recreate log-count enforcement function + trigger
CREATE OR REPLACE FUNCTION increment_and_check_module_log_count()
RETURNS TRIGGER AS $$
DECLARE
    current_count INTEGER;
BEGIN
    UPDATE module_executions
    SET log_count = log_count + 1
    WHERE id = NEW.execution_id
    RETURNING log_count INTO current_count;

    IF current_count > 1000 THEN
        RAISE EXCEPTION 'Execution % exceeded maximum log entries (1000)', NEW.execution_id
            USING HINT = 'Log entry dropped to prevent resource exhaustion',
                  ERRCODE = 'check_violation';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER log_count_enforce_limit
    BEFORE INSERT ON module_execution_logs
    FOR EACH ROW
    EXECUTE FUNCTION increment_and_check_module_log_count();

-- Update table comments
COMMENT ON TABLE module_executions IS 'Tracks standalone module executions (webhook-triggered, manual runs) with full audit trail';
COMMENT ON TABLE module_execution_logs IS 'Detailed log messages from module executions for debugging and monitoring';

-- ============================================================
-- 2. webhook_listeners → webhook_triggers
-- ============================================================
ALTER TABLE webhook_listeners RENAME TO webhook_triggers;

-- Rename indexes on webhook_triggers
ALTER INDEX idx_webhook_listeners_module_id       RENAME TO idx_webhook_triggers_module_id;
ALTER INDEX idx_webhook_listeners_enabled         RENAME TO idx_webhook_triggers_enabled;
ALTER INDEX idx_webhook_listeners_user_id         RENAME TO idx_webhook_triggers_user_id;
ALTER INDEX idx_webhook_listeners_enabled_user    RENAME TO idx_webhook_triggers_enabled_user;
ALTER INDEX idx_webhook_listeners_last_triggered  RENAME TO idx_webhook_triggers_last_triggered;

-- Rename the foreign-key column in webhook_request_log
ALTER TABLE webhook_request_log RENAME COLUMN listener_id TO trigger_id;

-- Update table comment
COMMENT ON TABLE webhook_triggers IS 'Active HTTP trigger configurations: each row maps an inbound webhook URL to a WASM module execution';

-- ============================================================
-- Self-validate
-- ============================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'module_executions'
    ) THEN
        RAISE EXCEPTION 'Migration 015 failed: module_executions table not found';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'module_execution_logs'
    ) THEN
        RAISE EXCEPTION 'Migration 015 failed: module_execution_logs table not found';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'webhook_triggers'
    ) THEN
        RAISE EXCEPTION 'Migration 015 failed: webhook_triggers table not found';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'webhook_request_log' AND column_name = 'trigger_id'
    ) THEN
        RAISE EXCEPTION 'Migration 015 failed: webhook_request_log.trigger_id column not found';
    END IF;

    RAISE NOTICE 'Migration 015 completed successfully: node_executions→module_executions, webhook_listeners→webhook_triggers';
END $$;
