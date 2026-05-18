-- Optimize Execution Logging: Fix O(N²) performance issue in log rate limiting
-- This migration adds a log counter to avoid COUNT(*) queries on every log insert
--
-- Performance improvement: O(N²) → O(1)
-- Before: 1000 logs = ~500,000 row scans
-- After:  1000 logs = 1,000 counter increments

-- Add log counter column to node_executions
ALTER TABLE node_executions ADD COLUMN IF NOT EXISTS log_count INTEGER DEFAULT 0;

-- Create index for performance (optional, but helpful for monitoring queries)
CREATE INDEX IF NOT EXISTS idx_node_executions_log_count ON node_executions(log_count);

-- Trigger function to increment counter and enforce limit
CREATE OR REPLACE FUNCTION increment_and_check_log_count()
RETURNS TRIGGER AS $$
DECLARE
    current_count INTEGER;
BEGIN
    -- Increment the counter atomically
    UPDATE node_executions
    SET log_count = log_count + 1
    WHERE id = NEW.execution_id
    RETURNING log_count INTO current_count;

    -- Check if limit exceeded (1000 logs per execution)
    IF current_count > 1000 THEN
        RAISE EXCEPTION 'Execution % exceeded maximum log entries (1000)', NEW.execution_id
            USING HINT = 'Log entry dropped to prevent resource exhaustion',
                  ERRCODE = 'check_violation';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger to node_execution_logs
DROP TRIGGER IF EXISTS log_count_enforce_limit ON node_execution_logs;
CREATE TRIGGER log_count_enforce_limit
    BEFORE INSERT ON node_execution_logs
    FOR EACH ROW
    EXECUTE FUNCTION increment_and_check_log_count();

-- Backfill existing log counts (for existing data)
-- This is safe to run even if log_count is already populated
UPDATE node_executions
SET log_count = (
    SELECT COUNT(*)
    FROM node_execution_logs
    WHERE node_execution_logs.execution_id = node_executions.id
)
WHERE log_count = 0;

-- Add comments
COMMENT ON COLUMN node_executions.log_count IS 'Number of log entries for this execution (auto-incremented by trigger, max 1000)';
COMMENT ON FUNCTION increment_and_check_log_count() IS 'Increments log counter and enforces 1000 log limit per execution';

-- Verify the migration worked
DO $$
DECLARE
    test_execution_id UUID;
    test_count INTEGER;
BEGIN
    -- Check that log_count column exists
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'node_executions' AND column_name = 'log_count'
    ) THEN
        RAISE EXCEPTION 'Migration failed: log_count column not created';
    END IF;

    -- Check that trigger exists
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.triggers
        WHERE trigger_name = 'log_count_enforce_limit'
    ) THEN
        RAISE EXCEPTION 'Migration failed: trigger not created';
    END IF;

    RAISE NOTICE 'Migration 013 completed successfully: log_count optimization applied';
END $$;
