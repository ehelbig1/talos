-- Node Executions: Track standalone node executions (webhook-triggered, manual runs, etc.)
-- This enables execution history and logs for nodes that run outside of workflows
--
-- Design decisions:
-- 1. Separate from workflow_executions since these are standalone (no workflow context)
-- 2. Links to module_id (the WASM node) instead of workflow_id
-- 3. Stores input/output for debugging and audit trail
-- 4. Includes trigger metadata (webhook, manual, scheduled, etc.)

-- Main node executions table
CREATE TABLE IF NOT EXISTS node_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    module_id UUID NOT NULL REFERENCES wasm_modules(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Execution status
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed', 'timeout')),

    -- Execution context
    trigger_type TEXT NOT NULL CHECK (trigger_type IN ('webhook', 'manual', 'scheduled', 'test')),
    trigger_metadata JSONB,  -- Stores webhook event details, schedule info, etc.

    -- Input/Output
    input_data JSONB,  -- The input provided to the WASM module
    output_data JSONB,  -- The output returned by the WASM module (NULL if failed)

    -- Timing
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    duration_ms INTEGER,  -- Execution duration in milliseconds

    -- Error tracking
    error_message TEXT,
    error_type TEXT,  -- 'timeout', 'panic', 'validation', 'runtime', etc.

    -- Resource usage
    fuel_consumed BIGINT,  -- WASM fuel (CPU) consumed
    memory_used_mb INTEGER,  -- Peak memory usage

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Node execution logs: Detailed log messages from execution
-- Separate table to avoid bloating node_executions with large log strings
CREATE TABLE IF NOT EXISTS node_execution_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id UUID NOT NULL REFERENCES node_executions(id) ON DELETE CASCADE,

    -- Log details
    level TEXT NOT NULL CHECK (level IN ('DEBUG', 'INFO', 'WARN', 'ERROR')),
    message TEXT NOT NULL,

    -- Contextual metadata
    metadata JSONB,  -- Structured log data (event details, filter results, etc.)

    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Performance indexes
CREATE INDEX idx_node_executions_module_id ON node_executions(module_id);
CREATE INDEX idx_node_executions_user_id ON node_executions(user_id);
CREATE INDEX idx_node_executions_status ON node_executions(status);
CREATE INDEX idx_node_executions_started_at ON node_executions(started_at DESC);
CREATE INDEX idx_node_executions_user_started ON node_executions(user_id, started_at DESC);
CREATE INDEX idx_node_executions_trigger ON node_executions(trigger_type, started_at DESC);

-- Composite index for webhook queries (module + recent)
CREATE INDEX idx_node_executions_module_recent ON node_executions(module_id, started_at DESC);

-- Logs indexes
CREATE INDEX idx_node_execution_logs_execution_id ON node_execution_logs(execution_id);
CREATE INDEX idx_node_execution_logs_created_at ON node_execution_logs(execution_id, created_at ASC);
CREATE INDEX idx_node_execution_logs_level ON node_execution_logs(execution_id, level);

-- Update trigger for updated_at
CREATE OR REPLACE FUNCTION update_node_execution_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_node_execution_updated_at
    BEFORE UPDATE ON node_executions
    FOR EACH ROW
    EXECUTE FUNCTION update_node_execution_updated_at();

-- Auto-calculate duration on completion
CREATE OR REPLACE FUNCTION calculate_node_execution_duration()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.completed_at IS NOT NULL AND OLD.completed_at IS NULL THEN
        NEW.duration_ms := EXTRACT(EPOCH FROM (NEW.completed_at - NEW.started_at)) * 1000;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_node_execution_duration
    BEFORE UPDATE ON node_executions
    FOR EACH ROW
    EXECUTE FUNCTION calculate_node_execution_duration();

-- Comments for documentation
COMMENT ON TABLE node_executions IS 'Tracks standalone node executions (webhook-triggered, manual runs) with full audit trail';
COMMENT ON TABLE node_execution_logs IS 'Detailed log messages from node executions for debugging and monitoring';

COMMENT ON COLUMN node_executions.status IS 'Execution status: pending (queued), running (executing), completed (success), failed (error), timeout (exceeded time limit)';
COMMENT ON COLUMN node_executions.trigger_type IS 'What triggered this execution: webhook (Google Calendar, etc.), manual (user-initiated), scheduled (cron), test (development)';
COMMENT ON COLUMN node_executions.trigger_metadata IS 'Structured metadata about the trigger (webhook event ID, schedule name, etc.)';
COMMENT ON COLUMN node_executions.input_data IS 'Input data provided to the WASM module (e.g., calendar event JSON)';
COMMENT ON COLUMN node_executions.output_data IS 'Output data returned by the WASM module (NULL if execution failed)';
COMMENT ON COLUMN node_executions.duration_ms IS 'Total execution time in milliseconds (auto-calculated on completion)';
COMMENT ON COLUMN node_executions.fuel_consumed IS 'WASM fuel (CPU instructions) consumed during execution';

COMMENT ON COLUMN node_execution_logs.level IS 'Log level: DEBUG (verbose), INFO (normal), WARN (warning), ERROR (error)';
COMMENT ON COLUMN node_execution_logs.metadata IS 'Structured log metadata (filter results, event details, performance metrics)';
