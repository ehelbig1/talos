-- Workflow Executions: Track all workflow runs with full audit trail
-- This enables proper authorization, event replay, and execution history

-- Main executions table
CREATE TABLE workflow_executions (
    id UUID PRIMARY KEY,
    workflow_id UUID NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Execution events: Audit trail of all events during execution
CREATE TABLE execution_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id UUID NOT NULL REFERENCES workflow_executions(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL CHECK (event_type IN ('started', 'node_started', 'node_completed', 'node_failed', 'completed', 'failed')),
    node_id UUID,  -- NULL for workflow-level events
    status TEXT NOT NULL CHECK (status IN ('Running', 'Completed', 'Failed')),
    log_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Performance indexes
CREATE INDEX idx_executions_user_id ON workflow_executions(user_id);
CREATE INDEX idx_executions_workflow_id ON workflow_executions(workflow_id);
CREATE INDEX idx_executions_status ON workflow_executions(status);
CREATE INDEX idx_executions_started_at ON workflow_executions(started_at DESC);  -- For cleanup and recent queries
CREATE INDEX idx_executions_user_started ON workflow_executions(user_id, started_at DESC);  -- Composite for user history

CREATE INDEX idx_events_execution_id ON execution_events(execution_id);
CREATE INDEX idx_events_created_at ON execution_events(execution_id, created_at ASC);  -- For event replay in order

-- Update trigger for updated_at
CREATE OR REPLACE FUNCTION update_workflow_execution_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_workflow_execution_updated_at
    BEFORE UPDATE ON workflow_executions
    FOR EACH ROW
    EXECUTE FUNCTION update_workflow_execution_updated_at();

-- Comments for documentation
COMMENT ON TABLE workflow_executions IS 'Tracks all workflow executions for authorization, audit trail, and history';
COMMENT ON TABLE execution_events IS 'Audit trail of all events during workflow execution for replay and debugging';
COMMENT ON COLUMN workflow_executions.status IS 'Current execution status: pending (created), running (executing), completed (success), failed (error), cancelled (user stopped)';
COMMENT ON COLUMN execution_events.event_type IS 'Type of event: started, node_started, node_completed, node_failed, completed, failed';
