-- Migration: Add performance indexes for high-frequency queries
-- These indexes improve query performance for execution tracking and lookups

-- ============================================================================
-- Execution Tracking Indexes
-- ============================================================================

-- Index for module_executions cleanup and listing by user/status
CREATE INDEX IF NOT EXISTS idx_module_executions_user_status_created 
ON module_executions(user_id, status, created_at DESC);

-- Index for stuck execution detection
CREATE INDEX IF NOT EXISTS idx_module_executions_stuck 
ON module_executions(status, started_at) 
WHERE status IN ('pending', 'running');

-- Index for workflow execution history queries
CREATE INDEX IF NOT EXISTS idx_workflow_executions_user_created 
ON workflow_executions(user_id, created_at DESC);

-- Index for stuck workflow execution detection
CREATE INDEX IF NOT EXISTS idx_workflow_executions_stuck 
ON workflow_executions(status, updated_at) 
WHERE status IN ('pending', 'running');

-- ============================================================================
-- State Persistence Indexes
-- ============================================================================

-- Index for execution state lookups
CREATE INDEX IF NOT EXISTS idx_execution_state_lookup 
ON execution_state(execution_id, key);

-- ============================================================================
-- Event/Log Indexes
-- ============================================================================

-- Index for execution events by execution and node
CREATE INDEX IF NOT EXISTS idx_execution_events_exec_node 
ON execution_events(execution_id, node_id, created_at DESC);

-- ============================================================================
-- Self-validation
-- ============================================================================
DO $$
BEGIN
    -- Verify indexes were created
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE indexname = 'idx_module_executions_user_status_created'
    ) THEN
        RAISE EXCEPTION 'Index idx_module_executions_user_status_created was not created';
    END IF;
    
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE indexname = 'idx_workflow_executions_stuck'
    ) THEN
        RAISE EXCEPTION 'Index idx_workflow_executions_stuck was not created';
    END IF;
END $$;
