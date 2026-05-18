-- Durable execution state for crash recovery of long-running workflows.
-- State is flushed from worker in-memory stores to this table at checkpoints.

CREATE TABLE IF NOT EXISTS execution_state (
    execution_id    UUID NOT NULL,
    key             TEXT NOT NULL,
    value           TEXT NOT NULL,
    -- Optimistic concurrency control: increment on every write.
    version         BIGINT NOT NULL DEFAULT 1,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (execution_id, key)
);

-- Fast lookup for loading all state for a given execution on recovery.
CREATE INDEX IF NOT EXISTS idx_execution_state_exec
    ON execution_state (execution_id);

-- Encrypted checkpoint data for workflow executions.
-- Replaces plain JSON in workflow_executions.output_data for sensitive workflows.
ALTER TABLE workflow_executions
    ADD COLUMN IF NOT EXISTS checkpoint_encrypted BYTEA,
    ADD COLUMN IF NOT EXISTS checkpoint_nonce     BYTEA;
