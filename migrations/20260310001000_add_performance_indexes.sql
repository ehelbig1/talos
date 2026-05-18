-- Index for registry access checks (correlated subquery runs N times per workflow)
CREATE INDEX IF NOT EXISTS idx_workflow_module_refs_module_id_workflow_id
ON workflow_module_refs(module_id, workflow_id);

-- Index for scheduler polling (runs every 15 seconds)
CREATE INDEX IF NOT EXISTS idx_workflow_schedules_enabled_trigger
ON workflow_schedules(next_trigger_at) WHERE is_enabled = true;

-- Index for stuck execution recovery
CREATE INDEX IF NOT EXISTS idx_workflow_executions_status_updated
ON workflow_executions(status, updated_at);

-- Index for execution event replay
CREATE INDEX IF NOT EXISTS idx_execution_events_execution_created
ON execution_events(execution_id, created_at);

-- Index for module deduplication
CREATE INDEX IF NOT EXISTS idx_wasm_modules_content_hash_user
ON wasm_modules(content_hash, user_id);
