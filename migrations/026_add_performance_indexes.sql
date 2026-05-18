-- Add index for webhook logs
CREATE INDEX IF NOT EXISTS idx_webhook_request_log_user_trigger ON webhook_request_log(trigger_id, created_at DESC);

-- Add index for module executions
CREATE INDEX IF NOT EXISTS idx_module_executions_status_created ON module_executions(status, created_at DESC);
