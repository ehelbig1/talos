-- Add input_data to workflow_executions.
--
-- Required by the approval gate continuation workflow trigger and webhook
-- approval handler, which pass the gate payload as execution input so the
-- continuation workflow knows what was approved.
--
-- Column is nullable because existing execution paths (scheduler, direct
-- trigger, replay, bulk trigger) do not supply input data at this level —
-- they pass payloads through NATS job messages instead.

ALTER TABLE workflow_executions ADD COLUMN IF NOT EXISTS input_data JSONB;
