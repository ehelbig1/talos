-- Add `error_class` column to execution_events.
--
-- The engine's `NodeEventWrite` struct gained an `error_class:
-- Option<String>` field (talos-workflow-engine-core v0.2.x). The NATS
-- dispatcher populates it on `retry_skipped` events with the classifier
-- tag ("non-transient", "transient", etc). The engine also parses the
-- canonical `(non-transient: <class>)` wrapper out of dispatcher error
-- strings and stamps `error_class` on `node_failed` events.
--
-- Persisting the column lets analytics correlate retry_skipped →
-- node_failed pairs without regex-matching log_message, and lets
-- `analyze_execution_failure` surface a machine-readable failure class
-- in its remediation response.
--
-- Nullable: legacy events pre-dating this column will have NULL.
-- Existing rows are not rewritten; callers must tolerate NULL.

ALTER TABLE execution_events
    ADD COLUMN IF NOT EXISTS error_class TEXT;

-- Small supporting index for the common analytics query
-- "failures grouped by class over the last N days".
CREATE INDEX IF NOT EXISTS idx_execution_events_error_class
    ON execution_events (error_class, created_at)
    WHERE error_class IS NOT NULL;
