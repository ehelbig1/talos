-- Retention sweeps for the tables that had a writer and no reaper
-- (2026-09-10, whole-codebase review follow-up B2-1).
--
-- `ExecutionRetention` (talos-advanced-repository) gains two tiers:
--
--   * tier four, clocked on the TOTAL execution lifetime
--     (ARCHIVE_AFTER_DAYS + EXECUTION_RETENTION_DAYS): `llm_usage.recorded_at`,
--     `judge_scores.created_at`, and orphaned `execution_state` rows;
--   * tier five, clocked on TALOS_AUDIT_TABLE_RETENTION_DAYS (default 180,
--     floor 30): `actor_action_log."timestamp"`, `module_update_history.created_at`,
--     and `ops_alerts.resolved_at WHERE status = 'resolved'`.
--
-- Every sweep is `DELETE … WHERE <pk> IN (SELECT <pk> … WHERE <ts> < NOW() - N
-- ORDER BY <ts>, <pk> LIMIT 5000 FOR UPDATE SKIP LOCKED)`, so each needs a
-- btree whose LEADING column is the timestamp it orders on. Verified against
-- migrations/.baseline/schema.sql + the post-baseline migrations:
--
--   llm_usage              has (actor_id, recorded_at), (user_id, recorded_at)  — no leading recorded_at
--   judge_scores           has (workflow_id, created_at), (execution_id, created_at DESC) — no leading created_at
--   actor_action_log       has (actor_id, "timestamp" DESC), (org_id)         — no leading "timestamp"
--   module_update_history  has (module_id, created_at DESC), (org_id, user_id) — no leading created_at
--   ops_alerts             has (user_id, status, last_seen DESC, id DESC) and two partial (user_id, …) — no resolved_at
--
-- Already covered, no index added: actor_memory (idx_actor_memory_expires,
-- partial on expires_at IS NOT NULL), execution_memory_context (idx_emc_created),
-- user_sessions (idx_user_sessions_expires_at), rotated_session_audit
-- (rotated_session_audit_expires_at_idx), sub_workflow_runs (started_at
-- indexes), execution_state (PK (execution_id, key) serves the archive-move
-- cascade and the orphan anti-join).
--
-- NOT indexed and NOT swept: admin_event_log, auth_audit_log, secret_audit_log,
-- audit_events — all carry the prevent_audit_modification BEFORE DELETE
-- trigger (20260408000001) and are append-only by policy. The sweeps never
-- name them.
--
-- Plain CREATE INDEX (no CONCURRENTLY — sqlx runs migrations in a transaction,
-- lint check 30). All five tables are small on the reference fleet; the build
-- is a brief lock.

CREATE INDEX IF NOT EXISTS idx_llm_usage_recorded_at
    ON llm_usage (recorded_at, id);

CREATE INDEX IF NOT EXISTS idx_judge_scores_created_at
    ON judge_scores (created_at, id);

CREATE INDEX IF NOT EXISTS idx_actor_action_log_timestamp
    ON actor_action_log ("timestamp", id);

CREATE INDEX IF NOT EXISTS idx_module_update_history_created_at
    ON module_update_history (created_at, id);

-- Partial: only resolved alerts are ever reaped, and only they carry a
-- resolved_at the sweep can order on.
CREATE INDEX IF NOT EXISTS idx_ops_alerts_resolved_at
    ON ops_alerts (resolved_at, id)
    WHERE status = 'resolved';
