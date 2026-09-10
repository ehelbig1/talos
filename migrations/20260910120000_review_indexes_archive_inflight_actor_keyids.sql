-- 2026-09-10 codebase review — five indexes for read paths that were
-- measured as sequential scans on the reference fleet. Every column below
-- was verified against migrations/.baseline/schema.sql before this file
-- was written (all five exist; none had a covering index).
--
-- No CONCURRENTLY: sqlx runs migrations inside a transaction (check 30).
-- Every statement is IF NOT EXISTS so a re-run is a no-op.

-- workflow_executions_archive.replayed_from_id — the replay-chain readers
-- (`get_execution_replay_chain`, lineage) walk `replayed_from_id` on BOTH
-- tiers since #748/#749 taught them the archive exists; the live table has
-- an index on it, the archive did not. Partial: most archived rows are not
-- replays.
CREATE INDEX IF NOT EXISTS idx_archive_replayed_from
    ON workflow_executions_archive (replayed_from_id)
    WHERE replayed_from_id IS NOT NULL;

-- workflow_executions (workflow_id) restricted to IN-FLIGHT statuses — the
-- concurrency-limit gate (`create_execution_under_concurrency_limit`), the
-- stale-execution sweep and the health/queue readers all ask "how many of
-- THIS workflow's runs are still running", which today walks
-- idx_executions_workflow_id and filters ~every row (terminal rows are
-- >99% of the table). The status set mirrors the in-flight literal used by
-- the readers (check 26 requires 'resuming' in it); 'pending' is included
-- for the approval-gate TOCTOU path even though the CHECK constraint no
-- longer admits it — harmless in a partial-index predicate.
CREATE INDEX IF NOT EXISTS idx_executions_workflow_inflight
    ON workflow_executions (workflow_id)
    WHERE status IN ('running', 'queued', 'pending', 'resuming');

-- workflow_executions (actor_id, started_at DESC) — the per-actor hourly
-- execution budget (`budget_precheck`) and the actor summary/action-log
-- readers ask "this actor's most recent N runs"; the existing
-- idx_wf_executions_actor_id answers the actor half and then sorts.
CREATE INDEX IF NOT EXISTS idx_executions_actor_started
    ON workflow_executions (actor_id, started_at DESC)
    WHERE actor_id IS NOT NULL;

-- actor_memory (value_key_id) — the crypto-invariant orphan scan
-- (`run_crypto_orphan_scan`, hourly since 2026-09-10; it was every 60 s)
-- anti-joins this column against encryption_keys(id), as do the per-org
-- re-encryption sweeps (`re_encrypt_memories_to_org`) and
-- `dekMigrationStatus`'s pending count. Column is NOT NULL, so no partial
-- predicate.
CREATE INDEX IF NOT EXISTS idx_actor_memory_value_key_id
    ON actor_memory (value_key_id);

-- module_executions (payload_enc_key_id) — same scan family as above on
-- the module-payload tier (`re_encrypt_module_payloads_to_org`, the orphan
-- gauge). Nullable: unencrypted/legacy rows carry NULL and are never the
-- subject of the query, so partial.
CREATE INDEX IF NOT EXISTS idx_module_executions_payload_key
    ON module_executions (payload_enc_key_id)
    WHERE payload_enc_key_id IS NOT NULL;
