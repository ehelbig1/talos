-- RFC 0012 P2 — the four dispatch kinds P1 could not see.
--
-- `20260906120000` admitted exactly five `dispatch_kind` values, and said so
-- deliberately: they were the five whose dispatcher routes through
-- `execute_subworkflow_graph`, and "a value nothing writes is the same defect
-- as a seeded metric label nothing increments". The other four
-- (`dispatch`, `capability_dispatch`, `agent_loop`, `react_loop`) hydrate a
-- child engine at a DIFFERENT site — `AdapterSet::into_engine_with_graph`
-- called directly in `scheduler_handlers.rs`, one of them inside an
-- `async move` that captures the adapter set rather than `self` — so P1 was
-- structurally blind to them and NAMED the gap in
-- `talos_child_run_ledger::UNRECORDED_DISPATCH_KINDS` instead.
--
-- They now have live writers, routed through the same `ChildRunReporter` as
-- the original five, so the CHECK is widened to admit them. The rule is
-- unchanged: a value is admitted here only once something writes it.
--
-- NOT an edit of the applied migration (that would change its checksum and
-- break sqlx). A follow-up that replaces the constraint, per the house rule.
--
-- `agent_loop` / `react_loop` record ONE ROW PER ITERATION. A loop that runs
-- five iterations dispatched five child runs, and folding them into one would
-- make the ledger disagree with the fuel and the durations those same
-- iterations produced.

ALTER TABLE sub_workflow_runs
    DROP CONSTRAINT IF EXISTS sub_workflow_runs_dispatch_kind_check;

ALTER TABLE sub_workflow_runs
    ADD CONSTRAINT sub_workflow_runs_dispatch_kind_check
    CHECK (dispatch_kind IN (
        'sub_workflow',
        'judge',
        'ensemble',
        'reflective_retry',
        'llm_dispatch',
        'dispatch',
        'capability_dispatch',
        'agent_loop',
        'react_loop'
    ));

-- ── `since()` was a SEQ SCAN, and P2 multiplied its callers ────────────────
--
-- `ChildRunLedger::since` is `SELECT MIN(started_at) FROM sub_workflow_runs`
-- — deliberately not user-scoped, because "from when was anything being
-- recorded" is a deployment fact. None of the three P1 indexes leads with
-- `started_at`, so that MIN is a sequential scan of the whole table. Measured
-- 2026-09-07 on a standalone replica of this table with the same three
-- indexes:
--
--     13 500 rows (60 days at ~225 child runs/day):   1.7 – 1.9 ms, Seq Scan
--    135 000 rows (the same at 10x volume):          14.4 – 15.5 ms, Seq Scan
--    135 000 rows WITH this index:                    0.036 – 0.045 ms,
--                                                     Index Only Scan
--
-- i.e. linear in the table and ~400x cheaper with it. The read is cached per
-- process for 60 s, so this was affordable in P1 where two consumers called
-- it. P2 takes it to five (three readiness scorers, the readiness list, the
-- hygiene report), each of which reads the floor before every batched count,
-- so the cache is refreshed more often and by more processes.
--
-- Cost of the index itself is one more b-tree on an APPEND-ONLY table whose
-- write volume is ~225 rows/day today: no updates to churn it, and the
-- retention sweep already deletes in `SKIP LOCKED` batches.
--
-- `CREATE INDEX`, not `CONCURRENTLY` — sqlx runs migrations in a transaction.
CREATE INDEX IF NOT EXISTS idx_sub_workflow_runs_started_at
    ON sub_workflow_runs (started_at);
