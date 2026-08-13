-- Relabel the `module_executions` rows the engine never finalized.
--
-- WHY
-- ---
-- Until 2026-08-12 `run_single_node_dispatch` opened a `module_executions`
-- row with `record_started` and never closed it. (Its two siblings — the loop
-- path and the pipeline-step path — did.) Every single-node workflow dispatch
-- therefore sat in `'running'` until the 30-minute stuck-execution sweep
-- rewrote it to `status='timeout'`, `error_type='stuck'`, with the message
-- "Execution timed out — worker did not report completion within the allowed
-- window".
--
-- That message is false for these rows. The worker DID report; nothing on the
-- controller side wrote the report down. Measured on the dev fleet the day of
-- the fix: 21,065 `timeout` rows, 0 `completed` rows in the table's entire
-- history, and 20,252 of those timeouts had a parent `workflow_executions`
-- row whose status was `completed`. Their `duration_ms` is equally false —
-- the BEFORE UPDATE trigger `calculate_module_execution_duration` derives it
-- from `completed_at - started_at`, and `completed_at` was stamped by the
-- sweep, so the number records TIME UNTIL THE SWEEP NOTICED, not work time.
-- The minimum across the whole table was 1,800,301 ms: the 30-minute
-- threshold plus 301 ms. The maximum was 216,917,679 ms (~60 h).
--
-- WHAT THIS MIGRATION DELIBERATELY DOES NOT DO
-- --------------------------------------------
-- It does NOT resurrect these rows as `'completed'`, for two independent
-- reasons, each sufficient on its own:
--
--  1. NOT ONE of the 21,065 rows carries an output payload — `output_data`
--     and `output_data_enc` are both NULL for every one of them, because the
--     sweep never had an output to write. `'completed'` is precisely the
--     status `WorkflowRepository::list_completed_module_executions` selects
--     on to build `replay_module_regression`'s corpus, and
--     `find_latest_completed_execution_io` likewise. Backfilling would swap
--     an EMPTY corpus for a corpus of 20,252 empty baselines — replay would
--     then diff live output against NULL. A silent no-op is a better failure
--     than a loud wrong answer.
--
--  2. "The parent workflow completed" does not entail "this node succeeded".
--     A node can fail under `continue_on_error` (or be skipped, or return an
--     `__error` envelope) while its workflow still reaches `completed`. The
--     predicate is a good filter for "the ledger was broken here"; it is not
--     evidence about the node's outcome. We do not know these nodes'
--     outcomes and this migration does not pretend to.
--
-- It also leaves `status` alone. The CHECK constraint admits only
-- pending/running/completed/failed/timeout/cancelled, and every reader in the
-- workspace routes on those six; inventing a seventh would need each of them
-- audited. `'timeout'` remains defensible as a literal statement about the
-- LEDGER — no completion was ever recorded — while `error_type` is the field
-- that carries the CAUSE, and `'stuck'` (a worker that died) is the part that
-- was never true.
--
-- WHAT IT DOES
-- ------------
-- For rows the sweep converted whose parent workflow COMPLETED:
--   * `error_type`    'stuck' -> 'ledger_unfinalized'
--   * `error_message` replaced with an honest description
--   * `duration_ms`   -> NULL (it measured the sweep, not the module)
--
-- `duration_ms` can be set here: the duration trigger only fires when
-- `completed_at` transitions from NULL, and it is already non-NULL on these
-- rows, so this UPDATE will not recompute it.
--
-- Idempotent: re-running matches nothing (the predicate requires
-- `error_type = 'stuck'`, which the first run clears).
--
-- Batched with per-batch exception handling per CLAUDE.md's migration rules.
-- The nested BEGIN/EXCEPTION creates an implicit SAVEPOINT so a single bad
-- batch cannot abort the whole migration. Batching (rather than one statement
-- per row) is the right granularity here: the work is a column rewrite with
-- no per-row logic that can fail differently, and 21k single-row UPDATEs
-- inside one transaction is needless lock churn.
--
-- allow-actor-memory-sql: not actor_memory — this is module_executions.

DO $$
DECLARE
    batch_size CONSTANT int := 2000;
    touched    int;
    total      int := 0;
BEGIN
    LOOP
        BEGIN
            WITH candidates AS (
                SELECT m.id
                FROM module_executions m
                JOIN workflow_executions w ON w.id = m.workflow_execution_id
                WHERE m.status = 'timeout'
                  AND m.error_type = 'stuck'
                  AND w.status = 'completed'
                LIMIT batch_size
            )
            UPDATE module_executions m
            SET error_type = 'ledger_unfinalized',
                error_message = 'Never finalized by the engine (pre-2026-08-12 '
                                || 'single-node dispatch gap); converted by the '
                                || 'stuck-execution sweep. The recorded outcome and '
                                || 'duration are not evidence about this module run.',
                duration_ms = NULL
            FROM candidates c
            WHERE m.id = c.id;

            GET DIAGNOSTICS touched = ROW_COUNT;
            total := total + touched;
            EXIT WHEN touched = 0;
        EXCEPTION WHEN others THEN
            RAISE WARNING 'relabel_unfinalized_module_executions: batch failed, stopping: %', SQLERRM;
            EXIT;
        END;
    END LOOP;

    RAISE NOTICE 'relabel_unfinalized_module_executions: relabelled % rows', total;
END $$;
