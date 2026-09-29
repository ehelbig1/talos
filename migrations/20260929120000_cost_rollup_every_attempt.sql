-- execution_cost_rollup records the fuel of EVERY verified dispatch attempt.
--
-- Until now a row was written only for a node that COMPLETED and whose output
-- was a JSON object carrying `__fuel_consumed__`: the fuel figure travelled
-- inside the module's output, the worker could stamp it only into an object,
-- and a failed run returns no output. So the actor's hourly fuel budget
-- (`max_fuel_per_hour`, which sums this table) never counted a module that
-- returned an array, string or number, any failed or fuel-exhausted attempt,
-- any retried attempt, any loop-body iteration, or any module-bound dispatch
-- (webhook, push, DLQ replay). Measured 2026-09-29: 2 of 36 153 completed
-- module rows in 30 days had no fuel for the first reason alone.
--
-- Rows now come from the controller's fuel sink, one per verified attempt,
-- with the figure read from the signed `JobResult` (see
-- `talos_workflow_job_protocol::spent_fuel`).
--
-- `outcome` separates what a BUDGET must count from what a LEARNER may read.
-- The budget sums every row: a failed attempt spent its fuel. Adaptive fuel
-- ceilings, the fuel usage report, the high-utilisation detector, the timing
-- fallback and the fuel-exhaustion advisor read `outcome = 'completed'` only;
-- a fuel-exhausted attempt sits at its limit, and learning a ceiling from it
-- would raise the ceiling after every exhaustion. Existing rows are all
-- completed attempts, so the default describes them correctly.
ALTER TABLE execution_cost_rollup
    ADD COLUMN IF NOT EXISTS outcome text NOT NULL DEFAULT 'completed';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'execution_cost_rollup_outcome_check'
    ) THEN
        ALTER TABLE execution_cost_rollup
            ADD CONSTRAINT execution_cost_rollup_outcome_check
            CHECK (outcome IN ('completed', 'failed'));
    END IF;
END $$;

-- A module-bound dispatch (webhook, Gmail/Calendar/GCP push, DLQ replay) runs
-- one module with no workflow and no graph node, so it has neither id. Its
-- row carries the actor and the module; every report that joins `workflows`
-- (the tenancy predicate) excludes it, and the budget, which reads
-- `actor_id` alone, counts it.
ALTER TABLE execution_cost_rollup ALTER COLUMN workflow_id DROP NOT NULL;
ALTER TABLE execution_cost_rollup ALTER COLUMN node_id DROP NOT NULL;

COMMENT ON COLUMN execution_cost_rollup.outcome IS
    'completed | failed: whether the dispatch attempt this row records '
    'succeeded. Budgets count every row; learners and percentile reports '
    'read completed rows only.';

-- Supersedes the comment set by 20260831120000.
COMMENT ON COLUMN execution_cost_rollup.wall_time_ms IS
    'MONOTONIC elapsed milliseconds for one dispatch attempt, despite the '
    'column name. From 20260929120000 it is the worker-measured execution '
    'time of the attempt (JobResult.execution_time_ms, Instant-based); '
    'earlier rows hold the engine''s node dispatch time. Rows exist for '
    'every verified attempt that reported fuel > 0; see outcome.';
