-- A module-bound result's fuel is recorded once (security review 2026-10-14,
-- B-1).
--
-- A module-bound dispatch (webhook, Gmail/Calendar/GCP push, DLQ replay) is
-- finalized by the controller's `talos.results.*` observer, which records the
-- attempt's fuel by ADDING it to `module_executions.fuel_consumed` and
-- inserting an `execution_cost_rollup` row. The observer is in a queue group,
-- so each controller replica sees a different share of the messages, and its
-- process-local replay cache cannot see a copy delivered to another replica.
-- One captured result republished inside its freshness window was counted
-- once per copy, draining the actor's hourly fuel budget.
--
-- The result's signed nonce is now recorded on the rollup row, and the pair
-- (execution, nonce) is unique: `talos_cost_attribution` inserts the row with
-- ON CONFLICT DO NOTHING and adds to `module_executions.fuel_consumed` only
-- when the row was inserted. NULL on every row written before this migration
-- and on workflow dispatch rows (their result is verified once by the one
-- dispatcher that holds the reply inbox), so existing rows are unaffected.
-- Only `talos_cost_attribution` writes the column.

ALTER TABLE execution_cost_rollup ADD COLUMN IF NOT EXISTS result_nonce TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS uq_cost_rollup_execution_result_nonce
    ON execution_cost_rollup (execution_id, result_nonce)
    WHERE result_nonce IS NOT NULL;
