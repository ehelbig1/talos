-- A child run's fuel is charged to the ROOT run's actor too (security
-- review 2026-10-14, G-8).
--
-- A sub-workflow's dispatch is recorded under the actor the child runs as
-- (`actor_id`: its own bound actor, or the parent's it inherits). A run
-- admitted once against its actor's hourly fuel cap could move its spend into
-- children bound to another actor and never be charged for it. The root run's
-- actor is now recorded beside it, and the hourly fuel sum
-- (`talos_actor_budget_refusal::fuel_last_hour`) counts a row once for either
-- actor (`$1 IN (actor_id, root_actor_id)`).
--
-- NULL on the root run's own dispatches and on module-bound dispatches (no
-- run), so existing rows and their sums are unchanged. Only
-- `talos_cost_attribution` writes the column.
--
-- Index: partial, on the rows that carry a root, matching the existing
-- `(actor_id, recorded_at)` index the other arm of the sum uses.

ALTER TABLE execution_cost_rollup ADD COLUMN IF NOT EXISTS root_actor_id UUID;

CREATE INDEX IF NOT EXISTS idx_cost_rollup_root_actor
    ON execution_cost_rollup (root_actor_id, recorded_at)
    WHERE root_actor_id IS NOT NULL;
