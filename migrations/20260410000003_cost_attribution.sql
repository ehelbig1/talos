-- Cost attribution: per-node fuel consumption rollup for actor/workflow cost reports.

CREATE TABLE IF NOT EXISTS execution_cost_rollup (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id UUID,
    workflow_id UUID NOT NULL,
    execution_id UUID NOT NULL,
    node_id TEXT NOT NULL,
    module_id UUID,
    fuel_consumed BIGINT NOT NULL DEFAULT 0,
    wall_time_ms BIGINT NOT NULL DEFAULT 0,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cost_rollup_actor ON execution_cost_rollup (actor_id, recorded_at)
    WHERE actor_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_cost_rollup_workflow ON execution_cost_rollup (workflow_id, recorded_at);
CREATE INDEX IF NOT EXISTS idx_cost_rollup_execution ON execution_cost_rollup (execution_id);

-- Extend actor budget policies with fuel-based budgets
ALTER TABLE actor_budget_policies
    ADD COLUMN IF NOT EXISTS fuel_budget_daily BIGINT,
    ADD COLUMN IF NOT EXISTS fuel_alert_threshold_pct INT NOT NULL DEFAULT 80;

COMMENT ON TABLE execution_cost_rollup IS 'Per-node fuel consumption records for cost attribution. Aggregated for actor/workflow cost reports and budget enforcement.';
COMMENT ON COLUMN actor_budget_policies.fuel_budget_daily IS 'Maximum total fuel allowed per day. NULL = unlimited.';
COMMENT ON COLUMN actor_budget_policies.fuel_alert_threshold_pct IS 'Percentage of daily fuel budget at which to fire an alert (default 80%).';
