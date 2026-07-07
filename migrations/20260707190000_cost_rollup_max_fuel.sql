-- Effective per-node fuel limit on the cost rollup row.
--
-- Pre-fix, fuel reports (get_execution_status / get_execution_trace) joined
-- execution_cost_rollup to modules.max_fuel for the display ceiling — but the
-- limit the dispatch ACTUALLY enforces is `node config max_fuel override >
-- module default, engine-clamped` (engine_dispatch_single). A node with a
-- config override could therefore report fuel_consumed ABOVE its displayed
-- "limit" (observed: fuel=2905011/1380000 on a JS node with a 10M override,
-- 2026-07-07 functional sweep).
--
-- The worker now stamps `__fuel_limit__` (the limit it enforced — req.max_fuel
-- is HMAC-bound in the JobRequest) into node output next to `__fuel_consumed__`;
-- the node-completion hook persists it here. NULLABLE by design: rows written
-- by pre-fix workers (or engine paths that don't carry output fuel metadata)
-- stay NULL and readers COALESCE back to modules.max_fuel — the pre-fix
-- behavior, correct for modules without a config override.
ALTER TABLE execution_cost_rollup
    ADD COLUMN IF NOT EXISTS max_fuel BIGINT;
