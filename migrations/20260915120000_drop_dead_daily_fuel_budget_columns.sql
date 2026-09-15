-- The daily fuel budget that enforced nothing (package BN, 2026-09-15).
--
-- `actor_budget_policies.fuel_budget_daily` and `fuel_alert_threshold_pct` were
-- added by 20260410000003 ("Maximum total fuel allowed per day"; "Percentage of
-- daily fuel budget at which to alert"). Measured before dropping:
--
--   * no writer anywhere in the workspace — no MCP tool, GraphQL mutation,
--     scaffold or clone sets either column (the clone copies every other
--     budget column and not these);
--   * one reader, `talos_cost_attribution::check_fuel_budget`, called only by
--     `get_actor_cost_report`, which had zero callers — so no execution was
--     ever refused and no alert ever fired on a daily budget;
--   * on the reference deployment 0 of 5 policy rows set `fuel_budget_daily`;
--     `fuel_alert_threshold_pct` is the column default 80 on all 5;
--   * no view, function or policy references either column.
--
-- The HOURLY fuel cap (`max_fuel_per_hour`) is real — enforced at row creation
-- in `create_execution_under_concurrency_limit` — and is untouched.
-- `docs/fuel-budget-sizing.md`, which named the daily column as a backstop, is
-- corrected in the same change.

ALTER TABLE actor_budget_policies DROP COLUMN IF EXISTS fuel_budget_daily;
ALTER TABLE actor_budget_policies DROP COLUMN IF EXISTS fuel_alert_threshold_pct;
