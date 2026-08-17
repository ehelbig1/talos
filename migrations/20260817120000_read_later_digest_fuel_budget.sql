-- pa-read-later-digest / `digest`: a fuel budget that never fit.
--
-- ── What was wrong ──────────────────────────────────────────────────
-- The `digest` node carried NO `data.max_fuel`, so it inherited the
-- `LLM Inference` module-row default of 1,404,000. Real per-node fuel from
-- `execution_cost_rollup`:
--
--   2026-07-15  964,487 / 1,404,000   68.7%   ok  (creation test)
--   2026-07-25  1,359,999 / 1,404,000 96.9%   ok  (full payload)
--   2026-08-01  —                    >100%   FAILED
--   2026-08-10  681,908 / 1,404,000   48.6%   ok  (small payload)
--   2026-08-17  —                    >100%   FAILED
--
-- Two of the four SCHEDULED runs failed; the single full-payload success
-- cleared the ceiling by 3.1%. The budget was wrong from the workflow's
-- first execution — this is not a regression, and it is not staleness
-- (`MAX_PER_ACCOUNT: 10` x 2 accounts caps the input at 20 items no matter
-- how long the gap; the LONGEST gap produced the SMALLEST payload).
--
-- ── Why 8,000,000 and not "a bit more" ──────────────────────────────
-- Derived, not guessed:
--
--  1. The node's own `MAX_TOKENS` is 1400. The completion that consumed
--     96.9% of the budget was roughly a third of that, so the ceiling
--     cannot accommodate the node's own configured maximum output. The
--     token axis alone puts the requirement near 3 x 1.36M ~ 4.1M.
--  2. `digest` runs in the `secrets-node` capability world, which is
--     memory-eligible, so the engine injects `__actor_context__` on top of
--     the upstream payload — up to `SMART_MEMORY_CONTEXT_BYTE_BUDGET`
--     (12,000 bytes default). That cost is invisible in
--     `module_executions.input_data` and must be budgeted for.
--  3. Twelve sibling nodes on the SAME `LLM Inference` module already run
--     at 8M-14M. `pa-ask-grounded/answer` sits at 8M on a near-identical
--     prompt size (11,502 vs 11,543 tokens).
--  4. Adaptive fuel would not have reached this number: p95 over the two
--     surviving samples is ~1.32M, x2 = ~2.65M, which still would not
--     cover a full-`MAX_TOKENS` completion. (It would not have fired at
--     all — see the note on the sample floor below.)
--
-- ── Blast radius ────────────────────────────────────────────────────
-- NODE-SCOPED. `data.max_fuel` on one node of one workflow. The shared
-- `modules.max_fuel` default (1,404,000) is deliberately NOT raised: the
-- other override-less consumer of that module is
-- `content-pipeline-weekly/weekly_idea`, which is running comfortably and
-- has not asked for a raise.
--
-- Fuel is a RESOURCE LIMIT, so this is a security change as much as a
-- performance one. What still bounds it:
--   * the engine-wide ceiling `max_fuel_per_node` (50,000,000) clamps this
--     value in `ParallelWorkflowEngine::resolve_node_max_fuel`;
--   * the per-step wall-clock timeout is unchanged;
--   * the bound actor's `actor_budget_policies` row has
--     `max_fuel_per_execution`, `max_fuel_per_hour` and `fuel_budget_daily`
--     all NULL, and `tenant_quotas` is empty, so no per-actor or
--     per-tenant fuel budget interacts with this change today. If either
--     is ever populated, THAT becomes the binding constraint, not this.
--
-- Raising fuel does NOT bound the payload: `readlater-fetch` truncates
-- `snippet` to 220 chars but does not truncate `Subject` or `From` at all,
-- and both are sender-influenceable. See `docs/fuel-budget-sizing.md`.
--
-- ── Why a migration ─────────────────────────────────────────────────
-- `workflows.graph_json` is the mutable DRAFT and this workflow has no
-- rows in `workflow_versions`, so the scheduler's version-preferring read
-- falls back to the draft — the draft IS what executes. Published
-- snapshots are immutable by contract (migration 20260421200000) and are
-- deliberately NOT touched here.
--
-- Idempotent: only nodes whose `data.max_fuel` is absent or BELOW the
-- target are rewritten, so a re-run is a no-op and an operator who has
-- since raised it further is never lowered. Per-row BEGIN/EXCEPTION so one
-- malformed `graph_json` cannot abort the batch.

DO $$
DECLARE
    target_fuel CONSTANT BIGINT := 8000000;
    r RECORD;
    gj JSONB;
    new_nodes JSONB;
    rewrote INT := 0;
    skipped INT := 0;
    failed  INT := 0;
BEGIN
    -- The driving query selects graph_json as TEXT and does NOT cast. The
    -- `::jsonb` cast lives INSIDE the per-row BEGIN/EXCEPTION block below,
    -- because a cast in the FOR-over-SELECT is evaluated while the loop is
    -- fetching rows — i.e. OUTSIDE any handler — so a single unparseable
    -- `graph_json` anywhere in the table aborts the entire migration with
    -- `invalid input syntax for type json` and rewrites nothing. Verified by
    -- planting a malformed row: the pre-fix shape failed exactly that way,
    -- which is the failure the per-row savepoint discipline exists to
    -- prevent.
    FOR r IN
        SELECT w.id, w.graph_json AS raw
        FROM workflows w
        WHERE w.name = 'pa-read-later-digest'
          AND w.graph_json IS NOT NULL
    LOOP
        BEGIN
            gj := r.raw::jsonb;

            IF jsonb_typeof(gj -> 'nodes') <> 'array' THEN
                skipped := skipped + 1;
                CONTINUE;
            END IF;

            SELECT jsonb_agg(
                CASE
                    -- A non-numeric `max_fuel` counts as ABSENT, matching the
                    -- engine: `node_config_max_fuel` reads it with
                    -- `serde_json::Value::as_u64`, so a string or a float is
                    -- `None` there and falls back to the module default.
                    -- Treating it as a real ceiling here would leave the node
                    -- broken while the migration reported success.
                    WHEN n ->> 'id' = 'digest'
                         AND COALESCE(
                                 CASE
                                     WHEN (n -> 'data' ->> 'max_fuel') ~ '^[0-9]+$'
                                     THEN (n -> 'data' ->> 'max_fuel')::BIGINT
                                 END,
                                 0
                             ) < target_fuel
                    THEN jsonb_set(
                             n,
                             '{data}',
                             COALESCE(n -> 'data', '{}'::jsonb)
                                 || jsonb_build_object('max_fuel', target_fuel),
                             true
                         )
                    ELSE n
                END
                ORDER BY ord
            )
            INTO new_nodes
            FROM jsonb_array_elements(gj -> 'nodes') WITH ORDINALITY AS a(n, ord);

            IF new_nodes IS DISTINCT FROM (gj -> 'nodes') THEN
                UPDATE workflows
                SET graph_json = jsonb_set(gj, '{nodes}', new_nodes, false)::text
                WHERE id = r.id;
                rewrote := rewrote + 1;
            ELSE
                skipped := skipped + 1;
            END IF;
        EXCEPTION WHEN others THEN
            -- Nested block = implicit SAVEPOINT: a malformed graph_json
            -- rolls back only its own iteration.
            failed := failed + 1;
            RAISE WARNING 'read-later digest fuel migration: workflow % skipped: %',
                r.id, SQLERRM;
        END;
    END LOOP;

    RAISE NOTICE 'read-later digest fuel budget: % rewritten, % already at/above target, % failed',
        rewrote, skipped, failed;
END $$;
