-- updated_at must date a USER EDIT, not a maintenance write.
--
-- THE DEFECT (measured on the dev DB 2026-09-05)
-- ----------------------------------------------
-- `update_updated_at_column()` was `NEW.updated_at = NOW(); RETURN NEW;` — it
-- stamps the row on ANY column change, so a background job that recomputes a
-- derived column makes every row look "just edited".
--
--   * ALL 36 workflows had `updated_at = readiness_computed_at` EXACTLY, to the
--     microsecond, all inside one second (the controller's boot second). The
--     hourly readiness recompute (`UPDATE workflows SET readiness_score = $1,
--     readiness_computed_at = NOW()`) had overwritten 100% of the column.
--   * 75 of 112 `modules` rows shared one second — the catalog seeder rewrites
--     every catalog row at every boot.
--
-- That is not only a cosmetic report field. `updated_at` decides RUNTIME
-- ROUTING: `resolve_by_capabilities` picks the workflow to execute with
-- `ORDER BY updated_at DESC LIMIT 1`, and `run_workflow_chains` picks which
-- chained workflows fire. With every row tied inside one second, both were
-- resolving on heap order. The true edit history is unrecoverable.
--
-- THE FIX
-- -------
-- One implementation, and it is SELF-DESCRIBING: each trigger declares its
-- table's MAINTENANCE columns as trigger arguments, and the shared function
-- bumps `updated_at` only when something OUTSIDE that set actually changed.
--
-- Why this direction (a deny-list of maintenance columns) rather than an
-- allow-list of content columns: a column added later is treated as CONTENT by
-- default, so a new user-editable column keeps `updated_at` honest with no
-- action required. The residual duty is on whoever adds a new DERIVED column —
-- and that is the person writing the maintenance job, i.e. exactly the person
-- who is thinking about it. An allow-list would have inverted this and gone
-- silently wrong on every new content column, which is the more common event
-- (workflows gained ~13 content columns and ~5 derived ones).
--
-- A second property: an idempotent rewrite of identical values no longer bumps
-- anything.
--
-- That is NECESSARY for the `modules` catalog seeder and NOT SUFFICIENT, and the
-- distinction cost a cycle to find. A BEFORE UPDATE trigger decides whether to
-- OVERWRITE `updated_at`; it can never REVERT a value the statement supplied.
-- The seeder is an `INSERT … ON CONFLICT … DO UPDATE SET …, updated_at = NOW()`,
-- so with this trigger installed and nothing else changed it went on re-dating
-- every catalog row at every boot. Seven statements had to drop the explicit
-- stamp — across BOTH catalog source-of-truth modes, disk seeding AND the OCI
-- registry sync — and structural lint check 83 keeps them dropped.
--
-- COST, MEASURED rather than assumed (pgvector/pgvector:pg17, 500 seeded rows
-- at the live dev shape: graph_json ~1.3 kB, embedding vector(1024) = 4.1 kB;
-- `modules` at the live shape, wasm_bytes 120 kB; medians over 7-25 reps).
--
--   statement                                   old        new     delta
--   -------------------------------------------------------------------
--   readiness recompute, 500-row batch        38.45 ms   65.91 ms   +55 us/row
--   graph save, one workflow                   0.06 ms    0.11 ms   +50 us
--   embedding write, one workflow              0.25 ms    0.30 ms   +50 us
--   AOT precompile store, one module           0.35 ms    0.53 ms  +174 us
--   usage-telemetry bump, one module           0.03 ms    0.22 ms  +197 us
--
-- The worst case is the last row and it is worth naming rather than averaging
-- away: an 8-byte write to a 120 kB module row costs 8x more, because to_jsonb
-- must hex-encode `wasm_bytes` on both sides regardless of what the statement
-- touched. In absolute terms it is +197 us on `increment_usage`, best-effort
-- telemetry issued once per module use against a WASM execution measured in
-- tens of milliseconds — under 1%. The hourly readiness batch pays +27 ms once
-- an hour. Both are accepted; neither is free, and the numbers are here so the
-- next person can re-decide rather than re-derive.
--
-- TWO CHEAPER IMPLEMENTATIONS WERE BUILT AND MEASURED AND REJECTED:
--   * Serialise OLD only, mask NEW's ignored columns via jsonb_populate_record,
--     compare records. Sounds strictly cheaper (one serialisation, not two).
--     It is SLOWER: 0.34 ms vs 0.21 ms on the module row, 80 ms vs 57 ms on the
--     batch — jsonb_populate_record costs more than the second to_jsonb saves.
--   * A generated per-table allow-list of content columns, which needs no
--     serialisation at all. Rejected on semantics, not speed: it goes silently
--     wrong on every column added after it was generated, which is the quiet
--     direction this migration exists to close.
-- The whole-record fast path below WAS measured a win and is kept.
--
-- DELIBERATELY OUT OF SCOPE (verdicts, not oversights):
--   * workflow_executions / module_executions keep their own bump-on-any-change
--     triggers. Their `updated_at` means "last state change", which for a
--     machine-written execution row IS the honest semantic — measured healthy
--     spread on 2026-09-05 (9534 distinct `updated_at` seconds over 46429
--     module_executions rows; 8516 over 9575 workflow_executions). They are
--     also the hottest write path in the system, so a per-row jsonb comparison
--     over their large `output`/`input` columns would cost real latency for no
--     correctness gain.
--   * slack_integrations, google_calendar_integrations,
--     google_calendar_watch_channels, google_cloud_integrations,
--     integration_state keep theirs. OAuth token refresh IS a maintenance write
--     there, but no reader anywhere in the tree consults their `updated_at`, and
--     the live tables hold 0-3 rows, so there is no measured corruption to fix.
--     Recorded here so the next person sees a decision rather than a gap.

-- ---------------------------------------------------------------------------
-- 1. The shared implementation.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
DECLARE
    -- Columns whose change must NOT be read as a user edit. `updated_at`
    -- itself is always ignored: comparing it would make every statement that
    -- stamps it explicitly look like a content change.
    --
    -- Note what this does NOT do: ignoring the column here means the trigger
    -- declines to OVERWRITE an explicit value, so such a statement sets the
    -- column unconditionally and escapes the verdict entirely. That is a
    -- property of BEFORE triggers, not a choice made here, and it is why
    -- lint check 83 forbids an explicit stamp in an upsert on these tables.
    ignored_columns text[];
BEGIN
    -- Fast path. An idempotent rewrite is not an edit, and a record comparison
    -- answers that without serialising anything. This is the catalog seeder's
    -- exact shape (it rewrites every catalog row with identical values at every
    -- controller boot), and MEASURED on a 120 kB `modules` row it is
    -- 0.216 ms -> 0.038 ms, with no measurable cost (0.226 vs 0.228 ms) on the
    -- path where the row really did change.
    --
    -- Record comparison needs a usable `=` for every column type; a future
    -- column of a type without one (json, xml, point) would raise here on every
    -- UPDATE. That is loud rather than silent, and
    -- `every_table_carrying_the_trigger_supports_record_comparison` in
    -- controller/tests/updated_at_maintenance_tests.rs fails in CI first.
    IF OLD IS NOT DISTINCT FROM NEW THEN
        RETURN NEW;
    END IF;

    ignored_columns := COALESCE(TG_ARGV, ARRAY[]::text[]) || ARRAY['updated_at'];

    IF to_jsonb(OLD) - ignored_columns IS DISTINCT FROM to_jsonb(NEW) - ignored_columns THEN
        NEW.updated_at = NOW();
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION update_updated_at_column() IS
    'Stamps updated_at only when a column outside the trigger''s declared '
    'maintenance set changed. Declare maintenance (derived/telemetry) columns '
    'as trigger arguments: EXECUTE FUNCTION update_updated_at_column(''col_a'', ''col_b''). '
    'A column not declared is treated as user content.';

-- ---------------------------------------------------------------------------
-- 2. Declare each table's maintenance columns, and REFUSE to install a
--    declaration naming a column that does not exist.
--
--    A typo'd or since-renamed name would silently do nothing — the exact
--    quiet re-corruption this migration exists to end — so it fails loudly
--    here instead. `updated_at_declarations_name_real_columns` in
--    controller/tests/updated_at_maintenance_tests.rs re-checks this against
--    the live catalog on every CI run, so the guard outlives the migration.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    spec         record;
    missing      text[];
    arg_list     text;
BEGIN
    FOR spec IN
        SELECT * FROM (VALUES
            -- workflows: readiness_* are recomputed hourly off a clock;
            -- embedding and search_text are derived from content that has
            -- already bumped the row on its own edit.
            ('workflows',           'update_workflows_updated_at',
             ARRAY['readiness_score','readiness_computed_at','readiness_scored_at','embedding','search_text']),

            -- secrets: touched on EVERY module secret read. Pre-fix, reading a
            -- secret dated it as though it had been rotated.
            ('secrets',             'update_secrets_updated_at',
             ARRAY['last_accessed_at','access_count']),

            -- users: login telemetry and lockout state, not account edits.
            ('users',               'update_users_updated_at',
             ARRAY['last_login_at','failed_login_attempts','locked_until']),

            -- webhook_triggers: per-fire counters and latency average.
            ('webhook_triggers',    'update_webhook_listeners_updated_at',
             ARRAY['last_triggered_at','trigger_count','success_count','error_count','avg_response_ms']),

            -- mcp_agents: connection heartbeat.
            ('mcp_agents',          'update_mcp_agents_updated_at',
             ARRAY['last_connected_at']),

            -- modules: compile outputs (wasm/hash/size/compiled_at) and usage
            -- telemetry. Recompiling a module unchanged is not an edit of it.
            ('modules',             'modules_set_updated_at',
             ARRAY['wasm_bytes','content_hash','size_bytes','compiled_at','usage_count','last_used_at']),

            -- No maintenance writer exists for either of these today. They are
            -- listed rather than left alone so they share the one
            -- implementation, and so a future maintenance write has an obvious
            -- place to declare itself.
            ('agent_roles',         'update_agent_roles_updated_at',
             ARRAY[]::text[]),
            ('user_audit_settings', 'update_user_audit_settings_updated_at',
             ARRAY[]::text[])
        ) AS t(table_name, trigger_name, maintenance_columns)
    LOOP
        -- The table may legitimately not exist on a partially-migrated DB.
        IF to_regclass('public.' || quote_ident(spec.table_name)) IS NULL THEN
            RAISE NOTICE 'updated_at: table % absent, skipping', spec.table_name;
            CONTINUE;
        END IF;

        SELECT array_agg(c)
          INTO missing
          FROM unnest(spec.maintenance_columns) AS c
         WHERE NOT EXISTS (
             SELECT 1 FROM information_schema.columns
              WHERE table_schema = 'public'
                AND table_name = spec.table_name
                AND column_name = c
         );

        IF missing IS NOT NULL THEN
            RAISE EXCEPTION
                'updated_at maintenance declaration for "%" names column(s) % that do not exist. '
                'Fix the declaration — a name that matches nothing silently disables the guard.',
                spec.table_name, missing;
        END IF;

        -- `updated_at` is added by the function itself; declaring it here would
        -- be redundant and is more likely a mistake than an intent.
        IF 'updated_at' = ANY (spec.maintenance_columns) THEN
            RAISE EXCEPTION
                'updated_at maintenance declaration for "%" must not list updated_at itself.',
                spec.table_name;
        END IF;

        SELECT COALESCE(string_agg(quote_literal(c), ', '), '')
          INTO arg_list
          FROM unnest(spec.maintenance_columns) AS c;

        EXECUTE format('DROP TRIGGER IF EXISTS %I ON public.%I',
                       spec.trigger_name, spec.table_name);
        EXECUTE format(
            'CREATE TRIGGER %I BEFORE UPDATE ON public.%I '
            'FOR EACH ROW EXECUTE FUNCTION update_updated_at_column(%s)',
            spec.trigger_name, spec.table_name, arg_list);
    END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- 3. `modules` had a byte-identical private copy of the old function. It is
--    unreferenced once the trigger above is re-pointed; drop it so there is one
--    implementation rather than two that can drift (migration 20260423000000
--    recreates it on a full-chain replay, and this migration runs after it).
-- ---------------------------------------------------------------------------
DROP FUNCTION IF EXISTS modules_touch_updated_at();

-- ---------------------------------------------------------------------------
-- 4. NO BACKFILL — deliberately.
--
-- The pre-existing values are the recompute clock, not edit times, and the true
-- edit history is gone. `workflow_versions` was evaluated as a source and
-- REJECTED: it covers 18 of 36 workflows (a publish, not an edit, so even for
-- those it is only a lower bound). Writing max(version.created_at) into half the
-- rows would produce a column where a plausible-but-wrong value and an
-- untouched recompute stamp are indistinguishable to every reader — strictly
-- worse than uniformly-known-bad. The rows heal on their next real edit.
-- ---------------------------------------------------------------------------
