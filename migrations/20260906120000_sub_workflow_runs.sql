-- `sub_workflow_runs` — the child-run ledger (RFC 0012 P1).
--
-- `execute_subworkflow_graph` runs a child workflow IN-PROCESS and records no
-- `workflow_executions` row. Measured on the reference fleet 2026-09-05 and
-- re-measured 2026-09-06: ZERO rows carry a `parent_execution_id`, live table
-- AND archive, platform-wide, against an estimated ~225 child runs per day. So
-- every reader that answers "did this workflow run, how often, how recently?"
-- — all of which read `workflow_executions` — is structurally blind to a
-- child. #758/#760/#762/#763 taught the DESTRUCTIVE and SCORING readers to say
-- "no evidence" instead of "never ran". None of them can ANSWER the question.
--
-- WHY NOT `workflow_executions` (RFC 0012 "Alternatives"): 161 of the 163
-- reads of that table carry no `parent_execution_id` filter, so every fleet
-- total, error rate and cost aggregate would double-count from the first child
-- run; `budget_precheck` counts execution rows against
-- `max_executions_per_hour`, so a parent with a `team_gather` child would be
-- charged twice for one run; and the retention sweep archives by row, so a
-- tree would be split across tiers at day 30.
--
-- NO PAYLOAD COLUMNS. The ledger answers "ran / when / how / for whom"; the
-- child's output already lives in the parent's node result. Nothing here is
-- content, so there is no new ciphertext table, nothing to re-encrypt per org,
-- and nothing for DLP to miss. `error_class` is the one free-text column and it
-- passes through the engine's output sanitizer (the same redaction
-- `workflow_executions.error_message` gets) and is capped to 512 chars on a
-- char boundary BEFORE the bind; the CHECK below is the second belt.
--
-- NO FOREIGN KEY on `parent_execution_id`, deliberately. Archival is a DELETE
-- from `workflow_executions` plus an INSERT into `workflow_executions_archive`,
-- so `ON DELETE CASCADE` would erase the ledger at day 30 while the parent
-- survives to day 60, and `ON DELETE RESTRICT` would break the sweep. The
-- ledger keeps its OWN retention (`archive_after_days + purge_after_days`) in
-- the existing retention pass. `parent_workflow_id` is denormalised for the
-- same reason: a purged parent must still answer "who ran me".
--
-- NO FOREIGN KEY on `parent_workflow_id`, `child_workflow_id` or `actor_id`
-- either, for the same class of reason. A workflow that is deleted must not
-- take the evidence that it RAN with it — `delete_workflows_checked` exists
-- precisely because children get deleted — and an `ON DELETE RESTRICT` FK to
-- `actors` (the shape `workflow_executions` uses) would make a retired actor
-- undeletable for as long as the ledger remembers it. `user_id` DOES carry the
-- house `ON DELETE CASCADE` to `users`: a deleted user's rows are the one case
-- where the evidence must go too.
--
-- NO `org_id` COLUMN, and this DEPARTS from the RFC's first draft — the reason
-- is a code fact measured before the table was written. `ParallelWorkflowEngine`
-- has no org handle at the write site (it carries `user_id`, `actor_id`,
-- `workflow_id` and nothing else tenant-shaped), so the column could only be
-- filled by an extra query per child run. It would also be the same unreliable
-- tenant key `20260904210000` documents on the archive: that policy joins
-- `workflows` for the org rather than trusting the row's own column. This table
-- does exactly that, so the column would have been decorative and wrong.

CREATE TABLE IF NOT EXISTS sub_workflow_runs (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The execution the parent ran under. No FK — see the header.
    parent_execution_id uuid        NOT NULL,
    -- Denormalised so a purged parent still answers "who ran me", and so the
    -- RLS policy below has a `workflows` row to derive the tenant org from.
    parent_workflow_id  uuid        NOT NULL,
    -- The graph node id as the author wrote it ("n3", "team_gather"),
    -- control-char-scrubbed and capped by the writer.
    parent_node_id      text        NOT NULL,
    -- The five system-node kinds that reach `execute_subworkflow_graph`. This
    -- set is DERIVED FROM THE CODE, not from the RFC's illustrative list: it is
    -- exactly the kinds whose dispatcher routes through the chokepoint, so
    -- every value here has a live writer. `agent_loop` / `react_loop` /
    -- `dispatch` / `capability_dispatch` run a child through a DIFFERENT
    -- hydration site and are NOT recorded in P1 — admitting a value nothing
    -- writes would be the same defect as seeding a metric label nothing
    -- increments. They are named in
    -- `talos_child_run_ledger::UNRECORDED_DISPATCH_KINDS` and disclosed by
    -- every consumer.
    dispatch_kind       text        NOT NULL,
    child_workflow_id   uuid        NOT NULL,
    user_id             uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- The EFFECTIVE actor the child ran as, read off the sub-engine AFTER
    -- `bind_subengine_actor_and_ceilings` — a sub-workflow bound to its own
    -- actor runs AS that actor, so the parent's actor would be the wrong
    -- answer. NULL when the run had no bound actor at all.
    actor_id            uuid        NULL,
    -- Nesting depth; 1 = a direct child of a top-level execution.
    depth               smallint    NOT NULL,
    started_at          timestamptz NOT NULL,
    completed_at        timestamptz NOT NULL,
    status              text        NOT NULL,
    error_class         text        NULL,
    duration_ms         bigint      NOT NULL,

    CONSTRAINT sub_workflow_runs_dispatch_kind_check CHECK (
        dispatch_kind IN ('sub_workflow', 'judge', 'ensemble', 'reflective_retry', 'llm_dispatch')
    ),
    CONSTRAINT sub_workflow_runs_status_check CHECK (
        status IN ('completed', 'failed')
    ),
    CONSTRAINT sub_workflow_runs_depth_check CHECK (depth > 0),
    CONSTRAINT sub_workflow_runs_node_id_len_check CHECK (char_length(parent_node_id) <= 120),
    CONSTRAINT sub_workflow_runs_error_class_len_check CHECK (char_length(error_class) <= 512),
    CONSTRAINT sub_workflow_runs_duration_check CHECK (duration_ms >= 0)
);

-- "How often / how recently did THIS child run?" — the readiness, hygiene and
-- reuse questions P2 will ask, and the one `count_for_children_since` asks now.
CREATE INDEX IF NOT EXISTS sub_workflow_runs_child_started_idx
    ON sub_workflow_runs (child_workflow_id, started_at DESC);
-- "What did THIS parent execution dispatch?" — `get_execution_lineage`.
CREATE INDEX IF NOT EXISTS sub_workflow_runs_parent_execution_idx
    ON sub_workflow_runs (parent_execution_id);
-- Tenant-scoped listing and the `since()` floor.
CREATE INDEX IF NOT EXISTS sub_workflow_runs_user_started_idx
    ON sub_workflow_runs (user_id, started_at DESC);
-- Nothing else until a reader measures a need.

-- ── RLS ─────────────────────────────────────────────────────────────────────
--
-- From the FIRST migration, not after the fact. `workflow_executions_archive`
-- shipped without it and held real tenant ciphertext for as long as it held
-- rows (#748); this table holds tenant metadata from its first INSERT.
--
-- POLICY SHAPE — copied clause-for-clause from
-- `20260904210000_rls_workflow_executions_archive.sql`, not re-derived:
--
--   * `NULLIF(current_setting(...), '') IS NULL` → permissive when unset. The
--     WRITER is the engine's dispatch path and the retention purge is a
--     background sweep; neither sets the GUC, so without this clause the
--     ledger could not be written at all. Same transition posture as both
--     execution tiers.
--   * `user_id = app.current_user_id` → the owner sees their own child runs.
--   * `EXISTS (SELECT 1 FROM workflows w WHERE w.id = parent_workflow_id AND
--     w.org_id = ANY(app.current_org_ids))` → a child run's TENANT is its
--     PARENT WORKFLOW's org, exactly as an execution's tenant is its
--     workflow's org. The parent, not the child, because the run belongs to
--     the parent's execution; both are visible only to the same `user_id`
--     anyway (`get_sub_workflow_graph(sub_wf_id, user_id)` is the only way a
--     child graph is loaded). If the parent workflow was deleted the EXISTS is
--     false and only the owner clause matches — the same correct outcome the
--     archive policy documents.
--
-- WITH CHECK mirrors `20260602120000`'s clause: a write must be owned by the
-- acting user, with the same unset→permit transition clause so the engine's
-- un-wired write path works.

ALTER TABLE sub_workflow_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE sub_workflow_runs FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS sub_workflow_runs_tenant_isolation ON sub_workflow_runs;
CREATE POLICY sub_workflow_runs_tenant_isolation ON sub_workflow_runs
USING (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    OR EXISTS (
        SELECT 1
        FROM workflows w
        WHERE w.id = sub_workflow_runs.parent_workflow_id
          AND w.org_id = ANY(
              string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[]
          )
    )
)
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
);
