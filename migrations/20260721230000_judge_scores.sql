-- Weekly self-report quality signals — observe-only judge verdicts.
--
-- Workflows now carry observe-only judge nodes (e.g. brief_judge,
-- prep_judge) whose verdicts are attached to the parent node output as
-- `__judge_score__` / `__judge_passed__`. Node outputs are ENCRYPTED at
-- rest (per-context AEAD), so the weekly `assistant_report` node cannot
-- mine them back out with SQL. Instead the engine records each verdict
-- at evaluation time into THIS small, UNENCRYPTED metrics table — scores
-- and the pass boolean ONLY. The judge reasoning/feedback text is NEVER
-- stored here: it can quote email-derived content (DLP).
--
-- No FKs on workflow_id / node_id / execution_id: (a) the recorder is a
-- best-effort, fire-and-forget spawn — a judge node inside a nested
-- sub-workflow runs under a synthetic (non-durable) execution id that
-- would violate an execution_id FK, so we keep the columns FK-free like
-- the DLQ path; (b) tenancy for the report read comes from the
-- `JOIN workflows w ON w.id = js.workflow_id WHERE w.user_id = $1`, which
-- naturally drops rows whose workflow was deleted.
CREATE TABLE IF NOT EXISTS judge_scores (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id  uuid NOT NULL,
    node_id      uuid NOT NULL,
    execution_id uuid NOT NULL,
    score        double precision NOT NULL,
    passed       boolean NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Weekly-report query: per-workflow judge aggregates over a trailing
-- window, newest first. The report groups by workflow and windows on
-- created_at, so (workflow_id, created_at DESC) covers it.
CREATE INDEX IF NOT EXISTS idx_judge_scores_workflow_created
    ON judge_scores (workflow_id, created_at DESC);
