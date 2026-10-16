-- A message the platform sent, one row per send node that completed with the
-- notification contract's verdict (docs/notification-contract.md, "What every
-- adapter returns"). The engine writes it at node completion from the output
-- it holds in plaintext; outputs are encrypted at rest, so without this row
-- nothing can count what was sent, and a tap on an action link
-- (workflow_action_tokens.used_at) cannot be set against the message that
-- carried the link. A dry run writes nothing here.
--
-- The row names no recipient, no service address and no message text: a
-- provider word, the counts the adapter reported, and the ids that tie the
-- send to its workflow, execution and node.
--
-- No row-level policy: the writer is the engine on the pool, and the one
-- reader (the message-engagement report) joins `workflows` under the caller's
-- user id, as `judge_scores` does. A tenant-scoped reader added later brings
-- the policy with it (docs/engineering-log/DECISIONS.md, "Row security").
CREATE TABLE IF NOT EXISTS message_deliveries (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id uuid NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    -- No foreign key: an execution row moves to workflow_executions_archive,
    -- and a send stays countable after that (the same choice as
    -- workflow_action_tokens.source_execution_id).
    execution_id uuid NOT NULL,
    node_id uuid NOT NULL,
    provider text NOT NULL CHECK (char_length(provider) BETWEEN 1 AND 32),
    parts_total integer NOT NULL CHECK (parts_total BETWEEN 1 AND 64),
    parts_sent integer NOT NULL CHECK (parts_sent BETWEEN 1 AND parts_total),
    actions_sent integer NOT NULL CHECK (actions_sent BETWEEN 0 AND 1024),
    one_tap_actions integer NOT NULL CHECK (one_tap_actions BETWEEN 0 AND actions_sent),
    kept_actions integer NOT NULL CHECK (kept_actions BETWEEN 0 AND actions_sent),
    -- How the run was started (schedule, action_link, manual, test, ...): the
    -- engine's word, so a report can leave rehearsals out.
    started_by_kind text CHECK (char_length(started_by_kind) <= 32),
    sent_at timestamptz NOT NULL DEFAULT now()
);

-- The report reads one user's workflows over a window; the join to taps is by
-- execution; the reaper walks by age.
CREATE INDEX IF NOT EXISTS idx_message_deliveries_workflow_sent
    ON message_deliveries (workflow_id, sent_at DESC);
CREATE INDEX IF NOT EXISTS idx_message_deliveries_execution
    ON message_deliveries (execution_id);
CREATE INDEX IF NOT EXISTS idx_message_deliveries_sent_at
    ON message_deliveries (sent_at);

-- Readable by the platform-admin query tool: identifiers and counts only. The
-- role has no default privileges, so every new table is granted or withheld by
-- name (talos-advanced-repository/tests/admin_read_role_grants.rs).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'talos_admin_read') THEN
        RETURN;
    END IF;
    GRANT SELECT ON public.message_deliveries TO talos_admin_read;
END$$;
