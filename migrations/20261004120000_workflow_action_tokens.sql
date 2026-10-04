-- Action links: a capability URL that, when its owner confirms it, starts
-- ONE named workflow with ONE fixed payload. Token store for
-- /action-links/{token}.
--
-- An email or message the platform composes can carry "done", "keep",
-- "hold this time" as links. Until now the only link of that kind was the
-- approval link (execution_approval_tokens), which resumes a suspended
-- execution and can do nothing else, so every other action in a message
-- was a `mailto:` link that a capture workflow picked up on its next run.
--
-- WHO MINTS. Only the controller, from the `action_links` system node. The
-- node's configuration (written by the graph's author, not by a module)
-- names the workflows its links may start; a module's output chooses among
-- them and supplies the payload. A token row therefore records a decision
-- the author allowed and the module made, bound to the user the run
-- belonged to.
--
-- HASH-ONLY AT REST, like execution_approval_tokens and
-- ops_alert_correction_tokens: the raw 256-bit token exists only in the
-- rendered message. A read of this table yields nothing clickable.
--
-- SINGLE USE. `used_at` is CLAIMED by the apply path in one conditional
-- UPDATE before the workflow is started, so a link starts its workflow at
-- most once however many times it is submitted. A start that fails before
-- an execution exists releases the claim.
--
-- `payload` is stored as the trigger input will be
-- (workflow_executions.input_data is jsonb too). It is bounded by the
-- CHECK below; a module must not put a credential in it.
--
-- ON DELETE CASCADE from workflows: a link to a workflow that no longer
-- exists is dead, and its row should go with it. `source_execution_id`
-- carries no foreign key on purpose — executions are archived and deleted
-- on their own schedule, and a link outliving the run that minted it is the
-- normal case.

CREATE TABLE IF NOT EXISTS workflow_action_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL,
    workflow_id uuid NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    label text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 160),
    payload jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 8192),
    source_execution_id uuid,
    source_node text,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    used_at timestamptz,
    triggered_execution_id uuid
);

-- The mint path sweeps expired rows first; keep that a range scan.
CREATE INDEX IF NOT EXISTS idx_workflow_action_tokens_expiry
    ON workflow_action_tokens (expires_at);

-- "Which links did this run mint" (the node's own bound on links per run,
-- and an operator reading what a message carried).
CREATE INDEX IF NOT EXISTS idx_workflow_action_tokens_source
    ON workflow_action_tokens (source_execution_id)
    WHERE source_execution_id IS NOT NULL;
