-- One-click email approve/reject links for SUSPENDED confidence-gate
-- executions: token store for /approval-actions/{token}/{approve,reject}.
--
-- WHY A PARALLEL TABLE (not workflow_approval_gates):
-- Talos has two distinct approval subsystems (see CLAUDE.md / memory
-- "Two approval subsystems"):
--   * workflow_approval_gates  — CONTINUATION gates. A gate row carries
--     `continuation_workflow_id` + `payload`; approving it TRIGGERS A NEW
--     workflow (talos_continuation_trigger). Its /approvals/{token} routes
--     keep the RAW token at rest (re-displayed in the UI).
--   * execution_approvals + workflow_executions.status='waiting' — the
--     CONFIDENCE-GATE pause. `submit_workflow_approval(execution_id,
--     approved)` flips the execution_approvals row and RESUMES THE SAME
--     execution's checkpoint (talos_execution_orchestration::
--     resume_waiting_execution). No workflow_approval_gates row exists.
-- `pa-followup-approve-send` is the second kind, so bolting a token onto
-- workflow_approval_gates would misrepresent a suspended execution as a
-- continuation gate and would never resume the checkpoint. This table
-- binds tokens to the suspended EXECUTION.
--
-- Deliberately HASH-ONLY (tighter than workflow_approval_gates, which the
-- 20260608140000 migration had to retrofit with a token_hash column):
-- tokens are minted fresh per approval-request email render and never
-- re-shown, so the raw 256-bit token exists only inside the email. A DB
-- compromise leaks no clickable links. Mirrors
-- ops_alert_correction_tokens (20260720150000).
--
-- SINGLE-USE-PER-DECISION: one token per execution; the URL path segment
-- picks approve vs reject. "Already decided" is enforced by the underlying
-- execution_approvals pending-row check (a decided execution has no
-- pending row, so update_execution_approval_decision returns 0), NOT by
-- token consumption — so re-clicking either link after a decision renders
-- the uniform "already decided" page. `used_at` is observability only.
--
-- ON DELETE CASCADE ties token lifetime to the execution row.
-- workflow_executions is not an append-only / immutability-trigger table,
-- so CASCADE is safe (cf. lint 47's scope).

CREATE TABLE IF NOT EXISTS execution_approval_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id uuid NOT NULL REFERENCES workflow_executions(id) ON DELETE CASCADE,
    user_id uuid NOT NULL,
    token_hash text NOT NULL UNIQUE,
    -- Reserved-purpose column (mirrors ops_alert_correction_tokens): today
    -- always 'approve_reject'; encoding it now means a future purpose
    -- (e.g. a read-only "view" capability) cannot silently widen an
    -- already-minted approve/reject token.
    purpose text NOT NULL DEFAULT 'approve_reject',
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    used_at timestamptz
);

-- One live token per execution: re-minting for the same execution (e.g. a
-- resent notification) replaces the prior hash rather than accumulating
-- orphaned capabilities. Enables the ON CONFLICT upsert in mint.
CREATE UNIQUE INDEX IF NOT EXISTS uq_execution_approval_tokens_execution
    ON execution_approval_tokens (execution_id);

-- Opportunistic expiry cleanup runs DELETE ... WHERE expires_at < NOW()
-- on each mint; keep that a range scan.
CREATE INDEX IF NOT EXISTS idx_execution_approval_tokens_expiry
    ON execution_approval_tokens (expires_at);
