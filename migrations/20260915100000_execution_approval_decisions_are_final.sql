-- An approval decision is FINAL (package BH, 2026-09-15).
--
-- `execution_approvals` records whether a human approved or denied a gated
-- module in a waiting execution. Two statements write the decision, both in
-- `talos-execution-repository`:
--
--   * `update_execution_approval_decision` (MCP `submit_workflow_approval`
--     and the one-click email link) — guarded `AND status = 'pending'`;
--   * `decide_execution_approval_scoped` (GraphQL `approveExecution` /
--     `denyExecution`, the web UI's approval queue) — NOT guarded.
--
-- So through GraphQL a denied approval could be re-decided as approved, and
-- the denier's `decided_by`, `decided_at` and `reason` overwritten. The UI is
-- two-step by design (decide in the approval queue, then Resume from execution
-- history, which re-evaluates the gate against the row), so the overwrite had
-- a runtime path: deny → approve the same id → resume → the gated module runs.
-- It is confined to the workflow's owner (same tenant): a finality and audit
-- defect, not a cross-tenant one. Population on the reference deployment: six
-- decided rows (2026-07-21), none pending.
--
-- The statement is fixed in Rust; this trigger is the rule's ONE home, so a
-- third writer — or a revert of the guard — cannot re-open it. A decided row's
-- four decision columns may not change; every other column may (nothing else
-- is a decision). `pending` → `approved`/`denied` is the only transition the
-- status CHECK and this trigger together allow. DELETE is not blocked: the
-- table is not an append-only audit log, and retention may remove rows.
--
-- Deliberately NOT named `trg_%_immutable`: `security_audit` counts triggers
-- with that name as audit-table immutability triggers, and this is not one.
--
-- SQLSTATE 23514 (check_violation): a decided row changing its decision is a
-- constraint violation, and callers already classify that code.

CREATE OR REPLACE FUNCTION execution_approval_decision_is_final()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status <> 'pending'
       AND (NEW.status IS DISTINCT FROM OLD.status
            OR NEW.decided_by IS DISTINCT FROM OLD.decided_by
            OR NEW.decided_at IS DISTINCT FROM OLD.decided_at
            OR NEW.reason IS DISTINCT FROM OLD.reason)
    THEN
        RAISE EXCEPTION
            'execution approval % was already %; an approval decision is final',
            OLD.id, OLD.status
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_execution_approvals_decision_final ON execution_approvals;
CREATE TRIGGER trg_execution_approvals_decision_final
    BEFORE UPDATE ON execution_approvals
    FOR EACH ROW
    EXECUTE FUNCTION execution_approval_decision_is_final();
