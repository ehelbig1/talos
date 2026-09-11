-- 2026-09-11: a workflow-chain run records WHICH module execution fired it on
-- its OWN row, instead of rewriting that module row's `workflow_execution_id`.
--
-- Until this migration `talos-engine/src/workflow_chains.rs` linked the two by
-- `UPDATE module_executions SET workflow_execution_id = <chain run> WHERE id =
-- <trigger module execution>`. That column is HALF OF THE WORM LEDGER'S KEY
-- SPACE: the worker seals every audit chain under
-- `genesis_hash(workflow_execution_id, job_id)` using the ids ON THE WIRE, and
-- a standalone (module-bound webhook / push) dispatch is signed with
-- `workflow_execution_id = job_id`. Rewriting the row after the seal moved the
-- verifier's expectation away from what the worker had hashed, so every
-- module-bound dispatch that fired a chain verified as `genesis_mismatch` —
-- "possible tampering" — on `TalosAuditVerificationFailures`. Measured
-- 2026-09-11: 3 of 3 such rows in the 30-day window, and every one of the
-- fleet's post-#7xx chain failures.
--
-- The link is a fact about the CHAIN RUN (what fired it), so it lives there.
-- No foreign key, on purpose: `module_executions` rows are tombstoned and
-- retained on their own schedule (#749's rule for `parent_execution_id`), and
-- a dangling id here is a truthful "the trigger row has since been retired".
ALTER TABLE workflow_executions
    ADD COLUMN IF NOT EXISTS triggered_by_module_execution_id UUID;
ALTER TABLE workflow_executions_archive
    ADD COLUMN IF NOT EXISTS triggered_by_module_execution_id UUID;
COMMENT ON COLUMN workflow_executions.triggered_by_module_execution_id IS
    'The module execution whose completion fired this chain run (talos-engine workflow_chains). NULL for every other dispatch path. Never write module_executions.workflow_execution_id to express this link: that column is the WORM ledger genesis key the worker sealed under.';
-- Reverse lookup (which chain runs did this module execution fire) is rare and
-- the column is NULL on every non-chain row, so a partial index costs nothing
-- on the common path.
CREATE INDEX IF NOT EXISTS idx_workflow_executions_triggered_by_module_execution
    ON workflow_executions (triggered_by_module_execution_id)
    WHERE triggered_by_module_execution_id IS NOT NULL;
