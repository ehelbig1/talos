-- Phase A of "every execution gets an actor": attribute module_executions to
-- an owning actor.
--
-- Today module_executions has NO actor_id column at all, so an in-workflow
-- module run can only be tied to its owning actor indirectly, via a JOIN
-- through workflow_execution_id -> workflow_executions.actor_id. Standalone
-- module dispatch (gmail/gcal/webhook push notifications) has no actor link
-- whatsoever.
--
-- Add a nullable actor_id, populated going forward from the engine's actor for
-- in-workflow dispatch. The standalone-dispatch seams stay NULL until a later
-- phase resolves them to the user's default actor. Nullable + ON DELETE SET
-- NULL deliberately mirrors workflow_executions.actor_id (added in
-- 20260320000500); a later phase tightens both to NOT NULL once every writer
-- populates the column and the actor hard-delete question is settled.

ALTER TABLE module_executions
    ADD COLUMN IF NOT EXISTS actor_id UUID REFERENCES actors(id) ON DELETE SET NULL;

-- Backfill historical rows from the parent workflow execution's actor. Single
-- JOIN UPDATE (no per-row exception handling needed — clean equi-join, no
-- malformed-row class here). Rows with no parent workflow_execution_id, or
-- whose parent itself has a NULL actor, stay NULL.
UPDATE module_executions me
   SET actor_id = we.actor_id
  FROM workflow_executions we
 WHERE me.workflow_execution_id = we.id
   AND me.actor_id IS NULL
   AND we.actor_id IS NOT NULL;

-- Partial index, matching the workflow_executions.actor_id pattern
-- (idx_wf_executions_actor_id ... WHERE actor_id IS NOT NULL).
CREATE INDEX IF NOT EXISTS idx_module_executions_actor_id
    ON module_executions (actor_id) WHERE actor_id IS NOT NULL;
