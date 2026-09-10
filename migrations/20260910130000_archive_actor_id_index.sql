-- 2026-09-10 review: the lifetime execution budget (`actors.max_executions_total`)
-- is now counted over the LIVE table plus `workflow_executions_archive` by
-- `actor_id`, inside the per-actor advisory-lock admission transaction
-- (talos-workflow-repository/src/executions.rs). Before this the archive move
-- silently reset a lifetime budget after 30 days. The archive carried no
-- actor_id index, so that count would have been a sequential scan of the one
-- table designed to grow forever, held under the admission lock.
CREATE INDEX IF NOT EXISTS idx_archive_actor_id
    ON workflow_executions_archive (actor_id)
    WHERE actor_id IS NOT NULL;
