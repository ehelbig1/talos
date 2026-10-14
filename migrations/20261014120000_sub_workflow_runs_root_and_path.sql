-- `sub_workflow_runs` names the top-level execution and the node path of a
-- child run, however deep it is (2026-10-14).
--
-- A child workflow runs in-process under a SYNTHETIC execution id that names
-- no row anywhere. A direct child's row names its real parent execution in
-- `parent_execution_id`; a grandchild's row named only the synthetic id of the
-- child that ran it. So a grandchild run could not be traced back to the run
-- it belonged to, `list_executions` could not say where it ran, and the
-- retention purge's pinned-parent exemption (which looks the parent up in
-- `workflow_executions`) never matched it: a pinned run's grandchildren were
-- purged on schedule while its children were kept.
--
-- * `root_execution_id` — the top-level execution. Equal to
--   `parent_execution_id` for a direct child. NULL on rows written before
--   this migration; nothing is backfilled, because a grandchild's root cannot
--   be derived from what the row holds.
-- * `node_path` — the dispatching node labels from the top-level execution
--   down to and including `parent_node_id`, the path
--   `get_sub_workflow_output` takes. NULL on older rows. Each element is
--   capped by the writer like `parent_node_id`; the list to 64 elements
--   (`talos_workflow_engine_core::MAX_NODE_PATH_LEN`), far above the engine's
--   default nesting limit of 16.
--
-- No index: the readers that use these columns select by
-- `child_workflow_id` (indexed) and read them as values. The purge's
-- exemption probes `workflow_executions` by primary key with them.
--
-- No payload: the ledger still holds none (RFC 0012). A child run's node
-- outputs are kept in the PARENT execution's stored output.

ALTER TABLE sub_workflow_runs ADD COLUMN IF NOT EXISTS root_execution_id uuid NULL;
ALTER TABLE sub_workflow_runs ADD COLUMN IF NOT EXISTS node_path text[] NULL;

ALTER TABLE sub_workflow_runs
    DROP CONSTRAINT IF EXISTS sub_workflow_runs_node_path_len_check;
ALTER TABLE sub_workflow_runs
    ADD CONSTRAINT sub_workflow_runs_node_path_len_check
    CHECK (node_path IS NULL OR cardinality(node_path) <= 64);
