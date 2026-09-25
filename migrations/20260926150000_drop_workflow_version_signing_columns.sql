-- `workflow_versions.graph_hash` / `graph_signature` (20260410100001) were
-- never written and never read: the `talos-workflow-signing` crate that was
-- meant to populate and verify them had zero callers, so the columns
-- advertised a workflow-signing control that did not exist. The crate is
-- deleted with this migration; the columns go with it.
ALTER TABLE workflow_versions DROP COLUMN IF EXISTS graph_signature;
ALTER TABLE workflow_versions DROP COLUMN IF EXISTS graph_hash;
