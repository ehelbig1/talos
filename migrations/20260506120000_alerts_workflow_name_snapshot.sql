-- N-L: snapshot the workflow name on `workflow_alerts` rows so
-- alerts referencing deleted workflows still surface a meaningful
-- name in the operator dashboard. Pre-fix, `list_alerts` did
-- `LEFT JOIN workflows w ON w.id = a.workflow_id` and used
-- `COALESCE(w.name, 'unknown')` — when the underlying workflow row
-- was deleted, the operator saw `workflow_name: "unknown"` for
-- every post-delete alert, with no way to tie the alert back to its
-- origin.
--
-- Migration:
-- 1. Add the column nullable (a backfill from `workflows.name` runs
--    next; rows that no longer have a matching workflow stay NULL).
-- 2. Backfill existing rows where the workflow still exists. Rows
--    whose workflow has already been deleted stay NULL — the alert
--    list reader uses COALESCE(snapshot, 'unknown') so the operator
--    facing string is identical to today's behaviour for those
--    historical rows. Going forward, every new INSERT populates
--    the snapshot at creation time so the post-delete case is
--    fully covered.

ALTER TABLE workflow_alerts
    ADD COLUMN IF NOT EXISTS workflow_name TEXT;

UPDATE workflow_alerts a
SET workflow_name = w.name
FROM workflows w
WHERE w.id = a.workflow_id
  AND a.workflow_name IS NULL;
