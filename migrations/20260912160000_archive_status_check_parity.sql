-- `workflow_executions_archive`: bring its status CHECK into parity with the
-- live table's.
--
-- The archive was created by 20260314000500 with the live table's status set
-- OF THAT DAY — ('pending', 'running', 'completed', 'failed', 'cancelled') —
-- and three later migrations widened the LIVE constraint without touching the
-- archive's: 20260314001000 (`queued`), 20260319000000 (`waiting`),
-- 20260530000000 (`resuming`); `pending` left the live set along the way.
-- Measured on the dev database 2026-09-12: live allows {running, completed,
-- failed, cancelled, queued, waiting, resuming}; the archive allows {pending,
-- running, completed, failed, cancelled}; the archive holds 2 226 rows, all
-- `completed` or `failed`.
--
-- Inert today, stated: the retention sweep moves only TERMINAL rows
-- (`status IN ('completed', 'failed', 'cancelled')`), every one of which both
-- constraints admit. It stops being inert the day any writer moves a
-- non-terminal row (an operator's manual archive, a future "archive
-- everything on decommission") — the INSERT would fail 23514 against a
-- constraint that names a status the platform retired in March. The column
-- parity between the two tables is already pinned (`ARCHIVED_EXECUTION_COLUMNS`
-- + `execution_archive_read_tests`); the constraint parity was not.
--
-- The new set is the LIVE set, verbatim: `pending` goes (no live row can carry
-- it, none of the 2 226 archived rows does), the three later statuses come in.
-- The constraint is renamed so a catalog read tells the two apart.

ALTER TABLE workflow_executions_archive DROP CONSTRAINT IF EXISTS workflow_executions_status_check;
ALTER TABLE workflow_executions_archive DROP CONSTRAINT IF EXISTS workflow_executions_archive_status_check;
ALTER TABLE workflow_executions_archive
    ADD CONSTRAINT workflow_executions_archive_status_check
    CHECK (status IN ('running', 'completed', 'failed', 'cancelled', 'queued', 'waiting', 'resuming'));
