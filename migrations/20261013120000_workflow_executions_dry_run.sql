-- 2026-10-13: an execution row says whether its run is a DRY RUN.
--
-- Until this migration the dry-run flag lived only in the engine that
-- started the run. Two things rebuild an engine for a run that already
-- exists, and neither could know: the resume of a paused run (an approval,
-- a wait node) and crash recovery after a controller restart. Both built an
-- ordinary engine, so a rehearsal that paused came back as a real run: its
-- stubbed sends were made and its action links were minted. A retry or a
-- replay of a dry run was a real run for the same reason.
--
-- The flag is written by the INSERT that creates the row (never by a later
-- UPDATE: a crash between the two would leave a rehearsal recorded as real)
-- and is never changed afterwards. Nothing in the application updates it.
--
-- NOT NULL DEFAULT false: every existing row was started by an engine whose
-- mode is not recoverable; `false` is what each of them is treated as today,
-- so the default changes nothing for them. Adding a column with a constant
-- default rewrites no rows.
--
-- The archive carries it too: the move copies an explicit column list
-- (`ARCHIVED_EXECUTION_COLUMNS`), and the two tables are held column for
-- column identical by `archive_schema_parity_in_the_database`.
ALTER TABLE workflow_executions
    ADD COLUMN IF NOT EXISTS dry_run boolean NOT NULL DEFAULT false;
ALTER TABLE workflow_executions_archive
    ADD COLUMN IF NOT EXISTS dry_run boolean NOT NULL DEFAULT false;
COMMENT ON COLUMN workflow_executions.dry_run IS
    'TRUE when the run was started as a dry run (a rehearsal: outbound calls stubbed, no action link minted). Written once, by the INSERT that creates the row, and read by every path that rebuilds an engine for this row (resume, crash recovery, retry) or starts a new run from it (replay). Never updated.';
