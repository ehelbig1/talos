-- One retention path, part 1: make the archive able to RECEIVE an execution.
--
-- Three defects, all measured on the live dev DB (2026-09-04), all of which
-- make `workflow_executions_archive` structurally unable to hold a row:
--
--  1. COLUMN PARITY. `workflow_executions` has 32 columns, the archive 25.
--     The archive was created `LIKE workflow_executions INCLUDING ALL`
--     (20260314000500) and then hand-mirrored three times (20260320000000,
--     20260323000000, 20260323000100). Every column added from
--     20260326000002_add_execution_lineage.sql onward was never mirrored, so
--     the background sweep's `INSERT INTO ... SELECT *` has raised
--     "INSERT has more expressions than target columns" since 2026-03-26.
--     That is a PARSE-time error, not a row-time one: `DELETE ... WHERE false
--     RETURNING *` raises it identically. The sweep has failed on every daily
--     tick for ~5.3 months, and the caller discarded the error.
--
--     `20260320000000_sync_archive_columns.sql` already stated this failure
--     mode verbatim ("fails with a column count mismatch even when zero rows
--     are being archived") and fixed it by hand. A hand-mirrored parity with
--     no gate is a snapshot, not a check — so the code side of this change
--     stops using `SELECT *` and a DB-backed test asserts parity from now on.
--
--     (`org_id` reached the archive only because
--     20260529130000_org_id_columns.sql swept a table list that happened to
--     name it. The other seven had no such accident.)
--
--  2. THE ARCHIVE HOLDS AN FK INTO THE TABLE ROWS ARE LEAVING.
--     `workflow_executions_archive_replayed_from_id_fkey` references
--     `workflow_executions(id)`. Archiving a replay pair together therefore
--     fails: the parent is deleted from the live table in the same statement
--     that inserts the child, so the child's `replayed_from_id` "is not
--     present in table workflow_executions". Reproduced directly. An archive
--     must not be referentially bound to its source table — the pointer is
--     kept as a plain UUID and resolves against the archive.
--
--  3. THE LIVE SELF-FK IS `NO ACTION`, SO ONE REPLAY BLOCKS ALL RETENTION.
--     `workflow_executions_replayed_from_id_fkey` refuses to let a replay
--     PARENT be deleted while its child is still live. Reproduced. Because
--     the sweep deletes in 5000-row batches and a constraint violation aborts
--     the whole statement, a single replay pair straddling the retention
--     boundary stops every subsequent sweep — for the archival path AND for
--     the plain-DELETE cleanup that exists today. `ON DELETE SET NULL` is
--     what the archive table itself already chose in 20260320000000; it is
--     applied here to the live table for the same reason. The trade is
--     explicit: the child's pointer to an archived parent becomes NULL rather
--     than blocking retention. Under the pre-change plain DELETE that parent
--     row was destroyed outright, so no link survives today either.
--
-- Latency of the two FK defects on this fleet: 0 of 9,512 live executions
-- currently have `replayed_from_id` set, so both are latent, not live. They
-- are fixed here because `replay_execution` is a shipped tool and because
-- neither the archival sweep nor its test can work while they stand.

-- ── 1. Column parity ────────────────────────────────────────────────────────
-- Types and NULL/DEFAULT posture copied from `workflow_executions` so the
-- archive can accept any live row verbatim.
ALTER TABLE workflow_executions_archive
    ADD COLUMN IF NOT EXISTS parent_execution_id UUID,
    ADD COLUMN IF NOT EXISTS root_execution_id   UUID,
    ADD COLUMN IF NOT EXISTS output_data_enc     BYTEA,
    ADD COLUMN IF NOT EXISTS output_enc_key_id   UUID,
    ADD COLUMN IF NOT EXISTS output_data_format  SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS checkpoint_seq      BIGINT   NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS epoch               BIGINT   NOT NULL DEFAULT 0;

-- ── 2. Drop the archive's FK into the live table ────────────────────────────
ALTER TABLE workflow_executions_archive
    DROP CONSTRAINT IF EXISTS workflow_executions_archive_replayed_from_id_fkey;

-- ── 3. Live self-FK: NO ACTION → ON DELETE SET NULL ─────────────────────────
ALTER TABLE workflow_executions
    DROP CONSTRAINT IF EXISTS workflow_executions_replayed_from_id_fkey;
ALTER TABLE workflow_executions
    ADD CONSTRAINT workflow_executions_replayed_from_id_fkey
    FOREIGN KEY (replayed_from_id) REFERENCES workflow_executions(id) ON DELETE SET NULL;

-- ── 4. `archived_at` — the purge clock ──────────────────────────────────────
-- The purge leg needs a clock that is NOT `completed_at`. With both windows
-- defaulting to 30 days, "archive when completed_at is older than 30d" and
-- "purge when completed_at is older than 30d" select the same rows, so a row
-- would be purged on the same sweep that archived it and the archive tier
-- would be a no-op — which is where the platform already is. Stamping the
-- moment of the move makes EXECUTION_RETENTION_DAYS mean literally "how long
-- an archived execution is kept", and gives the archive a provenance column an
-- operator can read.
--
-- This is the one column the archive has that the live table does not; the
-- parity assertion in controller/tests/execution_retention_tests.rs knows
-- about it by name, so it stays a deliberate exception rather than drift.
ALTER TABLE workflow_executions_archive
    ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_archive_archived_at
    ON workflow_executions_archive(archived_at);
