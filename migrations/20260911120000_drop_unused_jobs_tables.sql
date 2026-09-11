-- Drop the two tables that only the deleted `talos-jobs` crate ever read.
--
-- `jobs` and `dead_letter_jobs` were created by 20260329000000 for a
-- background-job queue whose processor (`JobProcessor::start_processor`) had
-- zero callers workspace-wide and whose `process_next_job` was a stub; the
-- crate is deleted in the same change. Measured on the reference fleet
-- 2026-09-11: 0 rows in each. Nothing else references either table —
-- `dead_letter_jobs.original_job_id` was the only FK and it pointed at `jobs`.
-- Dropping the tables also drops their three indexes and the RLS policies the
-- 20260529130000 org-id migration attached.
--
-- `IF EXISTS` for idempotency (a fresh database built from the baseline still
-- has both; a database where an operator already dropped them does not).
-- No CONCURRENTLY (sqlx runs migrations in a transaction).
DROP TABLE IF EXISTS dead_letter_jobs;
DROP TABLE IF EXISTS jobs;
