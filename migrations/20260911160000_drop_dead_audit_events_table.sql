-- 2026-09-11: `audit_events` has held ZERO rows since it was created
-- (20260312000700, "Persistent audit ledger") and nothing in the workspace has
-- ever written it: the execution audit ledger is the per-job HMAC hash chain
-- the WORKER writes to the S3/MinIO WORM bucket (`talos-audit-event` +
-- `talos-audit-ledger`), verified hourly by the controller's chain sweep.
-- What this table DID carry was an immutability trigger, three indexes, a row
-- in `docs/security/architecture.md` naming it "Primary security audit ledger",
-- a place in the SOC 2 evidence scripts (whose `audit_events` summary query
-- selected `details` and `created_at` — columns this table never had, so that
-- evidence query has never once executed), and a slot in structural check 47's
-- audit-table list. Every one of those described a control that did not exist.
-- Dropped for the same reason `jobs` / `dead_letter_jobs` were (20260911120000):
-- a table nobody writes is a report nobody should read.
--
-- The shared trigger FUNCTION `prevent_audit_modification` stays — the three
-- real audit tables (`auth_audit_log`, `secret_audit_log`, `admin_event_log`)
-- still carry it.
DROP TRIGGER IF EXISTS trg_audit_events_immutable ON audit_events;
DROP TABLE IF EXISTS audit_events;
