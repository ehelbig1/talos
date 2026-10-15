# Secret audit log retention

`secret_audit_log` records who did what to which secret: every create, update,
rotate and delete, and — since 2026-10-14 — one `dispatch_read` row for each
secret a dispatch is handed (`controller_read` for a read the controller makes
itself, 2026-10-15). It is **append-only**: the triggers
`trg_secret_audit_log_immutable` (UPDATE, DELETE) and
`trg_secret_audit_log_immutable_truncate` refuse any change, and the platform's
retention sweep (`cleanup_audit_logs`) answers `ImmutableByPolicy` rather than
delete a row. Nothing in the platform trims it.

So the table grows with dispatch volume, and **retention is the operator's
act**, taken deliberately and recorded. `security_audit` reports its size and
how far back it goes (`secret_audit_log_extent`).

## When to archive

When `secret_audit_log_extent` reports more history than your retention policy
keeps, or more rows than you want the database to carry. There is no default
period: an audit trail is kept as long as the obligations it serves require.

## How

1. **Export first.** The rows leave the database only into a copy you keep:

   ```bash
   psql "$DATABASE_URL" -c "\copy (SELECT * FROM secret_audit_log WHERE \"timestamp\" < '2026-01-01') TO 'secret_audit_log-before-2026-01-01.csv' CSV HEADER"
   ```

   Store the file wherever your other audit exports go (it holds key-path
   hashes, actor ids and timestamps; never a secret value).

2. **Delete, with the immutability trigger lifted for that one statement,
   inside one transaction, as a superuser:**

   ```sql
   BEGIN;
   ALTER TABLE secret_audit_log DISABLE TRIGGER trg_secret_audit_log_immutable;
   DELETE FROM secret_audit_log WHERE "timestamp" < '2026-01-01';
   ALTER TABLE secret_audit_log ENABLE TRIGGER trg_secret_audit_log_immutable;
   COMMIT;
   ```

   If anything between `BEGIN` and `COMMIT` fails, the transaction rolls back
   and the trigger is still enabled. Check afterwards:

   ```sql
   SELECT tgname, tgenabled FROM pg_trigger
   WHERE tgrelid = 'secret_audit_log'::regclass AND NOT tgisinternal;
   ```

   Both triggers must read `O` (enabled).

3. **Record it.** Note the cut-off, the row count and where the export went
   wherever your organisation records operator actions on audit data.

Do not do this from a migration: check 105 refuses a migration that rewrites an
append-only audit table, because the trigger refuses it on any database that
holds audit rows.
