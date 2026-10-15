# 2026-10-15 — `secret_audit_log.key_hash` is not backfilled

**Context.** Migration `20261014191000` (#1301) added `secret_audit_log.key_hash`
and backfilled it with an `UPDATE` of existing rows. `trg_secret_audit_log_immutable`
(`20260408000001`) refuses every UPDATE on that table, so the migration failed on the
reference deployment ("Audit records are immutable — UPDATE on secret_audit_log is
not permitted") and `make up` stopped at migrate. CI passed: a test database holds no
audit rows, and a row trigger does not fire on zero rows.

**Decided.** `20261014191000` is removed and replaced by `20261015120000`: the same
column, index and comment, with no backfill. A follow-up migration could not help,
since the old one fails before any later one runs, and the pre-commit hook forbids
editing a migration file; the operator chose a replacement over bypassing the hook.
The old one was never recorded as applied on the reference deployment (its
`_sqlx_migrations` stops at `20261014190500`), and the schema baseline does not
include it, so nothing persistent knows its version. No later migration uses the
column. Rows written before it stay NULL and are attributed through `secret_id` while
their secret exists, as before.

**Deliberately NOT done.** Disabling the trigger around the backfill: rewriting audit
history is what the append-only policy forbids, from a migration as from anything else.

**Measured.** The replacement's statements, run on the reference database (35,900 audit rows)
inside a rolled-back transaction: ALTER, CREATE INDEX, COMMENT, column present.

**Stated limits.** A scratch test database that already applied the old version will
report it as applied but missing; recreate it with `scripts/dev-test-db.sh`. Nothing yet stops a future migration from writing to an
append-only audit table (a lint for it is proposed separately).
