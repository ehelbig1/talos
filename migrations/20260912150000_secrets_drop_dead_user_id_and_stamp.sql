-- `secrets`: drop the org-stamp trigger that would have been WRONG had it
-- ever fired, the never-written `user_id` column it keyed on, and the three
-- indexes over that column; index the two columns reads actually filter on.
--
-- Measured on the dev database 2026-09-12:
--   * `secrets.user_id` is NULL on 14 of 14 rows. Both INSERT sites
--     (`talos-secrets-manager`, create + upsert) set `created_by` and
--     `owner_user_id`; nothing writes `user_id`, nothing reads it — the only
--     reference outside `migrations/` was one test seed, updated with this.
--   * Three indexes sat on it (`idx_secrets_user_keypath (user_id, key_path)`,
--     `idx_secrets_user_name (user_id, name)`, `idx_secrets_org (org_id,
--     user_id)`) while `owner_user_id` — the column the manager's reads filter
--     on, 3 648 calls in the statistics window — had none.
--   * `trg_set_org_id` (20260529140000's M3 autostamp) fires on
--     `NEW.user_id IS NOT NULL`, so on this table it has stamped nothing since
--     May; the M2 backfill loop keyed `secrets` on `x.user_id` too and
--     backfilled nothing. `org_id` is NULL on 14 of 14.
--
-- Why the trigger is DROPPED rather than re-keyed on `owner_user_id`: for
-- `secrets`, `org_id IS NULL` is not a transition state, it is the DEFINITION
-- of a personal secret. RFC 0006 decision (b), 20260608130000: the owner pin
-- applies only to personal secrets (`org_id IS NULL`) and is SKIPPED for
-- org-shared rows (`org_id IS NOT NULL`), which are governed by the org pin
-- and membership. A stamp that wrote the owner's personal org onto every
-- personal secret would reclassify all of them as org-shared and switch the
-- owner pin OFF for exactly the rows it exists to protect. The June decision
-- supersedes the May trigger for this table; the trigger stays on actors /
-- modules / webhook_triggers, where `org_id IS NULL` carries no such meaning.
-- For the same reason there is NO backfill.
--
-- `idx_secrets_org` is replaced by `(org_id)` alone (the org arm of the
-- policy and the manager's org-scoped reads filter on it), and
-- `owner_user_id` gains the index its reads have been missing. Both are
-- created before the drops so the table is never without them.

CREATE INDEX IF NOT EXISTS idx_secrets_owner_user_id ON secrets (owner_user_id);
CREATE INDEX IF NOT EXISTS idx_secrets_org_id ON secrets (org_id);

DROP TRIGGER IF EXISTS trg_set_org_id ON secrets;

DROP INDEX IF EXISTS idx_secrets_user_keypath;
DROP INDEX IF EXISTS idx_secrets_user_name;
DROP INDEX IF EXISTS idx_secrets_org;
ALTER TABLE secrets DROP COLUMN IF EXISTS user_id;
