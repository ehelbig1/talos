-- Backfill secrets.owner_user_id from created_by for rows where it was never set.
-- This closes a gap from early OAuth flows before the credential service was wired.
UPDATE secrets
SET owner_user_id = created_by,
    updated_at = NOW()
WHERE owner_user_id IS NULL
  AND created_by IS NOT NULL;
