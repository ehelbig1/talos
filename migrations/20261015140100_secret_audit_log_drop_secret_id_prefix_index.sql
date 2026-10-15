-- `(secret_id)` alone is the leading prefix of `idx_secret_audit_log_secret_timestamp`
-- (`20261015140000`): every lookup by secret id, the foreign key's included,
-- is served by that index, and this one only cost a write per audit row
-- (`index_hygiene_tests` refuses a non-unique leading-prefix pair).
DROP INDEX IF EXISTS idx_secret_audit_secret_id;
