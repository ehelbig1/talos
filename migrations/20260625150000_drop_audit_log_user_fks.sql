-- Drop the user_id foreign keys from auth_audit_log and admin_event_log.
--
-- Same class as 20260625140000 (secret_audit_log -> secrets). Both tables carry
-- the prevent_audit_modification trigger (BEFORE DELETE OR UPDATE), and both
-- declare `user_id REFERENCES users(id) ON DELETE SET NULL`. Deleting a user
-- fires the SET-NULL, which is an UPDATE on the audit row — blocked by the
-- trigger:
--
--   ERROR: Audit records are immutable — UPDATE on auth_audit_log is not
--   permitted. Audit tables are append-only by security policy.
--
-- So a user with any auth/admin audit history (every user — login writes one)
-- cannot be deleted. There is no delete-user mutation today, so this is latent
-- — but any future account-closure / GDPR-erasure / admin-cleanup path would
-- fail closed against it. ON DELETE SET NULL and CASCADE are both unworkable
-- with the immutability trigger; the correct shape for an append-only audit log
-- is to NOT be FK-bound to the deletable principal it records. `user_id`
-- remains a nullable historical reference; audit rows outlive the user.
ALTER TABLE auth_audit_log
    DROP CONSTRAINT IF EXISTS auth_audit_log_user_id_fkey;

ALTER TABLE admin_event_log
    DROP CONSTRAINT IF EXISTS admin_event_log_user_id_fkey;
