-- N T2-N1: bind AES-GCM ciphertexts in `secrets.encrypted_value` to the
-- row's `id` via Additional Authenticated Data (AAD). An attacker with
-- write access to the secrets table previously could swap
-- `encrypted_value` bytes between two rows that share the same
-- `encryption_key_id` and reads would decrypt cleanly to the wrong
-- plaintext (ciphertext substitution).
--
-- Forward-compatibility: existing rows are v0 (no AAD). New writes
-- after this migration use v1 (AAD = secret id bytes). Reads dispatch
-- on this column. `re_encrypt_secrets` (operator-driven DEK rotation
-- pathway) upgrades v0 rows to v1 in place.
--
-- The column is NOT NULL with DEFAULT 0 so the migration is
-- non-breaking: existing rows land at version 0 and continue to read
-- via the legacy no-AAD path.

ALTER TABLE secrets
    ADD COLUMN IF NOT EXISTS encryption_format_version SMALLINT NOT NULL DEFAULT 0;

-- Defense in depth: clamp the value to known versions so a future
-- bad write can't bypass the dispatch by setting an unknown version
-- byte. v0 = legacy no-AAD; v1 = AAD-bound (secret_id as AAD).
ALTER TABLE secrets
    ADD CONSTRAINT secrets_encryption_format_version_known
    CHECK (encryption_format_version IN (0, 1));
