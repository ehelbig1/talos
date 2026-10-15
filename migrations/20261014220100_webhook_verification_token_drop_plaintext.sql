-- Drop the plaintext static verification token (security review 2026-10-14,
-- F-3). 20261014220000 filled `verification_token_hash` from it; nothing reads
-- or writes the plaintext column after that change.
--
-- Deploy note: a controller built before that change SELECTs this column, so
-- during a rolling update an old pod answers a webhook delivery 500 until it
-- is replaced (a sender retries a 5xx). Rolling back to such an image needs
-- the column back, and the tokens cannot be recovered from their hashes:
-- every static-token webhook would have to be recreated.

ALTER TABLE webhook_triggers DROP COLUMN IF EXISTS verification_token;
