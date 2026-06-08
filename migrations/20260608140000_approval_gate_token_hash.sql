-- Harden approval-gate token lookup (defense-in-depth).
--
-- The /approvals/<token>/{approve,reject} handler and its preview
-- authenticate purely on the URL token. The lookup was `WHERE token = $1`
-- — a Postgres byte-level comparison on the raw secret, rather than the
-- canonical `subtle::ConstantTimeEq` discipline used for every other
-- bearer credential in the workspace (CSRF, API keys, TOTP, registry
-- signatures, webhook HMAC). A 256-bit random token makes a timing
-- side-channel impractical, but keying the indexed lookup on a non-secret
-- digest and constant-time-comparing the full token after fetch removes
-- the gap structurally.
--
-- `token_hash` is a STORED generated column so it is always derived from
-- `token` automatically — existing rows are backfilled by the column add,
-- and inserts from any code path (including pre-deploy code that doesn't
-- know about the column) stay correct with no application change. The
-- expression matches `talos_text_util::sha256_hex` byte-for-byte
-- (SHA-256 of the token's UTF-8 bytes, lowercase hex), so the application
-- can look up `WHERE token_hash = $1` using that helper.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE workflow_approval_gates
    ADD COLUMN IF NOT EXISTS token_hash TEXT
    GENERATED ALWAYS AS (encode(digest(token, 'sha256'), 'hex')) STORED;

-- Fast, non-secret-keyed lookup for the approval URL handler + preview.
CREATE INDEX IF NOT EXISTS idx_approval_gates_token_hash
    ON workflow_approval_gates (token_hash);

-- The plaintext-token lookup index is superseded by the hash index. The
-- UNIQUE constraint on `token` keeps its own implicit index, so token
-- uniqueness enforcement is unaffected.
DROP INDEX IF EXISTS idx_approval_gates_token;
