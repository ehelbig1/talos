-- RFC 0010 P2 hardening inc.2 — per-worker provisioning tokens.
--
-- The shared TALOS_WORKER_REGISTRATION_TOKEN authenticates "a legit worker
-- pod", not a specific worker_id. Inc.1's TOFU rule stops a token-holder from
-- re-binding an EXISTING worker_id, but a never-before-seen worker_id is still
-- first-come-first-served. This table closes that: an operator mints a
-- SINGLE-USE, EXPIRING token, optionally BOUND to the one worker_id it may
-- register (worker_id IS NULL = wildcard, kept for migration compatibility
-- while fleets move off the shared token; TALOS_WORKER_REG_REQUIRE_BOUND_TOKEN=1
-- flips full enforcement).
--
-- SECURITY MODEL: the raw token is shown ONCE at mint time and NEVER stored —
-- only its SHA-256 hex lands here, so a DB read cannot recover a redeemable
-- credential (the approval-gate token_hash discipline, lint check 41: no
-- raw-token equality anywhere). Redemption is a single atomic
-- UPDATE ... WHERE used_at IS NULL ... RETURNING inside the registration
-- transaction, so two racing redeems admit exactly one and a REFUSED
-- registration rolls the consumption back (a failed attempt does not burn the
-- token). Like worker_identities, this is platform-infrastructure state: no
-- org_id, no RLS; written by the operator CLI and the registration endpoint
-- only.

CREATE TABLE IF NOT EXISTS worker_provisioning_tokens (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- SHA-256 hex (64 chars) of the raw token. UNIQUE doubles as the
    -- redemption lookup index.
    token_hash        TEXT        NOT NULL UNIQUE,
    -- The one worker_id this token may register. NULL = wildcard (any
    -- worker_id, TOFU semantics) — migration compat only; refused outright
    -- when bound-token enforcement is on.
    worker_id         TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ NOT NULL,
    -- Single-use consumption marker + who redeemed it (forensics).
    used_at           TIMESTAMPTZ,
    used_by_worker_id TEXT,
    -- Operator revocation (mint mistakes, leaked token). Revoking beats
    -- deleting: the row remains as an audit record of the mint.
    revoked_at        TIMESTAMPTZ,
    -- Free-form operator note ("node-7 rack B", ticket ref, ...).
    note              TEXT,
    CONSTRAINT worker_provisioning_tokens_hash_len CHECK (char_length(token_hash) = 64)
);
