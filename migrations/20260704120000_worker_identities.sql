-- RFC 0010 P2 increment 4 — dynamic worker-identity registry.
--
-- The static `TALOS_WORKER_PUBLIC_KEYS` env registry (P2 inc.2/3) covers a fixed
-- fleet, but an autoscaling fleet needs workers to register their Ed25519 public
-- key at boot without an operator editing a ConfigMap. This table is that
-- registry: the controller unions these ACTIVE rows with the env registry and
-- verifies worker-signed `JobResult`/RPC against the union.
--
-- SECURITY MODEL: rows hold only PUBLIC keys — a registered key lets the
-- controller VERIFY a worker's signature, never forge one. The trust boundary is
-- therefore entirely on WRITE (who may register a row); the registration path
-- (P2 inc.4c) authenticates callers with a constant-time bearer token AND a
-- proof-of-possession signature over the request. This is NOT tenant/user data —
-- it is platform-infrastructure state, so it carries NO org_id and NO RLS (same
-- class as `encryption_keys`); it is written only by the in-cluster registration
-- endpoint / operator CLI and read only by the controller verify path.
--
-- ROTATION: a worker may hold several active keys at once (blue/green, key
-- rotation overlap) — exactly the "repeat worker_id" semantics the env registry
-- already supports. The PK is (worker_id, public_key) so re-registering the same
-- key is idempotent (ON CONFLICT), and a NEW key for an existing worker_id adds a
-- row rather than replacing — both keys verify until the old one is deactivated.

CREATE TABLE IF NOT EXISTS worker_identities (
    -- The signed, non-guest-controllable worker identity bound into every
    -- Ed25519 `JobResult`/RPC signature (job_protocol::validate_worker_id shape:
    -- A-Z a-z 0-9 . - _). NOT a UUID — operators/pods choose it (pod name, etc.).
    worker_id        TEXT        NOT NULL,
    -- Raw 32-byte Ed25519 verifying key (NOT hex) — compact and exact. Length is
    -- enforced below so a malformed key can never enter the registry.
    public_key       BYTEA       NOT NULL,
    -- Signature algorithm tag. Only Ed25519 identities live here; ephemeral
    -- X25519 sealing keys (P3/D3b) are per-execution and NEVER stored.
    key_algo         TEXT        NOT NULL DEFAULT 'ed25519',
    -- P3/D3b capability bit: does this worker speak the claim/ephemeral-sealing
    -- protocol? Lets the controller seal claim-based to capable workers and
    -- inline (legacy WSK) to the rest during a heterogeneous rollout. A worker's
    -- capability is uniform across its keys, so it is carried per-row and read
    -- per worker_id.
    supports_sealing BOOLEAN     NOT NULL DEFAULT false,
    -- Soft-retire for rotation: a deactivated key stops verifying without a
    -- DELETE (keeps an audit trail of every key a worker ever held).
    active           BOOLEAN     NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Updated on every (idempotent) re-registration — a cheap liveness signal an
    -- operator can use to reap workers that have not checked in.
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (worker_id, public_key),
    -- Belt-and-suspenders: reject anything that is not a 32-byte Ed25519 point at
    -- the DB layer, independent of the app-side validation.
    CONSTRAINT worker_identities_public_key_len CHECK (octet_length(public_key) = 32),
    CONSTRAINT worker_identities_key_algo CHECK (key_algo = 'ed25519')
);

-- Hot path: "active verifying keys for this worker_id" on every result/RPC
-- verify, and the full active-set load the controller's refresh task runs. Both
-- are covered by this partial index scoped to live keys.
CREATE INDEX IF NOT EXISTS idx_worker_identities_active
    ON worker_identities (worker_id)
    WHERE active;
