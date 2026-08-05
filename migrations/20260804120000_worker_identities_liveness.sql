-- Bound how long a departed worker's signing key stays in the trusted verify
-- ring: the `last_liveness_at` column.
--
-- WHY: `worker_identities.active` was written once, at boot registration, and
-- cleared only by an operator running `deactivate-worker-identity` by hand. So
-- every worker that ever registered — a CI container, a review rig, a
-- scaled-down replica, a crashed pod — left a PERMANENTLY TRUSTED Ed25519
-- signing identity behind. Observed live 2026-08-04: a throwaway review
-- container deleted hours earlier still held an active row.
--
-- WHY NOT `last_seen_at`: it is written ONLY at boot registration. There is no
-- periodic re-register, and the NATS fleet heartbeat does not touch this table
-- (in fact nothing publishes that heartbeat at all — `WorkerHeartbeat` is
-- constructed only in tests and `start_worker_management` has no call sites, so
-- the fleet view is permanently empty). Decaying trust on `last_seen_at` would
-- therefore deactivate a long-lived HEALTHY worker, which breaks job-result
-- verification fleet-wide. That is the trap; this column exists to avoid it.
--
-- SEMANTICS — the whole point is the three-valued reading, so state it plainly:
--   * NULL      = this row has NEVER demonstrated that it speaks the liveness
--                 protocol. Its liveness is UNKNOWN in both directions, so the
--                 automatic reaper MUST NOT touch it. Absence of evidence is
--                 not evidence of departure. Every row predating this migration
--                 is NULL, which is exactly why the migration is safe to deploy
--                 ahead of (or without) any worker rollout: on the day it lands,
--                 nothing is reapable.
--   * non-NULL  = the worker holding this key proved possession of it at that
--                 instant (Ed25519 proof-of-possession at
--                 `POST /internal/worker-liveness`). Silence PAST the configured
--                 window is then positive evidence of departure, because a
--                 running worker on this build pings every 60s by default.
--
-- Written ONLY by the liveness endpoint's guarded UPDATE, which can neither
-- create a row nor re-activate a deactivated one — it may only move this one
-- timestamp forward on a row that is already ACTIVE. A liveness ping therefore
-- grants no trust that registration did not already grant.
--
-- NULLABLE is load-bearing (same rationale as `build_version`): it makes the
-- migration safe in ANY deploy order. An old worker never pings and stays NULL
-- (never reaped); an old controller ignores the column entirely.

ALTER TABLE worker_identities
    ADD COLUMN IF NOT EXISTS last_liveness_at TIMESTAMPTZ;

COMMENT ON COLUMN worker_identities.last_liveness_at IS
    'Last Ed25519 proof-of-possession liveness ping for this key, or NULL if this row has never participated in the liveness protocol. NULL rows are exempt from the AUTOMATIC reaper (unknown liveness is not evidence of departure), but they are exactly the population of the separate opt-in TALOS_WORKER_IDENTITY_REAP_PRE_PROTOCOL_HOURS arm, which ages them on last_seen_at — so NULL is not unconditionally unreapable. Written only by POST /internal/worker-liveness.';

-- The reaper sweep's predicate: active rows that have participated and gone
-- silent. Partial on `active` (matching idx_worker_identities_active) because
-- the sweep never considers inactive rows, and the table is fleet-sized.
CREATE INDEX IF NOT EXISTS idx_worker_identities_liveness
    ON worker_identities (last_liveness_at)
    WHERE active AND last_liveness_at IS NOT NULL;
