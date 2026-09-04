-- Make the worker's write-ceiling ENFORCEMENT STATE observable from the
-- controller: the `write_ceiling_enforced` / `write_ceiling_strict_egress`
-- columns.
--
-- WHY: `actors.max_write_ceiling` ('readonly'|'write') is set by the operator
-- tool `set_actor_write_ceiling` and travels HMAC-bound on every JobRequest,
-- but it is ENFORCED only inside the worker process, gated on the worker-only
-- env var `TALOS_WRITE_CEILING_ENFORCED` (default OFF). Nothing reported that
-- state anywhere. So every controller-side surface that mentions the ceiling —
-- `set_actor_write_ceiling`, `get_actor_summary`, `get_my_capability_ceiling`,
-- and `security_audit` (which had no ceiling check at all) — said exactly the
-- same words on a deployment where the ceiling is a live control and on a
-- default deployment where it is decorative. Presence is not function, and the
-- function lived in a process the reporting surfaces could not see.
--
-- SEMANTICS — three-valued, and the third value is the point:
--   * NULL   = this registration did not report the field. Either a
--              pre-feature worker, or the operator CLI
--              (`register-worker-identity`), which knows nothing about a pod's
--              env. Liveness's rule applies verbatim: absence of evidence is
--              not evidence of absence. A NULL row must be reported as
--              UNKNOWN, never rolled into "not enforcing" — a summary that
--              silently counts unknown as false would re-tell the exact lie
--              this migration exists to stop.
--   * false  = the worker read the flag and it was off. The ceiling is
--              ADVISORY on that worker.
--   * true   = the worker read the flag and it was on.
--
-- `write_ceiling_strict_egress` is the SUBORDINATE sibling
-- (`TALOS_WRITE_CEILING_STRICT_EGRESS`): it restricts a read-only actor's
-- non-mutating HTTP to operator-NAMED hosts, and its own gate is
-- `enforced && strict && readonly && wildcard-admission`, so it is inert
-- whenever `write_ceiling_enforced` is false. Stored as its own column rather
-- than folded into one tri-state, because a worker at (true,false) and one at
-- (true,true) do enforce different things, and collapsing them would recreate
-- this defect one level down on the day it is fixed.
--
-- DIAGNOSTIC ONLY — MUST NEVER GATE AUTHORIZATION. Same standing, and the same
-- reasoning, as `build_version` (20260728120000): the value is deliberately NOT
-- covered by the Ed25519 proof-of-possession that authenticates the
-- registration, so a worker can report anything it likes. That is acceptable
-- precisely because nothing trusts it — it answers "what does the fleet say it
-- is doing?" and makes no trust decision. Note the direction of the residual
-- risk and that it is the harmless one: a worker could only ever LIE ITSELF
-- INTO a report of enforcement it is not performing, which makes an operator
-- MORE cautious, never less permissive at the boundary; the boundary itself is
-- the worker's own `write_ceiling_denies`, unreachable from here. Any future
-- code that BRANCHES on these columns (rather than logging or reporting them)
-- is a security regression.
--
-- WHY REGISTRATION AND NOT THE HEARTBEAT: a NATS `WorkerHeartbeat` is
-- HMAC-signed under the FLEET-SHARED `WORKER_SHARED_KEY`, so any key-holder can
-- mint one naming any worker_id — a claim attributable to nobody. Structural
-- lint check 67 forbids `talos-worker-fleet` from touching this table or
-- growing a DB dependency, for exactly that reason. Registration is a
-- proof-of-possession of the worker's OWN key. It is also the correct CLOCK:
-- the worker reads the env once at boot into a OnceLock, so a
-- registration-time report can never be staler than the enforcement it
-- describes — both change only on restart, and a restart re-registers.
--
-- Written UNCONDITIONALLY on every registration, including back to NULL, for
-- the same reason `build_version` is: the columns mean "what the LATEST
-- registration reported", and preserving a previous value across a silent
-- re-registration would leave a stale claim standing as if it were current.
--
-- NULLABLE is load-bearing: it makes the migration safe in ANY deploy order.
-- An old worker sends no field; an old controller ignores the field (the
-- request struct has no `deny_unknown_fields`). Every pre-existing row is NULL
-- and therefore reported as UNKNOWN, which is the truth about it.

ALTER TABLE worker_identities
    ADD COLUMN IF NOT EXISTS write_ceiling_enforced BOOLEAN;

ALTER TABLE worker_identities
    ADD COLUMN IF NOT EXISTS write_ceiling_strict_egress BOOLEAN;

COMMENT ON COLUMN worker_identities.write_ceiling_enforced IS
    'Worker-reported TALOS_WRITE_CEILING_ENFORCED as read at ITS boot, or NULL when the registration did not report it (pre-feature worker, or the operator CLI). NULL means UNKNOWN and must never be reported as false. DIAGNOSTIC ONLY: not covered by the registration proof-of-possession and MUST NEVER gate authorization.';

COMMENT ON COLUMN worker_identities.write_ceiling_strict_egress IS
    'Worker-reported TALOS_WRITE_CEILING_STRICT_EGRESS as read at ITS boot, or NULL when unreported. Subordinate to write_ceiling_enforced (inert when that is false), so an effective-strict-egress count must require both. DIAGNOSTIC ONLY: not covered by the registration proof-of-possession and MUST NEVER gate authorization.';
