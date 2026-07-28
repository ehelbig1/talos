-- Controller↔worker build-identity handshake — the `build_version` column.
--
-- WHY: "are the controller and worker running the same build?" was unanswerable
-- during the 2026-07-27 signing outage without hand-comparing image digests, and
-- it cost a wrong hypothesis plus several diagnostic turns. Signed wire formats
-- are version-coupled three ways now (job dispatch #598, memory RPC #600,
-- envelope sealing), so build skew is a first-class failure mode and deserves a
-- first-class answer: a WARN at registration and a `fleet` section in
-- get_platform_info.
--
-- SEMANTICS: the worker-reported version string, same composite shape the
-- controller stamps for itself — `{cargo_pkg_version}+{git_sha}[-dirty]`, or the
-- `TALOS_VERSION` override verbatim. NULL means "a pre-handshake worker
-- registered this row" (it never sent the field), NOT "unknown build" — the two
-- are reported differently.
--
-- DIAGNOSTIC ONLY — MUST NEVER GATE AUTHORIZATION. The value is NOT covered by
-- the Ed25519 proof-of-possession that authenticates the registration, so a
-- worker can report anything it likes. That is acceptable precisely because
-- nothing trusts it: a lying worker is already excluded by the key check, and
-- this column only answers "is the fleet on one build?" — it makes no trust
-- decision. Any future code that BRANCHES on this value (rather than logging or
-- reporting it) is a security regression.
--
-- NULLABLE is load-bearing: it makes the migration safe in ANY deploy order.
-- An old worker (no field) and an old controller (ignores the field — the
-- request struct has no `deny_unknown_fields`) both keep working unchanged.

ALTER TABLE worker_identities
    ADD COLUMN IF NOT EXISTS build_version TEXT;

COMMENT ON COLUMN worker_identities.build_version IS
    'Worker-reported build string ({pkg}+{sha}[-dirty]) or NULL for a pre-handshake worker. DIAGNOSTIC ONLY: not covered by the registration proof-of-possession and MUST NEVER gate authorization.';
