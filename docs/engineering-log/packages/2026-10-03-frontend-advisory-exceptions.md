# Frontend advisories: busboy bumped, a reviewed exception for one with no fix (2026-10-03)

**Seen.** The frontend job failed on #1046 (which changes no dependency) with
11 high advisories. Two root causes:

* `@fastify/busboy` 3.2.0 (GHSA-xjh9-v7x6-24jw, GHSA-x8mw-p69m-v3mx): fixed in
  3.2.2. Lockfile-only bump of that one package (`npm update
  @fastify/busboy --package-lock-only`, 3 lines). `npm audit fix` was tried and
  REJECTED: it rewrote 622 lockfile lines.
* `braces` (GHSA-vfj7-8cjw-p6xm, stack-exhaustion DoS on deeply nested
  patterns, published 2026-09-18): **every version is affected and no patched
  release exists.** The other nine entries are packages that depend on it, all
  through `@graphql-codegen/cli` → `micromatch` → `braces` — a development tool
  that generates types from this repository's own GraphQL files. It never
  parses untrusted input and is not in the shipped bundle.

**Decision: a reviewed, expiring exception, per advisory.** The gate had no way
to accept an advisory nobody can fix, so it blocked every frontend PR until
upstream ships one. The decision moved from inline `jq` in `quality.yml` to
`scripts/frontend_audit_gate.py` (with `--self-test`, run in CI before the
decision):
* It decides per ADVISORY URL, not per package — npm lists every dependent of
  a vulnerable package as a vulnerability of its own, so one advisory appeared
  as ten entries.
* `frontend/audit-exceptions.json` names one advisory per entry with a reason
  and an `expires` date. An expired entry blocks again, which forces a
  re-review instead of a permanent waiver. An entry without an expiry is
  refused.
* Excepted advisories are printed as warnings on every run.
* The transport cases (no answer, unparseable output, an `error` object) are
  unchanged: UNKNOWN, warned, not clean.

The braces exception expires 2026-11-03.

**Checked.** Self-test: eight decision cases plus the missing-expiry refusal.
On today's audit with the bump: 1 advisory, 1 excepted, 0 blocking, exit 0. On
`main`'s lockfile (busboy unfixed) as the control: 2 blocking, exit 1.

**Stated limits.** The exception is keyed on the advisory URL; if GitHub ever
re-issues the same finding under a new id, it blocks again (the loud
direction). Whether braces is reachable by untrusted input was judged from the
dependency path, not by tracing every call.
