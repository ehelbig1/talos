# RFC 0009 — Migration baseline (squash checkpoint) for fresh environments

**Status:** Draft — phase 1 (tooling + verification gate) proposed here; phase 2 (cutover) gated on the phase-1 verifier being green in CI.
**Author:** Platform
**Date:** 2026-07-02
**Builds on:** the "never edit an applied migration" rule (CLAUDE.md, Migration Rules) and the isolated-DB test harness (`controller/tests/common`, lint check 43).

## TL;DR

There are **264 migrations**, and the full chain is replayed from scratch every time a fresh schema is built: a new production install, a local `make up` on an empty volume, and — the hot path — the `talos_ctl` **template** database that the test harness clones per test. This RFC adds a **baseline snapshot** (`migrations/.baseline/schema.sql`) plus a `_sqlx_migrations` **seed** so a fresh environment can apply one snapshot and then only the migrations *after* the cutpoint, instead of all 264.

It does **not** delete or edit any existing migration — the chain stays the source of truth for existing deploys and stays embedded in the binary (their checksums must remain stable). The baseline is an *additive, optional* fast path, and phase 2 (making any install path actually use it) is gated behind a CI verifier that proves baseline+seed+tail produces a schema **byte-identical** to the full chain.

## Why this is delicate (the sqlx-checksum interaction)

The controller applies migrations with the **compile-time** macro `sqlx::migrate!("../migrations")` (`controller/src/main.rs`). At runtime sqlx:

1. Reads the `_sqlx_migrations` table: `(version, description, installed_on, success, checksum, execution_time)`.
2. For each embedded migration, computes a **SHA-384** checksum of the file bytes and compares to the recorded row.
   - No row for that version → **run it**.
   - Row exists, checksum matches → **skip it**.
   - Row exists, checksum **differs** → **hard error** ("migration was previously applied but has been modified"). This is the same mechanism that makes editing an applied migration fatal.

So a baseline that coexists with `migrate!` cannot simply "load a schema and go" — sqlx would then try to run **all 264** embedded migrations against the already-populated schema and fail on the first `CREATE TABLE` that isn't `IF NOT EXISTS`. The baseline must therefore **seed `_sqlx_migrations`** with a correct `(version, checksum)` row for every migration at or before the cutpoint, computed from the *actual, unchanged* files. Then `migrate!` sees `≤ V` as applied and runs only `> V`.

### Two hard cases

1. **Checksum fidelity.** The seed's checksums must be the exact SHA-384 sqlx would compute (of the raw file bytes, no normalization). If the seed is wrong by one byte, sqlx rejects the whole run. The generator computes them from the files directly, and the verifier (below) is what proves they're right — we never hand-maintain checksums.
2. **Baseline drift.** A `pg_dump`-ed baseline can subtly differ from what the chain produces (dump ordering, default-value formatting, extension/owner noise, `search_path`). If `schema.sql` and "apply the chain" diverge, fresh installs and existing installs run on *different* schemas — the worst possible outcome. The verifier diffs both, normalized, and **fails** on any difference; the baseline is not trusted until it passes.

## Design

```
migrations/
  001_…  …  <cutpoint version V>.sql   ← frozen chain (unchanged)
  <V+1>…  …                            ← tail: still applied normally
  .baseline/
    schema.sql                          ← pg_dump --schema-only of the chain at V
    seed_sqlx_migrations.sql            ← INSERT … INTO _sqlx_migrations for every ≤ V (with real checksums)
    CUTPOINT                            ← the version V + generation metadata
  .idempotency-grandfathered            ← (existing, unrelated)
```

**Fresh-environment bootstrap (phase 2, opt-in via `TALOS_USE_SCHEMA_BASELINE=1`):**
1. `psql < migrations/.baseline/schema.sql`
2. `psql < migrations/.baseline/seed_sqlx_migrations.sql`
3. `sqlx::migrate!` runs only migrations `> V`.

**Existing deploys:** unchanged. Their `_sqlx_migrations` already records `1..N`; they never look at `.baseline/`.

## Tooling (phase 1 — this RFC)

- **`make schema-baseline`** → `scripts/generate-schema-baseline.sh`: against a disposable Postgres, runs the full chain, `pg_dump --schema-only --no-owner --no-privileges` into `.baseline/schema.sql`, emits `seed_sqlx_migrations.sql` (version + SHA-384 per file + description), and records the cutpoint. Regenerated deliberately, not on every migration.
- **`make verify-schema-baseline`** → `scripts/verify-schema-baseline.sh`: builds DB **A** (full chain) and DB **B** (baseline + seed + tail), normalizes both with `pg_dump --schema-only`, and `diff`s. Non-zero exit on any difference. This is the gate; wire it into `quality.yml` before phase 2.

Both need a live Postgres, so they run in CI / on an operator box, not in the offline pre-push hook.

## Phased rollout

- **Phase 1 (now):** land the two scripts + `make` targets + this RFC. Generate an initial baseline at the current head as `V`. Add `verify-schema-baseline` to `quality.yml`. **No install path changes** — the baseline is generated and continuously verified but not yet consumed. Value: the mechanism is proven and drift-protected before anyone depends on it.
- **Phase 2 (follow-up, separate PR):** flip the test-template build (highest-frequency replay) to `TALOS_USE_SCHEMA_BASELINE=1`, measured against the verifier. Then optionally the k3s install path.
- **Re-baselining cadence:** advance `V` to head roughly quarterly (or when the tail grows past ~50), regenerate, let the verifier confirm identity. The frozen chain below `V` never changes.

## Alternatives considered

- **Delete old migrations, keep only a squashed `0001_baseline.sql`.** Rejected: breaks every existing deploy (their `_sqlx_migrations` references versions that no longer exist → checksum-missing behavior is undefined/hostile) and violates the never-edit-applied rule. The additive baseline avoids touching the chain entirely.
- **Switch off `sqlx::migrate!` for a hand-rolled runner.** Rejected: loses the checksum-drift protection that has repeatedly caught edited-migration bugs. The seed approach keeps sqlx as the enforcer.
- **Do nothing.** Defensible today — the per-test cost is already amortized by the template clone (the chain runs once per test *process*, not per test). This RFC is worth phase 1 mainly to cap the *linear growth* (1.4 migrations/day) before the once-per-CI-run and fresh-install costs become painful, and to have the drift-proof mechanism ready.
