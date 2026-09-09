<!-- Archived narrative, moved VERBATIM out of CLAUDE.md. Do not reword: the
     digest in CLAUDE.md's "Engineering log" section points here, and
     `scripts/check-engineering-log.py` proves every removed line still
     appears here. New decisions go in CLAUDE.md first. -->

## Three artefacts that described a system that does not exist (2026-09-07)

**PRESENCE IS NOT FUNCTION at the config and documentation layer** — the class
"The verifier that could never read the ledger it verified" records one level
up. A credential, a documented variable and a checked-in snapshot each LOOKED
like the thing they named and were not it. None is a vulnerability; each is a
statement an operator acts on that has been false for weeks or months, and in
every case the artefact and the code drifted apart with nothing able to say so.

### (W1) A credential for a principal that does not exist

`docker-compose.yml` handed the WORKER `AWS_ENDPOINT_URL`,
`AWS_ACCESS_KEY_ID = ${MINIO_WORKER_USER}`, `AWS_SECRET_ACCESS_KEY`,
`AWS_DEFAULT_REGION`, `AWS_S3_FORCE_PATH_STYLE` and `MINIO_BUCKET` under the
comment *"MinIO / S3 for audit ledger"*; the Helm worker Deployment mounted the
same pair out of the bootstrap Secret as **REQUIRED** `secretKeyRef`s;
`install.sh` generated and stored them; `values.yaml` declared them;
`.env.example`, `QUICKSTART.md`, `scripts/setup-dev.sh` and `ci.yml` all
carried them; and `deploy/helm/talos/README.md` called it a *"least-privilege
worker writer"*. Three independent things were wrong at once, measured
2026-09-07:

* **The worker has no reader for those names.** `grep -rn 'AWS_\|MINIO_'
  worker/src talos-worker-runtime/src` → nothing. The worker publishes audit
  events to the NATS subject `talos.audit.ledger`; the CONTROLLER is the only
  process that writes the object store.
* **The principal does not exist.** `mc admin user list` on the live MinIO
  (READ-ONLY) returns exactly two users — `talos-controller`
  (`audit_write_only`) and `verifier-…` (`audit_read_only`). `minio-init`'s
  script issues `mc admin user add` twice and names `$$MINIO_WORKER_USER`
  nowhere; #767's `minio-provisioning` Job likewise.
* **It was a REQUIRED key for an unread value.** Unlike the `OCI_REGISTRY_*`
  refs three lines above it, the worker's `secretKeyRef` carried no
  `optional: true`, so a bootstrap Secret without those keys wedges the Pod in
  `CreateContainerConfigError`.

Removed end to end. **On upgrade an existing bootstrap Secret keeps the two
stale keys and nothing selects on them** — the only chart-wide consumer of that
Secret's CONTENT is `talos.secretChecksum`, which hashes the live Secret, so
unchanged extra keys keep the hash stable and trigger no bounce. They can be
dropped at the next rotation.

**The brief's own premise was partly refuted and the refutation matters**: the
worker DOES have an S3 code path. `talos-worker-runtime/src/context.rs` reads
`S3_ENDPOINT` / `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` / `S3_REGION` for
the `talos:core/object-storage` WIT host functions, which only the
`automation-node` (`Trusted`) world may import. Different names, different
subsystem, deliberately unset everywhere — see (W2).

**Adjacent break found in the same files and fixed here.** `scripts/setup-dev.sh`
and `.github/workflows/ci.yml` both write a `.env` naming the DEAD worker pair
and **not** `MINIO_VERIFIER_USER`/`_PASSWORD`, which #767 made a `${VAR:?}`
requirement in `docker-compose.yml`. Compose interpolation is FILE-GLOBAL —
verified empirically, `docker compose build a` on a two-service file fails on a
`:?` in service `b` — so a fresh `make setup` produced a `.env` that could not
bring the stack up at all, and `ci.yml`'s image build would have failed the
same way. Latent only because both are `workflow_dispatch`/manual paths that
have not run since #767.

### (W2) Four documented variables that configure a different subsystem

`docs/deployment.md`'s env table and its "S3 / MinIO Configuration" section
both listed `S3_ENDPOINT` / `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` /
`S3_REGION` under the sentence *"Talos uses S3-compatible object storage for
the audit ledger and module artifact storage"*. **Both halves are false and the
failure is silent**: an operator on AWS who set exactly those four gets no
error and a dark ledger. Measured: the ledger reads
`AWS_ENDPOINT_URL`/`MINIO_ENDPOINT`, `MINIO_BUCKET`, `AWS_S3_FORCE_PATH_STYLE`,
the SDK's `AWS_*` chain for the writer and `AUDIT_VERIFIER_*` for the verifier;
and NOTHING in the workspace writes a module artifact to an object store
(compiled WASM lives in `modules.wasm_bytes` and the OCI registry, and the only
`put_object` callers are the audit ledger and `talos-offhost-backup`). The
two-identities table twelve lines below was correct the whole time — the
section contradicted itself.

`docs/configuration-reference.md` already had it right (*"worker | S3 endpoint
for module host storage"*), so it is now stated to be the AUTHORITATIVE list
and `docs/deployment.md` points at it. Both files gained the region asymmetry
that neither recorded: the VERIFIER resolves `AWS_REGION`/`AWS_DEFAULT_REGION`
itself with a `us-east-1` fallback, while the WRITER takes whatever
`aws_config::load_defaults` resolves — so a deployment setting neither can have
a writer that errors on region and a verifier that quietly assumes one.

**A lint was built, MEASURED and REJECTED; `--count` stays 86.** The candidate:
*every backticked `UPPER_SNAKE` token in `docs/deployment.md`'s env tables must
be read somewhere in `.rs`, compose, helm or a script.* Run against pristine
`origin/main` it reports **2 of 49 tokens**, and neither is an `S3_*` — because
the `S3_*` four DO have a reader, just not the one the doc claimed. **The
detector is green over the entire defect it was written for**, which is the
gate-that-doesn't-gate shape (#624, checks 64/65). It reports the same 2 on the
fixed tree, so it would also ship above zero. What it DID surface is a third
instance of the class, now corrected in the doc: `GRAPHQL_MAX_DEPTH` and
`GRAPHQL_MAX_COMPLEXITY` are documented as tunables with defaults `10`/`5000`
and are **hardcoded** `limit_depth(15)` / `limit_complexity(5000)` in
`controller/src/bootstrap/services.rs` — so the name is not a knob and the
documented depth default was not even the live value. No knob was invented
(that is a behaviour change); the rows now say what is true.

### (W3) A snapshot with a regeneration command and no gate

`frontend/schema.graphql` is graphql-codegen's offline input. Measured: last
regenerated 2026-07-27 (`aa173fa9`); the compiled schema is 2030 lines against
the snapshot's 1870, a **186-line diff — 173 added, 13 removed** (the removals
are doc-comment rewordings, not dropped fields, so the brief's "additive only"
was close but not exact). Nothing in `frontend/src` queried a drifted name, so
nothing was broken — it was a snapshot that stopped being true six weeks
earlier and had no way to say so. Check 64's lesson: a sweep is a snapshot, not
a gate.

`talos_api::schema_sdl()` is now the ONE construction and both the
`dump_schema` binary and
`schema_snapshot_tests::the_checked_in_snapshot_matches_the_compiled_schema`
call it — two expressions for "the schema" is how a writer and a checker drift
apart. **Why a TEST and not a lint, argued rather than assumed**: the
comparison needs the COMPILED schema, and `scripts/lint-structural.sh` has no
Rust build on its default path (check 7's clippy is gated behind
`TALOS_LINT_CLIPPY=1` precisely because a 60-90s build is too much), so a lint
leg could only compare text to text — it could say the file exists and never
that it is current. A `#[cfg(test)] mod` inside `src/` also runs in CI's
ordinary unit job with no runner registration, so it cannot rot the way check
64's hand-maintained `tests/`-binary lists do. Mutation-proved twice: one
flipped field nullability, and the REAL pre-fix snapshot restored from `HEAD` —
both red, restore green, and the failure message prints the exact regeneration
command.

**`schema.ts` needed its OWN gate, and the measurement is why.** It has zero
direct importers but reaches 49 files through `graphql.ts`'s
`export * from "./schema"`. Pinning `schema.graphql` proves the INPUT is
current and says nothing about whether the derived output was regenerated —
and on this tree both were stale TOGETHER, which is exactly why neither
noticed. Nothing else in the frontend gate can see it: eslint EXCLUDES
`src/generated/**`, and `tsc --noEmit` only fails when some file references a
type the stale output is MISSING, so a snapshot that merely lacks new types
typechecks perfectly. `quality.yml`'s frontend job gains a
`npm run codegen && git diff --exit-code -- src/generated` step. Deliberately
NOT in `make lint-frontend`: that target skips itself when
`frontend/node_modules` is absent, and a gate that skips is not a gate.
Determinism was verified rather than assumed — codegen run from two different
starting states produced byte-identical output.

### (W4) An improvements list that contradicted its own components

Found LIVE 2026-09-07 12:03Z. The moment `pa-quality-judge` crossed RFC 0012
P2's 3-run ledger floor, `get_readiness_breakdown` scored it `54/100`,
`basis: "ledger"`, reliability `15/50` from `executions_30d: 3,
source: "sub_workflow_runs"` — and `improvements[0]` in the SAME response read
*"Execute the workflow at least once to establish reliability baseline"*,
`points_available: 50`, `measured: true`. Check 74's contradiction shape, and
both halves were computed correctly from DIFFERENT inputs: P2 moved the SCORE
onto the child-run ledger and left the ADVICE keyed on the
`workflow_executions` count, which is 0 for a sub-workflow by construction.

`build_readiness_improvements` is now a PURE function that **does not receive
that count at all** — its reliability and freshness inputs are the ones the
score was computed from and the basis says which table they came from, so a
caller cannot hand it a pair that disagrees with the score. Three more things
the same reading fixed:

* Two arms were gated on `!is_child`, so a LEDGER-measured child — back on the
  full 100-point scale — was the only kind of row scored out of 100 that was
  never told how to move 70 of those points. The gate is now
  `is_unmeasurable_child`, the same predicate #770 chose for the `below_50`
  exclusion and for the same reason.
* `points_available` is `max − score` per component. The freshness arm fired
  only at `freshness == 0.0` and offered a literal `10` where the gap is 20,
  and said nothing at `freshness == 10.0` (8-30 days old) where the gap is 10 —
  so `total_points_available` understated the real gap in both directions.
* Every reliability/freshness line now names its `source` table. Two numbers
  under one field name from two tables is how this stayed invisible.

**`CHILD_UNMEASURED_REASON` was one release behind the ledger too.** It asserts
reliability is *"read from that table and from nothing else"* — false the
moment `sub_workflow_runs` holds a row, and `get_all_readiness_scores` prints
`ledger_runs: 1` two fields above it in the same object. The per-workflow
surfaces now call `child_unmeasured_reason(ledger)`, which is three-valued: no
evidence → the constant verbatim; runs below `LEDGER_MIN_RUNS` → a sentence
that says the ledger IS a second source and the shortfall is the COUNT, not the
source; at or above the floor there is no unmeasured reason at all. The
constant is KEPT for the population-level `why` in `get_all_readiness_scores`,
where there is no one child's evidence to speak about.

Reproduced before it was fixed: the renderer was extracted PRESERVING the
pre-fix logic, the test seeded `ReadinessBasis::LedgerMeasured` at n=3 and
failed with the live sentence in the assertion output, and only then was the
logic replaced. Three mutations on the fixed tree are red (re-blinding ledger
children via `is_parent_dispatched`; the literal-10 freshness arm; the
below-floor reason reverted to the constant). `retry_warning_for` was lifted to
one home in the same pass — it is rendered BOTH as an `improvements` entry and
as `components.risk.detail.retry_warning`, and two copies of a predicate is two
answers to one question in one response.

### (W5) Check 55 stopped at the crates a background loop does not live in

The SLA-breach monitor in `controller/src/bootstrap/background.rs` decoded the
NULLABLE `workflow_sla_thresholds.notification_webhook` with
`Row::get::<String, _>(..)` inside a `tokio::spawn`ed loop. `Row::get` PANICS
on a decode failure; the NULL is not a corner case but the DOCUMENTED
API-polling configuration that migration
`20260404000001_nullable_sla_notification_webhook.sql` exists to allow. **A
panic in a spawned background task is worse than one in a request handler**:
nobody is waiting, nothing restarts it, nothing logs it beyond tokio's default
stderr line — the alerter is simply off for the process lifetime while every
surface still reports the thresholds as configured. Check 55's scope is
DB-LAYER CRATES, so it structurally could not see a controller-bin file: the
population was 5 and the check was green.

Scope widened to `controller/src/bootstrap/` + `controller/src/main.rs`, and
the qualification is measured on the same evidence the DB-layer crates were:
`r`/`row`.get("…") in those paths is a sqlx row read in **5 of 5** occurrences
and a serde_json `.get` in 0 — which is why mcp-handlers and the engine stay
OUT of scope. Run against the real pre-fix file it reports exactly those 5 and
0 on the fixed tree; two mutations (a reinstated bare read in `background.rs`,
a fresh one in `main.rs`) are reported by line.

**Note for whoever merges this**: `origin/main` advanced to #772 (RFC 0012 P3)
mid-session and independently burned the same 5 sites down with the same
warn-and-continue shape. This change carries the fix too so its own lint is
green; the merge resolution there is "take either side". #772 did NOT widen the
check, and did not touch the improvements renderer either — (W4) is still live
on `origin/main`.

**Recorded remainder, NOT fixed here: a spawned loop's death is invisible.**
Measured 2026-09-07 — `controller/src/bootstrap/` + `main.rs` hold **63**
`tokio::spawn` sites and **62** discard the `JoinHandle` outright. The
sixty-third (`spawn_catalog_missing_wasm_gauge`) collects handles only to
sequence a metrics gauge and awaits them as `let _ = h.await;`, discarding the
`JoinError` as well. There is **no `std::panic::set_hook`** anywhere in
`controller/` or `worker/`. So a panicking background loop produces one
unstructured stderr line, no metric, no audit event and no restart, and every
operator-facing surface keeps reporting the subsystem as configured. Building a
supervisor is a separate change; what this one buys is that the most likely
CAUSE of such a panic — a bare `.get` on a nullable column — can no longer be
added to that directory silently.
