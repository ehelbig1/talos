<!-- Archived narrative, moved VERBATIM out of CLAUDE.md. Do not reword: the
     digest in CLAUDE.md's "Engineering log" section points here, and
     `scripts/check-engineering-log.py` proves every removed line still
     appears here. New decisions go in CLAUDE.md first. -->

## The verifier that could never read the ledger it verified (#767)

**Measured live 2026-09-06, and the shape is "presence is not function" at the
identity layer.** The WORM audit bucket has one job that needs `PutObject` and
another that needs `ListBucket`+`GetObject`, and until this change ONE identity
served both. `build_audit_s3_client` resolved credentials through
`aws_config::load_defaults` — the `AWS_*` chain — for the write path AND the
read path, and on every deployment of this platform `AWS_*` is
`MINIO_CONTROLLER_USER`, whose policy is `audit_write_only` (`s3:PutObject` and
nothing else). So: `mc ls` under those credentials answers **Access Denied**;
the bucket held **48,946** execution prefixes written since 2026-07-08 with the
newest minutes old (the WRITER works); the hourly sweep logged **37**
`audit_chain_verification_errored` lines in one hour and the controller's ENTIRE
history contained **zero** `audit_chain_verification_failed` and zero verified
chains. Chain verification had never once succeeded.

**Why nothing said so.** `record_chain_verification_outcome` incremented
`talos_audit_verification_failures_total{stage="chain"}` only on `Ok(report)`
with breaks; the `Err` arm incremented NOTHING and logged one WARN. The single
alert on that series names the gap in its own comment. `security_audit` had no
chain check at all — `audit_event_signing` signs a probe in memory,
`audit_immutability_triggers` counts `pg_trigger` rows. And the log said
`error = list_objects_v2 failed for <exec>/: service error`, because `Display`
on an `SdkError` drops the S3 code: AccessDenied, NoSuchBucket and a reset
connection are the same four words. **And the identity was only half of it** —
the sweep was also naming an id space the writer has never used, which the
population section below establishes with a live positive control.

**The two identities are now separate and the writer stays write-only.** The
verifier is `MINIO_VERIFIER_USER` under a new `audit_read_only` policy
(`s3:ListBucket` on the bucket + `s3:GetObject` on its objects; NO Put, NO
Delete), reaching the controller as `AUDIT_VERIFIER_ACCESS_KEY_ID` /
`AUDIT_VERIFIER_SECRET_ACCESS_KEY`. `talos_audit_ledger::verifier`
builds that client from an EXPLICIT `Credentials` provider with **no
`load_defaults` on the path**, so there is no environment chain for the writer's
key to be picked up from. Absent verifier credentials are `VerifierClient::
NoCredentials` — three-valued against `NoEndpoint`, because "there is no WORM
store here" and "there is one and nothing can read it" are different findings —
and the sweep then refuses to start with one ERROR rather than silently retrying
a key that cannot work. **Do not widen the writer's policy to "fix"
verification**: a writer that can also list and get is a writer that can survey
and target what it wrote.

**Failure is CLASSIFIED, and the classification decides the sweep's shape.**
`ChainVerifyErrorKind::{AccessDenied, NoSuchBucket, NotFound, Transport, Other,
NoCredentials}`, derived from the SDK's typed `ProvideErrorMetadata::code`
rather than from the rendered string, with the full chain captured via
`DisplayErrorContext`. `AccessDenied`/`NoSuchBucket`/`NoCredentials` are
DEPLOYMENT-WIDE facts — one identity, one bucket — so the 2nd..Nth jobs in a
sweep cannot answer differently; the sweep ABORTS on the first, records
`ChainSweepStats::aborted`, and emits ONE `audit_chain_sweep_aborted` ERROR
instead of up to `MAX_JOBS_PER_SWEEP` identical WARNs. `NotFound`/`Transport` are per-object and do NOT
abort. The abort flag is a CLAIM ABOUT COVERAGE in the same family as
`cap_hit`: after an abort `failed == 0 && errored == 1` is true and means
nothing.

**Instruments.** `talos_audit_chain_unverifiable_total{reason}` (all six values
PRE-SEEDED at 0 — `increase(...) > 0` over an absent series matches nothing, which
is exactly how this stayed quiet) is deliberately a SEPARATE series from
`talos_audit_verification_failures_total`: unverifiable is not verified-bad
(#578), and folding an object-store blip into the CRITICAL tamper alert would
train operators to ignore it. Two GAUGES, and they answer different questions
that disagreed for two months on this stack:
`talos_audit_chain_last_verified_ok_timestamp_seconds` (the control works) and
`talos_audit_chain_sweep_timestamp_seconds` (the loop is alive). The first is
deliberately NOT pre-seeded — a zero seed reads as 1970 and would fire every
staleness rule on a healthy cold boot — so `TalosAuditChainNeverVerified`
carries an explicit `absent()` arm and is GATED on the sweep having run, so a
deployment with no object store is not permanently red.
`TalosAuditChainUnverifiable` is `warning`, not critical: it says the CONTROL is
not working, not that the ledger is bad.

**`security_audit` gains `audit_chain_verification` (`control`, `round_trip`),
WEIGHT 0 — and the zero is argued from scratch rather than borrowed.** Of
`write_ceiling_enforcement`'s three reasons exactly ONE applies: the grade bands
are ABSOLUTE against a 100-point total (`weights_sum_to_max_score`, and
`MAX_SCORE`'s own doc block leans on a dev stack topping out at exactly
`GRADE_A`), so an eleventh weighted check would re-grade every deployment and
make every score recorded before today incomparable. Reason 1 ("default-OFF by
design") does NOT apply — the sweep defaults ON. Reason 3 ("conditional") does
NOT apply — where a ledger is written and never verified the compliance artifact
is unbacked unconditionally. The zero is not decorative: an unverifiable control
and a broken chain both render `Status::Fail` with CRITICAL, so both land in
`status_counts.fail` and in `recommendation_for`, which names failing checks by
name. The check runs the REAL verifier on the most recent terminal execution
outside the settle window (`CHAIN_SETTLE_SECS`, now shared with the sweep so the
two grade the same population), increments no counter (an operator re-running
the audit must not move a series an alert fires on), and renders five outcomes
including `NothingToVerify` split three-valued so a failed candidate query never
reads as "there is nothing to verify".

**The chart NEVER provisioned any of this, and that is fixed here too.**
`grep -rn "mc admin" deploy/` matched nothing: the MinIO StatefulSet set only
ROOT credentials, `install.sh` generated a controller user+password no `mc`
invocation ever created, and README.md called it a "least-privilege write-only
user". On a k3s deploy the bucket would not exist and the writer's key would
name no principal — the ledger dark end to end. The new `minio-provisioning`
Job (post-install/post-upgrade hook, idempotent) creates the bucket and BOTH
identities, mirroring the compose recipe. This remains **LATENT**: there is no
production environment (memory `no_production_environment`), so nothing was
observed failing this way — stated rather than dressed up.

**What was measured and NOT changed.** The compose `minio-init` container
receives `MINIO_WORKER_USER`/`_PASSWORD` and has never created that user —
`mc admin user list` on the live MinIO returns exactly ONE user. Dead env, a
separate finding, and the worker does not touch S3 (it publishes to
`talos.audit.ledger`). **CLOSED 2026-09-07** — see "A credential for a
principal that does not exist" below; the pair is gone from compose, the chart,
`values.yaml`, `install.sh`, `.env.example` and both `.env` generators, and
`mc admin user list` now returns exactly TWO users, neither of them a
worker. The GraphQL `verifyAuditChain` error message is generic
and correctly directed and is unchanged; what DID change is that it now builds
its client from the verifier identity, so the operator's on-demand path was
broken by the same defect and is fixed by the same line.

**No lint check was added and `--count` stays 86.** The obvious guard — "the
verifier must not use the writer's credentials" — has a population of ONE, which
is the bar this repo does not ship at (#765's own numbers), and the structural
answer is already stronger: a distinct env name, an explicit credentials
provider with no `load_defaults` on the path, and
`verifier_client_signs_with_the_explicit_credentials`, which drives a real
`list_objects_v2` at a one-shot TCP listener and reads the access key id out of
the SigV4 `Authorization` header the SDK actually put on the wire. That test
exists because `aws_sdk_s3::Config::credentials_provider()` is DEPRECATED and
returns `None` unconditionally, so the obvious config-readback assertion would
have passed vacuously against a client carrying no credentials at all — the
exact mutation it is there to catch.

**The fix would have made the report WORSE, and that was found by driving the
real verifier against the live store rather than by reasoning.** With
read-capable credentials the SAME execution the writer's key was denied came
back `ok=true, total_events=0` — because `verify_chain` over an EMPTY event set
answers `ok == true` (there are no gaps, no broken links and no bad signatures
in nothing). Then the id-space, measured in BOTH directions: **200 of 200**
recent ledger prefixes are `module_executions.id` and **0 of 200** are
`workflow_executions.id`, live table AND archive; **0 of 200** recent
`workflow_executions.id` appear as a prefix; **34 of 34** terminal executions
inside the sweep's own 2 h window have an empty prefix — against a WRITER that
is healthy (2,686 objects in 2 days, 49,239 / 23 MiB total). The writer keys on
the `execution_id` carried by the audit EVENT, which is the module execution;
`run_chain_verification_sweep` enumerated `workflow_executions`. So repairing
the identity alone would have turned 37 loud WARNs into 37 silent
`verified_ok`, stamped the new "last verified ok" gauge, rendered
`security_audit` PASS and kept `TalosAuditChainNeverVerified` quiet — strictly
worse than the AccessDenied, which at least logged. `ChainVerifyErrorKind::
EmptyChain` (7th reason, seeded, does NOT abort — one execution may legitimately
emit no events and the VOLUME is the finding), `ChainSweepStats::empty` counted
separately from `verified_ok`, no gauge stamp on an empty read, and the check
renders `Warn`/`NotVerified` saying *the identity is working and the prefix is
empty* so nobody chases a permission fault that no longer exists. Note
`verified_ok`'s meaning moved (it now requires ≥1 event).

**And the POPULATION is fixed in the same change, because a verifier that
enumerates an id space the writer never uses verifies nothing forever.** An
honest `empty` on 100% of rows is a report nobody can act on and a control that
still does not work — the gate-that-doesn't-gate class (#624, checks 64/65) one
level up. **The binding was ESTABLISHED, not guessed**, and the guess was wrong:
`worker/src/main.rs` builds the worker's `execution_context` as
`(req.workflow_execution_id, req.job_id, req.module_uri)`, `runtime.rs` turns
the first two into `ExecutionLedger::new(workflow_id, execution_id)`, and
`job_id` IS `module_executions.id` (`engine_dispatch_single.rs` mints it and
passes it as `ExecutionStartedContext { id: job_id, .. }`, the primary key of
the row it inserts). So the genesis pair is
`(module_executions.workflow_execution_id, module_executions.id)` — the FIRST
half is a workflow EXECUTION id, not `workflows.id`, even though the ledger
field is named `workflow_id`. **The live positive control settles it**, driving
the real `verify_execution_chain` against the live MinIO with read-capable
credentials (one temporary example binary, since deleted): the established pair
returns `ok=true total_events=1 breaks=0 sigs_checked=true` (6 of 6 sampled, 50
of 50 in a wider run); the pair a reader would GUESS from the field name
(`workflows.id`) returns `ok=false breaks=1`, a genesis mismatch on a healthy
chain; and the pre-fix sweep's own shape returns `ok=true total_events=0`.
`ChainVerifyErrorKind::EmptyChain` was therefore load-bearing for one day and is
kept: an empty prefix stays a distinct outcome whichever id space is
enumerated — but its EXPECTED frequency has inverted, and the prose says so.
Sampled 200 recent settled module executions: **0 have an empty prefix**, so a
non-zero `empty` is now a real per-job finding (the worker emitted nothing, or
its batch never reached the store) rather than the whole population.

**The ledger is keyed per JOB; the operator asks per RUN; both grains are
reported and neither is folded into the other.** `run_chain_verification_sweep`
enumerates `module_executions` through ONE query with NO join — that table
carries both halves of the pair, so the join a reader expects is not batched
away, it is unnecessary — and `roll_up_by_workflow_execution` lifts the per-job
outcomes to workflow executions with WORST OUTCOME WINS (`Failed > Errored >
Empty > VerifiedOk`, the `Ord` derive on `JobChainOutcome` IS the precedence).
One broken chain among a run's four jobs makes that run's audit trail broken,
not three-quarters clean. The summary line, the `security_audit` sweep note and
the admin `verifyAuditChain` query all carry both numbers plus
`LEDGER_KEY_SPACE`, so nobody has to guess which table an id belongs to.
`security_audit`'s round-trip check picks the most recent settled MODULE
execution and names both ids and the key space in its detail.
**`verifyAuditChain` was the THIRD surface with this defect** and was doubly
wrong — it used the caller's `workflow_executions.id` as the S3 prefix AND
`workflows.id` as the genesis half, i.e. both of the two negative controls
above. It now resolves the execution to its jobs, verifies each, and returns
per-job reports under an aggregate whose `ok` requires **at least one** verified
chain: `jobs.iter().all(..)` over an empty iterator is `true`, which is this
whole change's defect in one line.

**Cost and cap, measured rather than assumed.** The population is ~3.3x larger:
101 module executions in the sweep's own 2 h window against 32 workflow
executions, peak 150 vs 45 per 2 h bucket over 7 days, 1,342/day. A verification
is one `list_objects_v2` + one `get_object`; 50 real ones against the live store
took 1.6 s wall including process start (~30 ms each). `MAX_JOBS_PER_SWEEP` moves
500 → **2000**, restoring the ~11x headroom the old cap had and costing ~60 s of
an HOURLY tick at the cap. `cap_hit` is exactly as honest as before: the sweep
keeps no cursor, so rows the cap drops age out of the sliding window and no
later pass picks them up.

**What was measured and NOT changed.** `module_executions.workflow_execution_id`
is NULLABLE and a row without one has no genesis pair, so it cannot be verified —
measured at **0 of 48,577 rows platform-wide**, i.e. LATENT, and stated as such
rather than dressed up. It is COUNTED (`ChainSweepStats::unbound`, disclosed in
the summary and in the sweep note) rather than filtered out of sight, and that
decision needed a structural move: with the increment inside the S3-dependent
sweep loop, deleting it left **all 45 ledger tests and all 84 security-audit
tests green** (measured, not inferred). `partition_sweep_rows` returns
`(targets, unbound)` so the caller cannot obtain the targets without the count it
must disclose, and the mutation now fails. The same discipline put the sweep's
enumeration statement in `enumerate_sweep_jobs`: a DB test drives the EXACT
statement the sweep issues, because the defect was a SELECT naming the wrong
table and no amount of testing the verification logic could see it. And the
sweep still runs on the BARE POOL — a platform-wide system task with no caller
and no tenant to scope to; a tenant-scoped tx would verify one tenant's chains
and silently certify the rest.

**Adjacent fix in the same change (#765's class, one sentence over).**
`describe_disabled_retry_protection`'s zero-ceiling arm said *"even its single
first attempt can outrun the budget"* — the TRUNCATED wording — for BOTH shapes
a zero ceiling can take, because `max_retries_within_budget` returns `Some(0)`
whenever the retries=0 sequence is not `AttemptFit::Full`, which is true of a
CLAMPED single attempt too. Measured on the reference fleet 2026-09-06: that arm
fires on exactly TWO nodes and BOTH are clamped, so **2 of 2 live occurrences
were false** — and both nodes emitted the sibling `attempt-window-clamped`
finding saying *"Every configured attempt starts, but attempt 1 is CLAMPED to
118s of the 125s"* in the SAME `validate_workflow` response, five lines apart.
`NodeRetryBudget` now carries the ceiling and the single-attempt fit as one
value from one function, so a caller cannot supply a pair that disagrees, and
`zero_ceiling_reason()` has ONE home — `get_workflow_risk_assessment` carried
its own copy of the truncated wording in its `recommendation` string and now
reads the same clause.

**2026-09-07 — the first sweep that ever ran called an identical redelivery
"possible tampering".** #767 gave the verifier an identity that can read; the
FIRST completed pass then reported `jobs_scanned=102 jobs_verified_ok=101
jobs_failed=1`, and the one failure was a prefix holding ONE object whose two
lines were BYTE-IDENTICAL — same `sequence_num` 1, same `previous_hash`, same
`hash`, same `hmac_signature`, same `timestamp` — logged at ERROR as *"possible
tampering, deletion, reorder, or corruption"* and incrementing
`talos_audit_verification_failures_total{stage="chain"}`, the series whose HELP
text says "positive tamper/corruption evidence" and whose whole value is that
its steady state is 0. A false CRITICAL on the one control that exists to raise
a true one (check 69's class, on the audit control).

**Two duplicate kinds, and only one says anything about integrity.**
`verify_chain` sorted by `sequence_num` and reported `DuplicateSequence`
whenever two adjacent events shared one, WITHOUT comparing their content. Now:
BYTE-IDENTICAL (equal recomputed hash AND equal signature — hash covers every
field but the signature, so the pair is equal iff the events are) is
`ChainBreak::DuplicateDelivery`, which is REPORTED and does not clear `ok`;
CONFLICTING content stays `DuplicateSequence`, still tamper evidence, still
CRITICAL. `ChainBreak::is_tamper_evidence` is the one predicate `ok` is computed
from, so a NEW variant must decide which it is at the point it is added instead
of inheriting "break". Chain continuity was ALREADY computed over the deduped
sequence — the pre-existing `continue` left `prev_hash` and `expected_seq`
untouched — and that is recorded as a no-op rather than claimed as a fix.
`anchor_verdict` now dedupes too: without it one identical redelivery produced
TWO hard failures (`CountMismatch`, because the anchor commits 1 and the
verifier counted 2; and a phantom `MultipleAnchors`).

**The writer/verifier split is asymmetric ON PURPOSE.** `process_batch` drops an
exact duplicate that shares a batch (`talos_audit_ledger::batch_dedupe`,
`talos_audit_ledger_duplicate_deliveries_total{scope="batch"}`, one INFO line
per batch, every dropped copy still ACKed — an unacked message is redelivered
forever). It CANNOT dedupe across batches, because that means LISTING and
READING the execution's prefix and the ledger writer's S3 identity is
**write-only by design** — the read-only verifier is a separate credential
precisely so a compromised writer cannot survey what it wrote. **Do not widen
it.** Cross-batch copies are classified at the verifier instead, where the
read-only identity already belongs.

**The cause was the PRODUCER, and the population says so.** Measured over the
whole bucket 2026-09-07 (49,720 objects / 49,461 prefixes): **196 prefixes
(0.40 %) carried more than one terminal anchor — 35 byte-identical, 161
CONFLICTING**. So the verifier classification covers 18 % of the historical
population and the producer fix covers all of it. Mechanism, from the worker log
(one `Received job`, one `Job completed`, **two** `wasm-execution` spans):
`execute_job_with_full_features`' retry loop called the internal attempt
function up to `RetryPolicy::max_attempts + 1 = 4` times, and EACH attempt built
a fresh `ExecutionLedger::new(workflow_id, exec_id)` and appended its own
terminal anchor — every attempt restarting at `current_sequence = 0` and at the
deterministic genesis hash, so every attempt emitted an `execution_complete`
event claiming `sequence_num` 1. `AuditEvent::timestamp` is WHOLE SECONDS, so
two attempts inside one second are byte-identical and two either side of a
second boundary are not: **a second boundary is the whole difference between the
35 and the 161**, not any property of the transport. The object size classes
match the attempt ceiling exactly (2, 3 and 4 copies; none above 4 in the recent
population).

Now: ONE ledger per JOB, minted above the retry loop and shared by every
attempt, so the chain is one monotonic sequence over the whole job; and ONE
anchor, appended by `seal_job_audit_chain` after the last attempt. The retry
loop's four terminal exits were wrapped in a labelled block so the anchor has
exactly ONE emission site — a helper called at each of four exits is one
forgotten call site away from the defect being reintroduced. The anchor is still
EARNED, not automatic: `anchor_eligible` is set at the same point the inline
anchor used to be appended (below the wall-clock timeout's `?`), so a job killed
by the wall clock still earns nothing and keeps the deliberately-soft
`Unanchored` verdict.

**What #769 did NOT close, and it is 150 of the 196 prefixes.** The anchor is one
per DISPATCH, not one per JOB-ID. A controller-level retry re-dispatches the SAME
`job_id` (`talos-workflow-engine-nats::execute_job_with_retry`, whose own doc
notes the worker re-sees it), and each re-dispatch is a fresh
`execute_job_with_full_features` call with a fresh ledger — which is why the
ledger holds prefixes with far more copies than the in-worker ceiling of 4 (one
has ELEVEN objects written 5 s apart across 55 s). Reconstructing a prior
dispatch's ledger needs persisted state the credential-free worker cannot read.
That is the next entry.
