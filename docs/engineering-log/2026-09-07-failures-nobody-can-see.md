<!-- Archived narrative, moved VERBATIM out of CLAUDE.md. Do not reword: the
     digest in CLAUDE.md's "Engineering log" section points here, and
     `scripts/check-engineering-log.py` proves every removed line still
     appears here. New decisions go in CLAUDE.md first. -->

## Failures nobody can see: a dead binding, and a loop that stops (2026-09-07)

Three surfaces where the platform could not SAY that something had stopped
working. Not a misleading report this time — a missing one.

### A push channel bound to a module the load cannot find

**Measured live.** Four Pub/Sub deliveries arrived (19:41Z x3, 19:57Z x1) and
every one failed with the byte-identical line
`WARN talos_google_cloud::handlers: gcp pubsub: dispatch failed
user_id=… error=load module for gcp dispatch`. Three things were wrong at once.

**(a) The log said nothing.** `error = %e` renders `Display` on an `anyhow`
chain, which prints only the OUTERMOST context — so
*"Module not found or access denied"*, the `module_id` and the `channel_uuid`
were all invisible. `{:#}` now renders the chain, the WARN carries
`channel_uuid`, and the module-load context names the channel and the module.

**(b) The module the channel names does not exist, and reading that took the
service.** The row is `integration_state (google_cloud,
watch/43773540-…)`, `value_format = 4`, so `module_id` is not readable from
psql; a temporary example binary drove the real `SecretsManager` +
`IntegrationStateService` (since deleted) and returned
`module_id = 51ff1d27-9e16-49cc-a7cf-92d7d61b495d`,
`display_name = "sandbox-monitoring"`, created 2026-07-17. That id matches **0
rows** in `modules`, has **0** `module_executions`, and appears in
`admin_event_log` **0** times — there is no record of how it went away. The
INTEGRATION row is healthy. Population: the fleet has 2 push channels
(`gmail`, `google_cloud`) and `google_calendar_watch_channels` is empty; the
gmail row binds no module, so **1 of 1 module-binding channels is dangling.**

**(c) Nothing durable was recorded, and the surface built for it was dark
because its input had never been produced.** `watch_channel_service`'s
`recent_failure` selects `event_type IN ('gcp_channel_push_rejected',
'gcp_dispatch_failed')` — and `google_calendar_audit_log` held **zero** rows of
either, ever, while carrying 18 rows for three other integrations. The cause:
`dispatch_monitoring_incident` has SIX failure exits and only TWO wrote the
audit row (signing, NATS publish). The four that fire in practice — module
load, the module-bound ceiling refusal, execution-row create, job serialise —
recorded nothing anywhere. **The fix is a wrapper, not a fifth call site**:
`dispatch_monitoring_incident` is now a thin outer over
`dispatch_monitoring_incident_inner` that writes exactly one row on any `Err`
(chain-rendered), and the two inline calls are DELETED so a failure cannot
write twice. A helper called at each exit is one forgotten call site away from
this state; a wrapper over the whole body cannot be forgotten.

**`module_name: null` was three states rendered as one**, and the read that
produced it was `.unwrap_or_default()` (check 74's shape). `module_binding` is
now four-valued — `none` (no binding) / `bound` / `missing` (set, and names
nothing this user can load — **every push fails**) / `unreadable` (the lookup
itself failed; calling that `missing` is a determinate negative over a query
that did not answer). `classify_module_binding` takes the lookup's own
`Result`, not a pre-flattened `Option`, and that is structural: with an
`Option` the classifier is correct and the CALL SITE can still hand it
`Some(HashMap::new())` on an `Err` — a one-line revert that **every test here
SURVIVES** (measured). Reading the `Result` makes the collapse a deliberate
rewrite; it does not make it impossible, and checks 74b/79b state that limit as
their own.

**What was measured and NOT changed.** `create_watch` gates the INTEGRATION
(ownership-checked) and accepts ANY `module_id` uuid, so a typo mints a
permanently-dead channel with no error and no trace — the most likely origin of
this fleet's state. Not fixed, because a correct create-time gate needs a
THREE-valued module-visibility read that does not exist: `get_module` folds
"not found" and "DB error" into one `Err` (check 79's leg (b)), and
`module_owned_by_user` has no `user_id IS NULL` arm so it DISAGREES with the
dispatch predicate about a shared catalog module — a gate on either would be a
third answer to a question that already has two. **No MCP tool lists GCP watch
channels** (grepped; `get_public_url_status` only prints prose telling the
operator to "list endpoints via the watch-channels API"), and
`get_platform_hygiene_report` / `list_workflow_triggers` do not know push
channels exist. Wiring one in would give `talos-hygiene-service` a dependency
on `talos-google-cloud`, inverting its layering. Recorded.

### A background loop can panic, or simply stop, and nothing says so

Package 20 (W5) recorded this remainder and left it. **Re-measured with a
statement-aware inventory** (`scripts/background-task-inventory.py`, added
here): `controller/src/bootstrap/` + `main.rs` hold **54** `tokio::spawn` call
sites — not 63; the difference is comment lines plus five uses of
`tokio::spawn` as a FUNCTION VALUE handed to
`async_graphql::dataloader::DataLoader::new`, which are not spawn sites — of
which **45 are loop-shaped** and exactly **one** binds the `JoinHandle` (and
discards the `JoinError`). `set_hook` occurrences in `controller/`, `worker/`
and `talos-worker-runtime/`: **0**.

**That 54 was a SCOPE, not a population — corrected 2026-09-08, one day
later.** The same statement-aware walk over `talos-*/src` as well finds **127**
further bare-spawn call sites in 34 crates, **28 of them long-lived loops**
that nothing observes. Two of those crates held the loops the controller
believed it was already supervising. A prior hand count put the library figure
at 26 across ten crates; re-measured it is **24** for those ten (one site each
in `talos-audit-ledger` and `talos-envelope-seal` is inside a `#[cfg(test)]`
module) out of the 127. The inventory script's default roots are now the whole
workspace, and its output classifies `supervised` / `handle` / `loop` /
`oneshot` per crate so the remainder is a number rather than a guess.

**Two instruments, and they answer different questions.** Both live in the new
leaf crate `talos-task-supervision`.

* `install_panic_hook(process)` — installed in BOTH binaries immediately after
  the tracing subscriber, before anything can spawn. One structured line on
  target `talos_audit`, `event_kind = "task_panicked"`, carrying `process` /
  `thread` / `location` / a control-char-scrubbed 300-char message, plus
  `talos_task_panics_total{process}`. It covers EVERY panic in the process,
  including code nothing wraps. **It cannot name the task**: a tokio worker
  thread is `tokio-runtime-worker` and the location is wherever the panic was
  raised, usually a callee. The hook must never panic itself (a double panic
  ABORTS), so the payload downcast falls back to a fixed string, the message is
  truncated on a char boundary, and the counter is constructed before the hook
  is installed.
* `spawn_supervised(BackgroundTask, fut)` — applied at **41 of the 54**
  controller sites plus **18 loops inside library crates** (7 in the first
  2026-09-08 pass, 11 more in the second — see the sub-section below; it was
  42 controller sites, one of which was a launcher — see below), and it sees
  the shape a panic hook structurally CANNOT: **a clean exit.** A
  loop that `break`s, or whose `while let Some(_) = rx.recv().await` ends
  because the channel closed, returns `Ok(())` — no panic, no stderr line, no
  trace at all, and the subsystem is off for the process lifetime while every
  status surface still reports it as configured.
  `talos_background_task_exits_total{task, outcome}`.

The **12 sites not wrapped**, named rather than counted: three one-shot startup
sweeps in `background.rs` that only LOOK like loops to a windowed scan
(`grandfather_embedding_model`, the crash-recovery sweep, the actor-memory
embedding backfill), three detached per-event tasks there, three in `main.rs`,
two in `services.rs`, and the one handle-bound compile task. Each is a one-shot
whose death is bounded to one event, and the panic hook still covers it.

**Nothing is restarted, deliberately.** Restarting a loop whose panic is
deterministic would spin, and deciding per-task whether a restart is safe is a
separate change. What this buys is that the death is SAYABLE.

**Cardinality.** `BackgroundTask` is an ENUM whose variants, labels and `ALL`
array come from ONE macro table, so the label set is closed BY THE COMPILER and
a variant that the pre-seed loop misses is not expressible — no hand-maintained
parallel list, and therefore no lint. `EXIT_OUTCOMES` was three-valued
(`panicked` / `completed` / `cancelled`): a `JoinError` is either a panic or a
cancellation, and folding an abort into "panicked" would report a deliberate
shutdown as a defect. **It is FIVE-valued from 2026-09-08** — `declined` and
`shutdown` join it; see the correction below. Every series a process can
increment is PRE-SEEDED at 0. **The `process` label
is seeded with ONE value per process** — a `{process="worker"}` series on a
controller would be a seeded combination nothing there can increment, which is
the same defect as a dead metric. **That claim was true of `process` and FALSE
of `task`, measured live 2026-09-08**: `register_metrics` walked the whole
`BackgroundTask` table regardless of caller, so the WORKER's `/metrics` carried
all 126 controller-only `(task, outcome)` pairs at 0 while the worker
supervises nothing — seeded combinations nothing in that process can ever
increment, which is check 58's own rule and the exact defect this sentence
claims to avoid. The function now takes the supervised set as a required
argument: the controller passes `BackgroundTask::ALL`, the worker passes `&[]`,
and `the_panic_hook_is_wired_in_both_binaries` pins both. The
count of series in this note was 127 (126 exits + 1 panic) per process; on the
controller it is now `BackgroundTask::ALL.len() * 5 + 1` and on the worker it
is **1**. The worker registers into
`prometheus::default_registry()` (what `get_prometheus_metrics` gathers and
`seed_circuit_breaker_series` already seeds into), so its series survives an
OTEL exporter-build failure.

**Two alerts, both `warning`, and the argument is not the refusal one.** A
refusal counter fires when the policy is WORKING; a panic in a spawned task is
never working as designed, so it has no legitimate steady state above 0 —
`TalosTaskPanic`. `TalosBackgroundTaskExited` is the same argument for the
shape the hook cannot see, and it is the one that names WHICH loop.
`warning` rather than `critical` because the blast radius is one task.
Three `promtool` cases in `observability/alerts_test.yml` (pinned
`prom/prometheus:v2.48.0`), the first of which drives permanently-zero
pre-seeded series and asserts SILENCE — the shape a healthy controller has for
its whole lifetime, and the one an ABSENT series renders identically.

**The wiring is guarded, because it is the half nothing else can see.** The
crate's own tests prove the wrapper counts and logs; they cannot prove the 41
loops go through it, and reverting one site is behaviourally identical on a
healthy process. `task_supervision_wiring_tests` pins the supervised count, the
deliberately-bare count, and the two one-per-binary call sites
(`install_panic_hook`, `register_metrics`) — all three mutations red. Check 58
cannot see any of this: it asks whether a `TalosMetrics` FIELD has an increment
site, and these collectors are not `TalosMetrics` fields at all.

### 2026-09-08 — the supervisor called two healthy returns a death, on its first boot

**And nothing above could have caught it.** One second after the first boot
under this instrument the controller logged, at ERROR on target `talos_audit`:
`background_task_exited task="worker_fleet_management" outcome="completed"` and
the same for `task="registry_sync"`. `talos_background_task_exits_total` summed
to 2 across 126 series. **Both were false, and both are the healthy state of
this fleet.** The correction below amends this entry rather than contradicting
it: the two instruments, their argument, the no-restart decision and the alert
severities all stand.

* `registry_sync` awaits `start_registry_sync_loop`, which RETURNS when
  `TALOS_REGISTRY_URL` is unset — disk seeding is the source of truth here, and
  "dormant by config is not broken".
* `worker_fleet_management` awaited a **LAUNCHER**:
  `talos_worker_fleet::start_worker_management` spawns the heartbeat listener
  and the prune loop itself and returns `Ok(())` at once. So the wrapper
  supervised a function that was never going to run long, and the two loops
  that matter were exactly as unobserved as they had been before it existed.

**The wrapper's own FIRST LIVE READING is what found this**, and that is the
part worth carrying. A wrapper over a launcher is behaviourally identical to no
wrapper: no test in this workspace could see it, the count pin was green, and
the crate's unit tests all passed. The live read after deploy is the guard
#767/#769/#771 each named for their own changes; here it earned its keep on the
day the change landed.

**`TalosBackgroundTaskExited` did not fire, and the reason is a coin-flip.**
`increase(...[15m]) > 0` read `inactive` only because both increments landed
BEFORE the first scrape, so every sample in the series was already `1` and
there was no rise to measure (verified against the live Prometheus: 40 samples,
first and last both `1`). A scrape that caught the seed would have paged on a
healthy boot. So the shipped state was an ERROR on every boot plus an alert
whose silence depended on scrape timing — check 69's class, one day old.

**Leg A — a declined start is not a stopped loop, and the TYPE says which.**
The future's `Output` moves from `()` to `TaskExit`:
`Declined(DeclineReason)` / `ShuttingDown` / `LoopEnded`. A genuine `loop {}`
with no `break` has type `!` and coerces, so **every real loop compiled
unchanged**; every body that CAN return had to say why, and the compiler
enumerated that population instead of a grep — 20 controller bodies turned out
to `break` on shutdown, plus the reaper's opt-in-flag return and the four
delegate sites. `DeclineReason` is a CLOSED enum (`not_configured` /
`feature_disabled` / `policy_not_explicit`) reaching a log FIELD, never a
label; `outcome` remains the only label added and now has five compile-time
values. `declined` and `shutdown` log at **INFO** under their own event kinds
(`background_task_declined` with the reason, `background_task_shutdown`) and
are excluded from the alert by `outcome!~"declined|shutdown"`. **`completed`
keeps everything it had** — the ERROR line and the alert — because a loop that
falls out is the finding this instrument exists for. `TaskExit::is_finding()`
is the ONE predicate the log level and the alert selector both rest on.

**`shutdown` is deliberately not folded into `declined`**, and the reason is
this entry's own class: three of the five delegate bodies (both integration
renewals and the workflow scheduler) run for the whole process lifetime and
return only on the shutdown watch. Calling that "declined" would assert they
never ran.

**Leg B — supervise the loops, not their launchers.** `WorkerFleetManagement`
is DROPPED from the enum rather than left as a series nothing can increment
(check 58's rule); `worker_fleet_heartbeat` and `worker_fleet_prune` are
supervised INSIDE `talos-worker-fleet`, which is allowed because
`talos-task-supervision` is a leaf (`prometheus` + `tokio` + `tracing`) and
check 67(b) forbids that crate only `sqlx`, `reqwest` and the identity
repository. Six more library loops joined them —
`audit_ledger_subscriber`, `envelope_seal_claim_responder`,
`envelope_seal_orphan_sweep`, `integration_state_sweeper`, and the seven
signed-RPC subscribers (one variant per subject, not one shared
`rpc_subscriber`: the whole value of the `task` label is naming WHICH loop
stopped, and a dead `talos.memory.op` subscriber times out every actor-memory
call while `talos.state.write` keeps running).

**The five "delegate" sites were not five launchers — READ, not assumed.**
Only `start_worker_management` is one. `start_registry_sync_loop` runs forever
after two config-gated returns; `gmail_renewal_task`, `channel_renewal_task`
(one shared `run_renewal_scheduler`) and `run_with_shutdown` all run for the
process lifetime and return only on shutdown.

**The guard for a re-wrapped launcher needed TWO tests, and measuring which
half each covers is the point.** The controller's count pin DOES catch the
controller half (re-wrapping the launcher moves supervised 41→42 and bare 7→6,
so it fails twice — measured). It structurally cannot see the OTHER half, the
two inner loops reverting to bare `tokio::spawn` inside `talos-worker-fleet`,
because its count is over `background.rs` alone. That half is pinned by
`the_two_fleet_loops_are_supervised_not_their_launcher` in that crate, and by
`the_fleet_launcher_is_not_supervised_here` on the controller side.

**Expected live state on this fleet after deploy**, stated so it can be read
rather than assumed: **zero** `event_kind="background_task_exited"` lines on a
healthy boot; **zero** increments at `outcome!~"declined|shutdown"`; exactly
**one** `talos_background_task_exits_total{task="registry_sync",
outcome="declined"}` with an INFO `background_task_declined
reason="not_configured"` line beside it. `worker_identity_reaper` is ENABLED
here (`TALOS_WORKER_IDENTITY_REAP_ENABLED=1`), so it runs its loop and
contributes nothing — on a fleet with that flag off it would be a SECOND
`declined`, which is why the pre-fix boot showed two false exits and not three.
The worker's `/metrics` loses all 126 exit series and keeps
`talos_task_panics_total{process="worker"} 0`.

**What was NOT done, with the reason** — SUPERSEDED the same day by the
sub-section below, which classified all 28 by reading them and supervised
eleven; the paragraph is kept because its LINT reasoning still stands.
28 long-lived library-crate loops
remain unsupervised, including six with no shutdown arm at all
(`talos-actor-policies`' policy-cache sweeper, `talos-worker-runtime`'s epoch
ticker and circuit-breaker cleanup, `talos-workflow-engine`'s rate-limit
eviction, the worker's metrics-server rate-limiter cleanup). Each needs a
`BackgroundTask` variant, a dependency edge and a return-type change in a crate
whose loop shape has to be read first; they are enumerated with their
classification in `scripts/background-task-inventory.py`'s output. **No lint
was added and `--count` stays 88**: the candidate — "a long-lived
`tokio::spawn` must go through `spawn_supervised`" — cannot tell a loop from a
one-shot textually (the inventory's 60-line window misclassifies in both
directions, and it reads 4 loop-shaped bare spawns in `background.rs` that the
wiring test correctly calls one-shots), so it would ship at 28 markers on
correct code. The in-file count pins are stronger and cost no check number.

### 2026-09-08 (second pass) — the loops the wrapper still could not see, classified by reading them

The entry above supervised the loops whose LAUNCHER the controller was
already wrapping and recorded "28 long-lived library-crate loops remain
unsupervised" as a remainder. That 28 was the inventory's WINDOW count, not
a population: classifying every one of them by reading the body gives a very
different answer, and the difference is the whole point of this pass.

**Classification of the 28, by shape rather than by window.**

| shape | n | verdict |
|---|---|---|
| (b)/(c)/(d) — a real exit path (`select!` shutdown arm, or a `Notify`-driven flush-and-break) | 8 | SUPERVISED |
| (a) — pure `loop { tick; f() }`, no exit path, CONTROLLER process | 3 | SUPERVISED for panic attribution only |
| (a) — pure ticker, WORKER process | 4 | recorded, NOT supervised |
| dead code (`talos-jobs::start_processor`, zero callers) | 1 | recorded, NOT supervised |
| window false positives (startup one-shots, per-connection, per-execution, a test-only file, a demo binary) | 12 | not loops |

**The eight with a real exit path are the ones this instrument exists for**,
and they are supervised: `bcrypt_cache_revocation_sweep` (the sweep that
bounds the MCP bearer-token revocation window),
`memory_consolidation_scheduler`, `memory_reflection_scheduler`,
`rank_training_scheduler`, `ml_disagreement_digest`, `ml_policy_evaluator`,
`ml_teacher_audit` and `dlq_batch_processor` — the last of which is the
sharpest: its `Notify` arm flushes the in-memory batch and `break`s, so a
premature stop leaves every later DLQ write dropped at the channel with no
signal anywhere. Each `break` is now `break TaskExit::ShuttingDown`, so the
compiler named the exit rather than a grep.

**The three controller-side pure tickers are supervised for ATTRIBUTION and
nothing else, and saying so is the point.** `actor_policy_cache_sweep`,
`public_url_discovery` and `engine_rate_limit_eviction` have no `break` and
no shutdown arm; their bodies have type `!`, they cannot exit cleanly, and
the only death they can have is a panic the process-wide hook ALREADY
counts. What the wrapper adds is a `task` label instead of
`tokio-runtime-worker`. That is worth exactly the one line it cost — the bar
the brief set — and it must not be read as closing a silent-death gap those
three do not have.

**The four remaining real loops are all in the WORKER and are NOT
supervised**: `talos-worker-runtime`'s circuit-breaker cleanup
(`circuit_breaker.rs:325`) and epoch ticker (`runtime.rs:71`), the
job-idempotency sweep (`worker/src/main.rs:2407`) and the metrics-server
rate-limiter cleanup (`metrics_server.rs:199`). All four are pure tickers,
so the same attribution-only argument applies — but the COST is different
and that is the deciding fact: `BackgroundTask::ALL` is what the CONTROLLER
pre-seeds, so a worker-side variant seeds five controller series nothing
there can increment, which is the exact defect the worker's
`register_metrics(.., &[])` argument was added on 2026-09-08 to remove.
Supervising them costs a PROCESS PARTITION of the shared enum, not one
line. The epoch ticker costs more again: it returns a `JoinHandle` that four
`worker/tests/kill_switch_tests.rs` cases `abort()`, and `spawn_supervised`
hands back the OUTER handle — aborting that does not stop the inner task, so
the wrapper would silently leak a ticker per test.

**`talos-jobs::start_processor` has a correct shutdown arm and zero callers
workspace-wide** — `grep -rn start_processor --include=*.rs` returns its own
definition and nothing else, and its `process_next_job` is a stub returning
`Ok(())`. Supervising dead code seeds five series nothing can increment,
which is check 58's rule read the other way, so it is recorded rather than
wrapped. The other twelve are the window's false positives and are
enumerated with their reasons in
`scripts/background-task-inventory.py`'s docstring, so the next reader
classifies none of them twice: three startup one-shots plus the
deliberately-bare fleet launcher in `background.rs`, the PER-EXECUTION
epoch-fence heartbeat in `talos-engine/src/fence.rs` (supervising it would
record one exit per workflow run), two per-SSE-connection tasks, one
per-stream SSE reader, a test-only file the `#[cfg(test)]` strip cannot see,
and a hand-run demo binary.

**The pins.** `talos-worker-fleet`'s in-crate pin covers its two loops and
`task_supervision_wiring_tests` covers `background.rs`; neither can see any
of the eleven new sites, and re-baring one is behaviourally identical on a
healthy process. Each of the ten touched files now carries a
`task_supervision_pin` module asserting its own supervised and bare spawn
counts. The COUNTING RULE has one home —
`talos_task_supervision::production_spawn_counts`, which strips everything
from the first column-0 `#[cfg(test)]` so a pin's own prose cannot vouch for
a deleted call (check 73's self-report trap) — while the ASSERTION stays in
the crate that owns the file, because only that crate knows how many of each
it should have. Stated limits, inherited by all ten: TEXTUAL and per-FILE,
so it cannot say whether a site wraps the RIGHT future or names the right
`BackgroundTask`, and it cannot see a loop moved to another file.

**Expected live state on this fleet after deploy**, so it can be read rather
than assumed. **Zero** `event_kind="background_task_exited"` ERROR lines on
a healthy boot, and zero increments at `outcome!~"declined|shutdown"` — the
2026-09-08 first-pass expectation is unchanged, because every one of the
eleven new bodies either runs forever or stops only on the shutdown watch.
`talos_background_task_exits_total` gains 55 pre-seeded series on the
CONTROLLER (11 tasks × 5 outcomes) and **none on the worker**, which still
passes `&[]`. Three of the eleven are config-gated ABOVE their spawn and
their series therefore sit at 0 on a deployment that has not enabled them —
`memory_consolidation_scheduler` / `memory_reflection_scheduler`
(`ENABLE_MEMORY_CONSOLIDATION`), `rank_training_scheduler`
(`ENABLE_ADAPTIVE_RANK_TRAINING`) and `public_url_discovery`
(`TALOS_NGROK_API_URL`). That is NOT check 58's defect: this process can
leave that state by configuration, unlike a `{process="worker"}` label on a
controller. The gate was deliberately left ABOVE the spawn rather than moved
inside the body to manufacture a `Declined` — each already logs an INFO
saying it was not spawned, and moving it would be a behaviour change bought
for a nicer-looking series.

**No lint was added and `--count` stays 88.** The candidate is the one the
entry above already measured and rejected — "a long-lived `tokio::spawn`
must go through `spawn_supervised`" — and this pass makes the rejection
sharper rather than weaker: of the 28 rows the 60-line window called loops,
**13 were false positives (46%)**, so a lint on that signal would ship at
thirteen markers on correct code and would still miss a loop whose `loop {`
sits past the window. The per-file count pins are stronger, cost no check
number, and were mutation-proved (see below).

### The scheduler refusal counter: six survivors, not one

Package 24 recorded ONE surviving mutation on `talos_dispatch_refused_total`.
**No such series exists** — the instrument is
`talos_scheduler_dispatches_total{phase,outcome}`, written through one
`record_dispatch` helper — and deleting each of its **17** call sites in turn
found **SIX** survivors, while the `denied` site the note points at was already
caught. The two existing guards cover different things and neither covers the
six: `record_dispatch_moves_every_seeded_series` drives the WRAPPER, which is
exactly the property that stays true when every call site is deleted (check
58's stated wrapper limit); `every_terminal_path_records_an_outcome` is
anchored on a bare `return;`, and two of the six are the neighbour-vouching
limit that test DOCUMENTS actually happening, while the other four — the
wall-clock-timeout arm and the three tail arms (`completed`, `fenced`, the
terminal `failed`) — reach their end with no `return;` at all.

`every_recording_site_is_still_there` pins the per-outcome call-site count
(`completed 1, failed 10, skipped 3, denied 2, fenced 1`) plus a tripwire that
every call in the region is enumerated. **Re-running all 17 mutations against
it: 17 caught, 0 survivors.** One thing measured rather than reasoned: the
tripwire's first version counted `record_dispatch(` and read 18 on a HEALTHY
tree, because the function's own DEFINITION sits inside the scanned region.

**"The other pre-seeded paths" — the number is 29, and they are RECORDED.**
`talos-metrics` pre-seeds 29 collectors; mutation-testing all of them is ~80
build+test cycles and was not attempted. What WAS measured, in the same crate
and therefore cheap: all three `scheduler_readiness_*` publish sites SURVIVE
their own deletion — the pure `decide_hold` is well tested, the wiring that
publishes it is not. **CLOSED 2026-09-08 — see the sub-section below.** The cheap substitute ("does any file referencing the
collector contain an assertion") was built and REJECTED: it answers yes for 28
of 29, i.e. it only proves the file has tests somewhere. A grep cannot answer
"would deleting this call site turn a test red"; only mutation can.

**No lint check was added and `--count` stays 88.** Two candidates were
considered and both are answered structurally instead. "A long-lived
`tokio::spawn` must go through `spawn_supervised`" has a population of 54 in
ONE file and no way to tell a loop from a one-shot textually (the 60-line
window in the inventory script misclassifies three of 45 in both directions) —
the in-file count test is stronger and costs no check number. "Every
`BackgroundTask` must be pre-seeded" is not expressible as a defect: the enum
and the seed list come from one macro table.

### 2026-09-08 — the three publish sites that survived their own deletion, and one narrowing nothing drove

Two entries above recorded MEASURED SURVIVORS and left them: all three
`scheduler_readiness_*` publish sites, and `dlq_updates`' permission
narrowing. Both are the same shape one level under check 58's stated wrapper
limit — the counter HAS an increment site and nothing asked whether anything
reaches it — and both are closed by moving the DECISION and the PUBLISH into
one function a test can drive, rather than by testing a wrapper.

**The scheduler readiness barrier.** `decide_hold` and `clear_holds_and_rearm`
are pure and well tested; the `.inc()` / `.set(1)` / `.set(0)` beside them sat
in `SchedulerService::hold_or_degrade` and `::note_fleet_visible`, which need a
pool, a module registry, a secrets manager, a worker manager, a
module-execution service and a NATS client to reach — so no unit test could
touch them and all three deletions were green. The transition AND its publish
now live in the free `readiness_hold_or_degrade` /
`readiness_note_fleet_visible` over the production atomics, and the two `&self`
methods are one-line delegates.
`the_readiness_publishers_move_the_series` installs a REAL `TalosMetrics` and
asserts on DELTAS (`set_global` is a process-wide one-shot `OnceLock`) that a
hold moves `talos_scheduler_readiness_holds_total`, that crossing the bound
sets `talos_scheduler_readiness_degraded` to 1, that an already-degraded poll
does NOT re-count, and that a visible fleet returns the gauge to 0. **All three
previously-surviving mutations are red under it.** The residual is stated
rather than implied: the one-line delegate inside each method is still
unreachable from a unit test, so deleting IT survives — the same call-site
limit checks 74b/79b state as their own, and the honest guard is the live read
of the two series after deploy.

**A flake this change INTRODUCED and closed, recorded because it was measured
rather than reasoned.** The first version of that test called
`talos_metrics::set_global` itself, and the sibling
`record_dispatch_moves_every_seeded_series` already did — under a comment
saying *"This is the only test in the crate that installs the process-global
metrics registry … keep it that way"*. `set_global` is a one-shot `OnceLock`,
so whichever test won the race installed ITS registry while the loser asserted
against a local `Arc` no production site writes to: one failure under
`cargo test --workspace`, green on every re-run of the crate alone. Both tests
now go through `installed_test_metrics()`, which RETURNS the installed global
and installs only if there is none — one ACCESSOR is a stronger rule than one
installer, and it is the rule a third such test will inherit for free.

**`dlq_updates`' permission refresh.** #779 made an unreadable refresh NARROW
to own-events-only rather than KEEP the prior set — the one outcome that
defeats a refresh whose entire purpose is to notice a revocation — and recorded
it as untested, because the decision lived inside an `async_stream::stream!`
body in a GraphQL resolver needing a schema, a broadcast channel and a live
subscription. It is now
`talos_api::schema::subscriptions::refresh_dlq_permissions`, which performs
both reads and returns the narrowed `DlqPermissions`;
`controller/tests/fail_open_gate_tests` drives it against a real database with
`organization_members` DROPPED and, separately, with
`users.is_platform_admin` RENAMED away, each with its healthy CONTROL in the
same run (a non-admin keeps its real org list; a real admin still bypasses the
filter with the list deliberately cleared so a demotion forces a re-fetch).
Two mutations are red: an `Err` arm that preserves admin visibility, and one
that returns a non-empty org set. The extraction ALSO makes the pre-fix
behaviour unrepresentable — the function has no prior set to preserve — which
is the structural half, the same move `ReadinessBasis::from_scan`'s deletion
made. Same residual: a stream body that calls it and discards the answer
survives, and that is a dataflow question rather than a textual one.

**A comment corrected in the same pass.** The block above
`PERM_REFRESH_INTERVAL_SECS` still read "on refresh failure (DB hiccup),
preserve the previous permission set rather than failing closed" — false since
#779, i.e. a comment asserting a safety property the code deliberately dropped
(#732's class). It now says what the code does and why.

**No lint check was added and `--count` stays 88.** The candidate — "a metric
publish must have a test that moves the series" — is not expressible as text:
the defect is that nothing REACHES an increment site that plainly exists,
which is check 58's own stated limit and needs a call graph rather than a
grep. The population here is four sites; the structural answer is that the
decision and the publish are now one function, and mutation is what proved it.

### 2026-09-08 — the channel nobody could see, validate, or be told was dead

Package 25 (2026-09-07) made every failed push to the dangling GCP channel write
an audit row and log the ids, and recorded three remainders WITH REASONS: no MCP
tool lists push channels, `create_watch` never validates the `module_id` it
binds, and the hygiene report does not know push channels exist. All three are
closed here, and each reason held — none was re-argued.

**What was refuted before anything changed.** The brief said the GCP watch row's
`idx_ts_1` was unused; it is `last_push_received_ms` (the storage table in
`watch.rs` says so, `upsert_row` binds it) and BOTH live watch rows carry it.
That makes the rejection of "write the module id into an index slot" STRONGER,
not weaker: all three usable slots are occupied and the fourth (`idx_int_1`) is
a `bigint`. And the brief's "GCP is the only module-binding channel" is a fact
about the FLEET, not the code — **gmail's create takes a caller-supplied
`module_id` and validated it no more than GCP did**, while its summary resolved
module names with `.unwrap_or_default()`, the exact collapse #778's
`classify_module_binding` had removed one integration over. GCal's REST create
passes a literal `None`, so its only module-binding caller is the GraphQL
`create_module_from_template`, which binds a module it created three statements
earlier — safe by CONSTRUCTION, not by validation, and one refactor away from
not being.

**The RED measurement.** On pristine `origin/main`, driving the production REST
handler: a create naming a random uuid returned `200 OK` and landed a row, with
both controls (a real module; no module at all) green. The live row that
motivated all of this — `integration_state (google_cloud, watch/43773540-…)`,
display name "sandbox-monitoring", created 2026-07-17 — names a module matching
**0** of 112 rows in `modules`, 0 `module_executions` and 0 `admin_event_log`
entries.

**The gate has ONE home**, `talos_integration_helpers::watch_binding::
check_module_binding`, because the mapping from a three-valued visibility read
to a refusal IS the decision and two copies of a decision is two answers. The
READ it consults is new: `talos_registry::module_visibility::{module_visibility,
visible_module_names}`, sited beside the dispatch-time `get_module` whose
predicate it is pinned equal to — `get_module` folds "no such row" and "the
query failed" into one `Err`, which is correct for a dispatcher and is exactly
why package 25 could not build this gate. `ModuleVisibility` is `#[must_use]`
with no `Into<Option>`, no `is_visible()` boolean and no `.ok()` (the
`ExecutionLookup` / `WorkflowDispatchLookup` shape).

**The two refusals are ONE caller sentence and TWO operator `event_kind`s.**
Splitting "no such module" from "not yours" in the reply is a module-existence
oracle for anyone who can guess a uuid (`caller_facing_unauthorized`'s argument,
#754's collapsed `write_ceiling_unreadable`). `Unreadable` is a SEPARATE,
retryable refusal at 503: refusing with "that module does not exist" while the
database is the broken thing is the determinate negative checks 74 / 79 / 81
exist to remove, and the create is still refused because a channel minted on an
unverified binding is what the gate is for. The gate runs ABOVE the create lock
and above any upstream API call, so a refusal leaves nothing behind — asserted
on ROWS, not on the returned status, because a status assertion alone passes on
a tree where the write would have failed anyway. `CreateWatchError` is a typed
enum rather than one `anyhow::Error`, so the compiler asked both GCP call sites
and both gmail ones how they render it; pre-fix every failure rendered
`500 "Failed to create watch channel"`, which is right for an internal error and
wrong for a request the caller can fix.

**Deliberately NOT gated: the RENEWAL path.** `create_fresh_watch_locked` /
`create_fresh_watch_channel_locked` re-use an already-admitted binding, and
refusing a renewal because the module was deleted meanwhile takes a LIVE watch
off the air rather than stopping a new one being created wrong — #777's resume
argument. GCal's refusal is flattened into `anyhow` rather than typed, and the
reason is measured: it has no caller for whom 400-vs-503 is actionable.

**The operator surface is ONE trait in a NEW leaf crate**,
`talos-push-channel-inventory` — `PushChannelInventory`, `PushChannelRow`, the
four-valued `ModuleBinding`, `classify_module_binding` (MOVED from
`talos-google-cloud`, not copied) and the `PushChannelInventorySet` newtype that
hides the `dyn`. It is leaf on purpose: `talos-mcp-handlers` and
`talos-hygiene-service` sit BELOW the integration crates and the edge the other
way is the layering inversion package 25 refused. It deliberately does not
depend on `talos-integration-helpers` either — that pulls in secrets-manager,
envelope-seal, memory and reqwest — so `RenewalFailure` is re-expressed as a
three-field `PushChannelFailure` and converted at each integration. **A
`PushChannelRow` carries no push token, no endpoint (the GCP endpoint embeds the
raw token) and no payload**, pinned by a unit test AND by a DB test over a real
row.

**All THREE integrations are enrolled**, including gcal, whose channel count on
this fleet is ZERO. A survey that silently covers two of three is the
misleading-report class one level up. Each impl is a POOL-ONLY struct rather
than the watch service: it can then be built whether or not that integration's
push RECEIVER is wired (a watch ROW outlives `GCP_PUBSUB_AUDIENCE`, and a
channel invisible because a receiver env var is absent is exactly the failure
being reported), and it cannot create a watch, so it can never race the create
lock. `list_rows_for_user` became a free function in each `watch.rs` and the
service method delegates, so the two readers cannot drift.

**`list_push_channels` is a tool of its own, and the default was argued.**
`list_workflow_triggers` is keyed by WORKFLOW; a push channel binds a MODULE and
carries no workflow id at all, so this fleet's one live example would have
appeared under no workflow however that tool was extended. The hygiene report
carries the FINDING; the tool carries the INVENTORY, including the healthy
channels the report deliberately says nothing about. `None` inventory renders
`channels: null, measured: false` — never `[]`.

**The hygiene section obeys "nothing to say ⇒ no key" (#762).**
`PushChannelReadout` is THREE-valued: `NotConsulted` (this process wired no
inventory — SILENCE, not zero, and it contributes nothing to `total_issues`,
which has never spoken about push channels) and `Surveyed`, which emits
`dangling_push_channels` + `push_channel_survey` only when there is a finding, an
unclassifiable binding, or an unreadable integration. A fleet whose channels are
all healthy gets a byte-identical report — pinned by a test that compares every
key. `unclassifiable` (the module lookup did not answer) is disclosed SEPARATELY
and is not counted as dangling: that would put a pool timeout in the same bucket
as a permanently dead channel. An integration whose LIST read failed goes in the
`Readings` ledger, so `total_issues` and the severity buckets NULL and
`degraded_recommendation` names the field. Severity is `critical` in BOTH the
bucket and the recommendation — a bucket and a recommendation disagreeing about
one finding is the contradiction-in-one-response class, and the first draft here
had exactly that (bucket `high`, recommendation `critical`).

**`build_report` and `HygieneService::new` both take the readout as a REQUIRED
parameter, and that is a measurement rather than taste.** With a
`with_push_channels(..)` builder, deleting the two lines in `create_router` that
called it left EVERY test in the workspace green while the report silently
stopped mentioning push channels — mutation M9, the call-site class checks 74b
and 79b name as their own limit. As a parameter the compiler asks every site.
It still cannot stop a caller answering `None`, so `push_channel_wiring_tests`
pins the wiring in `create_router`'s source (the `task_supervision_wiring_tests`
shape), with a tripwire that fails loudly if the scanned region ever vanishes.

**Eleven mutations, two initial SURVIVORS, both closed.** M4 — reverting the
classifier's argument to an already-flattened map, the one-line collapse its own
doc warns about — survived until a DB test dropped the `modules` relation and
asserted `Unreadable` rather than `Missing`. M10 — deleting gmail's gate —
survived because gmail's create calls Google and cannot be driven end to end;
closed by a test that asserts WHICH refusal comes back, with a control that gets
PAST the gate and fails downstream instead. M5 (a module name rendered beside a
`missing` binding) is recorded as a NO-OP mutation, not a survivor: the name map
cannot contain a non-`Bound` id by construction, so the guard is defence in
depth and no test can distinguish it.

**No lint check was added and `--count` stays 88.** The candidate — "a watch
create that accepts a caller-supplied `module_id` must consult the gate" — was
BUILT (`scripts/lint-watch-module-binding-candidate.sh`, kept so the numbers can
be re-derived) and MEASURED on both trees. On pristine `origin/main` it reports
**19 sites of which 3 are the real create entry points — 15.8% precision** (the
other 16 are struct fields, summary projections, admin JSON parsing, the
classifier's own signature and a test helper), and on the FIXED tree it still
reports **10, every one legitimate**, so it would ship at ten markers on correct
code. Worse, 3 of the 8 it calls "gated" are the `_locked` renewal helpers that
must NOT be gated and read as gated only because they share a file with the gate
— check 86(a)'s file-scope limit in a name-glob's clothing. The structural
answers are stronger: one `pub` gate, `ModuleVisibility` with no boolean
projection, a typed `CreateWatchError` whose `ModuleBinding` variant can only
come from the shared gate, and DB tests driving all three integrations.

**What is NOT covered, stated rather than implied.** `list_push_channels` has no
test through the production MCP `dispatch` — that needs a full `McpState`, which
this binary does not build; its pure halves (the survey, the classification, the
row's redaction) are covered by DB tests and the handler body is not. Gmail's
and gcal's `module_binding` field on their REST summaries has no test. The gcal
inventory attaches no `recent_failure` (that enrichment is a method on the full
service handle); stated on the impl rather than silently omitted. And on THIS
fleet the audit table holds **zero** `gcp_%` rows, so package 25's
`recent_failure` enrichment has nothing to show yet — `module_binding: "missing"`
is the only signal the dangling channel will produce after deploy.

### 2026-09-09 — the data plane had no instrument, and its log partition called a designed state a failure

**`record_rpc_metric` recorded no metric.** The function's NAME asserted one;
its body was two `tracing` calls. Measured live: `curl /metrics/prometheus |
grep '^talos_rpc'` returned exactly SIX series, all of them #760's
`talos_rpc_write_ceiling_refusals_total`, all at 0 — nothing counted a call, an
outcome or a latency on ANY of the seven subjects, while 1317
`module_executions` in 24 h drove the memory / database / graph ones. #760's own
entry had already MEASURED this ("`talos_rpc` is a TRACING TARGET ONLY … no RPC
counter was registered") and then added a counter for ONE outcome on THREE
subjects — the fixed-the-path-not-the-population shape this file names
repeatedly. And the gap is the other half of a question #783 closed one side of:
a subscriber that DIES is sayable (`talos_background_task_exits_total`); one
ALIVE and erroring every call was invisible in every machine-readable channel.

**The partition was binary, and its own comment described one the code did not
have.** `outcome == "ok"` -> `debug!`, everything else -> `warn!`, under a
comment reading *"Failure outcomes stay at warn!/info!"* — there was no `info!`
arm and `git log -S` shows there never had been (#732's class). Two
consequences. (a) The whole SUCCESS volume was at `debug!`, which this
deployment enables for exactly one target and it is not this one, AND uncounted
— so **zero** `rpc completed` lines exist in the controller's entire log. (b)
Every non-ok outcome was an alarm: **17 of the controller's 32 WARN lines (53%)
were ONE designed state**, `talos.ml.predict` / `not_promoted`, one per hour for
seventeen consecutive hours, unbroken, and it is the only non-ok outcome this
fleet has ever produced. The producer is identifiable: the fleet's ONLY
hourly-on-the-hour schedule classifies against the `ops-severity` model, whose
`lifecycle_state` is **`llm_only`** — the FIRST position on the documented ladder
(`llm_only -> shadow -> hybrid -> fast_primary`), where
`serve::state_serves_production` is false and every prediction falls back to the
LLM by construction. `MlRpcError::NotPromoted`'s own doc is a statement of fact
("Model exists but has no promoted version to serve"); its sibling
`NotAvailable`'s is *"the RFC's loud lifecycle failure mode"*. **The enum
already separated the designed state from the failure; only the log level did
not.** Check 69's harm, on the one channel this subsystem had.

**The instrument.** `talos_rpc_calls_total{subject,outcome,class}` (counter,
PRE-SEEDED) and `talos_rpc_duration_seconds{subject,outcome,class}` (histogram,
deliberately NOT seeded). `record_rpc_metric` now takes `RpcSubject` /
`RpcOutcome` and two `Duration`s; the LOG LINE is byte-identical (same field
names, same integer milliseconds, same messages for the served and finding
arms), so no operator's saved filter breaks.

**The label sets are closed BY THE COMPILER, not by convention.** The brief
recorded that both parameters were already `&'static str` and every argument at
every call site was a literal or a `match`-bound local — true, and not the same
thing: `&'static str` also accepts `Box::leak(caller_supplied.into())`, which is
#786's own stated caveat about its `tool` label — that instrument is the same
shape on the other half of the request surface, and it types its OUTCOME as an
enum for this reason while leaving `tool` a `&'static str` because ~320 tools
make an enum impractical there. With 7 subjects and 18 outcomes BOTH axes are
affordable here, so `talos-metrics/src/rpc.rs` carries ONE macro
table per axis from which the enum, the label, the class and the pre-seed loop
all derive. `actor_id` stays a LOG FIELD and must NEVER become a label — it is
caller-supplied and unbounded, i.e. a cardinality DoS surface reachable by
anything that can publish to the subject.

**The seed set is 64 pairs, not 126, and both numbers were measured.** Each
subject's declared outcomes are exactly what ITS subscriber can pass — its own
literals plus every arm of its own exhaustive terminal `match`. The cross
product would seed 62 combinations no call site can reach, which is check 58's
own defect (the one the worker's `register_metrics(.., &[])` argument was added
to remove). Every one of the 64 was checked for a live PRODUCER rather than
merely an exhaustive arm; the ones worth naming are `memory.op`/`write_ceiling`
(reachable only through the terminal match, produced at `lib.rs:1915`/`:1965`)
and both `storage_full`s. **Two of the brief's own counts were refuted**: 41
production call sites, not 49, and **18** distinct outcome literals, not 13.

**The HISTOGRAM is deliberately unseeded, and the reason is narrower than
"expensive".** The absent-vs-zero rule is a rule about COUNTS: a seeded
histogram over zero observations renders every bucket 0, `_sum` 0 and `_count`
0 — exactly what the seeded counter at 0 already says — and
`histogram_quantile` over it is NaN either way. Measured cost is 21 lines per
observed pair against the counter's 1 (pinned by
`the_rpc_instrument_costs_the_lines_the_seed_decision_assumes`, so the number in
this paragraph cannot go stale silently). Buckets are
`exponential_buckets(0.0005, 2.0, 18)` = 0.5 ms … 65.5 s: the house default of
15 tops out at 16.4 s, BELOW `PERMIT_GUARD_TIMEOUT_SECS` (30 s), and the
semaphore queue sits OUTSIDE that guard, so one call can exceed it.

**Timings are `Duration`, not the pre-rounded milliseconds the call sites used
to pass**, and that is a measurement rather than taste: every `queue_ms` and
`exec_ms` this fleet has ever logged is `0`, so a histogram fed `as_millis()`
would put 100% of observations in its bottom bucket — an instrument that reports
nothing, which is the defect this change exists to remove.

**Three labels, and the third one is what stops an alert regex rotting.**
`class` is a pure FUNCTION of `outcome`, so it adds ZERO series (each pair has
exactly one class) and it buys the one thing PromQL cannot do for itself: rest
`TalosRPCSubjectFailing` on the SAME `RpcOutcome::class()` the log level rests
on. Without it the alert would spell `outcome=~"internal|timeout|…"`, a
hand-maintained alternation that a nineteenth outcome would be added to the
enum, classified correctly, logged correctly and silently fall outside — check
74's own recorded rot mode.

**The classification, derived per outcome from its enum's own documentation.**
Names follow #780's `TaskExit::is_finding()`, because the question is not "did
the platform fail" but "should someone look". `Served` (`ok`) -> `debug!`.
`Declined` -> `info!` — the arm the old comment CLAIMED: `not_promoted`,
`not_found`, `invalid`, `too_large`, `storage_full`, `always_blocked`,
`disallowed_function`, `statement_not_permitted`. `Finding` -> `warn!`:
`unauthorized`, `replay`, `write_ceiling`, `stale_deadline`, `not_available`,
`query_error`, `connection_failed`, `timeout`, `internal`.

Four of those are worth the argument. **`unauthorized` is a Finding**, not a
decline: it IS a refusal, but on a transport where every legitimate sender holds
the fleet-shared `WORKER_SHARED_KEY` it means clock skew, a half-rotated key, or
a sender that should not be there — the brief's own class-2 definition ("a
designed state the operator has not misconfigured") excludes it. Live count on
this fleet: **0, ever**, so keeping it loud costs nothing today. The
caller-facing reply is UNTOUCHED — `caller_facing_unauthorized` still collapses
every rejection reason and `every_unauthorized_arm_blinds_its_reply` still binds
all seven arms. **`replay` is a Finding** on the same argument. **`not_found` /
`invalid` are Declined**: caller errors, the caller is told (identically for
every reason), and the calling module's own execution fails through the ordinary
channel, so the operator is not blind — and nothing about the reply changes.
**`query_error` is a Finding on BOTH its producers even though one of them is a
caller error, and that is a compromise stated rather than hidden**: on
`database.query` it is the GUEST's SQL failing, but on `state.write` it is the
CONTROLLER's own `execution_state` UPSERT failing — silent to the guest by
contract, and MCP-733 deliberately made it WARN *"so SIEM / dashboard alerting
can fire on sustained query_error outcomes"*. One label cannot say both;
classifying it Declined would silence a live decision. The counter separates
them by `subject`. **`write_ceiling` is a Finding** because #760 already decided
this exact question in this exact direction and ships a `warning` alert on it.

**ONE alert, `TalosRPCSubjectFailing`, `warning`, and the refusal class gets
none.** The established position — a counter on the policy WORKING gets no alert
— covers `Declined` entirely, and the promtool case that matters drives
`not_promoted` climbing on every sample and asserts SILENCE. The FINDING class
is the open question C6 names, and it is alerted: a subject whose calls are
>50% findings, with >=5 findings in the window, sustained 10 minutes. A RATIO
because every one of these subjects has failure modes that are normal at low
rates; the `>=5` floor because a single timeout on a quiet subject would
otherwise hold the ratio at 1.0 for a whole rate window. **It cannot fire on an
idle fleet**: the seeds make the series exist, their rate is 0, the denominator
is 0, and 0/0 is NaN. Five `promtool` cases pin all of that, including the
permanently-zero one, and the FIRING case was mutation-proved non-vacuous.
**`unauthorized` gets NO alert of its own**, argued rather than omitted: this
fleet has produced zero, so any threshold is a guess and the obvious one fires
on a rolling deploy's clock skew — the counter makes it graphable and the
metric's HELP carries the query. The alert can CO-FIRE with
`TalosRPCWriteCeilingRefusals` when the finding class is dominated by
`write_ceiling`; that is disclosed in its own annotation rather than papered
over with a hand-maintained exclusion that would rot.

**Guards, and what each covers.** `the_declared_table_matches_the_source`
(in `talos-rpc-subscribers`, where both the table and the call sites are
visible) splits `lib.rs` at the seven subscriber headers and compares the
`RpcOutcome::` tokens per region against `RpcSubject::outcomes()` in BOTH
directions — an undeclared outcome would be an ABSENT series, a declared one
nothing emits is check 58's defect. It fails LOUDLY if the scan finds fewer than
60 pairs or if a subscriber is renamed away.
`the_rpc_instrument_seeds_exactly_the_reachable_pairs` asserts all 64 present at
0 on a cold registry and NO pair outside the table.
`controller/tests/rpc_instrument_tests` (CTRL_TESTS, sub-leg 64b) drives the
REAL `spawn_memory_rpc_subscriber` over real NATS against real Postgres and
asserts the counter moved by EXACTLY one on a served call, that a decline lands
on its own series, that a refusal ABOVE the handler is counted, that a subject
nothing was sent to did not move, and that the actor id appears NOWHERE in the
exposition.

**Two measured SURVIVORS, both closed rather than recorded.** (1) The
histogram's OBSERVED VALUE: reverting it to `exec` alone — dropping the
semaphore queue wait, i.e. the only part of an RPC that grows under
backpressure — left every test in the workspace green, because every observed
duration on this fleet is 0 either way. Closed by
`the_duration_histogram_observes_queue_plus_exec`, which also pins the
sub-millisecond resolution and therefore makes the pre-rounded-milliseconds
revert red. (2) The LOG LEVEL had no test at all: the class table is pinned by
name, and nothing pinned that the level rests on it, so both shapes of "put the
designed state back on the alarm channel" were silent. Closed by
`the_log_level_rests_on_the_outcome_class`, which captures `target: "talos_rpc"`
events and asserts the mapping for all 18 outcomes (a new dev-only
`tracing-subscriber` dependency; the production graph is unchanged).

**What was measured and deliberately NOT changed.** A THIRD metric family,
`talos_rpc_queue_duration_seconds{subject}`, was considered and declined: the
existing doc comment says the queue/exec split exists so operators can tell
backpressure from downstream slowdown, and the histogram measures the TOTAL, so
that split now lives in the log alone. Three reasons. Backpressure is
structurally unreachable at the measured volume (1317 module executions per 24 h
≈ 0.9/min against per-subject in-flight caps of 8 / 16 / 32, and every observed
`queue_ms` is 0); the saturation signal SURVIVES the collapse as its own outcome
label, because `stale_deadline` IS the queue outrunning the caller's deadline;
and the split is unchanged in the log line. Stated as a limit rather than sold:
an operator who wants queue-vs-exec attribution still has to read the log.
`talos-metrics` gained NO new dependency — it was already a direct dependency of
`talos-rpc-subscribers` (#754 added it), verified by reading the manifest — and
the seven subject strings are DUPLICATED into `talos-metrics` rather than
imported, because `talos-memory` would invert the layering; they are pinned to
their originals by `the_subject_table_matches_the_wire_constants`, exactly
#760's `RPC_WRITE_CEILING_SUBJECTS` precedent. `TalosMetrics::new()` is
CONTROLLER-only (`grep` finds it nowhere in `worker/` or
`talos-worker-runtime/`, neither of which depends on the crate), so these 64
series cannot be seeded into a process that can never increment them — #778's
worker regression is not reachable here.

**No lint check was added and `--count` stays 88.** The brief's own candidate —
*"a call site must pass an outcome from the closed table"* — is answered by the
TYPE SYSTEM: mutating one to `Box::leak(req.actor_id.to_string().into_boxed_str())`
does not compile. The GENERALISATION was built and measured instead
(`scripts/lint-rpc-label-closure-candidate.sh`, kept per #781 so the numbers can
be re-derived): *"every Prometheus label value must come from a closed
compile-time set"* inspects **121** `with_label_values` arguments workspace-wide
and flags **73** as not provably closed — and essentially every one is CORRECT
(a `&'static str` parameter bound by an enum's `as_str()` one frame up, a
`pub const`, or a `kind.metric_label()` helper). It reports the same 73 on
pristine `origin/main` and on the fixed tree, i.e. 0-for-0 as a bug detector,
and would ship at seventy-three markers on correct code. It cannot be narrowed,
because the defect it exists for is a `&'static str` whose VALUE came from the
caller and no textual rule can tell that from one whose value came from an enum
one frame up — a dataflow question. The structural answer is what shipped.

**Expected live state on this fleet after deploy**, so it can be read rather
than assumed. `/metrics/prometheus` gains **64** `talos_rpc_calls_total` lines,
all at 0 until traffic; the histogram exports NOTHING until a first call.
`talos.memory.op` / `talos.database.query` / `talos.graph.search` should show
`{outcome="ok"}` climbing. The hourly `talos.ml.predict` line moves from WARN to
INFO and starts incrementing `{outcome="not_promoted",class="declined"}` — so
the controller's WARN volume should fall from 32 to about 15, and
`TalosRPCSubjectFailing` should stay silent: `not_promoted` is `declined` and
the finding class is expected to remain 0 on every subject.

### 2026-09-09 — a chart that crashed on the runs an operator most wants to see

`get_execution_waterfall` computed `bar_len.clamp(1, chart_width - bar_start)`
with `bar_start` capped at `chart_width`, so a row where
`start_ms >= total_ms` evaluated `clamp(1, 0)` — **min > max, which panics**. A
panic in an MCP handler unwinds the tokio task, so the caller gets a DROPPED
REQUEST rather than an error, and nothing in the response says why.

**Reachable, and not on the shape the earlier note guessed.** That note recorded
it as "a node's start equals the run's total". Measured against the live fleet
2026-09-09 by driving the handler's own arithmetic over `workflow_executions`
joined to `execution_events`: **2 of 10,729** completed executions trip it, and
both are `failed` long-running runs whose last `node_started` landed **21 s and
30 s AFTER `completed_at`** — not a tie, an inversion. The cause is two writers:
`total_ms` comes from the EXECUTION's `completed_at` while every `start_ms` is an
offset from that NODE's own event, so a node event written after the execution
was finalized reads as starting past the end. So the tool crashed precisely on
the class of execution — failed, long-running — an operator is most likely to
open a waterfall for.

The geometry moved to the pure, total `bar_geometry`, which is panic-free for
every input including `total_ms <= 0` and `chart_width == 0`. `start` now caps at
`chart_width - 1` rather than `chart_width`: a zero-width bar renders a row
claiming the node did not run, and it is what inverted the clamp.

**Not panicking is only half of it.** `BarGeometry::beyond_total` is the other
half, because a bar silently pinned to the right edge asserts the node ran AT the
end when the data says it started PAST the end — the misleading-report class
(checks 74/76/79/81) in a chart. Such rows are marked inline and the chart
carries a footer naming the count, the total it is drawn against, and the
two-writer reason, so the reader is not sent hunting a rendering bug.

**What was measured and NOT changed.** The finalization ordering itself — a
`node_started` written after its execution's `completed_at` — is left alone. It
is a real ordering fact about the engine's failure path, not a rendering
question, and fixing it is a change to how executions finalize rather than to
how they are drawn. The population is the 2 rows above.

**No lint check was added and `--count` stays 88.** The candidate — "a `clamp`
whose bounds are both computed must have its min <= max proved" — is a dataflow
question, not a textual one, and the structural answer is already stronger: the
arithmetic has ONE home, it is `#[must_use]`-free but total by construction, and
the totality is pinned by a test over hostile inputs (`i64::MIN`, `i64::MAX`,
`total_ms == 0`, `chart_width == 0`). Guards, and their limits: the four unit
tests drive the PURE function and are RED on the pre-fix arithmetic (3 of 4
panic) with an ordinary-row CONTROL that stays green, and a second mutation
silencing `beyond_total` is red too. Neither can see the HANDLER BODY — a caller
that computes the geometry correctly and discards `beyond_total` survives, which
is checks 74b/79b's stated limit and is the honest position here.
