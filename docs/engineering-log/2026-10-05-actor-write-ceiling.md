# The actor write ceiling (moved from CLAUDE.md, 2026-10-05)

The four paragraphs of `CLAUDE.md`'s `__memory_write__` section that told how
`actors.max_write_ceiling` came to be enforced on every route to an actor's data
(the returned envelope, the signed-RPC mutations), which output protocols were
decided to stay outside it, and how the control's own reporting was repaired.
Byte-for-byte as they stood. The rules they left behind are in `CLAUDE.md` under
"The actor's write ceiling"; the decisions are digested in `DECISIONS.md`.

**The envelope obeys the actor's WRITE CEILING (#750).** `actors.max_write_ceiling`
is ONE control with TWO enforcement surfaces, and until #750 only the worker's
existed. A module reaches `actor_memory` either by calling `agent_memory::set`
(refused in the worker by `TalosContext::write_ceiling_refuses`) or by RETURNING
this envelope, which the CONTROLLER persists on node completion — a route that
needs **no capability at all**: a `minimal-node` module — whose
`get_module_info.mutation_profile` is EMPTY, because `write_gated_ops` profiles
HOST OPS and the envelope is not one — wrote durable memory for a `readonly`
actor simply by returning a JSON object, and the execution reported success.
The profile was not wrong so much as SILENT about a real write route, which an
operator reading "this module mutates nothing" cannot tell apart; both
`write_gated_ops` and the tool's `note` now say so explicitly.
Now: the engine applies `talos_workflow_engine::write_ceiling_gate::apply_memory_write_ceiling`
at node completion AND per pipeline step, using the ENGINE's `max_write_ceiling`
(already narrowed for a sub-workflow by `bind_subengine_actor_and_ceilings`, so a
sub-workflow bound to a stricter actor is gated at the stricter ceiling). On
refusal the envelope is REMOVED (never merely flagged — a flagged envelope is one
`unwrap_or(false)` away from being honoured) and the engine-authored
`__memory_write_refused__` `{key, reason, ceiling}` is written in its place; the
node COMPLETES rather than fails (see the fn's docs for why — the worker path
returns an error to the GUEST and does not itself guarantee node failure either).
Like every engine-authored key it is **set-or-REMOVE, never set-or-inherit** — a
module cannot fabricate a refusal record. The DECISION is
`talos_workflow_engine_core::write_ceiling_denies(enforced, ceiling)`, shared with
the worker (whose copy is now a re-export) — do NOT hand-copy it; two paths
answering one question differently IS the bug. **`TALOS_WRITE_CEILING_ENFORCED`
must be set on BOTH processes** (the controller cannot read the worker's env);
`docker-compose.yml` and `values.yaml` now set both, and the chart's old
"controller side needs no change … Worker-only env" comment was false.
Defence in depth: `ControllerNodeHook::persist_memory_write_if_present` takes the
ceiling as a REQUIRED parameter, which is the only gate on `test_module` (that
tool now resolves the actor's real ceiling instead of hardcoding `Write`).
Audit parity is in the VOCABULARY (`op = "agent-memory-set"`,
`policy = "write-ceiling"` — the worker's exact tokens) but NOT the transport:
the worker's refusals also enter the hash-chained WORM ledger and the controller
has no `ExecutionLedger` producer, so its refusals reach the `talos_audit`
tracing target and `talos_memory_write_failures_total{reason="write_ceiling"}`
only. **Both instruments live on `ControllerNodeHook`; the ENGINE gate reaches
them by NOTIFYING it.** `NodeLifecycleHook::on_memory_write_refused` is called
from both engine gate sites and delegates to the single
`record_memory_write_refusal` that the hook's own in-method gate also calls —
one recording routine, two gates, no vocabulary drift. That notification is
load-bearing and was the one part of #750 nothing tested (even
`CaptureNodeLifecycleHook::MemoryWriteRefused`, added for it, had zero
consumers): delete it and the gate still gates perfectly while every instrument
goes permanently silent — a refusal indistinguishable from a write that never
happened, which is the exact reading the gate exists to remove.
`controller/tests/write_ceiling_memory_write_tests` now asserts the counter
moved EXACTLY once and the `talos_audit` event carried the right
`op`/`policy`/`ceiling`/`key`/`actor_id`/`node_id`, and that a PERMITTED write
moves neither. Both were verified firing on the live dev controller 2026-09-05
(`{reason="write_ceiling"} 1`; the WARN in the container log), so those
assertions are a REGRESSION GUARD proven by mutation, not a reproducer — saying
so matters more than implying they caught something.
**And "the `talos_audit` target" is exactly one thing: a target string on an
ordinary log line.** The controller installs
`registry().with(EnvFilter).with(fmt::layer()).with(otel_layer)` and no
per-target layer, so nothing subscribes to, routes, persists or alerts on
`talos_audit` — ~60 emitters share it as a grep convention that reaches stdout
and thence container logs. A reader who takes "audit target" to mean a durable
audit channel over-trusts it in exactly the sentence that contrasts it with a
WORM ledger. The METRIC is the only machine-readable half, and it is now
**pre-seeded at 0**: until 2026-09-05 the four `MemoryWriteError::metric_label`
reasons were seeded and this fifth, literal one was not, so on any controller
that had not yet refused anything (i.e. after every restart)
`{reason="write_ceiling"}` was ABSENT — "policy has never declined a write" and
"the gate is not wired" rendered identically. Deliberately NO alert on it: a
refusal is the policy working as designed, and the two live rules on this
counter select `reason="crypto"`/`"db"`, so a refusal cannot page anyone.
The pipeline-step gate site (`engine_dispatch_pipeline`) is dormant by CONFIG,
not by omission — every production entry point passes `ChainDispatch::Disabled`
(see `talos-workflow-engine/tests/chain_dispatch_gate.rs`), so that gate and its
notification fire only under `run_with_transport`, which no production caller in
this workspace uses. Routes deliberately NOT gated, for the record: the memory-RPC
`MemoryOp::Set` handler (`talos-rpc-subscribers`) still TRUSTS the worker's gate
— an asymmetry that only bites a mixed-config fleet; and operator-invoked writes
only. Routes deliberately NOT gated, for the record: operator-invoked writes
(`actor_remember`, `clone_memories`, `scaffold_actor` seeds, the GraphQL memory
mutations) plus platform-authored ones (`ml_digest`, consolidation/reflection,
the `upsert_scratchpad_trace` execution trace) are the OPERATOR's or the
PLATFORM's writes, not the actor's, and the ceiling does not speak to them.

**The signed-RPC routes are now gated too (#754).** #750 recorded that the
memory-RPC `MemoryOp::Set` handler "still TRUSTS the worker's gate". That trust
rests on an assumption the transport does not support: these requests are
HMAC-signed under `WORKER_SHARED_KEY`, which is FLEET-SHARED, so the signature
proves the sender holds a key — not that the sender ran a gate. Measured on
pristine main with enforcement ON at the controller: a signed `Set` naming a
`readonly` actor landed a row and the reply said `Ok`. The gate is
`talos_rpc_subscribers::write_ceiling::gate`, applied at every actor-attributed
mutation the CONTROLLER performs on a worker's behalf —
`MemoryOp::Set`/`Delete` (`talos.memory.op`), `IntegrationOp::Set`/`Delete`
(`talos.integration_state.op`) and a MUTATING `talos.database.query`. It uses
the SAME `write_ceiling_denies` predicate and the SAME `TALOS_WRITE_CEILING_ENFORCED`
reader (`write_ceiling_gate::controller_write_ceiling_enforced`) as the #750
envelope gate; the actor's ceiling comes from
`talos_actor_repository::read_actor_write_ceiling`, resolved by the SIGNED
`actor_id` only. **The read is three-valued and fails CLOSED**: `Ok(None)` (no
such actor) and `Err` (the rule could not be read) both REFUSE, with a
`write_ceiling_unreadable` reason distinct from the `write_ceiling` policy
reason — distinct for the OPERATOR (`talos_audit` field + `talos_rpc` outcome
tag), collapsed for the CALLER, because a reason-split reply would hand a
holder of the fleet key an actor-EXISTENCE oracle (the same argument
`caller_facing_unauthorized` makes). **Cost is zero when the flag is off**: the
`OnceLock` short-circuits before the query, so a default deployment is
byte-identical. With it on, one PK read of `actors` — measured 1.1 µs
server-side, 0.43 ms including the host round trip. A per-actor cache was
considered and REJECTED: a TTL on a security rule is a window in which a
revoked grant is still honoured, and the measured volume on this path is ~1
write/week. Enforcement is lint-enforced by **check 82** and pinned equal to
the worker's op list by
`write_ceiling::write_ceiling_tests::complement_is_worker_local` — every
ceiling-gated WORKER op must be classified as controller-served (and gated
here) or worker-local egress. `talos.state.write` is deliberately NOT gated:
the worker does not ceiling-gate execution `state` either (it is engine-internal
durability, not the actor's data), and a controller stricter than the worker is
the same defect in the other direction. **One finding worth carrying**: the
controller's `database.query` gate classifies read-vs-mutation from its OWN
AST, and the first version — `matches!(stmt, Insert|Update|Delete|Merge)` —
was WRONG. sqlparser 0.53 parses a data-modifying CTE
(`WITH ins AS (INSERT …) SELECT * FROM ins`) into `Statement::Query`, which
`controller_permits_data_statement` ADMITS, so a `readonly` actor could have
smuggled an INSERT past a gate that called it a read. The classifier now walks
the AST and breaks on any nested non-`Query` statement. The WORKER's twin
(`sql_stmt_type_is_read_only` over its validator's `stmt_type`) very likely has
the same hole and is NOT fixed here — the controller is currently the stricter
of the two for that shape.
**And the class is wider than this key.** The SAME hook, on the SAME
module-returned output and the SAME actor binding, also drives
`__ops_alert__` (→ `ops_alerts`) and `__ml_distill__` (→ ML dataset rows). Both
take the actor id, both refuse only when it is ABSENT, and neither consults the
ceiling — i.e. "a module bypasses the ceiling by returning a value" is true of
three output protocols and #750 gated one.

**DECIDED 2026-09-06: those two stay OUTSIDE the ceiling, and the reports
now say so.** #750 left it as "an operator policy call"; the call is that
`actors.max_write_ceiling` governs the ACTOR's own DATA PLANE — actor_memory,
integration state, sandbox SQL — and these two are PLATFORM ingestion that takes
the actor id for TENANCY, not because the rows are the actor's data: one is a
diagnostic, the other a training-example append. The live evidence is the
decisive part rather than the argument: of 5 `readonly` actors on this fleet
exactly ONE is `active`, it is bound to exactly ONE enabled workflow, and that
workflow's whole purpose is to emit `__ops_alert__` through this hook. Gating
the protocol would take the only live readonly actor's alert pipeline off the
air — the intended shape is `readonly` PLUS these protocols, not either-or. The
refusal that stays is the ABSENT-actor one: no actor is no tenancy principal.
What changed is the REPORTING, because "enforced" with no scope is read as
"nothing this actor emits reaches the database": `get_module_info`'s
`write_gated_ops` note, `set_actor_write_ceiling`'s description and
`security_audit.write_ceiling_enforcement` (detail + a
`parts.controller_gate.probe.ungated_output_protocols` array, from the single
`talos_security_audit::UNGATED_OUTPUT_PROTOCOLS`) all name both protocols.
`controller/tests/write_ceiling_hook_gate_tests` is a POSITIVE CONTROL: a real
`readonly` actor's `__ops_alert__` must still land a row, so a future "fix"
fails loudly (mutation-proved — early-returning from
`persist_ops_alert_if_present` gives `left: 0, right: 1`). `__ml_distill__` gets
NO equivalent test and the reason is measured, not asserted:
`spawn_distill_from_output` short-circuits on the process-global
`DISTILL_CONTEXT` `OnceLock` that sibling tests in one binary race (check 82's
own objection), and past it the flow needs an ML MAC key, an embedding provider,
a model and a dataset. Its half of the decision is pinned at the call site in
`talos-engine/src/node_hook.rs` and in the shared constant only.

**The control's own REPORTING was two defects behind the control (#760).**
Two, measured 2026-09-05, and they are the same shape one level up — a
misleading report about the thing being reported on.
**(a) `security_audit.write_ceiling_enforcement` described a controller that no
longer exists.** Its detail said, verbatim, "the enforcing gate lives in the
worker process, so the controller cannot exercise it from here", and graded
itself `config_presence`. True when #752 wrote it; false from #750 (the
`__memory_write__` envelope gate) and #757 (the signed-RPC mutation gate), both
of which run IN the controller and are PURE functions. So the audit's own
legend — `round_trip` = "a probe value was pushed through the real primitive and
the result inspected" — was reachable and unclaimed. `ControllerGateProbe::run()`
now drives both real chokepoints every run (`probe_envelope_gate` /
`probe_rpc_gate`, each owned by its gate's crate): a readonly probe must be
REFUSED and its envelope REMOVED, a write-capable one permitted, an unreadable
rule refused (fail closed), and an unenforcing deployment must permit
everything. A broken arm is `Status::Fail` + `RoundTrip` + `CRITICAL`, which
outranks every fleet finding. **The two halves are now rendered separately**
(`parts.controller_gate` at `round_trip`, `parts.worker_fleet` at
`config_presence`) because they are known to different standards and one word
must misstate one of them; the check's TOP-level `verification` stays **the
weakest of the facts its `status` rests on**, so `verification_counts` cannot
over-claim — promoting the whole check because half of it was exercised would be
the same overstatement in the other direction. Weight stays **0** (#752's three
reasons stand). New finding it can now make: fleet `all` + controller flag unset
is a **SPLIT CONTROL** `Warn`, not a `Pass` — the `some`-shaped state in the
OTHER direction from #757's, where every worker refuses a readonly actor's host
calls while the controller honours the same actor's returned envelope and its
signed-RPC mutations. `TALOS_WRITE_CEILING_ENFORCED` must be set on BOTH
processes and this is the check that can now say whether you did.
**(b) An RPC refusal was indistinguishable from a routine envelope refusal.**
#757 correctly said a refusal at the controller "means a worker sent a mutation
its own gate should have refused — a fleet-config signal worth alerting on,
unlike #750's envelope refusal", and routed it to `event_kind =
"rpc_write_ceiling_refused"` plus the per-subject `talos_rpc` outcome tag.
Measured live: **`talos_rpc` is a TRACING TARGET ONLY** — `curl
/metrics/prometheus | grep '^talos_rpc'` returns nothing and no RPC counter was
registered — and the three MEMORY routes folded into
`talos_memory_write_failures_total{reason="write_ceiling"}`, **the same counter
and label the routine envelope refusal uses, whose own HELP text says "do not
alert on it"**, while the integration-state and database routes incremented
NOTHING. So the fleet-config signal existed as prose and not as a series, and
the one counter carrying part of it actively instructed operators to ignore it —
check 58/65's class. Now: `talos_rpc_write_ceiling_refusals_total{subject,
reason}` (`subject` = the NATS subject, `reason` = `policy` | `unreadable`), all
six combinations PRE-SEEDED at 0 (absent ≠ zero: `increase(...) > 0` over an
absent series matches nothing), incremented at the ONE chokepoint
`write_ceiling::gate` so a new controller-served write op cannot forget it, and
alerted at `warning`/never-paging by `TalosRPCWriteCeilingRefusals`. The
`memory_write_failures` increment is KEPT — it answers a different question
("which actor-memory writes did not land") — and the double count is now stated
in its HELP text rather than silent. The log keeps the worker's tokens
(`RefusalReason::as_str`); the metric uses the short pair
(`RefusalReason::metric_label`), paired by an exhaustive match and pinned by
`refusal_reason_spellings_stay_paired`.
**No lint check was added, and that is a measurement, not an omission.** The
obvious guard — "a refusal chokepoint that logs an `event_kind` must also
increment a counter" — was measured before it was written: the workspace holds
**22** `event_kind = "…refus|denied|reject|blocked…"` emitters and **21** have no
counter within ±20 lines. A check cannot ship at 21, this repo does not re-add
baselines (check 52's own rule), and the adjacency proxy has known false
positives besides. So the count stays **84**.
