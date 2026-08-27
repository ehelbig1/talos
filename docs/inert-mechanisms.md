# Inert-mechanism inventory — findings

**Tree:** `/Users/evanhelbig/projects/talos/.claude/worktrees/inert-inventory`,
branch `claude/inert-mechanism-inventory`, HEAD `31c13519` (clean).
The main repo was **not** touched; it is at the same commit and clean.
The live `talos` DB was not written.
**Every measurement below was taken in the worktree**, not in main.

**Method.** Every hit resolved to (a) its TYPE / receiver and (b) whether it is
an ASSIGNMENT, a DECLARATION, a READ, or a comment. A name-based count is
reported nowhere in this document.

---

## PROCESS A — premise verification

### P1. `deadline_unix_secs`: "21 assignment sites, 0 set to anything but 0"
**VERIFIED, with the decomposition made explicit.**

`grep -rn "deadline_unix_secs" --include="*.rs"` → **37** mentions.
Of those, **22** match the `field:` form. One of the 22 is the struct
DECLARATION (`talos-workflow-job-protocol/src/lib.rs:3219`,
`pub deadline_unix_secs: u64`). **21 are assignments and every one is `0`.**

Sites (all `: 0`): `talos-google-cloud/src/dispatch.rs:311`,
`talos-gmail/src/dispatch.rs:483`, `talos-google-calendar/src/handlers.rs:1511`,
`talos-webhooks/src/router.rs:1233` and `:2896`,
`talos-integration-helpers/src/lib.rs:411`,
`talos-workflow-engine-nats/src/dispatcher.rs:973` and `:1260`,
`worker/src/main.rs:762`, `controller/examples/verify_llm_tier_ceiling.rs:92`,
8 constructor/fixture sites in `talos-workflow-job-protocol/src/lib.rs`
(6221, 6276, 6323, 6503, 6550, 6614, 6730, 6786), and 3 in that crate's
`tests/`.

The remaining 15 mentions are: 2 reads in the signing payload
(`lib.rs:3652`), 2 reads in the worker guard (`worker/src/main.rs:1082`,
`:1087`), test assertions/snapshots, and comments.
**No production assignment anywhere in the workspace sets a non-zero value.**

### P2. `cancellation_token`: "32 assignment sites; the 3 that look live are the engine's in-process token"
**PARTLY VERIFIED — the shape is right, the numbers differ, and the
receiver claim is REFUTED (see the correction below).**

`grep` → **90** mentions, **35** in the `field:` form. Resolving each by type:

| kind | count | type |
|---|---|---|
| declarations | 3 | `Option<String>` — `job-protocol/src/lib.rs:3224` (`JobRequest`), `:4437` (`PipelineStep`), `talos-worker-runtime/src/context.rs:198` (`TalosContext`) |
| declaration / fn param | 2 | `Option<tokio_util::sync::CancellationToken>` — `talos-workflow-engine/src/engine.rs:815` (field decl), `:894` (fn param) |
| in-process-token assignments | 2 | `engine.rs:1060` (`None`), `engine.rs:1110` (`.clone()` — a REAL propagation) |
| **wire-field assignments** | **28** | **all `None`** |

The 2 `engine.rs` assignments are the trap the plan named: they are
`tokio_util::sync::CancellationToken`, a different type with a different
purpose (epoch fencing). That token IS live — `talos-engine/src/fence.rs:117`
and `:172` call `engine.set_cancellation_token(Some(token))` in production
code, and `fence.rs:230`/`:238` fire `token.cancel()`.

The only `= Some(...)` writes to the **wire** field are in `#[cfg(test)]`
H-7/C-2 tamper tests (`lib.rs:8295`, `:8315`, `:8502`, `:8519`).

> **CORRECTION to [[built-enforced-never-populated]] (#686).** That note's
> table says the wire `cancellation_token`'s receiver is "worker". **It is
> not.** `TalosContext.cancellation_token: Option<String>` is declared,
> carries a doc comment stating *"host functions check this token
> periodically and abort if revoked"*, is set to `None` at both construction
> sites (`worker/src/main.rs:763`, `context.rs:1180`), and is **read
> nowhere** in `worker/` or `talos-worker-runtime/` — `grep -rn
> cancellation_token worker/ talos-worker-runtime/` returns exactly 3 lines,
> all of them the declaration or a `None`. So this field is not
> "built, enforced, never populated"; it is **declared, documented as
> enforced, and neither populated NOR enforced.** That is a *different and
> worse* category, because the doc comment asserts a behaviour that has no
> implementation. See F-1 below for what IS enforced.

### P3. The other three rows (heartbeat / uploader / `increment_usage`)
Carried from #675 / #679 / #681 and not re-derived in this cycle; they are
used only as prior instances for the D1 causal question, not as new counts.

---

## PROCESS C / D1 — the refuting measurement, taken first

**The measurement that would refute the plan:** if the five instances have no
shared cause, they are five coincidences and the output is five notes. The
discriminating observable is **the growth history of each side**: if the
enforcement surface and the producer surface grew at the same rate, "shipped
receiver-first" is a story about one bad commit, not a pattern. If enforcement
grew repeatedly, across authors and months, while the producer stayed at zero,
there is a mechanism.

**Result: NOT REFUTED. There is a shared cause, and it is specific.**

Taking the largest instance (worker cooperative cancellation, F-1 below):

| side | commits that changed it | span |
|---|---|---|
| **enforcement** (`if self.is_cancelled()` guards) | **4** — `8f13f1e9` (2026-05-18), `47f27b18` (2026-07-01, #380), `0e622a53` (2026-07-11, #470), `88c1acfb` (2026-07-14, #484) | ~2 months, ≥3 unrelated features |
| **producer** (`TalosContext::cancel`) | **1** — the initial import; it has **never gained a caller** | — |

The 2026-07-11 and 2026-07-14 commits are ML feature work (`talos.ml.predict`,
`talos.ml.fewshot`). Neither is about cancellation. **Each new host function
copied the `is_cancelled()` guard from its neighbours** — which is exactly
right as local practice, and is why the enforcement surface reached 20 sites
while the producer stayed at 0.

**The cause, stated:** **enforcement replicates by pattern-copying between
sibling call sites; population requires one deliberate wiring decision that no
individual feature owns.** A new host function has an obvious template to copy
(the guard). A new dispatch path has no comparable pull toward populating
`deadline_unix_secs` — populating it is a fleet-wide behaviour change, so it is
nobody's incidental work. The asymmetry is structural, not accidental.

Two corroborating observations:
* `47f27b18` is titled *"…P0 correctness/security fixes + **enforcement**…"* —
  a review-remediation pass that **added more enforcement** to a mechanism with
  no producer. **Reviews audit the receiving end.** Nothing in the review
  process asks "and who sets this?"
* The two H-7 hardening commits (`06257fa1`, 2026-05-23) HMAC-bound
  `deadline_unix_secs` and `cancellation_token` — security work on fields no
  producer sets. (For `deadline_unix_secs` this is **not** vacuous: binding it
  stops an on-wire attacker INJECTING a past deadline to make the worker refuse
  jobs. For `cancellation_token` it is anticipatory only, since nothing reads
  the field.)

**So: one finding, not five.** The five instances share the mechanism above.
They do **not** share a disposition — see D3, where they split three ways.

---

## D2 — closing the set

**Method, and why the obvious grep is not enough.** I swept every field of
`JobRequest` (33), `JobResult` (10), `PipelineStep` (20), `PipelineJobRequest`
(16), `PipelineStepResult` (5), `PipelineJobResult` (10), `WorkerHeartbeat` (6),
`LlmUsageEntry` (5), `DispatchJob` (35), and every field of the six signed RPC
protocols in `talos-memory/src/` (`memory_rpc`, `graph_rpc`, `database_rpc`,
`state_rpc`, `ml_rpc`, `integration_state_rpc` — 24 structs). Assignments were
collected as `field:` initialisers **and** `field,` shorthand, with
`module-templates/*/src/bindings.rs` (wit-bindgen output), `tests/`, `_tests.rs`
and `examples/` excluded, and declaration lines dropped.

**The automated sweep alone gives the wrong answer, in both directions.** Its
raw output on the wire types was 3 candidates; **1 was real and 2 were false
positives**, and it **missed** the one instance the plan already knew about:

| sweep said | truth | why the sweep was wrong |
|---|---|---|
| `deadline_unix_secs` — all 17 prod assignments `0` | **inert** ✓ | — |
| `step_results` — all 8 prod assignments `vec![]` | **live** ✗ | populated by field **shorthand** at `worker/src/main.rs:1763` |
| `heartbeat_nonce` — all 4 prod assignments `String::new()` | **live** ✗ | populated by **later mutation**: `self.heartbeat_nonce = nonce` (`job-protocol/src/lib.rs:5527`, the `sign()` path). Same shape as `signature`, `job_nonce`, `result_nonce` |
| `cancellation_token` — "mixed, therefore live" | **inert** ✗ | the two non-`None` assignments are `Option<tokio_util::sync::CancellationToken>` in `engine.rs`, a **different type** |

That last row is the trap the plan named, reproduced mechanically: a
value-based grep classified the wire field as live because a **different type
with the same field name** has a real assignment 3 crates away.

### The closed set: 2 inert wire mechanisms, 0 in the RPC protocols

**F-1 — worker cooperative cancellation. `TalosContext.cancelled` + the wire
`cancellation_token`. INERT. The largest instance in the codebase.**

* **Producer:** `TalosContext::cancel()` (`talos-worker-runtime/src/context.rs:1924`)
  is the only writer of the flag. Workspace-wide, `.cancel()` on a
  `TalosContext` has **exactly one call site: `worker/tests/kill_switch_tests.rs:245`**
  — a test. **Zero production callers.** (The other 11 `.cancel()` hits resolve
  to `tokio_util::sync::CancellationToken`: 9 in engine tests, 2 in
  `talos-engine/src/fence.rs:230`/`:238` — epoch fencing, a different mechanism
  that IS live.)
* **Receiver:** `is_cancelled()` is read at **20 sites across 12 files** in
  `talos-worker-runtime/src/host/` — `http`, `http_stream`, `llm`,
  `llm_streaming`, `llm_tools`, `graphql`, `database`, `email`, `webhook`,
  `model`, `integration_state`. Plus a background clone read at
  `host/http_stream.rs:353`.
* **The wire field that would feed it is itself inert AND unread.**
  `TalosContext.cancellation_token: Option<String>` is `None` at both
  construction sites and is read nowhere; `JobRequest.cancellation_token` /
  `PipelineStep.cancellation_token` are `None` at all **28** production
  assignments.
* **Operator-visible consequence.** `cancel_execution`
  (`talos-mcp-handlers/src/executions.rs:977`) calls
  `ExecutionRepository::mark_execution_cancelled`, which is a **single `UPDATE
  workflow_executions SET status='cancelled'`** and nothing else — no NATS
  signal. The handler then returns *"Execution cancelled successfully"*. The
  in-flight WASM keeps running to fuel exhaustion or timeout. This is the
  [[misleading-report-field-class]] shape at the tool boundary: the operator is
  told a thing happened that did not.
* **Consequent dead metric.** `wasm.executions.cancelled`
  (`talos-worker-runtime/src/metrics.rs:1072`) has 7 live `.add(1)` call sites,
  so it **passes lint check 58** — but every one sits behind an
  `is_cancelled()` branch that is never true. It reads a permanent 0. Check 58
  is scoped to `TalosMetrics` in `talos-metrics/src/lib.rs` and tests for the
  presence of an increment; it cannot see an increment that is unreachable.
* **A doc comment names a field that does not exist.**
  `talos-workflow-engine/src/error.rs:185` says in-flight cancellation is
  *"the dispatcher impl's responsibility (e.g. by carrying the
  `DispatchJob::cancellation_token` to the worker…)"*. **`DispatchJob` has no
  `cancellation_token` field** — `grep -n cancellation
  talos-workflow-engine-core/src/dispatcher.rs` returns 2 lines, both about
  timeout timers. A rustdoc link to a nonexistent item.

**F-2 — `JobRequest.deadline_unix_secs`. INERT.** 21 assignments, all `0`; the
sole receiver is the `> 0` admission guard at `worker/src/main.rs:1082`. Already
documented in-code at `talos-workflow-engine-core/src/dispatcher.rs:169`
(*"which no caller currently populates"*), added by #686.

**F-3 — the six signed RPC protocols: ZERO inert fields.** Every field of all 24
structs has at least one production assignment to a non-disabled value. This is
a real contrast, not an absence of evidence — the RPC protocols were built with
their producers, and they are the part of the wire surface where the pattern
does **not** appear.

**F-4 — `DispatchJob` (35 fields): ZERO inert fields**, including `deadline`,
which #686 wired to `clamp_attempt_timeout`.

**F-5 — `RuntimeMetrics` (worker OTel, 12 metric fields): ZERO first-order dead
metrics.** Every field has a live `.add`/`.record`/`.observe` call site outside
tests. The only defect here is the second-order one under F-1.

### Legitimately-optional fields the sweep correctly did NOT flag
Worth naming, because any future guard must not flag them either:
`sealing` (23 prod assignments `0`, **1** `SEALING_CLAIM_ECIES`),
`crypto_scheme` (53 × `0`, **1** `CRYPTO_SCHEME_ED25519`),
`dry_run` (25 × `false`, 1 × `true`), `claim_inbox` (1 non-`None` site),
`reply_topic` (3 sites). These are env-gated opt-ins that are 96–98 % "off" at
the assignment level and entirely correct.

---

## ⚠ SECURITY — one of these is a security control, and it is F-1

**Stated separately and loudly, per the plan's invariant.**

`TalosContext::is_cancelled()` is the guard in front of **the worker's egress
host functions**, specifically: `host/http.rs` (`fetch`, `fetch_all`),
`host/http_stream.rs` (SSE), `host/llm.rs` + `host/llm_streaming.rs` +
`host/llm_tools.rs` (data to LLM providers), `host/email.rs` (`send`),
`host/webhook.rs` (`send`, incl. inside the retry sleep), `host/graphql.rs`,
`host/database.rs`, `host/integration_state.rs`, `host/model.rs`.

**These are the paths by which an in-flight module moves data off the host.
The abort control in front of all of them has no production trigger.**

The containment action an operator would take on discovering a misbehaving,
looping-on-egress, or compromised module is `cancel_execution`. That call
writes one DB row and answers **"Execution cancelled successfully."** The
module keeps fetching, keeps sending, keeps calling the LLM.

**Severity, bounded honestly — I do not have an observation of this being
exploited, and three sibling controls ARE live:**
* Fuel metering and **epoch interruption** genuinely stop a runaway or
  non-yielding loop (`kill_switch_tests` 1 and 2 — those mechanisms have real
  production drivers, `spawn_epoch_ticker` among them).
* Per-attempt timeouts and the workflow-budget clamp (#686) bound duration.
* So the exposure is not unbounded: it is **the remaining budget of the
  in-flight node**, not forever.

**What is genuinely missing is the *operator-initiated* abort.** The only abort
actually available today is coarse and fleet-wide — restart the worker — which
kills every co-resident execution. That is the gap, and it is a security gap,
not a convenience gap.

**Its test suite asserts the opposite impression.**
`worker/tests/kill_switch_tests.rs` opens *"These prove the guarantees the whole
sandbox design leans on"* and item 3 is
`cancellation_aborts_http_promptly`. The test is **correct** — the mechanism
works when invoked — and it is a legitimate test, not a booby trap by
[[tripwire-versus-booby-trap]]'s criterion (it asserts an invariant, and it
would go red for the right reason). But its presence in the kill-switch suite
means a reader auditing "can we stop a runaway module?" gets a green answer to
a question production never asks.

**F-2 `deadline_unix_secs` is NOT a security control** — I checked rather than
assumed. Replay protection for `JobRequest` comes from the nonce freshness
window plus the replay cache (`check_freshness_window`,
`talos-workflow-job-protocol/src/lib.rs:1303`), not from the deadline. The
deadline guard is a resource-efficiency admission control. Its **HMAC binding**
(H-7) is separately worth keeping and is not vacuous: it stops an on-wire
attacker injecting a *past* deadline to make the worker refuse valid jobs.

---

## D3 — classification and disposition

**Nothing was wired or deleted in this cycle.** Recommendations only.

| # | mechanism | populated | enforced | disposition |
|---|---|---|---|---|
| F-1a | `TalosContext.cancelled` / `is_cancelled()` (20 guards) | **no** (1 test caller) | yes, heavily | **document + assign an owner** (security) |
| F-1b | wire `cancellation_token` (`JobRequest`, `PipelineStep`) | **no** (28 × `None`) | **no** (read nowhere) | **document, do not delete yet** |
| F-1c | `wasm.executions.cancelled` OTel counter | increments exist but are unreachable | — | **document** alongside F-1a |
| F-2 | `JobRequest.deadline_unix_secs` | **no** (21 × `0`) | yes (`> 0` admission) | **already documented — leave alone** |
| — | `increment_usage` (#681) | no (0 callers) | is the ORDER BY key's sole writer | **already documented — no action** |
| — | off-host backup uploader (#675) | never executed | chart alerts | per #675 — not re-derived here |
| — | `WorkerHeartbeat` (#679) | **yes, since 2026-08** | yes | **resolved, not inert** |

### F-1 — document, and give it an owner. Do not wire, do not delete.
* **Do not wire in this cycle.** In-flight abort needs a design decision the
  plan explicitly puts out of scope: a controller→worker signal (a NATS
  cancel subject keyed on `job_id`, or a claim-inbox-style channel), plus a
  policy for pipelines and for jobs already past their last `is_cancelled()`
  checkpoint. That is a fleet-wide behaviour change.
* **Do not delete.** The 20 guards are cheap, correct, and are the receiving
  half of a control we want. Deleting them would make wiring it later a
  20-file change and would remove the only record that the design intended it.
  The wire field cannot be deleted casually either: it is HMAC-bound in
  `signing_payload` (H-7 / C-2), so removing it is a wire-format change under
  the deploy-compat rule and needs a coordinated worker/controller roll.
* **Do document — in code, per the #675/#681 house shape**, at three places
  where a reader currently gets a false impression:
  1. `TalosContext::cancel` (`talos-worker-runtime/src/context.rs:1924`) — the
     producer. State that it has no production caller and name what would be
     one. This is the single highest-value line, because it is where anyone
     tracing the mechanism lands.
  2. `TalosContext.cancellation_token` (`context.rs:197-198`) — its doc comment
     currently asserts *"host functions check this token periodically and abort
     if revoked."* **No host function reads this field.** That sentence is
     false as written and should say what is actually true: the abort is driven
     by the `cancelled` flag, and nothing sets it.
  3. `cancel_execution` — the operator message. **This is the one change I
     would recommend making outside the documentation set**, because it is
     local, non-fleet-wide, and fixes a
     [[misleading-report-field-class]] defect: the handler reports
     *"Execution cancelled successfully"* for an operation that marks a row and
     does not stop the work. It should say that in-flight work continues until
     its budget expires.
* **Separately, a factual correction:**
  `talos-workflow-engine/src/error.rs:185` documents in-flight cancellation as
  carrying **`DispatchJob::cancellation_token`** — a field that **does not
  exist** on `DispatchJob`. A rustdoc link to a nonexistent item, and the kind
  of claim [[falsification-first]] flags: grep for the mechanism a comment
  asserts, not for the comment.

### F-2 — leave alone. Explicitly do not wire.
Already carries the house-shape note at
`talos-workflow-engine-core/src/dispatcher.rs:169`. #686 established that
wiring it is the **wrong** remedy — it is admission-only and would have
ADMITTED the incident's attempt 3. Nothing in this cycle changes that. The
correct control (clamp the attempt to the remaining budget) shipped in #686.

---

## D4 — is a guard possible? **Measured. Recommendation: NO GUARD.**

The candidate rule: *"a wire-type field whose every production assignment is
the disabled value."* I built it, ran it against D2's closed set, and measured
it at three levels of refinement.

| version | candidates | true positives | false positives | recall vs D2's 2 inert mechanisms |
|---|---|---|---|---|
| naive (`field:` literals only) | 3 | 1 (`deadline_unix_secs`) | 2 (`step_results`, `heartbeat_nonce`) | **1/2 (50 %)** |
| + shorthand + `.field =` mutation exclusion | **0** | 0 | 0 | **0/2 (0 %)** |
| + `#[cfg(test)] mod` region stripping | 1 | 1 | 0 | **1/2 (50 %)** |

**Each refinement that fixed one failure mode opened another.** Adding the
mutation exclusion (needed to kill the `heartbeat_nonce` false positive)
silently killed the only TRUE positive as well, because the H-7 tamper tests
live in an inline `#[cfg(test)] mod` inside `job-protocol/src/lib.rs` and do
`req.deadline_unix_secs = 0`. Recovering it needed check 58's exact perl
`#[cfg(test)]`-region machinery. **A version of this guard that looked
reasonable scored 0 % recall while reporting a clean sweep** — a
[[gate-that-doesnt-gate]] at its most convincing.

**Recall caps at 50 % and grep cannot lift it.** No refinement finds
`cancellation_token`, because the wire field is classified live by a
`self.cancellation_token.clone()` on a **different type**
(`tokio_util::sync::CancellationToken`) three crates away. Separating them
requires resolving the receiver type of a struct literal — not something a
textual lint can do. That is the same failure that produced a wrong answer
three times this session, and it is *structural* for this rule, not a bug in my
regex.

**And the one true positive is already a known, deliberate state.** A shipped
guard would fire on `deadline_unix_secs` on day one, take an opt-out
immediately, and thereafter be worth only "catches the next one" — at 50 %
recall, against a class that has produced 2 members in a full sweep of ~130
wire and trait-boundary fields, over a workspace history of months. Set against
check 58's machinery as the implementation cost, that is a poor trade, and it
matches the six of seven guards already rejected on precision this arc.

**What I would do instead, and it is cheaper.** The D1 evidence says the
failure is not in the code, it is in the review: `47f27b18` was an explicit
*enforcement* remediation pass that added guards to a mechanism with no
producer. A one-line review question — **"this check reads a field: what sets
it, and is that a production path?"** — has recall a lint cannot reach,
because a reviewer can resolve a type. It also catches the second-order case
(F-1c: a metric with live increments behind an unreachable branch), which no
version of the lint above can see.

---

## Standing mandate — how this document itself goes stale, and what makes it wrong

Applying the thesis to itself, since the whole point is that a mechanism can
look live while being inert.

**This document is a snapshot of `31c13519` and has an expiry date.** It becomes
wrong, silently, if:
* **Someone wires F-1** (adds a production `ctx.cancel()` caller, or a
  controller→worker cancel signal). The security section then overstates the
  gap. **Refuting check: `grep -rn '\.cancel()' --include='*.rs' .` and resolve
  each hit to its receiver type — a `TalosContext` receiver outside
  `worker/tests/` means this document is stale.**
* **Someone populates `deadline_unix_secs`.** **Refuting check:
  `grep -rn 'deadline_unix_secs[[:space:]]*:' --include='*.rs' .` — any value
  other than `0` outside the struct declaration.**
* **Someone deletes the wire `cancellation_token`** — then F-1b is moot and the
  wire-format snapshot tests will have changed.
* **A new wire field lands receiver-first.** Nothing here detects that; D4
  concluded no guard, so this document does not self-maintain. That is a
  deliberate accepted cost, stated rather than hidden.

**The count "2 inert mechanisms across ~130 fields" is the load-bearing number,
and it is the one most likely to be wrong.** It rests on a textual sweep whose
own limitations I measured in D4 — it cannot resolve types, so a *second*
`cancellation_token`-shaped field (same name as a live one on another type)
would be invisible to it exactly as the first one was. **The count is a floor,
not a total.** Anything that reads it as a total is reading it wrong.

**Nothing in this document should be cited as evidence that the rest of the
wire surface is fine.** F-3 (RPC protocols clean) and F-4/F-5 (`DispatchJob`,
`RuntimeMetrics` clean) are results of the same limited method.
