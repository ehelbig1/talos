# 2026-09-09 — the herd, and the timeout that was not a per-call timeout

Narrative for the CLAUDE.md digest entry of the same name. Every number here was
re-measured in this package; three of the five briefed claims needed correcting.

## What was briefed, and what survived

**C1 — the tail is real.** SURVIVES verbatim. Over 7 days of `module_executions`:
`Hybrid Classify (Alerts)` n=166 p50 8.3 s p95 38.6 s max 162.5 s; `LLM Inference`
n=113 p50 13.8 s p95 63.6 s max 142.5 s; `hybrid-classify-inbox` n=63 p50 5.3 s max
14.4 s. `duration_source` is `monotonic` for all 9 337 rows in the window, so these
are measured rather than derived.

**C2 — the tail is a HERD.** SURVIVES, and the mechanism is now pinned to the
second. All 11 `>60 s` executions completed; 8 of them start within 30 s of 12:00:00
UTC; and on four separate days the two slow calls are a PAIR — `LLM Inference` then
`Hybrid Classify (Alerts)`, 1–8 s apart — a shape the brief did not name.

**C3 — "five workflows fire together, several with LLM nodes".** REFUTED in two
places, one of them load-bearing.

*The Ollama in the brief is not the Ollama that serves inference.* The worker and the
controller both carry `OLLAMA_URL=http://host.docker.internal:11434`, which is a
NATIVE host Ollama 0.31.2 (PID 1535). The `talos-ollama` CONTAINER (Ollama 0.5.1)
publishes no ports and serves the controller's `EMBEDDING_API_URL` only: across the
61 499 log lines `docker logs` will surrender it has taken **3 810 `POST
/v1/embeddings` and 0 `/api/chat`**. Anyone debugging this from the container logs —
which is what the brief's framing invites — sees an idle Ollama and concludes there
is no herd.

*Three of the five named workflows have no LLM node at all.* `pa-ask-email` (`*/15`),
`pa-followup-approval-notifier` (`*/15`) and `ops-critical-notifier` (`*/30`) carry
zero, which is why every observed slow pair is exactly two modules and never a third.
The real population is **12 enabled LLM-bearing schedules and 15 LLM-bearing nodes
across 15 non-archived workflows, every one `PROVIDER=ollama`, none external.**

**C4 — nothing bounds concurrent LLM calls.** SURVIVES. `Semaphore|acquire|permit|
max_concurrent` over `talos-worker-runtime/src/host/llm*.rs`,
`host/llm_providers/` and all of `talos-llm/src/` returns zero matches;
`local_llm_http_client()` sets a connect timeout and a redirect policy and no
`.timeout()`, no `pool_max_idle_per_host`, no `pool_idle_timeout`. The upstream gates
bound NODES and EXECUTIONS, not LLM calls per backend.

**C5 — the blast radius.** The brief did not know it. It is live, daily, and has
already failed a workflow outright.

## Where the serialization actually happens

Not in Talos.

```
grep -h 'server config' ~/.ollama/logs/server.log | tail -1
  → OLLAMA_NUM_PARALLEL:1  OLLAMA_MAX_QUEUE:512  OLLAMA_MAX_LOADED_MODELS:0
    OLLAMA_KEEP_ALIVE:5m0s  OLLAMA_CONTEXT_LENGTH:131072
```

One inference slot per loaded model, FIFO, queue depth 512, on a host process Talos
does not configure and cannot see. Talos contributes the other half: it issues an
unbounded number of simultaneous requests into that single slot, and it charges the
WAIT to a timeout documented as bounding one call.

## The mechanism, reconstructed to the second

2026-09-09, the daily 12:00 UTC fire (08:00 EDT in the Ollama log):

| | |
|---|---|
| `module_executions` | LLM Inference `12:00:06.365 → 12:01:31.597 UTC` = 85 227 ms, **completed** |
| host Ollama | `08:01:06 \| 500 \| 1m0s` (started 08:00:06) then `08:01:31 \| 200 \| 25.079s` |
| arithmetic | 60.00 + 25.08 = **85.08 s** ✓ |

and its sibling, 1.2 s behind it — `Hybrid Classify (Alerts)`, 98 406 ms, also
completed, also a 60 s timeout at `08:01:07` then a 24.868 s success and five short
calls to `08:01:45.9`.

2026-09-07 is the same shape with one more attempt: `59.977s`, `59.880s`, then a
success — 60 + 60 + 23 = **142.5 s**, matching the module row exactly, and that
execution carries a `node_retrying` event.

**Nothing else was in flight.** `grep '^\[GIN\] 2026/09/09 - 0(7:5[0-9]|8:[0-1][0-9])'`
returns those eleven `/api/chat` lines and nothing else. The two workflows were
contending with **each other**. And it is not model loading: the load events in that
log run `0.76 – 3.3 s` and there is **no load event between 07:35 and 08:01:06** —
the runner was already up.

So the second request's ENTIRE 60 s budget was queue. It was never sent anything to
wait for; it was waiting for its sibling.

## The dose-response curve

All 1 194 completed LLM module executions over 31 days, bucketed by how many other
LLM module executions overlapped them in wall-clock (a self-join on
`b.started_at < a.completed_at AND b.completed_at > a.started_at`):

| concurrent siblings | n | p50 | p90 | share >60 s |
|---|---|---|---|---|
| **0** | 1029 | **8.5 s** | 18.0 s | **1.3 %** |
| **1** | 99 | **37.8 s** | 112.4 s | **20 %** |
| **2** | 45 | **83.3 s** | 2444 s | **58 %** |
| **3** | 14 | **1106 s** | 5211 s | **86 %** |
| 4 | 6 | 87.2 s | 4165 s | 67 % |
| 7 | 1 | 277 s | — | 100 % |

One concurrent sibling quadruples p50 and takes the timeout rate from 1.3 % to 20 %.
This is a single-server FIFO queueing curve and it is the whole finding — the brief's
eleven-call anecdote badly undersold it.

**The consequence that decides the fix**: serializing is FASTER in aggregate, not
merely fairer. Two calls whose solo p50 is 8.5 s finish in ~17 s back to back; run
together their measured p50 is 37.8 s. Concurrency on a compute-saturated inference
backend is pure overhead.

## The blast radius (C5)

**48 sixty-second timeouts** across all retained host-Ollama logs (2026-08-10 →
2026-09-09, 32 972 `/api/chat` calls, 0.146 %). Ground truth from the logs, not from
`increase()` — which extrapolates across worker restarts and reported 20 where the
logs show 13 for the same window. By time of day:

```
  21 08:01     3 08:11     2 20:08  2 09:17  2 09:08  2 09:07  2 09:04
   2 09:03     2 09:01     2 08:32  2 08:16  1 09:46  1 09:11  1 07:31
   1 07:14     1 07:05     1 05:20
```

**21 of 48 at exactly 08:01 EDT = 12:01 UTC**, 24 within the twelve minutes after
12:00 UTC.

**It has already failed a workflow.** the hourly alert-triage workflow, 2026-08-27 13:00 UTC:
`Scheduled workflow failed: workflow execution timed out after 300 seconds` — in a
window where the Ollama log shows **six** 60 s timeouts. `LLM Inference` carries 18
hard `failed` rows in 31 days, several reading `execution timed out after 120
seconds (enforced limit from job)`.

**It is one second from failing the flagship.** `pa-chief-of-staff` carries
`workflows.timeout_seconds = 180`. On 2026-09-07 it took **174.5 s — 97 % of its
budget**, of which 120 s was two timeouts that bought nothing.

**The attempt-window clamp is NOT the harm vector, checked fleet-wide.** Computing
`timeout_secs + TOKIO_WRAP_GRACE_SECS(5) > budget − BUDGET_RESERVE_SECS(2)` over
every node of every non-archived workflow returns 11 nodes in 3 workflows — the
already-documented `pa-ask-email` / `pa-followup-approval-notifier` /
`ops-critical-notifier` population — and none of them is LLM-bearing. Neither herd
workflow appears. The brief's guess was right and is now checked everywhere rather
than on one workflow.

## Why a bound and not jitter

Jitter is the standard answer to a herd, and it was measured before it was rejected:

| bucket | overlapping | total |
|---|---|---|
| 12:00–12:14 UTC | 49 | 62 |
| everything else | **116** | 1132 |

**70 % of all overlapping LLM executions happen outside the noon herd**, and the
busiest single minute is **10:00 UTC (36 overlapping) — more than 12:00 (34)**; that
is `pa-autonomy-digest` (`0 6` EDT) meeting the hourly alert-triage workflow. The cron
set has more collisions built into it: `pa-meeting-prep` `35 7` and `pa-inbox-triage`
`37 7` are two minutes apart, `pa-inbox-organizer` `20 7-23/2` and `-work`
`25 7-23/2` are five.

So any jitter narrow enough to be defensible fixes one of at least two herds, and it
changes WHEN a user's workflows run, which is operator-visible; an opt-in
default-off jitter fixes nothing on the fleet that has the problem. A concurrency
bound covers every overlap including the ones that are not schedule-driven at all,
and — per the curve above — it is faster rather than merely fairer. Both would be
better than either; jitter is not ruled out, it is out of scope for a package that
does not change the user's schedules.

## The mutation that mattered

Nine mutations, worst blast radius first, each applied alone with the diff printed
before the result was believed. Eight caught immediately. **M8 — reverting the
SECOND call site (`llm_tools.rs`) to `let _ =` — left all 651 crate tests green**,
because the gate's own unit tests cannot see a call site (checks 74b/79b's stated
limit). Closed by a third production-path case driving
`wit_llm_tools::Host::complete_with_tools`; M8 and M9 then both fail. One test per
SITE whose consequence is a real behaviour change, not one per shape.

And a measurement that corrected a claim this package had itself written:
**`#[must_use]` on `LocalLlmSlot` does not protect the call sites.** Both bind
`Option<LocalLlmSlot>` and the attribute does not propagate through `Option`; a probe
reducing a site to a bare expression statement produced no clippy diagnostic under
`-D warnings`. The doc comment says so now instead of claiming a guard it does not
give.
