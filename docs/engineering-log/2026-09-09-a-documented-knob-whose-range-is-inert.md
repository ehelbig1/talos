# A documented tunable whose advertised range is inert, on the model that decides what an actor remembers (2026-09-09)

Digest entry: **"A documented knob whose advertised range is inert"** in
`CLAUDE.md`. This file is the narrative; every decision is there.

## What was measured

`ADAPTIVE_RANK_LOOKBACK_DAYS` is documented in TWO places
(`docs/adaptive-memory-ranking.md`, `docs/configuration-reference.md`) as the
adaptive-rank "training window", default 30, and
`talos_config::adaptive_rank_lookback_days()` clamps it to **[1, 3650]** — ten
years. `talos-memory-ranking/src/lib.rs` carries a hardcoded
`TRAINING_FETCH_CAP = 20_000`, and the Phase-1 fetch
(`talos_memory::fetch_rank_training_examples`) is
`ORDER BY emc.created_at DESC LIMIT $3`. Widening the window therefore adds only
OLDER rows, which sort last and are never read.

**The effective window, measured to three decimals** on the reference fleet, for
the one truncating actor (`personal-assistant`, ~2 400–3 100 provenance rows/day
across the whole 30-day window):

```
  rank |     created_at      | days ago
     1 | 2026-09-09 20:16:57 |  0.002
 20000 | 2026-09-03 07:00:15 |  6.555   <- the real window
 72656 | 2026-08-10 20:30:10 | 29.993   <- the configured window
```

**Configured 30 days → 6.555 days used.**

**Proved rather than argued.** The md5 of the fetched id set at each setting:

```
lookback_days | n_fetched | digest
            1 |     2 966 | ae7554746649b2ee70369bd161a03277
            7 |    20 000 | 71538603da87d22d1cabfa9294ac1531
           30 |    20 000 | 71538603da87d22d1cabfa9294ac1531
           60 |    20 000 | 71538603da87d22d1cabfa9294ac1531
           90 |    20 000 | 71538603da87d22d1cabfa9294ac1531
          365 |    20 000 | 71538603da87d22d1cabfa9294ac1531
         3650 |    20 000 | 71538603da87d22d1cabfa9294ac1531
```

Six of the seven — **every value from 7 to 3650, i.e. 99.8 % of the advertised
range** — return the same 20 000 rows. And the fit itself is identical: driving
the PRODUCTION `build_training_set` + `fit_rank_weights` over each row set gives
`rel=+0.801003 rec=+0.985961 imp=+1.327735 acc=+1.162790` at days=30, 60 AND 90,
**to six decimal places**. The knob is effective DOWNWARD only.

## The live truncation, and why it was the ONLY WARN

`docker logs talos-controller`: 423 lines since the 19:53Z deploy, **1 WARN, 0
ERROR**, and the WARN is
`rank_training_truncated cap=20000 n_fetched=20000 n_available=72642
n_dropped=52642 lookback_days=30`. 72.5 % of the configured window dropped, and
not at random — the OLDEST 72.5 %.

## What the brief got wrong, and it changed the shape of the fix

The brief said the disclosure existed "in exactly one channel: a log line — no
metric, no operator tool, **nothing on the stored model**". Two of those three
are false, and #654 (`eaa1dab1`, 2026-08-19, *"a training cap that reported
itself as the population"*) is why.

* **The stored model DOES carry it.** `RankWeights.fetch:
  Option<FetchProvenance>`, and the live row proves it:
  `"fetch": {"fetch_cap": 20000, "n_fetched": 20000, "n_available": 72642}`.
* **An operator tool DOES render it.** `get_operator_digest`'s learned panel has
  emitted `n_fetched` / `window_available` / `window_rows_dropped` /
  `population_note` since #654.
* **No metric — that half stands.** `curl /metrics/prometheus | grep -i rank`
  returns only the generic `talos_background_task_exits_total{task=
  "rank_training_scheduler"}` supervision series.

**So the gap was not "there is no disclosure". It was that every existing
disclosure is denominated in ROWS — and the row counts MOVE when the inert knob
is turned.** `n_available` is counted with the operator's own `since`:

```
lookback_days | n_available
            7 |  21 117
           30 |  72 656
           60 | 110 805
```

An operator who raises 30 → 90 watches `window_rows_dropped` go 52 642 → 90 805
while every fitted coefficient stays bit-identical. The disclosure does not
merely fail to say the knob is inert — **it reacts to the inert knob in the
direction that reads as "the change took effect"**.

## The finding the brief did not have: there are FOUR ceilings, and the third one binds even with no cap

| # | ceiling | value | effective window here | where |
|---|---|---|---|---|
| 1 | `TRAINING_FETCH_CAP` | 20 000 rows | **6.56 days** | hardcoded |
| 2 | `RANK_TRAINING_EXAMPLE_MAX` | 50 000 rows | ~17 days | hardcoded clamp on the caller's `limit` |
| 3 | **execution ARCHIVAL** | `ARCHIVE_AFTER_DAYS` = 30 | **~30 days** | the fetch `LEFT JOIN workflow_executions` and never the archive |
| 4 | provenance retention | `MEMORY_RANK_PROVENANCE_RETENTION_DAYS` = 90 | 90 days | a sweep |

Ceiling 3 is the one that decides the design. Past archival a provenance row's
`LEFT JOIN workflow_executions` yields NULL, so `example_label` returns `None`
and `build_training_set` DROPS the row as unlabeled:

```
lookback_days | emc rows | with a LIVE execution | orphaned
            7 |  21 117  |  21 117               |      0
           30 |  72 663  |  72 663               |      0
           45 | 102 461  |  72 712               | 29 749
           60 | 110 812  |  72 712               | 38 100
           90 | 110 812  |  72 712               | 38 100
```

`with a LIVE execution` **SATURATES at 72 712** from 30 days on. Confirmed
through the fit: at an unbounded cap, days=60 and days=90 produce the same model
as each other (`labeled` saturates at 74 894).

**So lifting the row cap would not restore the advertised range.** That is what
settled the behaviour decision.

## What the refit would change, so the trade is on the record

Through the production fit, an unbounded fetch over the whole 30-day window
against the shipped capped fetch:

| | relevance | recency | importance | access | bias |
|---|---|---|---|---|---|
| capped (6.56 days) | +0.801003 | +0.985961 | +1.327735 | +1.162790 | +1.552335 |
| full 30 days | +0.711537 | +0.886853 | +1.263605 | +1.189874 | +1.392189 |
| delta | −11.2 % | −10.1 % | −4.8 % | +2.3 % | — |

Normalised to relevance, the full-window fit leans **~7 % harder on importance**.
Real, and modest. #654 measured the downstream effect once — refitting on the
whole window moved the top-1 injected memory in 81 of 7 541 executions (1.07 %),
the top-3 set in 98, any ordering in 409 — and recorded that this is a LOWER
bound, since the provenance table records only memories that were ALREADY
injected. **Neither fit is known to be the better one; there is no held-out
evaluation of this ranker.**

## Cost, measured so it cannot be cited as the reason

`EXPLAIN ANALYZE` of the verbatim production fetch, three runs each:

```
LIMIT 20000: 19.953 / 16.913 / 18.377 ms   (shared hit=14 616)
LIMIT 50000: 60.565 / 58.097 / 58.227 ms   (shared hit=38 182, read=7)
count(*) denominator: 6.695 ms             (shared hit=887)
```

Roughly linear. At the hard 50 000 ceiling the whole fleet's fetch is well under
3 s per SIX-HOURLY tick over ≤50 actors. "It would be expensive" is the easy
wrong reason to leave the cap alone.

## C4 — this really is the model that decides what an actor recalls

One serving call site, `talos-workflow-repository/src/actor_context.rs:371`,
inside `ENABLE_ADAPTIVE_RANK` (default true). `docker inspect` shows
`ENABLE_ADAPTIVE_RANK=` and `ADAPTIVE_RANK_LOOKBACK_DAYS=` — set but EMPTY,
which `bool_env_or_default` / `positive_env_or_default` read as unset (check 73's
rule), so both defaults are in force. `personal-assistant`'s model has
`n_examples: 20000` ≥ the 50-example trust gate and all-positive base
coefficients, so the LEARNED weights serve. And they are nowhere near the
globals — normalised to relevance = 1:

| | relevance | recency | importance | access |
|---|---|---|---|---|
| global default | 1.00 | 0.30 | 0.50 | 0.15 |
| learned (capped fit) | 1.00 | 1.23 | 1.66 | 1.00 (clamped from 1.163) |

## Is it a class? Four, of which two are undisclosed

Measured by enumerating every call site of every documented numeric
`talos_config::` knob and reading each one, not by the brief's 117-file proxy:

| | site | const | knob | disclosed? |
|---|---|---|---|---|
| **A** | `talos-memory-ranking/src/lib.rs` | `TRAINING_FETCH_CAP = 20_000` | `ADAPTIVE_RANK_LOOKBACK_DAYS` | at the CONST only — fixed here |
| **B** | `talos-workflow-validation/src/lib.rs:788` | `HISTORY_MAX_EXECUTIONS = 50` | `history_window_days()` | **yes**, at the const |
| **C** | `talos-workflow-validation/src/lib.rs:832` | `HISTORY_WINDOW_DAYS = 30` | `ARCHIVE_AFTER_DAYS` | **yes**, at the const + a test |
| **D** | `talos-workflow-repository/src/actor_context.rs:249` | bare literals `10`/`20`/`clamp(1,50)` in three files | `SMART_MEMORY_CONTEXT_BYTE_BUDGET` | **no** |

**B is the instructive one.** Its doc comment says, unprompted: *"On a daily
workflow 50 covers the entire retention window. On a high-frequency one it
covers roughly the last twelve hours, so the check is strongly recency-biased
there and will stay quiet about a chronic-but-rare failure that a 30-day view
would surface."* That is the sentence this package had to write for A. **The repo
already knows how to write this disclosure; it writes it where the reader of the
CONSTANT will see it, not where the operator reading
`docs/configuration-reference.md` will.**

The contrast that proves the shape is real: `stale_sweep`'s
`STALE_SWEEP_BATCH = 500` beside `STALE_EXECUTION_MINUTES` is the same query
shape and is NOT a defect, because it orders `started_at ASC` and repeats, so the
backlog drains. **`DESC` + a cap + no cursor is what makes A a defect.**

## The trailing-space item

`talos-mcp-handlers/src/executions.rs:5101-5107` (from #788) each ended
`... the \n\`, so every wrapped line of the waterfall's `[!] rows past the run's
end` footer carried a trailing blank. Removing the space before each `\n` is
behaviour-preserving. #785's `scripts/lint-whitespace-runs.py` looks for runs of
≥5 spaces and is structurally blind to a single one.

Extending #785's own literal resolver to look for a rendered line ENDING in
whitespace: **13 hits / 5 files pre-fix (7 real, 6 legitimate), 6 hits / 4 files
after**. 53.8 % precision, six markers on correct code — the survivors are three
trailing spaces inside multi-line SQL raw strings, a REGEX character class
`[^ \t\n]`, and a deliberate whitespace test fixture. Not shipped.

**One measurement error worth recording**: the first detector used `[^\S\n]+\n`,
which matches `\r\n` — `\r` is whitespace and is not `\n` — and reported **82
hits across 23 files**, every HTTP and MIME header among them. Narrowing to
`[ \t]+\n` gives the 13.


## Addendum 2026-09-11 — the two adjacent knobs, closed by deletion

The original entry verified `DB_EXECUTION_TIMEOUT_SECS` (read, logged as
`execution_timeout=300s` on every connect, applied to nothing) and
`EXECUTION_MAX_ROWS` (a `talos-config` accessor with zero callers, documented
in two places as "max execution rows before eviction") and left both alone as
"a behaviour change with its own blast radius". That framing assumed the fix
was to WIRE them. Deleting them is not a behaviour change — nothing read either
value — and it is what shipped: the read and the connect-line claim in
`talos-db`, the accessor and its three tests in `talos-config`, and both doc
rows struck through in the `GRAPHQL_MAX_DEPTH` style, saying what was never
true.

Measured first, so the population is on record rather than assumed: the
authoritative `docs/configuration-reference.md` names **331** tokens; following
every token that is read only inside `talos-config` to its accessor and then to
that accessor's callers finds exactly ONE with none (`EXECUTION_MAX_ROWS`). The
other is read directly by `talos-db`, which the accessor walk cannot see — two
detectors, two shapes, the same class. Wiring was declined on evidence: there is
no "execution-path pool" for a second timeout to govern, the live
`pg_stat_statements` shows the slowest application statement at 274 ms (the
only entries above a second are the one-off `COPY`s of the pg16→pg17 restore),
and count-based eviction would add a destructive sweep beside the age-based
archive/delete pair that already exists.

Found on the way: `set_workflow_priority`'s SUCCESS TEXT still read "New
executions will be dispatched with this priority" after #801 had corrected the
tool's DESCRIPTION — the same false claim in the second of the two places it
lived. The live check for #801 (set `high`, run through `call_workflow`, read
the row: `high`) surfaced it, which is the argument for doing the live check.


## Addendum 2026-09-11 — the truncation line is INFO

Eight consecutive dev deploys on 2026-09-10/11 each produced exactly one
controller WARN at boot, and it was this one: `rank_training_truncated cap=20000
…`. The entry above declined an alert on this state because the cap is
deliberately fixed and binds on every tick on any fleet with one busy actor,
so an alert would fire permanently — check 69's trap. A WARN line on the same
cadence is the same trap one level down: an operator who learns that the first
WARN after every boot is noise has learned to skim WARN. The line is now INFO,
every field intact (`lookback_inert`, `effective_lookback_days`,
`lookback_shortfall_days`, `n_dropped`), and the machine-readable half —
`talos_rank_training_fetches_total{coverage}` and the shortfall gauge — is
what a dashboard or a future alert reads. The neighbouring
"population count failed" WARN is unchanged: that is a read that did not
answer, which is a finding, not a steady state.
