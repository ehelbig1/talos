# Scheduler benchmarking & regression detection

The repo ships a Criterion benchmark suite at
`talos-workflow-engine/benches/scheduler.rs` covering the scheduler
reactor under three families: fan-out, linear-chain, and seeded
resume. The numbers reflect scheduling overhead only — the dispatcher
is a no-op, no network, no wasm runtime, no real worker. Use them to
catch regressions in the engine's own bookkeeping (ready queue,
`FuturesUnordered` orchestration, chain detection, seed propagation).

## Workflow

Two scripts under `scripts/` wrap the Criterion workflow.

### `scripts/bench-baseline.sh`

Capture a baseline of the current scheduler perf:

```bash
./scripts/bench-baseline.sh
```

Saves to `target/criterion/<bench>/main/`. Override the baseline name
via `BENCH_BASELINE=feature-x` to avoid clobbering an existing one.

When to run:

* On `main` after merging an intentional perf change (so the new
  baseline reflects the new normal).
* On a feature branch before starting a perf-sensitive change (so you
  have a "before" you can diff against locally).

### `scripts/bench-check.sh`

Compare the current run against the saved baseline:

```bash
./scripts/bench-check.sh
```

* Exits `0` when every bench stays within the noise threshold
  (`±10%` by default — override via `BENCH_NOISE=0.05` for a tighter
  gate).
* Exits `1` when at least one bench regressed past the threshold.
  Stderr names the regressing case(s).
* Exits `2` when no baseline exists. Run `bench-baseline.sh` first.

Wire `bench-check.sh` into CI on a merge queue or pre-merge job to
catch regressions before they ship. Run it locally before opening any
PR that touches the scheduler reactor, chain detector, or post-
completion handlers.

## What's measured

| Group | Sizes | What it stresses |
|---|---|---|
| `fanout/N` | 10 / 100 / 1000 | `FuturesUnordered`, per-node dispatch path, ready-queue churn. |
| `chain/M` | 10 / 100 | Linear-chain detection + the `dispatch_chain` batched path. |
| `seeded_resume/S` | 10 / 100 / 1000 | The seed-propagation initialisation in `run_inner` (every node but one is pre-completed). |

Each iteration builds a fresh engine + dispatcher to measure
end-to-end scheduling, not warm-cache behaviour on the global
rate-limit map or the in-memory module fetcher.

## Reading regression output

A typical regression looks like:

```text
fanout/100              time:   [546.32 µs 548.10 µs 550.21 µs]
                        change: [+18.234% +18.972% +19.703%] (p = 0.00 < 0.05)
                        Performance has regressed.
```

The `change:` line shows the lower-bound / median / upper-bound
versus the baseline. `p < 0.05` means Criterion is statistically
confident this isn't noise. The `Performance has regressed` line is
what `bench-check.sh` greps for.

If a regression is intentional (e.g. you added a security check that
costs ~5% throughput), re-baseline with `scripts/bench-baseline.sh`
and document the change in the CHANGELOG so reviewers don't get
surprised by a moved goalpost.

## What this does NOT cover

* **Real dispatch latency.** The bench dispatcher is a no-op; numbers
  do not reflect NATS / HTTP / wasm runtime overhead.
* **Sub-workflow handlers.** `Judge`, `Ensemble`, `AgentLoop`, etc.
  are not exercised. They're tested for correctness but not
  benchmarked — their cost is dominated by the underlying sub-workflow
  dispatch, not scheduling.
* **Memory / allocations.** Criterion measures wall time. Hook
  `dhat` or `heaptrack` if you need allocation profiles.

## CI integration

Drop this into your CI workflow:

```yaml
- name: Bench regression check
  run: ./scripts/bench-check.sh
  env:
    BENCH_BASELINE: main
    BENCH_NOISE: "0.10"
```

Note: the `target/criterion/` directory has to be persisted across
runs for the baseline to be available. Either restore it from cache
keyed on the merge-base of `main`, or run `bench-baseline.sh` once
on `main` and check the resulting directory into a CI artifact
store.

Without a persisted baseline, `bench-check.sh` exits 2 — useful for
distinguishing "no baseline" (operator action required) from
"regressed" (PR action required) in CI.
