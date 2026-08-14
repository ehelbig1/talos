/// OpenTelemetry metrics for WASM runtime observability
///
/// This module provides production-grade metrics for monitoring:
/// - Execution counts and rates
/// - Duration histograms (p50, p95, p99)
/// - Cache hit rates
/// - Memory usage
/// - Active instances
/// - Compilation performance
///
/// Metrics are exposed in Prometheus format at /metrics endpoint
///
/// ## Instrument naming — do NOT put `total` in a counter's name
///
/// `opentelemetry-prometheus` renders an OTEL instrument by replacing `.`
/// with `_` and then, for every monotonic counter, APPENDING `_total`
/// unconditionally. It does not check whether the name already ends in
/// `total`. So an instrument named `wasm.executions.total` is exported as
/// `wasm_executions_total_total` — verified empirically against
/// opentelemetry-prometheus 0.32 and pinned by
/// `exported_prometheus_names_are_stable_and_idle_seeds_at_zero` in
/// `metrics_tests.rs`.
///
/// Until 2026-08-02 three instruments here carried the redundant suffix
/// (`wasm.executions.total`, `wasm.errors.total`, `wasm.retries.total`) and
/// the alert rules in `observability/rules/alerts.yml` selected on the SINGLE-
/// suffixed names the exporter never produces. That is the read side of the
/// same defect as an unregistered metric: every one of those alerts was
/// permanently unfireable, and the Grafana dashboard had already been
/// hand-patched to the double-suffixed spelling — two files disagreeing
/// about the name of one series, with the alerts on the losing side.
///
/// The names below therefore carry NO `total` component; the exporter adds
/// exactly one. Sibling rule to the same class in `talos-metrics`
/// (structural lint checks 58 and 65(c)).
use opentelemetry::{global, metrics::*, KeyValue};
use std::sync::atomic::{AtomicU64, Ordering};

/// Explicit bucket boundaries (milliseconds) for `wasm.execution.duration_ms`.
///
/// ## Why these are not the defaults
///
/// Until 2026-08-04 this histogram used the OTEL Rust SDK's DEFAULT explicit
/// boundaries — `0, 5, 10, 25, 50, 75, 100, 250, 500, 750, 1000, 2500, 5000,
/// 7500, 10000` — because no `with_boundaries` call and no View existed
/// anywhere in the workspace. Its top finite bound was therefore 10 000 ms,
/// and **the thing it exists to measure lives above that**: execution duration
/// includes nested Ollama `llm::complete` time.
///
/// The consequence is specific and was measured, not inferred.
/// `histogram_quantile` cannot interpolate inside the `+Inf` bucket, so it
/// returns the highest FINITE bound whenever the quantile lands there. Over a
/// 13.75 h window the dashboard's p95 was pinned at exactly 10000.0 for 19 % of
/// evaluated points; re-measured independently over 15 d at a 60 s step, 128 of
/// 810 non-NaN points (15.8 %) read exactly 10000.0, the second most common
/// value the panel reported after 450 ms. (Reproducing that requires CHUNKED
/// `query_range` calls: 15 d at a 60 s step is 21 600 points and Prometheus
/// refuses any single request over 11 000 with `exceeded maximum resolution`.
/// A re-measurement over a later 15 d window at the same step recovered 361 of
/// 1653 non-NaN points, 21.8 % — the exact fraction moves with the window, the
/// phenomenon does not.) Every "p95 is 10 seconds" this arc
/// reported was a FLOOR reported as a value — the same misleading-report class
/// as a metric whose name implies a verdict the number does not carry.
///
/// The p99 is worse and is the sharper argument for the change: at 97.13 %
/// cumulative by 10 000 ms, the 99th percentile lands in the overflow bucket
/// even over the FULL 15 d population, so `histogram_quantile(0.99, …)`
/// returns a flat 10000 no matter how much data it is given. The p95 at least
/// resolves over a long window (5556.6 ms measured); the p99 was simply not a
/// number this histogram could produce.
///
/// ## What the live distribution actually is (15 d, ~1114 executions)
///
/// Cumulative, from `sum by (le) (increase(wasm_execution_duration_ms_bucket[15d]))`
/// on the dev stack, 2026-08-04:
///
/// | ≤ ms   |     0 |     5 |    10 |    25 |    50 |    75 |   100 |   250 |   500 |  1000 |  2500 |  5000 |  7500 | 10000 |  +Inf |
/// |--------|-------|-------|-------|-------|-------|-------|-------|-------|-------|-------|-------|-------|-------|-------|-------|
/// | cum %  |  0.0  |  0.0  | 45.3  | 57.4  | 57.9  | 59.3  | 61.1  | 62.2  | 81.7  | 85.7  | 89.7  | 94.5  | 96.3  | 97.1  | 100.0 |
///
/// The `0` and `5` columns are in the table ON PURPOSE, even though both read
/// zero. An earlier version of this table started at `10`, and omitting them is
/// what let the "largest bucket" claim below survive a review: `(5,10]` holds
/// 45.3 % of the population, more than double any other bucket, and a table
/// that starts at `10` renders that as a single opening number instead of a
/// bucket you can compare against the rest.
///
/// `_sum/_count` mean = 1283.8 ms (unaffected by saturation).
///
/// The tail above 10 s cannot be read from that table at all — it is one
/// undifferentiated 2.87 % overflow. Its actual values were recovered by
/// diffing RAW counter samples: over-sample `_count`/`_sum` below the 10 s
/// scrape interval, compress runs of identical state, and keep only intervals
/// where `_count` advanced by exactly 1 — then `Δ_sum` IS that one execution's
/// duration, exactly. 39 executions were isolated this way; 16 exceeded 10 s:
///
/// ```text
/// 10.3  10.3  10.4  11.2  12.8  13.6  13.9  14.7
/// 15.2  15.6  18.4  19.5  24.8  26.0  50.5  81.9   (seconds)
/// ```
///
/// **The slowest single execution observed was 81.9 s — 8.2× the old top
/// bound.** That sample is deliberately NOT used for percentiles: isolated
/// executions are over-represented among slow ones (41 % of the sample is
/// above 10 s versus 2.87 % of the population, a ~14× enrichment), so it is
/// evidence about the SHAPE of the tail and nothing else. The body percentages
/// above come from all 1114 executions and are unbiased.
///
/// ## Region-by-region justification
///
/// * **`5, 10`** — 45.3 % of all executions finish inside 10 ms (cache-hit
///   trivial modules). This is the modal population and needs to stay visible,
///   but distinguishing 3 ms from 8 ms drives no decision, so two boundaries.
///   The default's `0` is DROPPED: `le=0` counted exactly 0 executions across
///   the whole 15 d window, so it was a series permanently equal to its
///   neighbour.
///
///   Note the mechanism carefully, because the first version of this note had
///   it BACKWARDS and the inverted form is the more plausible-sounding one.
///   `duration_ms` is `elapsed().as_millis() as f64`, so a sub-millisecond
///   execution records exactly `0.0` — and the lowest bucket is `(-∞, 0]`,
///   which INCLUDES `0.0`. Truncation is therefore the thing that would
///   POPULATE `le=0`, not the thing that makes it unreachable. `le=0` is empty
///   here as an EMPIRICAL fact about this workload (nothing has completed in
///   under 1 ms), not as a structural impossibility.
///
///   **`5` fails that same empirical test today and is kept anyway — stated
///   rather than glossed, because it is the one place this set does not meet
///   its own standard.** `le=5` also counted exactly 0 over the window: every
///   one of the 45.3 % lands in `(5,10]`, so `5` is currently as
///   equal-to-its-neighbour as the `0` that was dropped for exactly that
///   reason, and removing it moves no quantile of interest by any amount. It
///   is retained as forward resolution for the modal population (a boundary
///   that is reachable and cheap, unlike `0`), NOT because the measured data
///   earns it. Dropping it is a legitimate follow-up; it orphans no selector.
/// * **`25, 100`** — the 25 → 250 ms span holds only 4.8 % of executions, and
///   the default spent FOUR boundaries (25/50/75/100) on it. `(25,50]` alone
///   held 0.45 %. Two boundaries here, not four; `50` and `75` are dropped.
/// * **`250, 400, 500`** — `(250,500]` is the largest bucket ABOVE the
///   sub-10 ms mode: 19.5 % of ALL executions. (It is not the largest bucket
///   in the histogram — `(5,10]` is, at 45.3 %, as the table above shows. An
///   earlier draft of this note claimed the superlative outright and the
///   table two paragraphs up falsified it; the split is justified by the next
///   sentence, not by the superlative.) The healthy p95 sits inside it, and
///   the default gave it ZERO interior resolution, so "the healthy p95" was
///   only ever knowable to ±250 ms. Measured: over 15 d, every one of the 505
///   evaluated p95 points that landed in `(250,500]` was in `(400,500]` —
///   modal values 456.2 / 458.3 / 462.5 ms — so `400` halves the width of the
///   bucket the healthy p95 actually occupies, 250 ms → 100 ms. That is the
///   same criterion that saved `7500` below.
///
///   Exactly one split, not two — but by a RULE, not from the data, and the
///   distinction matters because an earlier draft claimed the opposite:
///   nothing in the measurements distinguishes 400 from 375 or 425 (the
///   exact-recovery sample has no observations in this range at all, being
///   biased to the tail). The rule is "split the healthy band once, below the
///   interpolated p95". A second interior boundary would have no rule behind
///   it at all.
/// * **`1000, 2500, 5000, 7500, 10000`** — 11.4 % of executions span 1–10 s.
///   `2500` and `10000` are load-bearing: `SlowWASMExecution` and
///   `VerySlowWASMExecution` select on them by `le=`, and their thresholds
///   were calibrated in #628. They are KEPT AT THEIR EXACT VALUES so this
///   change does not silently re-calibrate an alert while re-bucketing a
///   histogram — two changes that must not ride in one commit. `750` is
///   dropped (1.8 %).
///
///   `7500` was ALSO dropped in the first draft of this set, on an occupancy
///   argument, and that was a reasoning error worth naming because it is easy
///   to repeat: **a boundary's value is not its own bucket's mass, it is the
///   WIDTH it gives to whichever bucket a quantile of interest lands in.**
///   (The occupancy figure quoted in that first draft was also the wrong
///   bucket — it cited `(7500,10000]` at 0.8 %, while the bucket that actually
///   disappears when `7500` is removed is `(5000,7500]` at 1.7 %. Naming a
///   bucket by its UPPER bound is the convention used everywhere else in this
///   note.) The 15 d p95 sits at ~5.6 s, i.e. in the bucket immediately above
///   5000. Removing 7500 widens that bucket from 2500 ms to 5000 ms and moves
///   the interpolated p95 by ~4 % — measured 5666.7 → 5919.5 ms on one 15 d
///   window and 5553.9 → 5750.4 ms on a later one — doubling the uncertainty
///   band on the single number this whole cycle exists to report correctly. It
///   costs one series. Kept. (`p90` is unaffected — it lands lower down —
///   which is why the occupancy argument looked fine until the p95 was
///   actually computed both ways.)
///
///   **Those two p95 pairs are two SNAPSHOTS of the same quantity, not a
///   contradiction, and the headline figure at the top of this note (5556.6 ms)
///   is a third.** The p95 here is hypersensitive: it interpolates inside a
///   bucket holding ~21 executions out of ~1200, so roughly ONE execution
///   moving across `5000` accounts for the whole ~110 ms spread between
///   snapshots. Any reader re-measuring will get their own value. What is
///   stable is the claim this cycle makes — that the number is a MEASUREMENT
///   in the 5.5–5.7 s range rather than a 10000.0 ceiling.
/// * **`15000, 20000, 30000, 60000, 120000`** — the region that did not exist
///   before, and the entire point of the change. Placed on the recovered
///   values: 8 of the 16 over-10 s observations fall in 10–15 s, 4 in 15–20 s,
///   2 in 20–30 s, then 50.5 s and 81.9 s. `120000` is not a data point but
///   the worker's DEFAULT per-node wall-clock timeout
///   (`WASM_EXECUTION_TIMEOUT_SECS`, default 120, resolved in
///   `worker/src/main.rs` and `DEFAULT_NODE_TIMEOUT_SECS`).
///
///   It is a DEFAULT, not a clamp, and the difference is operational: the
///   engine states plainly that there is no implicit clamp, and
///   `worker/src/main.rs` honours a per-request `timeout_ms` when it is > 0,
///   so a node authored with `timeout_secs: 300` legitimately runs to 300 s in
///   ONE attempt. Overflow past `120000` therefore has TWO causes — retries
///   and backoff accumulating in `overall_start.elapsed()`, OR a node with a
///   raised timeout — and an operator who reads it as "retries, necessarily"
///   will misdiagnose the second. Either way it is exceptional and worth
///   surfacing, which is what the boundary buys; the earlier claim that a
///   single successful attempt "cannot exceed it" was simply false.
///   Five boundaries for 2.87 % of the mass is disproportionate BY MASS on
///   purpose: mass is the wrong metric for a tail, and the operational
///   question this whole arc has been unable to answer — "how slow is slow?" —
///   lives entirely here.
///
/// ## Cardinality
///
/// Bucket series = (finite boundaries + 1 for `+Inf`) × label sets ×
/// instances; `_sum` and `_count` add 2 more per label set per instance.
///
/// **17 finite boundaries here versus 15 in the SDK default — 18 bucket series
/// per (status, instance) instead of 16, i.e. +2 (+12.5 %).** Six boundaries
/// were added (`400`, `15000`, `20000`, `30000`, `60000`, `120000`) and four
/// removed (`0`, `50`, `75`, `750`). The reallocation, not the growth, is the
/// change: five of the six additions cover a decade of latency the histogram
/// previously could not express at all.
///
/// Counting whole series including `_sum`/`_count`:
///
/// * live today (`status="success"` only, one replica): **20 vs 18**.
/// * realistic ceiling — the three statuses `record_execution` is actually
///   called with (`success`, `error`, `retry_exhausted`) × the compose file's
///   declared default of 2 replicas (`WORKER_REPLICAS:-2`): **120 vs 108, i.e.
///   +12**. Note `make up` overrides that with `--scale worker=1`, so the dev
///   stack's actual figure is half again — 60 vs 54. The declared default is
///   quoted here because it is the conservative direction; do not read "2
///   replicas" as a statement about what is running.
/// * theoretical maximum — all 8 values `normalize_status` can produce ×
///   2 replicas: **320 vs 288, i.e. +32**.
///
/// Thirty-two series is not a cardinality risk on any axis that matters; the
/// risk in this metric was never the boundary count but the label set, and
/// that is untouched. No label is added, and every label value remains a
/// compile-time `&'static str` from the closed `normalize_status` set — no
/// caller-derived value can reach it.
///
/// ## Mechanism
///
/// Set via `HistogramBuilder::with_boundaries` on the instrument rather than a
/// `SdkMeterProvider` View. A View is a `Fn(&Instrument) -> Option<Stream>`
/// that runs against EVERY instrument and must re-match this one by name, so
/// it can silently re-bucket a sibling histogram if the predicate is ever
/// loosened; `with_boundaries` cannot target anything but the instrument it is
/// written on. Both are read once at instrument construction and cost nothing
/// per `record()`, so there is no hot-path difference. (Precedence, if a View
/// is ever added: the View's aggregation WINS over these boundaries.)
///
/// Boundaries must be finite, sorted and duplicate-free or the SDK returns a
/// NO-OP instrument and logs — i.e. the failure mode is a silently dead
/// histogram, not a startup error. `execution_duration_boundaries_are_valid`
/// in `metrics_tests.rs` asserts those properties directly, and
/// `exported_prometheus_names_are_stable_and_idle_seeds_at_zero` pins the
/// exported `le=` set that `observability/rules/alerts.yml` selects on.
///
/// SIBLING DEFECT, DELIBERATELY NOT FIXED HERE: `wasm.llm.duration_ms` still
/// uses the SDK defaults and is saturated the same way — 206 calls over the
/// same window, mean 3945.8 ms, and 12.1 % of them past its 10 000 ms top
/// bound. Nothing selects on its `le=` values (no rule, no dashboard), so it
/// orphans nothing and can be re-bucketed independently. It is left alone
/// because re-bucketing it is a second re-bucketing, and each one is a
/// boundary-change event that has to be verified against the guard on its own.
pub(crate) const EXECUTION_DURATION_BOUNDARIES_MS: &[f64] = &[
    // Sub-100 ms: the 45 % of executions that never touch the network.
    5.0, 10.0, 25.0, 100.0,
    // The healthy band. 19.5 % of ALL executions land in (250, 500] and the
    // healthy p95 sits inside it; 400 is the one interior split.
    250.0, 400.0, 500.0,
    // Seconds. 2500 and 10000 are selected BY NAME from
    // observability/rules/alerts.yml and must not move without moving the
    // alert thresholds with them. 7500 is kept for INTERPOLATION WIDTH, not
    // for its own occupancy — see the region-by-region note above.
    1000.0, 2500.0, 5000.0, 7500.0, 10000.0,
    // The LLM tail — previously one undifferentiated overflow bucket.
    // 120000 is the worker's DEFAULT per-node wall-clock timeout — a default,
    // not a clamp: a node with an explicit `timeout_secs` runs past it in one
    // attempt.
    15000.0, 20000.0, 30000.0, 60000.0, 120000.0,
];

/// Explicit bucket boundaries (milliseconds) for `wasm.llm.duration_ms`.
///
/// The sibling defect `EXECUTION_DURATION_BOUNDARIES_MS` names in its own
/// header ("SIBLING DEFECT, DELIBERATELY NOT FIXED HERE"), fixed 2026-08-14 as
/// its own boundary-change event with its own verification, exactly as that
/// note asked for.
///
/// ## What this histogram actually measures — read this before the numbers
///
/// **It is SUCCESS-ONLY, and that is not fixed here.** `record_llm_request` is
/// called at ONE site, after every early return in `complete_impl`, so a call
/// that times out at 60 s — the single worst latency event this system can
/// produce — contributes NOTHING to this distribution. It increments
/// `wasm.llm.failures{outcome="timeout"}` instead. So "p99 LLM latency" from
/// this histogram means *p99 among calls that succeeded*, and it under-reports
/// true tail latency by exactly the timeout population. Widening the buckets to
/// 120 s does not change that; it only stops the SUCCESSFUL tail from being
/// clipped. Recording failed durations here would change what the series means
/// and is a separate decision.
///
/// It also covers `complete_impl` only — not streaming, tool-calling,
/// embeddings, or any controller-side LLM call. See `llm_failures`.
///
/// ## Why not the defaults
///
/// The SDK defaults (`0, 5, 10, 25, 50, 75, 100, 250, 500, 750, 1000, 2500,
/// 5000, 7500, 10000`) top out at 10 000 ms against exchange timeouts of 60 s
/// local / 120 s external, and `histogram_quantile` cannot interpolate inside
/// `+Inf` — it returns the highest finite bound. Measured on the dev stack
/// 2026-08-14 over 15 d at a 300 s step, `rate(...[1h])`: **756 of 2315
/// non-NaN p95 points (32.7 %) read exactly 10000.0, and so did 757 of 2315
/// p99 points.** A third of every latency reading this panel produced was a
/// FLOOR reported as a value.
///
/// (An earlier grounding pass put the over-10 s share at 12.1 %; measured over
/// this window it is 7.72 %. The fraction moves with the window — as the
/// sibling constant found too — the saturation does not.)
///
/// ## The live distribution (15 d, 1606 calls, unbiased)
///
/// `sum by (le) (increase(wasm_llm_duration_ms_bucket[15d]))`, cumulative %:
///
/// | ≤ ms  | 250 |  500 |  750 | 1000 | 2500 | 5000 | 7500 | 10000 | +Inf |
/// |-------|-----|------|------|------|------|------|------|-------|------|
/// | cum % | 0.0 | 1.25 | 46.0 | 75.2 | 81.0 | 85.7 | 89.0 |  92.3 | 100  |
///
/// Every default boundary at or below 250 counted **zero** observations —
/// eight of the fifteen, resolving a region that does not occur on this
/// workload at all. Counting `500` as well, nine of fifteen were spent on
/// 1.25 % of the mass, while the 7.7 % above 10 s got one undifferentiated
/// overflow bucket.
///
/// The tail above 10 s was recovered exactly, by the method the sibling
/// constant established: over-sample `_count`/`_sum` at a 10 s step, compress
/// runs of identical state, keep only intervals where `_count` advanced by
/// exactly 1 — then `Δ_sum` IS that one call's duration. 243 calls isolated;
/// 86 exceeded 10 s; **the slowest was 57.5 s**, just under the 60 s local
/// timeout, and NOTHING was above 60 s (consistent with 100 % of this stack's
/// LLM traffic being local Ollama).
///
/// That sample is tail-BIASED and is used for SHAPE only: 35 % of it is above
/// 10 s versus 7.7 % of the population, a ~4.5× enrichment. Isolated calls are
/// over-represented among slow ones because a slow call is more likely to be
/// alone in a scrape interval.
///
/// ## Region-by-region
///
/// * **Nothing below `500`.** 1.25 % of calls land there and the fastest call
///   ever recovered was 510 ms, so the bottom bucket is `(-∞, 500]` with no
///   interior resolution — deliberately, on the same rule the sibling constant
///   used to drop `le=0`. **Stated as a live risk, not glossed:** if this
///   deployment ever moves to a faster/smaller local model the whole
///   distribution collapses into that one bucket and this histogram goes
///   blind at the bottom. That is the trigger to revisit; it is not a reason
///   to spend boundaries on a region that measures zero today.
/// * **`500, 750, 1000`** — the mode, and the one place the SDK defaults were
///   already right. `(500,750]` alone holds **44.8 %** of all calls and
///   `(750,1000]` a further **29.2 %**: 74 % of the population inside a 500 ms
///   span. `750` is KEPT here for exactly the reason the sibling constant
///   DROPPED it — there it split 1.8 %, here it splits the mode.
/// * **`2500, 5000, 7500, 10000`** — the shoulder, 5.7 / 4.8 / 3.3 / 3.2 % per
///   bucket. Kept at the defaults' values. Nothing selects on them by `le=`
///   (see "Coupling" below), so this is continuity for its own sake: these
///   four survive the re-bucketing, which is what keeps a quantile below 10 s
///   computable across the deploy.
/// * **`15000, 17500, 20000`** — where the p95 actually lives, and the reason
///   the tail is bucketed at all. 92.28 % of the population is inside 10 s, so
///   the 95th percentile sits `(0.95 − 0.9228) / 0.0772` = **35.2 % into the
///   overflow mass**; read off the recovered tail as a conditional
///   distribution that is **≈15.6 s**. `17500` is the boundary that earns its
///   place: it puts p95 inside a **2500 ms** bucket, the tightest in the tail.
///   Same criterion that saved `7500` in the sibling constant — a boundary's
///   worth is the WIDTH it gives the bucket a quantile of interest lands in,
///   not its own occupancy. (Occupancy is fine too: the recovered tail splits
///   24 / 18 / 11 across `(10,15]`, `(15,17.5]`, `(17.5,20]`.)
///
///   **Corrected during implementation, and worth recording because the wrong
///   version was plausible:** a first draft placed a boundary at `12500` for a
///   p95 estimated at ≈14.5 s. That estimate mis-indexed the conditional
///   tail. At the correct ≈15.6 s, `12500` splits a bucket no quantile of
///   interest occupies and `17500` is what is actually needed. An estimate
///   this arithmetic drives a boundary directly, so getting it wrong silently
///   spends a series in the wrong decade.
/// * **`30000, 40000`** — where the p99 lives: 87.0 % into the overflow mass,
///   **≈35.6 s**. `40000` rather than `45000` deliberately — and NOT `35000`,
///   which is the estimate itself. A boundary placed AT a quantile makes the
///   reported value a bucket EDGE, which is the failure mode #628 recorded for
///   a p95 pinned at a bound; bracketing it in `(30000, 40000]` leaves it
///   interpolated. Recovered occupancy `(20,30]` = 19, `(30,40]` = 6,
///   `(40,60]` = 8.
/// * **`60000`** — `LOCAL_LLM_EXCHANGE_TIMEOUT_SECS`. A local call cannot
///   exceed it, so `le="60000"` is the "every Ollama call that succeeded" mark
///   and the bucket above it is structurally external-only.
/// * **`120000`** — `EXTERNAL_LLM_EXCHANGE_TIMEOUT_SECS`. **No boundary
///   between 60 s and 120 s**: that entire region is reachable only by
///   external-provider traffic, of which this deployment currently has none
///   (see the provider note below). Splitting it would be imagination, not
///   measurement.
///
/// ## Why `+Inf` is near-empty here, unlike the sibling
///
/// `EXECUTION_DURATION_BOUNDARIES_MS`'s top bound is a per-node *default* that
/// a node can legitimately run past. This one is closer to a clamp: the
/// `tokio::time::timeout` around the HTTP exchange is unconditional at 60/120 s
/// with no per-request override. **Not a hard guarantee, and the difference is
/// worth stating rather than rounding off:** `llm_start` is taken before key
/// resolution (a vault RPC) and the duration is read after response parsing, so
/// a recorded value CAN exceed the timeout — but only by time spent outside the
/// exchange, never by provider latency. Overflow past 120 s therefore means
/// "vault or parse was pathological", not "the provider was slow".
///
/// ## Cardinality and coupling
///
/// 14 finite boundaries → 15 bucket series, against the defaults' 15 → 16.
/// This is one series FEWER per label set while covering a decade more range —
/// the reallocation is the whole change. Labels are untouched: one `provider`
/// key, values from the closed `normalize_llm_provider` set.
///
/// **Nothing selects on this metric's `le=` values.** Verified 2026-08-14:
/// `wasm_llm_duration_ms` appears in `observability/rules/alerts.yml` only
/// inside `annotations.description` prose (`SlowWASMExecution`,
/// `VerySlowWASMExecution` point on-call at it as a triage step), never in an
/// `expr:`. So unlike `EXECUTION_DURATION_BOUNDARIES_MS` — whose `2500` and
/// `10000` are alert thresholds that must not move — no boundary here is
/// load-bearing for a rule, and re-bucketing re-calibrates nothing.
///
/// ## One-time discontinuity (do not read this as seamless)
///
/// Boundary changes are not retroactive. On the deploy that lands this, eight
/// `le` values STOP being reported (`0, 5, 10, 25, 50, 75, 100, 250`) and seven
/// START (`15000, 17500, 20000, 30000, 40000, 60000, 120000`). `500, 750, 1000,
/// 2500, 5000, 7500, 10000, +Inf` are preserved, which bounds the damage: any
/// quantile at or below 10 s stays computable across the change, and only
/// quantiles that land in the new region are meaningless over a window spanning
/// it. A `[15d]` quantile is mixing two layouts for 15 days afterwards.
///
/// The `provider` label flips from `other` to `ollama` in the SAME deploy (see
/// `normalize_llm_provider`). `sum by (le)` aggregations are unaffected; any
/// per-provider selection is not.
pub(crate) const LLM_DURATION_BOUNDARIES_MS: &[f64] = &[
    // The mode: 74 % of all calls live in (500, 1000].
    500.0, 750.0, 1000.0, //
    // The shoulder — kept at the defaults' values so a sub-10 s quantile
    // survives the re-bucketing.
    2500.0, 5000.0, 7500.0, 10000.0, //
    // Where p95 (≈15.6 s) and p99 (≈35.6 s) actually are. This region did not
    // exist before and is the point of the change. 17500 puts p95 in a 2500 ms
    // bucket; 30000/40000 bracket p99 rather than sitting on it.
    15000.0, 17500.0, 20000.0, 30000.0, 40000.0, //
    // The two exchange timeouts. Local calls cannot exceed 60 s; the bucket
    // above it is structurally external-only, and this stack has no external
    // LLM traffic, so it gets no interior boundary.
    60000.0, 120000.0,
];

// ========================================================================
// 🔥 SECURITY: Label Normalization
// Prevent unbounded cardinality which can cause memory exhaustion
// ========================================================================

/// Normalize status labels to a fixed set to prevent unbounded cardinality
fn normalize_status(status: &str) -> &'static str {
    match status {
        "success" => "success",
        "error" => "error",
        "timeout" => "timeout",
        "retry_exhausted" => "retry_exhausted",
        "out_of_fuel" => "out_of_fuel",
        "trap" => "trap",
        "memory_limit" => "memory_limit",
        _ => "other", // Catch-all for unknown statuses
    }
}

/// Normalize error type labels to fixed set
fn normalize_error_type(error_type: &str) -> &'static str {
    match error_type {
        "timeout" => "timeout",
        "out_of_fuel" => "out_of_fuel",
        "trap" => "trap",
        "memory_limit" => "memory_limit",
        "runtime_error" => "runtime_error",
        "module_error" => "module_error",
        "retries_exhausted" => "retries_exhausted",
        "network_error" => "network_error",
        "cache_error" => "cache_error",
        _ => "other", // Catch-all for unknown error types
    }
}

/// Normalize retry reason labels to fixed set
fn normalize_retry_reason(reason: &str) -> &'static str {
    match reason {
        "transient_error" => "transient_error",
        "network_error" => "network_error",
        "timeout" => "timeout",
        "rate_limit" => "rate_limit",
        "service_unavailable" => "service_unavailable",
        _ => "other",
    }
}

/// Normalize rate-limited function labels to fixed set
fn normalize_rate_limit_function(function: &str) -> &'static str {
    match function {
        "http" => "http",
        "db" => "db",
        "messaging" => "messaging",
        "log" => "log",
        "fs" => "fs",
        _ => "other",
    }
}

/// Normalize approval decision labels to fixed set
fn normalize_approval_decision(decision: &str) -> &'static str {
    match decision {
        "approved" => "approved",
        "denied" => "denied",
        _ => "other",
    }
}

/// Normalize LLM provider labels to fixed set.
///
/// ## The `ollama` arm was missing until 2026-08-14, and a test said that was
/// correct
///
/// The only caller (`record_llm_request` / `record_llm_failure`, both fed from
/// `complete_impl`) passes one of a CLOSED four-variant enum —
/// `anthropic | openai | gemini | ollama`. Three had arms; the fourth fell
/// through to `"other"`. This is a tier-1 stack whose LLM traffic is 100 %
/// local Ollama, so **every** LLM measurement it has ever produced was filed
/// under `provider="other"`. Confirmed live on the dev stack 2026-08-14:
/// `sum by (provider) (wasm_llm_requests_total)` returned exactly one series,
/// `{provider="other"} 93`.
///
/// What kept it alive is worth naming, because the mechanism generalises:
/// `metrics_tests.rs` carried
/// `test_normalize_llm_provider_unknown_defaults_to_other`, and its body was
/// `assert_eq!(normalize_llm_provider("ollama"), "other")`. Adding the arm
/// turned that test red, under a NAME asserting the person adding it was
/// wrong. A test can pin a bug as a requirement; when it does, the name is
/// what does the damage. It is fixed, not deleted — see
/// `normalize_llm_provider_labels_every_live_provider_and_folds_only_unknowns`.
///
/// `"other"` remains as the fold for a genuinely unknown string. It is now
/// UNREACHABLE from `complete_impl` (closed enum, all four arms present) and
/// is kept for the string-keyed callers a future provider could add — which is
/// also why no `provider="other"` series is pre-seeded.
///
/// **Series discontinuity**: on the deploy that lands this, the existing
/// `{provider="other"}` series stops advancing and `{provider="ollama"}`
/// starts from zero. Nothing aggregates by provider today (no rule, no
/// dashboard panel), so nothing breaks — but a `[15d]` per-provider query
/// spanning the deploy sees a series end and another begin, not a rename.
pub(crate) fn normalize_llm_provider(provider: &str) -> &'static str {
    match provider {
        "anthropic" => "anthropic",
        "openai" => "openai",
        "gemini" => "gemini",
        "ollama" => "ollama",
        _ => "other",
    }
}

/// Why an `llm::complete*` call did not return a completion.
///
/// **This is a closed Rust enum on purpose and must stay one.** It is the
/// `outcome` label of `wasm.llm.failures`, and the alternative — classifying
/// from the provider's error text — would put an attacker- and
/// prompt-influenced string into a Prometheus label. An LLM error body can
/// echo the prompt back; a model name, a URL, or an HTTP body in a label is
/// both an unbounded-cardinality memory-exhaustion surface and a data-leak
/// surface. Every value below is a compile-time `&'static str` chosen by the
/// call site, never derived from a response.
///
/// The variants are a partition of the exits from
/// `TalosContext::complete_inner`, which returns `Result<_, LlmCallFailure>`
/// specifically so that adding a new early return without choosing an outcome
/// does not compile. That is the structural guarantee behind "every failure
/// path is counted"; it is not an inspection of the current code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LlmFailure {
    /// The execution's cancellation flag was already set on entry, so no
    /// request was made. Counted for completeness — see the note on
    /// `record_llm_failure` about the overlap with
    /// `wasm_executions_cancelled_total`.
    Cancelled,
    /// No API key could be resolved for an external provider. Covers BOTH a
    /// genuinely absent key AND a Tier-1 ceiling refusing external egress:
    /// `get_llm_api_key` returns `None` for both, and `complete_inner` cannot
    /// tell them apart. The tier refusal is separately visible as a
    /// capability-denied event; do not read this label as "misconfigured".
    NotConfigured,
    /// The outbound request body could not be serialized.
    ///
    /// **Expect this to read a permanent 0, and do not "fix" it.** The exit is
    /// a real `?` on `serde_json::to_vec`, but the value being serialized is a
    /// `serde_json::Value` the adapter just built — `Value::Number` cannot
    /// hold NaN/Inf and object keys are always `String`, so there is no input,
    /// including a hostile `complete_with_options` payload (JSON has no NaN
    /// literal and serde_json rejects one), that makes it fail. It is
    /// classified rather than folded into another outcome so that if it ever
    /// DOES fire, the label says what happened instead of blaming the network.
    /// It is the one outcome below that no test drives through the production
    /// path, for this reason.
    InvalidRequest,
    /// The HTTP request never completed — connect refused, DNS, TLS, reset.
    Network,
    /// The whole exchange exceeded `LOCAL_/EXTERNAL_LLM_EXCHANGE_TIMEOUT_SECS`.
    Timeout,
    /// HTTP 429 from the provider.
    RateLimited,
    /// Any other non-2xx HTTP status. The status code itself is deliberately
    /// NOT a label: it is provider-controlled and would multiply the series
    /// count by the size of the HTTP status space.
    HttpStatus,
    /// The response body exceeded `MAX_LLM_BODY_BYTES` and the read was
    /// aborted.
    OversizedResponse,
    /// A 2xx response arrived but the adapter could not parse it.
    Decode,
}

impl LlmFailure {
    /// The Prometheus label value. `&'static str`, so building the `KeyValue`
    /// allocates nothing.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            LlmFailure::Cancelled => "cancelled",
            LlmFailure::NotConfigured => "not_configured",
            LlmFailure::InvalidRequest => "invalid_request",
            LlmFailure::Network => "network",
            LlmFailure::Timeout => "timeout",
            LlmFailure::RateLimited => "rate_limited",
            LlmFailure::HttpStatus => "http_status",
            LlmFailure::OversizedResponse => "oversized_response",
            LlmFailure::Decode => "decode",
        }
    }

    /// Every variant, for exhaustiveness tests and seeding.
    pub(crate) const ALL: [LlmFailure; 9] = [
        LlmFailure::Cancelled,
        LlmFailure::NotConfigured,
        LlmFailure::InvalidRequest,
        LlmFailure::Network,
        LlmFailure::Timeout,
        LlmFailure::RateLimited,
        LlmFailure::HttpStatus,
        LlmFailure::OversizedResponse,
        LlmFailure::Decode,
    ];
}

/// The provider label values `complete_impl` can actually produce — the four
/// variants of the WIT `Provider` enum, normalized. Deliberately NOT including
/// `"other"`: with all four arms present in `normalize_llm_provider`, no call
/// from `complete_impl` can reach it.
pub(crate) const LLM_PROVIDER_LABELS: [&str; 4] = ["anthropic", "openai", "gemini", "ollama"];

/// The `(provider, outcome)` pairs a live code path can actually write, and
/// therefore the exact set `seed_zero_series` pre-seeds at 0.
///
/// Two carve-outs, both in the SAFE direction (under-seeding means a series
/// appears on its first real event; over-seeding asserts a watched signal that
/// does not exist, which `seed_zero_series`' own doc calls the worse error):
///
/// * **`provider="other"`** — excluded entirely. Unreachable from
///   `complete_impl`; see `normalize_llm_provider`.
/// * **`(ollama, not_configured)`** — excluded. `complete_impl` branches on
///   `is_local` and skips key resolution for Ollama altogether, so the
///   `NotConfigured` exit is unreachable for it. This is why the seed set is
///   an irregular 35 and not a tidy 36; regularising it would be a
///   regression, which is what this comment and
///   `seeded_llm_failure_series_excludes_unreachable_combinations` exist to
///   prevent.
pub(crate) fn seeded_llm_failure_series() -> impl Iterator<Item = (&'static str, LlmFailure)> {
    LLM_PROVIDER_LABELS.into_iter().flat_map(|provider| {
        LlmFailure::ALL
            .into_iter()
            .filter(move |outcome| !(provider == "ollama" && *outcome == LlmFailure::NotConfigured))
            .map(move |outcome| (provider, outcome))
    })
}

/// Normalize LLM token direction labels to fixed set
fn normalize_token_direction(direction: &str) -> &'static str {
    match direction {
        "input" => "input",
        "output" => "output",
        _ => "other",
    }
}

/// Normalize quota metric labels to fixed set
fn normalize_quota_metric(metric: &str) -> &'static str {
    match metric {
        "http_calls" => "http_calls",
        "db_queries" => "db_queries",
        "messaging_publishes" => "messaging_publishes",
        "fs_bytes" => "fs_bytes",
        "log_messages" => "log_messages",
        "memory_bytes" => "memory_bytes",
        _ => "other",
    }
}

/// Normalize host function name labels to fixed set.
/// Prevents unbounded cardinality from dynamic function names.
fn normalize_host_function_name(name: &str) -> &'static str {
    match name {
        "http::fetch" => "http::fetch",
        "db::execute_query" => "db::execute_query",
        "messaging::publish" => "messaging::publish",
        "messaging::subscribe" => "messaging::subscribe",
        "cache::get" => "cache::get",
        "cache::set" => "cache::set",
        "cache::delete" => "cache::delete",
        "secrets::get_secret" => "secrets::get_secret",
        "files::read" => "files::read",
        "files::write" => "files::write",
        "graphql::execute" => "graphql::execute",
        "llm::complete" => "llm::complete",
        "llm::stream" => "llm::stream",
        "email::send" => "email::send",
        "logging::log" => "logging::log",
        _ => "other",
    }
}

/// Runtime metrics for observability
#[allow(dead_code)]
pub struct RuntimeMetrics {
    /// Total number of WASM executions
    executions_total: Counter<u64>,
    /// Execution duration histogram (milliseconds)
    execution_duration: Histogram<f64>,
    /// Component cache hits
    cache_hits: Counter<u64>,
    /// Component cache misses
    cache_misses: Counter<u64>,
    /// Number of active instances
    active_instances: UpDownCounter<i64>,
    /// Total executions counter (cumulative)
    pub total_executions: Counter<u64>,
    /// Cache hit ratio gauge (0.0‑1.0)
    cache_hit_ratio: Gauge<f64>,
    /// Compilation duration histogram (milliseconds)
    compilation_duration: Histogram<f64>,
    /// Retry attempts counter
    retry_attempts: Counter<u64>,
    /// Errors by type
    errors_total: Counter<u64>,
    // Split error counters for low-cardinality metric series
    error_timeout: Counter<u64>,
    error_out_of_fuel: Counter<u64>,
    error_trap: Counter<u64>,
    error_memory_limit: Counter<u64>,
    error_runtime_error: Counter<u64>,
    error_module_error: Counter<u64>,
    error_other: Counter<u64>,

    // ========================================================================
    // New feature metrics
    // ========================================================================
    /// Rate limit exceeded events by function type (http, db, messaging, log, fs)
    pub rate_limit_exceeded: Counter<u64>,

    /// Approval gate requests by workflow_id
    pub approval_requested: Counter<u64>,
    /// Approval gate decisions by decision (approved, denied)
    pub approval_decided: Counter<u64>,

    /// SUCCESSFUL `llm::complete*` calls by provider.
    ///
    /// Named `requests`, counts only successes — the read-side trap this
    /// metric's own sibling `llm_failures` was added to close. `requests +
    /// failures` is the attempt count; neither alone is.
    ///
    /// Scope is `complete_impl` ONLY (see `llm_failures`).
    pub llm_requests: Counter<u64>,
    /// LLM token usage by direction (input, output). Successful calls only —
    /// a failed call reports no usage.
    pub llm_token_usage: Counter<u64>,
    /// Duration of SUCCESSFUL `llm::complete*` calls (milliseconds).
    /// Buckets: `LLM_DURATION_BOUNDARIES_MS`, whose header explains why a
    /// timeout contributes nothing here.
    pub llm_duration: Histogram<f64>,

    /// `llm::complete*` calls that did NOT return a completion, by
    /// `(provider, outcome)`. → `wasm_llm_failures_total`.
    ///
    /// ## Scope — this counter does NOT cover LLM traffic in general
    ///
    /// Stated up front because a metric whose name implies whole-surface
    /// coverage is the defect this counter was added to fix: before
    /// 2026-08-14 `wasm.llm.requests` was incremented at exactly one site,
    /// below eight early returns, so it counted successes while being named
    /// for attempts, and no LLM failure anywhere in this system incremented
    /// anything at all.
    ///
    /// **Covered:** `TalosContext::complete_impl`, i.e. the WIT `llm::complete`,
    /// `llm::complete-json` and `llm::complete-with-options` host functions.
    ///
    /// **NOT covered, and unchanged by this work:**
    /// * streaming completions (`host/llm_streaming.rs`)
    /// * tool-calling completions (`host/llm_tools.rs`)
    /// * embeddings (`host/llm.rs`, `embedding` interface)
    /// * every controller-side LLM call — `talos-llm`, graph-RAG entity
    ///   extraction, `local_llm_complete`, workflow-engine LLM nodes
    ///
    /// Those emit no metrics of any kind, before or after this change. A zero
    /// here means "no `complete_impl` failure", never "no LLM failure".
    ///
    /// ## Cardinality
    ///
    /// Two labels, both closed compile-time sets: `provider` from
    /// `normalize_llm_provider` (4 reachable values) × `outcome` from
    /// `LlmFailure` (9). 35 reachable pairs (see `seeded_llm_failure_series`),
    /// all pre-seeded at 0, ×2 for the compose file's declared
    /// `WORKER_REPLICAS:-2` = 70 series. No response text, status code, model
    /// name, URL, or error string is or may become a label value.
    pub llm_failures: Counter<u64>,

    /// Executions cancelled via cancellation token
    pub executions_cancelled: Counter<u64>,

    /// Quota exceeded events by metric name
    pub quota_exceeded: Counter<u64>,

    // =======================================================================
    // Host function latency metrics
    // =======================================================================
    /// Host function call duration histogram (milliseconds)
    pub host_function_duration: Histogram<f64>,
    /// Host function calls by function name
    pub host_function_calls: Counter<u64>,

    // ========================================================================
    // 🔥 PERFORMANCE: Atomic counters for cache hit rate calculation
    // ========================================================================
    /// Atomic counter for total cache hits (for hit rate calculation)
    cache_hits_count: AtomicU64,
    /// Atomic counter for total cache misses (for hit rate calculation)
    cache_misses_count: AtomicU64,
}

#[allow(dead_code)]
impl RuntimeMetrics {
    /// Initialize OpenTelemetry metrics.
    ///
    /// The returned value has already had [`Self::seed_zero_series`] applied,
    /// so an idle worker exports the execution/cache series at 0 rather than
    /// not at all. See that method for why that distinction is load-bearing.
    pub fn new() -> Self {
        let meter = global::meter("talos-wasm-runtime");

        let this = Self {
            // → `wasm_executions_total` (the exporter appends `_total`).
            executions_total: meter
                .u64_counter("wasm.executions")
                .with_description("WASM executions COMPLETED, by terminal status")
                .build(),

            // Explicit boundaries — see EXECUTION_DURATION_BOUNDARIES_MS for
            // the measured distribution they were sized against. The SDK
            // defaults top out at 10 000 ms, below the LLM-bearing population
            // this histogram exists to measure.
            execution_duration: meter
                .f64_histogram("wasm.execution.duration_ms")
                .with_description("Execution duration in milliseconds")
                .with_boundaries(EXECUTION_DURATION_BOUNDARIES_MS.to_vec())
                .build(),

            cache_hits: meter
                .u64_counter("wasm.cache.hits")
                .with_description("Component cache hits")
                .build(),

            cache_misses: meter
                .u64_counter("wasm.cache.misses")
                .with_description("Component cache misses")
                .build(),

            active_instances: meter
                .i64_up_down_counter("wasm.instances.active")
                .with_description("Currently active WASM instances")
                .build(),
            // → `wasm_executions_started_total`.
            //
            // Until 2026-08-02 this instrument was declared with the SAME
            // OTEL name as `executions_total` above. Both were incremented
            // per execution — this one at dispatch (no attributes), the
            // other at completion (with `status`).
            //
            // Precisely what that produced, since "two counters, one name"
            // has a non-obvious resolution: the SDK's `InstrumentId`
            // includes the DESCRIPTION, and the two descriptions differed,
            // so the two instruments resolved to two SEPARATE aggregators
            // rather than summing. The Prometheus exporter then emitted both
            // under one metric family (`validate_metrics` logs a
            // description conflict and reuses the first-seen help rather
            // than dropping), and `prometheus::Registry::gather` merges
            // same-named families by appending metrics. Net: ONE metric
            // NAME carrying TWO series, told apart only by whether `status`
            // is present. So it was not one series double-counting — but
            // any `sum()` over the name DID count roughly twice per
            // execution, and any `sum by (status)` grew a meaningless
            // empty-status bucket, both off by an amount that varied with
            // the in-flight count. (Moot in practice: the name it collided
            // under was `wasm_executions_total_total`, which no alert or
            // dashboard selected on.) Distinct name, distinct meaning:
            // `started - sum(completed)` is the in-flight count.
            total_executions: meter
                .u64_counter("wasm.executions.started")
                .with_description("WASM executions STARTED (incremented at dispatch)")
                .build(),
            cache_hit_ratio: meter
                .f64_gauge("wasm.cache.hit_ratio")
                .with_description("Cache hit ratio (0.0‑1.0)")
                .build(),

            compilation_duration: meter
                .f64_histogram("wasm.compilation.duration_ms")
                .with_description("Module compilation duration in milliseconds")
                .build(),

            // → `wasm_retries_total`.
            retry_attempts: meter
                .u64_counter("wasm.retries")
                .with_description("Total retry attempts")
                .build(),

            // → `wasm_errors_total`.
            errors_total: meter
                .u64_counter("wasm.errors")
                .with_description("Total errors by type")
                .build(),
            // Individual error counters for low-cardinality series
            error_timeout: meter
                .u64_counter("wasm.errors.timeout")
                .with_description("Timeout errors")
                .build(),
            error_out_of_fuel: meter
                .u64_counter("wasm.errors.out_of_fuel")
                .with_description("Out of fuel errors")
                .build(),
            error_trap: meter
                .u64_counter("wasm.errors.trap")
                .with_description("Trap errors")
                .build(),
            error_memory_limit: meter
                .u64_counter("wasm.errors.memory_limit")
                .with_description("Memory limit errors")
                .build(),
            error_runtime_error: meter
                .u64_counter("wasm.errors.runtime_error")
                .with_description("Runtime errors")
                .build(),
            error_module_error: meter
                .u64_counter("wasm.errors.module_error")
                .with_description("Module errors")
                .build(),
            error_other: meter
                .u64_counter("wasm.errors.other")
                .with_description("Other errors")
                .build(),

            // ── New feature metrics ───────────────────────────────────────
            rate_limit_exceeded: meter
                .u64_counter("wasm.rate_limit.exceeded")
                .with_description("Rate limit exceeded events by function type")
                .build(),

            approval_requested: meter
                .u64_counter("wasm.approval.requested")
                .with_description("Approval gate requests")
                .build(),
            approval_decided: meter
                .u64_counter("wasm.approval.decided")
                .with_description("Approval gate decisions")
                .build(),

            // Descriptions say "successful" because these three instruments
            // are written at one site AFTER every early return in
            // `complete_impl`. The `# HELP` line is the only place an
            // operator reading /metrics can learn that.
            llm_requests: meter
                .u64_counter("wasm.llm.requests")
                .with_description(
                    "Successful llm::complete* calls by provider \
                     (failures: wasm_llm_failures_total)",
                )
                .build(),
            llm_token_usage: meter
                .u64_counter("wasm.llm.token_usage")
                .with_description("LLM token usage by direction (successful calls only)")
                .build(),
            llm_duration: meter
                .f64_histogram("wasm.llm.duration_ms")
                .with_description("Successful llm::complete* duration in milliseconds")
                .with_boundaries(LLM_DURATION_BOUNDARIES_MS.to_vec())
                .build(),
            // → `wasm_llm_failures_total`. See the field doc for the scope
            // this does and does not cover.
            llm_failures: meter
                .u64_counter("wasm.llm.failures")
                .with_description(
                    "Failed llm::complete* calls by provider and outcome \
                     (complete_impl only; not streaming/tools/embeddings)",
                )
                .build(),

            executions_cancelled: meter
                .u64_counter("wasm.executions.cancelled")
                .with_description("Executions cancelled via cancellation token")
                .build(),

            quota_exceeded: meter
                .u64_counter("wasm.quota.exceeded")
                .with_description("Quota exceeded events by metric name")
                .build(),

            // =======================================================================
            // Host function latency metrics
            // =======================================================================
            host_function_duration: meter
                .f64_histogram("wasm.host_function.duration_ms")
                .with_description("Host function call duration in milliseconds")
                .build(),
            host_function_calls: meter
                .u64_counter("wasm.host_function.calls")
                .with_description("Total host function calls by name")
                .build(),

            // Initialize atomic counters
            cache_hits_count: AtomicU64::new(0),
            cache_misses_count: AtomicU64::new(0),
        };

        this.seed_zero_series();
        this
    }

    /// Record a zero-valued measurement on every series whose label set is
    /// CLOSED and whose emitting call site is live, so the series exists on
    /// an idle process.
    ///
    /// ## Why
    ///
    /// An OTEL instrument produces no Prometheus series until its first
    /// recorded measurement. On an idle worker every `wasm_*` series is
    /// therefore ABSENT, not zero — and in PromQL those are different in a
    /// way that silences detectors: `rate(wasm_executions_total[30m]) == 0`
    /// over an absent series yields an EMPTY vector, and `empty == 0` matches
    /// nothing. The alert built to notice "nothing is executing" could only
    /// fire on a worker that HAD executed and then stopped, never on the
    /// cold-dead case. Seeding at 0 is the honest fix on the producer side;
    /// the `absent()` arm added to `NoWASMExecutions` is the belt to this
    /// braces (it still covers a worker too old to seed, or an exporter that
    /// died before first scrape).
    ///
    /// It is also what keeps the `WASMMetricsPipelineDead` meta-detector from
    /// being permanently red: with seeding, "target up and exporting nothing"
    /// means the pipeline is genuinely broken rather than merely quiet.
    ///
    /// ## What is deliberately NOT seeded
    ///
    /// Only combinations a live code path actually writes. Seeding a label
    /// combination nothing increments implies a wired signal that does not
    /// exist — a flat-zero series an operator reads as "checked, healthy"
    /// when it is really "never checked".
    ///
    /// * `executions` — seeded for the three statuses `record_execution` is
    ///   actually called with (`success`, `error`, `retry_exhausted` in
    ///   runtime.rs). The other five values `normalize_status` can produce
    ///   are reachable only as a normalisation of a caller string no caller
    ///   passes today, so they stay unseeded.
    /// * `executions.started` — deliberately NOT seeded, even though its
    ///   label set is empty and therefore maximally closed. It is written at
    ///   dispatch ENTRY (`runtime.rs`, `total_executions.add(1, &[])`) while
    ///   `executions` is written at completion, so a seeded 0 on the started
    ///   side would assert a dispatch path had been observed before any
    ///   execution reached it. The asymmetry with the seeded completion-side
    ///   counter is intentional; `exported_prometheus_names_are_stable_and_
    ///   idle_seeds_at_zero` pins both halves — absent on a cold process,
    ///   present once a dispatch has actually occurred.
    /// * `cache.hits` / `cache.misses` — no labels at all, and
    ///   `record_compilation` writes one or the other on every compile. Both
    ///   seeded, which also makes `LowCacheHitRate`'s
    ///   `hits / (hits + misses)` well-defined instead of dropping to an
    ///   empty vector whenever one leg had never been touched.
    /// * `errors` / `retries` / `llm.token_usage` / `approval.*` / `quota.*` /
    ///   `host_function.*` — NOT seeded. Their label populations are driven
    ///   by which failure or which host call actually happened, so a seeded
    ///   combination would assert a class of event is being watched for when
    ///   nothing distinguishes "zero timeouts" from "the timeout path was
    ///   deleted". Their alerts are `> threshold` shapes, which behave
    ///   correctly over an absent series (no data, no alert).
    /// * `llm.failures` and `llm.requests` — **seeded, 2026-08-14, breaking
    ///   the `llm.*` blanket above.** The `> threshold` argument is what
    ///   justifies leaving a counter unseeded, and it does not apply to
    ///   these two. The questions actually asked of a failure counter are
    ///   "is anything failing" (`increase(...) == 0`, EMPTY over an absent
    ///   series, so it matches nothing and reads as healthy on a worker that
    ///   has never reported) and "what fraction is failing"
    ///   (`failures / (failures + requests)`, which drops to an empty vector
    ///   whenever either leg has never been touched). That is the same
    ///   `a / (a + b)` shape already cited above as the reason `cache.hits`
    ///   and `cache.misses` are both seeded; this is that precedent applied,
    ///   not an exception to it. `llm.requests` is seeded per provider for
    ///   the four values `complete_impl` can emit; `llm.failures` for the 35
    ///   reachable `(provider, outcome)` pairs — the reachability carve-outs
    ///   live in `seeded_llm_failure_series`, and both legs must be seeded
    ///   or the ratio is no better defined than before.
    ///
    /// SECURITY: every label value below is a compile-time `&'static str`
    /// from a closed set. No worker id, execution id, module name, user id,
    /// guest content, or error text may ever be seeded (or emitted) as a
    /// label — unbounded label cardinality is a memory-exhaustion surface on
    /// both the worker and the Prometheus server.
    fn seed_zero_series(&self) {
        for status in ["success", "error", "retry_exhausted"] {
            self.executions_total
                .add(0, &[KeyValue::new("status", status)]);
        }
        self.cache_hits.add(0, &[]);
        self.cache_misses.add(0, &[]);
        // Both legs of `failures / (failures + requests)` — see the doc above.
        for provider in LLM_PROVIDER_LABELS {
            self.llm_requests
                .add(0, &[KeyValue::new("provider", provider)]);
        }
        for (provider, outcome) in seeded_llm_failure_series() {
            self.llm_failures.add(
                0,
                &[
                    KeyValue::new("provider", provider),
                    KeyValue::new("outcome", outcome.label()),
                ],
            );
        }
    }

    /// Record execution completion
    /// SECURITY: Status labels are normalized to prevent unbounded cardinality
    pub fn record_execution(&self, duration_ms: f64, status: &str) {
        let normalized_status = normalize_status(status);
        self.executions_total
            .add(1, &[KeyValue::new("status", normalized_status)]);
        self.execution_duration
            .record(duration_ms, &[KeyValue::new("status", normalized_status)]);
    }

    /// Record compilation duration
    pub fn record_compilation(&self, duration_ms: f64, cache_hit: bool) {
        if cache_hit {
            self.cache_hits.add(1, &[]);
            self.cache_hits_count.fetch_add(1, Ordering::Relaxed);
        } else {
            self.cache_misses.add(1, &[]);
            self.cache_misses_count.fetch_add(1, Ordering::Relaxed);
            self.compilation_duration.record(duration_ms, &[]);
        }
        // Update cache hit ratio gauge (0.0‑1.0)
        let hits = self.cache_hits_count.load(Ordering::Relaxed);
        let misses = self.cache_misses_count.load(Ordering::Relaxed);
        let total = hits + misses;
        let ratio = if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        };
        self.cache_hit_ratio.record(ratio, &[]);
    }

    /// Increment active instances
    pub fn increment_active(&self) {
        self.active_instances.add(1, &[]);
    }

    /// Decrement active instances
    pub fn decrement_active(&self) {
        self.active_instances.add(-1, &[]);
    }

    /// Record retry attempt
    /// SECURITY: Reason labels are normalized to prevent unbounded cardinality
    pub fn record_retry(&self, reason: &str) {
        let normalized_reason = normalize_retry_reason(reason);
        self.retry_attempts
            .add(1, &[KeyValue::new("reason", normalized_reason)]);
    }

    /// Record error
    /// SECURITY: Error type labels are normalized to prevent unbounded cardinality
    pub fn record_error(&self, error_type: &str) {
        let normalized_type = normalize_error_type(error_type);
        // Increment generic total counter
        self.errors_total
            .add(1, &[KeyValue::new("type", normalized_type)]);
        // Increment specific counter based on normalized type
        match normalized_type {
            "timeout" => self.error_timeout.add(1, &[]),
            "out_of_fuel" => self.error_out_of_fuel.add(1, &[]),
            "trap" => self.error_trap.add(1, &[]),
            "memory_limit" => self.error_memory_limit.add(1, &[]),
            "runtime_error" => self.error_runtime_error.add(1, &[]),
            "module_error" => self.error_module_error.add(1, &[]),
            _ => self.error_other.add(1, &[]),
        }
    }

    // ── New feature metric recording methods ────────────────────────────

    /// Record a rate limit exceeded event.
    /// SECURITY: Function labels are normalized to prevent unbounded cardinality.
    pub fn record_rate_limit_exceeded(&self, function: &str) {
        let normalized = normalize_rate_limit_function(function);
        self.rate_limit_exceeded
            .add(1, &[KeyValue::new("function", normalized)]);
    }

    /// Record an approval gate request.
    ///
    /// MCP-492: previously this took `workflow_id` and emitted it as a
    /// Prometheus label, with a doc claim of "truncated to 64 chars to
    /// bound cardinality." That was misleading — truncating a 36-char
    /// UUID to 64 chars does nothing to bound the value-space of the
    /// label. Every distinct workflow that requested approval allocated
    /// a fresh Prometheus series; over a long-lived worker process this
    /// grew unboundedly with the number of approval-gated workflows
    /// ever executed. Cardinality blow-ups in Prometheus translate
    /// directly into operator-visible memory pressure on the worker AND
    /// scrape-side OOMs on the Prometheus server.
    ///
    /// Approval-gate metrics are now aggregate. Per-workflow visibility
    /// belongs in audit logs / `wasi:approval_request` events emitted
    /// to the chain — those have proper retention semantics and don't
    /// pin worker memory. The other `normalize_*` helpers in this file
    /// genuinely bound cardinality by collapsing unknown values to a
    /// fixed `"other"`; that pattern is the right model when a label
    /// IS needed.
    pub fn record_approval_requested(&self) {
        self.approval_requested.add(1, &[]);
    }

    /// Record an approval gate decision.
    /// SECURITY: Decision labels are normalized to prevent unbounded cardinality.
    pub fn record_approval_decided(&self, decision: &str) {
        let normalized = normalize_approval_decision(decision);
        self.approval_decided
            .add(1, &[KeyValue::new("decision", normalized)]);
    }

    /// Record an `llm::complete*` call that did not return a completion.
    ///
    /// SECURITY: both label values are compile-time `&'static str` from closed
    /// sets — `normalize_llm_provider` folds anything unrecognised to
    /// `"other"`, and `outcome` comes from the `LlmFailure` enum, never from a
    /// provider response. Nothing caller-, guest- or provider-controlled can
    /// reach a label here.
    ///
    /// PERF: this sits on the LLM host path. The `KeyValue` array is two
    /// borrowed `&'static str`s on the stack — no allocation — and the SDK
    /// does one attribute-set lookup. Note the OTEL Rust API has no
    /// bound-instrument / "label children" concept (that is the `prometheus`
    /// crate's `with_label_values`), so the lookup cannot be hoisted to init;
    /// it is the same per-call cost every other recorder in this file pays,
    /// against a call that just spent between 0.5 s and 120 s on the network.
    ///
    /// OVERLAP, stated so nobody double-counts: `LlmFailure::Cancelled` is
    /// also counted by `record_execution_cancelled` →
    /// `wasm_executions_cancelled_total`. It is included here anyway so that
    /// `llm_requests + llm_failures` is exactly the number of entries into
    /// `complete_impl`, with no unaccounted exit. It is a pre-flight abort,
    /// not a provider failure; the label says so.
    pub fn record_llm_failure(&self, provider: &str, outcome: LlmFailure) {
        let normalized = normalize_llm_provider(provider);
        self.llm_failures.add(
            1,
            &[
                KeyValue::new("provider", normalized),
                KeyValue::new("outcome", outcome.label()),
            ],
        );
    }

    /// Record a SUCCESSFUL LLM API request. Failures go to
    /// `record_llm_failure`; this site is below every early return in
    /// `complete_impl`.
    /// SECURITY: Provider labels are normalized to prevent unbounded cardinality.
    pub fn record_llm_request(&self, provider: &str, duration_ms: f64) {
        let normalized = normalize_llm_provider(provider);
        self.llm_requests
            .add(1, &[KeyValue::new("provider", normalized)]);
        self.llm_duration
            .record(duration_ms, &[KeyValue::new("provider", normalized)]);
    }

    /// Record LLM token usage.
    /// SECURITY: Direction labels are normalized to prevent unbounded cardinality.
    pub fn record_llm_tokens(&self, direction: &str, count: u64) {
        let normalized = normalize_token_direction(direction);
        self.llm_token_usage
            .add(count, &[KeyValue::new("direction", normalized)]);
    }

    /// Record an execution cancellation.
    pub fn record_execution_cancelled(&self) {
        self.executions_cancelled.add(1, &[]);
    }

    /// Record a quota exceeded event.
    /// SECURITY: Metric labels are normalized to prevent unbounded cardinality.
    pub fn record_quota_exceeded(&self, metric: &str) {
        let normalized = normalize_quota_metric(metric);
        self.quota_exceeded
            .add(1, &[KeyValue::new("metric", normalized)]);
    }

    /// Record host function call latency.
    /// SECURITY: Function name labels are normalized to prevent unbounded cardinality.
    pub fn record_host_function_call(&self, function_name: &str, duration_ms: f64) {
        // Normalize function name to prevent cardinality explosion
        let normalized = normalize_host_function_name(function_name);
        self.host_function_duration
            .record(duration_ms, &[KeyValue::new("function", normalized)]);
        self.host_function_calls
            .add(1, &[KeyValue::new("function", normalized)]);
    }

    /// Calculate cache hit rate
    /// Returns value between 0.0 and 1.0
    ///
    /// # Example
    /// - 90 hits, 10 misses = 0.90 (90% hit rate)
    /// - 0 hits, 0 misses = 0.0 (no data yet)
    pub fn cache_hit_rate(&self) -> f64 {
        let hits = self.cache_hits_count.load(Ordering::Relaxed);
        let misses = self.cache_misses_count.load(Ordering::Relaxed);
        let total = hits + misses;

        if total == 0 {
            return 0.0; // No cache operations yet
        }

        hits as f64 / total as f64
    }
}

impl Default for RuntimeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Initialize OpenTelemetry with Prometheus exporter
/// This sets up the global meter provider with Prometheus metrics collection
pub fn init_telemetry() -> Result<(), Box<dyn std::error::Error>> {
    // The per-host outbound-HTTP circuit breaker publishes through the
    // `prometheus` crate rather than OTEL (see the header comment in
    // `circuit_breaker.rs` for the three reasons). It registers into the same
    // default registry the exporter below writes to, so it lands on the same
    // `/metrics` output. Forced here so an idle worker EXPORTS all five series
    // at 0 instead of omitting them until the breaker first trips — an
    // `increase(...) > 0` rule over an ABSENT series is silent on exactly the
    // worker that has never been observed to fail.
    //
    // THIS RUNS FIRST, BEFORE THE `?` BELOW, AND THAT ORDER IS LOAD-BEARING.
    // The exporter build is fallible and its failure is NON-FATAL: the worker's
    // caller (`worker/src/main.rs`) logs a warning and continues serving. If
    // the seed sat after the `?`, an exporter-build failure would leave
    // `/metrics` up and scraped but WITHOUT these five series, and the alert
    // built on them would go quiet with no other symptom — the same
    // "observability coupled to an optional component" failure this metric's
    // whole design argues against. Seeding only touches the default registry,
    // which `get_prometheus_metrics` gathers directly and which exists whether
    // or not OTEL initialises, so nothing here depends on the exporter.
    crate::circuit_breaker::seed_circuit_breaker_series();

    // Create Prometheus exporter (version 0.17+ API)
    let registry = prometheus::default_registry();
    let exporter = opentelemetry_prometheus::exporter()
        .with_registry(registry.clone())
        .build()?;

    // Set the global meter provider so that global::meter() actually sends data to Prometheus
    let provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
        .with_reader(exporter)
        .build();

    opentelemetry::global::set_meter_provider(provider);

    println!("[METRICS] OpenTelemetry initialized with Prometheus exporter");
    println!("[METRICS] Metrics will be available at /metrics endpoint");
    Ok(())
}

/// `init_telemetry` for tests, callable from anywhere in the binary.
///
/// The exporter registers a collector into `prometheus::default_registry()`,
/// which is process-global, so a second call returns
/// `InternalFailure("Duplicate metrics collector registration attempted")`.
/// That was harmless while `metrics_tests` was the only caller and could
/// document itself as such; it stopped being harmless the moment a second
/// module (`host::llm::llm_failure_metrics_tests`) also needed a live
/// exporter, because which one hit the duplicate depended on test scheduling.
///
/// Deliberately NOT solved by making `init_telemetry` itself idempotent:
/// production calls it exactly once and a real double-init there is a bug
/// worth surfacing, not swallowing.
#[cfg(test)]
pub(crate) fn init_telemetry_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        init_telemetry().expect("telemetry init");
    });
}

/// Get Prometheus metrics in text format
/// Call this from your HTTP /metrics endpoint
///
/// # Example
/// ```rust
/// // Simple example without requiring external crates
/// fn example() -> String {
///     // Directly obtain the Prometheus metrics string
///     talos_worker_runtime::metrics::get_prometheus_metrics()
/// }
/// ```
pub fn get_prometheus_metrics() -> String {
    use prometheus::{Encoder, TextEncoder};

    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];

    match encoder.encode(&metric_families, &mut buffer) {
        Ok(_) => String::from_utf8(buffer).unwrap_or_else(|e| {
            let error_msg = format!("[ERROR] Failed to encode metrics as UTF-8: {}", e);
            eprintln!("{}", error_msg);
            error_msg
        }),
        Err(e) => {
            let error_msg = format!("[ERROR] Failed to encode Prometheus metrics: {}", e);
            eprintln!("{}", error_msg);
            error_msg
        }
    }
}

#[cfg(test)]
#[path = "metrics_tests.rs"]
// The included file wraps its content in its own `mod tests` —
// latent clippy::module_inception surfaced by `--all-targets`.
#[allow(clippy::module_inception)]
mod tests;
